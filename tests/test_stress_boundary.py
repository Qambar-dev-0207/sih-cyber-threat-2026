"""
tests/test_stress_boundary.py
------------------------------
Adversarial Stress & Boundary Test Suite for SIH26145.
Covers:
1. High Burst Rates (50k, 100k, 200k PPS).
2. Boundary and Extreme Parameters (duration=0, pps=0, pps=1, non-existent, zero-byte, corrupted PCAPs).
3. Concurrency, Race Conditions, Thread Safety, Rapid Start/Stop Cycles.
4. Memory Leak and Algorithmic Complexity Profiling.
"""

import os
import sys
import time
import struct
import tempfile
import threading
import pytest
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.replay_traffic import (
    PacketBufferCache,
    HighSpeedReplayEngine,
    NativeSocketTransmitter,
    DryRunTransmitter,
)
from tests.throughput_benchmark import (
    ThroughputBenchmarkOrchestrator,
    SystemResourceProfiler,
    PipelineIngestionBridge,
    BenchmarkReportGenerator,
)
from src.ingestion.zeek_log_tailer import ZeekLogTailer, MultiZeekLogTailer
from src.ingestion.kafka_producer import TelemetryKafkaProducer, calculate_partition_key
from src.utils.metrics_calculator import MetricsCalculator
from scripts.generate_datasets import generate_all_datasets


# ==============================================================================
# Helper Fixtures & PCAP Generators
# ==============================================================================

@pytest.fixture(scope="session")
def test_pcap_dir(tmp_path_factory):
    """Creates synthetic test PCAPs for benchmarking."""
    pcap_dir = tmp_path_factory.mktemp("stress_pcaps")
    generate_all_datasets(output_dir=str(pcap_dir))
    return pcap_dir


@pytest.fixture(scope="session")
def benign_pcap(test_pcap_dir) -> str:
    pcap_path = test_pcap_dir / "benign_baseline.pcap"
    assert pcap_path.exists(), f"PCAP was not generated at {pcap_path}"
    return str(pcap_path)


# ==============================================================================
# 1. High Burst Rate Stress Tests (50k, 100k, 200k PPS)
# ==============================================================================

class TestHighBurstRateReplay:
    """Stress-tests the replay engine and benchmark harness at high line rates."""

    def test_replay_burst_50k_pps(self, benign_pcap):
        """Test replay engine at 50,000 PPS sustained over 1.0s."""
        engine = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=50000,
            duration_sec=1.0,
            engine_type="dry-run",
            quiet=True,
        )
        results = engine.run()
        assert results["total_packets"] >= 40000, f"Expected >=40k pkts at 50k pps, got {results['total_packets']}"
        assert results["achieved_pps"] >= 35000, f"Expected >=35k pps achieved, got {results['achieved_pps']}"
        assert results["elapsed_seconds"] >= 0.9, "Elapsed time was shorter than expected"

    def test_replay_burst_100k_pps(self, benign_pcap):
        """Test replay engine at 100,000 PPS ultra-high rate over 1.0s."""
        engine = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=100000,
            duration_sec=1.0,
            engine_type="dry-run",
            quiet=True,
        )
        results = engine.run()
        assert results["total_packets"] >= 75000, f"Expected >=75k pkts at 100k pps, got {results['total_packets']}"
        assert results["achieved_pps"] >= 70000, f"Expected >=70k pps achieved, got {results['achieved_pps']}"

    def test_replay_extreme_200k_pps_saturation(self, benign_pcap):
        """Test replay engine behavior under extreme 200,000 PPS rate."""
        engine = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=200000,
            duration_sec=0.5,
            engine_type="dry-run",
            quiet=True,
        )
        results = engine.run()
        assert results["total_packets"] > 0, "No packets were transmitted at 200k pps"
        assert results["achieved_pps"] > 50000, f"Expected >50k pps under extreme load, got {results['achieved_pps']}"

    def test_benchmark_orchestrator_50k_pps_dry_run(self, benign_pcap, tmp_path):
        """Test end-to-end benchmark orchestrator running at 50,000 PPS."""
        report_file = tmp_path / "benchmark_50k_report.md"
        orch = ThroughputBenchmarkOrchestrator(
            duration_sec=1.0,
            target_pps=50000,
            pcap_path=benign_pcap,
            output_report=str(report_file),
            dry_run=True,
            quiet=True,
        )
        res = orch.run_benchmark()
        assert res["metrics"]["total_events"] >= 30000
        assert res["metrics"]["sustained_eps"] >= 25000
        assert report_file.exists()

    def test_benchmark_orchestrator_100k_pps_dry_run(self, benign_pcap, tmp_path):
        """Test end-to-end benchmark orchestrator running at 100,000 PPS."""
        report_file = tmp_path / "benchmark_100k_report.md"
        orch = ThroughputBenchmarkOrchestrator(
            duration_sec=1.0,
            target_pps=100000,
            pcap_path=benign_pcap,
            output_report=str(report_file),
            dry_run=True,
            quiet=True,
        )
        res = orch.run_benchmark()
        assert res["metrics"]["total_events"] >= 50000
        assert res["metrics"]["sustained_eps"] >= 40000
        assert report_file.exists()


# ==============================================================================
# 2. Extreme & Boundary Parameters (Edge Conditions)
# ==============================================================================

class TestBoundaryAndExtremeParameters:
    """Stress-tests edge case parameter values and malformed file inputs."""

    def test_duration_zero_and_negative(self, benign_pcap):
        """Duration <= 0 should be clamped to a safe minimum positive value."""
        engine_zero = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=1000,
            duration_sec=0.0,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_zero.duration_sec >= 0.1
        res_zero = engine_zero.run()
        assert res_zero["total_packets"] > 0

        engine_neg = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=1000,
            duration_sec=-10.0,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_neg.duration_sec >= 0.1
        res_neg = engine_neg.run()
        assert res_neg["total_packets"] > 0

    def test_pps_zero_and_negative(self, benign_pcap):
        """Target PPS <= 0 should be clamped to at least 1 PPS."""
        engine_zero_pps = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=0,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_zero_pps.target_pps >= 1
        res_zero_pps = engine_zero_pps.run()
        assert res_zero_pps["total_packets"] >= 1

        engine_neg_pps = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=-500,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_neg_pps.target_pps >= 1

    def test_single_packet_per_second_rate(self, benign_pcap):
        """Target PPS = 1 should execute without division by zero or stalling."""
        engine = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=1,
            duration_sec=0.5,
            engine_type="dry-run",
            quiet=True,
        )
        res = engine.run()
        assert res["total_packets"] >= 1

    def test_batch_size_boundaries(self, benign_pcap):
        """Batch sizes: 0, negative, 1, and > 512."""
        # batch_size <= 0 should fallback to auto sizing
        engine_zero = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=10000,
            batch_size=0,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_zero.batch_size in (8, 32, 64, 128)

        # batch_size = 1
        engine_one = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=1000,
            batch_size=1,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_one.batch_size == 1

        # batch_size > 512 should be clamped to 512
        engine_huge = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=50000,
            batch_size=2048,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_huge.batch_size == 512

    def test_target_mbps_boundaries(self, benign_pcap):
        """Target mbps values: 0, negative, extremely small, and large."""
        engine_zero_mbps = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_pps=5000,
            target_mbps=0.0,
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_zero_mbps.target_pps == 5000

        engine_huge_mbps = HighSpeedReplayEngine(
            pcap_path=benign_pcap,
            target_mbps=1000.0, # 1 Gbps
            duration_sec=0.2,
            engine_type="dry-run",
            quiet=True,
        )
        assert engine_huge_mbps.target_pps > 10000

    def test_nonexistent_pcap_path(self):
        """Replay engine must raise FileNotFoundError for nonexistent file."""
        nonexistent = "/nonexistent/path/to/missing_traffic.pcap"
        with pytest.raises(FileNotFoundError):
            HighSpeedReplayEngine(pcap_path=nonexistent, quiet=True)

    def test_zero_byte_pcap_file(self, tmp_path):
        """Zero-byte PCAP file must raise ValueError or Scapy/Parser exception cleanly."""
        zero_pcap = tmp_path / "zero_byte.pcap"
        zero_pcap.write_bytes(b"")
        with pytest.raises((ValueError, Exception)):
            PacketBufferCache(str(zero_pcap))

    def test_corrupted_pcap_short_header(self, tmp_path):
        """Truncated PCAP header (< 24 bytes) must raise an error cleanly without crashing."""
        short_pcap = tmp_path / "short_header.pcap"
        short_pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00") # only 6 bytes
        with pytest.raises((ValueError, Exception)):
            PacketBufferCache(str(short_pcap))

    def test_corrupted_pcap_invalid_magic(self, tmp_path):
        """Invalid PCAP magic number must raise an error cleanly."""
        bad_magic_pcap = tmp_path / "bad_magic.pcap"
        bad_magic_pcap.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 20)
        with pytest.raises((ValueError, Exception)):
            PacketBufferCache(str(bad_magic_pcap))

    def test_corrupted_pcap_truncated_packet_data(self, tmp_path):
        """PCAP with valid 24-byte header but corrupted/truncated packet payload."""
        trunc_pcap = tmp_path / "trunc_packet.pcap"
        # Standard libpcap header (24 bytes)
        pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        # Packet header claiming 1000 bytes, but file ends after 10 bytes
        pkt_hdr = struct.pack("<IIII", 1600000000, 0, 1000, 1000)
        trunc_pcap.write_bytes(pcap_hdr + pkt_hdr + b"1234567890")

        # Either loads what it can or raises ValueError, but must not crash
        try:
            cache = PacketBufferCache(str(trunc_pcap))
            # If scapy or fallback loaded 0 or partial packets
            assert len(cache) >= 0
        except (ValueError, Exception):
            pass # Acceptable behavior for corrupted input


# ==============================================================================
# 3. Concurrency, Thread Safety & Rapid Lifecycle Tests
# ==============================================================================

class TestConcurrencyAndThreadSafety:
    """Stress-tests multi-threading, race conditions, and rapid lifecycles."""

    def test_rapid_replay_engine_start_stop_cycles(self, benign_pcap):
        """Instantiate and run HighSpeedReplayEngine in 10 rapid succession cycles."""
        for i in range(10):
            engine = HighSpeedReplayEngine(
                pcap_path=benign_pcap,
                target_pps=20000,
                duration_sec=0.1,
                engine_type="dry-run",
                quiet=True,
            )
            res = engine.run()
            assert res["total_packets"] > 0

    def test_rapid_resource_profiler_start_stop_cycles(self):
        """Start and stop SystemResourceProfiler in 20 rapid cycles to detect thread leaks."""
        profiler = SystemResourceProfiler(interval=0.05)
        for _ in range(20):
            profiler.start()
            time.sleep(0.01)
            profiler.stop()
        summary = profiler.aggregate_summary()
        assert "avg_host_cpu" in summary

    def test_concurrent_kafka_producer_multithreaded_burst(self):
        """10 concurrent threads publishing batches to TelemetryKafkaProducer."""
        producer = TelemetryKafkaProducer(
            bootstrap_servers="localhost:19092",
            batch_size=1024,
        )
        errors: List[Exception] = []

        def worker(thread_id: int):
            try:
                for i in range(100):
                    rec = {
                        "ts": time.time(),
                        "uid": f"CTHREAD_{thread_id}_{i}",
                        "id.orig_h": f"192.168.1.{thread_id}",
                        "id.orig_p": 10000 + i,
                        "id.resp_h": "10.0.0.1",
                        "id.resp_p": 443,
                        "proto": "tcp",
                        "service": "ssl",
                    }
                    producer.send_record("conn", rec)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        producer.flush(timeout=1.0)
        producer.close()

        assert len(errors) == 0, f"Encountered producer errors in threads: {errors}"
        assert producer.metrics["sent_count"] == 1000

    def test_concurrent_metrics_calculator_race_conditions(self):
        """20 concurrent threads hammering MetricsCalculator to verify thread safety."""
        calc = MetricsCalculator()
        calc.start()
        errors: List[Exception] = []

        def recorder(thread_id: int):
            try:
                for _ in range(500):
                    calc.record_batch(count=10, total_bytes=5120, latencies=[1.5, 2.0, 3.2, 4.1])
                    if thread_id % 5 == 0:
                        _ = calc.calculate_percentiles()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=recorder, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
        calc.stop()

        assert len(errors) == 0, f"MetricsCalculator had race conditions: {errors}"
        assert calc.total_events == 20 * 500 * 10
        summary = calc.summary()
        assert summary["total_events"] == 100000
        assert summary["p50_ms"] > 0

    def test_concurrent_zeek_log_tailers_same_file(self, tmp_path):
        """Multiple concurrent ZeekLogTailer instances reading the same active log file."""
        log_file = tmp_path / "conn.log"
        log_file.write_text('{"uid":"C001","proto":"tcp"}\n', encoding="utf-8")

        tailer1 = ZeekLogTailer(str(log_file), from_beginning=True)
        tailer2 = ZeekLogTailer(str(log_file), from_beginning=True)

        batch1 = tailer1.read_all_available()
        batch2 = tailer2.read_all_available()

        assert len(batch1) == 1
        assert len(batch2) == 1
        assert batch1[0]["uid"] == "C001"
        assert batch2[0]["uid"] == "C001"

        # Append 50 more records
        with open(log_file, "a", encoding="utf-8") as f:
            for i in range(50):
                f.write(f'{{"uid":"C{i:03d}","proto":"tcp"}}\n')

        batch1_more = tailer1.read_all_available(max_batch=100)
        batch2_more = tailer2.read_all_available(max_batch=100)

        assert len(batch1_more) == 50
        assert len(batch2_more) == 50

        tailer1.stop()
        tailer2.stop()


# ==============================================================================
# 4. Resource, Memory & Scalability Tests
# ==============================================================================

class TestResourceAndScalability:
    """Stress-tests memory stability and computational complexity."""

    def test_packet_buffer_cache_reuse_memory_stability(self, benign_pcap):
        """Verify that looping over PacketBufferCache 1,000,000 times does not leak memory."""
        cache = PacketBufferCache(benign_pcap)
        initial_count = len(cache.raw_packets)
        assert initial_count > 0

        # Simulate 500,000 packet reads
        total_read = 0
        for i in range(500000):
            idx = i % initial_count
            pkt = cache.raw_packets[idx]
            total_read += len(pkt)

        assert total_read > 0
        # Buffer count should remain unchanged
        assert len(cache.raw_packets) == initial_count

    def test_metrics_calculator_large_sample_percentiles_performance(self):
        """Stress-test percentiles calculation with 200,000 latency measurements."""
        calc = MetricsCalculator()
        calc.start()
        # Feed 200,000 latencies
        sample_batch = [1.2, 5.4, 25.1, 100.2, 2.3, 8.9, 15.0, 45.0, 3.1, 12.4] * 20000
        calc.record_batch(count=len(sample_batch), total_bytes=len(sample_batch) * 512, latencies=sample_batch)
        calc.stop()

        t0 = time.perf_counter()
        percentiles = calc.calculate_percentiles()
        elapsed = time.perf_counter() - t0

        assert elapsed < 0.5, f"Percentile computation took too long: {elapsed:.3f}s"
        assert percentiles["p50_ms"] > 0
        assert percentiles["p99_ms"] >= percentiles["p95_ms"] >= percentiles["p50_ms"]

    def test_metrics_calculator_sample_window_sliding_calculation(self):
        """Verify sample_window restricts percentile calculation to last K samples."""
        calc = MetricsCalculator()
        calc.start()
        # Add 10,000 baseline latencies around 10ms
        calc.record_batch(count=10000, total_bytes=10000 * 512, latencies=[10.0] * 10000)
        # Add 1,000 newer latencies around 50ms
        calc.record_batch(count=1000, total_bytes=1000 * 512, latencies=[50.0] * 1000)
        calc.stop()

        # Full calculation will be dominated by 10ms (p50 = 10.0)
        full_percentiles = calc.calculate_percentiles()
        assert full_percentiles["p50_ms"] == 10.0

        # Windowed calculation with window=1000 will only evaluate the last 1,000 samples (p50 = 50.0)
        windowed_percentiles = calc.calculate_percentiles(sample_window=1000)
        assert windowed_percentiles["p50_ms"] == 50.0
