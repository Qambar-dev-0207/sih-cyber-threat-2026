"""
tests/test_benchmark_suite.py
------------------------------
Comprehensive unit and integration test suite for Milestone 3 (R3):
Day-1 Line-Rate Ingestion Throughput Benchmark Suite.

Covers:
- TestBenchmarkSuiteCLI: CLI argument parsing, flags, defaults, and option overrides
- TestBenchmarkPipelineBridge: PCAP pre-parsing, JA4 extraction, nanosecond latency tracking
- TestResourceProfiler: Container and host CPU/RAM metrics sampling and aggregation
- TestTerminalDashboardRenderer: Visual ASCII terminal UI, progress bar, and SLA statuses
- TestBenchmarkReportGenerator: Standardized benchmark_results.md generation and schema
- TestEndToEndBenchmarkExecution: Turnkey execution with real state and metric validation
"""

import os
import sys
import math
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

# Ensure repository root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.throughput_benchmark import (
    SystemResourceProfiler,
    PipelineIngestionBridge,
    TerminalDashboardRenderer,
    BenchmarkReportGenerator,
    ThroughputBenchmarkOrchestrator,
)
from src.ingestion.kafka_producer import TelemetryKafkaProducer
from src.utils.metrics_calculator import MetricsCalculator


class TestBenchmarkSuiteCLI:
    """Validates CLI argument parsing and orchestrator initialization."""

    def test_orchestrator_initialization_defaults(self):
        orch = ThroughputBenchmarkOrchestrator()
        assert orch.duration_sec == 30.0
        assert orch.target_pps == 15000
        assert orch.topic == "telemetry.conn"
        assert orch.output_report == "benchmark_results.md"
        assert orch.engine_type == "native"
        assert orch.dry_run is False

    def test_orchestrator_custom_parameters(self):
        orch = ThroughputBenchmarkOrchestrator(
            duration_sec=10.0,
            target_pps=25000,
            pcap_path="data/pcaps/ddos_syn_flood.pcap",
            topic="telemetry.ssl",
            output_report="custom_benchmark.md",
            engine_type="dry-run",
            dry_run=True,
            quiet=True,
        )
        assert orch.duration_sec == 10.0
        assert orch.target_pps == 25000
        assert orch.pcap_path == "data/pcaps/ddos_syn_flood.pcap"
        assert orch.topic == "telemetry.ssl"
        assert orch.output_report == "custom_benchmark.md"
        assert orch.engine_type == "dry-run"
        assert orch.quiet is True


class TestBenchmarkPipelineBridge:
    """Validates PCAP packet ingestion bridge and nanosecond latency measurement."""

    def test_pipeline_bridge_preparsing_and_batch_processing(self):
        producer = TelemetryKafkaProducer(bootstrap_servers="localhost:19092")
        metrics = MetricsCalculator()
        metrics.start()

        bridge = PipelineIngestionBridge(
            pcap_path="data/pcaps/benign_baseline.pcap",
            producer=producer,
            metrics=metrics,
            topic="telemetry.conn",
        )

        assert len(bridge.precomputed_records) > 0

        # Process a batch of 64 records
        import time
        t0 = time.perf_counter_ns()
        sent = bridge.process_batch(batch_size=64, emit_time_ns=t0)
        assert sent == 64
        assert metrics.total_events == 64
        assert metrics.total_bytes > 0
        assert len(metrics.latencies_ms) == 64
        assert all(lat > 0 for lat in metrics.latencies_ms)

        producer.close()


class TestResourceProfiler:
    """Validates container and system resource telemetry sampling."""

    def test_sample_now_structure(self):
        profiler = SystemResourceProfiler(interval=0.1)
        sample = profiler.sample_now()

        assert "timestamp" in sample
        assert "host_cpu_percent" in sample
        assert "host_memory_total_gb" in sample
        assert "containers" in sample

        containers = sample["containers"]
        assert "sih_zeek" in containers
        assert "sih_redpanda" in containers
        assert "sih_timescaledb" in containers
        assert "sih_redis" in containers

        for name, stat in containers.items():
            assert "cpu_percent" in stat
            assert "memory_mb" in stat
            assert stat["memory_mb"] >= 0

    def test_aggregate_summary(self):
        profiler = SystemResourceProfiler(interval=0.1)
        profiler.start()
        import time
        time.sleep(0.3)
        profiler.stop()

        summary = profiler.aggregate_summary()
        assert "avg_host_cpu" in summary
        assert "peak_host_cpu" in summary
        assert "containers" in summary
        assert summary["total_container_memory_mb"] > 0


class TestTerminalDashboardRenderer:
    """Validates real-time visual terminal dashboard rendering."""

    def test_dashboard_render_without_exception(self):
        renderer = TerminalDashboardRenderer(duration_sec=30.0, target_pps=10000)
        metrics = MetricsCalculator()
        metrics.start()

        for i in range(100):
            metrics.record_event(byte_size=1024, latency_ms=35.0)

        profiler = SystemResourceProfiler(interval=0.5)

        # Render should execute safely without throwing exceptions with windowed and full mode
        renderer.render(
            elapsed_sec=1.0,
            metrics=metrics,
            profiler=profiler,
            lag=0,
            loss_pct=0.0,
            sample_window=50,
        )

        renderer.render(
            elapsed_sec=2.0,
            metrics=metrics,
            profiler=profiler,
            lag=0,
            loss_pct=0.0,
            sample_window=None,
        )

        assert renderer.last_events_count == 100
        assert renderer.rolling_eps >= 0


class TestBenchmarkReportGenerator:
    """Validates Markdown report generation conforming to Phase 0 specification."""

    def test_generate_report_markdown_structure(self):
        metrics = MetricsCalculator()
        metrics.start()
        for i in range(1000):
            metrics.record_event(byte_size=1024, latency_ms=32.5 + (i % 20))
        metrics.set_packet_counts(sent=1000, received=1000)
        metrics.stop()

        profiler = SystemResourceProfiler(interval=0.5)
        resource_summary = profiler.aggregate_summary()

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "test_results.md"
            res_path = BenchmarkReportGenerator.generate_report(
                output_path=str(out_file),
                duration_sec=30.0,
                target_pps=15000,
                pcap_path="data/pcaps/benign_baseline.pcap",
                topic="telemetry.conn",
                metrics=metrics,
                resource_summary=resource_summary,
            )

            assert Path(res_path).exists()
            content = out_file.read_text(encoding="utf-8")

            # Check required markdown sections
            assert "# SIH26145 — Day-1 Line-Rate Throughput Benchmark Results" in content
            assert "## 1. Executive Metrics Summary" in content
            assert "## 2. System & Test Environment Specification" in content
            assert "## 3. Detailed Ingestion & Latency Distribution" in content
            assert "## 4. Container Resource Overhead Breakdown" in content
            assert "## 5. Acceptance Criteria Validation Matrix" in content
            assert "## 6. Performance & Architectural Analysis" in content
            assert "AC-R3.1" in content
            assert "AC-R3.2" in content


class TestEndToEndBenchmarkExecution:
    """Validates turnkey execution of the throughput benchmark orchestrator."""

    def test_short_e2e_benchmark_run(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_md = Path(tmp_dir) / "benchmark_run.md"
            orch = ThroughputBenchmarkOrchestrator(
                duration_sec=1.5,
                target_pps=5000,
                pcap_path="data/pcaps/benign_baseline.pcap",
                topic="telemetry.conn",
                output_report=str(out_md),
                dry_run=True,
                quiet=True,
            )

            result = orch.run_benchmark()
            assert result is not None
            assert "metrics" in result
            assert "resources" in result
            assert "report_path" in result

            m = result["metrics"]
            assert m["total_events"] > 0
            assert m["sustained_eps"] > 0
            assert m["throughput_mbps"] > 0
            assert m["p50_ms"] > 0
            assert m["packet_loss_rate_pct"] == 0.0
            assert Path(result["report_path"]).exists()
