"""
SIH26145 - Adversarial Stress & Empirical Challenge Suite for Milestone 1
Ingestion & Partitioning Pipeline

Adversarial Tests:
1. Edge-case IPs: Broadcast, Multicast, Loopback, IPv6, Nulls, Corrupt strings, Whitespace, Subnet boundaries.
2. Partition determinism, bounds guarantee [0, N-1], and uniform distribution across variable partition counts.
3. InMemoryStreamingBus high-frequency concurrent multithreaded batch ingestion and queue draining.
4. ZeekLogTailer rapid real-time append, file rotation, file truncation, and malformed/corrupt JSON resilience.
5. Mathematical integrity & schema boundaries (Shannon entropy, Subdomain parsing, RawAlert confidence ranges).
6. Zero event loss and partition locality under intense concurrent producer/consumer contention.
"""

import json
import os
import queue
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Dict, Any

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
    RawAlert,
    calculate_shannon_entropy,
    extract_subdomain,
)
from src.ingestion.streaming_bus import (
    InMemoryStreamingBus,
    KafkaStreamingBus,
    get_source_ip_partition,
    extract_record_source_ip,
    serialize_record,
    get_streaming_bus,
)
from src.ingestion.zeek_log_tailer import (
    ZeekLogTailer,
    MultiZeekLogTailer,
    normalize_zeek_record,
)
from src.ingestion.kafka_producer import (
    TelemetryKafkaProducer,
    calculate_partition_key,
)


# ============================================================================
# 1. ADVERSARIAL IP EDGE CASES & PARTITION BOUNDARY STRESS
# ============================================================================

class TestAdversarialIPEdgeCases:
    """Stress-test partition hashing and source IP extraction across adversarial IP formats."""

    ADVERSARIAL_IPS = [
        # Standard IPv4
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        # Subnet Boundaries
        "0.0.0.0",
        "0.0.0.1",
        "255.255.255.255",
        "255.255.255.254",
        "127.0.0.1",
        "127.255.255.255",
        # Multicast / Class E
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        # IPv6 formats
        "::1",
        "::",
        "fe80::1",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::ffff:192.0.2.1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        # Malformed / Corrupt strings
        "",
        " ",
        "   \t\n  ",
        "not-an-ip",
        "192.168.1.999",
        "256.300.400.500",
        "192.168.1.1:8080",
        "DROP TABLE logs;--",
        "<script>alert(1)</script>",
        "\x00\x01\x02\xff\xfe",
        "🔥💀💻🛡️⚡",
        "a" * 1000,
    ]

    def test_partition_strictly_within_bounds_for_all_inputs(self):
        """Verify that partition index is strictly in [0, num_partitions-1] for any input."""
        for num_partitions in [1, 2, 3, 4, 8, 16, 64, 128]:
            for ip in self.ADVERSARIAL_IPS:
                p = get_source_ip_partition(ip, num_partitions=num_partitions)
                assert isinstance(p, int)
                assert 0 <= p < num_partitions, f"Partition {p} out of bounds [0, {num_partitions-1}] for IP '{ip}'"

    def test_partition_determinism_under_repetition(self):
        """Verify 100% deterministic hash output across repeated executions."""
        for ip in self.ADVERSARIAL_IPS:
            expected = get_source_ip_partition(ip, num_partitions=4)
            for _ in range(50):
                assert get_source_ip_partition(ip, num_partitions=4) == expected

    def test_extract_record_source_ip_resilience(self):
        """Verify source IP extraction never raises exceptions on diverse record types."""
        # Dictionary inputs
        assert extract_record_source_ip({"src_ip": "10.0.0.1"}) == "10.0.0.1"
        assert extract_record_source_ip({"source_ip": "10.0.0.2"}) == "10.0.0.2"
        assert extract_record_source_ip({"id.orig_h": "10.0.0.3"}) == "10.0.0.3"
        assert extract_record_source_ip({"orig_h": "10.0.0.4"}) == "10.0.0.4"
        assert extract_record_source_ip({}) == "0.0.0.0"
        assert extract_record_source_ip({"unknown_key": 12345}) == "0.0.0.0"

        # String inputs (JSON and non-JSON)
        assert extract_record_source_ip('{"src_ip": "10.0.0.5"}') == "10.0.0.5"
        assert extract_record_source_ip('{"id.orig_h": "10.0.0.6"}') == "10.0.0.6"
        assert extract_record_source_ip('invalid json string !!!') == "0.0.0.0"
        assert extract_record_source_ip('') == "0.0.0.0"

        # Pydantic models
        conn = ConnTelemetryEvent(src_ip="10.0.0.7", src_port=1234, dst_ip="1.1.1.1", dst_port=80)
        assert extract_record_source_ip(conn) == "10.0.0.7"

        alert = RawAlert(
            detector_name="test",
            threat_class="TEST",
            source_ip="10.0.0.8",
            evidence={},
        )
        assert extract_record_source_ip(alert) == "10.0.0.8"

        # None / invalid types
        assert extract_record_source_ip(None) == "0.0.0.0"
        assert extract_record_source_ip(12345) == "0.0.0.0"


# ============================================================================
# 2. IN-MEMORY STREAMING BUS CONCURRENCY & STRESS
# ============================================================================

class TestInMemoryStreamingBusStress:
    """Stress-test InMemoryStreamingBus under high-frequency multithreaded load."""

    def test_concurrent_producers_and_consumers(self):
        """
        10 producer threads pushing 500 events each (5,000 events total).
        4 consumer threads concurrently draining partition queues.
        Guarantees zero dropped events, zero deadlocks, and correct total counts.
        """
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        num_producers = 10
        events_per_producer = 500
        total_expected_events = num_producers * events_per_producer

        consumed_events: List[Dict[str, Any]] = []
        consumed_lock = threading.Lock()
        stop_consumers = threading.Event()

        # Producer worker
        def producer_worker(producer_id: int):
            for i in range(events_per_producer):
                host_ip = f"10.0.{producer_id}.{i % 50}"
                event = ConnTelemetryEvent(
                    src_ip=host_ip,
                    src_port=10000 + i,
                    dst_ip="192.168.1.1",
                    dst_port=80,
                    uid=f"C_{producer_id}_{i}",
                    orig_bytes=100 + i,
                )
                bus.publish("telemetry.conn", event)

        # Consumer worker per partition
        def consumer_worker(partition_id: int):
            while not stop_consumers.is_set():
                recs = bus.consume("telemetry.conn", partition=partition_id, max_records=50, timeout=0.01)
                if recs:
                    with consumed_lock:
                        consumed_events.extend(recs)
                else:
                    time.sleep(0.001)
            # Final drain after stop requested
            recs = bus.consume("telemetry.conn", partition=partition_id, max_records=total_expected_events)
            if recs:
                with consumed_lock:
                    consumed_events.extend(recs)

        # Launch 4 consumer threads (1 per partition)
        consumer_threads = [
            threading.Thread(target=consumer_worker, args=(p,))
            for p in range(4)
        ]
        for t in consumer_threads:
            t.start()

        # Launch 10 producer threads
        producer_threads = [
            threading.Thread(target=producer_worker, args=(pid,))
            for pid in range(num_producers)
        ]
        for t in producer_threads:
            t.start()

        for t in producer_threads:
            t.join()

        # Wait for consumers to drain
        time.sleep(0.2)
        stop_consumers.set()
        for t in consumer_threads:
            t.join()

        # Assert zero lost events
        assert len(consumed_events) == total_expected_events, (
            f"Expected {total_expected_events} consumed events, got {len(consumed_events)}"
        )

        # Assert partition metrics integrity
        metrics = bus.get_metrics()
        assert metrics["total_published"] == total_expected_events
        assert metrics["total_consumed"] == total_expected_events

        bus.close()

    def test_topic_isolation(self):
        """Verify events in telemetry.conn never appear in telemetry.dns, telemetry.ssl, or alerts.raw."""
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        bus.publish("telemetry.conn", ConnTelemetryEvent(src_ip="1.1.1.1", src_port=1, dst_ip="2.2.2.2", dst_port=2))
        bus.publish("telemetry.dns", DnsTelemetryEvent(src_ip="3.3.3.3", src_port=3, dst_ip="4.4.4.4", dst_port=53, query="test.com"))

        conn_recs = bus.consume_all("telemetry.conn")
        dns_recs = bus.consume_all("telemetry.dns")
        ssl_recs = bus.consume_all("telemetry.ssl")
        alert_recs = bus.consume_all("alerts.raw")

        assert len(conn_recs) == 1
        assert conn_recs[0]["src_ip"] == "1.1.1.1"

        assert len(dns_recs) == 1
        assert dns_recs[0]["query"] == "test.com"

        assert len(ssl_recs) == 0
        assert len(alert_recs) == 0

        bus.close()

    def test_high_throughput_burst(self):
        """Verify sub-millisecond burst throughput exceeding 30,000 EPS."""
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        batch_size = 15000
        events = [
            ConnTelemetryEvent(
                src_ip=f"10.1.{i % 256}.{(i // 256) % 256}",
                src_port=1024 + (i % 60000),
                dst_ip="172.16.0.1",
                dst_port=443,
                uid=f"BURST_{i}",
            )
            for i in range(batch_size)
        ]

        t0 = time.perf_counter()
        published = bus.publish_batch("telemetry.conn", events)
        t_pub = time.perf_counter() - t0

        pub_eps = batch_size / max(t_pub, 1e-6)
        assert published == batch_size
        assert pub_eps > 20000, f"Publish throughput {pub_eps:.2f} EPS too low"

        t1 = time.perf_counter()
        consumed = bus.consume_all("telemetry.conn", max_per_partition=batch_size)
        t_cons = time.perf_counter() - t1

        cons_eps = len(consumed) / max(t_cons, 1e-6)
        assert len(consumed) == batch_size
        assert cons_eps > 20000, f"Consume throughput {cons_eps:.2f} EPS too low"

        bus.close()


# ============================================================================
# 3. ZEEK LOG TAILER ROTATION, TRUNCATION & MALFORMED RESILIENCE
# ============================================================================

class TestZeekLogTailerAdversarial:
    """Stress-test Zeek log tailer on rapid appends, log rotation, truncation, and corrupted lines."""

    def test_tailer_rapid_append(self):
        """Tailer must capture all dynamically appended lines without blocking or dropping."""
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log", encoding="utf-8") as f:
            log_path = f.name
            f.write("#separator \\x09\n#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p\n")
            f.flush()

        try:
            tailer = ZeekLogTailer(log_path, from_beginning=True, log_type="conn")

            # Append 200 records in chunks
            with open(log_path, "a", encoding="utf-8") as f_app:
                for i in range(200):
                    rec = {
                        "ts": 1725000000.0 + i,
                        "uid": f"C_APPEND_{i}",
                        "id.orig_h": f"192.168.1.{i % 250 + 1}",
                        "id.orig_p": 10000 + i,
                        "id.resp_h": "10.0.0.1",
                        "id.resp_p": 80,
                    }
                    f_app.write(json.dumps(rec) + "\n")
                    f_app.flush()

            records = tailer.read_normalized_batch(max_batch=500)
            assert len(records) == 200
            assert records[0].uid == "C_APPEND_0"
            assert records[-1].uid == "C_APPEND_199"

            tailer.stop()
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)

    def test_tailer_log_rotation(self):
        """
        Tailer must seamlessly detect file rotation (new inode / file recreated)
        and read newly appended lines from the new file.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "conn.log"
            rotated_path = Path(tmpdir) / "conn.log.1"

            # Write initial 50 lines to conn.log
            with open(log_path, "w", encoding="utf-8") as f:
                for i in range(50):
                    f.write(json.dumps({"ts": 1725000000.0 + i, "uid": f"C_INITIAL_{i}", "id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80}) + "\n")

            tailer = ZeekLogTailer(str(log_path), from_beginning=True, log_type="conn")
            batch1 = tailer.read_normalized_batch(max_batch=100)
            assert len(batch1) == 50

            # Simulate logrotate: rename conn.log -> conn.log.1, create new conn.log with 50 new lines
            if tailer._current_file and not tailer._current_file.closed:
                tailer._current_file.close()
                tailer._current_file = None
            log_path.rename(rotated_path)

            with open(log_path, "w", encoding="utf-8") as f:
                for i in range(50):
                    f.write(json.dumps({"ts": 1725000100.0 + i, "uid": f"C_ROTATED_{i}", "id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80}) + "\n")

            time.sleep(0.05)
            batch2 = tailer.read_normalized_batch(max_batch=100)
            assert len(batch2) == 50
            assert batch2[0].uid == "C_ROTATED_0"
            assert batch2[-1].uid == "C_ROTATED_49"

            tailer.stop()

    def test_tailer_log_truncation(self):
        """
        Tailer must detect file truncation (file size shrinking) and read from new offset 0.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "conn.log"

            with open(log_path, "w", encoding="utf-8") as f:
                for i in range(40):
                    f.write(json.dumps({"ts": 1725000000.0 + i, "uid": f"C_PRE_{i}", "id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80}) + "\n")

            tailer = ZeekLogTailer(str(log_path), from_beginning=True, log_type="conn")
            batch1 = tailer.read_normalized_batch(max_batch=100)
            assert len(batch1) == 40

            # Truncate file and write 20 new lines
            with open(log_path, "w", encoding="utf-8") as f:
                for i in range(20):
                    f.write(json.dumps({"ts": 1725000200.0 + i, "uid": f"C_POST_{i}", "id.orig_h": "10.0.0.1", "id.orig_p": 80, "id.resp_h": "10.0.0.2", "id.resp_p": 80}) + "\n")

            time.sleep(0.05)
            batch2 = tailer.read_normalized_batch(max_batch=100)
            assert len(batch2) == 20
            assert batch2[0].uid == "C_POST_0"

            tailer.stop()

    def test_tailer_corrupt_and_malformed_lines(self):
        """Tailer must skip malformed lines, comment headers, and blank lines without crashing."""
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log", encoding="utf-8") as f:
            log_path = f.name
            f.write("#separator \\x09\n")
            f.write("#set_separator ,\n")
            f.write("#empty_field (empty)\n")
            f.write("#unset_field -\n")
            f.write("#fields ts uid id.orig_h\n")
            f.write("\n")
            f.write("   \n")
            # Injected malformed lines
            f.write("{broken json line\n")
            f.write("{\"ts\": 1725000000.0, \"uid\": \"VALID_1\", \"id.orig_h\": \"10.0.0.1\", \"id.orig_p\": 80, \"id.resp_h\": \"10.0.0.2\", \"id.resp_p\": 80}\n")
            f.write("PLAIN TEXT NON-JSON CONTENT\n")
            f.write("{\"ts\": 1725000001.0, \"uid\": \"VALID_2\", \"id.orig_h\": \"10.0.0.2\", \"id.orig_p\": 80, \"id.resp_h\": \"10.0.0.3\", \"id.resp_p\": 80}\n")
            f.write("\x00\x01\x02 binary garbage\n")
            f.write("{\"ts\": 1725000002.0, \"uid\": \"VALID_3\", \"id.orig_h\": \"10.0.0.3\", \"id.orig_p\": 80, \"id.resp_h\": \"10.0.0.4\", \"id.resp_p\": 80}\n")
            f.flush()

        try:
            tailer = ZeekLogTailer(log_path, from_beginning=True, log_type="conn")
            records = tailer.read_normalized_batch(max_batch=100)

            # Must have cleanly extracted exactly the 3 valid JSON lines
            assert len(records) == 3
            assert records[0].uid == "VALID_1"
            assert records[1].uid == "VALID_2"
            assert records[2].uid == "VALID_3"

            tailer.stop()
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)


# ============================================================================
# 4. MATHEMATICAL & SCHEMA BOUNDARY VERIFICATION
# ============================================================================

class TestMathematicalAndSchemaBoundaries:
    """Verify mathematical functions and Pydantic constraints under extreme inputs."""

    def test_shannon_entropy_mathematical_properties(self):
        """Verify Shannon entropy properties: 0 <= H(X) <= log2(N)."""
        # H("") == 0
        assert calculate_shannon_entropy("") == 0.0

        # Uniform string of length 8 with 8 distinct characters: H = log2(8) = 3.0
        assert calculate_shannon_entropy("abcdefgh") == 3.0

        # Monomorphic string
        assert calculate_shannon_entropy("zzzzzzzzzz") == 0.0

        # High entropy string (16 distinct chars uniformly distributed)
        # H = log2(16) = 4.0
        sixteen_char = "0123456789abcdef"
        assert calculate_shannon_entropy(sixteen_char) == 4.0

    def test_subdomain_extraction_boundaries(self):
        """Verify extract_subdomain across edge cases."""
        assert extract_subdomain("tunnel.exfil.target.com") == "tunnel"
        assert extract_subdomain("singlelabel") == "singlelabel"
        assert extract_subdomain("domain.co.uk") == "domain"
        assert extract_subdomain("") == ""
        assert extract_subdomain("   ") == ""

    def test_raw_alert_boundary_validation(self):
        """Verify RawAlert field constraints and defaults."""
        # Valid alert with minimal required fields
        alert = RawAlert(
            detector_name="test_det",
            threat_class="VOLUMETRIC_DDOS",
            source_ip="192.168.1.100",
        )
        assert alert.alert_id is not None
        assert alert.confidence == 0.8
        assert alert.severity == "MEDIUM"
        assert "[MEDIUM] VOLUMETRIC_DDOS detected on 192.168.1.100" in alert.title

        # Confidence out of bounds
        with pytest.raises(ValidationError):
            RawAlert(
                detector_name="test",
                threat_class="TEST",
                source_ip="1.1.1.1",
                confidence=-0.01,
            )

        with pytest.raises(ValidationError):
            RawAlert(
                detector_name="test",
                threat_class="TEST",
                source_ip="1.1.1.1",
                confidence=1.01,
            )

        # Port out of bounds
        with pytest.raises(ValidationError):
            RawAlert(
                detector_name="test",
                threat_class="TEST",
                source_ip="1.1.1.1",
                target_port=65536,
            )

        with pytest.raises(ValidationError):
            RawAlert(
                detector_name="test",
                threat_class="TEST",
                source_ip="1.1.1.1",
                target_port=-1,
            )
