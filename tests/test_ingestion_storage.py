"""
SIH26145 - Comprehensive Test Suite for Ingestion & Storage Python Modules
Tests ZeekLogTailer, MultiZeekLogTailer, TelemetryKafkaProducer, TimescaleDatabase, and MetricsCalculator.
"""

import os
import sys
import tempfile
import json
import time
from pathlib import Path
from datetime import datetime, timezone
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ingestion.zeek_log_tailer import ZeekLogTailer, MultiZeekLogTailer
from src.ingestion.kafka_producer import TelemetryKafkaProducer, calculate_partition_key
from src.storage.db import TimescaleDatabase, normalize_timestamp
from src.utils.metrics_calculator import MetricsCalculator


class TestZeekLogTailer:
    """Tests for real-time Zeek structured JSON log tailing."""

    def test_tail_single_line_and_batch(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log", encoding="utf-8") as tmp:
            tmp_path = tmp.name
            # Write header comments
            tmp.write("#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto\n")
            # Write JSON records
            rec1 = {"ts": 1700000001.0, "uid": "C101", "id.orig_h": "10.0.0.1", "id.orig_p": 12345, "id.resp_h": "1.1.1.1", "id.resp_p": 53, "proto": "udp"}
            rec2 = {"ts": 1700000002.0, "uid": "C102", "id.orig_h": "10.0.0.2", "id.orig_p": 54321, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"}
            tmp.write(json.dumps(rec1) + "\n")
            tmp.write(json.dumps(rec2) + "\n")
            tmp.flush()

        try:
            tailer = ZeekLogTailer(tmp_path, from_beginning=True)
            batches = tailer.read_all_available()
            assert len(batches) == 2
            assert batches[0]["uid"] == "C101"
            assert batches[1]["uid"] == "C102"
            assert "_tail_ts" in batches[0]
            tailer.stop()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_multi_zeek_tailer(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dir_path = Path(tmp_dir)
            conn_log = dir_path / "conn.log"
            dns_log = dir_path / "dns.log"
            ssl_log = dir_path / "ssl.log"

            conn_log.write_text(json.dumps({"ts": 1700000001.0, "uid": "C01", "proto": "tcp"}) + "\n", encoding="utf-8")
            dns_log.write_text(json.dumps({"ts": 1700000002.0, "uid": "D01", "query": "google.com"}) + "\n", encoding="utf-8")
            ssl_log.write_text(json.dumps({"ts": 1700000003.0, "uid": "S01", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"}) + "\n", encoding="utf-8")

            multi_tailer = MultiZeekLogTailer(str(dir_path), from_beginning=True)
            assert multi_tailer.get_tailer("conn") is not None
            assert multi_tailer.get_tailer("dns") is not None
            assert multi_tailer.get_tailer("ssl") is not None

            conn_records = multi_tailer.get_tailer("conn").read_all_available()
            assert len(conn_records) == 1
            assert conn_records[0]["uid"] == "C01"

            dns_records = multi_tailer.get_tailer("dns").read_all_available()
            assert len(dns_records) == 1
            assert dns_records[0]["query"] == "google.com"

            ssl_records = multi_tailer.get_tailer("ssl").read_all_available()
            assert len(ssl_records) == 1
            assert "ja4" in ssl_records[0]

            multi_tailer.stop_all()


class TestKafkaProducer:
    """Tests for Kafka/Redpanda telemetry publisher."""

    def test_partition_key_calculation(self):
        r1 = {"id.orig_h": "192.168.1.50"}
        assert calculate_partition_key(r1) == "192.168.1.50"

        r2 = {"source_ip": "10.20.30.40"}
        assert calculate_partition_key(r2) == "10.20.30.40"

        r3 = {"other": "value"}
        assert calculate_partition_key(r3) == "0.0.0.0"

    def test_producer_send_batch_and_metrics(self):
        producer = TelemetryKafkaProducer(bootstrap_servers="localhost:19092")
        records = [
            {"ts": 1700000000.0, "id.orig_h": "10.0.0.1", "proto": "tcp"},
            {"ts": 1700000001.0, "id.orig_h": "10.0.0.2", "proto": "udp"},
        ]
        sent = producer.send_batch("conn", records)
        assert sent == 2
        metrics = producer.metrics
        assert metrics["sent_count"] >= 2
        producer.close()


class TestTimescaleStorage:
    """Tests for TimescaleDB batch ingestion formatting and helpers."""

    def test_timestamp_normalization(self):
        dt = normalize_timestamp(1700000000.0)
        assert isinstance(dt, datetime)
        assert dt.year == 2023

        iso_dt = normalize_timestamp("2026-08-30T12:00:00Z")
        assert iso_dt.year == 2026

    def test_mock_timescale_batch_insertion(self):
        db = TimescaleDatabase(host="localhost", port=5432)
        records = [
            {
                "ts": 1700000000.0,
                "uid": "U1234",
                "id.orig_h": "192.168.1.10",
                "id.orig_p": 10000,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 53,
                "proto": "udp",
            }
        ]
        # In mock mode, returns len(records)
        assert db.insert_conn_telemetry_batch(records) == 1
        assert db.insert_dns_telemetry_batch(records) == 1
        assert db.insert_ssl_telemetry_batch(records) == 1
        assert db.insert_alert("c2_detector", "C2_BEACON", "HIGH", 0.95, "192.168.1.10", {"interval": 10.0}) is True
        assert db.record_system_metric(events_per_second=50000, packets_per_second=50000, megabits_per_second=350.5) is True
        db.close()


class TestMetricsCalculator:
    """Tests for metrics and line-rate calculations."""

    def test_sustained_eps_and_percentiles(self):
        calc = MetricsCalculator()
        calc.start()
        for i in range(500):
            calc.record_event(byte_size=1024, latency_ms=float(i % 10 + 1))
        calc.set_packet_counts(sent=500, received=500)
        calc.stop()

        res = calc.summary()
        assert res["total_events"] == 500
        assert res["total_bytes"] == 500 * 1024
        assert res["packet_loss_rate_pct"] == 0.0
        assert res["p50_ms"] > 0
        assert res["p95_ms"] >= res["p50_ms"]

        md = calc.format_markdown_table()
        assert "Sustained Events-Per-Second" in md
