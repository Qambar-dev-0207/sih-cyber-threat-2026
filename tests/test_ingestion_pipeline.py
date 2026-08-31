"""
SIH26145 - Comprehensive Test Suite for Milestone 1: Ingestion & Partitioning Pipeline
Validates:
1. Pydantic Telemetry Models (ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, RawAlert).
2. Deterministic 4-Partition Routing by Murmur3/hash(source_ip) % 4.
3. InMemoryStreamingBus & KafkaStreamingBus with topic routing.
4. ZeekLogTailer and MultiZeekLogTailer schema normalization and batch ingestion.
5. TelemetryKafkaProducer publishing and metrics.
6. High-throughput line-rate (>10,000 EPS) stress and partition locality verification.
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, List

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
    StreamingBus,
    InMemoryStreamingBus,
    KafkaStreamingBus,
    get_streaming_bus,
    get_source_ip_partition,
    extract_record_source_ip,
    serialize_record,
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


class TestTelemetryModels:
    """Test suite for Pydantic telemetry models and validation."""

    def test_conn_telemetry_event_from_zeek_dict(self):
        raw = {
            "ts": 1725000001.123456,
            "uid": "CHttpFlow12345678",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 0.452,
            "orig_bytes": 1024,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "orig_pkts": 10,
            "resp_pkts": 12,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "community_id": "1:abc123456==",
        }
        event = ConnTelemetryEvent.from_zeek_dict(raw)
        assert event.src_ip == "192.168.1.100"
        assert event.src_port == 49152
        assert event.dst_ip == "10.0.0.1"
        assert event.dst_port == 80
        assert event.proto == "tcp"
        assert event.service == "http"
        assert event.duration == 0.452
        assert event.orig_bytes == 1024
        assert event.resp_bytes == 4096
        assert event.conn_state == "SF"
        assert event.orig_pkts == 10
        assert event.resp_pkts == 12
        assert event.community_id == "1:abc123456=="
        assert event.event_id is not None
        assert event.ingest_ts > 0

        # Verify serialization
        d = event.to_dict()
        assert d["src_ip"] == "192.168.1.100"
        j = event.to_json()
        assert "192.168.1.100" in j

    def test_conn_telemetry_event_missing_fields_defaults(self):
        raw = {
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 5555,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "duration": "-",
            "orig_bytes": "-",
            "resp_bytes": "-",
            "service": "-",
        }
        event = ConnTelemetryEvent.from_zeek_dict(raw)
        assert event.src_ip == "10.0.0.5"
        assert event.duration == 0.0
        assert event.orig_bytes == 0
        assert event.resp_bytes == 0
        assert event.service is None
        assert event.proto == "tcp"
        assert event.conn_state == "SF"

    def test_dns_telemetry_event_from_zeek_dict(self):
        raw = {
            "ts": 1725000002.5,
            "uid": "CDnsFlow98765432",
            "id.orig_h": "172.16.0.10",
            "id.orig_p": 53535,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 4321,
            "query": "malicious-c2-beacon.corp.internal.example.com",
            "qclass_name": "C_INTERNET",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["198.51.100.25", "198.51.100.26"],
            "TTLs": [300.0, 300.0],
        }
        event = DnsTelemetryEvent.from_zeek_dict(raw)
        assert event.src_ip == "172.16.0.10"
        assert event.src_port == 53535
        assert event.dst_ip == "8.8.8.8"
        assert event.dst_port == 53
        assert event.trans_id == 4321
        assert event.query == "malicious-c2-beacon.corp.internal.example.com"
        assert event.subdomain == "malicious-c2-beacon"
        assert event.subdomain_entropy > 2.5
        assert len(event.answers) == 2
        assert event.ttls == [300.0, 300.0]

    def test_shannon_entropy_calculation(self):
        # Empty string
        assert calculate_shannon_entropy("") == 0.0
        # All same characters
        assert calculate_shannon_entropy("aaaaaaa") == 0.0
        # Low entropy domain
        low_ent = calculate_shannon_entropy("google")
        # High entropy random domain
        high_ent = calculate_shannon_entropy("qx83f9m2v7w1k0lp")
        assert high_ent > low_ent
        assert high_ent >= 3.5

    def test_subdomain_extractor(self):
        assert extract_subdomain("tunnel.data.evil.com") == "tunnel"
        assert extract_subdomain("google.com") == "google"
        assert extract_subdomain("host") == "host"
        assert extract_subdomain("") == ""

    def test_ssl_telemetry_event_from_zeek_dict(self):
        raw = {
            "ts": 1725000003.8,
            "uid": "CSslFlow55555555",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 60000,
            "id.resp_h": "203.0.113.80",
            "id.resp_p": 443,
            "version": "TLSv13",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "server_name": "secure.bank.com",
            "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "ja4s": "t1302h2_1301_0000",
            "ja4_raw_ciphers": "1301,1302,1303,cca8,cca9",
            "established": "true",
            "subject": "CN=secure.bank.com",
            "issuer": "CN=DigiCert Global Root CA",
        }
        event = SslTelemetryEvent.from_zeek_dict(raw)
        assert event.src_ip == "192.168.1.50"
        assert event.dst_ip == "203.0.113.80"
        assert event.version == "TLSv13"
        assert event.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"
        assert event.ja4s == "t1302h2_1301_0000"
        assert event.established is True
        assert event.subject == "CN=secure.bank.com"

    def test_raw_alert_validation(self):
        alert = RawAlert(
            detector_id="ddos_entropy",
            threat_class="VOLUMETRIC_DDOS",
            severity="CRITICAL",
            confidence=0.98,
            source_ip="192.168.1.200",
            target_ip="10.0.0.1",
            target_port=80,
            protocol="tcp",
            evidence={
                "current_rate_pps": 55000.0,
                "rate_z_score": 6.8,
                "port_entropy": 0.12,
            },
            mitre_technique="T1498",
        )
        assert alert.alert_id is not None
        assert alert.detector_name == "ddos_entropy"
        assert alert.threat_class == "VOLUMETRIC_DDOS"
        assert alert.severity == "CRITICAL"
        assert alert.confidence == 0.98
        assert alert.source_ip == "192.168.1.200"
        assert "[CRITICAL] VOLUMETRIC_DDOS detected on 192.168.1.200" in alert.title
        assert alert.evidence["current_rate_pps"] == 55000.0

        # Confidence boundary validation
        with pytest.raises(ValidationError):
            RawAlert(
                detector_id="test",
                threat_class="TEST",
                confidence=1.5,  # Invalid > 1.0
                source_ip="1.1.1.1",
            )


class TestDeterministicPartitioning:
    """Test suite for deterministic hash(source_ip) % 4 partition routing."""

    def test_partition_determinism(self):
        test_ips = [
            "192.168.1.1",
            "192.168.1.105",
            "10.0.0.1",
            "172.16.31.254",
            "8.8.8.8",
            "1.1.1.1",
            "2001:db8::1",
            "::1",
        ]
        for ip in test_ips:
            # 100 consecutive calls must produce the exact same partition index
            expected_p = get_source_ip_partition(ip, num_partitions=4)
            for _ in range(100):
                p = get_source_ip_partition(ip, num_partitions=4)
                assert p == expected_p
                assert 0 <= p < 4

    def test_partition_distribution(self):
        # Generate 1,000 distinct source IPs
        partition_counts = [0, 0, 0, 0]
        for a in range(10):
            for b in range(100):
                ip = f"10.{a}.{b}.1"
                p = get_source_ip_partition(ip, num_partitions=4)
                partition_counts[p] += 1

        # All 4 partitions must receive substantial traffic (no starved partitions)
        for p, count in enumerate(partition_counts):
            assert count > 150, f"Partition {p} received too few records ({count}/1000)"

    def test_partition_edge_cases(self):
        assert get_source_ip_partition("", 4) == 0
        assert get_source_ip_partition("0.0.0.0", 4) in (0, 1, 2, 3)
        assert get_source_ip_partition("255.255.255.255", 4) in (0, 1, 2, 3)
        assert get_source_ip_partition("192.168.1.1", 1) == 0


class TestInMemoryStreamingBus:
    """Test suite for InMemoryStreamingBus multi-partition topic operations."""

    def test_topic_partition_routing(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        # Discover IPs that map to each of the 4 partitions [0, 1, 2, 3]
        partition_ips = {}
        for i in range(100):
            test_ip = f"10.0.0.{i}"
            p = get_source_ip_partition(test_ip, 4)
            if p not in partition_ips:
                partition_ips[p] = test_ip
            if len(partition_ips) == 4:
                break

        for p, ip in partition_ips.items():
            event = ConnTelemetryEvent(
                src_ip=ip, src_port=10000 + p, dst_ip="1.1.1.1", dst_port=80, uid=f"C_{p}"
            )
            bus.publish("telemetry.conn", event)

        # Verify each partition received its corresponding event
        for p, ip in partition_ips.items():
            records = bus.consume("telemetry.conn", partition=p, max_records=10)
            assert len(records) == 1
            assert records[0]["src_ip"] == ip

        bus.close()

    def test_publish_batch_and_consume_all(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        events = []
        for i in range(100):
            events.append(
                DnsTelemetryEvent(
                    src_ip=f"192.168.1.{i % 50 + 1}",
                    src_port=10000 + i,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    query=f"host{i}.example.com",
                    uid=f"D{i}",
                )
            )

        published = bus.publish_batch("telemetry.dns", events)
        assert published == 100

        all_consumed = bus.consume_all("telemetry.dns", max_per_partition=100)
        assert len(all_consumed) == 100

        metrics = bus.get_metrics()
        assert metrics["total_published"] >= 100
        assert metrics["total_consumed"] >= 100
        bus.close()

    def test_factory_get_streaming_bus(self):
        mem_bus = get_streaming_bus(bus_type="memory", num_partitions=4)
        assert isinstance(mem_bus, InMemoryStreamingBus)
        assert mem_bus.num_partitions == 4

        kafka_bus = get_streaming_bus(bus_type="kafka", bootstrap_servers="localhost:19092")
        assert isinstance(kafka_bus, KafkaStreamingBus)


class TestZeekLogTailerNormalization:
    """Test suite for Zeek log tailing and schema normalization."""

    def test_tailer_read_normalized_batch(self):
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log", encoding="utf-8") as tmp:
            tmp_path = tmp.name
            tmp.write("#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state\n")
            rec1 = {
                "ts": 1725000010.0,
                "uid": "C_TEST_1",
                "id.orig_h": "192.168.1.10",
                "id.orig_p": 45000,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 1.25,
                "orig_bytes": 500,
                "resp_bytes": 1500,
                "conn_state": "SF",
            }
            rec2 = {
                "ts": 1725000011.0,
                "uid": "C_TEST_2",
                "id.orig_h": "192.168.1.11",
                "id.orig_p": 45001,
                "id.resp_h": "93.184.216.34",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 0.5,
                "orig_bytes": 200,
                "resp_bytes": 800,
                "conn_state": "SF",
            }
            tmp.write(json.dumps(rec1) + "\n")
            tmp.write(json.dumps(rec2) + "\n")
            tmp.flush()

        try:
            tailer = ZeekLogTailer(tmp_path, from_beginning=True, log_type="conn")
            normalized_records = tailer.read_normalized_batch()
            assert len(normalized_records) == 2
            assert isinstance(normalized_records[0], ConnTelemetryEvent)
            assert normalized_records[0].uid == "C_TEST_1"
            assert normalized_records[0].src_ip == "192.168.1.10"
            assert normalized_records[0].orig_bytes == 500
            assert isinstance(normalized_records[1], ConnTelemetryEvent)
            assert normalized_records[1].uid == "C_TEST_2"
            tailer.stop()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_multi_tailer_read_normalized_all(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p = Path(tmp_dir)
            conn_log = p / "conn.log"
            dns_log = p / "dns.log"
            ssl_log = p / "ssl.log"

            conn_log.write_text(
                json.dumps({"ts": 1725000000.0, "uid": "C01", "id.orig_h": "10.0.0.1", "id.orig_p": 1234, "id.resp_h": "10.0.0.2", "id.resp_p": 80}) + "\n",
                encoding="utf-8",
            )
            dns_log.write_text(
                json.dumps({"ts": 1725000001.0, "uid": "D01", "id.orig_h": "10.0.0.1", "id.orig_p": 5353, "id.resp_h": "8.8.8.8", "id.resp_p": 53, "query": "test.corp"}) + "\n",
                encoding="utf-8",
            )
            ssl_log.write_text(
                json.dumps({"ts": 1725000002.0, "uid": "S01", "id.orig_h": "10.0.0.1", "id.orig_p": 4434, "id.resp_h": "1.1.1.1", "id.resp_p": 443, "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"}) + "\n",
                encoding="utf-8",
            )

            multi = MultiZeekLogTailer(str(p), from_beginning=True)
            norm_data = multi.read_normalized_all()

            assert len(norm_data["conn"]) == 1
            assert isinstance(norm_data["conn"][0], ConnTelemetryEvent)
            assert norm_data["conn"][0].uid == "C01"

            assert len(norm_data["dns"]) == 1
            assert isinstance(norm_data["dns"][0], DnsTelemetryEvent)
            assert norm_data["dns"][0].query == "test.corp"

            assert len(norm_data["ssl"]) == 1
            assert isinstance(norm_data["ssl"][0], SslTelemetryEvent)
            assert norm_data["ssl"][0].ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"

            multi.stop_all()


class TestTelemetryKafkaProducer:
    """Test suite for TelemetryKafkaProducer routing and alert emission."""

    def test_producer_send_pydantic_events(self):
        producer = TelemetryKafkaProducer()
        conn_event = ConnTelemetryEvent(
            src_ip="192.168.10.50",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=80,
            uid="C_PROD_1",
        )
        dns_event = DnsTelemetryEvent(
            src_ip="192.168.10.50",
            src_port=50001,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="api.github.com",
            uid="D_PROD_1",
        )
        ssl_event = SslTelemetryEvent(
            src_ip="192.168.10.50",
            src_port=50002,
            dst_ip="140.82.121.4",
            dst_port=443,
            ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
            uid="S_PROD_1",
        )

        assert producer.send_record("conn", conn_event) is True
        assert producer.send_record("dns", dns_event) is True
        assert producer.send_record("ssl", ssl_event) is True

        # Send alert
        alert = RawAlert(
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            severity="HIGH",
            confidence=0.92,
            source_ip="192.168.10.50",
            evidence={"distinct_ports": 150, "hll_cardinality": 148.5},
            mitre_technique="T1046",
        )
        assert producer.send_alert(alert) is True

        metrics = producer.metrics
        assert metrics["sent_count"] >= 4
        assert metrics["error_count"] == 0
        producer.close()


class TestThroughputAndPartitionLocalityStress:
    """Stress test verifying >10,000 EPS ingestion throughput and per-host stateful locality."""

    def test_line_rate_ingestion_and_host_locality(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        # 5 distinct attacker IPs and 5 distinct benign IPs (total 10 source hosts)
        hosts = [f"192.168.1.{10 + i}" for i in range(10)]
        expected_host_partitions = {ip: get_source_ip_partition(ip, 4) for ip in hosts}

        num_events = 20000
        events: List[ConnTelemetryEvent] = []
        for i in range(num_events):
            src_ip = hosts[i % len(hosts)]
            events.append(
                ConnTelemetryEvent(
                    src_ip=src_ip,
                    src_port=1024 + (i % 60000),
                    dst_ip="10.0.0.1",
                    dst_port=80,
                    orig_bytes=100 + (i % 500),
                    resp_bytes=200 + (i % 1000),
                    uid=f"C_STRESS_{i}",
                )
            )

        start_time = time.perf_counter()
        published = bus.publish_batch("telemetry.conn", events)
        elapsed = time.perf_counter() - start_time

        assert published == num_events
        eps = num_events / max(elapsed, 1e-6)
        print(f"\nIngestion Throughput: {eps:,.2f} EPS (processed {num_events} events in {elapsed:.4f}s)")
        assert eps > 10000, f"Throughput {eps:.2f} EPS fell below 10,000 EPS target"

        # Verify Partition Locality:
        # For each partition [0..3], consume all records and verify that EVERY event
        # originated from a host whose expected partition matches the partition it was read from.
        for p in range(4):
            records = bus.consume("telemetry.conn", partition=p, max_records=num_events)
            for rec in records:
                src_ip = rec["src_ip"]
                assert expected_host_partitions[src_ip] == p, (
                    f"Partition Locality Violation: Host {src_ip} routed to partition {p}, "
                    f"expected partition {expected_host_partitions[src_ip]}"
                )

        bus.close()
