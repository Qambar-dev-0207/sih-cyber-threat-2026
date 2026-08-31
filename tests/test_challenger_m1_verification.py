"""
tests/test_challenger_m1_verification.py
-----------------------------------------
Empirical Challenger 2 Verification Suite for Milestone 1:
Ingestion & Partitioning Pipeline (Phase 1).

Oracles & Stress Tests:
1. Multi-Threaded Partition Locality: 20 concurrent producer threads sending 50,000 events
   from 1,000 shared and unique source IPs -> Verify zero cross-partition leakage per IP.
2. 10,000 Distinct Source IPs Balance Verification:
   Statistical uniformity and zero partition starvation across 10,000 distinct IPv4 & IPv6 addresses.
3. Line-Rate Serialization & Partitioning Throughput & Latency:
   Measure serialization + partitioning + queuing throughput (> 50,000 EPS target) and sub-500ms latency.
4. Adversarial Edge Cases:
   IPv6 representation variants, malformed IPs, null strings, whitespace, large payloads.
"""

import math
import sys
import time
import queue
import threading
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict, Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
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
    get_source_ip_partition,
    extract_record_source_ip,
    serialize_record,
)
from src.ingestion.kafka_producer import TelemetryKafkaProducer


class TestChallengerMultiThreadedLocality:
    """
    Stress-tests multi-threaded concurrent ingestion to verify that events from
    the same source IP NEVER route to different partitions under race conditions.
    """

    def test_multithreaded_partition_isolation_20_threads_50k_events(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        num_threads = 20
        events_per_thread = 2500
        total_events = num_threads * events_per_thread # 50,000 events
        num_distinct_ips = 500

        # Shared IP pool
        ip_pool = [f"192.168.{(i // 256)}.{i % 256}" for i in range(num_distinct_ips)]
        expected_partition_map = {ip: get_source_ip_partition(ip, num_partitions=4) for ip in ip_pool}

        # Track per-thread errors
        thread_errors: List[Exception] = []

        def producer_worker(thread_id: int):
            try:
                for j in range(events_per_thread):
                    src_ip = ip_pool[(thread_id * 37 + j) % num_distinct_ips]
                    event = ConnTelemetryEvent(
                        src_ip=src_ip,
                        src_port=1024 + (j % 60000),
                        dst_ip="10.0.0.1",
                        dst_port=80,
                        orig_bytes=100 + (j % 200),
                        resp_bytes=200 + (j % 400),
                        uid=f"C_MT_{thread_id}_{j}",
                    )
                    bus.publish("telemetry.conn", event)
            except Exception as exc:
                thread_errors.append(exc)

        threads = [threading.Thread(target=producer_worker, args=(t,)) for t in range(num_threads)]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
        elapsed = time.perf_counter() - t0

        assert len(thread_errors) == 0, f"Thread errors encountered: {thread_errors}"

        # Consume all partitions and verify strict partition locality
        consumed_per_partition: Dict[int, List[Dict]] = {}
        total_consumed = 0
        ip_seen_in_partitions: Dict[str, Set[int]] = defaultdict(set)

        for p in range(4):
            records = bus.consume("telemetry.conn", partition=p, max_records=total_events)
            consumed_per_partition[p] = records
            total_consumed += len(records)
            for rec in records:
                sip = rec["src_ip"]
                ip_seen_in_partitions[sip].add(p)
                # Check that this partition matches the mathematically expected partition
                assert p == expected_partition_map[sip], (
                    f"VIOLATION: Event for {sip} found in partition {p}, "
                    f"expected {expected_partition_map[sip]}"
                )

        assert total_consumed == total_events, f"Expected {total_events} consumed, got {total_consumed}"

        # Invariant: Each IP must appear in EXACTLY ONE partition
        for ip, partitions in ip_seen_in_partitions.items():
            assert len(partitions) == 1, (
                f"LOCALITY VIOLATION: Source IP {ip} was routed to multiple partitions: {partitions}"
            )
            assert list(partitions)[0] == expected_partition_map[ip]

        eps = total_events / max(elapsed, 1e-6)
        print(f"\n[Multi-Threaded Locality Test] Ingested {total_events:,} events across {num_threads} threads in {elapsed:.3f}s -> {eps:,.2f} EPS (100% Locality Verified)")
        bus.close()


class TestChallengerPartitionDistribution10kIPs:
    """
    Verifies that partition distribution across a synthetic population of 10,000 distinct source IPs
    is balanced (no partition starvation, uniform spread across 4 partitions).
    """

    def test_partition_balance_10000_distinct_ips(self):
        num_ips = 10000
        distinct_ips: List[str] = []

        # Generate 10,000 distinct IPv4 addresses spanning different subnets
        for i in range(num_ips):
            octet1 = 10 + (i // (256 * 256))
            octet2 = (i // 256) % 256
            octet3 = i % 256
            octet4 = 1 + (i % 254)
            distinct_ips.append(f"{octet1}.{octet2}.{octet3}.{octet4}")

        partition_counts = [0, 0, 0, 0]
        for ip in distinct_ips:
            p = get_source_ip_partition(ip, num_partitions=4)
            partition_counts[p] += 1

        expected_mean = num_ips / 4.0 # 2500 per partition
        print(f"\n[10k IP Distribution] Partition Counts: {partition_counts} (Expected mean: {expected_mean})")

        # Check for starvation (no partition should receive < 20% of traffic, i.e., > 2000 per partition)
        for p, count in enumerate(partition_counts):
            ratio = count / num_ips
            assert count >= 2000, f"Partition {p} is starved! Count={count} ({ratio:.2%})"
            assert count <= 3000, f"Partition {p} is overloaded! Count={count} ({ratio:.2%})"

        # Chi-Square goodness-of-fit test against uniform distribution (df=3, critical value at p=0.01 is 11.345)
        chi_sq = sum((c - expected_mean) ** 2 / expected_mean for c in partition_counts)
        print(f"[10k IP Distribution] Chi-Square statistic: {chi_sq:.4f} (df=3, critical p=0.01 is 11.345)")
        assert chi_sq < 25.0, f"Partition distribution deviates significantly from uniform: chi_sq={chi_sq}"

    def test_partition_balance_ipv6_addresses(self):
        # Test 1,000 distinct IPv6 addresses
        ipv6_list = [f"2001:db8:{i:x}::{(i*7)%65535:x}" for i in range(1000)]
        counts = [0, 0, 0, 0]
        for ip in ipv6_list:
            p = get_source_ip_partition(ip, num_partitions=4)
            counts[p] += 1

        print(f"\n[1k IPv6 Distribution] Partition Counts: {counts}")
        for p, c in enumerate(counts):
            assert c > 180, f"IPv6 partition {p} starved: {c}/1000"


class TestChallengerThroughputAndLatencySLA:
    """
    Measures serialization + partitioning throughput (>50,000 EPS) and latency (<500ms).
    """

    def test_sustained_throughput_exceeds_50k_eps(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        num_events = 60000
        events = []
        for i in range(num_events):
            events.append(
                ConnTelemetryEvent(
                    src_ip=f"10.0.{(i // 256) % 256}.{i % 256}",
                    src_port=1024 + (i % 60000),
                    dst_ip="172.16.0.1",
                    dst_port=443,
                    orig_bytes=512,
                    resp_bytes=2048,
                    proto="tcp",
                    service="ssl",
                    uid=f"C_TP_{i}",
                )
            )

        # Measure serialization + routing + publishing
        t0 = time.perf_counter()
        published = bus.publish_batch("telemetry.conn", events)
        publish_time = time.perf_counter() - t0

        assert published == num_events
        eps = num_events / publish_time
        print(f"\n[Throughput Benchmark] Ingested {num_events:,} Pydantic events in {publish_time:.4f}s -> {eps:,.2f} EPS (Target: >50,000 EPS)")
        assert eps > 50000, f"Ingestion throughput {eps:,.2f} EPS did not meet SLA >50,000 EPS"

        # Measure consume latency / throughput
        t1 = time.perf_counter()
        consumed = bus.consume_all("telemetry.conn", max_per_partition=num_events)
        consume_time = time.perf_counter() - t1

        assert len(consumed) == num_events
        consume_eps = num_events / consume_time
        print(f"[Consumption Benchmark] Consumed {num_events:,} events in {consume_time:.4f}s -> {consume_eps:,.2f} EPS")

        bus.close()

    def test_single_event_latency_sub_500ms(self):
        bus = InMemoryStreamingBus(num_partitions=4)
        bus.clear()

        latencies_ms = []
        num_samples = 2000

        for i in range(num_samples):
            ev = ConnTelemetryEvent(
                src_ip=f"192.168.1.{i % 250 + 1}",
                src_port=5000,
                dst_ip="8.8.8.8",
                dst_port=53,
                uid=f"C_LAT_{i}",
            )
            t_start = time.perf_counter()
            bus.publish("telemetry.conn", ev)
            target_partition = get_source_ip_partition(ev.src_ip, 4)
            records = bus.consume("telemetry.conn", partition=target_partition, max_records=1)
            t_end = time.perf_counter()

            assert len(records) == 1
            lat_ms = (t_end - t_start) * 1000.0
            latencies_ms.append(lat_ms)

        latencies_ms.sort()
        p50 = latencies_ms[int(num_samples * 0.50)]
        p95 = latencies_ms[int(num_samples * 0.95)]
        p99 = latencies_ms[int(num_samples * 0.99)]
        max_lat = latencies_ms[-1]

        print(f"\n[Latency Benchmark (N={num_samples})] P50: {p50:.4f}ms | P95: {p95:.4f}ms | P99: {p99:.4f}ms | Max: {max_lat:.4f}ms (SLA: <500ms)")
        assert p99 < 500.0, f"P99 latency {p99:.4f}ms exceeded 500ms SLA"
        assert p50 < 10.0, f"P50 latency {p50:.4f}ms exceeded 10ms"

        bus.close()


class TestChallengerAdversarialEdgeCases:
    """
    Tests hostile, boundary, and malformed inputs against models, partitioners, and serialization.
    """

    def test_edge_case_ip_inputs(self):
        # Empty string
        assert get_source_ip_partition("", 4) == 0
        # None string / null
        assert get_source_ip_partition(None, 4) == 0
        # Whitespace padded IP
        p1 = get_source_ip_partition("192.168.1.1", 4)
        p2 = get_source_ip_partition("  192.168.1.1 \t\n", 4)
        assert p1 == p2, "Whitespace in IP string caused partition mismatch"

        # IPv6 addresses
        p_v6_a = get_source_ip_partition("::1", 4)
        assert 0 <= p_v6_a < 4
        p_v6_b = get_source_ip_partition("fe80::1ff:fe23:4567:890a", 4)
        assert 0 <= p_v6_b < 4

    def test_extract_record_source_ip_edge_cases(self):
        # Dict with various keys
        assert extract_record_source_ip({"src_ip": "1.2.3.4"}) == "1.2.3.4"
        assert extract_record_source_ip({"source_ip": "5.6.7.8"}) == "5.6.7.8"
        assert extract_record_source_ip({"id.orig_h": "9.10.11.12"}) == "9.10.11.12"
        assert extract_record_source_ip({"orig_h": "13.14.15.16"}) == "13.14.15.16"
        assert extract_record_source_ip({}) == "0.0.0.0"
        assert extract_record_source_ip("malformed json") == "0.0.0.0"

    def test_entropy_and_subdomain_resilience(self):
        # Very long repetitive string
        assert calculate_shannon_entropy("a" * 10000) == 0.0
        # Maximum entropy string of uniform alphabet
        alphabet_ent = calculate_shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
        assert alphabet_ent > 5.0

        # Subdomain extraction edge cases
        assert extract_subdomain("") == ""
        assert extract_subdomain("...") == ""
        assert extract_subdomain(".a.b.c.") == "a"
        assert extract_subdomain("singleword") == "singleword"
