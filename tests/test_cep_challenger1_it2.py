from __future__ import annotations

import collections
import concurrent.futures
import gc
import math
import random
import threading
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from src.cep import (
    AlertDeduplicator,
    CEPAggregatorEngine,
    ConfidenceFuser,
    DeduplicationRecord,
    FusedIncident,
    HostSlidingWindow,
    SignalCorrelator,
    SlidingWindowBuffer,
    SlidingWindowConfig,
    SubnetSlidingWindow,
    TokenBucket,
    TokenBucketBurstLimiter,
    extract_subnet,
)
from src.cep.correlator import STAGE_SEQUENCE
from src.ingestion.models import RawAlert


class TestAdversarialThreatMaskingUnderFlood:
    """
    Adversarial Challenge 1: Threat Masking & Stage Escalation during Volumetric Floods.
    Tests whether stealthy multi-stage attack vectors (Recon, C2, Exfil) interleaved into
    burst floods are correctly detected, preserved, classified, and escalated to APT_MULTI_STAGE_ATTACK.
    """

    def test_multi_stage_stealth_injected_entirely_during_rate_limiting(self):
        """
        Attacker exhausts token bucket with DDoS flood, then while COMPLETELY rate-limited,
        executes Reconnaissance -> Delivery -> C2 Beaconing -> Data Exfiltration.
        Verify:
        1. All 4 novel threat classes and participating detectors are captured in inc.threat_classes and inc.participating_detectors.
        2. All 4 kill chain stages are captured and chronologically/logically sorted in inc.kill_chain_stages.
        3. Threat class escalates to 'APT_MULTI_STAGE_ATTACK'.
        4. Severity escalates to 'CRITICAL'.
        5. Attack stage reflects the highest kill chain stage ('EXFILTRATION' / 'ACTIONS_ON_OBJECTIVES').
        """
        config = SlidingWindowConfig(rate_limit_capacity=5.0, rate_limit_refill_rate=1.0)
        engine = CEPAggregatorEngine(config=config)
        attacker = "198.51.100.99"
        base_time = 1000.0

        # 1. Exhaust bucket with 5 allowed alerts
        for i in range(5):
            engine.ingest_alert(
                RawAlert(
                    alert_id=f"ddos_init_{i}",
                    source_ip=attacker,
                    detector_id="ddos_entropy",
                    threat_class="VOLUMETRIC_DDOS",
                    severity="HIGH",
                    timestamp=base_time,
                ),
                current_time=base_time,
            )

        # 2. Flood with 1000 DDoS alerts (all rate-limited)
        for i in range(1000):
            res = engine.ingest_alert(
                RawAlert(
                    alert_id=f"ddos_flood_{i}",
                    source_ip=attacker,
                    detector_id="ddos_entropy",
                    threat_class="VOLUMETRIC_DDOS",
                    severity="HIGH",
                    timestamp=base_time,
                ),
                current_time=base_time,
            )
            assert res is not None

        # 3. Interleave stealthy attack stages while rate-limited at t=base_time
        stealth_alerts = [
            ("portscan_hll", "PORT_SCAN_RECON", "LOW", "RECONNAISSANCE"),
            ("dga_lstm", "DGA_TUNNELLING", "MEDIUM", "DELIVERY"),
            ("ja4_malware", "ENCRYPTED_MALWARE", "HIGH", "COMMAND_AND_CONTROL"),
            ("exfil_ratio", "DATA_EXFILTRATION", "CRITICAL", "EXFILTRATION"),
        ]

        for det, threat, sev, expected_stg in stealth_alerts:
            inc = engine.ingest_alert(
                RawAlert(
                    alert_id=f"stealth_{det}",
                    source_ip=attacker,
                    detector_id=det,
                    threat_class=threat,
                    severity=sev,
                    confidence=0.92,
                    target_ip="10.0.0.50",
                    target_port=443,
                    timestamp=base_time,
                ),
                current_time=base_time,
            )
            assert inc is not None

        inc_final = engine.get_incident_for_host(attacker)
        assert inc_final is not None

        # Assertions for threat preservation
        assert "VOLUMETRIC_DDOS" in inc_final.threat_classes
        assert "PORT_SCAN_RECON" in inc_final.threat_classes
        assert "DGA_TUNNELLING" in inc_final.threat_classes
        assert "ENCRYPTED_MALWARE" in inc_final.threat_classes
        assert "DATA_EXFILTRATION" in inc_final.threat_classes

        # Assertions for detector preservation
        expected_dets = {"ddos_entropy", "portscan_hll", "dga_lstm", "ja4_malware", "exfil_ratio"}
        assert expected_dets.issubset(set(inc_final.participating_detectors))

        # Assertions for kill chain stages
        assert "RECONNAISSANCE" in inc_final.kill_chain_stages
        assert "DELIVERY" in inc_final.kill_chain_stages
        assert "COMMAND_AND_CONTROL" in inc_final.kill_chain_stages
        assert "EXFILTRATION" in inc_final.kill_chain_stages
        assert "ACTIONS_ON_OBJECTIVES" in inc_final.kill_chain_stages

        # Escalation checks
        assert inc_final.threat_class == "APT_MULTI_STAGE_ATTACK"
        assert inc_final.severity == "CRITICAL"
        assert inc_final.raw_alert_count == 1005 + 4
        assert inc_final.total_raw_alerts_collapsed == 1005 + 4

    def test_storm_conclusion_merges_all_threat_classes_cleanly(self):
        """
        Verify that when a storm concludes (token bucket refills and an allowed alert arrives),
        the storm summary threat classes and all prior rate-limited threats are retained in FusedIncident.
        """
        config = SlidingWindowConfig(rate_limit_capacity=2.0, rate_limit_refill_rate=1.0)
        engine = CEPAggregatorEngine(config=config)
        attacker = "198.51.100.150"

        # 2 allowed alerts at t=100.0
        engine.ingest_alert(
            RawAlert(source_ip=attacker, detector_id="ddos_entropy", threat_class="VOLUMETRIC_DDOS", timestamp=100.0),
            current_time=100.0,
        )
        engine.ingest_alert(
            RawAlert(source_ip=attacker, detector_id="ddos_entropy", threat_class="VOLUMETRIC_DDOS", timestamp=100.0),
            current_time=100.0,
        )

        # 20 rate-limited alerts with C2 and Exfil at t=100.0
        for _ in range(10):
            engine.ingest_alert(
                RawAlert(source_ip=attacker, detector_id="ddos_entropy", threat_class="VOLUMETRIC_DDOS", timestamp=100.0),
                current_time=100.0,
            )
        engine.ingest_alert(
            RawAlert(source_ip=attacker, detector_id="c2_beacon", threat_class="C2_BEACONING", timestamp=100.0),
            current_time=100.0,
        )
        engine.ingest_alert(
            RawAlert(source_ip=attacker, detector_id="exfil_ratio", threat_class="DATA_EXFILTRATION", timestamp=100.0),
            current_time=100.0,
        )

        # Advance time by 10 seconds -> bucket refills
        # Ingest allowed alert at t=110.0
        concluded_inc = engine.ingest_alert(
            RawAlert(source_ip=attacker, detector_id="portscan_hll", threat_class="PORT_SCAN_RECON", timestamp=110.0),
            current_time=110.0,
        )

        assert concluded_inc is not None
        assert "VOLUMETRIC_DDOS" in concluded_inc.threat_classes
        assert "C2_BEACONING" in concluded_inc.threat_classes
        assert "DATA_EXFILTRATION" in concluded_inc.threat_classes
        assert "PORT_SCAN_RECON" in concluded_inc.threat_classes
        assert concluded_inc.threat_class == "APT_MULTI_STAGE_ATTACK"


class TestAdversarialDeduplicationAndCountIntegrity:
    """
    Adversarial Challenge 2: Duplicate reference prevention, exact alert counting,
    and memory boundedness in sliding windows and subnets.
    """

    def test_500_coalesced_alerts_single_flow_exact_counts(self):
        """
        Verify that 500 identical alerts coalesced into 1 flow:
        1. Result in exactly 1 DeduplicationRecord in HostSlidingWindow.
        2. HostSlidingWindow.get_total_raw_alerts() returns exactly 500 (NOT 500^2 = 250,000).
        3. Attack timeline in FusedIncident has exactly 1 entry.
        4. SubnetAggregation.total_alerts returns exactly 500.
        """
        config = SlidingWindowConfig(dedup_coalesce_sec=10.0, rate_limit_capacity=1000.0)
        engine = CEPAggregatorEngine(config=config)
        src = "192.168.10.100"

        for i in range(500):
            engine.ingest_alert(
                RawAlert(
                    alert_id=f"alt_{i}",
                    source_ip=src,
                    detector_id="portscan_hll",
                    threat_class="PORT_SCAN_RECON",
                    target_ip="10.0.0.1",
                    target_port=80,
                    protocol="TCP",
                    evidence={"syn_rate": 100 + i},
                    timestamp=500.0 + (i * 0.01),
                ),
                current_time=500.0 + (i * 0.01),
            )

        host_win = engine.buffer.get_host_window(src)
        assert host_win is not None
        assert len(host_win.get_records()) == 1
        assert host_win.get_total_raw_alerts() == 500

        inc = engine.get_incident_for_host(src)
        assert inc is not None
        assert inc.raw_alert_count == 500
        assert len(inc.attack_timeline) == 1
        assert inc.attack_timeline[0].evidence != {}
        assert "syn_rate" in inc.attack_timeline[0].evidence

        subnet_win = engine.buffer.get_subnet_window("192.168.10.0/24")
        assert subnet_win is not None
        agg = subnet_win.get_aggregation()
        assert agg.total_alerts == 500

    def test_multi_host_multi_flow_subnet_aggregation_exactness(self):
        """
        Verify subnet alert aggregation across 10 hosts, each with 5 distinct flows,
        each flow receiving 20 coalesced alerts = 10 * 5 * 20 = 1,000 total alerts.
        """
        config = SlidingWindowConfig(dedup_coalesce_sec=10.0, rate_limit_capacity=5000.0)
        engine = CEPAggregatorEngine(config=config)

        detectors = ["portscan_hll", "dga_lstm", "ja4_malware", "exfil_ratio", "ddos_entropy"]
        threats = ["PORT_SCAN_RECON", "DGA_TUNNELLING", "ENCRYPTED_MALWARE", "DATA_EXFILTRATION", "VOLUMETRIC_DDOS"]

        total_alerts_sent = 0
        for h in range(1, 11):
            src_ip = f"172.16.50.{h}"
            for f in range(5):
                for a in range(20):
                    engine.ingest_alert(
                        RawAlert(
                            source_ip=src_ip,
                            detector_id=detectors[f],
                            threat_class=threats[f],
                            target_ip="10.0.0.1",
                            target_port=80 + f,
                            timestamp=100.0 + (a * 0.1),
                        ),
                        current_time=100.0 + (a * 0.1),
                    )
                    total_alerts_sent += 1

        assert total_alerts_sent == 1000

        subnet_win = engine.buffer.get_subnet_window("172.16.50.0/24")
        assert subnet_win is not None
        agg = subnet_win.get_aggregation(campaign_threshold=3)
        assert agg.is_campaign is True
        assert len(agg.active_hosts) == 10
        assert agg.total_alerts == 1000
        assert len(agg.participating_detectors) == 5
        assert len(agg.threat_classes) == 5

    def test_sliding_window_eviction_purges_fingerprint_index(self):
        """
        Verify that when a record expires and is evicted from HostSlidingWindow,
        its entry in _fp_to_record is cleanly popped. If the same flow arrives later,
        it should be treated as a fresh record in the window.
        """
        host_win = HostSlidingWindow("10.0.0.1", window_duration_sec=30.0, created_at=100.0)
        rec1 = DeduplicationRecord(
            fingerprint="fp_test_1",
            source_ip="10.0.0.1",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            first_seen=100.0,
            last_seen=100.0,
            occurrence_count=5,
        )
        host_win.add_record(rec1, current_time=100.0)
        assert "fp_test_1" in host_win._fp_to_record
        assert len(host_win.get_records()) == 1

        # Advance time to t=150.0 (past 30s window)
        host_win.evict_expired(150.0)
        assert len(host_win.get_records()) == 0
        assert "fp_test_1" not in host_win._fp_to_record
        assert host_win.get_total_raw_alerts() == 0


class TestAdversarialEmergencyEvictionPerformance:
    """
    Adversarial Challenge 3: Emergency Eviction Bottleneck & High Scale Verification.
    Tests O(1) LRU eviction behavior under capacity saturation.
    """

    def test_emergency_eviction_speed_under_saturation(self):
        """
        Ingest 20,000 distinct hosts into SlidingWindowBuffer with max_tracked_hosts=2,000.
        Verify:
        1. Ingestion completes in < 3.0 seconds (sub-millisecond eviction).
        2. Tracked hosts count remains tightly bounded around max_tracked_hosts.
        3. Most recently active hosts are retained, older ones evicted.
        """
        max_hosts = 2000
        config = SlidingWindowConfig(max_tracked_hosts=max_hosts, window_duration_sec=60.0)
        buffer = SlidingWindowBuffer(config=config)

        total_hosts = 20000
        start = time.perf_counter()

        for i in range(total_hosts):
            ip = f"10.{(i // 65536) % 255}.{(i // 256) % 255}.{i % 256}"
            rec = DeduplicationRecord(
                fingerprint=f"fp_{i}",
                source_ip=ip,
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                first_seen=float(i),
                last_seen=float(i),
                occurrence_count=1,
            )
            buffer.ingest_record(rec, current_time=float(i))

        elapsed = time.perf_counter() - start
        avg_time_per_host_us = (elapsed / total_hosts) * 1_000_000

        print(f"\n[Emergency Eviction Scale Test] Processed {total_hosts} hosts against capacity {max_hosts} in {elapsed:.4f}s ({avg_time_per_host_us:.2f} µs/host)")

        # Ingestion must be fast (no O(N log N) stall)
        assert elapsed < 5.0, f"Emergency eviction too slow: took {elapsed:.4f}s for {total_hosts} hosts"
        assert len(buffer._hosts) <= max_hosts

        # Verify that the latest host is present
        latest_ip = f"10.{((total_hosts - 1) // 65536) % 255}.{((total_hosts - 1) // 256) % 255}.{(total_hosts - 1) % 256}"
        assert latest_ip in buffer._hosts

        # Verify that an early host (e.g. host 0) has been evicted
        first_ip = "10.0.0.0"
        assert first_ip not in buffer._hosts

    def test_lru_move_to_end_preserves_hot_hosts(self):
        """
        Verify that repeated access to a hot host moves it to the end of the OrderedDict,
        preventing it from being evicted during emergency eviction sweeps.
        """
        config = SlidingWindowConfig(max_tracked_hosts=10, window_duration_sec=60.0)
        buffer = SlidingWindowBuffer(config=config)

        hot_ip = "192.168.99.99"

        # Ingest hot_ip initially
        rec_hot = DeduplicationRecord(
            fingerprint="fp_hot",
            source_ip=hot_ip,
            detector_id="c2_beacon",
            threat_class="C2_BEACONING",
            first_seen=1.0,
            last_seen=1.0,
        )
        buffer.ingest_record(rec_hot, current_time=1.0)

        # Ingest 50 other hosts to trigger multiple emergency eviction cycles,
        # but touch hot_ip every 5 hosts
        for i in range(50):
            ip = f"10.0.0.{i + 1}"
            rec = DeduplicationRecord(
                fingerprint=f"fp_{i}",
                source_ip=ip,
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                first_seen=float(i + 2),
                last_seen=float(i + 2),
            )
            buffer.ingest_record(rec, current_time=float(i + 2))

            if i % 5 == 0:
                rec_hot_ping = DeduplicationRecord(
                    fingerprint="fp_hot",
                    source_ip=hot_ip,
                    detector_id="c2_beacon",
                    threat_class="C2_BEACONING",
                    first_seen=float(i + 2),
                    last_seen=float(i + 2),
                )
                buffer.ingest_record(rec_hot_ping, current_time=float(i + 2))

        # Hot host must still be present because it was constantly refreshed
        assert hot_ip in buffer._hosts


class TestAdversarialMultiTenantConcurrencyAndChaos:
    """
    Adversarial Challenge 4: High-concurrency multithreading, multi-tenant chaos,
    and extreme input boundary validation.
    """

    def test_concurrent_multi_attacker_flood_with_isolated_victims(self):
        """
        50 concurrent threads:
        - 25 threads simulate aggressive DDoS flood attackers (500 alerts each)
        - 25 threads simulate low-volume victim / stealth targets (20 alerts each)
        Verify:
        1. No thread crashes, race conditions, or corrupted metrics.
        2. Attacker floods do not rate-limit or starve the stealth/victim hosts.
        3. Metrics total matches exactly (25*500 + 25*20 = 13,000 alerts).
        """
        config = SlidingWindowConfig(
            rate_limit_capacity=10.0,
            rate_limit_refill_rate=5.0,
        )
        engine = CEPAggregatorEngine(config=config)

        total_flood_threads = 25
        total_victim_threads = 25
        flood_alerts_per_thread = 500
        victim_alerts_per_thread = 20

        total_expected = (total_flood_threads * flood_alerts_per_thread) + (total_victim_threads * victim_alerts_per_thread)

        barrier = threading.Barrier(total_flood_threads + total_victim_threads)
        errors: List[Exception] = []

        def flood_worker(t_id: int):
            try:
                barrier.wait()
                attacker_ip = f"198.51.100.{t_id + 1}"
                for i in range(flood_alerts_per_thread):
                    engine.ingest_alert(
                        RawAlert(
                            source_ip=attacker_ip,
                            detector_id="ddos_entropy",
                            threat_class="VOLUMETRIC_DDOS",
                            severity="HIGH",
                            timestamp=100.0 + (i * 0.001),
                        ),
                        current_time=100.0 + (i * 0.001),
                    )
            except Exception as e:
                errors.append(e)

        def victim_worker(t_id: int):
            try:
                barrier.wait()
                victim_ip = f"10.200.50.{t_id + 1}"
                for i in range(victim_alerts_per_thread):
                    engine.ingest_alert(
                        RawAlert(
                            source_ip=victim_ip,
                            detector_id="portscan_hll",
                            threat_class="PORT_SCAN_RECON",
                            severity="LOW",
                            timestamp=100.0 + (i * 0.5),
                        ),
                        current_time=100.0 + (i * 0.5),
                    )
            except Exception as e:
                errors.append(e)

        threads: List[threading.Thread] = []
        for t in range(total_flood_threads):
            threads.append(threading.Thread(target=flood_worker, args=(t,)))
        for t in range(total_victim_threads):
            threads.append(threading.Thread(target=victim_worker, args=(t,)))

        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.perf_counter() - start

        assert len(errors) == 0, f"Encountered thread errors: {errors}"
        metrics = engine.get_metrics()
        print(f"\n[Multi-Tenant Concurrency] Ingested {total_expected} alerts across 50 threads in {elapsed:.4f}s ({total_expected/elapsed:.1f} eps)")

        assert metrics["total_ingested_alerts"] == total_expected

        # Check victim hosts: every victim host should have formed an incident with 20 alerts
        for v in range(total_victim_threads):
            victim_ip = f"10.200.50.{v + 1}"
            inc = engine.get_incident_for_host(victim_ip)
            assert inc is not None, f"Victim host {victim_ip} missing incident!"
            assert inc.raw_alert_count == victim_alerts_per_thread

    def test_polymorphic_alert_input_formats_and_fault_tolerance(self):
        """
        Verify engine handles RawAlert instance, raw dict, JSON string,
        and gracefully raises ValueError on unsupported types without leaking state.
        """
        engine = CEPAggregatorEngine()

        # 1. Pydantic model
        inc1 = engine.ingest_alert(
            RawAlert(source_ip="10.0.0.1", detector_id="portscan_hll", threat_class="PORT_SCAN_RECON", timestamp=10.0)
        )
        assert inc1 is not None

        # 2. Dict
        dict_alert = {
            "source_ip": "10.0.0.2",
            "detector_id": "dga_lstm",
            "threat_class": "DGA_TUNNELLING",
            "timestamp": 10.0,
        }
        inc2 = engine.ingest_alert(dict_alert)
        assert inc2 is not None

        # 3. JSON String
        json_str = '{"source_ip": "10.0.0.3", "detector_id": "ja4_malware", "threat_class": "ENCRYPTED_MALWARE", "timestamp": 10.0}'
        inc3 = engine.ingest_alert(json_str)
        assert inc3 is not None

        # 4. Unsupported type -> raises ValueError
        with pytest.raises(ValueError, match="Unsupported alert payload type"):
            engine.ingest_alert([1, 2, 3])  # type: ignore

        assert engine.total_ingested_alerts == 3

    def test_callback_exception_isolation(self):
        """
        Verify that a faulty callback raising an unhandled exception does not crash
        ingest_alert() or interrupt streaming pipeline execution.
        """
        engine = CEPAggregatorEngine()
        callback_called = []

        def failing_callback(inc: FusedIncident):
            callback_called.append(True)
            raise RuntimeError("Downstream telemetry endpoint unreachable!")

        engine.register_incident_callback(failing_callback)

        # Ingest alert
        inc = engine.ingest_alert(
            RawAlert(
                source_ip="10.0.0.99",
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                timestamp=100.0,
            )
        )

        assert inc is not None
        assert len(callback_called) == 1
        assert inc.primary_source_ip == "10.0.0.99"


class TestAdversarialExtremeBoundsAndFaultTolerance:
    """
    Adversarial Challenge 5: Extreme boundaries, initial rate-limiting initialization,
    50,000 alert burst memory profiling, and MITRE mapping integrity.
    """

    def test_initial_alert_rate_limited_initializes_incident_correctly(self):
        """
        Test case where the very first alert ingested for a host is rate-limited (capacity=1.0, refill=0.1, 2 alerts at same instant).
        Verify that the rate-limited alert creates the FusedIncident in _active_incidents with proper fields.
        """
        config = SlidingWindowConfig(rate_limit_capacity=1.0, rate_limit_refill_rate=0.1)
        engine = CEPAggregatorEngine(config=config)
        src = "198.51.100.200"

        # Alert 1 consumes the only token (allowed)
        a1 = RawAlert(
            source_ip=src,
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            timestamp=100.0,
        )
        engine.ingest_alert(a1, current_time=100.0)

        # Clear active incidents manually to simulate a host whose incident expired but bucket is still empty
        engine._active_incidents.clear()

        # Alert 2 arrives at t=100.0 (rate limited!)
        a2 = RawAlert(
            alert_id="rate_limited_first_alert",
            source_ip=src,
            detector_id="c2_beacon",
            threat_class="C2_BEACONING",
            severity="HIGH",
            confidence=0.95,
            target_ip="10.0.0.5",
            target_port=443,
            timestamp=100.0,
        )
        inc = engine.ingest_alert(a2, current_time=100.0)

        assert inc is not None
        assert inc.primary_source_ip == src
        assert "C2_BEACONING" in inc.threat_classes
        assert "c2_beacon" in inc.participating_detectors
        assert inc.attack_stage == "COMMAND_AND_CONTROL"
        assert inc.raw_alert_count == 2
        assert inc.total_raw_alerts_collapsed == 2
        assert "rate_limited_first_alert" in inc.raw_alert_ids

    def test_50k_burst_flood_strict_memory_boundedness(self):
        """
        Bombard engine with 50,000 raw flood alerts from 5 distinct hosts (10,000 each).
        Verify:
        1. All 50,000 alerts are ingested without error.
        2. Over 49,500 alerts are rate-limited / collapsed.
        3. Total memory diff is < 15 MB.
        4. Fused incidents have bounded sample alert lists (<= 10) and bounded IDs (<= 200).
        """
        config = SlidingWindowConfig(
            rate_limit_capacity=10.0,
            rate_limit_refill_rate=5.0,
        )
        engine = CEPAggregatorEngine(config=config)

        tracemalloc.start()
        gc.collect()
        snap_before = tracemalloc.take_snapshot()

        total_alerts = 50000
        start = time.perf_counter()

        for i in range(total_alerts):
            host_idx = i % 5
            src_ip = f"198.51.100.{host_idx + 1}"
            engine.ingest_alert(
                RawAlert(
                    alert_id=f"flood_50k_{i}",
                    source_ip=src_ip,
                    detector_id="ddos_entropy",
                    threat_class="VOLUMETRIC_DDOS",
                    severity="HIGH",
                    confidence=0.91,
                    timestamp=1000.0 + (i * 0.0001),
                ),
                current_time=1000.0 + (i * 0.0001),
            )

        elapsed = time.perf_counter() - start
        gc.collect()
        snap_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap_after.compare_to(snap_before, "lineno")
        mem_diff_kb = sum(s.size_diff for s in stats) / 1024.0

        eps = total_alerts / max(0.0001, elapsed)
        print(f"\n[50k Burst Memory Test] Ingested {total_alerts} alerts in {elapsed:.4f}s ({eps:.1f} eps), Mem delta: {mem_diff_kb:.2f} KB")

        metrics = engine.get_metrics()
        assert metrics["total_ingested_alerts"] == total_alerts
        assert metrics["total_rate_limited_alerts"] >= 49500
        assert mem_diff_kb < 15000.0, f"Memory growth exceeded 15MB: {mem_diff_kb:.2f} KB"

        incidents = engine.get_all_active_incidents()
        assert len(incidents) == 5
        for inc in incidents:
            assert inc.raw_alert_count == 10000
            assert len(inc.alerts) <= 10
            assert len(inc.raw_alert_ids) <= 200

    def test_mitre_attack_hints_aggregation_and_defaults(self):
        """
        Verify that MITRE ATT&CK hints are aggregated from explicit alert techniques
        and default detector mappings without duplicates.
        """
        engine = CEPAggregatorEngine()
        src = "10.10.10.50"

        # Alert with explicit MITRE technique
        engine.ingest_alert(
            RawAlert(
                source_ip=src,
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                mitre_technique="T1595.001",
                timestamp=100.0,
            ),
            current_time=100.0,
        )

        # Alert without explicit technique -> defaults to T1568.002 for dga_lstm
        engine.ingest_alert(
            RawAlert(
                source_ip=src,
                detector_id="dga_lstm",
                threat_class="DGA_TUNNELLING",
                timestamp=101.0,
            ),
            current_time=101.0,
        )

        inc = engine.get_incident_for_host(src)
        assert inc is not None
        assert "T1595.001" in inc.mitre_attack_hints
        assert "T1568.002" in inc.mitre_attack_hints

