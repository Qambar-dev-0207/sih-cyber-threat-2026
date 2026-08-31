import ipaddress
import itertools
import math
import random
import threading
import time
import pytest

from src.cep.models import (
    AttackStage,
    DeduplicationRecord,
    FusedIncident,
    RawAlert,
    SlidingWindowConfig,
    SubnetAggregation,
)
from src.cep.sliding_window import (
    HostSlidingWindow,
    SubnetSlidingWindow,
    SlidingWindowBuffer,
    extract_subnet,
)
from src.cep.deduplicator import AlertDeduplicator, generate_flow_fingerprint
from src.cep.burst_limiter import TokenBucket, TokenBucketBurstLimiter
from src.cep.correlator import ConfidenceFuser, SignalCorrelator, DETECTOR_STAGE_MAP, MITRE_TECHNIQUE_DEFAULTS
from src.cep.engine import CEPAggregatorEngine


class TestSlidingWindowBoundaryEdgeCases:
    """
    Adversarial stress-testing of sliding window boundaries,
    temporal discontinuities, out-of-order timestamps, and microsecond precision.
    """

    def test_exact_expiration_boundary(self):
        """Test record eviction precisely at cutoff boundary (t == t0 + W and t == t0 + W + epsilon)."""
        window_duration = 60.0
        host_win = HostSlidingWindow("192.168.1.100", window_duration_sec=window_duration, created_at=1000.0)

        # Record 1 at t=1000.0
        rec1 = DeduplicationRecord(
            fingerprint="fp1",
            source_ip="192.168.1.100",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.8,
            first_seen=1000.0,
            last_seen=1000.0,
            occurrence_count=1,
        )
        host_win.add_record(rec1, current_time=1000.0)
        assert len(host_win.get_records()) == 1

        # At t=1060.0, cutoff is 1060.0 - 60.0 = 1000.0.
        # last_seen (1000.0) < cutoff (1000.0) is False. Record 1 should STILL be retained.
        host_win.evict_expired(1060.0)
        assert len(host_win.get_records()) == 1, "Record at exactly t0 should survive at t0 + W"

        # At t=1060.0001 (t0 + W + epsilon), cutoff is 1000.0001.
        # last_seen (1000.0) < cutoff (1000.0001) is True. Record 1 should be evicted.
        evicted = host_win.evict_expired(1060.0001)
        assert evicted == 1
        assert len(host_win.get_records()) == 0
        assert host_win.is_empty()

    def test_massive_forward_time_jump(self):
        """Test sliding window when a time jump of 100,000 seconds occurs."""
        host_win = HostSlidingWindow("10.0.0.5", window_duration_sec=60.0, created_at=1000.0)
        for i in range(10):
            rec = DeduplicationRecord(
                fingerprint=f"fp_{i}",
                source_ip="10.0.0.5",
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                confidence=0.8,
                first_seen=1000.0 + i,
                last_seen=1000.0 + i,
            )
            host_win.add_record(rec, current_time=1000.0 + i)

        assert len(host_win.get_records()) == 10

        # Massive jump
        jump_time = 1000.0 + 100_000.0
        rec_future = DeduplicationRecord(
            fingerprint="fp_future",
            source_ip="10.0.0.5",
            detector_id="c2_beaconing",
            threat_class="C2_BEACONING",
            confidence=0.9,
            first_seen=jump_time,
            last_seen=jump_time,
        )
        host_win.add_record(rec_future, current_time=jump_time)

        # All 10 past records should be evicted, only the future record should remain
        records = host_win.get_records()
        assert len(records) == 1
        assert records[0].fingerprint == "fp_future"
        assert host_win.last_activity == jump_time

    def test_sliding_window_deque_fifo_eviction_behavior(self):
        """
        Demonstrate FIFO eviction characteristics of HostSlidingWindow deque.
        In FIFO deque, records are evicted from the left as long as record[0].last_seen < cutoff.
        """
        host_win = HostSlidingWindow("172.16.0.10", window_duration_sec=60.0, created_at=500.0)

        # Monotonic timestamp ingestion: 500, 520, 540, 560
        timestamps = [500.0, 520.0, 540.0, 560.0]
        for idx, ts in enumerate(timestamps):
            rec = DeduplicationRecord(
                fingerprint=f"fp_mono_{idx}",
                source_ip="172.16.0.10",
                detector_id="dga_tunneling",
                threat_class="DGA_TUNNELLING",
                confidence=0.85,
                first_seen=ts,
                last_seen=ts,
            )
            host_win.add_record(rec, current_time=ts)

        assert len(host_win.get_records()) == 4

        # Add 5th record at ts=580.0 (cutoff = 580.0 - 60.0 = 520.0)
        # In add_record, evict_expired(580.0) pops record 0 (500.0 < 520.0).
        # Record at 520.0 survives (520.0 < 520.0 is False).
        rec5 = DeduplicationRecord(
            fingerprint="fp_mono_4",
            source_ip="172.16.0.10",
            detector_id="dga_tunneling",
            threat_class="DGA_TUNNELLING",
            confidence=0.85,
            first_seen=580.0,
            last_seen=580.0,
        )
        host_win.add_record(rec5, current_time=580.0)

        recs = host_win.get_records()
        assert len(recs) == 4
        surviving_ts = [r.last_seen for r in recs]
        assert surviving_ts == [520.0, 540.0, 560.0, 580.0]

    def test_window_buffer_emergency_eviction_under_host_saturation(self):
        """Test LRU emergency eviction when max_tracked_hosts limit is reached."""
        config = SlidingWindowConfig(max_tracked_hosts=100, window_duration_sec=60.0)
        buffer = SlidingWindowBuffer(config=config)

        # Ingest records for 120 distinct hosts
        for i in range(120):
            rec = DeduplicationRecord(
                fingerprint=f"fp_{i}",
                source_ip=f"10.0.{i // 256}.{i % 256}",
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                confidence=0.7,
                first_seen=100.0 + i,
                last_seen=100.0 + i,
            )
            buffer.ingest_record(rec, current_time=100.0 + i)

        # Active hosts tracked in buffer should not exceed max_tracked_hosts + emergency batch slack
        assert len(buffer._hosts) <= config.max_tracked_hosts

    def test_window_ttl_inactivity_pruning(self):
        """Test that inactive host windows and subnet windows are cleanly pruned after host_inactivity_ttl_sec."""
        config = SlidingWindowConfig(window_duration_sec=30.0, host_inactivity_ttl_sec=100.0)
        buffer = SlidingWindowBuffer(config=config)

        rec = DeduplicationRecord(
            fingerprint="fp_ttl",
            source_ip="192.168.10.50",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.8,
            first_seen=100.0,
            last_seen=100.0,
        )
        buffer.ingest_record(rec, current_time=100.0)

        # At t=150.0, record is expired from sliding window, but host window is within TTL (50s < 100s)
        buffer.periodic_cleanup(150.0)
        assert buffer.get_host_window("192.168.10.50") is not None
        assert buffer.get_host_window("192.168.10.50").is_empty()

        # At t=250.0 (150s elapsed > 100s TTL), host window and subnet window must be pruned
        pruned = buffer.periodic_cleanup(250.0)
        assert pruned >= 1
        assert buffer.get_host_window("192.168.10.50") is None
        assert buffer.get_subnet_window("192.168.10.0/24") is None


class TestSubnetGroupingEdgeCases:
    """
    Adversarial testing of IPv4/IPv6 CIDR extraction, edge IP addresses,
    broadcast, multicast, invalid formats, and campaign aggregation.
    """

    @pytest.mark.parametrize(
        "ip_str,prefix_v4,prefix_v6,expected_cidr",
        [
            ("192.168.1.1", 24, 48, "192.168.1.0/24"),
            ("192.168.1.0", 24, 48, "192.168.1.0/24"),  # Network address
            ("192.168.1.255", 24, 48, "192.168.1.0/24"),  # Broadcast address
            ("10.50.100.200", 16, 48, "10.50.0.0/16"),  # Custom /16 prefix
            ("10.50.100.200", 8, 48, "10.0.0.0/8"),  # Custom /8 prefix
            ("0.0.0.0", 24, 48, "0.0.0.0/24"),
            ("255.255.255.255", 24, 48, "255.255.255.0/24"),
            ("127.0.0.1", 24, 48, "127.0.0.0/24"),  # Loopback
            ("224.0.0.251", 24, 48, "224.0.0.0/24"),  # Multicast mDNS
            ("   192.168.10.20   ", 24, 48, "192.168.10.0/24"),  # Whitespace padding
            # IPv6 test cases
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 24, 48, "2001:db8:85a3::/48"),
            ("::1", 24, 48, "::/48"),  # IPv6 Loopback
            ("fe80::1ff:fe00:3a60", 24, 64, "fe80::/64"),  # Link-local /64
            ("::", 24, 48, "::/48"),  # Unspecified IPv6
            # Malformed / Non-IP cases (fallback safely)
            ("", 24, 48, "0.0.0.0/24"),
            ("invalid-ip-string", 24, 48, "invalid-ip-string/24"),
            ("999.999.999.999", 24, 48, "999.999.999.999/24"),
            ("c2.evil-domain.com", 24, 48, "c2.evil-domain.com/24"),
        ],
    )
    def test_extract_subnet_edge_cases(self, ip_str, prefix_v4, prefix_v6, expected_cidr):
        cidr = extract_subnet(ip_str, prefix_v4=prefix_v4, prefix_v6=prefix_v6)
        assert cidr == expected_cidr

    def test_subnet_sliding_window_campaign_detection(self):
        """Test campaign threshold triggering and host eviction in subnet window."""
        subnet_win = SubnetSlidingWindow("10.0.1.0/24", window_duration_sec=60.0, created_at=1000.0)

        # Add 2 hosts -> not a campaign yet (threshold = 3)
        for host in ["10.0.1.10", "10.0.1.20"]:
            rec = DeduplicationRecord(
                fingerprint=f"fp_{host}",
                source_ip=host,
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                confidence=0.8,
                first_seen=1000.0,
                last_seen=1000.0,
                occurrence_count=5,
            )
            subnet_win.update_host_activity(host, rec, current_time=1000.0)

        agg = subnet_win.get_aggregation(campaign_threshold=3)
        assert agg.is_campaign is False
        assert len(agg.active_hosts) == 2
        assert agg.total_alerts == 10

        # Add 3rd host at t=1010.0 -> is_campaign becomes True
        rec3 = DeduplicationRecord(
            fingerprint="fp_host3",
            source_ip="10.0.1.30",
            detector_id="c2_beaconing",
            threat_class="C2_BEACONING",
            confidence=0.95,
            first_seen=1010.0,
            last_seen=1010.0,
            occurrence_count=2,
        )
        subnet_win.update_host_activity("10.0.1.30", rec3, current_time=1010.0)

        agg2 = subnet_win.get_aggregation(campaign_threshold=3)
        assert agg2.is_campaign is True
        assert len(agg2.active_hosts) == 3
        assert set(agg2.participating_detectors) == {"portscan_hll", "c2_beaconing"}
        assert set(agg2.threat_classes) == {"PORT_SCAN_RECON", "C2_BEACONING"}
        assert agg2.total_alerts == 12

        # Advance time to t=1065.0: hosts 1 and 2 (last_seen=1000.0) expire (cutoff = 1065 - 60 = 1005)
        # Only host 3 (last_seen=1010.0) survives
        evicted = subnet_win.evict_expired(1065.0)
        assert evicted == 2
        agg3 = subnet_win.get_aggregation(campaign_threshold=3)
        assert agg3.is_campaign is False
        assert agg3.active_hosts == ["10.0.1.30"]
        assert agg3.total_alerts == 2


class TestMultiDetectorKillChainSequences:
    """
    Adversarial testing of complex multi-detector kill-chain sequences,
    conflicting/overlapping alerts, out-of-order stages, and composite classification.
    """

    def test_full_five_stage_kill_chain_escalation(self):
        """
        Verify end-to-end multi-detector kill chain:
        Recon (portscan_hll) -> Delivery (dga_tunneling) -> C2 (c2_beaconing) -> Exfil (exfil_ratio) -> DDoS (ddos_entropy)
        """
        config = SlidingWindowConfig(window_duration_sec=120.0)
        correlator = SignalCorrelator(config=config)
        host_win = HostSlidingWindow("192.168.50.15", window_duration_sec=120.0, created_at=100.0)

        stages_data = [
            ("portscan_hll", "PORT_SCAN_RECON", "LOW", 0.70, 100.0, AttackStage.RECONNAISSANCE),
            ("dga_tunneling", "DGA_TUNNELLING", "MEDIUM", 0.85, 110.0, AttackStage.DELIVERY),
            ("c2_beaconing", "C2_BEACONING", "HIGH", 0.92, 120.0, AttackStage.COMMAND_AND_CONTROL),
            ("exfil_ratio", "DATA_EXFILTRATION", "HIGH", 0.88, 130.0, AttackStage.EXFILTRATION),
            ("ddos_entropy", "VOLUMETRIC_DDOS", "CRITICAL", 0.95, 140.0, AttackStage.ACTIONS_ON_OBJECTIVES),
        ]

        for det, threat, sev, conf, ts, expected_stg in stages_data:
            rec = DeduplicationRecord(
                fingerprint=f"fp_{det}",
                source_ip="192.168.50.15",
                detector_id=det,
                threat_class=threat,
                severity=sev,
                confidence=conf,
                target_ip="10.0.0.1",
                target_port=443,
                first_seen=ts,
                last_seen=ts,
                occurrence_count=1,
            )
            host_win.add_record(rec, current_time=ts)

        incident = correlator.correlate_host(host_win, current_time=140.0)
        assert incident is not None
        assert incident.threat_class == "APT_MULTI_STAGE_ATTACK"
        assert incident.severity == "CRITICAL"
        assert len(incident.participating_detectors) == 5
        assert len(incident.kill_chain_stages) == 5
        assert incident.kill_chain_stages == [
            "RECONNAISSANCE",
            "DELIVERY",
            "COMMAND_AND_CONTROL",
            "EXFILTRATION",
            "ACTIONS_ON_OBJECTIVES",
        ]
        # Verify chronological timeline ordering
        timeline_ts = [entry.timestamp for entry in incident.attack_timeline]
        assert timeline_ts == [100.0, 110.0, 120.0, 130.0, 140.0]

    def test_reverse_order_stage_arrival(self):
        """
        Verify that out-of-order stage arrivals (e.g. Exfil received BEFORE Recon)
        are properly sorted in the timeline and classified correctly.
        """
        correlator = SignalCorrelator()
        host_win = HostSlidingWindow("10.10.10.10", window_duration_sec=60.0, created_at=100.0)

        # Ingest Exfiltration (t=120.0), then Recon (t=100.0), then Delivery (t=110.0)
        recs = [
            DeduplicationRecord(
                fingerprint="fp_exfil",
                source_ip="10.10.10.10",
                detector_id="exfil_ratio",
                threat_class="DATA_EXFILTRATION",
                severity="HIGH",
                confidence=0.88,
                first_seen=120.0,
                last_seen=120.0,
            ),
            DeduplicationRecord(
                fingerprint="fp_recon",
                source_ip="10.10.10.10",
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                severity="LOW",
                confidence=0.65,
                first_seen=100.0,
                last_seen=100.0,
            ),
            DeduplicationRecord(
                fingerprint="fp_dga",
                source_ip="10.10.10.10",
                detector_id="dga_tunneling",
                threat_class="DGA_TUNNELLING",
                severity="MEDIUM",
                confidence=0.80,
                first_seen=110.0,
                last_seen=110.0,
            ),
        ]

        for r in recs:
            host_win.add_record(r, current_time=125.0)

        incident = correlator.correlate_host(host_win, current_time=125.0)
        assert incident is not None
        # Check that timeline is sorted by timestamp (100.0, 110.0, 120.0)
        stages_in_timeline = [entry.stage for entry in incident.attack_timeline]
        assert stages_in_timeline == ["RECONNAISSANCE", "DELIVERY", "EXFILTRATION"]

    def test_single_detector_many_alerts_does_not_escalate_to_apt(self):
        """
        Verify that 100 alerts from the SAME detector (e.g. portscan_hll)
        do NOT get misclassified as APT_MULTI_STAGE_ATTACK.
        """
        correlator = SignalCorrelator()
        host_win = HostSlidingWindow("192.168.1.5", window_duration_sec=60.0, created_at=100.0)

        for port in range(1, 20):
            rec = DeduplicationRecord(
                fingerprint=f"fp_port_{port}",
                source_ip="192.168.1.5",
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                severity="LOW",
                confidence=0.75,
                target_ip="192.168.1.1",
                target_port=port,
                first_seen=100.0 + port,
                last_seen=100.0 + port,
                occurrence_count=5,
            )
            host_win.add_record(rec, current_time=100.0 + port)

        incident = correlator.correlate_host(host_win, current_time=120.0)
        assert incident is not None
        assert incident.threat_class == "PORT_SCAN_RECON"
        assert incident.participating_detectors == ["portscan_hll"]
        assert len(incident.target_ports) == 19
        assert incident.raw_alert_count == 19 * 5


class TestConfidenceFusionMathematicalAccuracy:
    """
    Adversarial verification of the mathematical confidence fusion engine:
    C = min(1.0, 1 - prod(1 - c_i) + synergy_boost).
    Tests permutations, limits, monotonic increases, precision, and boundary clamping.
    """

    def test_probabilistic_union_exact_calculations(self):
        config = SlidingWindowConfig(
            multi_detector_synergy_2=0.05,
            multi_detector_synergy_3_plus=0.10,
            max_confidence_clamp=1.0,
        )

        # Case 1: Single alert c = 0.6, 1 detector -> 1 - (1 - 0.6) = 0.60, boost = 0
        c1 = ConfidenceFuser.compute_fused_confidence([0.6], unique_detector_count=1, config=config)
        assert math.isclose(c1, 0.60, abs_tol=1e-4)

        # Case 2: Two alerts [0.5, 0.4] from same detector (unique=1) -> 1 - (0.5 * 0.6) = 0.70, boost = 0
        c2 = ConfidenceFuser.compute_fused_confidence([0.5, 0.4], unique_detector_count=1, config=config)
        assert math.isclose(c2, 0.70, abs_tol=1e-4)

        # Case 3: Two alerts [0.5, 0.4] from TWO distinct detectors -> 0.70 + 0.05 = 0.75
        c3 = ConfidenceFuser.compute_fused_confidence([0.5, 0.4], unique_detector_count=2, config=config)
        assert math.isclose(c3, 0.75, abs_tol=1e-4)

        # Case 4: Three alerts [0.6, 0.5, 0.4] from THREE distinct detectors
        # prod = 0.4 * 0.5 * 0.6 = 0.12 -> base = 0.88 -> boost = 0.10 -> fused = 0.98
        c4 = ConfidenceFuser.compute_fused_confidence([0.6, 0.5, 0.4], unique_detector_count=3, config=config)
        assert math.isclose(c4, 0.98, abs_tol=1e-4)

    def test_permutation_invariance(self):
        """Confidence fusion MUST be strictly invariant under all permutations of confidences."""
        config = SlidingWindowConfig()
        confidences = [0.12, 0.45, 0.78, 0.91, 0.33]

        all_perms = list(itertools.permutations(confidences))
        expected = ConfidenceFuser.compute_fused_confidence(confidences, unique_detector_count=3, config=config)

        # Test 50 random permutations
        sampled_perms = random.sample(all_perms, min(50, len(all_perms)))
        for perm in sampled_perms:
            fused = ConfidenceFuser.compute_fused_confidence(list(perm), unique_detector_count=3, config=config)
            assert math.isclose(fused, expected, abs_tol=1e-4), f"Permutation {perm} gave {fused} != {expected}"

    def test_monotonicity_property(self):
        """Adding any new evidence with confidence > 0.0 must never decrease fused confidence."""
        config = SlidingWindowConfig()
        current_confs = [0.4]
        prev_fused = ConfidenceFuser.compute_fused_confidence(current_confs, unique_detector_count=1, config=config)

        for _ in range(20):
            new_c = random.uniform(0.01, 0.99)
            current_confs.append(new_c)
            new_fused = ConfidenceFuser.compute_fused_confidence(
                current_confs, unique_detector_count=1, config=config
            )
            assert new_fused >= prev_fused, f"Monotonicity violated: {new_fused} < {prev_fused}"
            prev_fused = new_fused

    def test_extreme_and_boundary_confidences(self):
        """Test confidence = 0.0, 1.0, and clamping beyond boundaries."""
        config = SlidingWindowConfig(max_confidence_clamp=1.0)

        # Any 1.0 confidence -> fused is 1.0
        assert ConfidenceFuser.compute_fused_confidence([1.0, 0.2], 1, config) == 1.0
        assert ConfidenceFuser.compute_fused_confidence([0.9, 0.9, 0.9], 4, config) == 1.0  # (0.999 + 0.10) clamped to 1.0

        # All 0.0 confidences
        assert ConfidenceFuser.compute_fused_confidence([0.0, 0.0], 1, config) == 0.0
        assert ConfidenceFuser.compute_fused_confidence([0.0, 0.0], 2, config) == 0.05  # synergy boost added

        # Empty list fallback
        assert ConfidenceFuser.compute_fused_confidence([], 0, config) == 0.8


class TestCEPAggregatorEngineEndToEndStress:
    """
    Stress test the complete CEP Engine under high burst floods,
    deduplication, streaming bus ingestion, and concurrent threads.
    """

    def test_10000_alert_burst_flood_shield(self):
        """Verify engine sustains 10,000 alerts in single burst without crashing or unbounded growth."""
        engine = CEPAggregatorEngine()
        src_ip = "198.51.100.42"
        now = time.time()

        for i in range(10000):
            alert = RawAlert(
                alert_id=f"alert_flood_{i}",
                timestamp=now + (i * 0.0001),
                detector_id="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                severity="HIGH",
                confidence=0.90,
                source_ip=src_ip,
                target_ip="203.0.113.1",
                target_port=80,
                evidence={"pps": 50000 + i, "entropy": 1.2},
            )
            engine.ingest_alert(alert, current_time=now + (i * 0.0001))

        metrics = engine.get_metrics()
        assert metrics["total_ingested_alerts"] == 10000
        assert metrics["total_rate_limited_alerts"] > 9900

        incident = engine.get_incident_for_host(src_ip)
        assert incident is not None
        assert incident.raw_alert_count == 10000
        assert incident.total_raw_alerts_collapsed == 10000
        # Check bounded sample alerts
        assert len(incident.alerts) <= 10

    def test_concurrent_multithreaded_ingestion_stress(self):
        """Verify thread-safety when 10 threads simultaneously ingest alerts for overlapping IPs."""
        engine = CEPAggregatorEngine()
        num_threads = 10
        alerts_per_thread = 100
        barrier = threading.Barrier(num_threads)
        errors = []

        def worker(thread_idx: int):
            try:
                barrier.wait()
                for i in range(alerts_per_thread):
                    ip = f"10.20.{(thread_idx % 4)}.{i % 10}"
                    alert = RawAlert(
                        alert_id=f"thread_{thread_idx}_alert_{i}",
                        timestamp=1000.0 + (i * 0.1),
                        detector_id="portscan_hll" if i % 2 == 0 else "c2_beaconing",
                        threat_class="PORT_SCAN_RECON" if i % 2 == 0 else "C2_BEACONING",
                        severity="MEDIUM",
                        confidence=0.8,
                        source_ip=ip,
                        target_ip="192.168.1.1",
                        target_port=80 + (i % 10),
                    )
                    engine.ingest_alert(alert, current_time=1000.0 + (i * 0.1))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors encountered: {errors}"
        metrics = engine.get_metrics()
        assert metrics["total_ingested_alerts"] == num_threads * alerts_per_thread


class TestEmpiricalChallengerFindings:
    """
    Verification tests confirming remediation of empirical findings in src/cep/:
    Finding 1: Typo in DETECTOR_STAGE_MAP for DATA_EXFILTRATION fixed.
    Finding 2: Deque eviction handles non-monotonic / out-of-order timestamps without trapping.
    Finding 3: Coalesce window condition correctly rejects negative time delta.
    """

    def test_finding_typo_in_data_exfiltration_stage_map(self):
        """
        Verify that DETECTOR_STAGE_MAP contains 'DATA_EXFILTRATION'
        and maps custom detector alerts to AttackStage.EXFILTRATION.
        """
        assert "DATA_EXFILTRATION" in DETECTOR_STAGE_MAP

        correlator = SignalCorrelator()
        stage = correlator.classify_stage(detector_name="suricata_custom_detector", threat_class="DATA_EXFILTRATION")
        assert stage == AttackStage.EXFILTRATION

    def test_finding_out_of_order_deque_trapping(self):
        """
        Verify that HostSlidingWindow's eviction loop cleanly removes expired
        records even when an out-of-order older record was appended.
        """
        host_win = HostSlidingWindow("192.168.1.50", window_duration_sec=60.0, created_at=500.0)

        # Ingest record at t=500.0
        rec_500 = DeduplicationRecord(
            fingerprint="fp_500",
            source_ip="192.168.1.50",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.8,
            first_seen=500.0,
            last_seen=500.0,
        )
        host_win.add_record(rec_500, current_time=500.0)

        # Ingest record at t=550.0
        rec_550 = DeduplicationRecord(
            fingerprint="fp_550",
            source_ip="192.168.1.50",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.8,
            first_seen=550.0,
            last_seen=550.0,
        )
        host_win.add_record(rec_550, current_time=550.0)

        # Ingest out-of-order record at t=480.0 (appended to right of deque)
        rec_480 = DeduplicationRecord(
            fingerprint="fp_480",
            source_ip="192.168.1.50",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.8,
            first_seen=480.0,
            last_seen=480.0,
        )
        host_win.records.append(rec_480)

        # At t=560.0, cutoff is 500.0.
        # rec_480 (last_seen=480.0) must be evicted (480 < 500)
        host_win.evict_expired(560.0)
        recs = host_win.get_records()
        last_seen_list = [r.last_seen for r in recs]
        assert 480.0 not in last_seen_list, "Expired record at 480.0 was properly evicted despite out-of-order arrival"

    def test_finding_deduplicator_negative_delta_coalescing(self):
        """
        Verify that AlertDeduplicator does not coalesce historical alerts from the past into active records.
        """
        dedup = AlertDeduplicator(config=SlidingWindowConfig(dedup_coalesce_sec=5.0))

        # First alert at t=1000.0
        a1 = RawAlert(
            source_ip="10.0.0.1",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            severity="MEDIUM",
            confidence=0.75,
            timestamp=1000.0,
        )
        is_dup1, rec1 = dedup.deduplicate(a1, current_time=1000.0)
        assert not is_dup1
        assert rec1.occurrence_count == 1

        # An alert from 500 seconds in the past (t=500.0)
        # (500.0 - 1000.0) = -500.0 < 0.0, so should not coalesce
        a_old = RawAlert(
            source_ip="10.0.0.1",
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            severity="MEDIUM",
            confidence=0.75,
            timestamp=500.0,
        )
        is_dup_old, rec_old = dedup.deduplicate(a_old, current_time=500.0)
        assert is_dup_old is False, "Old alert from 500s past should NOT coalesce with newer record"
        assert rec_old.occurrence_count == 1
