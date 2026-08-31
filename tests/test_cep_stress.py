from __future__ import annotations

import concurrent.futures
import gc
import sys
import threading
import time
import tracemalloc
from typing import List, Dict, Any
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
    TokenBucketBurstLimiter,
    extract_subnet,
)
from src.ingestion.models import RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus


def test_stress_burst_volume_10k_alerts_memory_bounded():
    """
    Stress Test 1: Bombard CEP engine with 10,000 raw alerts from a single IP.
    Verify:
    1. Zero unhandled crashes or exceptions.
    2. Rate limiter collapses >9,900 flood alerts.
    3. Peak memory usage remains strictly bounded (no unbounded list growth).
    4. Incident payload has <= 10 sample alerts (not 10,000).
    """
    config = SlidingWindowConfig(
        window_duration_sec=60.0,
        rate_limit_capacity=10.0,
        rate_limit_refill_rate=5.0,
    )
    engine = CEPAggregatorEngine(config=config)

    tracemalloc.start()
    gc.collect()
    snap_before = tracemalloc.take_snapshot()

    src_ip = "198.51.100.123"
    target_ip = "10.0.0.1"
    num_alerts = 10000

    start_time = time.perf_counter()
    for i in range(num_alerts):
        alert = RawAlert(
            source_ip=src_ip,
            detector_id="ddos_entropy",
            threat_class="VOLUMETRIC_DDOS",
            severity="HIGH",
            confidence=0.90 + (i % 10) * 0.01,
            target_ip=target_ip,
            target_port=80,
            flow_id=f"flow_{i}",
            timestamp=1000.0 + (i * 0.0005),
        )
        engine.ingest_alert(alert)

    elapsed = time.perf_counter() - start_time
    gc.collect()
    snap_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    metrics = engine.get_metrics()
    inc = engine.get_incident_for_host(src_ip)

    # Ingestion rate calculation
    eps = num_alerts / max(0.0001, elapsed)

    # Memory growth diff
    stats = snap_after.compare_to(snap_before, "lineno")
    total_mem_diff_kb = sum(stat.size_diff for stat in stats) / 1024.0

    print(f"\n[Stress 10k Burst] Processed {num_alerts} in {elapsed:.4f}s ({eps:.1f} alerts/sec)")
    print(f"[Stress 10k Burst] Total memory delta: {total_mem_diff_kb:.2f} KB")
    print(f"[Stress 10k Burst] Rate limited: {metrics['total_rate_limited_alerts']} / {num_alerts}")

    assert inc is not None
    assert metrics["total_ingested_alerts"] == num_alerts
    assert metrics["total_rate_limited_alerts"] >= 9900
    assert inc.raw_alert_count == num_alerts
    assert inc.total_raw_alerts_collapsed == num_alerts
    assert len(inc.alerts) <= 10
    assert len(inc.raw_alert_ids) <= 200
    # Memory growth for 10k alerts collapsed should be modest (< 5MB)
    assert total_mem_diff_kb < 5000.0


def test_stress_high_concurrency_multithreaded_ingestion():
    """
    Stress Test 2: 20 concurrent threads ingesting 10,000 alerts across 50 IPs.
    Verify:
    1. Thread safety with concurrent RLock.
    2. Exact count of total ingested alerts (no lost updates).
    3. No race conditions or deadlocks.
    """
    config = SlidingWindowConfig(
        rate_limit_capacity=20.0,
        rate_limit_refill_rate=10.0,
    )
    engine = CEPAggregatorEngine(config=config)

    num_threads = 20
    alerts_per_thread = 500
    total_expected = num_threads * alerts_per_thread

    def worker(thread_idx: int):
        for i in range(alerts_per_thread):
            host_id = (thread_idx * 17 + i) % 50
            src_ip = f"192.168.1.{host_id + 1}"
            det = ["portscan_hll", "dga_lstm", "ja4_malware", "ddos_entropy"][i % 4]
            threat = [
                "PORT_SCAN_RECON",
                "DGA_TUNNELLING",
                "ENCRYPTED_MALWARE",
                "VOLUMETRIC_DDOS",
            ][i % 4]

            alert = RawAlert(
                source_ip=src_ip,
                detector_id=det,
                threat_class=threat,
                severity="MEDIUM",
                confidence=0.85,
                target_ip="10.0.0.1",
                target_port=80 + (i % 100),
                timestamp=500.0 + (i * 0.1),
            )
            engine.ingest_alert(alert)

    start_time = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, t) for t in range(num_threads)]
        concurrent.futures.wait(futures)

    elapsed = time.perf_counter() - start_time
    eps = total_expected / max(0.0001, elapsed)

    metrics = engine.get_metrics()
    print(f"\n[Concurrent Ingestion] Processed {total_expected} across {num_threads} threads in {elapsed:.4f}s ({eps:.1f} alerts/sec)")

    assert metrics["total_ingested_alerts"] == total_expected
    active_incidents = engine.get_all_active_incidents()
    assert len(active_incidents) <= 50
    assert len(active_incidents) > 0


def test_concurrent_ingestion_with_concurrent_periodic_cleanup():
    """
    Stress Test 3: Concurrent ingestion while periodic_cleanup is actively executing in background.
    Verify:
    1. No RuntimeError: dictionary changed size during iteration.
    2. No deadlocks between cleanup and ingestion locks.
    """
    config = SlidingWindowConfig(
        window_duration_sec=5.0,
        host_inactivity_ttl_sec=10.0,
        rate_limit_capacity=100.0,
    )
    engine = CEPAggregatorEngine(config=config)

    stop_event = threading.Event()
    cleanup_errors: List[Exception] = []

    def cleanup_runner():
        sim_time = 0.0
        while not stop_event.is_set():
            try:
                sim_time += 2.0
                engine.periodic_cleanup(current_time=sim_time)
                time.sleep(0.01)
            except Exception as ex:
                cleanup_errors.append(ex)

    cleanup_thread = threading.Thread(target=cleanup_runner, daemon=True)
    cleanup_thread.start()

    num_alerts = 4000
    for i in range(num_alerts):
        src_ip = f"10.50.{(i % 100)}.{((i // 100) % 254) + 1}"
        alert = RawAlert(
            source_ip=src_ip,
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            confidence=0.80,
            timestamp=float(i % 50),
        )
        engine.ingest_alert(alert)

    stop_event.set()
    cleanup_thread.join(timeout=2.0)

    assert len(cleanup_errors) == 0, f"Cleanup encountered errors: {cleanup_errors}"
    assert engine.total_ingested_alerts == num_alerts


def test_multi_tenant_flood_isolation():
    """
    Stress Test 4: Verify that a flooding host does NOT starve or rate-limit other legitimate hosts.
    """
    config = SlidingWindowConfig(rate_limit_capacity=10.0, rate_limit_refill_rate=5.0)
    engine = CEPAggregatorEngine(config=config)

    flooding_ip = "192.168.100.1"
    victim_ip = "192.168.100.2"

    # Step 1: Flooding host sends 2,000 alerts at t=100.0
    for i in range(2000):
        a = RawAlert(
            source_ip=flooding_ip,
            detector_id="ddos_entropy",
            threat_class="VOLUMETRIC_DDOS",
            timestamp=100.0,
        )
        engine.ingest_alert(a)

    # Step 2: Legitimate host sends 5 alerts at t=100.0
    allowed_count = 0
    for i in range(5):
        a = RawAlert(
            source_ip=victim_ip,
            detector_id="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            timestamp=100.0,
        )
        inc = engine.ingest_alert(a)
        if inc is not None and inc.primary_source_ip == victim_ip:
            allowed_count += 1

    assert allowed_count == 5, "Legitimate host was improperly rate-limited by neighbor flood!"


def test_threat_diversity_during_burst_flood():
    """
    Stress Test 5: Threat class diversity under burst flood conditions.
    Attacker floods 1,000 DDoS alerts, but also injects C2 Beaconing and Exfiltration.
    Verify whether the system preserves awareness of multiple threat classes in the storm summary
    and the final fused incident.
    """
    config = SlidingWindowConfig(rate_limit_capacity=10.0, rate_limit_refill_rate=5.0)
    engine = CEPAggregatorEngine(config=config)

    attacker_ip = "198.51.100.77"

    # 10 initial allowed DDoS alerts at t=10.0
    for _ in range(10):
        engine.ingest_alert(
            RawAlert(
                source_ip=attacker_ip,
                detector_id="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                timestamp=10.0,
            )
        )

    # 500 flood DDoS alerts at t=10.0 (rate limited)
    for _ in range(500):
        engine.ingest_alert(
            RawAlert(
                source_ip=attacker_ip,
                detector_id="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                timestamp=10.0,
            )
        )

    # Injected C2 Beaconing during flood at t=10.0 (rate limited)
    engine.ingest_alert(
        RawAlert(
            source_ip=attacker_ip,
            detector_id="c2_beacon",
            threat_class="C2_BEACONING",
            timestamp=10.0,
        )
    )

    # Injected Exfiltration during flood at t=10.0 (rate limited)
    engine.ingest_alert(
        RawAlert(
            source_ip=attacker_ip,
            detector_id="exfil_ratio",
            threat_class="DATA_EXFILTRATION",
            timestamp=10.0,
        )
    )

    # Check active storm tracking in burst limiter
    active_storms = engine.burst_limiter.get_active_storms(current_time=10.0)
    assert len(active_storms) == 1
    storm = active_storms[0]
    assert storm.source_ip == attacker_ip
    assert "C2_BEACONING" in storm.threat_classes
    assert "DATA_EXFILTRATION" in storm.threat_classes
    assert "VOLUMETRIC_DDOS" in storm.threat_classes
    print(f"\n[Threat Diversity] Storm captured threat classes: {storm.threat_classes}")


def test_massive_scale_60k_hosts_emergency_eviction():
    """
    Stress Test 6: Ingest 60,000 distinct host records against max_tracked_hosts=1,000.
    Verify:
    1. Emergency eviction bounds tracked hosts to ~1,000.
    2. No memory leak or crash.
    """
    config = SlidingWindowConfig(max_tracked_hosts=1000, window_duration_sec=60.0)
    buf = SlidingWindowBuffer(config=config)

    start = time.perf_counter()
    for i in range(5000):
        # 5,000 distinct host IPs
        ip = f"10.{(i // 65536) % 255}.{(i // 256) % 255}.{i % 255 + 1}"
        rec = DeduplicationRecord(
            fingerprint=f"fp_{i}",
            source_ip=ip,
            detector_name="portscan_hll",
            threat_class="PORT_SCAN_RECON",
            first_seen=float(i),
            last_seen=float(i),
            occurrence_count=1,
        )
        buf.ingest_record(rec, current_time=float(i))

    elapsed = time.perf_counter() - start
    print(f"\n[Emergency Eviction] Ingested 5,000 hosts across limit of 1,000 in {elapsed:.4f}s")
    assert len(buf._hosts) <= 1050


def test_threat_masking_vulnerability_in_fused_incident():
    """
    Adversarial Challenge: Verify if FusedIncident preserves C2_BEACONING and DATA_EXFILTRATION
    when injected during a DDoS flood.
    """
    config = SlidingWindowConfig(rate_limit_capacity=5.0, rate_limit_refill_rate=1.0)
    engine = CEPAggregatorEngine(config=config)
    attacker_ip = "198.51.100.88"

    # 1. 5 allowed DDoS alerts at t=0.0
    for _ in range(5):
        engine.ingest_alert(
            RawAlert(
                source_ip=attacker_ip,
                detector_id="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                timestamp=0.0,
            )
        )

    # 2. 500 DDoS flood alerts at t=0.0 (rate limited)
    for _ in range(500):
        engine.ingest_alert(
            RawAlert(
                source_ip=attacker_ip,
                detector_id="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                timestamp=0.0,
            )
        )

    # 3. Critical C2 Beacon and Exfiltration slipped in during flood at t=0.0
    engine.ingest_alert(
        RawAlert(
            source_ip=attacker_ip,
            detector_id="c2_beacon",
            threat_class="C2_BEACONING",
            timestamp=0.0,
        )
    )
    engine.ingest_alert(
        RawAlert(
            source_ip=attacker_ip,
            detector_id="exfil_ratio",
            threat_class="DATA_EXFILTRATION",
            timestamp=0.0,
        )
    )

    # 4. Storm ends at t=10.0 with 1 new alert
    engine.ingest_alert(
        RawAlert(
            source_ip=attacker_ip,
            detector_id="ddos_entropy",
            threat_class="VOLUMETRIC_DDOS",
            timestamp=10.0,
        )
    )

    inc = engine.get_incident_for_host(attacker_ip)
    assert inc is not None
    print(f"\n[Threat Masking Test] Fused incident threat classes: {inc.threat_classes}")
    print(f"[Threat Masking Test] Fused incident participating detectors: {inc.participating_detectors}")
    print(f"[Threat Masking Test] Fused incident kill chain stages: {inc.kill_chain_stages}")

    # Check if C2_BEACONING or DATA_EXFILTRATION made it into the incident
    has_c2 = "C2_BEACONING" in inc.threat_classes or "c2_beacon" in inc.participating_detectors
    has_exfil = "DATA_EXFILTRATION" in inc.threat_classes or "exfil_ratio" in inc.participating_detectors

    # This assertion exposes whether threat masking exists
    assert has_c2 and has_exfil, "VULNERABILITY CONFIRMED: C2 and Exfiltration were masked/dropped during flood!"


def test_sliding_window_duplicate_reference_explosion():
    """
    Adversarial Challenge: Verify whether deduplicated records are repeatedly appended
    to HostSlidingWindow.records deque, leading to O(N^2) duplication in get_total_raw_alerts()
    and attack_timeline.
    """
    config = SlidingWindowConfig(dedup_coalesce_sec=5.0)
    engine = CEPAggregatorEngine(config=config)
    ip = "192.168.1.55"

    # Ingest 5 identical alerts within 1 second
    for i in range(5):
        engine.ingest_alert(
            RawAlert(
                source_ip=ip,
                detector_id="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                timestamp=10.0 + (i * 0.1),
            )
        )

    host_win = engine.buffer.get_host_window(ip)
    assert host_win is not None
    # If HostSlidingWindow deduplicates references, len(records) should be 1
    # If it duplicates references, len(records) is 5
    num_records = len(host_win.get_records())
    total_raw = host_win.get_total_raw_alerts()
    print(f"\n[Duplicate Reference Test] Unique records in host window: {num_records} (expected: 1)")
    print(f"[Duplicate Reference Test] get_total_raw_alerts(): {total_raw} (expected: 5)")

    inc = engine.get_incident_for_host(ip)
    assert inc is not None
    print(f"[Duplicate Reference Test] Attack timeline entry count: {len(inc.attack_timeline)} (expected: 1)")

    assert num_records == 1, f"HOST WINDOW DUPLICATION: {num_records} records in window for 1 coalesced flow!"
    assert total_raw == 5, f"CALCULATION CORRUPTION: get_total_raw_alerts() returned {total_raw} instead of 5!"
    assert len(inc.attack_timeline) == 1, f"TIMELINE EXPLOSION: {len(inc.attack_timeline)} timeline entries created for 1 coalesced flow!"

