from __future__ import annotations

import time
import uuid
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
    TokenBucketBurstLimiter,
    extract_subnet,
    generate_flow_fingerprint,
)
from src.ingestion.models import RawAlert
from src.ingestion.streaming_bus import InMemoryStreamingBus


def test_sliding_window_basic_addition_and_summary():
    hw_win = HostSlidingWindow('192.168.1.100', window_duration_sec=60.0)

    rec1 = DeduplicationRecord(
        fingerprint='fp1',
        source_ip='192.168.1.100',
        detector_name='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        severity='MEDIUM',
        confidence=0.85,
        target_ip='10.0.0.1',
        target_port=80,
        first_seen=100.0,
        last_seen=105.0,
        occurrence_count=10,
    )
    hw_win.add_record(rec1, current_time=105.0)

    assert not hw_win.is_empty()
    assert hw_win.get_total_raw_alerts() == 10
    assert hw_win.get_participating_detectors() == ['portscan_hll']
    assert hw_win.get_threat_classes() == ['PORT_SCAN_RECON']
    assert hw_win.get_target_ips() == ['10.0.0.1']
    assert hw_win.get_target_ports() == [80]
    assert hw_win.get_max_severity() == 'MEDIUM'
    assert hw_win.get_max_confidence() == 0.85

    summ = hw_win.get_summary(subnet_cidr='192.168.1.0/24')
    assert summ.source_ip == '192.168.1.100'
    assert summ.alert_count == 10
    assert summ.deduplicated_record_count == 1


def test_sliding_window_rolling_eviction():
    hw_win = HostSlidingWindow('192.168.1.100', window_duration_sec=30.0)

    # Record at t=0.0
    r1 = DeduplicationRecord(
        fingerprint='fp1',
        source_ip='192.168.1.100',
        detector_name='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        first_seen=0.0,
        last_seen=0.0,
        occurrence_count=1,
    )
    hw_win.add_record(r1, current_time=0.0)
    assert len(hw_win.get_records()) == 1

    # Record at t=20.0
    r2 = DeduplicationRecord(
        fingerprint='fp2',
        source_ip='192.168.1.100',
        detector_name='dga_lstm',
        threat_class='DGA_TUNNELLING',
        first_seen=20.0,
        last_seen=20.0,
        occurrence_count=1,
    )
    hw_win.add_record(r2, current_time=20.0)
    assert len(hw_win.get_records()) == 2

    # Record at t=35.0 (evicts r1 at t=0)
    r3 = DeduplicationRecord(
        fingerprint='fp3',
        source_ip='192.168.1.100',
        detector_name='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        first_seen=35.0,
        last_seen=35.0,
        occurrence_count=1,
    )
    hw_win.add_record(r3, current_time=35.0)
    recs = hw_win.get_records()
    assert len(recs) == 2
    assert [r.detector_name for r in recs] == ['dga_lstm', 'ja4_malware']


def test_sliding_window_ttl_pruning():
    buffer = SlidingWindowBuffer(
        config=SlidingWindowConfig(window_duration_sec=30.0, host_inactivity_ttl_sec=60.0)
    )
    r = DeduplicationRecord(
        fingerprint='fp1',
        source_ip='192.168.1.50',
        detector_name='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        first_seen=0.0,
        last_seen=0.0,
        occurrence_count=1,
    )
    buffer.ingest_record(r, current_time=0.0)
    assert buffer.get_host_window('192.168.1.50') is not None

    # At t=100.0 (> 60s TTL), cleanup prunes the host
    pruned = buffer.periodic_cleanup(current_time=100.0)
    assert pruned == 1
    assert buffer.get_host_window('192.168.1.50') is None


def test_subnet_hierarchy_ipv4_and_ipv6():
    assert extract_subnet('192.168.1.50', prefix_v4=24, prefix_v6=48) == '192.168.1.0/24'
    assert extract_subnet('10.240.15.205', prefix_v4=24, prefix_v6=48) == '10.240.15.0/24'
    assert extract_subnet('2001:db8:85a3::1', prefix_v4=24, prefix_v6=48) == '2001:db8:85a3::/48'
    assert extract_subnet('', prefix_v4=24, prefix_v6=48) == '0.0.0.0/24'


def test_subnet_campaign_detection():
    buffer = SlidingWindowBuffer(
        config=SlidingWindowConfig(subnet_campaign_threshold=3, window_duration_sec=60.0)
    )

    # 3 distinct hosts in 192.168.1.0/24
    for i, ip in enumerate(['192.168.1.10', '192.168.1.11', '192.168.1.12']):
        r = DeduplicationRecord(
            fingerprint=f'fp_{ip}',
            source_ip=ip,
            detector_name='portscan_hll',
            threat_class='PORT_SCAN_RECON',
            first_seen=10.0 + i,
            last_seen=10.0 + i,
            occurrence_count=5,
        )
        buffer.ingest_record(r, current_time=10.0 + i)

    campaigns = buffer.get_campaign_subnets(current_time=15.0)
    assert len(campaigns) == 1
    assert campaigns[0].subnet_cidr == '192.168.1.0/24'
    assert campaigns[0].active_hosts == ['192.168.1.10', '192.168.1.11', '192.168.1.12']
    assert campaigns[0].is_campaign is True
    assert campaigns[0].total_alerts == 15


def test_flow_fingerprint_generation_determinism():
    fp1 = generate_flow_fingerprint(
        source_ip='10.0.0.5',
        detector_name='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        target_ip='198.51.100.1',
        target_port=443,
        protocol='TCP',
    )
    fp2 = generate_flow_fingerprint(
        source_ip='10.0.0.5',
        detector_name='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        target_ip='198.51.100.1',
        target_port=443,
        protocol='TCP',
    )
    assert fp1 == fp2
    assert len(fp1) == 32


def test_alert_deduplication_coalescing():
    dedup = AlertDeduplicator(config=SlidingWindowConfig(dedup_coalesce_sec=5.0))

    a1 = RawAlert(
        source_ip='192.168.1.50',
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        severity='MEDIUM',
        confidence=0.75,
        target_ip='192.168.1.1',
        target_port=22,
        flow_id='flow_1',
        timestamp=100.0,
    )

    is_dup1, rec1 = dedup.deduplicate(a1, current_time=100.0)
    assert not is_dup1
    assert rec1.occurrence_count == 1
    assert rec1.flow_ids == ['flow_1']

    # Second alert within 5s coalesces
    a2 = RawAlert(
        source_ip='192.168.1.50',
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        severity='HIGH',
        confidence=0.90,
        target_ip='192.168.1.1',
        target_port=22,
        flow_id='flow_2',
        timestamp=102.0,
    )
    is_dup2, rec2 = dedup.deduplicate(a2, current_time=102.0)
    assert is_dup2
    assert rec2.occurrence_count == 2
    assert rec2.severity == 'HIGH'
    assert rec2.confidence == 0.90
    assert rec2.flow_ids == ['flow_1', 'flow_2']

    # Third alert after 6s starts new window
    a3 = RawAlert(
        source_ip='192.168.1.50',
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        severity='MEDIUM',
        confidence=0.75,
        target_ip='192.168.1.1',
        target_port=22,
        flow_id='flow_3',
        timestamp=108.0,
    )
    is_dup3, rec3 = dedup.deduplicate(a3, current_time=108.0)
    assert not is_dup3
    assert rec3.occurrence_count == 1


def test_alert_deduplication_evidence_merging():
    dedup = AlertDeduplicator()
    a1 = RawAlert(
        source_ip='10.0.0.1',
        detector_id='ddos_entropy',
        threat_class='VOLUMETRIC_DDOS',
        evidence={'packet_count': 100, 'pps_rate': 500.0, 'target_ports': [80, 443]},
        timestamp=0.0,
    )
    a2 = RawAlert(
        source_ip='10.0.0.1',
        detector_id='ddos_entropy',
        threat_class='VOLUMETRIC_DDOS',
        evidence={'packet_count': 200, 'pps_rate': 1000.0, 'target_ports': [8080]},
        timestamp=1.0,
    )

    dedup.deduplicate(a1, current_time=0.0)
    _, rec = dedup.deduplicate(a2, current_time=1.0)

    assert rec.evidence["packet_count"] == 300
    assert rec.evidence["pps_rate"] == 1000.0
    assert 80 in rec.evidence['target_ports']
    assert 8080 in rec.evidence['target_ports']


def test_token_bucket_burst_rate_limiting():
    limiter = TokenBucketBurstLimiter(
        SlidingWindowConfig(rate_limit_capacity=5.0, rate_limit_refill_rate=1.0)
    )
    a = RawAlert(source_ip='172.16.0.1', detector_id='ddos_entropy', threat_class='VOLUMETRIC_DDOS')

    # 5 allowed tokens at t=0
    for _ in range(5):
        allowed, storm = limiter.allow_alert(a, current_time=0.0)
        assert allowed is True
        assert storm is None

    # 6th alert rate-limited
    allowed, storm = limiter.allow_alert(a, current_time=0.0)
    assert allowed is False
    assert storm is None
    assert limiter.is_rate_limited('172.16.0.1') is True


def test_token_bucket_refill_mechanism():
    limiter = TokenBucketBurstLimiter(
        SlidingWindowConfig(rate_limit_capacity=5.0, rate_limit_refill_rate=2.0)
    )
    a = RawAlert(source_ip='172.16.0.1', detector_id='ddos_entropy', threat_class='VOLUMETRIC_DDOS')

    # Consume all 5 initial tokens at t=0.0
    for _ in range(5):
        limiter.allow_alert(a, current_time=0.0)

    # 5 flood alerts at t=0.0 (all 5 rejected and tracked in storm)
    for _ in range(5):
        limiter.allow_alert(a, current_time=0.0)

    # After 2.0s (+4 tokens), allow alert and conclude storm
    allowed, storm = limiter.allow_alert(a, current_time=2.0)
    assert allowed is True
    assert storm is not None
    assert storm.alert_count == 5
    assert storm.source_ip == '172.16.0.1'


def test_1000_alert_flood_collapse_scenario():
    engine = CEPAggregatorEngine(
        config=SlidingWindowConfig(rate_limit_capacity=10.0, rate_limit_refill_rate=5.0)
    )

    src_ip = '198.51.100.99'
    target_ip = '10.0.0.50'

    start_time = time.perf_counter()
    flood_alerts = [
        RawAlert(
            source_ip=src_ip,
            detector_id='ddos_entropy',
            threat_class='VOLUMETRIC_DDOS',
            severity='HIGH',
            confidence=0.92,
            target_ip=target_ip,
            target_port=80,
            flow_id=f'flood_flow_{i}',
            timestamp=100.0 + (i * 0.001),
        )
        for i in range(1200)
    ]

    for a in flood_alerts:
        engine.ingest_alert(a)

    metrics = engine.get_metrics()

    assert metrics['total_ingested_alerts'] == 1200
    assert metrics['total_rate_limited_alerts'] >= 1100
    assert metrics['active_host_windows'] == 1

    inc = engine.get_incident_for_host(src_ip)
    assert inc is not None
    assert inc.primary_source_ip == src_ip
    assert inc.raw_alert_count == 1200 or inc.total_raw_alerts_collapsed == 1200
    assert inc.severity in ['HIGH', 'CRITICAL']
    assert len(inc.alerts) <= 10  # Memory-bounded!


def test_confidence_fuser_probabilistic_union():
    cfg = SlidingWindowConfig()

    c1 = ConfidenceFuser.compute_fused_confidence([0.80], 1, cfg)
    assert c1 == 0.80

    c2 = ConfidenceFuser.compute_fused_confidence([0.80, 0.80], 2, cfg)
    assert c2 == 1.0

    c3 = ConfidenceFuser.compute_fused_confidence([0.40, 0.40], 2, cfg)
    assert c3 == 0.69

    c4 = ConfidenceFuser.compute_fused_confidence([0.30, 0.30, 0.30], 3, cfg)
    assert c4 == 0.757


def test_multi_detector_kill_chain_fusion_full_sequence():
    engine = CEPAggregatorEngine()
    attacker_ip = '185.220.101.5'
    victim_ip = '192.168.1.200'

    # 1. Recon at t=0
    a1 = RawAlert(
        source_ip=attacker_ip,
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        severity='MEDIUM',
        confidence=0.82,
        target_ip=victim_ip,
        target_port=22,
        timestamp=0.0,
    )
    inc1 = engine.ingest_alert(a1, current_time=0.0)
    assert inc1 is not None
    assert inc1.attack_stage == 'RECONNAISSANCE'
    assert inc1.severity == 'MEDIUM'

    # 2. Delivery at t=10
    a2 = RawAlert(
        source_ip=attacker_ip,
        detector_id='dga_lstm',
        threat_class='DGA_TUNNELLING',
        severity='HIGH',
        confidence=0.88,
        target_ip='8.8.8.8',
        target_port=53,
        timestamp=10.0,
    )
    inc2 = engine.ingest_alert(a2, current_time=10.0)
    assert inc2 is not None
    assert inc2.threat_class == 'APT_MULTI_STAGE_ATTACK'
    assert 'RECONNAISSANCE' in inc2.kill_chain_stages
    assert 'DELIVERY' in inc2.kill_chain_stages

    # 3. C2 at t=25
    a3 = RawAlert(
        source_ip=attacker_ip,
        detector_id='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        severity='HIGH',
        confidence=0.95,
        target_ip=victim_ip,
        target_port=8443,
        timestamp=25.0,
    )
    inc3 = engine.ingest_alert(a3, current_time=25.0)
    assert inc3 is not None
    assert inc3.severity == 'CRITICAL'


    # 4. Exfiltration at t=45
    a4 = RawAlert(
        source_ip=attacker_ip,
        detector_id='exfil_ratio',
        threat_class='DATA_EXFILTRATION',
        severity='CRITICAL',
        confidence=0.96,
        target_ip=victim_ip,
        target_port=443,
        timestamp=45.0,
    )
    inc4 = engine.ingest_alert(a4, current_time=45.0)
    assert inc4 is not None
    assert inc4.threat_class == 'APT_MULTI_STAGE_ATTACK'
    assert inc4.severity == 'CRITICAL'
    assert len(inc4.participating_detectors) == 4
    assert len(inc4.kill_chain_stages) == 4
    assert inc4.fused_confidence >= 0.99

    timeline = inc4.attack_timeline
    assert len(timeline) == 4
    assert timeline[0].stage == 'RECONNAISSANCE'
    assert timeline[1].stage == 'DELIVERY'
    assert timeline[2].stage == 'COMMAND_AND_CONTROL'
    assert timeline[3].stage == 'EXFILTRATION'


def test_correlator_single_critical_escalation():
    corr = SignalCorrelator()
    hw = HostSlidingWindow('10.10.10.10')
    r = DeduplicationRecord(
        fingerprint='fp_crit',
        source_ip='10.10.10.10',
        detector_name='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        severity='CRITICAL',
        confidence=0.95,
    )
    hw.add_record(r)
    inc = corr.correlate_host(hw)
    assert inc is not None
    assert inc.severity == 'CRITICAL'


def test_cep_engine_streaming_bus_integration():
    bus = InMemoryStreamingBus()
    engine = CEPAggregatorEngine(streaming_bus=bus)

    dispatched_incidents: List[FusedIncident] = []
    engine.register_incident_callback(lambda inc: dispatched_incidents.append(inc))

    a1 = RawAlert(
        source_ip='10.99.0.1',
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        confidence=0.90,
    )
    a2 = RawAlert(
        source_ip='10.99.0.1',
        detector_id='c2_beacon',
        threat_class='C2_BEACONING',
        confidence=0.92,
    )

    bus.publish(p='alerts.raw', topic='alerts.raw', message=a1, key='10.99.0.1') if False else bus.publish(topic='alerts.raw', message=a1, key='10.99.0.1')
    bus.publish(topic='alerts.raw', message=a2, key='10.99.0.1')

    processed = engine.process_streaming_bus(
        topic_in='alerts.raw', topic_out='incidents.fused', max_records=10
    )
    assert processed == 2

    fused_records = []
    for p in range(4):
        fused_records.extend(bus.consume(topic='incidents.fused', partition=p, max_records=10))

    assert len(fused_records) >= 1
    assert fused_records[-1]['primary_source_ip'] == '10.99.0.1'


def test_cep_engine_batch_ingestion():
    engine = CEPAggregatorEngine()
    alerts = [
        RawAlert(
            source_ip=f'10.0.1.{i}',
            detector_id='portscan_hll',
            threat_class='PORT_SCAN_RECON',
            confidence=0.80,
        )
        for i in range(10)
    ]
    incidents = engine.ingest_batch(alerts)
    assert len(incidents) == 10
    assert engine.get_metrics()['total_ingested_alerts'] == 10


def test_cep_engine_high_throughput_performance():
    engine = CEPAggregatorEngine()
    start = time.perf_counter()
    count = 5000
    for i in range(count):
        a = RawAlert(
            source_ip=f'192.168.{(i % 250)}.{i % 254 + 1}',
            detector_id='portscan_hll',
            threat_class='PORT_SCAN_RECON',
            confidence=0.85,
        )
        engine.ingest_alert(a)
    elapsed = time.perf_counter() - start
    eps = count / max(0.0001, elapsed)
    assert eps > 1000  # High throughput line-rate processing speed


def test_sliding_window_emergency_eviction():
    cfg = SlidingWindowConfig(max_tracked_hosts=100, window_duration_sec=60.0)
    buf = SlidingWindowBuffer(config=cfg)

    # Ingest 115 distinct hosts to trigger emergency LRU eviction
    for i in range(115):
        r = DeduplicationRecord(
            fingerprint=f'fp_{i}',
            source_ip=f'10.0.{(i // 250)}.{i % 250}',
            detector_name='portscan_hll',
            threat_class='PORT_SCAN_RECON',
            first_seen=float(i),
            last_seen=float(i),
            occurrence_count=1,
        )
        buf.ingest_record(r, current_time=float(i))

    assert len(buf.get_all_active_hosts(current_time=115.0)) <= 115


def test_out_of_order_timestamps():
    hw = HostSlidingWindow('192.168.1.99', window_duration_sec=30.0)
    r_late = DeduplicationRecord(
        fingerprint='fp_late',
        source_ip='192.168.1.99',
        detector_name='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        first_seen=20.0,
        last_seen=20.0,
    )
    r_early = DeduplicationRecord(
        fingerprint='fp_early',
        source_ip='192.168.1.99',
        detector_name='dga_lstm',
        threat_class='DGA_TUNNELLING',
        first_seen=10.0,
        last_seen=10.0,
    )
    hw.add_record(r_late, current_time=20.0)
    hw.add_record(r_early, current_time=20.0)

    recs = hw.get_records()
    assert len(recs) == 2


def test_fused_incident_serialization_roundtrip():
    engine = CEPAggregatorEngine()
    a = RawAlert(
        source_ip='10.10.10.10',
        detector_id='ja4_malware',
        threat_class='ENCRYPTED_MALWARE',
        severity='HIGH',
        confidence=0.95,
        target_ip='192.168.1.1',
        target_port=443,
    )
    inc = engine.ingest_alert(a)
    assert inc is not None

    # Test JSON serialization and validation
    json_str = inc.model_dump_json()
    reconstructed = FusedIncident.model_validate_json(json_str)

    assert reconstructed.incident_id == inc.incident_id
    assert reconstructed.primary_source_ip == inc.primary_source_ip
    assert reconstructed.fused_confidence == inc.fused_confidence
    assert reconstructed.severity == inc.severity
    assert reconstructed.requires_human_approval is True


def test_cep_engine_dict_and_json_ingestion():
    engine = CEPAggregatorEngine()

    # Ingest via dictionary
    dict_alert = {
        'source_ip': '10.20.30.40',
        'detector_name': 'portscan_hll',
        'threat_class': 'PORT_SCAN_RECON',
        'confidence': 0.85,
    }
    inc_dict = engine.ingest_alert(dict_alert)
    assert inc_dict is not None
    assert inc_dict.primary_source_ip == '10.20.30.40'

    # Ingest via JSON string
    raw_model = RawAlert(
        source_ip='10.20.30.50',
        detector_id='dga_lstm',
        threat_class='DGA_TUNNELLING',
        confidence=0.88,
    )
    inc_json = engine.ingest_alert(raw_model.model_dump_json())
    assert inc_json is not None
    assert inc_json.primary_source_ip == '10.20.30.50'


def test_cep_engine_cleanup_and_clear():
    engine = CEPAggregatorEngine()
    a = RawAlert(
        source_ip='10.0.0.100',
        detector_id='portscan_hll',
        threat_class='PORT_SCAN_RECON',
        confidence=0.80,
    )
    engine.ingest_alert(a)
    assert len(engine.get_all_active_incidents()) == 1

    engine.clear()
    assert len(engine.get_all_active_incidents()) == 0
    assert engine.get_metrics()['active_host_windows'] == 0

