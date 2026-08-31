from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union


from src.cep.burst_limiter import TokenBucketBurstLimiter
from src.cep.correlator import STAGE_SEQUENCE, SignalCorrelator
from src.cep.deduplicator import AlertDeduplicator
from src.cep.models import (
    AlertStormSummary,
    DeduplicationRecord,
    FusedIncident,
    RawAlert,
    SlidingWindowConfig,
    SubnetAggregation,
)
from src.cep.sliding_window import SlidingWindowBuffer
from src.ingestion.streaming_bus import StreamingBus

logger = logging.getLogger('cep.engine')


class CEPAggregatorEngine:
    """
    High-throughput Complex Event Processing (CEP) &thin; Incident Fusion Engine.
    Subscribes to 'alerts.raw', deduplicates, rate-limits floods, maintains
    sliding windows, fuses multi-detector kill-chain sequences, and publishes
    structured incidents to 'incidents.fused'.
    """

    def __init__(
        self,
        config: Optional[SlidingWindowConfig] = None,
        streaming_bus: Optional[StreamingBus] = None,
        incident_callbacks: Optional[List[Callable[[FusedIncident], None]]] = None,
    ):
        self.config: SlidingWindowConfig = config or SlidingWindowConfig()
        self.streaming_bus: Optional[StreamingBus] = streaming_bus
        self.incident_callbacks: List[Callable[[FusedIncident], None]] = incident_callbacks or []

        # Subsystems
        self.buffer: SlidingWindowBuffer = SlidingWindowBuffer(config=self.config)
        self.deduplicator: AlertDeduplicator = AlertDeduplicator(config=self.config)
        self.burst_limiter: TokenBucketBurstLimiter = TokenBucketBurstLimiter(config=self.config)
        self.correlator: SignalCorrelator = SignalCorrelator(config=self.config)

        # Active Incidents By Host IP
        self._active_incidents: Dict[str, FusedIncident] = {}
        self._host_total_alerts: Dict[str, int] = {}
        self._lock: threading.RLock = threading.RLock()

        # Operational Metrics
        self.total_ingested_alerts: int = 0
        self.total_deduplicated_alerts: int = 0
        self.total_rate_limited_alerts: int = 0
        self.total_incidents_fused: int = 0
        self.total_floods_collapsed: int = 0
        self._last_event_time: Optional[float] = None

        # Worker state
        self._running: bool = False
        self._worker_thread: Optional[threading.Thread] = None

    def register_incident_callback(
        self, callback: Callable[[FusedIncident], None]
    ) -> None:
        """Registers a downstream callback receiving FusedIncident events."""
        with self._lock:
            if callback not in self.incident_callbacks:
                self.incident_callbacks.append(callback)


    def ingest_alert(
        self,
        alert: Union[RawAlert, Dict[str, Any], str],
        current_time: Optional[float] = None,
    ) -> Optional[FusedIncident]:
        """
        Ingests, validates, rate-limits, deduplicates, and correlates a single alert.
        Returns the created or updated FusedIncident if formed, else None.
        """
        raw: RawAlert = self._normalize_alert(alert)
        now = current_time if current_time is not None else raw.timestamp

        with self._lock:
            self._last_event_time = now
            self.total_ingested_alerts += 1
            self._host_total_alerts[raw.source_ip] = self._host_total_alerts.get(raw.source_ip, 0) + 1
            total_for_host = self._host_total_alerts[raw.source_ip]

            # 1. Rate Limiting & Burst Flood Collapse
            allowed, storm_summary = self.burst_limiter.allow_alert(raw, current_time=now)
            if storm_summary:
                self.total_floods_collapsed += 1

            if not allowed:
                self.total_rate_limited_alerts += 1
                stage = self.correlator.classify_stage(raw.detector_name, raw.threat_class).value
                inc = self._active_incidents.get(raw.source_ip)
                if inc is not None:
                    inc.raw_alert_count = total_for_host
                    inc.total_raw_alerts_collapsed = total_for_host
                    inc.updated_at = now
                    if raw.threat_class and raw.threat_class not in inc.threat_classes:
                        inc.threat_classes.append(raw.threat_class)
                    if raw.detector_name and raw.detector_name not in inc.participating_detectors:
                        inc.participating_detectors.append(raw.detector_name)
                    if stage not in inc.kill_chain_stages:
                        inc.kill_chain_stages.append(stage)
                        stage_order = {s.value: i for i, s in enumerate(STAGE_SEQUENCE)}
                        inc.kill_chain_stages.sort(key=lambda s: stage_order.get(s, 99))
                    if len(inc.kill_chain_stages) >= 2 or len(inc.participating_detectors) >= 2:
                        inc.threat_class = 'APT_MULTI_STAGE_ATTACK'
                        inc.attack_stage = inc.kill_chain_stages[-1]
                        inc.severity = 'CRITICAL' if (len(inc.kill_chain_stages) >= 4 or len(inc.participating_detectors) >= 3) else 'HIGH'
                    if raw.target_ip and raw.target_ip not in inc.target_ips and len(inc.target_ips) < 50:
                        inc.target_ips.append(raw.target_ip)
                    if raw.target_port is not None and raw.target_port not in inc.target_ports and len(inc.target_ports) < 50:
                        inc.target_ports.append(raw.target_port)
                    if raw.alert_id and raw.alert_id not in inc.raw_alert_ids and len(inc.raw_alert_ids) < 200:
                        inc.raw_alert_ids.append(raw.alert_id)
                    if len(inc.alerts) < 10:
                        inc.alerts.append(raw)
                else:
                    inc = FusedIncident(
                        primary_source_ip=raw.source_ip,
                        source_subnet='',
                        target_ips=[raw.target_ip] if raw.target_ip else [],
                        target_ports=[raw.target_port] if raw.target_port is not None else [],
                        participating_detectors=[raw.detector_name],
                        threat_classes=[raw.threat_class],
                        threat_class=raw.threat_class,
                        raw_alert_count=total_for_host,
                        total_raw_alerts_collapsed=total_for_host,
                        fused_confidence=raw.confidence,
                        overall_confidence=raw.confidence,
                        severity=(raw.severity or 'MEDIUM').upper(),
                        attack_stage=stage,
                        kill_chain_stages=[stage],
                        alerts=[raw],
                        raw_alert_ids=[raw.alert_id] if raw.alert_id else [],
                        created_at=now,
                        updated_at=now,
                    )
                    self._active_incidents[raw.source_ip] = inc
                return inc

            # 2. Alert Deduplication
            is_dup, dedup_rec = self.deduplicator.deduplicate(raw, current_time=now)
            if is_dup:
                self.total_deduplicated_alerts += 1

            # 3. Sliding Window Buffer Ingestion
            host_win, subnet_win = self.buffer.ingest_record(dedup_rec, current_time=now)

            # 4. Signal Correlation & Incident Fusion
            fused_incident = self.correlator.correlate_host(
                host_window=host_win,
                subnet_window=subnet_win,
                current_time=now,
            )

            if fused_incident is not None:
                # Track previous incident id to preserve identifier stability and merge historical rate-limited threats
                existing = self._active_incidents.get(raw.source_ip)
                if existing is not None:
                    fused_incident.incident_id = existing.incident_id
                    fused_incident.created_at = existing.created_at
                    for tc in existing.threat_classes:
                        if tc not in fused_incident.threat_classes:
                            fused_incident.threat_classes.append(tc)
                    for det in existing.participating_detectors:
                        if det not in fused_incident.participating_detectors:
                            fused_incident.participating_detectors.append(det)
                    for stg in existing.kill_chain_stages:
                        if stg not in fused_incident.kill_chain_stages:
                            fused_incident.kill_chain_stages.append(stg)

                if storm_summary is not None:
                    for tc in storm_summary.threat_classes:
                        if tc not in fused_incident.threat_classes:
                            fused_incident.threat_classes.append(tc)

                stage_order = {s.value: i for i, s in enumerate(STAGE_SEQUENCE)}
                fused_incident.kill_chain_stages.sort(key=lambda s: stage_order.get(s, 99))
                if len(fused_incident.kill_chain_stages) >= 2 or len(fused_incident.participating_detectors) >= 2:
                    fused_incident.threat_class = 'APT_MULTI_STAGE_ATTACK'
                    fused_incident.attack_stage = fused_incident.kill_chain_stages[-1]
                    if len(fused_incident.kill_chain_stages) >= 4 or len(fused_incident.participating_detectors) >= 3:
                        fused_incident.severity = 'CRITICAL'
                    elif fused_incident.severity in ('LOW', 'MEDIUM'):
                        fused_incident.severity = 'HIGH'

                fused_incident.updated_at = now
                fused_incident.raw_alert_count = total_for_host
                fused_incident.total_raw_alerts_collapsed = total_for_host

                if len(fused_incident.alerts) > 10:
                    fused_incident.alerts = fused_incident.alerts[:10]
                if len(fused_incident.raw_alert_ids) > 200:
                    fused_incident.raw_alert_ids = fused_incident.raw_alert_ids[:200]

                self._active_incidents[raw.source_ip] = fused_incident
                self.total_incidents_fused += 1

                # Publish to streaming bus topic 'incidents.fused'
                if self.streaming_bus is not None:
                    self.streaming_bus.publish(
                        topic='incidents.fused',
                        message=fused_incident,
                        key=fused_incident.primary_source_ip,
                    )

                # Dispatch to registered callbacks
                for cb in self.incident_callbacks:
                    try:
                        cb(fused_incident)
                    except Exception as e:
                        logger.warning(f'Error in incident callback: {e}')

                return fused_incident

            return None


    def ingest_batch(
        self,
        alerts: List[Union[RawAlert, Dict[str, Any], str]],
        current_time: Optional[float] = None,
    ) -> List[FusedIncident]:
        """Batch ingestion returning all generated or updated fused incidents."""
        incidents: Dict[str, FusedIncident] = {}
        for a in alerts:
            inc = self.ingest_alert(a, current_time=current_time)
            if inc is not None:
                incidents[inc.primary_source_ip] = inc
        return list(incidents.values())

    def process_streaming_bus(
        self,
        topic_in: str = 'alerts.raw',
        topic_out: str = 'incidents.fused',
        max_records: int = 1000,
        timeout: float = 0.0,
    ) -> int:
        """
        Consumes pending raw alerts from the streaming bus across all partitions.
        Returns count of alerts processed.
        """
        if self.streaming_bus is None:
            return 0

        processed_count = 0
        for p in range(4):  # 4-partition deterministic routing
            records = self.streaming_bus.consume(
                topic=topic_in, partition=p, max_records=max_records, timeout=timeout
            )
            for rec in records:
                self.ingest_alert(rec)
                processed_count += 1

        return processed_count


    def periodic_cleanup(self, current_time: Optional[float] = None) -> int:
        """Prunes expired buffers and deduplication records."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            self.deduplicator.prune_expired(now, max_age_sec=self.config.window_duration_sec)
            self.burst_limiter.prune_inactive(now, ttl_sec=self.config.host_inactivity_ttl_sec)
            pruned = self.buffer.periodic_cleanup(now)

            # Prune inactive incidents
            expired_inc_srcs = [
                src
                for src, inc in self._active_incidents.items()
                if (now - inc.updated_at) >= self.config.host_inactivity_ttl_sec
            ]
            for src in expired_inc_srcs:
                del self._active_incidents[src]

            return pruned


    def _normalize_alert(self, alert: Union[RawAlert, Dict[str, Any], str]) -> RawAlert:
        """Normalizes input formats to a RawAlert Pydantic model."""
        if isinstance(alert, RawAlert):
            return alert
        if isinstance(alert, dict):
            return RawAlert(**alert)
        if isinstance(alert, str):
            return RawAlert.model_validate_json(alert)
        raise ValueError(f'Unsupported alert payload type: {type(alert)}')


    def get_incident_for_host(self, source_ip: str) -> Optional[FusedIncident]:
        """Returns the active fused incident for a given host IP."""
        with self._lock:
            return self._active_incidents.get(source_ip)


    def get_all_active_incidents(self) -> List[FusedIncident]:
        """Returns all active fused incidents."""
        with self._lock:
            return list(self._active_incidents.values())


    def get_metrics(self) -> Dict[str, Any]:
        """Returns CEP engine operational metrics."""
        with self._lock:
            return {
                'total_ingested_alerts': self.total_ingested_alerts,
                'total_deduplicated_alerts': self.total_deduplicated_alerts,
                'total_rate_limited_alerts': self.total_rate_limited_alerts,
                'total_incidents_fused': self.total_incidents_fused,
                'total_floods_collapsed': self.total_floods_collapsed,
                'active_host_windows': len(self.buffer.get_all_active_hosts(current_time=self._last_event_time)),
                'active_fused_incidents': len(self._active_incidents),
                'active_storms': len(self.burst_limiter.get_active_storms()),
            }

    def clear(self) -> None:
        """Resets all engine state."""
        with self._lock:
            self.buffer.clear()
            self.deduplicator.clear()
            self.burst_limiter.clear()
            self._active_incidents.clear()
            self._host_total_alerts.clear()


# Alias for compatibility
CEPAggregator = CEPAggregatorEngine
