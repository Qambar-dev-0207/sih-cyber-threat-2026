from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from src.cep.models import DeduplicationRecord, RawAlert, SlidingWindowConfig

logger = logging.getLogger('cep.deduplicator')

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

SEVERITY_RANKS: Dict[str, int] = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}


def generate_flow_fingerprint(
    source_ip: str,
    detector_name: str,
    threat_class: str,
    target_ip: Optional[str] = None,
    target_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> str:
    """
    Generates a deterministic 32-character hex flow signature fingerprint.
    Uses Murmur3 128-bit hash if available, falling back to SHA256.
    """
    src = str(source_ip).strip()
    dst = str(target_ip).strip() if target_ip else 'ANY'
    dport = str(target_port) if target_port is not None else '0'
    proto = str(protocol).strip().upper() if protocol else 'ANY'
    threat = str(threat_class).strip().upper()
    detector = str(detector_name).strip().lower()

    raw_signature = f'{src}:{dst}:{dport}:{proto}:{threat}:{detector}'

    if HAS_MMH3:
        hash_128 = mmh3.hash128(raw_signature.encode('utf-8')) & ((1 << 128) - 1)
        return format(hash_128, '032x')
    else:
        return hashlib.sha256(raw_signature.encode('utf-8')).hexdigest()[:32]


class AlertDeduplicator:
    """
    High-throughput, thread-safe alert deduplication engine.
    Coalesces alerts matching the same flow signature within configurable bucket (default 5s).
    """

    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        self.config: SlidingWindowConfig = config or SlidingWindowConfig()
        self._records: Dict[str, DeduplicationRecord] = {}
        self._lock: threading.RLock = threading.RLock()
        self.total_deduplicated_count: int = 0
        self.total_unique_records_created: int = 0

    def deduplicate(
        self, alert: RawAlert, current_time: Optional[float] = None
    ) -> Tuple[bool, DeduplicationRecord]:
        """
        Ingests a RawAlert and checks for coalescing with an active DeduplicationRecord.
        """
        now = current_time if current_time is not None else alert.timestamp
        fp = generate_flow_fingerprint(
            source_ip=alert.source_ip,
            detector_name=alert.detector_name,
            threat_class=alert.threat_class,
            target_ip=alert.target_ip,
            target_port=alert.target_port,
            protocol=alert.protocol,
        )

        with self._lock:
            existing = self._records.get(fp)
            if existing is not None and 0.0 <= (now - existing.last_seen) <= self.config.dedup_coalesce_sec:
                existing.occurrence_count += 1
                existing.last_seen = max(existing.last_seen, now)
                existing.confidence = max(existing.confidence, alert.confidence)

                alert_sev = (alert.severity or 'MEDIUM').upper()
                curr_sev = (existing.severity or 'MEDIUM').upper()
                if SEVERITY_RANKS.get(alert_sev, 2) > SEVERITY_RANKS.get(curr_sev, 2):
                    existing.severity = alert_sev

                if alert.flow_id and alert.flow_id not in existing.flow_ids:
                    if len(existing.flow_ids) < 50:
                        existing.flow_ids.append(alert.flow_id)

                if alert.alert_id and alert.alert_id not in existing.alert_ids:
                    if len(existing.alert_ids) < 200:
                        existing.alert_ids.append(alert.alert_id)

                if alert.mitre_technique and alert.mitre_technique not in existing.mitre_techniques:
                    existing.mitre_techniques.append(alert.mitre_technique)

                if alert.evidence:
                    self._merge_evidence(existing.evidence, alert.evidence)

                if len(existing.sample_alerts) < 5:
                    existing.sample_alerts.append(alert)

                self.total_deduplicated_count += 1
                return True, existing

            else:
                new_record = DeduplicationRecord(
                    fingerprint=fp,
                    source_ip=alert.source_ip,
                    detector_name=alert.detector_name,
                    threat_class=alert.threat_class,
                    severity=(alert.severity or 'MEDIUM').upper(),
                    confidence=alert.confidence,
                    target_ip=alert.target_ip,
                    target_port=alert.target_port,
                    protocol=alert.protocol,
                    first_seen=now,
                    last_seen=now,
                    occurrence_count=1,
                    flow_ids=[alert.flow_id] if alert.flow_id else [],
                    alert_ids=[alert.alert_id] if alert.alert_id else [],
                    mitre_techniques=[alert.mitre_technique] if alert.mitre_technique else [],
                    evidence=dict(alert.evidence) if alert.evidence else {},
                    sample_alerts=[alert],
                )
                self._records[fp] = new_record
                self.total_unique_records_created += 1
                return False, new_record

    def _merge_evidence(self, target_ev: Dict[str, Any], new_ev: Dict[str, Any]) -> None:
        for k, v in new_ev.items():
            if isinstance(v, (int, float)):
                if k.endswith(('_count', '_bytes', '_pkts', '_total', '_sum')):
                    target_ev[k] = target_ev.get(k, 0) + v
                elif k.endswith(('_rate', '_pps', '_score', '_ratio', '_prob', '_entropy', '_x_score')):
                    target_ev[k] = max(target_ev.get(k, 0.0), float(v))
                else:
                    target_ev[k] = v
            elif isinstance(v, list):
                if k not in target_ev or not isinstance(target_ev[k], list):
                    target_ev[k] = list(v[:20])
                else:
                    for item in v:
                        if item not in target_ev[k] and len(target_ev[k]) < 50:
                            target_ev[k].append(item)
            elif isinstance(v, (str, bool)):
                target_ev[k] = v

    def prune_expired(
        self, current_time: Optional[float] = None, max_age_sec: float = 60.0
    ) -> int:
        now = current_time if current_time is not None else time.time()
        cutoff = now - max_age_sec
        with self._lock:
            expired_fps = [fp for fp, rec in self._records.items() if rec.last_seen < cutoff]
            for fp in expired_fps:
                del self._records[fp]
            return len(expired_fps)


    def get_record(self, fingerprint: str) -> Optional[DeduplicationRecord]:
        with self._lock:
            return self._records.get(fingerprint)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
