from __future__ import annotations

import collections
import ipaddress
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.cep.models import (
    AggregationBuffer,
    DeduplicationRecord,
    RawAlert,
    SlidingWindowConfig,
    SubnetAggregation,
)

logger = logging.getLogger('cep.sliding_window')


def extract_subnet(ip_str: str, prefix_v4: int = 24, prefix_v6: int = 48) -> str:
    if not ip_str:
        return '0.0.0.0/24'
    ip_clean = str(ip_str).strip()
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f'{ip_clean}/{prefix_v4}', strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f'{ip_clean}/{prefix_v6}', strict=False)
            return str(net)
    except ValueError:
        return f'{ip_clean}/24'


class HostSlidingWindow:
    def __init__(self, source_ip: str, window_duration_sec: float = 60.0, created_at: Optional[float] = None):
        self.source_ip: str = source_ip
        self.window_duration_sec: float = float(window_duration_sec)
        self.records: collections.deque[DeduplicationRecord] = collections.deque()
        self._record_ids: Set[int] = set()
        self._lock: threading.RLock = threading.RLock()
        self.created_at: float = created_at if created_at is not None else 0.0
        self.last_activity: float = self.created_at
        self._initialized: bool = created_at is not None

    def add_record(
        self, record: DeduplicationRecord, current_time: Optional[float] = None
    ) -> None:
        with self._lock:
            now = current_time if current_time is not None else record.last_seen
            if not self._initialized:
                self.created_at = now
                self.last_activity = max(record.last_seen, now)
                self._initialized = True
            else:
                self.last_activity = max(self.last_activity, record.last_seen, now)

            rec_id = id(record)
            if rec_id not in self._record_ids:
                self._record_ids.add(rec_id)
                self.records.append(record)

            self.evict_expired(now)

    def evict_expired(self, current_time: float) -> int:
        with self._lock:
            cutoff = current_time - self.window_duration_sec
            evicted_count = 0
            while self.records and self.records[0].last_seen < cutoff:
                popped = self.records.popleft()
                self._record_ids.discard(id(popped))
                evicted_count += 1
            if any(r.last_seen < cutoff for r in self.records):
                surviving = collections.deque()
                for r in self.records:
                    if r.last_seen < cutoff:
                        self._record_ids.discard(id(r))
                        evicted_count += 1
                    else:
                        surviving.append(r)
                self.records = surviving
            return evicted_count

    def get_records(self) -> List[DeduplicationRecord]:
        with self._lock:
            return list(self.records)

    def is_empty(self) -> bool:
        with self._lock:
            return len(self.records) == 0

    @property
    def _fp_to_record(self) -> Dict[str, DeduplicationRecord]:
        with self._lock:
            return {r.fingerprint: r for r in self.records}

    def is_expired(self, current_time: float, ttl_sec: float = 300.0) -> bool:
        with self._lock:
            return len(self.records) == 0 and (current_time - self.last_activity) >= ttl_sec

    def get_participating_detectors(self) -> List[str]:
        with self._lock:
            detectors: Set[str] = set()
            for r in self.records:
                detectors.add(r.detector_name)
            return sorted(list(detectors))

    def get_threat_classes(self) -> List[str]:
        with self._lock:
            classes: Set[str] = set()
            for i in self.records:
                classes.add(i.threat_class)
            return sorted(list(classes))

    def get_target_ips(self) -> List[str]:
        with self._lock:
            targets: Set[str] = set()
            for r in self.records:
                if r.target_ip:
                    targets.add(r.target_ip)
            return sorted(list(targets))

    def get_target_ports(self) -> List[int]:
        with self._lock:
            ports: Set[int] = set()
            for r in self.records:
                if r.target_port is not None:
                    ports.add(r.target_port)
            return sorted(list(ports))


    def get_total_raw_alerts(self) -> int:
        with self._lock:
            return sum(r.occurrence_count for r in self.records)


    def get_max_severity(self) -> str:
        ranks = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        with self._lock:
            max_rank = 1
            max_sev = 'MEDIUM'
            for r in self.records:
                rank = ranks.get(r.severity.upper(), 2)
                if rank > max_rank:
                    max_rank = rank
                    max_sev = r.severity.upper()
            return max_sev

    def get_max_confidence(self) -> float:
        with self._lock:
            if not self.records:
                return 0.0
            return max(r.confidence for r in self.records)

    def get_all_alert_ids(self) -> List[str]:
        with self._lock:
            ids: List[str] = []
            for r in self.records:
                ids.extend(r.alert_ids)
            return ids[:200]

    def get_all_mitre_hints(self) -> List[str]:
        with self._lock:
            hints: Set[str] = set()
            for r in self.records:
                hints.update(r.mitre_techniques)
            return sorted(list(hints))

    def get_sample_alerts(self, max_samples: int = 10) -> List[RawAlert]:
        with self._lock:
            samples: List[RawAlert] = []
            for r in self.records:
                for a in r.sample_alerts:
                    if len(samples) < max_samples:
                        samples.append(a)
                    else:
                        break
                if len(samples) >= max_samples:
                    break
            return samples

    def get_summary(self, subnet_cidr: str = '') -> AggregationBuffer:
        with self._lock:
            first_seen = min((r.first_seen for r in self.records), default=self.created_at)
            last_seen = max((r.last_seen for r in self.records), default=self.last_activity)
            return AggregationBuffer(
                source_ip=self.source_ip,
                subnet_cidr=subnet_cidr,
                alert_count=self.get_total_raw_alerts(),
                deduplicated_record_count=len(self.records),
                unique_detectors=self.get_participating_detectors(),
                unique_threat_classes=self.get_threat_classes(),
                first_seen=first_seen,
                last_seen=last_seen,
            )


class SubnetSlidingWindow:
    def __init__(self, subnet_cidr: str, window_duration_sec: float = 60.0, created_at: Optional[float] = None):
        self.subnet_cidr: str = subnet_cidr
        self.window_duration_sec: float = float(window_duration_sec)
        self._host_last_seen: Dict[str, float] = {}
        self._host_records: Dict[str, Dict[int, DeduplicationRecord]] = {}
        self._host_threat_classes: Dict[str, Set[str]] = {}
        self._host_detectors: Dict[str, Set[str]] = {}
        self._lock: threading.RLock = threading.RLock()
        self.first_seen: float = created_at if created_at is not None else 0.0
        self.last_activity: float = self.first_seen
        self._initialized: bool = created_at is not None

    def update_host_activity(
        self,
        source_ip: str,
        record: DeduplicationRecord,
        current_time: Optional[float] = None,
    ) -> None:
        with self._lock:
            now = current_time if current_time is not None else record.last_seen
            if not self._initialized:
                self.first_seen = now
                self.last_activity = max(record.last_seen, now)
                self._initialized = True
            else:
                self.last_activity = max(self.last_activity, record.last_seen, now)
            self._host_last_seen[source_ip] = max(
                self._host_last_seen.get(source_ip, 0.0), record.last_seen, now
            )
            if source_ip not in self._host_records:
                self._host_records[source_ip] = {}
            self._host_records[source_ip][id(record)] = record

            if source_ip not in self._host_threat_classes:
                self._host_threat_classes[source_ip] = set()
            self._host_threat_classes[source_ip].add(record.threat_class)

            if source_ip not in self._host_detectors:
                self._host_detectors[source_ip] = set()
            self._host_detectors[source_ip].add(record.detector_name)

            self.evict_expired(now)

    def evict_expired(self, current_time: float) -> int:
        with self._lock:
            cutoff = current_time - self.window_duration_sec
            expired_hosts = [
                h for h, last_seen in self._host_last_seen.items() if last_seen < cutoff
            ]
            for h in expired_hosts:
                del self._host_last_seen[h]
                self._host_records.pop(h, None)
                self._host_threat_classes.pop(h, None)
                self._host_detectors.pop(h, None)
            for h, recs in list(self._host_records.items()):
                expired_ids = [rec_id for rec_id, rec in recs.items() if rec.last_seen < cutoff]
                for rec_id in expired_ids:
                    del recs[rec_id]
            return len(expired_hosts)

    def get_active_hosts(self) -> List[str]:
        with self._lock:
            return sorted(list(self._host_last_seen.keys()))

    def is_campaign(self, threshold: int = 3) -> bool:
        with self._lock:
            return len(self._host_last_seen) >= threshold

    def get_aggregation(self, campaign_threshold: int = 3) -> SubnetAggregation:
        with self._lock:
            all_threats: Set[str] = set()
            for threats in self._host_threat_classes.values():
                all_threats.update(threats)
            all_detectors: Set[str] = set()
            for dets in self._host_detectors.values():
                all_detectors.update(dets)

            active = sorted(list(self._host_last_seen.keys()))
            total_alerts = sum(
                sum(r.occurrence_count for r in recs.values())
                for recs in self._host_records.values()
            )

            return SubnetAggregation(
                subnet_cidr=self.subnet_cidr,
                active_hosts=active,
                total_alerts=total_alerts,
                threat_classes=sorted(list(all_threats)),
                participating_detectors=sorted(list(all_detectors)),
                first_seen=self.first_seen,
                last_seen=self.last_activity,
                is_campaign=len(active) >= campaign_threshold,
            )


class SlidingWindowBuffer:
    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        self.config: SlidingWindowConfig = config or SlidingWindowConfig()
        self._hosts: collections.OrderedDict[str, HostSlidingWindow] = collections.OrderedDict()
        self._subnets: Dict[str, SubnetSlidingWindow] = {}
        self._lock: threading.RLock = threading.RLock()
        self._last_cleanup: float = time.time()

    def ingest_record(
        self, record: DeduplicationRecord, current_time: Optional[float] = None
    ) -> Tuple[HostSlidingWindow, SubnetSlidingWindow]:
        now = current_time if current_time is not None else record.last_seen

        with self._lock:
            host_win = self._hosts.get(record.source_ip)
            if host_win is None:
                if len(self._hosts) >= self.config.max_tracked_hosts:
                    self._emergency_eviction(now)

                host_win = HostSlidingWindow(
                    source_ip=record.source_ip,
                    window_duration_sec=self.config.window_duration_sec,
                )
                self._hosts[record.source_ip] = host_win
            else:
                self._hosts.move_to_end(record.source_ip)

            host_win.add_record(record, current_time=now)

            subnet_cidr = extract_subnet(
                record.source_ip,
                prefix_v4=self.config.subnet_cidr_prefix_v4,
                prefix_v6=self.config.subnet_cidr_prefix_v6,
            )
            subnet_win = self._subnets.get(subnet_cidr)
            if subnet_win is None:
                subnet_win = SubnetSlidingWindow(
                    subnet_cidr=subnet_cidr,
                    window_duration_sec=self.config.window_duration_sec,
                )
                self._subnets[subnet_cidr] = subnet_win

            subnet_win.update_host_activity(record.source_ip, record, current_time=now)

            if now - self._last_cleanup > 30.0:
                self.periodic_cleanup(now)
                self._last_cleanup = now

            return host_win, subnet_win

    def get_host_window(self, source_ip: str) -> Optional[HostSlidingWindow]:
        with self._lock:
            return self._hosts.get(source_ip)

    def get_subnet_window(self, subnet_cidr: str) -> Optional[SubnetSlidingWindow]:
        with self._lock:
            return self._subnets.get(subnet_cidr)

    def get_all_active_hosts(self, current_time: Optional[float] = None) -> List[str]:
        now = current_time if current_time is not None else time.time()
        with self._lock:
            active: List[str] = []
            for ip, h in self._hosts.items():
                h.evict_expired(now)
                if not h.is_empty():
                    active.append(ip)
            return sorted(active)

    def get_campaign_subnets(
        self, current_time: Optional[float] = None
    ) -> List[SubnetAggregation]:
        now = current_time if current_time is not None else time.time()
        with self._lock:
            campaigns: List[SubnetAggregation] = []
            for cidr, s in self._subnets.items():
                s.evict_expired(now)
                if s.is_campaign(threshold=self.config.subnet_campaign_threshold):
                    campaigns.append(
                        s.get_aggregation(
                            campaign_threshold=self.config.subnet_campaign_threshold
                        )
                    )
            return campaigns

    def periodic_cleanup(self, current_time: Optional[float] = None) -> int:
        now = current_time if current_time is not None else time.time()
        pruned_hosts = 0

        with self._lock:
            expired_ips = []
            for ip, h in list(self._hosts.items()):
                h.evict_expired(now)
                if h.is_expired(now, ttl_sec=self.config.host_inactivity_ttl_sec):
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self._hosts[ip]
                pruned_hosts += 1

            expired_subnets = []
            for cidr, s in list(self._subnets.items()):
                s.evict_expired(now)
                if len(s.get_active_hosts()) == 0 and (now - s.last_activity) >= self.config.host_inactivity_ttl_sec:
                    expired_subnets.append(cidr)

            for cidr in expired_subnets:
                del self._subnets[cidr]

            return pruned_hosts

    def _emergency_eviction(self, current_time: float) -> None:
        with self._lock:
            evict_count = max(1, len(self._hosts) // 10)
            for _ in range(evict_count):
                if self._hosts:
                    self._hosts.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._hosts.clear()
            self._subnets.clear()
