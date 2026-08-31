from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.cep.models import AlertStormSummary, RawAlert, SlidingWindowConfig

logger = logging.getLogger('cep.burst_limiter')


class TokenBucket:
    """
    Token Bucket instance for a given host or flow.
    Tracks token availability and active storm metrics under flood conditions.
    """

    def __init__(
        self,
        capacity: float = 10.0,
        refill_rate: float = 5.0,
        current_time: Optional[float] = None,
    ):
        self.capacity: float = float(capacity)
        self.refill_rate: float = float(refill_rate)
        now = current_time if current_time is not None else time.time()
        self.tokens: float = self.capacity
        self.last_refill: float = now
        self.last_activity: float = now

        # Storm / Flood Tracking
        self.in_storm: bool = False
        self.storm_start_time: float = now
        self.storm_alert_count: int = 0
        self.storm_threat_classes: Set[str] = set()
        self.storm_sample_alert_ids: List[str] = []
        self.storm_sample_alerts: List[RawAlert] = []

    def refill(self, current_time: float) -> None:
        """Refills tokens proportional to elapsed time."""
        elapsed = max(0.0, current_time - self.last_refill)
        self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
        self.last_refill = current_time
        self.last_activity = current_time

    def consume(self, current_time: float) -> bool:
        """
        Attempts to consume 1.0 token after refilling.
        Returns True if token was available and consumed, False otherwise.
        """
        self.refill(current_time)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class TokenBucketBurstLimiter:
    """
    Token-bucket rate limiter that collapses 1,000+ raw alerts per second
    into bounded incident payloads without memory exhaustion or dropping unique threats.
    """

    def __init__(self, config: Optional[SlidingWindowConfig] = None):
        self.config: SlidingWindowConfig = config or SlidingWindowConfig()
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock: threading.RLock = threading.RLock()
        self.total_alerts_limited: int = 0
        self.total_storms_collapsed: int = 0

    def allow_alert(
        self,
        alert: RawAlert,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, Optional[AlertStormSummary]]:
        """
        Evaluates whether an alert is allowed through or rate-limited.

        Returns:
            (allowed, storm_summary_or_none)
            - allowed = True: alert passes rate limiter (and if a previous storm just ended,
              its summary is returned).
            - allowed = False: alert is rate-limited and collapsed into storm buffer.
        """
        now = current_time if current_time is not None else alert.timestamp
        src = alert.source_ip

        with self._lock:
            bucket = self._buckets.get(src)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=self.config.rate_limit_capacity,
                    refill_rate=self.config.rate_limit_refill_rate,
                    current_time=now,
                )
                self._buckets[src] = bucket

            if bucket.consume(now):
                # Alert is allowed!
                if bucket.in_storm:
                    # Storm has concluded! Generate summary
                    summary = self._build_storm_summary(src, bucket, now)
                    bucket.in_storm = False
                    bucket.storm_alert_count = 0
                    bucket.storm_threat_classes.clear()
                    bucket.storm_sample_alert_ids.clear()
                    bucket.storm_sample_alerts.clear()
                    self.total_storms_collapsed += 1
                    return True, summary
                return True, None

            else:
                # Rate limited! Collapse into storm
                self.total_alerts_limited += 1
                if not bucket.in_storm:
                    bucket.in_storm = True
                    bucket.storm_start_time = now
                    bucket.storm_alert_count = 1
                    bucket.storm_threat_classes = {alert.threat_class}
                    bucket.storm_sample_alert_ids = [alert.alert_id] if alert.alert_id else []
                    bucket.storm_sample_alerts = [alert]
                else:
                    bucket.storm_alert_count += 1
                    bucket.storm_threat_classes.add(alert.threat_class)
                    if alert.alert_id and len(bucket.storm_sample_alert_ids) < 20:
                        bucket.storm_sample_alert_ids.append(alert.alert_id)
                    if len(bucket.storm_sample_alerts) < 5:
                        bucket.storm_sample_alerts.append(alert)

                return False, None

    def force_flush_storm(
        self, source_ip: str, current_time: Optional[float] = None
    ) -> Optional[AlertStormSummary]:
        """Forcibly flushes and concludes an active storm for a host."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            bucket = self._buckets.get(source_ip)
            if bucket is not None and bucket.in_storm:
                summary = self._build_storm_summary(source_ip, bucket, now)
                bucket.in_storm = False
                bucket.storm_alert_count = 0
                bucket.storm_threat_classes.clear()
                bucket.storm_sample_alert_ids.clear()
                bucket.storm_sample_alerts.clear()
                self.total_storms_collapsed += 1
                return summary
            return None

    def _build_storm_summary(
        self, source_ip: str, bucket: TokenBucket, current_time: float
    ) -> AlertStormSummary:
        duration = max(0.1, current_time - bucket.storm_start_time)
        peak_pps = bucket.storm_alert_count / duration
        threat_list = sorted(list(bucket.storm_threat_classes))
        primary_threat = threat_list[0] if threat_list else 'VOLUMETRIC_FLOOD'

        return AlertStormSummary(
            source_ip=source_ip,
            alert_count=bucket.storm_alert_count,
            duration_sec=duration,
            peak_pps=peak_pps,
            primary_threat=primary_threat,
            dropped_duplicates=max(0, bucket.storm_alert_count - 10),
            threat_classes=threat_list,
            sample_alert_ids=list(bucket.storm_sample_alert_ids),
        )

    def is_rate_limited(self, source_ip: str, current_time: Optional[float] = None) -> bool:
        """Returns True if a host is currently in an active storm."""
        with self._lock:
            bucket = self._buckets.get(source_ip)
            if bucket is not None:
                return bucket.in_storm
            return False

    def get_active_storms(self, current_time: Optional[float] = None) -> List[AlertStormSummary]:
        """Returns all hosts currently experiencing alert storms."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            storms: List[AlertStormSummary] = []
            for ip, bucket in self._buckets.items():
                if bucket.in_storm:
                    storms.append(self._build_storm_summary(ip, bucket, now))
            return storms

    def prune_inactive(
        self, current_time: Optional[float] = None, ttl_sec: float = 300.0
    ) -> int:
        """Prunes inactive token buckets to prevent memory leaks."""
        now = current_time if current_time is not None else time.time()
        with self._lock:
            expired_ips = [
                ip for ip, bucket in self._buckets.items()
                if not bucket.in_storm and (now - bucket.last_activity) >= ttl_sec
            ]
            for ip in expired_ips:
                del self._buckets[ip]
            return len(expired_ips)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()
