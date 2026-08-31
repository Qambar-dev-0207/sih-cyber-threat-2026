"""
SIH26145 - Detector 3: Data Exfiltration Threat Detector
Streaming threat detector evaluating directional asymmetric byte ratios (R_out/in)
against dynamic per-host P² quantile baselines (P95, P99) and external egress thresholds.
"""

from __future__ import annotations

import collections
import ipaddress
import logging
import math
import time
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from ..ingestion.models import ConnTelemetryEvent, RawAlert
from ..utils.p2_quantile import P2QuantileEstimator
from .base import BaseDetector

logger = logging.getLogger("detectors.exfil_ratio")

# Fast cache for private IP lookups to avoid repetitive IP parsing
_IP_PRIVACY_CACHE: Dict[str, bool] = {}

_INTERNAL_V4_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("0.0.0.0/8"),
)


def is_external_ip(ip_str: str) -> bool:
    """
    Returns True if the destination IP is external (public Internet),
    and False if it is RFC-1918 private, loopback, multicast, link-local, or unspecified.
    Specifically ensures RFC 5737 test/benchmark subnets (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) return True.
    """
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255"):
        return False
    cached = _IP_PRIVACY_CACHE.get(ip_str)
    if cached is not None:
        return cached

    if "." in ip_str:
        if ip_str.startswith(("10.", "127.", "0.", "169.254.", "192.168.")):
            is_ext = False
        elif ip_str.startswith("172."):
            parts = ip_str.split(".")
            try:
                second = int(parts[1])
                is_ext = not (16 <= second <= 31)
            except (IndexError, ValueError):
                is_ext = False
        else:
            try:
                first = int(ip_str.split(".")[0])
                if 224 <= first <= 255:
                    is_ext = False
                else:
                    is_ext = True
            except (IndexError, ValueError):
                is_ext = False
    else:
        try:
            ip = ipaddress.ip_address(ip_str)
            is_ext = not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_private)
        except ValueError:
            is_ext = False

    if len(_IP_PRIVACY_CACHE) < 50000:
        _IP_PRIVACY_CACHE[ip_str] = is_ext
    return is_ext


class HostExfiltrationState:
    """
    Stateful tracker for a monitored source host, maintaining rolling 60s windows,
    streaming P² quantile estimators for baseline ratio distribution, and historical egress velocity.
    """

    def __init__(
        self,
        source_ip: str,
        window_sec: float = 60.0,
        epsilon_bytes: int = 1024,
    ):
        self.source_ip = source_ip
        self.window_sec = window_sec
        self.epsilon_bytes = epsilon_bytes

        # P² Quantile Estimators for learning the host's normal flow ratio baseline
        self.p95_estimator = P2QuantileEstimator(p=0.95)
        self.p99_estimator = P2QuantileEstimator(p=0.99)
        self.total_flows_seen: int = 0

        # Rolling window deque storing (ts, orig_bytes, resp_bytes, dst_ip, dst_port, service, uid)
        self.recent_flows: Deque[Tuple[float, int, int, str, int, Optional[str], str]] = collections.deque(maxlen=10000)
        self.window_orig: int = 0
        self.window_resp: int = 0

        # Low-and-slow tracking across long windows (300s)
        self.long_window_flows: Deque[Tuple[float, int, int]] = collections.deque(maxlen=10000)
        self.long_orig: int = 0
        self.long_resp: int = 0

        self.last_alert_ts: float = 0.0
        self.last_seen_ts: float = 0.0

    def record_flow(
        self,
        orig_bytes: int,
        resp_bytes: int,
        dst_ip: str,
        dst_port: int,
        service: Optional[str],
        uid: str,
        ts: float,
    ) -> Tuple[float, float, float, int, int, float]:
        """
        Record flow and return:
        (flow_ratio, rolling_ratio, egress_mbps, window_orig_bytes, window_resp_bytes, p95_baseline)
        """
        self.last_seen_ts = ts
        self.total_flows_seen += 1

        # Calculate flow-level ratio with Laplace smoothing
        flow_ratio = float(orig_bytes) / float(resp_bytes + self.epsilon_bytes)

        # Update P² baseline estimators with flow ratio
        self.p95_estimator.add(flow_ratio)
        self.p99_estimator.add(flow_ratio)

        # Add to 60s rolling window
        self.recent_flows.append((ts, orig_bytes, resp_bytes, dst_ip, dst_port, service, uid))
        self.window_orig += orig_bytes
        self.window_resp += resp_bytes

        cutoff_60s = ts - self.window_sec
        while self.recent_flows and self.recent_flows[0][0] < cutoff_60s:
            popped = self.recent_flows.popleft()
            self.window_orig -= popped[1]
            self.window_resp -= popped[2]

        # Add to 300s long-and-slow window
        self.long_window_flows.append((ts, orig_bytes, resp_bytes))
        self.long_orig += orig_bytes
        self.long_resp += resp_bytes

        cutoff_300s = ts - 300.0
        while self.long_window_flows and self.long_window_flows[0][0] < cutoff_300s:
            popped_long = self.long_window_flows.popleft()
            self.long_orig -= popped_long[1]
            self.long_resp -= popped_long[2]

        # Aggregate 60s rolling stats (O(1))
        rolling_ratio = float(self.window_orig) / float(self.window_resp + self.epsilon_bytes)
        egress_mbps = (float(self.window_orig) * 8.0) / (self.window_sec * 1_000_000.0)

        p95_val = self.p95_estimator.get()
        return (
            round(flow_ratio, 4),
            round(rolling_ratio, 4),
            round(egress_mbps, 4),
            self.window_orig,
            self.window_resp,
            round(p95_val, 4),
        )

    def get_long_window_stats(self) -> Tuple[int, int, float]:
        """Compute cumulative orig_bytes, resp_bytes, and ratio over 300-second window."""
        long_ratio = float(self.long_orig) / float(self.long_resp + self.epsilon_bytes)
        return self.long_orig, self.long_resp, round(long_ratio, 4)


class ExfilRatioDetector(BaseDetector):
    """
    Detector 3: Data Exfiltration Threat Detector
    Detects anomalous outbound data transfers by baselining per-host asymmetric
    byte ratios (R_out/in) with streaming P² quantiles and monitoring velocity spikes.
    """

    def __init__(
        self,
        ratio_spike_threshold: float = 5.0,
        volume_threshold_bytes: int = 5 * 1024 * 1024,  # 5 MB in 60s
        single_flow_catastrophic_bytes: int = 10 * 1024 * 1024,  # 10 MB single flow
        single_flow_ratio_threshold: float = 10.0,
        sustained_low_slow_bytes: int = 10 * 1024 * 1024,  # 10 MB in 300s
        sustained_low_slow_ratio: float = 4.0,
        alert_cooldown_sec: float = 10.0,
        state_ttl_sec: float = 600.0,
        max_tracked_hosts: int = 100_000,
        bus: Optional[Any] = None,
        producer: Optional[Any] = None,
    ):
        super().__init__(
            detector_id="exfil_ratio",
            input_topic="telemetry.conn",
            output_topic="alerts.raw",
            bus=bus,
            producer=producer,
            state_ttl_sec=state_ttl_sec,
            max_tracked_hosts=max_tracked_hosts,
        )
        self.ratio_spike_threshold = ratio_spike_threshold
        self.volume_threshold_bytes = volume_threshold_bytes
        self.single_flow_catastrophic_bytes = single_flow_catastrophic_bytes
        self.single_flow_ratio_threshold = single_flow_ratio_threshold
        self.sustained_low_slow_bytes = sustained_low_slow_bytes
        self.sustained_low_slow_ratio = sustained_low_slow_ratio
        self.alert_cooldown_sec = alert_cooldown_sec

        # Per-source host tracking cache: source_ip -> HostExfiltrationState
        self._host_states: Dict[str, HostExfiltrationState] = {}

    def reset_state(self) -> None:
        """Clear all host state tracking."""
        self._host_states.clear()
        self._host_last_seen.clear()

    def _on_host_evicted(self, host: str) -> None:
        """Prune host state on TTL expiry."""
        self._host_states.pop(host, None)

    def _get_or_create_state(self, source_ip: str) -> HostExfiltrationState:
        """Retrieve or create state for source IP."""
        if source_ip not in self._host_states:
            self._host_states[source_ip] = HostExfiltrationState(source_ip=source_ip)
        return self._host_states[source_ip]

    def process_event(
        self,
        event: Union[ConnTelemetryEvent, Dict[str, Any], str],
    ) -> Optional[RawAlert]:
        """
        Evaluate a single connection flow event for data exfiltration indicators.
        """
        if isinstance(event, ConnTelemetryEvent):
            conn = event
        elif isinstance(event, dict):
            conn = ConnTelemetryEvent.from_zeek_dict(event)
        elif isinstance(event, str):
            import json
            conn = ConnTelemetryEvent.from_zeek_dict(json.loads(event))
        else:
            return None

        source_ip = conn.src_ip
        target_ip = conn.dst_ip
        target_port = conn.dst_port
        orig_bytes = max(0, conn.orig_bytes)
        resp_bytes = max(0, conn.resp_bytes)
        service = conn.service
        uid = conn.uid
        ts = conn.ts or time.time()

        # Update liveness in BaseDetector
        self.update_host_liveness(source_ip, ts)

        state = self._get_or_create_state(source_ip)
        (
            flow_ratio,
            rolling_ratio,
            egress_mbps,
            window_orig_bytes,
            window_resp_bytes,
            p95_baseline,
        ) = state.record_flow(
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            dst_ip=target_ip,
            dst_port=target_port,
            service=service,
            uid=uid,
            ts=ts,
        )

        is_ext = is_external_ip(target_ip)

        # -------------------------------------------------------------
        # Decision Rules Evaluation
        # -------------------------------------------------------------
        threat_class: Optional[str] = None
        severity = "HIGH"
        confidence = 0.85
        mitigation = "isolate_host"

        # Condition 1: Massive Single-Flow Egress to external IP
        if (orig_bytes >= self.single_flow_catastrophic_bytes) and (flow_ratio >= self.single_flow_ratio_threshold) and is_ext:
            threat_class = "data_exfiltration"
            severity = "CRITICAL"
            confidence = min(0.99, 0.90 + (0.08 if orig_bytes > 50 * 1024 * 1024 else 0.04))
            mitigation = "isolate_host"

        # Condition 2: Anomalous 60s Rolling Ratio Spike + Significant Volume Out
        elif (rolling_ratio >= self.ratio_spike_threshold) and (window_orig_bytes >= self.volume_threshold_bytes):
            # Check if rolling ratio significantly exceeds the learned host baseline (or baseline is low/uninitialized)
            if (p95_baseline <= 0.0) or (rolling_ratio >= (3.0 * p95_baseline)) or (state.total_flows_seen < 10):
                threat_class = "data_exfiltration"
                severity = "HIGH"
                confidence = min(0.95, 0.82 + (0.10 if rolling_ratio > 20.0 else 0.05))
                mitigation = "isolate_host"

        # Condition 3: Sustained Low-and-Slow Egress across 300s window
        else:
            long_orig, long_resp, long_ratio = state.get_long_window_stats()
            if (long_orig >= self.sustained_low_slow_bytes) and (long_ratio >= self.sustained_low_slow_ratio) and is_ext:
                threat_class = "data_exfiltration"
                severity = "HIGH"
                confidence = 0.88
                mitigation = "isolate_host"

        if threat_class is None:
            return None

        # Cooldown check per source host
        if (ts - state.last_alert_ts) < self.alert_cooldown_sec:
            return None

        state.last_alert_ts = ts

        # Build standardized evidence payload
        evidence = {
            "orig_bytes": orig_bytes if threat_class == "data_exfiltration" and orig_bytes >= self.single_flow_catastrophic_bytes else window_orig_bytes,
            "resp_bytes": resp_bytes if threat_class == "data_exfiltration" and orig_bytes >= self.single_flow_catastrophic_bytes else window_resp_bytes,
            "ratio_out_in": round(flow_ratio if orig_bytes >= self.single_flow_catastrophic_bytes else rolling_ratio, 4),
            "host_baseline_p95_ratio": round(state.p95_estimator.get(), 4),
            "host_baseline_p99_ratio": round(state.p99_estimator.get(), 4),
            "egress_velocity_mbps": round(egress_mbps, 4),
            "is_external_destination": is_ext,
            "service": service or "unknown",
        }

        alert = RawAlert(
            detector_name=self.detector_id,
            threat_class=threat_class,
            severity=severity,
            confidence=round(confidence, 2),
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            protocol=conn.proto or "tcp",
            flow_id=conn.uid,
            window_duration_sec=60.0,
            evidence=evidence,
            recommended_mitigation=mitigation,
        )
        return alert
