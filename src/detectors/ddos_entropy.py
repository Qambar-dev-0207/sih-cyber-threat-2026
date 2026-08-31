"""
SIH26145 - Detector 1: Volumetric & Protocol DDoS Detector
Streaming threat detector utilizing O(1) differential Shannon entropy H(X_dport)
and EWMA flow rate moving variance (Z_rate score) to identify targeted floods,
random-port UDP sweeps, and TCP half-open SYN floods with sub-millisecond latency.
"""

from __future__ import annotations

import collections
import logging
import math
import time
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from ..ingestion.models import ConnTelemetryEvent, RawAlert
from .base import BaseDetector

logger = logging.getLogger("detectors.ddos_entropy")


def _log2_term(c: int) -> float:
    """Helper to compute c * log2(c) with 0 * log2(0) = 0."""
    return c * math.log2(c) if c > 0 else 0.0


class DifferentialEntropyTracker:
    """
    O(1) streaming differential Shannon entropy tracker over a sliding window of size N.
    Maintains the cumulative term S = sum(c_i * log2(c_i)) dynamically upon element insertion and eviction.
    """

    def __init__(self, window_size: int = 500):
        self.window_size = max(10, window_size)
        self.window: Deque[int] = collections.deque()
        self.counts: Dict[int, int] = collections.defaultdict(int)
        self.s_term: float = 0.0  # Sum of c * log2(c)

    def reset(self) -> None:
        """Reset internal window and frequency counters."""
        self.window.clear()
        self.counts.clear()
        self.s_term = 0.0

    def add(self, item: int) -> Tuple[float, float]:
        """
        Add an item to the sliding window, evicting the oldest element if at capacity.
        Returns (raw_entropy, normalized_entropy) in O(1) time.
        """
        # 1. Evict oldest element if window is full
        if len(self.window) >= self.window_size:
            old_item = self.window.popleft()
            old_count = self.counts[old_item]
            # Subtract old contribution, add new contribution for old_item
            self.s_term -= _log2_term(old_count)
            if old_count > 1:
                self.counts[old_item] = old_count - 1
                self.s_term += _log2_term(old_count - 1)
            else:
                del self.counts[old_item]

        # 2. Insert new item
        new_count = self.counts[item]
        self.s_term -= _log2_term(new_count)
        self.counts[item] = new_count + 1
        self.s_term += _log2_term(new_count + 1)
        self.window.append(item)

        # 3. Compute Shannon Entropy H(X) = log2(N) - (1/N) * S
        n = len(self.window)
        if n <= 1:
            return 0.0, 0.0

        raw_entropy = max(0.0, math.log2(n) - (self.s_term / n))

        # Normalized Entropy = H(X) / log2(min(N, max_distinct_ports))
        max_possible = math.log2(min(n, 65536))
        norm_entropy = (raw_entropy / max_possible) if max_possible > 0 else 0.0
        return round(raw_entropy, 4), round(min(1.0, max(0.0, norm_entropy)), 4)


class RateEWMATracker:
    """
    Tracks arrival rate (packets or flows per second) using 1-second rolling buckets
    and an Exponentially Weighted Moving Average (EWMA) with moving variance and Z-score.
    """

    def __init__(self, alpha: float = 0.08, min_samples: int = 5):
        self.alpha = alpha
        self.min_samples = min_samples
        self.current_sec_bucket: int = 0
        self.current_bucket_count: int = 0
        self.current_bucket_pkts: int = 0
        self.last_rate_pps: float = 0.0

        self.ewma_rate: float = 0.0
        self.ewma_var: float = 0.0
        self.sample_count: int = 0

    def reset(self) -> None:
        """Reset EWMA rate tracker."""
        self.current_sec_bucket = 0
        self.current_bucket_count = 0
        self.current_bucket_pkts = 0
        self.last_rate_pps = 0.0
        self.ewma_rate = 0.0
        self.ewma_var = 0.0
        self.sample_count = 0

    def record_event(self, ts: float, pkts: int = 1) -> Tuple[float, float, float]:
        """
        Record flow event at timestamp ts.
        Returns (current_rate_pps, ewma_rate_pps, rate_z_score).
        """
        sec_bucket = int(ts)
        effective_pkts = max(1, pkts)

        if self.current_sec_bucket == 0:
            self.current_sec_bucket = sec_bucket
            self.current_bucket_count = 1
            self.current_bucket_pkts = effective_pkts
            self.last_rate_pps = float(effective_pkts)
            self.ewma_rate = float(effective_pkts)
            self.ewma_var = 1.0
            self.sample_count = 1
            return self.last_rate_pps, self.ewma_rate, 0.0

        if sec_bucket == self.current_sec_bucket:
            self.current_bucket_count += 1
            self.current_bucket_pkts += effective_pkts
            # Instantaneous estimate during active second
            instant_rate = max(self.last_rate_pps, float(self.current_bucket_pkts))
            std_dev = math.sqrt(max(0.01, self.ewma_var))
            z_score = (instant_rate - self.ewma_rate) / (std_dev + 1e-5)
            return instant_rate, self.ewma_rate, round(z_score, 2)

        # Elapsed second transition
        elapsed_sec = max(1, sec_bucket - self.current_sec_bucket)
        measured_rate = float(self.current_bucket_pkts) / elapsed_sec
        self.last_rate_pps = measured_rate

        # Update EWMA mean and variance
        if self.sample_count == 1:
            self.ewma_rate = measured_rate
            self.ewma_var = max(1.0, (measured_rate * 0.1) ** 2)
        else:
            diff = measured_rate - self.ewma_rate
            self.ewma_rate = (1.0 - self.alpha) * self.ewma_rate + self.alpha * measured_rate
            self.ewma_var = (1.0 - self.alpha) * self.ewma_var + self.alpha * (diff**2)

        self.sample_count += 1
        self.current_sec_bucket = sec_bucket
        self.current_bucket_count = 1
        self.current_bucket_pkts = effective_pkts

        # Active instantaneous rate for current second transition
        instant_rate = max(self.last_rate_pps, float(self.current_bucket_pkts))
        std_dev = math.sqrt(max(0.01, self.ewma_var))
        z_score = (instant_rate - self.ewma_rate) / (std_dev + 1e-5)
        return instant_rate, round(self.ewma_rate, 2), round(z_score, 2)


class TargetHostDDoSState:
    """
    Per-target state tracking sliding port entropy, EWMA rates, and connection states.
    """

    def __init__(self, target_ip: str, window_size: int = 500):
        self.target_ip = target_ip
        self.entropy_tracker = DifferentialEntropyTracker(window_size=window_size)
        self.rate_tracker = RateEWMATracker(alpha=0.08)
        self.conn_state_window: Deque[str] = collections.deque(maxlen=window_size)
        self.recent_ports: Deque[int] = collections.deque(maxlen=10)
        self.last_alert_ts: float = 0.0
        self.last_alert_rate: float = 0.0
        self.last_seen_ts: float = 0.0

    def update(
        self,
        dst_port: int,
        ts: float,
        conn_state: str = "SF",
        orig_pkts: int = 1,
    ) -> Tuple[float, float, float, float, float, float]:
        """
        Updates state with new packet/flow.
        Returns (raw_entropy, norm_entropy, current_rate, ewma_rate, z_score, syn_ratio).
        """
        self.last_seen_ts = ts
        raw_entropy, norm_entropy = self.entropy_tracker.add(dst_port)
        current_rate, ewma_rate, z_score = self.rate_tracker.record_event(ts, pkts=orig_pkts)

        self.conn_state_window.append(conn_state)
        self.recent_ports.append(dst_port)

        # Calculate ratio of half-open / SYN-only states ('S0', 'REJ', or 'S')
        s0_count = sum(1 for s in self.conn_state_window if s in ("S0", "REJ", "RSTOS0"))
        syn_ratio = (s0_count / len(self.conn_state_window)) if self.conn_state_window else 0.0

        return (
            raw_entropy,
            norm_entropy,
            current_rate,
            ewma_rate,
            z_score,
            round(syn_ratio, 3),
        )


class DDoSEntropyDetector(BaseDetector):
    """
    Detector 1: Volumetric & Protocol DDoS Detector
    Detects targeted volumetric floods, port collapse attacks, random-port UDP sweeps,
    and TCP half-open SYN floods using streaming differential entropy and EWMA Z-scores.
    """

    def __init__(
        self,
        window_size: int = 500,
        rate_z_threshold: float = 3.0,
        rate_min_pps: float = 100.0,
        entropy_low_threshold: float = 1.2,
        entropy_high_norm_threshold: float = 0.85,
        syn_ratio_threshold: float = 0.70,
        alert_cooldown_sec: float = 5.0,
        state_ttl_sec: float = 300.0,
        max_tracked_hosts: int = 50_000,
        bus: Optional[Any] = None,
        producer: Optional[Any] = None,
    ):
        super().__init__(
            detector_id="ddos_entropy",
            input_topic="telemetry.conn",
            output_topic="alerts.raw",
            bus=bus,
            producer=producer,
            state_ttl_sec=state_ttl_sec,
            max_tracked_hosts=max_tracked_hosts,
        )
        self.window_size = window_size
        self.rate_z_threshold = rate_z_threshold
        self.rate_min_pps = rate_min_pps
        self.entropy_low_threshold = entropy_low_threshold
        self.entropy_high_norm_threshold = entropy_high_norm_threshold
        self.syn_ratio_threshold = syn_ratio_threshold
        self.alert_cooldown_sec = alert_cooldown_sec

        # Target-centric state dictionary: target_ip -> TargetHostDDoSState
        self._target_states: Dict[str, TargetHostDDoSState] = {}

    def reset_state(self) -> None:
        """Clear all tracked host states and base metrics."""
        self._target_states.clear()
        self._host_last_seen.clear()

    def _on_host_evicted(self, host: str) -> None:
        """Prune target host state upon eviction."""
        self._target_states.pop(host, None)

    def _get_or_create_state(self, target_ip: str) -> TargetHostDDoSState:
        """Retrieve or create state for target host."""
        if target_ip not in self._target_states:
            self._target_states[target_ip] = TargetHostDDoSState(
                target_ip=target_ip,
                window_size=self.window_size,
            )
        return self._target_states[target_ip]

    def process_event(
        self,
        event: Union[ConnTelemetryEvent, Dict[str, Any], str],
    ) -> Optional[RawAlert]:
        """
        Evaluate a single telemetry event for DDoS patterns.
        """
        # Normalize event
        if isinstance(event, ConnTelemetryEvent):
            conn = event
        elif isinstance(event, dict):
            conn = ConnTelemetryEvent.from_zeek_dict(event)
        elif isinstance(event, str):
            import json
            conn = ConnTelemetryEvent.from_zeek_dict(json.loads(event))
        else:
            return None

        target_ip = conn.dst_ip
        target_port = conn.dst_port
        source_ip = conn.src_ip
        ts = conn.ts or time.time()
        conn_state = conn.conn_state or "SF"
        orig_pkts = max(1, conn.orig_pkts or 1)

        # Update liveness in BaseDetector
        self.update_host_liveness(target_ip, ts)

        # Update target host state
        state = self._get_or_create_state(target_ip)
        (
            raw_entropy,
            norm_entropy,
            current_rate,
            ewma_rate,
            z_score,
            syn_ratio,
        ) = state.update(
            dst_port=target_port,
            ts=ts,
            conn_state=conn_state,
            orig_pkts=orig_pkts,
        )

        # -------------------------------------------------------------
        # Decision Rules Evaluation
        # -------------------------------------------------------------
        threat_class: Optional[str] = None
        severity = "HIGH"
        confidence = 0.85
        mitigation = "rate_limit"

        is_volumetric_rate = (current_rate >= self.rate_min_pps) or (
            current_rate >= (self.rate_min_pps * 0.5) and z_score >= self.rate_z_threshold
        )

        # Rule 1: Targeted Port Collapse (Concentrated flood targeting specific port like 80/443)
        if is_volumetric_rate and (
            raw_entropy < self.entropy_low_threshold or norm_entropy < 0.20
        ):
            threat_class = "volumetric_ddos"
            severity = "CRITICAL"
            confidence = min(0.99, 0.85 + (0.14 if z_score > 5.0 else 0.08))
            mitigation = "rate_limit"

        # Rule 2: Protocol SYN Flood (Half-Open S0 / REJ state saturation)
        elif (current_rate >= (self.rate_min_pps * 0.5) or (current_rate >= 20.0 and z_score >= (self.rate_z_threshold * 0.8))) and (
            syn_ratio >= self.syn_ratio_threshold
        ):
            threat_class = "protocol_ddos"
            severity = "CRITICAL"
            confidence = min(0.98, 0.88 + (0.10 if syn_ratio >= 0.90 else 0.05))
            mitigation = "rate_limit"

        # Rule 3: Distributed Random-Port UDP/SYN Sweep Flood (High rate + High entropy)
        elif is_volumetric_rate and (
            norm_entropy >= self.entropy_high_norm_threshold
        ):
            threat_class = "volumetric_ddos"
            severity = "HIGH"
            confidence = min(0.95, 0.82 + (0.10 if z_score > 5.0 else 0.05))
            mitigation = "block_source_ip"

        if threat_class is None:
            return None

        # Cooldown check: avoid spamming alerts for the same target
        if (ts - state.last_alert_ts < self.alert_cooldown_sec) and (
            current_rate < state.last_alert_rate * 1.5
        ):
            return None

        state.last_alert_ts = ts
        state.last_alert_rate = current_rate

        # Build standardized evidence payload
        evidence = {
            "current_rate_pps": round(float(current_rate), 2),
            "ewma_rate_pps": round(float(ewma_rate), 2),
            "rate_z_score": round(float(z_score), 2),
            "port_entropy": round(float(raw_entropy), 4),
            "max_entropy": 16.0,
            "normalized_port_entropy": round(float(norm_entropy), 4),
            "syn_only_ratio": round(float(syn_ratio), 4),
            "sample_target_ports": list(state.recent_ports),
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
            window_duration_sec=round(float(min(5.0, max(1.0, len(state.entropy_tracker.window) / max(1.0, current_rate)))), 2),
            evidence=evidence,
            recommended_mitigation=mitigation,
        )
        return alert
