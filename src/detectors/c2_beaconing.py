"""
SIH26145 - Detector 6: Streaming C2 Beaconing Threat Detector
Evaluates rolling inter-arrival time (Delta-T) circular buffers (N=25)
per (src_ip, dst_ip, dst_port) flow tuple to identify periodic C2 callbacks,
heartbeats, and jittered malware communication with sub-millisecond latency.
"""

from __future__ import annotations

import collections
import json
import logging
import math
import time
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

from ..ingestion.models import ConnTelemetryEvent, RawAlert
from .base import BaseDetector

logger = logging.getLogger("detectors.c2_beaconing")


def compute_interarrival_stats(
    intervals: Union[List[float], Deque[float]],
) -> Tuple[float, float, float, float, float, float]:
    """
    Computes statistical dispersion metrics over a collection of delta-T intervals.
    Returns: (mean, std_dev, cv, median, mad, jitter_ratio).
    """
    n = len(intervals)
    if n < 2:
        return 0.0, 0.0, 1.0, 0.0, 0.0, 1.0

    # 1. Arithmetic Mean (μ)
    mean_val = sum(intervals) / float(n)
    if mean_val <= 1e-6:
        return 0.0, 0.0, 1.0, 0.0, 0.0, 1.0

    # 2. Sample Standard Deviation (σ)
    variance = sum((x - mean_val) ** 2 for x in intervals) / float(n - 1)
    std_dev = math.sqrt(max(0.0, variance))

    # 3. Coefficient of Variation (CV = σ / μ)
    cv = std_dev / mean_val

    # 4. Median (M)
    sorted_vals = sorted(intervals)
    if n % 2 == 1:
        median_val = sorted_vals[n // 2]
    else:
        median_val = (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0

    # 5. Median Absolute Deviation (MAD)
    abs_devs = sorted(abs(x - median_val) for x in intervals)
    if n % 2 == 1:
        mad_val = abs_devs[n // 2]
    else:
        mad_val = (abs_devs[n // 2 - 1] + abs_devs[n // 2]) / 2.0

    # 6. Jitter Ratio
    jitter_ratio = (mad_val / median_val) if median_val > 1e-6 else 0.0

    return (
        round(mean_val, 4),
        round(std_dev, 4),
        round(cv, 4),
        round(median_val, 4),
        round(mad_val, 4),
        round(jitter_ratio, 4),
    )


class CircularDeltaTBuffer:
    """
    Fixed-capacity circular buffer storing up to maxlen inter-arrival timestamps.
    """

    def __init__(self, maxlen: int = 25):
        self.maxlen = maxlen
        self.buffer: Deque[float] = collections.deque(maxlen=maxlen)

    def add(self, delta_t: float) -> None:
        self.buffer.append(float(delta_t))

    def __len__(self) -> int:
        return len(self.buffer)

    def clear(self) -> None:
        self.buffer.clear()

    def get_intervals(self) -> List[float]:
        return list(self.buffer)


class FlowBeaconState:
    """
    State tracking object for a single (src_ip, dst_ip, dst_port) communication channel.
    """

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        buffer_size: int = 25,
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.buffer_size = buffer_size

        self.first_ts: float = 0.0
        self.last_ts: float = 0.0
        self.total_events: int = 0
        self.intervals: Deque[float] = collections.deque(maxlen=buffer_size)

        self.last_alert_ts: float = 0.0
        self.last_alert_count: int = 0

    def record_event(self, ts: float) -> Optional[Tuple[float, float, float, float, float, float, int]]:
        """
        Records a timestamp and updates intervals.
        Returns dispersion stats tuple if intervals >= 2, else None.
        """
        if self.total_events == 0:
            self.first_ts = ts
            self.last_ts = ts
            self.total_events = 1
            return None

        # Ignore non-monotonic or identical millisecond duplicate packets
        if ts <= self.last_ts:
            self.total_events += 1
            return None

        delta_t = ts - self.last_ts
        self.intervals.append(delta_t)
        self.last_ts = ts
        self.total_events += 1

        n = len(self.intervals)
        if n < 2:
            return None

        stats = compute_interarrival_stats(self.intervals)
        return stats + (n,)


class C2BeaconingDetector(BaseDetector):
    """
    Detector 6: Streaming C2 Beaconing Threat Detector.
    Detects periodic beaconing with CV < 0.15 across >= 15 connection intervals.
    """

    def __init__(
        self,
        buffer_size: int = 25,
        min_samples: int = 15,
        cv_threshold: float = 0.15,
        min_interval_sec: float = 0.5,
        alert_cooldown_sec: float = 60.0,
        state_ttl_sec: float = 300.0,
        max_tracked_hosts: int = 50_000,
        bus: Optional[Any] = None,
        producer: Optional[Any] = None,
    ):
        super().__init__(
            detector_id="c2_beacon",
            input_topic="telemetry.conn",
            output_topic="alerts.raw",
            bus=bus,
            producer=producer,
            state_ttl_sec=state_ttl_sec,
            max_tracked_hosts=max_tracked_hosts,
        )
        self.buffer_size = buffer_size
        self.min_samples = min_samples
        self.cv_threshold = cv_threshold
        self.min_interval_sec = min_interval_sec
        self.alert_cooldown_sec = alert_cooldown_sec

        # Flow map: (src_ip, dst_ip, dst_port) -> FlowBeaconState
        self._flow_states: Dict[Tuple[str, str, int], FlowBeaconState] = {}

    def reset_state(self) -> None:
        self._flow_states.clear()
        self._host_last_seen.clear()

    def _on_host_evicted(self, host: str) -> None:
        """Evict all flows originating from the expired host."""
        keys_to_remove = [k for k in self._flow_states if k[0] == host]
        for k in keys_to_remove:
            self._flow_states.pop(k, None)

    def _get_or_create_flow(self, src_ip: str, dst_ip: str, dst_port: int) -> FlowBeaconState:
        key = (src_ip, dst_ip, dst_port)
        if key not in self._flow_states:
            self._flow_states[key] = FlowBeaconState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                buffer_size=self.buffer_size,
            )
        return self._flow_states[key]

    def process_event(
        self,
        event: Union[ConnTelemetryEvent, Dict[str, Any], str],
    ) -> Optional[RawAlert]:
        """
        Process a single connection telemetry event and evaluate delta-T periodicity.
        """
        # Normalize event
        if isinstance(event, ConnTelemetryEvent):
            conn = event
        elif isinstance(event, dict):
            conn = ConnTelemetryEvent.from_zeek_dict(event)
        elif isinstance(event, str):
            conn = ConnTelemetryEvent.from_zeek_dict(json.loads(event))
        else:
            return None

        src_ip = conn.src_ip
        dst_ip = conn.dst_ip
        dst_port = conn.dst_port
        ts = conn.ts or time.time()

        # Update host liveness in BaseDetector
        self.update_host_liveness(src_ip, ts)

        # Update flow state
        flow = self._get_or_create_flow(src_ip, dst_ip, dst_port)
        res = flow.record_event(ts)
        if res is None:
            return None

        mean_val, std_dev, cv, median_val, mad_val, jitter_ratio, n = res

        # -------------------------------------------------------------
        # Decision Rule Evaluation
        # -------------------------------------------------------------
        # 1. Require at least min_samples (>= 15) intervals in circular buffer
        if n < self.min_samples:
            return None

        # 2. Filter out rapid sub-second burst transfers (e.g. file chunking / streaming)
        if mean_val < self.min_interval_sec:
            return None

        # 3. Trigger condition: Strong periodicity CV < cv_threshold (0.15)
        if cv >= self.cv_threshold:
            return None

        # 4. Alert cooldown to prevent redundant flooding
        if (ts - flow.last_alert_ts < self.alert_cooldown_sec) and (
            flow.total_events - flow.last_alert_count < self.buffer_size
        ):
            return None

        flow.last_alert_ts = ts
        flow.last_alert_count = flow.total_events

        # Calculate confidence score
        confidence = min(0.99, max(0.80, 1.0 - cv))
        severity = "CRITICAL" if (confidence >= 0.95 and n >= 20) else "HIGH"

        # Evidence dictionary conforming strictly to PROJECT.md line 97
        evidence = {
            "cv": round(float(cv), 4),
            "mean_interval_sec": round(float(mean_val), 3),
            "std_dev_sec": round(float(std_dev), 3),
            "median_interval_sec": round(float(median_val), 3),
            "mad_sec": round(float(mad_val), 3),
            "sample_count": int(n),
            "jitter_ratio": round(float(jitter_ratio), 4),
            "flow_tuple": f"{src_ip}->{dst_ip}:{dst_port}",
            "min_interval_sec": round(float(min(flow.intervals)), 3),
            "max_interval_sec": round(float(max(flow.intervals)), 3),
        }

        window_duration = round(float(sum(flow.intervals)), 2)

        alert = RawAlert(
            detector_name="c2_beacon",
            threat_class="C2_BEACONING",
            severity=severity,
            confidence=round(confidence, 2),
            source_ip=src_ip,
            target_ip=dst_ip,
            target_port=dst_port,
            protocol=conn.proto or "tcp",
            flow_id=conn.uid,
            window_duration_sec=window_duration,
            evidence=evidence,
            mitre_technique="T1071",
            recommended_mitigation=(
                f"Isolate host {src_ip} immediately; inspect active network sockets "
                f"connecting to C2 destination {dst_ip}:{dst_port}."
            ),
        )
        return alert


# Class alias for backwards / alternative naming compatibility
C2BeaconDetector = C2BeaconingDetector
