"""
SIH26145 - Detector 2: Port Scanning & Reconnaissance Detector
Streaming threat detector utilizing Dual-Bucket Slotted HyperLogLog (HLL, p=10, m=1024)
to estimate rolling 10-second distinct destination IP/port/endpoint cardinalities
and connection failure ratios (F_fail) with sub-microsecond register merges and lock-free locality.
"""

from __future__ import annotations

import collections
import logging
import math
import time
import zlib
from typing import Any, Deque, Dict, List, Optional, Tuple, Union

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

from ..ingestion.models import ConnTelemetryEvent, RawAlert
from .base import BaseDetector

logger = logging.getLogger("detectors.portscan_hll")

# Precomputed power-of-two inverses for register evaluation: 2^-v for v in [0..64]
_POW2_INV = tuple(2.0 ** (-i) for i in range(65))


def _hash64(val: Union[str, int]) -> int:
    """
    Computes a 64-bit unsigned hash integer for an input value.
    Uses mmh3.hash64 or 64-bit CRC32/FNV fallback.
    """
    val_str = str(val)
    if HAS_MMH3:
        # mmh3.hash64 returns a tuple of two 64-bit integers
        h64, _ = mmh3.hash64(val_str, seed=42)
        return h64 & 0xFFFFFFFFFFFFFFFF
    else:
        # 64-bit hash via dual CRC32 seeds
        c1 = zlib.crc32(val_str.encode("utf-8"), 0) & 0xFFFFFFFF
        c2 = zlib.crc32(val_str.encode("utf-8"), 0x5A5A5A5A) & 0xFFFFFFFF
        return (c1 << 32) | c2


class HyperLogLog:
    """
    Standard HyperLogLog cardinality estimator with precision p=10 (m=1024 registers).
    Theoretical standard error: 1.04 / sqrt(1024) ~= 3.25%.
    Maintains O(1) incremental z_sum and zero_count for sub-microsecond estimation.
    """

    def __init__(self, p: int = 10):
        self.p = p
        self.m = 1 << p  # 1024 registers for p=10
        self.registers = bytearray(self.m)
        # Precomputed alpha_m factor: alpha_1024 = 0.7213 / (1 + 1.079 / 1024) ~= 0.7205426
        self.alpha_m = 0.7213 / (1.0 + 1.079 / self.m)
        self.z_sum: float = float(self.m)
        self.zero_count: int = self.m

    def reset(self) -> None:
        """Clear all register values to 0."""
        self.registers = bytearray(self.m)
        self.z_sum = float(self.m)
        self.zero_count = self.m

    def add(self, item: Union[str, int]) -> None:
        """
        Hash the item, determine register index j and rank rho(w), and update register.
        """
        h = _hash64(item)
        # Register index: lowest p bits
        j = h & (self.m - 1)
        # Remaining 64 - p bits
        w = h >> self.p
        # Count leading zeros in w + 1
        max_bits = 64 - self.p
        if w == 0:
            rho = max_bits + 1
        else:
            rho = max_bits - w.bit_length() + 1

        old_val = self.registers[j]
        if rho > old_val:
            self.registers[j] = rho
            self.z_sum += _POW2_INV[rho] - _POW2_INV[old_val]
            if old_val == 0:
                self.zero_count -= 1

    def estimate(self) -> float:
        """
        Computes the cardinality estimate with LinearCounting bias correction in O(1) time.
        """
        if self.zero_count == self.m:
            return 0.0

        e_raw = (self.alpha_m * float(self.m * self.m)) / self.z_sum

        # Small range correction (LinearCounting) when E <= 2.5 * m
        if e_raw <= (2.5 * self.m):
            if self.zero_count > 0:
                return float(self.m) * math.log(float(self.m) / float(self.zero_count))
            return e_raw
        return e_raw

    @classmethod
    def estimate_from_registers(
        cls,
        registers: Union[bytearray, List[int]],
        m: int = 1024,
        alpha_m: float = 0.7205426,
    ) -> float:
        """
        Estimate cardinality from a given register bytearray/list.
        """
        pow2 = _POW2_INV
        z_sum = 0.0
        zero_count = 0
        for val in registers:
            z_sum += pow2[val]
            if val == 0:
                zero_count += 1

        if z_sum == 0.0:
            return 0.0

        e_raw = (alpha_m * float(m * m)) / z_sum

        # Small range correction (LinearCounting) when E <= 2.5 * m
        if e_raw <= (2.5 * m):
            if zero_count > 0:
                return float(m) * math.log(float(m) / float(zero_count))
            return e_raw
        return e_raw


class SlottedRollingHLL:
    """
    Dual-Bucket Slotted Rolling HyperLogLog maintaining a 10-second rolling window
    split into two 5-second sub-buckets (current and previous).
    Maintains incremental merged registers for O(1) cardinality estimation (< 1 microsecond).
    """

    def __init__(self, subwindow_sec: float = 5.0, p: int = 10):
        self.subwindow_sec = subwindow_sec
        self.p = p
        self.m = 1 << p
        self.current_hll = HyperLogLog(p=p)
        self.previous_hll = HyperLogLog(p=p)
        self.subwindow_start_ts: float = 0.0
        self.total_inserts: int = 0

        # Incremental merged register state for O(1) rolling estimation
        self.merged_registers = bytearray(self.m)
        self.merged_z_sum: float = float(self.m)
        self.merged_zero_count: int = self.m
        self.alpha_m = self.current_hll.alpha_m

    def reset(self) -> None:
        """Reset both current and previous buckets and merged state."""
        self.current_hll.reset()
        self.previous_hll.reset()
        self.subwindow_start_ts = 0.0
        self.total_inserts = 0
        self.merged_registers = bytearray(self.m)
        self.merged_z_sum = float(self.m)
        self.merged_zero_count = self.m

    def _rotate_if_needed(self, ts: float) -> None:
        """Rotate sub-buckets if current timestamp exceeds the sub-window."""
        if self.subwindow_start_ts == 0.0:
            self.subwindow_start_ts = ts
            return

        elapsed = ts - self.subwindow_start_ts
        if elapsed >= (2.0 * self.subwindow_sec):
            # Expired both sub-windows: clear completely
            self.current_hll.reset()
            self.previous_hll.reset()
            self.subwindow_start_ts = ts
            self.merged_registers = bytearray(self.m)
            self.merged_z_sum = float(self.m)
            self.merged_zero_count = self.m
        elif elapsed >= self.subwindow_sec:
            # Rotate current -> previous, create fresh current
            self.previous_hll.registers = bytearray(self.current_hll.registers)
            self.previous_hll.z_sum = self.current_hll.z_sum
            self.previous_hll.zero_count = self.current_hll.zero_count

            self.current_hll.reset()
            self.subwindow_start_ts = ts

            # Merged state at rotation is identical to previous_hll
            self.merged_registers = bytearray(self.previous_hll.registers)
            self.merged_z_sum = self.previous_hll.z_sum
            self.merged_zero_count = self.previous_hll.zero_count

    def add(self, item: Union[str, int], ts: float) -> None:
        """Add item to current HLL sub-bucket at timestamp ts and update merged state in O(1)."""
        self._rotate_if_needed(ts)

        h = _hash64(item)
        j = h & (self.m - 1)
        w = h >> self.p
        max_bits = 64 - self.p
        if w == 0:
            rho = max_bits + 1
        else:
            rho = max_bits - w.bit_length() + 1

        # Update current sub-bucket
        old_cur = self.current_hll.registers[j]
        if rho > old_cur:
            self.current_hll.registers[j] = rho
            self.current_hll.z_sum += _POW2_INV[rho] - _POW2_INV[old_cur]
            if old_cur == 0:
                self.current_hll.zero_count -= 1

        # Update rolling merged register
        old_merged = self.merged_registers[j]
        if rho > old_merged:
            self.merged_registers[j] = rho
            self.merged_z_sum += _POW2_INV[rho] - _POW2_INV[old_merged]
            if old_merged == 0:
                self.merged_zero_count -= 1

        self.total_inserts += 1

    def cardinality(self, ts: Optional[float] = None) -> int:
        """
        Estimate cardinality across the 10-second rolling window in O(1) time.
        """
        if ts is not None:
            self._rotate_if_needed(ts)

        if self.merged_zero_count == self.m:
            return 0

        e_raw = (self.alpha_m * float(self.m * self.m)) / self.merged_z_sum

        # Small range correction (LinearCounting) when E <= 2.5 * m
        if e_raw <= (2.5 * self.m):
            if self.merged_zero_count > 0:
                return int(round(float(self.m) * math.log(float(self.m) / float(self.merged_zero_count))))
            return int(round(e_raw))
        return int(round(e_raw))


class SourceHostScanState:
    """
    Per-source host state tracking rolling destination ports, target hosts,
    socket endpoints (dst_ip:dst_port), and connection failure states over 10s windows.
    """

    def __init__(self, source_ip: str):
        self.source_ip = source_ip
        self.hll_ports = SlottedRollingHLL(subwindow_sec=5.0, p=10)
        self.hll_hosts = SlottedRollingHLL(subwindow_sec=5.0, p=10)
        self.hll_endpoints = SlottedRollingHLL(subwindow_sec=5.0, p=10)

        # Sliding deque for connection failure ratio tracking: (conn_state, ts)
        self.conn_events: Deque[Tuple[str, float]] = collections.deque(maxlen=10000)
        self.port_samples: Deque[int] = collections.deque(maxlen=10)
        self.last_alert_ts: float = 0.0
        self.last_seen_ts: float = 0.0

    def update(
        self,
        dst_ip: str,
        dst_port: int,
        conn_state: str,
        ts: float,
    ) -> Tuple[int, int, int, float]:
        """
        Records connection attempt and updates HLL sketches and failure ratio.
        Returns (c_ports, c_hosts, c_endpoints, failure_ratio).
        """
        self.last_seen_ts = ts
        self.hll_ports.add(dst_port, ts)
        self.hll_hosts.add(dst_ip, ts)
        endpoint = f"{dst_ip}:{dst_port}"
        self.hll_endpoints.add(endpoint, ts)

        if dst_port not in self.port_samples:
            self.port_samples.append(dst_port)

        # Record connection event and prune events older than 10s
        self.conn_events.append((conn_state, ts))
        cutoff = ts - 10.0
        while self.conn_events and self.conn_events[0][1] < cutoff:
            self.conn_events.popleft()

        # Compute failure ratio F_fail
        total_events = len(self.conn_events)
        if total_events > 0:
            failed_count = sum(
                1 for state, _ in self.conn_events if state in ("S0", "REJ", "RSTO", "RSTR", "RSTOS0")
            )
            failure_ratio = float(failed_count) / float(total_events)
        else:
            failed_count = 0
            failure_ratio = 0.0

        self.failed_count = failed_count

        c_ports = self.hll_ports.cardinality(ts)
        c_hosts = self.hll_hosts.cardinality(ts)
        c_endpoints = self.hll_endpoints.cardinality(ts)

        return c_ports, c_hosts, c_endpoints, round(failure_ratio, 4)


class PortScanHLLDetector(BaseDetector):
    """
    Detector 2: Port Scanning & Reconnaissance Detector
    Identifies Nmap stealth SYN scans (-sS), connect scans (-sT), horizontal sweeps (-sU),
    and strobe scans in 10-second rolling windows using HyperLogLog and connection failure ratios.
    """

    def __init__(
        self,
        vertical_port_threshold: int = 25,
        horizontal_host_threshold: int = 20,
        strobe_endpoint_threshold: int = 40,
        failure_ratio_boost: float = 0.70,
        alert_cooldown_sec: float = 5.0,
        state_ttl_sec: float = 300.0,
        max_tracked_hosts: int = 100_000,
        bus: Optional[Any] = None,
        producer: Optional[Any] = None,
    ):
        super().__init__(
            detector_id="portscan_hll",
            input_topic="telemetry.conn",
            output_topic="alerts.raw",
            bus=bus,
            producer=producer,
            state_ttl_sec=state_ttl_sec,
            max_tracked_hosts=max_tracked_hosts,
        )
        self.vertical_port_threshold = vertical_port_threshold
        self.horizontal_host_threshold = horizontal_host_threshold
        self.strobe_endpoint_threshold = strobe_endpoint_threshold
        self.failure_ratio_boost = failure_ratio_boost
        self.alert_cooldown_sec = alert_cooldown_sec

        # Source host state cache: source_ip -> SourceHostScanState
        self._source_states: Dict[str, SourceHostScanState] = {}

    def reset_state(self) -> None:
        """Clear all source host states."""
        self._source_states.clear()
        self._host_last_seen.clear()

    def _on_host_evicted(self, host: str) -> None:
        """Prune source host state upon TTL eviction."""
        self._source_states.pop(host, None)

    def _get_or_create_state(self, source_ip: str) -> SourceHostScanState:
        """Retrieve or create state for source IP."""
        if source_ip not in self._source_states:
            self._source_states[source_ip] = SourceHostScanState(source_ip=source_ip)
        return self._source_states[source_ip]

    def process_event(
        self,
        event: Union[ConnTelemetryEvent, Dict[str, Any], str],
    ) -> Optional[RawAlert]:
        """
        Evaluate a single telemetry event for port scanning or reconnaissance behavior.
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
        ts = conn.ts or time.time()
        conn_state = conn.conn_state or "SF"

        # Update liveness in BaseDetector
        self.update_host_liveness(source_ip, ts)

        state = self._get_or_create_state(source_ip)
        c_ports, c_hosts, c_endpoints, failure_ratio = state.update(
            dst_ip=target_ip,
            dst_port=target_port,
            conn_state=conn_state,
            ts=ts,
        )

        # -------------------------------------------------------------
        # Decision Rules Evaluation
        # -------------------------------------------------------------
        threat_class: Optional[str] = None
        scan_type: Optional[str] = None
        severity = "HIGH"
        confidence = 0.80

        # Rule 1: Vertical Port Scan (Many ports on single/few hosts)
        if c_ports >= self.vertical_port_threshold and c_hosts <= 3:
            threat_class = "port_scan"
            if failure_ratio >= self.failure_ratio_boost:
                scan_type = "SYN_STEALTH"
                confidence = min(0.98, 0.88 + (0.10 * failure_ratio))
                severity = "HIGH"
            else:
                scan_type = "VERTICAL_PORT_SCAN"
                confidence = 0.85
                severity = "HIGH"

        # Rule 2: Horizontal Subnet Sweep (Same/few ports across many hosts)
        elif c_hosts >= self.horizontal_host_threshold and c_ports <= 3:
            threat_class = "recon_sweep"
            scan_type = "HORIZONTAL_SWEEP"
            severity = "MEDIUM" if failure_ratio < 0.50 else "HIGH"
            confidence = min(0.95, 0.80 + (0.15 * failure_ratio))

        # Rule 3: Strobe / Matrix Scan (Many distinct host:port endpoints with failure gating)
        elif c_endpoints >= self.strobe_endpoint_threshold and (failure_ratio >= 0.30 or getattr(state, "failed_count", 0) >= 10):
            threat_class = "port_scan"
            scan_type = "STROBE_MATRIX_SCAN"
            severity = "HIGH"
            confidence = min(0.96, 0.82 + (0.12 * failure_ratio))

        if threat_class is None:
            return None

        # Cooldown check per source host
        if (ts - state.last_alert_ts) < self.alert_cooldown_sec:
            return None

        state.last_alert_ts = ts

        # Build standardized evidence payload
        evidence = {
            "scan_type": scan_type,
            "hll_distinct_ports": int(c_ports),
            "hll_distinct_hosts": int(c_hosts),
            "hll_distinct_endpoints": int(c_endpoints),
            "failure_ratio": round(float(failure_ratio), 4),
            "scanned_port_samples": list(state.port_samples),
            "hll_registers_utilized": 1024,
        }

        alert = RawAlert(
            detector_name=self.detector_id,
            threat_class=threat_class,
            severity=severity,
            confidence=round(confidence, 2),
            source_ip=source_ip,
            target_ip=target_ip if c_hosts <= 3 else None,
            target_port=target_port if c_ports <= 3 else None,
            protocol=conn.proto or "tcp",
            flow_id=conn.uid,
            window_duration_sec=10.0,
            evidence=evidence,
            recommended_mitigation="block_source_ip",
        )
        return alert
