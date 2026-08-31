"""
SIH26145 - Multi-Detector Worker Orchestrator
Coordinates and routes streaming network telemetry across all 6 threat detectors:
1. Volumetric & Protocol DDoS (telemetry.conn)
2. Port Scanning & Recon (telemetry.conn)
3. Data Exfiltration (telemetry.conn)
4. DGA & DNS Tunnelling (telemetry.dns)
5. Encrypted Malware JA4/JA4S (telemetry.ssl)
6. C2 Beaconing (telemetry.conn)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from ..ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from ..ingestion.streaming_bus import InMemoryStreamingBus, StreamingBus
from .base import BaseDetector
from .c2_beaconing import C2BeaconingDetector
from .ddos_entropy import DDoSEntropyDetector
from .dga_tunneling import DGATunnelingDetector
from .encrypted_malware import EncryptedMalwareDetector
from .exfil_ratio import ExfilRatioDetector
from .portscan_hll import PortScanHLLDetector

logger = logging.getLogger("detectors.detector_manager")


class DetectorManager:
    """
    Multi-detector pipeline manager for a single partition worker or embedded test harness.
    Routes telemetry events to registered detectors based on event type or topic.
    """

    def __init__(
        self,
        bus: Optional[StreamingBus] = None,
        state_ttl_sec: float = 300.0,
        max_tracked_hosts: int = 50_000,
    ):
        self.bus = bus if bus is not None else InMemoryStreamingBus(num_partitions=4)
        self.state_ttl_sec = state_ttl_sec
        self.max_tracked_hosts = max_tracked_hosts

        # Instantiate all 6 Phase 2 streaming detectors
        self.detector_ddos = DDoSEntropyDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )
        self.detector_portscan = PortScanHLLDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )
        self.detector_exfil = ExfilRatioDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )
        self.detector_dga = DGATunnelingDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )
        self.detector_malware = EncryptedMalwareDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )
        self.detector_c2 = C2BeaconingDetector(
            bus=self.bus,
            state_ttl_sec=self.state_ttl_sec,
            max_tracked_hosts=self.max_tracked_hosts,
        )

        self.detectors: Dict[str, BaseDetector] = {
            "ddos_entropy": self.detector_ddos,
            "portscan_hll": self.detector_portscan,
            "exfil_ratio": self.detector_exfil,
            "dga_lstm": self.detector_dga,
            "ja4_malware": self.detector_malware,
            "c2_beacon": self.detector_c2,
        }

    def process_event(
        self,
        event: Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any]],
        topic: Optional[str] = None,
    ) -> List[RawAlert]:
        """
        Routes a single telemetry event to all relevant detectors.
        Returns a list of generated RawAlert objects.
        """
        alerts: List[RawAlert] = []

        if isinstance(event, DnsTelemetryEvent) or topic == "telemetry.dns":
            alert = self.detector_dga.handle_event(event)
            if alert:
                alerts.append(alert)

        elif isinstance(event, SslTelemetryEvent) or topic == "telemetry.ssl":
            alert = self.detector_malware.handle_event(event)
            if alert:
                alerts.append(alert)

        elif isinstance(event, ConnTelemetryEvent) or topic == "telemetry.conn":
            for det in (self.detector_ddos, self.detector_portscan, self.detector_exfil, self.detector_c2):
                alert = det.handle_event(event)
                if alert:
                    alerts.append(alert)

        elif isinstance(event, dict):
            # Infer from dictionary structure
            if "query" in event or "rcode_name" in event:
                alert = self.detector_dga.handle_event(event)
                if alert:
                    alerts.append(alert)
            elif "ja4" in event or "cipher" in event or "server_name" in event:
                alert = self.detector_malware.handle_event(event)
                if alert:
                    alerts.append(alert)
            else:
                for det in (self.detector_ddos, self.detector_portscan, self.detector_exfil, self.detector_c2):
                    alert = det.handle_event(event)
                    if alert:
                        alerts.append(alert)

        return alerts

    def reset_all_states(self) -> None:
        """Reset state across all detectors."""
        for det in self.detectors.values():
            det.reset_state()

    def evict_all_expired_states(self, current_ts: Optional[float] = None) -> Dict[str, int]:
        """Evicts expired host states across all detectors."""
        eviction_counts = {}
        for name, det in self.detectors.items():
            eviction_counts[name] = det.evict_expired_states(current_ts)
        return eviction_counts

    def get_all_metrics(self) -> Dict[str, Any]:
        """Returns consolidated metrics across all 6 detectors."""
        return {name: det.get_metrics() for name, det in self.detectors.items()}
