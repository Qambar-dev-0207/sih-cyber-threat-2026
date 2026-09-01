"""
SIH26145 - Application State, Connection Manager & Incident Ring Buffer
Provides thread-safe state management, multi-client WebSocket fan-out,
bounded in-memory incident indexing, and pipeline singletons.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from fastapi import WebSocket, WebSocketDisconnect

from src.api.config import ApiConfig, get_config
from src.api.models import (
    IncidentActionResponse,
    IncidentBroadcastMessage,
    IncidentDetailResponse,
    TelemetryStreamMessage,
)
from src.cep.engine import CEPAggregatorEngine
from src.storage.db import TimescaleDatabase
from src.utils.metrics_calculator import MetricsCalculator

logger = logging.getLogger("sih.api.state")


class ConnectionManager:
    """
    Thread-safe & async-safe WebSocket connection manager handling
    multi-client broadcast fan-out for telemetry gauges and incident feeds.
    """

    def __init__(self) -> None:
        self._telemetry_sockets: Set[WebSocket] = set()
        self._incident_sockets: Set[WebSocket] = set()
        self._lock: asyncio.Lock = asyncio.Lock()

    @property
    def telemetry_count(self) -> int:
        return len(self._telemetry_sockets)

    @property
    def incident_count(self) -> int:
        return len(self._incident_sockets)

    async def connect_telemetry(self, websocket: WebSocket) -> None:
        """Accepts and registers a new telemetry WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._telemetry_sockets.add(websocket)
        logger.info(f"Telemetry client connected. Active: {self.telemetry_count}")

    async def disconnect_telemetry(self, websocket: WebSocket) -> None:
        """Removes a telemetry WebSocket client."""
        async with self._lock:
            self._telemetry_sockets.discard(websocket)
        logger.info(f"Telemetry client disconnected. Active: {self.telemetry_count}")

    async def connect_incidents(self, websocket: WebSocket) -> None:
        """Accepts and registers a new incident push WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._incident_sockets.add(websocket)
        logger.info(f"Incident client connected. Active: {self.incident_count}")

    async def disconnect_incidents(self, websocket: WebSocket) -> None:
        """Removes an incident push WebSocket client."""
        async with self._lock:
            self._incident_sockets.discard(websocket)
        logger.info(f"Incident client disconnected. Active: {self.incident_count}")

    async def broadcast_telemetry(self, data: Union[Dict[str, Any], TelemetryStreamMessage]) -> int:
        """Broadcasts line-rate telemetry payload to all connected telemetry clients."""
        payload = data.model_dump() if isinstance(data, TelemetryStreamMessage) else data
        dead_sockets: List[WebSocket] = []

        async with self._lock:
            sockets_snapshot = list(self._telemetry_sockets)

        delivered = 0
        for ws in sockets_snapshot:
            try:
                await ws.send_json(payload)
                delivered += 1
            except Exception as exc:
                logger.debug(f"Telemetry broadcast send failure ({exc}), removing socket.")
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for dead_ws in dead_sockets:
                    self._telemetry_sockets.discard(dead_ws)

        return delivered

    async def broadcast_incident(self, data: Union[Dict[str, Any], IncidentBroadcastMessage, IncidentDetailResponse]) -> int:
        """Broadcasts triaged incident payload to all connected incident feed clients."""
        if isinstance(data, IncidentBroadcastMessage):
            payload = data.model_dump()
        elif isinstance(data, IncidentDetailResponse):
            payload = IncidentBroadcastMessage(
                event_type="NEW_INCIDENT",
                incident_id=data.incident_id,
                severity=data.severity,
                risk_score=data.risk_score,
                threat_class=data.primary_threat_class,
                summary=data.attack_narrative or f"{data.severity} {data.primary_threat_class} detected on {data.source_ip}",
                incident=data,
            ).model_dump()
        elif isinstance(data, dict):
            payload = data
        else:
            payload = {"event_type": "NEW_INCIDENT", "data": str(data)}

        dead_sockets: List[WebSocket] = []

        async with self._lock:
            sockets_snapshot = list(self._incident_sockets)

        delivered = 0
        for ws in sockets_snapshot:
            try:
                await ws.send_json(payload)
                delivered += 1
            except Exception as exc:
                logger.debug(f"Incident broadcast send failure ({exc}), removing socket.")
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for dead_ws in dead_sockets:
                    self._incident_sockets.discard(dead_ws)

        return delivered


class IncidentRingBuffer:
    """
    Thread-safe bounded circular ring buffer and index for triaged incidents (capped at 500).
    """

    def __init__(self, max_size: int = 500) -> None:
        self.max_size: int = max_size
        self._incidents: OrderedDict[str, IncidentDetailResponse] = OrderedDict()
        self._lock: threading.RLock = threading.RLock()

    def add_incident(self, incident: IncidentDetailResponse) -> None:
        """Adds or updates an incident in the ring buffer, evicting oldest if capacity exceeded."""
        with self._lock:
            # If exists, remove and re-insert at top
            if incident.incident_id in self._incidents:
                del self._incidents[incident.incident_id]

            self._incidents[incident.incident_id] = incident

            # Evict oldest if beyond max_size
            while len(self._incidents) > self.max_size:
                self._incidents.popitem(last=False)

    def get_incident(self, incident_id: str) -> Optional[IncidentDetailResponse]:
        """Retrieves an incident by its ID."""
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(
        self,
        page: int = 1,
        limit: int = 20,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Tuple[List[IncidentDetailResponse], int]:
        """Returns paginated, filtered incidents sorted descending by update timestamp."""
        with self._lock:
            # Copy all incidents (newest last in OrderedDict, so reverse for newest first)
            all_items = list(reversed(self._incidents.values()))

            filtered: List[IncidentDetailResponse] = []
            for inc in all_items:
                if severity and inc.severity.upper() != severity.upper():
                    continue
                if threat_class and threat_class.lower() not in inc.primary_threat_class.lower() and not any(threat_class.lower() in tc.lower() for tc in inc.threat_classes):
                    continue
                if status and inc.status.upper() != status.upper():
                    continue
                filtered.append(inc)

            total = len(filtered)
            start_idx = max(0, (page - 1) * limit)
            end_idx = start_idx + limit
            paged_items = filtered[start_idx:end_idx]

            return paged_items, total

    def update_incident_action(
        self,
        incident_id: str,
        action: str,
        notes: str = "",
    ) -> Optional[IncidentDetailResponse]:
        """Updates human-in-the-loop action status for an incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            action_upper = action.upper()
            if action_upper in ("APPROVE", "APPROVED"):
                incident.status = "APPROVED"
            elif action_upper in ("DISMISS", "DISMISSED"):
                incident.status = "DISMISSED"
            elif action_upper in ("RESOLVE", "RESOLVED"):
                incident.status = "RESOLVED"
            else:
                incident.status = action_upper

            incident.updated_at = time.time()
            if notes:
                if incident.evidence_summary is None:
                    incident.evidence_summary = {}
                incident.evidence_summary["analyst_notes"] = notes
                incident.evidence_summary["last_action"] = action_upper

            # Re-index at top
            del self._incidents[incident_id]
            self._incidents[incident_id] = incident
            return incident

    def count(self) -> int:
        with self._lock:
            return len(self._incidents)

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()


class AppState:
    """
    Central application state managing pipeline singletons, in-memory buffers,
    active detectors, and database connection fallback.
    """

    def __init__(self, config: Optional[ApiConfig] = None) -> None:
        self.config: ApiConfig = config or get_config()
        self.start_time: float = time.time()

        # WebSockets & Buffers
        self.connection_manager: ConnectionManager = ConnectionManager()
        self.incident_buffer: IncidentRingBuffer = IncidentRingBuffer(
            max_size=self.config.incident_buffer_size
        )

        # CEP Engine Singleton
        self.cep_engine: CEPAggregatorEngine = CEPAggregatorEngine()

        # Database Singleton with Graceful Fallback
        self.db: TimescaleDatabase = TimescaleDatabase(
            host=self.config.postgres_host,
            port=self.config.postgres_port,
            dbname=self.config.postgres_db,
            user=self.config.postgres_user,
            password=self.config.postgres_password,
        )

        # Performance Metrics Calculator
        self.metrics_calculator: MetricsCalculator = MetricsCalculator(window_seconds=1.0)
        self.metrics_calculator.start()

        # Detector Health Statuses
        self.detector_statuses: Dict[str, bool] = {
            "ddos_entropy": True,
            "portscan_hll": True,
            "exfil_ratio": True,
            "dga_lstm": True,
            "ja4_malware": True,
            "c2_beacon": True,
        }

        # Background Task Handles
        self.telemetry_task: Optional[asyncio.Task] = None
        self.is_running: bool = False
        self._compiled_triage_graph: Optional[Any] = None

    @property
    def uptime_seconds(self) -> float:
        return round(time.time() - self.start_time, 2)

    def get_triage_graph(self) -> Any:
        """Returns or lazily compiles the LangGraph triage graph."""
        if self._compiled_triage_graph is None:
            from src.agentic_triage.graph import compile_triage_graph
            self._compiled_triage_graph = compile_triage_graph(db=self.db, execution_mode="deterministic")
        return self._compiled_triage_graph


# Global singleton instance
_app_state: Optional[AppState] = None


def get_app_state() -> AppState:
    """Retrieves the global AppState singleton."""
    global _app_state
    if _app_state is None:
        _app_state = AppState()
    return _app_state


def reset_app_state() -> AppState:
    """Resets and reinitializes the global AppState (useful for testing)."""
    global _app_state
    _app_state = AppState()
    return _app_state
