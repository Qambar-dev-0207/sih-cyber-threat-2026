"""
SIH26145 - Incidents Query, Detail & Analyst Action REST Endpoints
"""

from __future__ import annotations

import math
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from src.api.models import (
    IncidentActionRequest,
    IncidentActionResponse,
    IncidentBroadcastMessage,
    IncidentDetailResponse,
    PaginatedIncidentsResponse,
)
from src.api.state import AppState, get_app_state

router = APIRouter(tags=["Incidents Management"])


@router.get(
    "/incidents",
    response_model=PaginatedIncidentsResponse,
    summary="List & Filter Triaged Incidents",
    description="Returns a paginated list of triaged security incidents with optional severity, threat class, and status filters.",
)
async def list_incidents(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    threat_class: Optional[str] = Query(default=None, description="Filter by threat class"),
    status: Optional[str] = Query(default=None, description="Filter by analyst review status (PENDING_REVIEW, APPROVED, DISMISSED)"),
    app_state: AppState = Depends(get_app_state),
) -> PaginatedIncidentsResponse:
    """Returns paginated incidents from the in-memory ring buffer."""
    items, total = app_state.incident_buffer.list_incidents(
        page=page,
        limit=limit,
        severity=severity,
        threat_class=threat_class,
        status=status,
    )

    pages = max(1, math.ceil(total / limit)) if total > 0 else 1

    return PaginatedIncidentsResponse(
        items=items,
        incidents=items,
        total=total,
        page=page,
        limit=limit,
        pages=pages,
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get Detailed Incident by ID",
    description="Returns full incident context including chronological timeline, explainable risk score breakdown, MITRE ATT&CK mappings, and 6 countermeasure artifacts.",
)
async def get_incident_detail(
    incident_id: str,
    app_state: AppState = Depends(get_app_state),
) -> IncidentDetailResponse:
    """Returns full investigation drawer details for the specified incident ID."""
    incident = app_state.incident_buffer.get_incident(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident with ID '{incident_id}' not found in active memory buffer.",
        )
    return incident


@router.post(
    "/incidents/{incident_id}/action",
    response_model=IncidentActionResponse,
    summary="Human-in-the-Loop Analyst Action",
    description="Allows SOC analysts to approve, dismiss, or resolve countermeasure artifacts while strictly preserving physical data diode isolation.",
)
async def execute_incident_action(
    incident_id: str,
    request: IncidentActionRequest,
    app_state: AppState = Depends(get_app_state),
) -> IncidentActionResponse:
    """Records human analyst confirmation or dismissal for an incident."""
    updated_incident = app_state.incident_buffer.update_incident_action(
        incident_id=incident_id,
        action=request.action,
        notes=request.analyst_notes or "",
    )

    if updated_incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident with ID '{incident_id}' not found to perform action '{request.action}'.",
        )

    # Broadcast action update to WebSocket clients
    broadcast_msg = IncidentBroadcastMessage(
        event_type="INCIDENT_ACTION",
        incident_id=incident_id,
        severity=updated_incident.severity,
        risk_score=updated_incident.risk_score,
        threat_class=updated_incident.primary_threat_class,
        summary=f"Analyst {request.analyst_id} set status to {updated_incident.status}: {request.analyst_notes}",
        incident=updated_incident,
    )
    await app_state.connection_manager.broadcast_incident(broadcast_msg)

    return IncidentActionResponse(
        incident_id=incident_id,
        action=request.action.upper(),
        status=updated_incident.status,
        updated_at=time.time(),
        analyst_notes=request.analyst_notes or "",
        requires_human_approval=True,
        message=f"Incident {incident_id} status updated to {updated_incident.status} by {request.analyst_id}.",
    )
