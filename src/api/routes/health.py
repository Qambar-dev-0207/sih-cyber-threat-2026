"""
SIH26145 - Health Check & Enclave Status Endpoint
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from src.api.models import DataDiodeStatus, HealthResponse
from src.api.state import AppState, get_app_state

router = APIRouter(tags=["System Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Detector Enclave Status",
    description="Returns backend health, active detector status, uptime, and physical data diode safety posture.",
)
async def get_system_health(
    app_state: AppState = Depends(get_app_state),
) -> HealthResponse:
    """Returns the overall operational health, detector statuses, and diode safety guarantees."""
    diode_status = DataDiodeStatus(
        status="ENFORCED",
        requires_human_approval=app_state.config.requires_human_approval,
        return_path="DISABLED",
        enclave_mode="AIR_GAPPED_PASSIVE",
    )

    return HealthResponse(
        status="healthy",
        uptime_seconds=app_state.uptime_seconds,
        version=app_state.config.version,
        detectors=app_state.detector_statuses,
        data_diode=diode_status,
        data_diode_status=diode_status,
        active_connections={
            "telemetry": app_state.connection_manager.telemetry_count,
            "incidents": app_state.connection_manager.incident_count,
        },
        total_incidents_stored=app_state.incident_buffer.count(),
    )
