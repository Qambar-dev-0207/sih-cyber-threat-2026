"""
SIH26145 - Telemetry & Ingest Metrics REST Endpoint
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from src.api.models import MetricsResponse
from src.api.services.telemetry_service import generate_instantaneous_telemetry
from src.api.state import AppState, get_app_state

router = APIRouter(tags=["Metrics & Telemetry"])


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Line-Rate Telemetry Metrics",
    description="Returns current instantaneous pipeline throughput (EPS, Mbps, PPS, loss %, latency percentiles).",
)
async def get_current_metrics(
    app_state: AppState = Depends(get_app_state),
) -> MetricsResponse:
    """Returns instantaneous line-rate throughput and latency percentiles."""
    telemetry = generate_instantaneous_telemetry(app_state)

    return MetricsResponse(
        timestamp=telemetry.timestamp,
        events_per_second=telemetry.events_per_second,
        megabits_per_second=telemetry.megabits_per_second,
        packets_per_second=telemetry.packets_per_second,
        packet_drop_rate=telemetry.packet_drop_rate,
        packet_loss_pct=telemetry.packet_loss_pct,
        latency_p50_ms=telemetry.latency_p50_ms,
        latency_p90_ms=telemetry.latency_p90_ms,
        latency_p99_ms=telemetry.latency_p99_ms,
        active_flows=telemetry.active_flows,
        buffer_utilization_pct=telemetry.buffer_utilization_pct,
    )
