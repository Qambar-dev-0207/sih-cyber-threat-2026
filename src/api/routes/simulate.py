"""
SIH26145 - Synthetic Threat Scenario Simulation Endpoint
Allows live presentation & judge replay of multi-stage attacks (APT, DDoS, C2, DNS Tunneling).
"""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException
from src.api.models import SimulationResponse
from src.api.services.pipeline_service import run_simulation_scenario
from src.api.state import AppState, get_app_state

logger = logging.getLogger("sih.api.simulate")
router = APIRouter(tags=["Attack Simulation"])

VALID_SCENARIOS = {
    "apt": "Multi-Stage APT Intrusion (Recon -> DGA -> JA4 CobaltStrike -> C2 -> Exfiltration)",
    "ddos": "Volumetric SYN Flood DDoS Storm (>45,000 PPS)",
    "c2": "Sliver / CobaltStrike C2 Periodic Heartbeat Beaconing",
    "dns_tunnel": "High-Entropy DGA DNS Exfiltration Tunneling",
    "dns": "High-Entropy DGA DNS Exfiltration Tunneling",
}


@router.post(
    "/simulate/{scenario}",
    response_model=SimulationResponse,
    summary="Trigger Synthetic Attack Scenario Replay",
    description="Injects synthetic security events for a chosen attack scenario through the live CEP aggregator and LangGraph triage state machine, saving results and broadcasting over WebSockets.",
)
async def trigger_attack_simulation(
    scenario: str,
    app_state: AppState = Depends(get_app_state),
) -> SimulationResponse:
    """Executes end-to-end detection, fusion, triage, and real-time broadcast for a synthetic scenario."""
    norm_scenario = scenario.strip().lower()
    if norm_scenario not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid simulation scenario '{scenario}'. Available scenarios: {list(VALID_SCENARIOS.keys())}",
        )

    try:
        sc_name, alert_count, incident_detail = await run_simulation_scenario(
            norm_scenario, app_state=app_state
        )

        return SimulationResponse(
            status="triggered",
            scenario=sc_name,
            incident_id=incident_detail.incident_id,
            alerts_count=alert_count,
            incident=incident_detail,
            message=f"Scenario '{sc_name}' ({VALID_SCENARIOS[norm_scenario]}) executed: {alert_count} alerts generated, fused into {incident_detail.incident_id} ({incident_detail.severity}, Risk: {incident_detail.risk_score:.1f}).",
        )
    except Exception as exc:
        logger.error(f"Simulation execution error for scenario '{scenario}': {exc}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to execute simulation scenario '{scenario}': {str(exc)}",
        )
