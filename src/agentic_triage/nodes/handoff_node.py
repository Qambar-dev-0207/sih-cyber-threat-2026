from __future__ import annotations

import logging
import time
from typing import Any, Dict
from src.agentic_triage.state import TriageStateDict

logger = logging.getLogger("agentic_triage.handoff_node")


class HandoffNode:
    """Node 5: Storage persistence, out-of-band handoff, and latency recording."""

    def __init__(self, db: Any = None):
        self.db = db

    def __call__(self, state: TriageStateDict) -> TriageStateDict:
        return self.execute(state)

    def execute(self, state: TriageStateDict) -> TriageStateDict:
        start_t = state.get("start_time") or time.time()
        elapsed_ms = max(0.1, (time.time() - start_t) * 1000.0)

        state["execution_latency_ms"] = round(elapsed_ms, 2)
        state["status"] = "PENDING_REVIEW"
        state["requires_human_approval"] = True

        incident_id = state.get("incident_id")
        persisted = False

        if self.db is not None and incident_id:
            try:
                # Save or update incident in storage if method exists
                if hasattr(self.db, "upsert_incident"):
                    self.db.upsert_incident(
                        incident_id=incident_id,
                        created_at=state.get("created_at"),
                        primary_source_ip=state.get("source_ip"),
                        target_ips=state.get("target_ips", []),
                        threat_class=state.get("primary_threat_class"),
                        overall_risk_score=state.get("risk_score"),
                        severity=state.get("severity"),
                        mitre_technique=state.get("primary_mitre_technique"),
                        mitre_tactic=state.get("primary_mitre_tactic"),
                        kill_chain_phase=state.get("kill_chain_phase"),
                        attack_narrative=state.get("attack_narrative"),
                        risk_breakdown=state.get("risk_breakdown"),
                        countermeasure_type=state.get("primary_countermeasure_type"),
                        countermeasure_artifact=state.get("primary_countermeasure_artifact"),
                        requires_human_approval=True,
                        status="PENDING_REVIEW",
                    )
                    persisted = True
                elif hasattr(self.db, "save_incident"):
                    self.db.save_incident(state)
                    persisted = True
            except Exception as e:
                logger.warning("Failed to persist incident %s to database: %s", incident_id, e)
                if "errors" not in state:
                    state["errors"] = []
                state["errors"].append(str(e))

        state["db_persisted"] = persisted
        state["persisted_id"] = incident_id or ""
        state["out_of_band_dispatched"] = False

        return state
