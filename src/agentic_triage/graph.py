from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional, Union
from langgraph.graph import END, START, StateGraph

from src.agentic_triage.nodes.classification_node import ClassificationNode
from src.agentic_triage.nodes.correlation_node import CorrelationNode
from src.agentic_triage.nodes.countermeasure_node import CountermeasureNode
from src.agentic_triage.nodes.handoff_node import HandoffNode
from src.agentic_triage.nodes.risk_scoring_node import RiskScoringNode
from src.agentic_triage.state import TriageStateDict


def build_triage_graph(
    db: Any = None,
    execution_mode: str = "deterministic",
    llm_client: Any = None,
) -> StateGraph:
    """Build the modular 5-node LangGraph StateGraph for incident triage."""
    builder = StateGraph(TriageStateDict)

    # Register Nodes
    builder.add_node("correlation", CorrelationNode(db=db))
    builder.add_node("risk_scoring", RiskScoringNode())
    builder.add_node("classification", ClassificationNode(execution_mode=execution_mode, llm_client=llm_client))
    builder.add_node("countermeasures", CountermeasureNode())
    builder.add_node("handoff", HandoffNode(db=db))

    # Wire Edges: START -> correlation -> risk_scoring -> classification -> countermeasures -> handoff -> END
    builder.add_edge(START, "correlation")
    builder.add_edge("correlation", "risk_scoring")
    builder.add_edge("risk_scoring", "classification")
    builder.add_edge("classification", "countermeasures")
    builder.add_edge("countermeasures", "handoff")
    builder.add_edge("handoff", END)

    return builder


def compile_triage_graph(
    db: Any = None,
    execution_mode: str = "deterministic",
    llm_client: Any = None,
) -> Any:
    """Compile the LangGraph triage engine into an executable Runnable graph."""
    builder = build_triage_graph(db=db, execution_mode=execution_mode, llm_client=llm_client)
    return builder.compile()


def triage_incident(
    incident_or_state: Union[Any, Dict[str, Any]],
    compiled_graph: Optional[Any] = None,
    db: Any = None,
    execution_mode: str = "deterministic",
    llm_client: Any = None,
) -> TriageStateDict:
    """Convenience entrypoint to triage a FusedIncident or initial state dictionary."""
    graph = compiled_graph or compile_triage_graph(
        db=db, execution_mode=execution_mode, llm_client=llm_client
    )

    now = time.time()
    initial_state: TriageStateDict = {}

    if isinstance(incident_or_state, dict):
        initial_state = dict(incident_or_state)
    elif hasattr(incident_or_state, "model_dump"):
        inc_data = incident_or_state.model_dump()
        initial_state = {
            "incident_id": inc_data.get("incident_id", f"INC-{uuid.uuid4().hex[:8].upper()}"),
            "incident": incident_or_state,
            "created_at": inc_data.get("created_at", now),
            "updated_at": inc_data.get("updated_at", now),
            "source_ip": inc_data.get("primary_source_ip", "0.0.0.0"),
            "subnet": inc_data.get("source_subnet", ""),
            "target_ips": inc_data.get("target_ips", []),
            "target_ports": inc_data.get("target_ports", []),
            "fused_alerts": inc_data.get("alerts", []) or inc_data.get("attack_timeline", []),
            "threat_classes_observed": inc_data.get("threat_classes", []),
            "primary_threat_class": inc_data.get("threat_class", "UNKNOWN"),
        }
    else:
        initial_state = {
            "incident_id": getattr(incident_or_state, "incident_id", f"INC-{uuid.uuid4().hex[:8].upper()}"),
            "incident": incident_or_state,
            "created_at": getattr(incident_or_state, "created_at", now),
            "updated_at": getattr(incident_or_state, "updated_at", now),
            "source_ip": getattr(incident_or_state, "primary_source_ip", "0.0.0.0"),
            "subnet": getattr(incident_or_state, "source_subnet", ""),
            "target_ips": getattr(incident_or_state, "target_ips", []),
            "target_ports": getattr(incident_or_state, "target_ports", []),
            "fused_alerts": getattr(incident_or_state, "alerts", []) or getattr(incident_or_state, "attack_timeline", []),
            "threat_classes_observed": getattr(incident_or_state, "threat_classes", []),
            "primary_threat_class": getattr(incident_or_state, "threat_class", "UNKNOWN"),
        }

    if "start_time" not in initial_state:
        initial_state["start_time"] = time.time()
    if "execution_mode" not in initial_state:
        initial_state["execution_mode"] = execution_mode

    return graph.invoke(initial_state)
