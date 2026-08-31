from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from src.agentic_triage.knowledge.mitre_catalog import lookup_mitre_techniques
from src.agentic_triage.state import MitreMapping, TriageStateDict
from src.agentic_triage.templates.narrative_templates import render_executive_narrative

logger = logging.getLogger("agentic_triage.classification_node")


class ClassificationNode:
    """Node 3: MITRE ATT&CK mapping, attack intent classification, and executive narrative generation."""

    def __init__(self, execution_mode: str = "deterministic", llm_client: Any = None):
        self.execution_mode = execution_mode
        self.llm_client = llm_client

    def __call__(self, state: TriageStateDict) -> TriageStateDict:
        return self.execute(state)

    def execute(self, state: TriageStateDict) -> TriageStateDict:
        threat_classes = state.get("threat_classes_observed", [])
        if not threat_classes:
            pt = state.get("primary_threat_class")
            if pt:
                threat_classes = [pt]

        # 1. MITRE ATT&CK Technique Lookup
        mitre_objs: List[MitreMapping] = lookup_mitre_techniques(threat_classes)
        mitre_dicts = [m.model_dump() for m in mitre_objs]
        state["mitre_mappings"] = mitre_dicts

        # 2. Attack Intent Classification
        primary_intent, primary_tech, primary_tactic, primary_phase = self._classify_intent(
            threat_classes, mitre_objs
        )

        state["primary_threat_class"] = primary_intent
        state["primary_mitre_technique"] = primary_tech
        state["primary_mitre_tactic"] = primary_tactic
        state["kill_chain_phase"] = primary_phase

        # 3. Executive Attack Narrative Generation
        narrative = self._generate_narrative(state)
        state["attack_narrative"] = narrative

        return state

    def _classify_intent(
        self, threat_classes: List[str], mitre_mappings: List[MitreMapping]
    ) -> tuple[str, str, str, str]:
        upper_threats = {t.upper() for t in threat_classes}

        has_recon = bool(upper_threats.intersection({"PORT_SCAN_RECON", "PORT_SCAN", "RECON_SWEEP"}))
        has_dga = bool(upper_threats.intersection({"DGA_TUNNELLING", "DGA_LSTM"}))
        has_malware = bool(upper_threats.intersection({"ENCRYPTED_MALWARE", "JA4_MALWARE"}))
        has_c2 = bool(upper_threats.intersection({"C2_BEACONING", "C2_BEACON"}))
        has_exfil = bool(upper_threats.intersection({"DATA_EXFILTRATION", "EXFIL_RATIO"}))
        has_ddos = bool(upper_threats.intersection({"VOLUMETRIC_DDOS", "PROTOCOL_DDOS", "DDOS_ENTROPY"}))

        primary_tech = mitre_mappings[0].technique_id if mitre_mappings else "T1595"
        primary_tactic = mitre_mappings[0].tactic_name if mitre_mappings else "Reconnaissance"
        primary_phase = mitre_mappings[0].kill_chain_phase if mitre_mappings else "Reconnaissance"

        if (has_recon or has_dga) and (has_malware or has_c2) and has_exfil:
            return "MULTI_STAGE_APT_INTRUSION", primary_tech, "Command and Control", "Multi-Stage APT"
        elif len(upper_threats) >= 3:
            return "MULTI_STAGE_APT_INTRUSION", primary_tech, "Command and Control", "Multi-Stage APT"
        elif (has_c2 or has_malware) and has_exfil:
            return "C2_DATA_EXFILTRATION_CAMPAIGN", "T1048.002", "Exfiltration", "Actions on Objectives"
        elif has_c2 or has_malware or has_dga:
            return "MALWARE_COMMAND_AND_CONTROL", "T1071.001", "Command and Control", "Command and Control"
        elif has_ddos:
            return "DISTRIBUTED_DENIAL_OF_SERVICE", "T1498.001", "Impact", "Impact"
        elif has_recon:
            return "RECONNAISSANCE_SWEEP", "T1595.001", "Reconnaissance", "Reconnaissance"
        elif has_exfil:
            return "DATA_EXFILTRATION_ANOMALY", "T1048.002", "Exfiltration", "Actions on Objectives"

        if threat_classes:
            return threat_classes[0], primary_tech, primary_tactic, primary_phase
        return "SUSPICIOUS_NETWORK_ACTIVITY", "T1595", "Reconnaissance", "Reconnaissance"

    def _generate_narrative(self, state: TriageStateDict) -> str:
        # Default deterministic template rendering
        deterministic_narrative = render_executive_narrative(state)

        mode = state.get("execution_mode") or self.execution_mode
        if mode == "llm_enhanced" and self.llm_client is not None:
            try:
                # LLM Hook with strict timeout
                return self._invoke_llm(state, fallback=deterministic_narrative)
            except Exception as e:
                logger.warning("LLM generation failed or timed out: %s. Using deterministic narrative.", e)
                return deterministic_narrative

        return deterministic_narrative

    def _invoke_llm(self, state: TriageStateDict, fallback: str) -> str:
        prompt = (
            f"Generate a SOC-grade executive incident narrative for Incident {state.get('incident_id')}:\n"
            f"Source IP: {state.get('source_ip')} ({state.get('asset_role')})\n"
            f"Classification: {state.get('primary_threat_class')}\n"
            f"Risk Score: {state.get('risk_score')}/100 ({state.get('severity')})\n"
            f"Timeline: {len(state.get('timeline', []))} steps\n"
        )
        if hasattr(self.llm_client, "generate"):
            res = self.llm_client.generate(prompt)
            if res and isinstance(res, str) and len(res.strip()) > 50:
                return res.strip()
        elif hasattr(self.llm_client, "invoke"):
            res = self.llm_client.invoke(prompt)
            if hasattr(res, "content") and res.content:
                return str(res.content).strip()
            elif isinstance(res, str) and len(res.strip()) > 50:
                return res.strip()
        return fallback
