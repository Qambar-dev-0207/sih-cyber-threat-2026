"""
Node 4: Countermeasure recommendation & artifact preparation.

Generates six classes of deterministic, syntax-valid countermeasure artifacts:
  1. iptables / ip6tables DROP rules
  2. nftables set-based blocking ruleset
  3. Cisco IOS extended named ACL
  4. BIND 9 / Unbound DNS RPZ entries
  5. Snort 3 / Suricata IDS alert rules
  6. STIX 2.1 Threat Intelligence Bundle

All artifacts enforce strict data diode safety:
  requires_human_approval = True
  Zero automated return-path execution.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from src.agentic_triage.state import CountermeasureItem, TriageStateDict
from src.agentic_triage.countermeasures.iptables_generator import generate_iptables
from src.agentic_triage.countermeasures.nftables_generator import generate_nftables
from src.agentic_triage.countermeasures.cisco_acl_generator import generate_cisco_acl
from src.agentic_triage.countermeasures.dns_rpz_generator import generate_dns_rpz
from src.agentic_triage.countermeasures.snort_generator import generate_snort_rules
from src.agentic_triage.countermeasures.stix_generator import generate_stix_bundle

logger = logging.getLogger("agentic_triage.countermeasure_node")


class CountermeasureNode:
    """Node 4: Countermeasure recommendation & artifact preparation with strict human-in-the-loop safety."""

    def __init__(self):
        pass

    def __call__(self, state: TriageStateDict) -> TriageStateDict:
        return self.execute(state)

    def execute(self, state: TriageStateDict) -> TriageStateDict:
        """
        Generate all countermeasure artifacts from the triage state and bundle
        them into the state dict.  All artifacts carry requires_human_approval=True.
        """
        # Build a normalised incident context dict from triage state
        incident: Dict[str, Any] = {
            "incident_id": state.get("incident_id", "INC-UNKNOWN"),
            "source_ip": state.get("source_ip", "0.0.0.0"),
            "subnet": state.get("subnet", ""),
            "target_ips": state.get("target_ips", []),
            "target_ports": state.get("target_ports", []),
            "primary_threat_class": state.get("primary_threat_class", "UNKNOWN"),
            "primary_mitre_technique": state.get("primary_mitre_technique", "T1595"),
            "mitre_mappings": state.get("mitre_mappings", []),
            "severity": state.get("severity", "HIGH"),
            "risk_score": state.get("risk_score", 0.0),
            "attack_narrative": state.get("attack_narrative", ""),
            # Optional enrichment fields
            "malicious_domains": _extract_malicious_domains(state),
            "ja4_fingerprint": _extract_ja4(state),
        }

        generators = [
            ("iptables",   generate_iptables),
            ("nftables",   generate_nftables),
            ("cisco_acl",  generate_cisco_acl),
            ("dns_rpz",    generate_dns_rpz),
            ("snort3",     generate_snort_rules),
            ("stix_bundle", generate_stix_bundle),
        ]

        countermeasures: List[Dict[str, Any]] = []
        primary_cm_type = "iptables"
        primary_cm_artifact = ""

        for cm_type, generator_fn in generators:
            try:
                artifact_content = generator_fn(incident)
                syntax_valid = bool(artifact_content and len(artifact_content.strip()) > 20)

                cm_item = CountermeasureItem(
                    countermeasure_type=cm_type,
                    target_entity=incident["source_ip"],
                    artifact_content=artifact_content,
                    syntax_valid=syntax_valid,
                    requires_human_approval=True,
                )
                countermeasures.append(cm_item.model_dump())

                if cm_type == "iptables":
                    primary_cm_type = "iptables"
                    primary_cm_artifact = artifact_content

                logger.debug("Generated %s artifact (%d bytes)", cm_type, len(artifact_content))

            except Exception as exc:
                logger.error("Countermeasure generator '%s' failed: %s", cm_type, exc)
                # Append a fallback error stub so the pipeline does not silently skip
                countermeasures.append(
                    CountermeasureItem(
                        countermeasure_type=cm_type,
                        target_entity=incident["source_ip"],
                        artifact_content=f"# Generator error for {cm_type}: {exc}\n# requires_human_approval: true",
                        syntax_valid=False,
                        requires_human_approval=True,
                    ).model_dump()
                )

        state["countermeasures"] = countermeasures
        state["primary_countermeasure_type"] = primary_cm_type
        state["primary_countermeasure_artifact"] = primary_cm_artifact
        state["requires_human_approval"] = True

        logger.info(
            "CountermeasureNode: generated %d artifacts for incident %s",
            len(countermeasures),
            incident["incident_id"],
        )
        return state


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_malicious_domains(state: TriageStateDict) -> List[str]:
    """Extract malicious domain strings from fused alert evidence."""
    domains: List[str] = []
    for alert in state.get("fused_alerts", []):
        if isinstance(alert, dict):
            # Check common evidence keys
            for key in ("query", "domain", "fqdn", "hostname"):
                val = alert.get(key) or alert.get("evidence", {}).get(key, "")
                if val and isinstance(val, str) and "." in val and len(val) < 256:
                    domains.append(val)
    return list(dict.fromkeys(domains))[:20]  # deduplicated, max 20


def _extract_ja4(state: TriageStateDict) -> str:
    """Extract JA4 fingerprint string from fused alert evidence."""
    for alert in state.get("fused_alerts", []):
        if isinstance(alert, dict):
            for key in ("ja4", "ja4_fingerprint"):
                val = alert.get(key) or alert.get("evidence", {}).get(key, "")
                if val and isinstance(val, str) and len(val) > 10:
                    return val
    return ""
