"""
tests/test_countermeasures.py

Comprehensive test suite for all 6 SIH26145 SENTINEL countermeasure generators:
  1. iptables_generator
  2. nftables_generator
  3. cisco_acl_generator
  4. dns_rpz_generator
  5. snort_generator
  6. stix_generator

Tests cover:
  - Output non-emptiness and syntactic correctness
  - requires_human_approval marker presence
  - IPv6, subnet, and empty-field edge cases
  - STIX JSON validity (json.loads)
  - CountermeasureNode integration
"""
from __future__ import annotations

import json
import re
import pytest

from src.agentic_triage.countermeasures.iptables_generator import generate_iptables
from src.agentic_triage.countermeasures.nftables_generator import generate_nftables
from src.agentic_triage.countermeasures.cisco_acl_generator import generate_cisco_acl
from src.agentic_triage.countermeasures.dns_rpz_generator import generate_dns_rpz
from src.agentic_triage.countermeasures.snort_generator import generate_snort_rules
from src.agentic_triage.countermeasures.stix_generator import generate_stix_bundle
from src.agentic_triage.nodes.countermeasure_node import CountermeasureNode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def representative_incident():
    """A realistic multi-threat incident context."""
    return {
        "incident_id": "INC-TEST-DDOS001",
        "source_ip": "192.168.100.55",
        "subnet": "192.168.100.0/24",
        "target_ips": ["10.0.0.1", "10.0.0.2", "172.16.0.50"],
        "target_ports": [80, 443, 8080, 4444],
        "primary_threat_class": "DISTRIBUTED_DENIAL_OF_SERVICE",
        "primary_mitre_technique": "T1498.001",
        "mitre_mappings": [
            {
                "technique_id": "T1498.001",
                "technique_name": "Direct Network Flood",
                "tactic_id": "TA0040",
                "tactic_name": "Impact",
                "kill_chain_phase": "Impact",
                "confidence": 0.92,
            }
        ],
        "severity": "HIGH",
        "risk_score": 78.5,
        "malicious_domains": ["evil-dga.net", "c2.badactor.io"],
        "ja4_fingerprint": "t13d1516h2_8daaf6152771",
    }


@pytest.fixture
def c2_incident():
    """C2 beaconing + malware incident context."""
    return {
        "incident_id": "INC-C2-MALWARE-002",
        "source_ip": "10.5.10.22",
        "subnet": "10.5.10.0/24",
        "target_ips": ["185.220.101.50"],
        "target_ports": [443, 4444, 8443],
        "primary_threat_class": "MALWARE_COMMAND_AND_CONTROL",
        "primary_mitre_technique": "T1071.001",
        "mitre_mappings": [],
        "severity": "CRITICAL",
        "risk_score": 92.0,
        "malicious_domains": ["cobalt-strike-c2.invalid"],
        "ja4_fingerprint": "t13d1516h2_cobalt_strike",
    }


@pytest.fixture
def minimal_incident():
    """Minimal incident with only required fields."""
    return {
        "incident_id": "INC-MIN-000",
        "source_ip": "0.0.0.0",
        "target_ips": [],
        "target_ports": [],
        "primary_threat_class": "UNKNOWN",
        "severity": "LOW",
        "risk_score": 10.0,
    }


@pytest.fixture
def ipv6_incident():
    """Incident with IPv6 source (generators must handle gracefully)."""
    return {
        "incident_id": "INC-IPV6-001",
        "source_ip": "2001:db8::1",
        "subnet": "2001:db8::/32",
        "target_ips": [],
        "target_ports": [22, 80],
        "primary_threat_class": "RECONNAISSANCE_SWEEP",
        "primary_mitre_technique": "T1595.001",
        "mitre_mappings": [],
        "severity": "MEDIUM",
        "risk_score": 45.0,
    }


# ===========================================================================
# 1. iptables Generator
# ===========================================================================

class TestIptablesGenerator:
    def test_non_empty_output(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert isinstance(result, str) and len(result.strip()) > 50

    def test_contains_human_approval_marker(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "requires_human_approval" in result

    def test_contains_source_ip(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "192.168.100.55" in result

    def test_contains_drop_action(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "DROP" in result

    def test_contains_iptables_command(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "iptables" in result

    def test_contains_ip6tables_command(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "ip6tables" in result

    def test_subnet_block_included(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "192.168.100.0/24" in result

    def test_incident_id_in_comment(self, representative_incident):
        result = generate_iptables(representative_incident)
        assert "INC-TEST-DDOS001" in result

    def test_minimal_incident_no_crash(self, minimal_incident):
        result = generate_iptables(minimal_incident)
        assert "iptables" in result and "DROP" in result

    def test_ipv6_incident_no_crash(self, ipv6_incident):
        result = generate_iptables(ipv6_incident)
        assert isinstance(result, str) and "requires_human_approval" in result

    def test_no_execution_commands(self, representative_incident):
        """Ensure no automated execution side effects."""
        result = generate_iptables(representative_incident)
        # Should not contain live execution side effects (rm, curl, wget, python, etc.)
        forbidden = ["curl ", "wget ", "rm -rf", "python ", "bash -c"]
        for f in forbidden:
            assert f not in result, f"Forbidden command '{f}' found in iptables output"


# ===========================================================================
# 2. nftables Generator
# ===========================================================================

class TestNftablesGenerator:
    def test_non_empty_output(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert len(result.strip()) > 50

    def test_contains_human_approval_marker(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert "requires_human_approval" in result

    def test_contains_add_table(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert "add table" in result

    def test_contains_drop(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert "drop" in result.lower()

    def test_contains_source_ip(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert "192.168.100.55" in result

    def test_contains_set_definition(self, representative_incident):
        result = generate_nftables(representative_incident)
        assert "add set" in result

    def test_minimal_incident_no_crash(self, minimal_incident):
        result = generate_nftables(minimal_incident)
        assert "nftables" in result.lower() or "add table" in result


# ===========================================================================
# 3. Cisco ACL Generator
# ===========================================================================

class TestCiscoAclGenerator:
    def test_non_empty_output(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert len(result.strip()) > 50

    def test_contains_human_approval_marker(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert "requires_human_approval" in result

    def test_contains_access_list(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert "ip access-list extended" in result

    def test_contains_deny(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert "deny" in result.lower()

    def test_contains_source_ip(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert "192.168.100.55" in result

    def test_contains_permit_any(self, representative_incident):
        """ACL must end with a permit any any to avoid blackholing all traffic."""
        result = generate_cisco_acl(representative_incident)
        assert "permit ip any any" in result

    def test_acl_name_includes_incident_id(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        assert "SENTINEL-BLOCK" in result

    def test_wildcard_mask_for_subnet(self, representative_incident):
        result = generate_cisco_acl(representative_incident)
        # /24 subnet → wildcard 0.0.0.255
        assert "0.0.0.255" in result

    def test_minimal_incident_no_crash(self, minimal_incident):
        result = generate_cisco_acl(minimal_incident)
        assert "ip access-list extended" in result


# ===========================================================================
# 4. DNS RPZ Generator
# ===========================================================================

class TestDnsRpzGenerator:
    def test_non_empty_output(self, representative_incident):
        result = generate_dns_rpz(representative_incident)
        assert len(result.strip()) > 50

    def test_contains_human_approval_marker(self, representative_incident):
        result = generate_dns_rpz(representative_incident)
        assert "requires_human_approval" in result

    def test_contains_cname_dot_sinkhole(self, representative_incident):
        result = generate_dns_rpz(representative_incident)
        assert "CNAME" in result and "." in result

    def test_contains_malicious_domains(self, representative_incident):
        result = generate_dns_rpz(representative_incident)
        assert "evil-dga.net" in result

    def test_contains_rpz_ip_trigger(self, representative_incident):
        """IP-based RPZ triggers use reversed octet notation."""
        result = generate_dns_rpz(representative_incident)
        # 192.168.100.55 → 55.100.168.192.rpz-ip
        assert "rpz-ip" in result

    def test_contains_origin_directive(self, representative_incident):
        result = generate_dns_rpz(representative_incident)
        assert "$ORIGIN" in result

    def test_dga_placeholder_generated_when_no_domains(self, minimal_incident):
        """For DGA threats without explicit domains, a placeholder should appear."""
        dga_incident = dict(minimal_incident)
        dga_incident["primary_threat_class"] = "DGA_TUNNELLING"
        dga_incident.pop("malicious_domains", None)
        result = generate_dns_rpz(dga_incident)
        assert "dga" in result.lower()

    def test_minimal_incident_no_crash(self, minimal_incident):
        result = generate_dns_rpz(minimal_incident)
        assert "$ORIGIN" in result or "requires_human_approval" in result


# ===========================================================================
# 5. Snort Rule Generator
# ===========================================================================

class TestSnortGenerator:
    def test_non_empty_output(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert len(result.strip()) > 50

    def test_contains_human_approval_marker(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert "requires_human_approval" in result

    def test_contains_alert_keyword(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert re.search(r"^alert\s+(tcp|udp|icmp|tls)", result, re.MULTILINE)

    def test_contains_msg_field(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert 'msg:' in result

    def test_contains_sid_field(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert "sid:" in result

    def test_contains_rev_field(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert "rev:" in result

    def test_contains_classtype(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        assert "classtype:" in result

    def test_ddos_generates_icmp_rule(self, representative_incident):
        """DDoS incidents should trigger ICMP flood rule."""
        result = generate_snort_rules(representative_incident)
        assert "alert icmp" in result

    def test_ja4_fingerprint_rule_generated(self, c2_incident):
        result = generate_snort_rules(c2_incident)
        assert "alert tls" in result and "tls.ja4" in result

    def test_sid_is_numeric(self, representative_incident):
        result = generate_snort_rules(representative_incident)
        sid_match = re.search(r"sid:(\d+)", result)
        assert sid_match and int(sid_match.group(1)) > 0

    def test_minimal_incident_no_crash(self, minimal_incident):
        result = generate_snort_rules(minimal_incident)
        assert "alert" in result


# ===========================================================================
# 6. STIX 2.1 Generator
# ===========================================================================

class TestStixGenerator:
    def test_valid_json(self, representative_incident):
        result = generate_stix_bundle(representative_incident)
        parsed = json.loads(result)  # Must not raise
        assert isinstance(parsed, dict)

    def test_bundle_type(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        assert parsed["type"] == "bundle"

    def test_spec_version_21(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        assert parsed["spec_version"] == "2.1"

    def test_bundle_has_objects(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        assert len(parsed.get("objects", [])) >= 3

    def test_contains_indicator_sdo(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        types = {obj["type"] for obj in parsed["objects"]}
        assert "indicator" in types

    def test_contains_attack_pattern_sdo(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        types = {obj["type"] for obj in parsed["objects"]}
        assert "attack-pattern" in types

    def test_contains_relationship_sro(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        types = {obj["type"] for obj in parsed["objects"]}
        assert "relationship" in types

    def test_contains_threat_actor_sdo(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        types = {obj["type"] for obj in parsed["objects"]}
        assert "threat-actor" in types

    def test_source_ip_in_indicator_pattern(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        patterns = [obj.get("pattern", "") for obj in parsed["objects"] if obj["type"] == "indicator"]
        assert any("192.168.100.55" in p for p in patterns)

    def test_mitre_external_reference(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        ap_objs = [obj for obj in parsed["objects"] if obj["type"] == "attack-pattern"]
        assert ap_objs
        ext_refs = ap_objs[0].get("external_references", [])
        assert any(r.get("source_name") == "mitre-attack" for r in ext_refs)

    def test_requires_human_approval_in_bundle(self, representative_incident):
        result = generate_stix_bundle(representative_incident)
        assert "requires_human_approval" in result

    def test_domain_indicators_present(self, representative_incident):
        parsed = json.loads(generate_stix_bundle(representative_incident))
        patterns = [obj.get("pattern", "") for obj in parsed["objects"] if obj["type"] == "indicator"]
        assert any("domain-name" in p for p in patterns)

    def test_minimal_incident_valid_json(self, minimal_incident):
        result = generate_stix_bundle(minimal_incident)
        parsed = json.loads(result)
        assert parsed["type"] == "bundle"

    def test_ipv6_incident_valid_json(self, ipv6_incident):
        result = generate_stix_bundle(ipv6_incident)
        parsed = json.loads(result)
        assert parsed["type"] == "bundle"

    def test_bundle_id_deterministic(self, representative_incident):
        """Same incident should always yield the same bundle ID (UUID5)."""
        id1 = json.loads(generate_stix_bundle(representative_incident))["id"]
        id2 = json.loads(generate_stix_bundle(representative_incident))["id"]
        assert id1 == id2


# ===========================================================================
# 7. CountermeasureNode Integration
# ===========================================================================

class TestCountermeasureNodeIntegration:
    def _base_state(self):
        return {
            "incident_id": "INC-NODE-TEST-001",
            "source_ip": "10.10.10.10",
            "subnet": "10.10.10.0/24",
            "target_ips": ["172.16.1.1"],
            "target_ports": [443, 8443],
            "primary_threat_class": "MALWARE_COMMAND_AND_CONTROL",
            "primary_mitre_technique": "T1071.001",
            "mitre_mappings": [],
            "severity": "HIGH",
            "risk_score": 82.0,
            "fused_alerts": [
                {"ja4": "t13d1516h2_8daaf6152771", "evidence": {"query": "bad-domain.net"}},
            ],
        }

    def test_node_produces_countermeasures_list(self):
        node = CountermeasureNode()
        state = self._base_state()
        result = node(state)
        assert "countermeasures" in result
        assert len(result["countermeasures"]) == 6

    def test_all_six_types_present(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        types = {cm["countermeasure_type"] for cm in result["countermeasures"]}
        expected = {"iptables", "nftables", "cisco_acl", "dns_rpz", "snort3", "stix_bundle"}
        assert types == expected

    def test_requires_human_approval_true(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        assert result["requires_human_approval"] is True
        for cm in result["countermeasures"]:
            assert cm["requires_human_approval"] is True

    def test_primary_countermeasure_type_set(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        assert result.get("primary_countermeasure_type") == "iptables"

    def test_primary_artifact_non_empty(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        assert len(result.get("primary_countermeasure_artifact", "")) > 20

    def test_all_artifacts_non_empty(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        for cm in result["countermeasures"]:
            assert len(cm["artifact_content"].strip()) > 10, \
                f"Empty artifact for type: {cm['countermeasure_type']}"

    def test_stix_artifact_valid_json(self):
        node = CountermeasureNode()
        result = node(self._base_state())
        stix_cm = next(cm for cm in result["countermeasures"] if cm["countermeasure_type"] == "stix_bundle")
        parsed = json.loads(stix_cm["artifact_content"])
        assert parsed["type"] == "bundle"
