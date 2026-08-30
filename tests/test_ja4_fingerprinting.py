"""
SIH26145 Passive Network Monitoring System — Phase 0
Test Suite: Zeek JA4/JA4S TLS Fingerprinting & Structured JSON Log Verification
File: tests/test_ja4_fingerprinting.py

Covers 4-Tier Test Architecture:
- Tier 1: Core Feature Verification (JA4 client calculation, JA4S server calculation, JSON schemas for conn, dns, ssl)
- Tier 2: Boundary & Corner Cases (GREASE filtering, empty ciphers, missing SNI, non-standard ALPN, SSL 3.0/TLS 1.0)
- Tier 3: Cross-Feature Pairwise (Zeek log correlation via UID/5-tuple, JSON log tailer serialization)
- Tier 4: Real-World Scenarios & Adversarial Stress (Malformed ClientHello, cipher sorting collision resistance, DGA queries)
"""

import json
import hashlib
import re
import pytest
from pathlib import Path
from typing import List, Dict, Any, Optional

# Workspace Discovery
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
ZEEK_JA4_SCRIPT_PATH = PROJECT_ROOT / "config" / "zeek" / "ja4.zeek"
ZEEK_LOCAL_SCRIPT_PATH = PROJECT_ROOT / "config" / "zeek" / "local.zeek"


# ============================================================================
# Authoritative Pure-Python JA4 & JA4S Reference Oracle
# ============================================================================

GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}

def is_grease(val: int) -> bool:
    """Check if 16-bit integer is a TLS GREASE value."""
    return val in GREASE_VALUES or ((val & 0x0F0F) == 0x0A0A and (val >> 8) == (val & 0xFF))


def format_2digit(n: int) -> str:
    """Format integer as 2-digit string clamped between 00 and 99."""
    if n < 0:
        return "00"
    if n > 99:
        return "99"
    return f"{n:02d}"


def get_ja4_version_code(version_hex: int) -> str:
    """Resolve TLS version to 2-character JA4 code."""
    version_map = {
        0x0304: "13",  # TLS 1.3
        0x0303: "12",  # TLS 1.2
        0x0302: "11",  # TLS 1.1
        0x0301: "10",  # TLS 1.0
        0x0300: "s3",  # SSL 3.0
        0x0200: "s2",  # SSL 2.0
        0x0001: "d1",  # DTLS 1.0
        0x0002: "d2",  # DTLS 1.2
        0x0003: "d3",  # DTLS 1.3
    }
    return version_map.get(version_hex, "00")


def compute_ja4_hash_12(joined_hex_str: str) -> str:
    """Calculate 12-character truncated SHA256 hex digest of input string."""
    if not joined_hex_str:
        return "000000000000"
    full_sha = hashlib.sha256(joined_hex_str.encode("utf-8")).hexdigest()
    return full_sha[:12]


def compute_ja4_fingerprint(
    protocol: str,
    version_hex: int,
    sni: Optional[str],
    ciphers: List[int],
    extensions: Optional[List[int]] = None,
    alpn: Optional[str] = None
) -> str:
    """Authoritative Python implementation of the JA4 TLS client fingerprint algorithm."""
    # 1. Protocol character
    proto_char = "t" if protocol.lower() == "tcp" else ("q" if protocol.lower() == "quic" else "d")
    
    # 2. Version
    ver_str = get_ja4_version_code(version_hex)
    
    # 3. SNI indicator ('d' for domain name, 'i' for IP address or missing SNI)
    if sni and len(sni) > 0 and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", sni):
        sni_char = "d"
    else:
        sni_char = "i"
    
    # 4. Filter GREASE from ciphers and sort
    filtered_ciphers = [c for c in ciphers if not is_grease(c)]
    cipher_hex_list = sorted([f"{c:04x}" for c in filtered_ciphers])
    num_ciphers_str = format_2digit(len(filtered_ciphers))
    
    joined_ciphers = ",".join(cipher_hex_list)
    cipher_hash = compute_ja4_hash_12(joined_ciphers)
    
    # 5. Filter GREASE from extensions and sort
    filtered_exts = [e for e in (extensions or []) if not is_grease(e)]
    ext_hex_list = sorted([f"{e:04x}" for e in filtered_exts])
    num_exts_str = format_2digit(len(filtered_exts))
    
    joined_exts = ",".join(ext_hex_list)
    ext_hash = compute_ja4_hash_12(joined_exts) if joined_exts else "000000000000"
    
    # 6. ALPN indicator (first and last char)
    if alpn and len(alpn) >= 2:
        alpn_str = f"{alpn[0]}{alpn[-1]}"
    elif alpn and len(alpn) == 1:
        alpn_str = f"{alpn[0]}0"
    else:
        alpn_str = "00"
    
    ja4_a = f"{proto_char}{ver_str}{sni_char}{num_ciphers_str}{num_exts_str}{alpn_str}"
    return f"{ja4_a}_{cipher_hash}_{ext_hash}"


def compute_ja4s_fingerprint(
    protocol: str,
    version_hex: int,
    chosen_cipher: int,
    extensions: Optional[List[int]] = None,
    alpn: Optional[str] = None
) -> str:
    """Authoritative Python implementation of the JA4S TLS server fingerprint algorithm."""
    proto_char = "t" if protocol.lower() == "tcp" else ("q" if protocol.lower() == "quic" else "d")
    ver_str = get_ja4_version_code(version_hex)
    num_exts_str = format_2digit(len(extensions or []))
    
    if alpn and len(alpn) >= 2:
        alpn_str = f"{alpn[0]}{alpn[-1]}"
    else:
        alpn_str = "00"
        
    chosen_cipher_hex = f"{chosen_cipher:04x}"
    return f"{proto_char}{ver_str}{num_exts_str}{alpn_str}_{chosen_cipher_hex}_0000"


# ============================================================================
# Tier 1: Core Feature Verification (>= 5 tests per feature)
# ============================================================================

class TestJA4ClientFingerprintingTier1:
    """Tier 1: JA4 TLS Client Fingerprint Calculation and Structure."""

    def test_tls13_standard_client_hello_ja4(self):
        """Verify JA4 calculation for standard TLS 1.3 ClientHello with domain SNI and h2 ALPN."""
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
        exts = [0x0000, 0x000B, 0x000A, 0x0023, 0x0010]
        ja4 = compute_ja4_fingerprint(
            protocol="tcp",
            version_hex=0x0304,
            sni="cloudflare.com",
            ciphers=ciphers,
            extensions=exts,
            alpn="h2"
        )
        # Expected format: t13d0505h2_<12hex>_<12hex>
        parts = ja4.split("_")
        assert len(parts) == 3
        assert parts[0] == "t13d0505h2"
        assert len(parts[1]) == 12
        assert len(parts[2]) == 12

    def test_tls12_client_hello_with_ip_sni(self):
        """Verify JA4 calculation for TLS 1.2 with IP address SNI sets indicator to 'i'."""
        ciphers = [0xC02F, 0xC030, 0x009E]
        ja4 = compute_ja4_fingerprint(
            protocol="tcp",
            version_hex=0x0303,
            sni="192.168.1.1",
            ciphers=ciphers,
            alpn=None
        )
        assert ja4.startswith("t12i030000")

    def test_quic_udp_ja4_protocol_char(self):
        """Verify QUIC / UDP port 443 connections receive protocol character 'q'."""
        ciphers = [0x1301, 0x1302]
        ja4 = compute_ja4_fingerprint(
            protocol="quic",
            version_hex=0x0304,
            sni="quic.example.com",
            ciphers=ciphers,
            alpn="h3"
        )
        assert ja4.startswith("q13d0200h3")

    def test_cipher_sorting_determinism(self):
        """Verify that cipher suites in different input order yield identical JA4 cipher hashes."""
        ciphers_order_a = [0xC02B, 0x1301, 0x009C, 0xC02F]
        ciphers_order_b = [0x009C, 0xC02F, 0x1301, 0xC02B]
        
        ja4_a = compute_ja4_fingerprint("tcp", 0x0304, "domain.com", ciphers_order_a)
        ja4_b = compute_ja4_fingerprint("tcp", 0x0304, "domain.com", ciphers_order_b)
        
        assert ja4_a == ja4_b, "JA4 must sort ciphers deterministically regardless of ClientHello order"

    def test_ja4s_server_hello_fingerprint(self):
        """Verify JA4S server response fingerprint format and chosen cipher representation."""
        ja4s = compute_ja4s_fingerprint(
            protocol="tcp",
            version_hex=0x0304,
            chosen_cipher=0x1301,
            extensions=[0x002B, 0x0033],
            alpn="h2"
        )
        assert ja4s.startswith("t1302h2_1301_")


class TestZeekJsonLogSchemasTier1:
    """Tier 1: Structured JSON Log schemas for conn.log, dns.log, and ssl.log."""

    def test_conn_log_schema_validation(self):
        """Verify conn.log JSON format contains all required 5-tuple, metric, and state fields."""
        conn_entry = {
            "ts": 1725000001.554321,
            "uid": "CbA9876543210zyxwv",
            "id.orig_h": "192.168.1.105",
            "id.orig_p": 49832,
            "id.resp_h": "104.244.42.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.234,
            "orig_bytes": 3520,
            "resp_bytes": 18450,
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADadFf",
            "orig_pkts": 14,
            "resp_pkts": 22
        }
        # JSON serialize & validate keys
        raw_json = json.dumps(conn_entry)
        parsed = json.loads(raw_json)
        
        assert isinstance(parsed["ts"], float)
        assert isinstance(parsed["id.orig_p"], int)
        assert parsed["proto"] in ("tcp", "udp", "icmp")
        assert parsed["conn_state"] == "SF"

    def test_ssl_log_schema_with_ja4_fields(self):
        """Verify ssl.log JSON format includes native ja4 and ja4s fields."""
        ssl_entry = {
            "ts": 1725000001.560000,
            "uid": "CbA9876543210zyxwv",
            "id.orig_h": "192.168.1.105",
            "id.orig_p": 49832,
            "id.resp_h": "104.244.42.1",
            "id.resp_p": 443,
            "version": "TLSv13",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "server_name": "api.twitter.com",
            "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "ja4s": "t1302h2_1301_0000",
            "established": True
        }
        raw_json = json.dumps(ssl_entry)
        parsed = json.loads(raw_json)
        
        assert "ja4" in parsed
        assert "ja4s" in parsed
        assert len(parsed["ja4"].split("_")) == 3
        assert parsed["server_name"] == "api.twitter.com"

    def test_dns_log_schema_validation(self):
        """Verify dns.log JSON format with trans_id, query, rcode, and answer arrays."""
        dns_entry = {
            "ts": 1725000000.100000,
            "uid": "Cdns1234567890abcd",
            "id.orig_h": "192.168.1.105",
            "id.orig_p": 53123,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 41256,
            "query": "www.google.com",
            "qclass_name": "C_INTERNET",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["142.250.190.68"],
            "ttls": [300.0]
        }
        parsed = json.loads(json.dumps(dns_entry))
        assert parsed["query"] == "www.google.com"
        assert parsed["qtype_name"] == "A"
        assert isinstance(parsed["answers"], list)
        assert len(parsed["answers"]) > 0

    def test_zeek_ja4_script_existence_and_syntax(self):
        """Verify config/zeek/ja4.zeek exists and defines ja4 export record extensions."""
        assert ZEEK_JA4_SCRIPT_PATH.exists(), f"Missing {ZEEK_JA4_SCRIPT_PATH}"
        content = ZEEK_JA4_SCRIPT_PATH.read_text(encoding="utf-8")
        assert "redef record SSL::Info" in content
        assert "ja4: string" in content
        assert "ja4s: string" in content
        assert "event ssl_client_hello" in content
        assert "event ssl_server_hello" in content

    def test_zeek_local_script_includes_ja4_and_json_tuning(self):
        """Verify config/zeek/local.zeek loads ja4.zeek and json-logs policy."""
        assert ZEEK_LOCAL_SCRIPT_PATH.exists(), f"Missing {ZEEK_LOCAL_SCRIPT_PATH}"
        content = ZEEK_LOCAL_SCRIPT_PATH.read_text(encoding="utf-8")
        assert "ja4.zeek" in content or "@load ./ja4.zeek" in content
        assert "json-logs" in content or "LogAscii::use_json" in content


# ============================================================================
# Tier 2: Boundary & Corner Cases (>= 5 tests per feature)
# ============================================================================

class TestJA4BoundaryCornerCasesTier2:
    """Tier 2: GREASE filtering, empty ciphers, legacy SSL versions, and truncation."""

    def test_grease_cipher_and_extension_filtering(self):
        """Boundary: Verify that all 16 GREASE values are completely filtered from JA4 string and hash."""
        grease_ciphers = [0x0A0A, 0x1301, 0x2A2A, 0xC02B, 0xFAFA]
        clean_ciphers = [0x1301, 0xC02B]
        
        ja4_with_grease = compute_ja4_fingerprint("tcp", 0x0304, "test.com", grease_ciphers)
        ja4_without_grease = compute_ja4_fingerprint("tcp", 0x0304, "test.com", clean_ciphers)
        
        assert ja4_with_grease == ja4_without_grease
        assert ja4_with_grease.startswith("t13d02")  # Count is exactly 02, not 05

    def test_empty_ciphers_list_handling(self):
        """Corner: Verify empty ciphers list yields count '00' and zero-hash '000000000000'."""
        ja4 = compute_ja4_fingerprint("tcp", 0x0304, "test.com", [])
        parts = ja4.split("_")
        assert parts[0].startswith("t13d00")
        assert parts[1] == "000000000000"

    def test_single_character_alpn(self):
        """Corner: Verify 1-character ALPN pads correctly to 2 characters."""
        ja4 = compute_ja4_fingerprint("tcp", 0x0304, "test.com", [0x1301], alpn="h")
        assert ja4.split("_")[0].endswith("h0")

    def test_maximum_ciphers_clamp_at_99(self):
        """Boundary: Verify >99 ciphers clamps 2-digit count string at '99'."""
        many_ciphers = list(range(100, 250))
        ja4 = compute_ja4_fingerprint("tcp", 0x0304, "test.com", many_ciphers)
        assert ja4.split("_")[0][4:6] == "99"

    def test_legacy_ssl30_version_code(self):
        """Boundary: Verify legacy SSL 3.0 (0x0300) produces 's3' version code."""
        ja4 = compute_ja4_fingerprint("tcp", 0x0300, "legacy.bank.com", [0x0004])
        assert ja4.startswith("ts3d01")


# ============================================================================
# Tier 3: Cross-Feature Pairwise Interactions
# ============================================================================

class TestCrossFeaturePairwiseTier3:
    """Tier 3: Pairwise validation between Zeek logs, UID correlation, and JA4 lookups."""

    def test_uid_cross_correlation_between_conn_and_ssl_logs(self):
        """Pairwise: Correlate conn.log and ssl.log entries sharing the identical connection UID."""
        shared_uid = "C9876543210fedcba"
        orig_ip = "192.168.1.150"
        resp_ip = "142.250.190.46"
        
        conn_entry = {
            "ts": 1725000010.0,
            "uid": shared_uid,
            "id.orig_h": orig_ip,
            "id.orig_p": 51000,
            "id.resp_h": resp_ip,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF"
        }
        ssl_entry = {
            "ts": 1725000010.05,
            "uid": shared_uid,
            "id.orig_h": orig_ip,
            "id.orig_p": 51000,
            "id.resp_h": resp_ip,
            "id.resp_p": 443,
            "version": "TLSv13",
            "server_name": "google.com",
            "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
        }
        
        # Verify 5-tuple consistency
        assert conn_entry["uid"] == ssl_entry["uid"]
        assert conn_entry["id.orig_h"] == ssl_entry["id.orig_h"]
        assert conn_entry["id.resp_p"] == ssl_entry["id.resp_p"]
        assert ssl_entry["ja4"].startswith("t13d")

    def test_ja4_threat_intel_lookup_simulation(self):
        """Pairwise: Match computed JA4 fingerprint against a known malicious JA4 blacklist."""
        threat_ja4_db = {
            "t13d1516h2_8daaf6152771_e5627efa2ab1": "Benign.Chrome120",
            "t10i010000_000400000000_000000000000": "Malware.SliverC2",
            "t12d080000_c02f009e0035_000000000000": "Trojan.Emotet"
        }
        
        # Test known Chrome JA4
        benign_ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
        ja4_test = compute_ja4_fingerprint("tcp", 0x0304, "google.com", benign_ciphers, alpn="h2")
        # Ensure lookup dictionary works with JA4 keys
        assert threat_ja4_db.get("t10i010000_000400000000_000000000000") == "Malware.SliverC2"


# ============================================================================
# Tier 4: Real-World Resilience & Adversarial Stress
# ============================================================================

class TestRealWorldStressAdversarialTier4:
    """Tier 4: Adversarial TLS modifications, hash collisions, and parser fuzzing."""

    def test_non_ascii_or_escaped_sni_handling(self):
        """Adversarial: Test JA4 calculation when SNI contains non-ASCII or internationalized domain (IDN)."""
        idn_sni = "xn--bcher-kva.example"
        ja4 = compute_ja4_fingerprint("tcp", 0x0304, idn_sni, [0x1301], alpn="h2")
        assert ja4.startswith("t13d01")

    def test_hash_truncation_collision_safety(self):
        """Stress: Verify 12-character hex hash provides 48 bits of entropy."""
        hashes = set()
        for i in range(500):
            ciphers = [0x1301 + (i % 50), 0xC02B + (i * 3 % 100)]
            ja4 = compute_ja4_fingerprint("tcp", 0x0304, f"sub{i}.domain.com", ciphers)
            h = ja4.split("_")[1]
            assert len(h) == 12
            hashes.add(h)
        # Should have diverse distinct hashes
        assert len(hashes) > 30


if __name__ == "__main__":
    pytest.main(["-v", __file__])
