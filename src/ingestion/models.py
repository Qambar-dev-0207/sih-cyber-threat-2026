"""
SIH26145 - Telemetry & Alert Data Models
Pydantic schemas for normalized Zeek telemetry events and structured threat detector alerts.
"""

from __future__ import annotations

import math
import time
import uuid
from collections import Counter
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon entropy H(X) = -sum(p_i * log2(p_i)) for a string.
    Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_subdomain(query: str) -> str:
    """
    Extracts the leftmost subdomain label from a FQDN.
    e.g. 'xyz123.evil.corp.com' -> 'xyz123'
         'google.com' -> 'google'
         'localhost' -> 'localhost'
    """
    if not query:
        return ""
    parts = [p for p in query.strip().strip(".").split(".") if p]
    if len(parts) >= 1:
        return parts[0]
    return ""


def _parse_float(val: Any, default: float = 0.0) -> float:
    """Helper to safely parse float values from Zeek logs (handles '-', None, etc.)."""
    if val is None or val == "-":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _parse_int(val: Any, default: int = 0) -> int:
    """Helper to safely parse int values from Zeek logs (handles '-', None, etc.)."""
    if val is None or val == "-":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _parse_str(val: Any, default: str = "") -> str:
    """Helper to safely parse string values from Zeek logs."""
    if val is None or val == "-":
        return default
    return str(val)


class ConnTelemetryEvent(BaseModel):
    """
    Normalized connection flow event from Zeek conn.log.
    Published to topic 'telemetry.conn' partitioned by source_ip.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = Field(default_factory=time.time, description="Unix timestamp of flow start")
    uid: str = Field(default_factory=lambda: f"C{uuid.uuid4().hex[:16]}", description="Zeek unique flow ID")
    src_ip: str = Field(..., alias="source_ip", description="Originating / source IP address")
    src_port: int = Field(..., alias="source_port", ge=0, le=65535, description="Originating transport port")
    dst_ip: str = Field(..., alias="target_ip", description="Destination / target IP address")
    dst_port: int = Field(..., alias="target_port", ge=0, le=65535, description="Destination transport port")
    proto: str = Field(default="tcp", description="Transport protocol (tcp, udp, icmp)")
    service: Optional[str] = Field(default=None, description="Identified service/protocol")
    duration: float = Field(default=0.0, ge=0.0, description="Flow duration in seconds")
    orig_bytes: int = Field(default=0, ge=0, description="Payload bytes sent by originator")
    resp_bytes: int = Field(default=0, ge=0, description="Payload bytes sent by responder")
    conn_state: str = Field(default="SF", description="Zeek connection state string (SF, S0, REJ, etc.)")
    orig_pkts: int = Field(default=0, ge=0, description="Packet count from originator")
    resp_pkts: int = Field(default=0, ge=0, description="Packet count from responder")
    missed_bytes: int = Field(default=0, ge=0, description="Missed bytes in flow")
    history: str = Field(default="", description="State transition history flags")
    community_id: Optional[str] = Field(default=None, description="Community ID flow hash")
    ingest_ts: float = Field(default_factory=time.time, description="Ingestion pipeline timestamp")

    @classmethod
    def from_zeek_dict(cls, raw: Dict[str, Any]) -> ConnTelemetryEvent:
        """
        Constructs a normalized ConnTelemetryEvent from a raw Zeek conn.log JSON record.
        """
        src_ip = (
            raw.get("id.orig_h")
            or raw.get("orig_h")
            or raw.get("src_ip")
            or raw.get("source_ip")
            or "0.0.0.0"
        )
        src_port = _parse_int(
            raw.get("id.orig_p")
            or raw.get("orig_p")
            or raw.get("src_port")
            or raw.get("source_port")
            or 0
        )
        dst_ip = (
            raw.get("id.resp_h")
            or raw.get("resp_h")
            or raw.get("dst_ip")
            or raw.get("target_ip")
            or "0.0.0.0"
        )
        dst_port = _parse_int(
            raw.get("id.resp_p")
            or raw.get("resp_p")
            or raw.get("dst_port")
            or raw.get("target_port")
            or 0
        )
        uid = _parse_str(raw.get("uid")) or f"C{uuid.uuid4().hex[:16]}"
        ts = _parse_float(raw.get("ts"), time.time())
        proto = _parse_str(raw.get("proto"), "tcp").lower()
        service = raw.get("service") if raw.get("service") not in ("-", None, "") else None
        duration = max(0.0, _parse_float(raw.get("duration"), 0.0))
        orig_bytes = max(0, _parse_int(raw.get("orig_bytes") or raw.get("orig_ip_bytes"), 0))
        resp_bytes = max(0, _parse_int(raw.get("resp_bytes") or raw.get("resp_ip_bytes"), 0))
        conn_state = _parse_str(raw.get("conn_state"), "SF")
        orig_pkts = max(0, _parse_int(raw.get("orig_pkts"), 0))
        resp_pkts = max(0, _parse_int(raw.get("resp_pkts"), 0))
        missed_bytes = max(0, _parse_int(raw.get("missed_bytes"), 0))
        history = _parse_str(raw.get("history"), "")
        community_id = raw.get("community_id") if raw.get("community_id") not in ("-", None, "") else None
        ingest_ts = _parse_float(raw.get("ingest_ts") or raw.get("_tail_ts"), time.time())

        return cls(
            event_id=str(raw.get("event_id") or uuid.uuid4()),
            ts=ts,
            uid=uid,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            service=service,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            conn_state=conn_state,
            orig_pkts=orig_pkts,
            resp_pkts=resp_pkts,
            missed_bytes=missed_bytes,
            history=history,
            community_id=community_id,
            ingest_ts=ingest_ts,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Convert model to JSON string."""
        return self.model_dump_json()


class DnsTelemetryEvent(BaseModel):
    """
    Normalized DNS query/response telemetry event from Zeek dns.log.
    Published to topic 'telemetry.dns' partitioned by source_ip.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = Field(default_factory=time.time, description="Unix timestamp of DNS interaction")
    uid: str = Field(default_factory=lambda: f"D{uuid.uuid4().hex[:16]}", description="Zeek connection UID")
    src_ip: str = Field(..., alias="source_ip", description="Client source IP address")
    src_port: int = Field(..., alias="source_port", ge=0, le=65535, description="Client source port")
    dst_ip: str = Field(..., alias="target_ip", description="DNS resolver IP address")
    dst_port: int = Field(..., alias="target_port", ge=0, le=65535, description="DNS resolver port (typically 53)")
    proto: str = Field(default="udp", description="Transport protocol (udp, tcp)")
    trans_id: int = Field(default=0, ge=0, description="16-bit DNS transaction ID")
    query: str = Field(..., description="Queried domain name")
    qclass_name: str = Field(default="C_INTERNET", description="DNS query class name")
    qtype_name: str = Field(default="A", description="DNS query type name (A, AAAA, TXT, etc.)")
    rcode_name: str = Field(default="NOERROR", description="DNS response code name (NOERROR, NXDOMAIN, etc.)")
    answers: List[str] = Field(default_factory=list, description="Resolved answers/IPs/records")
    ttls: List[float] = Field(default_factory=list, description="Resource record TTLs")
    subdomain: Optional[str] = Field(default=None, description="Extracted leftmost subdomain label")
    subdomain_entropy: float = Field(default=0.0, ge=0.0, description="Shannon entropy of subdomain label")
    ingest_ts: float = Field(default_factory=time.time, description="Ingestion pipeline timestamp")

    @classmethod
    def from_zeek_dict(cls, raw: Dict[str, Any]) -> DnsTelemetryEvent:
        """
        Constructs a normalized DnsTelemetryEvent from a raw Zeek dns.log JSON record.
        """
        src_ip = (
            raw.get("id.orig_h")
            or raw.get("orig_h")
            or raw.get("src_ip")
            or raw.get("source_ip")
            or "0.0.0.0"
        )
        src_port = _parse_int(
            raw.get("id.orig_p")
            or raw.get("orig_p")
            or raw.get("src_port")
            or raw.get("source_port")
            or 0
        )
        dst_ip = (
            raw.get("id.resp_h")
            or raw.get("resp_h")
            or raw.get("dst_ip")
            or raw.get("target_ip")
            or "0.0.0.0"
        )
        dst_port = _parse_int(
            raw.get("id.resp_p")
            or raw.get("resp_p")
            or raw.get("dst_port")
            or raw.get("target_port")
            or 53
        )
        uid = _parse_str(raw.get("uid")) or f"D{uuid.uuid4().hex[:16]}"
        ts = _parse_float(raw.get("ts"), time.time())
        proto = _parse_str(raw.get("proto"), "udp").lower()
        trans_id = _parse_int(raw.get("trans_id"), 0)
        query = _parse_str(raw.get("query"), "")
        qclass_name = _parse_str(raw.get("qclass_name"), "C_INTERNET")
        qtype_name = _parse_str(raw.get("qtype_name"), "A").upper()
        rcode_name = _parse_str(raw.get("rcode_name"), "NOERROR").upper()

        raw_answers = raw.get("answers", [])
        if isinstance(raw_answers, list):
            answers = [str(a) for a in raw_answers if a not in ("-", None)]
        elif isinstance(raw_answers, str) and raw_answers not in ("-", ""):
            answers = [raw_answers]
        else:
            answers = []

        raw_ttls = raw.get("TTLs") or raw.get("ttls") or []
        if isinstance(raw_ttls, list):
            ttls = [_parse_float(t, 0.0) for t in raw_ttls if t not in ("-", None)]
        elif isinstance(raw_ttls, (int, float)):
            ttls = [float(raw_ttls)]
        else:
            ttls = []

        subdomain = raw.get("subdomain")
        if not subdomain:
            subdomain = extract_subdomain(query)

        subdomain_entropy = _parse_float(raw.get("subdomain_entropy"), -1.0)
        if subdomain_entropy < 0:
            subdomain_entropy = calculate_shannon_entropy(subdomain)

        ingest_ts = _parse_float(raw.get("ingest_ts") or raw.get("_tail_ts"), time.time())

        return cls(
            event_id=str(raw.get("event_id") or uuid.uuid4()),
            ts=ts,
            uid=uid,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            trans_id=trans_id,
            query=query,
            qclass_name=qclass_name,
            qtype_name=qtype_name,
            rcode_name=rcode_name,
            answers=answers,
            ttls=ttls,
            subdomain=subdomain,
            subdomain_entropy=subdomain_entropy,
            ingest_ts=ingest_ts,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Convert model to JSON string."""
        return self.model_dump_json()


class SslTelemetryEvent(BaseModel):
    """
    Normalized TLS/SSL metadata event from Zeek ssl.log (with JA4/JA4S fingerprinting).
    Published to topic 'telemetry.ssl' partitioned by source_ip.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: float = Field(default_factory=time.time, description="Unix timestamp of SSL session")
    uid: str = Field(default_factory=lambda: f"S{uuid.uuid4().hex[:16]}", description="Zeek connection UID")
    src_ip: str = Field(..., alias="source_ip", description="Client source IP address")
    src_port: int = Field(..., alias="source_port", ge=0, le=65535, description="Client source port")
    dst_ip: str = Field(..., alias="target_ip", description="Server destination IP address")
    dst_port: int = Field(..., alias="target_port", ge=0, le=65535, description="Server destination port (typically 443)")
    version: str = Field(default="TLSv13", description="Negotiated or advertised TLS version")
    cipher: str = Field(default="", description="Negotiated cipher suite name or hex")
    server_name: Optional[str] = Field(default=None, description="SNI server name")
    ja4: Optional[str] = Field(default=None, description="JA4 client fingerprint string")
    ja4s: Optional[str] = Field(default=None, description="JA4S server fingerprint string")
    ja4_raw_ciphers: Optional[str] = Field(default=None, description="Raw hex ciphers list from ClientHello")
    established: bool = Field(default=True, description="Whether TLS handshake succeeded")
    subject: Optional[str] = Field(default=None, description="Server certificate subject DN")
    issuer: Optional[str] = Field(default=None, description="Server certificate issuer DN")
    ingest_ts: float = Field(default_factory=time.time, description="Ingestion pipeline timestamp")

    @classmethod
    def from_zeek_dict(cls, raw: Dict[str, Any]) -> SslTelemetryEvent:
        """
        Constructs a normalized SslTelemetryEvent from a raw Zeek ssl.log JSON record.
        """
        src_ip = (
            raw.get("id.orig_h")
            or raw.get("orig_h")
            or raw.get("src_ip")
            or raw.get("source_ip")
            or "0.0.0.0"
        )
        src_port = _parse_int(
            raw.get("id.orig_p")
            or raw.get("orig_p")
            or raw.get("src_port")
            or raw.get("source_port")
            or 0
        )
        dst_ip = (
            raw.get("id.resp_h")
            or raw.get("resp_h")
            or raw.get("dst_ip")
            or raw.get("target_ip")
            or "0.0.0.0"
        )
        dst_port = _parse_int(
            raw.get("id.resp_p")
            or raw.get("resp_p")
            or raw.get("dst_port")
            or raw.get("target_port")
            or 443
        )
        uid = _parse_str(raw.get("uid")) or f"S{uuid.uuid4().hex[:16]}"
        ts = _parse_float(raw.get("ts"), time.time())
        version = _parse_str(raw.get("version"), "TLSv13")
        cipher = _parse_str(raw.get("cipher"), "")
        server_name = raw.get("server_name") if raw.get("server_name") not in ("-", None, "") else None
        ja4 = raw.get("ja4") if raw.get("ja4") not in ("-", None, "") else None
        ja4s = raw.get("ja4s") if raw.get("ja4s") not in ("-", None, "") else None
        ja4_raw_ciphers = raw.get("ja4_raw_ciphers") if raw.get("ja4_raw_ciphers") not in ("-", None, "") else None

        established_raw = raw.get("established", True)
        if isinstance(established_raw, str):
            established = established_raw.lower() in ("true", "t", "1", "yes")
        else:
            established = bool(established_raw)

        subject = raw.get("subject") if raw.get("subject") not in ("-", None, "") else None
        issuer = raw.get("issuer") if raw.get("issuer") not in ("-", None, "") else None
        ingest_ts = _parse_float(raw.get("ingest_ts") or raw.get("_tail_ts"), time.time())

        return cls(
            event_id=str(raw.get("event_id") or uuid.uuid4()),
            ts=ts,
            uid=uid,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            version=version,
            cipher=cipher,
            server_name=server_name,
            ja4=ja4,
            ja4s=ja4s,
            ja4_raw_ciphers=ja4_raw_ciphers,
            established=established,
            subject=subject,
            issuer=issuer,
            ingest_ts=ingest_ts,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Convert model to JSON string."""
        return self.model_dump_json()


class RawAlert(BaseModel):
    """
    Standardized threat alert published to 'alerts.raw' by all 6 streaming detectors.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of alert generation")
    detector_name: str = Field(..., alias="detector_id", description="Originating detector identifier")
    threat_class: str = Field(
        ...,
        description="Threat classification (VOLUMETRIC_DDOS, PORT_SCAN_RECON, DATA_EXFILTRATION, DGA_TUNNELLING, ENCRYPTED_MALWARE, C2_BEACONING)",
    )
    severity: str = Field(default="MEDIUM", description="Alert severity level (LOW, MEDIUM, HIGH, CRITICAL)")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Detector confidence score [0.0, 1.0]")
    source_ip: str = Field(..., description="Attacker or compromised source IP address")
    target_ip: Optional[str] = Field(default=None, description="Targeted destination IP address")
    target_port: Optional[int] = Field(default=None, ge=0, le=65535, description="Targeted destination port")
    protocol: Optional[str] = Field(default=None, description="Observed network protocol")
    flow_id: Optional[str] = Field(default=None, description="Associated Zeek flow UID")
    window_duration_sec: Optional[float] = Field(default=None, ge=0.0, description="Observation window duration in seconds")
    title: Optional[str] = Field(default=None, description="Human-readable alert summary title")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Mathematical & evidentiary payload")
    mitre_technique: Optional[str] = Field(default=None, description="Mapped MITRE ATT&CK technique (e.g. T1498)")
    recommended_mitigation: Optional[str] = Field(default=None, description="Recommended incident response action")
    raw_telemetry_ref: Optional[Dict[str, Any]] = Field(default=None, description="Sample raw telemetry triggering alert")

    @model_validator(mode="after")
    def populate_default_title(self) -> RawAlert:
        """Auto-populate title and severity defaults if omitted."""
        if not self.title:
            self.title = f"[{self.severity}] {self.threat_class} detected on {self.source_ip}"
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return self.model_dump()

    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return self.model_dump_json()
