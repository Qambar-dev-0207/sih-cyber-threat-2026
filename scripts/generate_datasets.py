#!/usr/bin/env python3
"""
scripts/generate_datasets.py
----------------------------
Deterministic Synthetic PCAP Generator for SIH26145 Passive Network Monitoring System.

Generates realistic network traffic datasets:
1. data/pcaps/benign_baseline.pcap:
   - Realistic HTTP/1.1 GET/POST sessions with full 3-way handshake and teardown.
   - DNS queries & responses (A, AAAA, TXT, PTR, NXDOMAIN) with valid RR records.
   - TLS 1.2 & TLS 1.3 ClientHello / ServerHello handshakes yielding valid JA4/JA4S fingerprints.
2. data/pcaps/ddos_syn_flood.pcap:
   - High-rate randomized source IP SYN flood attack against target server.
3. data/pcaps/portscan_nmap.pcap:
   - Realistic multi-mode reconnaissance scan: TCP SYN scan (-sS), TCP Connect scan (-sT), UDP scan (-sU)
     with proper SYN-ACK/RST and ICMP Port Unreachable responses.

CLI Options:
  --output-dir      Directory to save generated PCAPs (default: data/pcaps)
  --flows           Number of benign flows to synthesize (default: 500)
  --syn-flood-pkts  Number of SYN flood packets (default: 10000)
  --scan-ports      Number of ports to sweep in portscan (default: 1000)
  --attack-types    Comma-separated list of attacks to generate: syn_flood,portscan,all (default: all)
  --seed            Deterministic random seed (default: 42)
"""

import os
import sys
import time
import struct
import random
import hashlib
import argparse
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

try:
    from scapy.all import (
        Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap
    )
except ImportError:
    print("Error: Scapy is required. Install via `pip install scapy`.", file=sys.stderr)
    sys.exit(1)


# ==============================================================================
# Helper Functions: JA4 Utilities & Binary Handshake Encoders
# ==============================================================================

def calculate_ja4(
    proto: str,
    tls_version: int,
    sni_present: bool,
    cipher_list: List[int],
    extension_list: List[int],
    alpn_str: str = ""
) -> str:
    """
    Computes a standard JA4 fingerprint for a TLS ClientHello.
    Format: [Protocol][Version][SNI][NumCiphers][NumExt][ALPN]_[SortedCipherHash]_[SortedExtHash]
    """
    # 1. Protocol character: t = TCP, q = QUIC, d = DTLS
    p_char = proto.lower()[0] if proto else "t"

    # 2. TLS Version string
    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
    ver_str = ver_map.get(tls_version, "00")

    # 3. SNI indicator: d = domain, i = IP / missing
    sni_char = "d" if sni_present else "i"

    # 4. Filter GREASE values (0x0a0a, 0x1a1a, etc.)
    grease = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
              0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
    filtered_ciphers = [c for c in cipher_list if c not in grease]
    filtered_extensions = [e for e in extension_list if e not in grease]

    # 5. Counts (2-digit zero padded, capped at 99)
    num_ciphers = f"{min(len(filtered_ciphers), 99):02d}"
    num_exts = f"{min(len(filtered_extensions), 99):02d}"

    # 6. ALPN (first and last alphanumeric char, or 00)
    if alpn_str:
        clean_alpn = "".join(c for c in alpn_str if c.isalnum())
        alpn_code = (clean_alpn[0] + clean_alpn[-1]) if len(clean_alpn) >= 2 else (clean_alpn + "0" if len(clean_alpn) == 1 else "00")
    else:
        alpn_code = "00"

    prefix = f"{p_char}{ver_str}{sni_char}{num_ciphers}{num_exts}{alpn_code}"

    # 7. Sorted Ciphers Hash (12 hex chars of SHA256 of comma-separated 4-char hex)
    sorted_ciphers = sorted(filtered_ciphers)
    ciphers_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
    ciphers_hash = hashlib.sha256(ciphers_str.encode("ascii")).hexdigest()[:12] if ciphers_str else "000000000000"

    # 8. Sorted Extensions Hash (12 hex chars of SHA256 of comma-separated 4-char hex)
    # Note: JA4 sorts extensions but excludes SNI (0x0000) and ALPN (0x0010) from the extension hash
    hash_exts = [e for e in filtered_extensions if e not in (0x0000, 0x0010)]
    sorted_exts = sorted(hash_exts)
    exts_str = ",".join(f"{e:04x}" for e in sorted_exts)
    exts_hash = hashlib.sha256(exts_str.encode("ascii")).hexdigest()[:12] if exts_str else "000000000000"

    return f"{prefix}_{ciphers_hash}_{exts_hash}"


def calculate_ja4s(
    proto: str,
    tls_version: int,
    selected_cipher: int,
    extension_list: List[int],
    alpn_str: str = ""
) -> str:
    """
    Computes a standard JA4S fingerprint for a TLS ServerHello.
    Format: [Protocol][Version][NumExt][ALPN]_[SelectedCipher]_[SortedExtHash]
    """
    p_char = proto.lower()[0] if proto else "t"
    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    ver_str = ver_map.get(tls_version, "00")
    num_exts = f"{min(len(extension_list), 99):02d}"

    if alpn_str:
        clean_alpn = "".join(c for c in alpn_str if c.isalnum())
        alpn_code = (clean_alpn[0] + clean_alpn[-1]) if len(clean_alpn) >= 2 else (clean_alpn + "0" if len(clean_alpn) == 1 else "00")
    else:
        alpn_code = "00"

    prefix = f"{p_char}{ver_str}{num_exts}{alpn_code}"
    cipher_hex = f"{selected_cipher:04x}"

    # Filter out ALPN from extension hash in JA4S
    hash_exts = [e for e in extension_list if e != 0x0010]
    sorted_exts = sorted(hash_exts)
    exts_str = ",".join(f"{e:04x}" for e in sorted_exts)
    exts_hash = hashlib.sha256(exts_str.encode("ascii")).hexdigest()[:12] if exts_str else "000000000000"

    return f"{prefix}_{cipher_hex}_{exts_hash}"


def build_raw_tls_client_hello(
    sni: str,
    ciphers: List[int],
    extensions_map: Dict[int, bytes],
    record_version: int = 0x0303,
    handshake_version: int = 0x0303,
    random_bytes: Optional[bytes] = None
) -> bytes:
    """
    Constructs a standards-compliant TLS ClientHello byte stream suitable for Zeek DPI.
    """
    if random_bytes is None:
        random_bytes = struct.pack(">I", int(time.time())) + os.urandom(28)
    else:
        if len(random_bytes) < 32:
            random_bytes = random_bytes.ljust(32, b"\x00")
        elif len(random_bytes) > 32:
            random_bytes = random_bytes[:32]

    # Session ID (32 bytes)
    session_id = os.urandom(32)
    session_id_bytes = struct.pack("B", len(session_id)) + session_id

    # Cipher Suites
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    ciphers_block = struct.pack(">H", len(cipher_bytes)) + cipher_bytes

    # Compression Methods (1 byte length + 0x00 [null])
    comp_block = b"\x01\x00"

    # Extensions Block
    ext_payload = bytearray()
    for ext_type, ext_data in extensions_map.items():
        ext_payload.extend(struct.pack(">HH", ext_type, len(ext_data)))
        ext_payload.extend(ext_data)

    ext_block = struct.pack(">H", len(ext_payload)) + bytes(ext_payload)

    # ClientHello Handshake Message
    ch_body = struct.pack(">H", handshake_version) + random_bytes + session_id_bytes + ciphers_block + comp_block + ext_block
    handshake_header = struct.pack("B", 0x01) + struct.pack(">I", len(ch_body))[1:] # Handshake Type 0x01 (ClientHello), 3-byte length
    handshake_record = handshake_header + ch_body

    # TLS Record Header: 0x16 (Handshake), Version, Length
    record_header = struct.pack(">BHH", 0x16, record_version, len(handshake_record))
    return record_header + handshake_record


def build_raw_tls_server_hello(
    selected_cipher: int,
    extensions_map: Dict[int, bytes],
    record_version: int = 0x0303,
    handshake_version: int = 0x0303,
    random_bytes: Optional[bytes] = None
) -> bytes:
    """
    Constructs a standards-compliant TLS ServerHello byte stream.
    """
    if random_bytes is None:
        random_bytes = struct.pack(">I", int(time.time())) + os.urandom(28)
    else:
        if len(random_bytes) < 32:
            random_bytes = random_bytes.ljust(32, b"\x00")
        elif len(random_bytes) > 32:
            random_bytes = random_bytes[:32]

    session_id = os.urandom(32)
    session_id_bytes = struct.pack("B", len(session_id)) + session_id
    cipher_bytes = struct.pack(">H", selected_cipher)
    comp_byte = b"\x00"

    ext_payload = bytearray()
    for ext_type, ext_data in extensions_map.items():
        ext_payload.extend(struct.pack(">HH", ext_type, len(ext_data)))
        ext_payload.extend(ext_data)

    ext_block = struct.pack(">H", len(ext_payload)) + bytes(ext_payload) if ext_payload else b""

    sh_body = struct.pack(">H", handshake_version) + random_bytes + session_id_bytes + cipher_bytes + comp_byte + ext_block
    handshake_header = struct.pack("B", 0x02) + struct.pack(">I", len(sh_body))[1:]
    handshake_record = handshake_header + sh_body

    record_header = struct.pack(">BHH", 0x16, record_version, len(handshake_record))
    return record_header + handshake_record


def encode_sni_extension(hostname: str) -> bytes:
    """Encodes TLS Server Name Indication (SNI) extension payload."""
    host_bytes = hostname.encode("utf-8")
    server_name_entry = b"\x00" + struct.pack(">H", len(host_bytes)) + host_bytes # NameType 0 = host_name
    return struct.pack(">H", len(server_name_entry)) + server_name_entry


def encode_alpn_extension(protocols: List[str]) -> bytes:
    """Encodes Application Layer Protocol Negotiation (ALPN) extension payload."""
    alpn_list = bytearray()
    for proto in protocols:
        proto_bytes = proto.encode("utf-8")
        alpn_list.append(len(proto_bytes))
        alpn_list.extend(proto_bytes)
    return struct.pack(">H", len(alpn_list)) + bytes(alpn_list)


# ==============================================================================
# Synthetic Dataset Generator Classes
# ==============================================================================

class BenignDatasetGenerator:
    """
    Generates realistic benign enterprise traffic:
    - HTTP/1.1 GET / POST flows with full TCP lifecycle
    - DNS A, AAAA, TXT, PTR, and NXDOMAIN queries and responses
    - TLS 1.2 & TLS 1.3 ClientHello / ServerHello handshakes yielding valid JA4/JA4S fingerprints
    """
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.client_mac = "02:42:ac:11:00:02"
        self.server_mac = "02:42:ac:11:00:03"
        self.dns_server_ip = "192.168.10.1"
        self.web_server_ip = "192.168.10.50"

        self.client_subnet = "192.168.1"
        self.domains = [
            "portal.service.gov.in", "cdn.security.lan", "api.internal.corp",
            "telemetry.mesh.net", "auth.sso.gov.in", "repo.enterprise.local",
            "updates.microsoft.com", "gateway.cloudflare.com", "dashboard.internal.lan"
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "curl/8.7.1"
        ]

    def _random_client_ip(self) -> str:
        return f"{self.client_subnet}.{self.rng.randint(10, 250)}"

    def generate_http_flow(self, base_time: float) -> Tuple[List[Any], float]:
        """Generates a complete HTTP/1.1 session (SYN -> SYN-ACK -> ACK -> REQ -> ACK -> RESP -> FIN teardown)."""
        packets = []
        t = base_time
        client_ip = self._random_client_ip()
        client_port = self.rng.randint(32768, 61000)
        server_port = 80
        domain = self.rng.choice(self.domains)
        ua = self.rng.choice(self.user_agents)

        c_seq = self.rng.randint(10000, 500000)
        s_seq = self.rng.randint(50000, 900000)

        # 1. 3-Way Handshake
        syn = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=client_ip, dst=self.web_server_ip) / \
              TCP(sport=client_port, dport=server_port, flags="S", seq=c_seq, window=64240,
                  options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
        syn.time = t
        packets.append(syn)
        t += self.rng.uniform(0.0005, 0.002)

        syn_ack = Ether(src=self.server_mac, dst=self.client_mac) / \
                  IP(src=self.web_server_ip, dst=client_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="SA", seq=s_seq, ack=c_seq + 1, window=65535,
                      options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
        syn_ack.time = t
        packets.append(syn_ack)
        t += self.rng.uniform(0.0003, 0.001)

        c_seq += 1
        s_seq += 1
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=client_ip, dst=self.web_server_ip) / \
              TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq, window=502)
        ack.time = t
        packets.append(ack)
        t += self.rng.uniform(0.0005, 0.002)

        # 2. HTTP Request (GET or POST)
        is_post = self.rng.random() < 0.3
        if is_post:
            body = '{"status":"active","telemetry_id":"' + f"{self.rng.randint(1000, 9999)}" + '"}'
            http_req_payload = (
                f"POST /api/v1/telemetry HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
                f"{body}"
            ).encode("utf-8")
        else:
            path = self.rng.choice(["/", "/index.html", "/api/v1/health", "/static/app.css", "/status"])
            http_req_payload = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: {ua}\r\n"
                f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")

        req_pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
                  IP(src=client_ip, dst=self.web_server_ip) / \
                  TCP(sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq, window=502) / \
                  Raw(load=http_req_payload)
        req_pkt.time = t
        packets.append(req_pkt)
        c_seq += len(http_req_payload)
        t += self.rng.uniform(0.001, 0.005)

        # Server ACK for request
        srv_ack = Ether(src=self.server_mac, dst=self.client_mac) / \
                  IP(src=self.web_server_ip, dst=client_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="A", seq=s_seq, ack=c_seq, window=502)
        srv_ack.time = t
        packets.append(srv_ack)
        t += self.rng.uniform(0.002, 0.008)

        # 3. HTTP Response
        resp_body = "<html><body><h1>200 OK</h1><p>Telemetry Node Operational</p></body></html>"
        http_resp_payload = (
            f"HTTP/1.1 200 OK\r\n"
            f"Date: Sun, 30 Aug 2026 00:00:00 GMT\r\n"
            f"Server: nginx/1.24.0\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(resp_body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{resp_body}"
        ).encode("utf-8")

        resp_pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
                   IP(src=self.web_server_ip, dst=client_ip) / \
                   TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq, window=502) / \
                   Raw(load=http_resp_payload)
        resp_pkt.time = t
        packets.append(resp_pkt)
        s_seq += len(http_resp_payload)
        t += self.rng.uniform(0.001, 0.003)

        # 4. Graceful Teardown (FIN-ACK sequences)
        srv_fin = Ether(src=self.server_mac, dst=self.client_mac) / \
                  IP(src=self.web_server_ip, dst=client_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="FA", seq=s_seq, ack=c_seq, window=502)
        srv_fin.time = t
        packets.append(srv_fin)
        s_seq += 1
        t += self.rng.uniform(0.0005, 0.001)

        cli_fin_ack = Ether(src=self.client_mac, dst=self.server_mac) / \
                      IP(src=client_ip, dst=self.web_server_ip) / \
                      TCP(sport=client_port, dport=server_port, flags="FA", seq=c_seq, ack=s_seq, window=502)
        cli_fin_ack.time = t
        packets.append(cli_fin_ack)
        c_seq += 1
        t += self.rng.uniform(0.0005, 0.001)

        final_ack = Ether(src=self.server_mac, dst=self.client_mac) / \
                    IP(src=self.web_server_ip, dst=client_ip) / \
                    TCP(sport=server_port, dport=client_port, flags="A", seq=s_seq, ack=c_seq, window=502)
        final_ack.time = t
        packets.append(final_ack)
        t += self.rng.uniform(0.0005, 0.001)

        return packets, t

    def generate_dns_flow(self, base_time: float) -> Tuple[List[Any], float]:
        """Generates realistic DNS A, AAAA, TXT, PTR, or NXDOMAIN query/response flows."""
        packets = []
        t = base_time
        client_ip = self._random_client_ip()
        client_port = self.rng.randint(32768, 61000)
        dns_id = self.rng.randint(1, 65535)

        qtype_choice = self.rng.choices(["A", "AAAA", "TXT", "NXDOMAIN"], weights=[0.65, 0.15, 0.10, 0.10])[0]

        if qtype_choice == "NXDOMAIN":
            domain = f"nonexistent-{self.rng.randint(10000, 99999)}.corp.local"
            qtype = "A"
            rcode = 3 # NXDOMAIN
            an_record = None
        else:
            domain = self.rng.choice(self.domains)
            rcode = 0 # NOERROR
            if qtype_choice == "A":
                qtype = "A"
                an_record = DNSRR(rrname=domain + ".", type="A", ttl=300, rdata=f"104.26.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}")
            elif qtype_choice == "AAAA":
                qtype = "AAAA"
                an_record = DNSRR(rrname=domain + ".", type="AAAA", ttl=300, rdata="2606:2800:220:1:248:1893:25c8:1946")
            else: # TXT
                qtype = "TXT"
                an_record = DNSRR(rrname=domain + ".", type="TXT", ttl=300, rdata="v=spf1 include:_spf.google.com ~all")

        # DNS Query Packet
        dns_query = DNS(id=dns_id, qr=0, opcode=0, rd=1, qd=DNSQR(qname=domain + ".", qtype=qtype))
        q_pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
                IP(src=client_ip, dst=self.dns_server_ip) / \
                UDP(sport=client_port, dport=53) / \
                dns_query
        q_pkt.time = t
        packets.append(q_pkt)
        t += self.rng.uniform(0.001, 0.004)

        # DNS Response Packet
        if an_record:
            dns_resp = DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, rcode=rcode,
                           qd=DNSQR(qname=domain + ".", qtype=qtype),
                           an=an_record)
        else:
            dns_resp = DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, rcode=rcode,
                           qd=DNSQR(qname=domain + ".", qtype=qtype))

        r_pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
                IP(src=self.dns_server_ip, dst=client_ip) / \
                UDP(sport=53, dport=client_port) / \
                dns_resp
        r_pkt.time = t
        packets.append(r_pkt)
        t += self.rng.uniform(0.0005, 0.001)

        return packets, t

    def generate_tls_flow(self, base_time: float, tls_version: str = "1.3") -> Tuple[List[Any], float, str, str]:
        """
        Generates realistic TLS 1.2 or TLS 1.3 Handshake flows yielding valid JA4 and JA4S fingerprints in Zeek.
        """
        packets = []
        t = base_time
        client_ip = self._random_client_ip()
        client_port = self.rng.randint(32768, 61000)
        server_port = 443
        domain = self.rng.choice(self.domains)

        c_seq = self.rng.randint(10000, 500000)
        s_seq = self.rng.randint(50000, 900000)

        # 1. TCP 3-Way Handshake
        syn = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=client_ip, dst=self.web_server_ip) / \
              TCP(sport=client_port, dport=server_port, flags="S", seq=c_seq, window=64240,
                  options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
        syn.time = t
        packets.append(syn)
        t += self.rng.uniform(0.0005, 0.002)

        syn_ack = Ether(src=self.server_mac, dst=self.client_mac) / \
                  IP(src=self.web_server_ip, dst=client_ip) / \
                  TCP(sport=server_port, dport=client_port, flags="SA", seq=s_seq, ack=c_seq + 1, window=65535,
                      options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)])
        syn_ack.time = t
        packets.append(syn_ack)
        t += self.rng.uniform(0.0003, 0.001)

        c_seq += 1
        s_seq += 1
        ack = Ether(src=self.client_mac, dst=self.server_mac) / \
              IP(src=client_ip, dst=self.web_server_ip) / \
              TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq, window=502)
        ack.time = t
        packets.append(ack)
        t += self.rng.uniform(0.0005, 0.001)

        # 2. TLS ClientHello Payload
        if tls_version == "1.3":
            # TLS 1.3 ClientHello (Modern Chrome/Edge cipher suite)
            ciphers = [
                0x1301, 0x1302, 0x1303,  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
                0xc02b, 0xc02f, 0xc00a, 0xc014, # ECDHE-ECDSA/RSA AES ciphers
                0x009c, 0x009d, 0x002f, 0x0035  # Standard RSA fallback ciphers
            ]
            alpn_protocols = ["h2", "http/1.1"]
            extensions_map = {
                0x0000: encode_sni_extension(domain),                          # server_name (SNI)
                0x000a: b"\x00\x06\x00\x1d\x00\x17\x00\x18",                   # supported_groups (x25519, secp256r1, secp384r1)
                0x0010: encode_alpn_extension(alpn_protocols),                 # alpn
                0x000d: b"\x00\x0a\x04\x03\x08\x04\x04\x01\x05\x01\x02\x01",   # signature_algorithms
                0x002b: b"\x04\x03\x04\x03\x03",                               # supported_versions (TLS 1.3 [0x0304], TLS 1.2 [0x0303])
                0x0033: b"\x00\x24\x00\x1d\x00\x20" + (b"\x07" * 32)          # key_share (x25519)
            }
            client_hello_raw = build_raw_tls_client_hello(
                sni=domain,
                ciphers=ciphers,
                extensions_map=extensions_map,
                record_version=0x0303,
                handshake_version=0x0303
            )
            ja4_fingerprint = calculate_ja4(
                proto="t",
                tls_version=0x0304,
                sni_present=True,
                cipher_list=ciphers,
                extension_list=list(extensions_map.keys()),
                alpn_str="h2"
            )

            # TLS 1.3 ServerHello Payload
            selected_cipher = 0x1301 # TLS_AES_128_GCM_SHA256
            sh_exts = {
                0x002b: b"\x03\x04",                                           # supported_versions (TLS 1.3)
                0x0033: b"\x00\x1d\x00\x20" + (b"\x09" * 32),                  # key_share response
                0x0010: encode_alpn_extension(["h2"])                         # alpn selected
            }
            server_hello_raw = build_raw_tls_server_hello(
                selected_cipher=selected_cipher,
                extensions_map=sh_exts,
                record_version=0x0303,
                handshake_version=0x0303
            )
            ja4s_fingerprint = calculate_ja4s(
                proto="t",
                tls_version=0x0304,
                selected_cipher=selected_cipher,
                extension_list=list(sh_exts.keys()),
                alpn_str="h2"
            )

        else:
            # TLS 1.2 ClientHello
            ciphers = [
                0xc02f, 0xc02b, 0xc013, 0xc014,
                0x009c, 0x009d, 0x002f, 0x0035
            ]
            alpn_protocols = ["http/1.1"]
            extensions_map = {
                0x0000: encode_sni_extension(domain),                          # server_name
                0x000b: b"\x02\x01\x00",                                       # ec_point_formats
                0x000a: b"\x00\x04\x00\x17\x00\x18",                           # supported_groups (secp256r1, secp384r1)
                0x0010: encode_alpn_extension(alpn_protocols),                 # alpn
                0x000d: b"\x00\x08\x04\x01\x05\x01\x06\x01\x02\x01"           # signature_algorithms
            }
            client_hello_raw = build_raw_tls_client_hello(
                sni=domain,
                ciphers=ciphers,
                extensions_map=extensions_map,
                record_version=0x0303,
                handshake_version=0x0303
            )
            ja4_fingerprint = calculate_ja4(
                proto="t",
                tls_version=0x0303,
                sni_present=True,
                cipher_list=ciphers,
                extension_list=list(extensions_map.keys()),
                alpn_str="11"
            )

            # TLS 1.2 ServerHello
            selected_cipher = 0xc02f # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            sh_exts = {
                0x000b: b"\x02\x01\x00",
                0x0010: encode_alpn_extension(["http/1.1"])
            }
            server_hello_raw = build_raw_tls_server_hello(
                selected_cipher=selected_cipher,
                extensions_map=sh_exts,
                record_version=0x0303,
                handshake_version=0x0303
            )
            ja4s_fingerprint = calculate_ja4s(
                proto="t",
                tls_version=0x0303,
                selected_cipher=selected_cipher,
                extension_list=list(sh_exts.keys()),
                alpn_str="11"
            )

        # 3. ClientHello Packet
        ch_pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
                 IP(src=client_ip, dst=self.web_server_ip) / \
                 TCP(sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq, window=502) / \
                 Raw(load=client_hello_raw)
        ch_pkt.time = t
        packets.append(ch_pkt)
        c_seq += len(client_hello_raw)
        t += self.rng.uniform(0.001, 0.004)

        # 4. ServerHello Packet
        sh_pkt = Ether(src=self.server_mac, dst=self.client_mac) / \
                 IP(src=self.web_server_ip, dst=client_ip) / \
                 TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq, window=502) / \
                 Raw(load=server_hello_raw)
        sh_pkt.time = t
        packets.append(sh_pkt)
        s_seq += len(server_hello_raw)
        t += self.rng.uniform(0.001, 0.003)

        # 5. Encrypted Application Data Simulation (TLS Record 0x17)
        app_data_c = struct.pack(">BHH", 0x17, 0x0303, 128) + (b"\xaa" * 128)
        app_pkt_c = Ether(src=self.client_mac, dst=self.server_mac) / \
                    IP(src=client_ip, dst=self.web_server_ip) / \
                    TCP(sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq, window=502) / \
                    Raw(load=app_data_c)
        app_pkt_c.time = t
        packets.append(app_pkt_c)
        c_seq += len(app_data_c)
        t += self.rng.uniform(0.001, 0.003)

        app_data_s = struct.pack(">BHH", 0x17, 0x0303, 256) + (b"\xbb" * 256)
        app_pkt_s = Ether(src=self.server_mac, dst=self.client_mac) / \
                    IP(src=self.web_server_ip, dst=client_ip) / \
                    TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq, window=502) / \
                    Raw(load=app_data_s)
        app_pkt_s.time = t
        packets.append(app_pkt_s)
        s_seq += len(app_data_s)
        t += self.rng.uniform(0.001, 0.003)

        # 6. Graceful FIN Teardown
        fin_c = Ether(src=self.client_mac, dst=self.server_mac) / \
                IP(src=client_ip, dst=self.web_server_ip) / \
                TCP(sport=client_port, dport=server_port, flags="FA", seq=c_seq, ack=s_seq, window=502)
        fin_c.time = t
        packets.append(fin_c)
        c_seq += 1
        t += self.rng.uniform(0.0005, 0.001)

        fin_s = Ether(src=self.server_mac, dst=self.client_mac) / \
                IP(src=self.web_server_ip, dst=client_ip) / \
                TCP(sport=server_port, dport=client_port, flags="FA", seq=s_seq, ack=c_seq, window=502)
        fin_s.time = t
        packets.append(fin_s)
        s_seq += 1
        t += self.rng.uniform(0.0005, 0.001)

        ack_c = Ether(src=self.client_mac, dst=self.server_mac) / \
                IP(src=client_ip, dst=self.web_server_ip) / \
                TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq, window=502)
        ack_c.time = t
        packets.append(ack_c)
        t += self.rng.uniform(0.0005, 0.001)

        return packets, t, ja4_fingerprint, ja4s_fingerprint

    def generate_dataset(self, num_flows: int = 500) -> Tuple[List[Any], Dict[str, Any]]:
        """Synthesizes the complete benign dataset containing mixed HTTP, DNS, and TLS flows."""
        all_packets = []
        cur_time = 1756531200.0 # Deterministic base epoch (2025-08-30 00:00:00 UTC)
        ja4_samples = set()
        ja4s_samples = set()

        # Distribution: 40% TLS 1.3, 20% TLS 1.2, 20% HTTP, 20% DNS
        flow_types = (
            ["tls13"] * int(num_flows * 0.40) +
            ["tls12"] * int(num_flows * 0.20) +
            ["http"] * int(num_flows * 0.20) +
            ["dns"] * int(num_flows * 0.20)
        )
        self.rng.shuffle(flow_types)

        for ftype in flow_types:
            if ftype == "tls13":
                pkts, cur_time, ja4, ja4s = self.generate_tls_flow(cur_time, "1.3")
                ja4_samples.add(ja4)
                ja4s_samples.add(ja4s)
            elif ftype == "tls12":
                pkts, cur_time, ja4, ja4s = self.generate_tls_flow(cur_time, "1.2")
                ja4_samples.add(ja4)
                ja4s_samples.add(ja4s)
            elif ftype == "http":
                pkts, cur_time = self.generate_http_flow(cur_time)
            else: # dns
                pkts, cur_time = self.generate_dns_flow(cur_time)

            all_packets.extend(pkts)
            cur_time += self.rng.uniform(0.0005, 0.005)

        stats = {
            "total_packets": len(all_packets),
            "total_flows": len(flow_types),
            "ja4_fingerprints": list(ja4_samples),
            "ja4s_fingerprints": list(ja4s_samples)
        }
        return all_packets, stats


class SynFloodDatasetGenerator:
    """
    Generates a volumetric, high-rate TCP SYN flood attack dataset.
    """
    def __init__(self, target_ip: str = "192.168.10.50", target_ports: Optional[List[int]] = None, seed: int = 42):
        self.rng = random.Random(seed)
        self.target_ip = target_ip
        self.target_ports = target_ports or [80, 443, 8080]
        self.client_mac = "02:42:ac:11:00:99"
        self.server_mac = "02:42:ac:11:00:03"

    def generate_dataset(self, num_packets: int = 10000) -> Tuple[List[Any], Dict[str, Any]]:
        packets = []
        cur_time = 1756532000.0 # Deterministic start epoch

        for _ in range(num_packets):
            # Spoofed source IP from private & test subnets
            src_ip = f"172.16.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            src_port = self.rng.randint(1024, 65535)
            dport = self.rng.choice(self.target_ports)
            seq_num = self.rng.randint(100000, 4000000000)

            pkt = Ether(src=self.client_mac, dst=self.server_mac) / \
                  IP(src=src_ip, dst=self.target_ip) / \
                  TCP(sport=src_port, dport=dport, flags="S", seq=seq_num, window=64240,
                      options=[("MSS", 1460), ("SAckOK", b"")])
            pkt.time = cur_time
            packets.append(pkt)
            cur_time += self.rng.uniform(0.00001, 0.00005) # ~20,000 to 100,000 pps rate simulation

        stats = {
            "total_packets": len(packets),
            "target_ip": self.target_ip,
            "target_ports": self.target_ports
        }
        return packets, stats


class PortscanDatasetGenerator:
    """
    Generates realistic multi-mode reconnaissance port scan traffic:
    - TCP SYN stealth scan (-sS)
    - TCP Connect scan (-sT)
    - UDP port sweep (-sU)
    """
    def __init__(self, target_ip: str = "192.168.10.50", scanner_ip: str = "192.168.1.105", seed: int = 42):
        self.rng = random.Random(seed)
        self.target_ip = target_ip
        self.scanner_ip = scanner_ip
        self.scanner_mac = "02:42:ac:11:00:10"
        self.target_mac = "02:42:ac:11:00:03"
        self.open_ports = {21, 22, 53, 80, 443, 8080, 8443, 9092, 6379, 5432}

    def generate_dataset(self, num_ports: int = 1000) -> Tuple[List[Any], Dict[str, Any]]:
        packets = []
        cur_time = 1756533000.0

        ports_to_scan = list(range(1, min(num_ports + 1, 65535)))
        self.rng.shuffle(ports_to_scan)

        # 1. TCP SYN Stealth Scan (-sS)
        for dport in ports_to_scan[:int(num_ports * 0.5)]:
            sport = self.rng.randint(32768, 61000)
            seq_s = self.rng.randint(10000, 500000)

            # Scanner -> Target SYN
            syn_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                      IP(src=self.scanner_ip, dst=self.target_ip) / \
                      TCP(sport=sport, dport=dport, flags="S", seq=seq_s, window=1024)
            syn_pkt.time = cur_time
            packets.append(syn_pkt)
            cur_time += self.rng.uniform(0.0001, 0.0005)

            if dport in self.open_ports:
                # Target -> Scanner SYN-ACK
                seq_t = self.rng.randint(50000, 900000)
                syn_ack = Ether(src=self.target_mac, dst=self.scanner_mac) / \
                          IP(src=self.target_ip, dst=self.scanner_ip) / \
                          TCP(sport=dport, dport=sport, flags="SA", seq=seq_t, ack=seq_s + 1, window=65535)
                syn_ack.time = cur_time
                packets.append(syn_ack)
                cur_time += self.rng.uniform(0.0001, 0.0003)

                # Scanner -> Target RST (Stealth Scan finishes with RST)
                rst_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                          IP(src=self.scanner_ip, dst=self.target_ip) / \
                          TCP(sport=sport, dport=dport, flags="R", seq=seq_s + 1, window=0)
                rst_pkt.time = cur_time
                packets.append(rst_pkt)
                cur_time += self.rng.uniform(0.0001, 0.0003)
            else:
                # Target -> Scanner RST-ACK (Closed Port)
                rst_ack = Ether(src=self.target_mac, dst=self.scanner_mac) / \
                          IP(src=self.target_ip, dst=self.scanner_ip) / \
                          TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=seq_s + 1, window=0)
                rst_ack.time = cur_time
                packets.append(rst_ack)
                cur_time += self.rng.uniform(0.0001, 0.0003)

        # 2. TCP Connect Scan (-sT)
        for dport in ports_to_scan[int(num_ports * 0.5):int(num_ports * 0.8)]:
            sport = self.rng.randint(32768, 61000)
            seq_s = self.rng.randint(10000, 500000)

            # Scanner -> Target SYN
            syn_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                      IP(src=self.scanner_ip, dst=self.target_ip) / \
                      TCP(sport=sport, dport=dport, flags="S", seq=seq_s, window=64240)
            syn_pkt.time = cur_time
            packets.append(syn_pkt)
            cur_time += self.rng.uniform(0.0001, 0.0005)

            if dport in self.open_ports:
                seq_t = self.rng.randint(50000, 900000)
                syn_ack = Ether(src=self.target_mac, dst=self.scanner_mac) / \
                          IP(src=self.target_ip, dst=self.scanner_ip) / \
                          TCP(sport=dport, dport=sport, flags="SA", seq=seq_t, ack=seq_s + 1, window=65535)
                syn_ack.time = cur_time
                packets.append(syn_ack)
                cur_time += self.rng.uniform(0.0001, 0.0003)

                # Scanner -> Target ACK (Completes 3-way handshake)
                ack_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                          IP(src=self.scanner_ip, dst=self.target_ip) / \
                          TCP(sport=sport, dport=dport, flags="A", seq=seq_s + 1, ack=seq_t + 1, window=502)
                ack_pkt.time = cur_time
                packets.append(ack_pkt)
                cur_time += self.rng.uniform(0.0001, 0.0003)

                # Scanner -> Target RST teardown
                rst_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                          IP(src=self.scanner_ip, dst=self.target_ip) / \
                          TCP(sport=sport, dport=dport, flags="R", seq=seq_s + 1, window=0)
                rst_pkt.time = cur_time
                packets.append(rst_pkt)
                cur_time += self.rng.uniform(0.0001, 0.0003)
            else:
                rst_ack = Ether(src=self.target_mac, dst=self.scanner_mac) / \
                          IP(src=self.target_ip, dst=self.scanner_ip) / \
                          TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=seq_s + 1, window=0)
                rst_ack.time = cur_time
                packets.append(rst_ack)
                cur_time += self.rng.uniform(0.0001, 0.0003)

        # 3. UDP Port Sweep (-sU)
        udp_sweep_ports = [53, 67, 68, 69, 123, 137, 161, 162, 500, 514, 520, 1900, 4500, 5353]
        for dport in udp_sweep_ports:
            sport = self.rng.randint(32768, 61000)
            udp_payload = b"\x00" * 16

            udp_pkt = Ether(src=self.scanner_mac, dst=self.target_mac) / \
                      IP(src=self.scanner_ip, dst=self.target_ip) / \
                      UDP(sport=sport, dport=dport) / \
                      Raw(load=udp_payload)
            udp_pkt.time = cur_time
            packets.append(udp_pkt)
            cur_time += self.rng.uniform(0.0002, 0.001)

            if dport not in self.open_ports:
                # Closed UDP Port -> ICMP Port Unreachable (Type 3, Code 3)
                orig_ip = IP(src=self.scanner_ip, dst=self.target_ip) / UDP(sport=sport, dport=dport) / Raw(load=udp_payload[:8])
                icmp_pkt = Ether(src=self.target_mac, dst=self.scanner_mac) / \
                           IP(src=self.target_ip, dst=self.scanner_ip) / \
                           ICMP(type=3, code=3) / \
                           orig_ip
                icmp_pkt.time = cur_time
                packets.append(icmp_pkt)
                cur_time += self.rng.uniform(0.0002, 0.0005)

        stats = {
            "total_packets": len(packets),
            "scanned_ports_count": num_ports,
            "target_ip": self.target_ip,
            "scanner_ip": self.scanner_ip
        }
        return packets, stats


# ==============================================================================
# Main Generation Orchestrator
# ==============================================================================

def generate_all_datasets(
    output_dir: str = "data/pcaps",
    benign_flows: int = 500,
    syn_flood_pkts: int = 10000,
    scan_ports: int = 1000,
    attack_types: Optional[List[str]] = None,
    seed: int = 42
) -> Dict[str, str]:
    """
    Generates all requested synthetic PCAPs into output_dir deterministically.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    generated_files = {}

    if attack_types is None or "all" in attack_types:
        do_benign = True
        do_syn_flood = True
        do_portscan = True
    else:
        do_benign = "benign" in attack_types or "baseline" in attack_types
        do_syn_flood = "syn_flood" in attack_types or "ddos" in attack_types
        do_portscan = "portscan" in attack_types or "scan" in attack_types

    print("=================================================================")
    print("  SIH26145 Synthetic PCAP Dataset Generator")
    print("=================================================================")
    print(f"[*] Target Output Directory: {out_path.resolve()}")
    print(f"[*] Random Seed:             {seed}")
    print("-----------------------------------------------------------------")

    # 1. Benign Baseline PCAP
    if do_benign:
        print(f"[*] Generating Benign Baseline Dataset ({benign_flows} flows)...")
        benign_gen = BenignDatasetGenerator(seed=seed)
        benign_pkts, benign_stats = benign_gen.generate_dataset(num_flows=benign_flows)
        benign_file = out_path / "benign_baseline.pcap"
        wrpcap(str(benign_file), benign_pkts)
        file_size_kb = benign_file.stat().st_size / 1024.0
        generated_files["benign_baseline"] = str(benign_file)
        print(f"    -> Written: {benign_file.name} ({len(benign_pkts)} pkts, {file_size_kb:.2f} KB)")
        print(f"    -> JA4 Sample Fingerprints:  {', '.join(benign_stats['ja4_fingerprints'][:2])}")
        print(f"    -> JA4S Sample Fingerprints: {', '.join(benign_stats['ja4s_fingerprints'][:2])}")

    # 2. DDoS SYN Flood PCAP
    if do_syn_flood:
        print(f"[*] Generating DDoS SYN Flood Dataset ({syn_flood_pkts} packets)...")
        syn_gen = SynFloodDatasetGenerator(seed=seed)
        syn_pkts, _ = syn_gen.generate_dataset(num_packets=syn_flood_pkts)
        syn_file = out_path / "ddos_syn_flood.pcap"
        wrpcap(str(syn_file), syn_pkts)
        file_size_kb = syn_file.stat().st_size / 1024.0
        generated_files["ddos_syn_flood"] = str(syn_file)
        print(f"    -> Written: {syn_file.name} ({len(syn_pkts)} pkts, {file_size_kb:.2f} KB)")

    # 3. Port Scan PCAP
    if do_portscan:
        print(f"[*] Generating Port Scan Dataset ({scan_ports} ports sweep)...")
        scan_gen = PortscanDatasetGenerator(seed=seed)
        scan_pkts, _ = scan_gen.generate_dataset(num_ports=scan_ports)
        scan_file = out_path / "portscan_nmap.pcap"
        wrpcap(str(scan_file), scan_pkts)
        file_size_kb = scan_file.stat().st_size / 1024.0
        generated_files["portscan_nmap"] = str(scan_file)
        print(f"    -> Written: {scan_file.name} ({len(scan_pkts)} pkts, {file_size_kb:.2f} KB)")

    print("=================================================================")
    print(f"[+] All requested PCAPs successfully generated ({len(generated_files)} files).")
    return generated_files


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic Synthetic PCAP Generator for SIH26145 Testing & Ingestion Benchmark"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/pcaps",
        help="Directory to save generated PCAPs (default: data/pcaps)"
    )
    parser.add_argument(
        "--flows", "--benign-flows",
        type=int,
        default=500,
        help="Number of benign flows to synthesize (default: 500)"
    )
    parser.add_argument(
        "--syn-flood-packets",
        type=int,
        default=10000,
        help="Number of SYN flood packets (default: 10000)"
    )
    parser.add_argument(
        "--scan-ports",
        type=int,
        default=1000,
        help="Number of ports to sweep in port scan (default: 1000)"
    )
    parser.add_argument(
        "--attack-types",
        type=str,
        default="all",
        help="Comma-separated attack types to generate: all, benign, syn_flood, portscan (default: all)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed (default: 42)"
    )

    args = parser.parse_args()
    attacks = [a.strip().lower() for a in args.attack_types.split(",") if a.strip()]

    generate_all_datasets(
        output_dir=args.output_dir,
        benign_flows=args.flows,
        syn_flood_pkts=args.syn_flood_packets,
        scan_ports=args.scan_ports,
        attack_types=attacks,
        seed=args.seed
    )


if __name__ == "__main__":
    main()
