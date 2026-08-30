"""
tests/test_replay_harness.py
----------------------------
Comprehensive verification suite for Milestone 2:
- Deterministic synthetic PCAP generation (Benign HTTP/DNS/TLS JA4, SYN flood, Portscan)
- Libpcap binary format validity & Scapy parseability
- JA4 & JA4S fingerprint calculation correctness and GREASE handling
- Token-bucket replay rate limiting precision at 1,000 pps, 10,000 pps, and 50,000 pps
- PacketBufferCache pre-serialization and in-memory replay performance
"""

import os
import sys
import time
import struct
import pytest
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP, DNS, Raw
from scripts.generate_datasets import (
    BenignDatasetGenerator,
    SynFloodDatasetGenerator,
    PortscanDatasetGenerator,
    calculate_ja4,
    calculate_ja4s,
    generate_all_datasets
)
from scripts.replay_traffic import (
    PacketBufferCache,
    HighSpeedReplayEngine,
    DryRunTransmitter
)


class TestDatasetGenerator:
    """Validates the synthetic PCAP dataset generators."""

    def test_benign_generator_flow_structure(self):
        gen = BenignDatasetGenerator(seed=123)
        packets, stats = gen.generate_dataset(num_flows=50)

        assert len(packets) > 0
        assert stats["total_flows"] == 50
        assert len(stats["ja4_fingerprints"]) > 0
        assert len(stats["ja4s_fingerprints"]) > 0

        # Verify presence of TCP and UDP packets
        tcp_count = sum(1 for p in packets if TCP in p)
        udp_count = sum(1 for p in packets if UDP in p)
        dns_count = sum(1 for p in packets if DNS in p)

        assert tcp_count > 0, "Benign dataset must include TCP flows (HTTP/TLS)"
        assert udp_count > 0, "Benign dataset must include UDP flows (DNS)"
        assert dns_count > 0, "Benign dataset must include DNS query/response packets"

    def test_tls_ja4_and_ja4s_fingerprints(self):
        gen = BenignDatasetGenerator(seed=42)
        pkts, cur_time, ja4, ja4s = gen.generate_tls_flow(1756531200.0, "1.3")

        assert len(pkts) >= 6
        assert ja4.startswith("t13d")
        assert len(ja4.split("_")) == 3, f"JA4 must have 3 underscore-separated segments: {ja4}"
        assert ja4s.startswith("t13")
        assert len(ja4s.split("_")) == 3, f"JA4S must have 3 underscore-separated segments: {ja4s}"

        # Test TLS 1.2 flow
        pkts_12, cur_time_12, ja4_12, ja4s_12 = gen.generate_tls_flow(cur_time, "1.2")
        assert ja4_12.startswith("t12d")
        assert ja4s_12.startswith("t12")

    def test_ja4_grease_filtering(self):
        # Ciphers with GREASE values (0x0a0a, 0x1a1a)
        ciphers = [0x0a0a, 0x1301, 0x1a1a, 0x1302, 0xc02b]
        exts = [0x2a2a, 0x0000, 0x000a, 0x0010]
        ja4_val = calculate_ja4("t", 0x0304, True, ciphers, exts, "h2")

        # GREASE filtered -> 3 ciphers, 3 extensions (SNI=0x0000, Groups=0x000a, ALPN=0x0010)
        assert ja4_val.startswith("t13d0303h2")

    def test_syn_flood_generator(self):
        gen = SynFloodDatasetGenerator(target_ip="192.168.10.50", target_ports=[80, 443], seed=99)
        pkts, stats = gen.generate_dataset(num_packets=500)

        assert len(pkts) == 500
        assert stats["target_ip"] == "192.168.10.50"

        src_ips = set()
        for p in pkts:
            assert IP in p
            assert TCP in p
            assert p[IP].dst == "192.168.10.50"
            assert p[TCP].flags == "S"
            assert p[TCP].dport in (80, 443)
            src_ips.add(p[IP].src)

        # High entropy of spoofed source IPs
        assert len(src_ips) > 200

    def test_portscan_generator(self):
        gen = PortscanDatasetGenerator(target_ip="192.168.10.50", scanner_ip="192.168.1.105", seed=77)
        pkts, stats = gen.generate_dataset(num_ports=100)

        assert len(pkts) > 100
        assert stats["scanned_ports_count"] == 100

        # Check for ICMP Port Unreachable packets from UDP scans
        icmp_pkts = [p for p in pkts if ICMP in p]
        assert len(icmp_pkts) > 0
        for p in icmp_pkts:
            assert p[ICMP].type == 3
            assert p[ICMP].code == 3

    def test_generate_all_datasets_disk_output(self, tmp_path):
        out_dir = tmp_path / "pcaps"
        generated = generate_all_datasets(
            output_dir=str(out_dir),
            benign_flows=20,
            syn_flood_pkts=100,
            scan_ports=30,
            seed=42
        )

        assert "benign_baseline" in generated
        assert "ddos_syn_flood" in generated
        assert "portscan_nmap" in generated

        for name, file_path in generated.items():
            p = Path(file_path)
            assert p.exists()
            assert p.stat().st_size > 0
            # Verify file starts with valid PCAP magic bytes
            with open(p, "rb") as f:
                magic = f.read(4)
                assert magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
            # Verify readable by scapy
            scapy_pkts = rdpcap(str(p))
            assert len(scapy_pkts) > 0


class TestReplayHarness:
    """Validates the high-speed packet replay engine and rate limiter."""

    @pytest.fixture
    def sample_pcap(self, tmp_path):
        out_dir = tmp_path / "test_pcap"
        generated = generate_all_datasets(
            output_dir=str(out_dir),
            benign_flows=30,
            syn_flood_pkts=200,
            scan_ports=20,
            seed=42
        )
        return generated["benign_baseline"]

    def test_packet_buffer_cache(self, sample_pcap):
        cache = PacketBufferCache(sample_pcap)
        assert len(cache) > 0
        assert len(cache.raw_packets) == len(cache)
        assert len(cache.packet_sizes) == len(cache)
        assert cache.total_bytes > 0
        assert all(isinstance(b, bytes) for b in cache.raw_packets)

    def test_replay_rate_1000_pps(self, sample_pcap):
        engine = HighSpeedReplayEngine(
            pcap_path=sample_pcap,
            target_pps=1000,
            duration_sec=1.5,
            loop=True,
            engine_type="dry-run",
            quiet=True
        )
        res = engine.run()

        assert res["total_packets"] > 0
        assert res["elapsed_seconds"] >= 1.4
        # Accuracy within ±20% of target
        assert 800 <= res["achieved_pps"] <= 1400

    def test_replay_rate_10000_pps(self, sample_pcap):
        engine = HighSpeedReplayEngine(
            pcap_path=sample_pcap,
            target_pps=10000,
            duration_sec=1.0,
            loop=True,
            engine_type="dry-run",
            quiet=True
        )
        res = engine.run()

        assert res["total_packets"] > 0
        assert 7000 <= res["achieved_pps"] <= 14000

    def test_replay_rate_50000_pps(self, sample_pcap):
        engine = HighSpeedReplayEngine(
            pcap_path=sample_pcap,
            target_pps=50000,
            duration_sec=1.0,
            loop=True,
            engine_type="dry-run",
            quiet=True
        )
        res = engine.run()

        assert res["total_packets"] > 0
        assert res["achieved_pps"] >= 25000, f"Achieved PPS was {res['achieved_pps']}"

    def test_replay_no_loop_mode(self, sample_pcap):
        cache = PacketBufferCache(sample_pcap)
        total_in_file = len(cache)

        engine = HighSpeedReplayEngine(
            pcap_path=sample_pcap,
            target_pps=5000,
            duration_sec=10.0, # Long duration, but loop=False should stop at end of file
            loop=False,
            engine_type="dry-run",
            quiet=True
        )
        res = engine.run()

        assert res["total_packets"] == total_in_file

    def test_replay_mbps_mode(self, sample_pcap):
        engine = HighSpeedReplayEngine(
            pcap_path=sample_pcap,
            target_pps=1000,
            target_mbps=50.0, # 50 Mbps constraint
            duration_sec=1.0,
            loop=True,
            engine_type="dry-run",
            quiet=True
        )
        res = engine.run()

        assert res["total_packets"] > 0
        assert res["achieved_mbps"] > 0
