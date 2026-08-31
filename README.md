# sih-cyber-threat-2026

### Autonomous Passive Network Threat Detection & Out-of-Band Countermeasure Generation for Data Diode Environments

**Smart India Hackathon 2026** | **Problem Statement:** SIH26145 | **Sponsoring Org:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Status:** Phase 0, Phase 1, and Phase 2 Complete (383/383 Tests Passing, Line-Rate Benchmark Verified)

---

## 1. Executive Summary

Critical infrastructure networks deploy hardware **data diodes** (physical one-way optical links) at gateway and peering points. The monitoring enclave observes incoming network traffic with **zero physical or protocol return path** into the production network, permanently eliminating the risk of a compromised security sensor becoming an active attack pivot.

This repository provides a high-throughput, passive network detection pipeline that ingests unencrypted flow telemetry, analyzes it across **six parallel streaming threat detectors**, and prepares structured, ready-to-deploy **countermeasure artifacts** for authorized human deployment.

---

## 2. High-Level Architecture

```
                                  =========================================
                                     UNIDIRECTIONAL SECURITY BOUNDARY
                                  =========================================
 [ Production Network Link ]
              │ (Physical Optical Tap / Span Port)
              ▼
   ┌─────────────────────┐
   │ Hardware Data Diode │ (Physical 1-way fiber TX -> RX only, no reverse path)
   └──────────┬──────────┘
              │ (Passive Traffic Mirror)
              ▼
 ╔═════════════════════════════════════════════════════════════════════════╗
 ║                     MONITORING ENCLAVE (READ-ONLY)                      ║
 ║                                                                         ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 0: High-Speed Ingest & Passive DPI (Zeek)             │       ║
 ║   │ • Connection Logs (conn.log, UID, Community ID)             │       ║
 ║   │ • DNS Query/Response Logs (dns.log, entropy, NXDOMAIN)      │       ║
 ║   │ • SSL/TLS Handshake Logs (ssl.log, x509.log)                │       ║
 ║   │ • Native JA4/JA4S Client/Server Handshake Fingerprints      │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ║                                  │ (JSON Stream / Kafka Producer)       ║
 ║                                  ▼                                      ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 1: Partitioned Streaming Backbone (Redpanda / Kafka)  │       ║
 ║   │ • Partitioned by hash(source_ip) for lock-free locality     │       ║
 ║   │ • Topics: telemetry.conn, telemetry.dns, telemetry.ssl      │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ║                                  │                                      ║
 ║                                  ▼                                      ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 2: Six Parallel Streaming Threat Detectors            │       ║
 ║   │ 1. Volumetric DDoS: Sliding Shannon Entropy + EWMA Rate     │       ║
 ║   │ 2. Port Scanning: HyperLogLog (HLL) Target Cardinality      │       ║
 ║   │ 3. Data Exfiltration: Per-Host In/Out Byte Ratio Baselines  │       ║
 ║   │ 4. DGA & DNS Tunnelling: Character-Level ONNX Classifier    │       ║
 ║   │ 5. Encrypted Malware: JA4 Threat Intel Match + Anomalies    │       ║
 ║   │ 6. C2 Beaconing: Delta-T Circular Buffer & CV Dispersion    │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ║                                  │ (Raw Streaming Alerts -> alerts.raw) ║
 ║                                  ▼                                      ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 3: Fast In-Memory Aggregator & CEP Buffer (Redis)     │       ║
 ║   │ • Sliding correlation window (30s–120s)                     │       ║
 ║   │ • Multi-detector alert fusion & deduplication               │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ║                                  │ (Fused Incident Context)             ║
 ║                                  ▼                                      ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 4: LangGraph Agentic Triage & Countermeasure Engine   │       ║
 ║   │ • Weighted-Evidence Explainable Risk Scoring                │       ║
 ║   │ • MITRE ATT&CK Mapping & Kill-Chain Narrative               │       ║
 ║   │ • Deterministic Countermeasure Artifact Generation          │       ║
 ║   │   (iptables, Cisco ACL, DNS RPZ, Snort/Suricata, STIX 2.1)  │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ║                                  │                                      ║
 ║                                  ▼                                      ║
 ║   ┌─────────────────────────────────────────────────────────────┐       ║
 ║   │ Layer 5: Storage & Human-in-the-Loop Defense UI             │       ║
 ║   │ • PostgreSQL / TimescaleDB Hypertables                      │       ║
 ║   │ • FastAPI WebSockets + Next.js Cyberpunk SOC Dashboard     │       ║
 ║   └──────────────────────────────┬──────────────────────────────┘       ║
 ╚══════════════════════════════════╪══════════════════════════════════════╝
                                    │
                                    ▼ (Out-of-Band Dispatches ONLY)
    ┌──────────────────────────────────────────────────────────────────┐
    │ Out-of-Band Integrations (Physically Separate Channel)           │
    │ • SOC Webhooks / Slack / Email / SIEM Ingest (STIX 2.1)          │
    │ • Human Security Operator Reviews & Manually Deploys Rules       │
    │ ⚠️ ZERO DIRECT EXECUTION ON PRODUCTION NETWORK                   │
    └──────────────────────────────────────────────────────────────────┘
```

---

## 3. The Six Streaming Threat Detectors

All detectors inherit from `BaseDetector` and process streaming events lock-free, partitioned by `hash(source_ip)`:

| # | Detector Module | Algorithmic Mechanism | Target Topic | Typical Latency | SLA |
|---|---|---|---|---|---|
| **1** | `src/detectors/ddos_entropy.py` | Sliding Shannon Entropy $H(X_{\text{dport}}) = -\sum P(x)\log_2 P(x)$ on target ports + EWMA rate variance $Z$-score. | `telemetry.conn` | $\sim 18\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |
| **2** | `src/detectors/portscan_hll.py` | Dual-bucket HyperLogLog (HLL, $p=10$) tracking distinct target IPs/ports in rolling 10s windows ($O(1)$ memory). | `telemetry.conn` | $\sim 12\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |
| **3** | `src/detectors/exfil_ratio.py` | Directional asymmetric byte ratios ($R_{\text{out/in}}$) against dynamic $P^2$ streaming quantile baselines (P95, P99). | `telemetry.conn` | $\sim 28\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |
| **4** | `src/detectors/dga_lstm.py` | Character-level domain classifier (ONNX Runtime) + subdomain Shannon entropy & NXDOMAIN/TXT ratio tracking. | `telemetry.dns` | $\sim 24\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |
| **5** | `src/detectors/ja4_malware.py` | Exact matching of JA4/JA4S fingerprints against threat intel (Cobalt Strike, Sliver, Emotet) + 5-feature TLS anomaly scoring. | `telemetry.ssl` | $\sim 9\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |
| **6** | `src/detectors/c2_beacon.py` | Streaming Delta-T circular buffer ($N=25$) tracking Coefficient of Variation ($CV = \sigma/\mu < 0.15$), median interval, and dispersion. | `telemetry.conn` | $\sim 15\,\mu\text{s}$ | $< 500\,\mu\text{s}$ |

---

## 4. Benchmark & Test Verification Results

### Automated Test Suite
```bash
pytest
======================= 383 passed in 128.03s =======================
```
- **Total Test Cases**: **383 / 383 Passed (100% Pass Rate)**
- **Test Categories**: Unit tests, adversarial challenge tests, boundary stress tests, JA4 protocol conformance, and E2E multi-detector integration tests.

### Line-Rate Throughput Benchmark Summary
*Target Pipeline: Traffic Replay $\rightarrow$ Zeek (JA4) $\rightarrow$ Redpanda $\rightarrow$ TimescaleDB*

| Metric Dimension | Measured Result | Target SLA | Margin / Delta | Verdict |
|---|---|---|---|---|
| **Sustained Ingest Rate** | **14,987.78 EPS** | $\ge 10,000\text{ EPS}$ | **+49.9%** | **PASS** |
| **Peak Ingest Rate** | **17,699.37 EPS** | $\ge 12,500\text{ EPS}$ | **+41.6%** | **PASS** |
| **Line Rate Throughput** | **122.78 Mbps** | $\ge 100.0\text{ Mbps}$ | **+22.8%** | **PASS** |
| **Ingest Latency ($p95$)** | **51.12 ms** | $\le 250.0\text{ ms}$ | **-79.6%** (Faster) | **PASS** |
| **Packet Loss Rate** | **0.00%** (0 drops) | $\le 0.10\%$ | **0 drops** | **PASS** |
| **Per-Event Latency** | **$8\,\mu\text{s} - 35\,\mu\text{s}$** | $\le 1000\,\mu\text{s}$ | **-96.5%** (Faster) | **PASS** |

---

## 5. Repository Structure

```
SIH/
├── config/
│   ├── db/01_init.sql                 # PostgreSQL base schema
│   ├── redis/redis.conf               # Redis CEP configuration
│   ├── redpanda/redpanda.yaml         # Redpanda broker settings
│   ├── timescale/init.sql             # Partitioned TimescaleDB hypertables
│   └── zeek/
│       ├── Dockerfile                 # Zeek 7.x build with JA4
│       ├── entrypoint.sh              # Zeek sensor startup script
│       ├── ja4.zeek                   # JA4/JA4S fingerprinting script
│       └── local.zeek                 # Structured JSON logging config
├── data/
│   └── pcaps/
│       ├── benign_baseline.pcap       # Clean TLS/DNS/HTTP traffic
│       ├── ddos_syn_flood.pcap        # High-rate SYN flood capture
│       └── portscan_nmap.pcap         # Stealth SYN port sweep
├── scripts/
│   ├── generate_datasets.py           # Scapy PCAP generator
│   ├── replay_traffic.py              # Token-bucket packet streamer
│   ├── run_30s_benchmark.py           # 30-second benchmark runner
│   ├── start_infrastructure.ps1 / .sh # Multi-container startup scripts
│   ├── stop_infrastructure.ps1 / .sh  # Teardown scripts
│   └── train_dga_model.py             # DGA model export script
├── src/
│   ├── detectors/
│   │   ├── base.py                    # Lock-free BaseDetector ABC
│   │   ├── c2_beacon.py               # Detector 6: C2 Beaconing (CV < 0.15)
│   │   ├── ddos_entropy.py            # Detector 1: Volumetric DDoS Entropy
│   │   ├── detector_manager.py        # Concurrent Multi-Detector Manager
│   │   ├── dga_lstm.py                # Detector 4: DGA ONNX Classifier
│   │   ├── exfil_ratio.py             # Detector 3: Exfiltration P² Baselines
│   │   ├── ja4_malware.py             # Detector 5: Encrypted Malware JA4
│   │   └── portscan_hll.py            # Detector 2: Portscan HyperLogLog
│   ├── ingestion/
│   │   ├── kafka_producer.py          # Partitioned Kafka/Redpanda producer
│   │   ├── models.py                  # Pydantic telemetry & alert schemas
│   │   ├── streaming_bus.py           # Partitioned streaming event bus
│   │   └── zeek_log_tailer.py         # Streaming JSON log tailer
│   ├── threat_intel/
│   │   └── ja4_malware_database.json  # Curated JA4 malware signatures
│   └── utils/
│       ├── metrics_calculator.py      # Statistical throughput profiler
│       └── p2_quantile.py             # P² streaming quantile estimator
├── tests/                             # 383 Unit, E2E & Latency Test Cases
├── docker-compose.yml                 # Multi-service stack
├── benchmark_results.md               # Detailed Day-1 benchmark report
├── PHASED_IMPLEMENTATION_PLAN.md      # Full 6-phase engineering plan
└── README.md
```

---

## 6. Quickstart & Execution

### Prerequisites
- Python 3.11+
- Docker & Docker Compose
- Git

### 1. Launch Infrastructure
```bash
# Windows
.\scripts\start_infrastructure.ps1

# Linux / macOS
chmod +x ./scripts/*.sh
./scripts/start_infrastructure.sh
```

### 2. Run Test Suite
```bash
pytest
```

### 3. Run Throughput Benchmark
```bash
python tests/throughput_benchmark.py
```

### 4. Run Individual Detector Latency Profiler
```bash
pytest tests/test_detectors_latency.py -v -s
```

---

## 7. Roadmap & Next Steps

- [x] **Phase 0**: Containerized infrastructure, traffic replay harness, and Day-1 throughput benchmark.
- [x] **Phase 1**: Ingest & partitioning pipeline with deterministic `hash(source_ip)` flow locality.
- [x] **Phase 2**: Six parallel streaming threat detectors with sub-millisecond per-event latency.
- [ ] **Phase 3**: Fast In-Memory Aggregator & Complex Event Processing (CEP) sliding window buffer.
- [ ] **Phase 4**: LangGraph Agentic Triage Engine & Deterministic Out-of-Band Countermeasure Generation.
- [ ] **Phase 5**: Real-time FastAPI WebSocket backend & Next.js Cyberpunk SOC Analyst Dashboard.
- [ ] **Phase 6**: Multi-stage APT end-to-end rehearsal and judge demonstration.

---

## 8. License

Developed for **Smart India Hackathon 2026** (Problem Statement SIH26145 - NTRO). All rights reserved.
