# sih-cyber-threat-2026

### Autonomous Passive Network Threat Detection & Out-of-Band Countermeasure Generation for Data Diode Environments

**Smart India Hackathon 2026** | **Problem Statement:** SIH26145 | **Sponsoring Org:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity

---

## 1. Overview

Critical infrastructure organizations deploy hardware **data diodes** (one-way optical taps) on gateway and peering links. The monitoring enclave ingests passively observed traffic with **zero physical return path** into the production network, preventing the monitoring system from being used as an attack pivot.

This project delivers an end-to-end, high-throughput passive threat detection and response pipeline capable of:
1. Ingesting high-speed network telemetry passively via **Zeek** with native **JA4/JA4S** fingerprinting.
2. Streaming telemetry across **Kafka/Redpanda** with flow-locality partitioning.
3. Parallel execution of **six streaming detection algorithms** (DDoS Entropy, Portscan HLL, Exfil Ratio, DGA LSTM ONNX, JA4 Malware Match, C2 Streaming Beaconing).
4. Multi-alert correlation and explainable risk scoring via a **LangGraph Agentic Triage Engine**.
5. Generating deterministic, ready-to-deploy **countermeasure artifacts** (iptables, Cisco ACL, BIND/Unbound DNS RPZ, Snort/Suricata rules, STIX 2.1 JSON) for authorized out-of-band human execution.

---

## 2. Architecture

```
[ Production Link ] ──(Data Diode / Optical Tap)──▶ [ Monitoring Enclave ]
                                                            │
                                                     ┌──────▼──────┐
                                                     │ Zeek + JA4  │
                                                     └──────┬──────┘
                                                            ▼
                                                     ┌─────────────┐
                                                     │  Redpanda   │
                                                     └──────┬──────┘
                                                            ▼
                                                ┌───────────────────────┐
                                                │ 6 Parallel Detectors  │
                                                └───────────┬───────────┘
                                                            ▼
                                                ┌───────────────────────┐
                                                │ Redis CEP Aggregator  │
                                                └───────────┬───────────┘
                                                            ▼
                                                ┌───────────────────────┐
                                                │ LangGraph AI Triage   │
                                                └───────────┬───────────┘
                                                            ▼
                                                ┌───────────────────────┐
                                                │ Out-of-Band SOC Alert │
                                                │ (Human Approval Only) │
                                                └───────────────────────┘
```

---

## 3. Phase 0 Line-Rate Benchmark Results

| Metric | Target SLA | Measured Result | Verdict |
|---|---|---|---|
| **Sustained Ingest Rate** | $\ge 10,000 \text{ EPS}$ | **14,999.47 EPS** | **PASS** |
| **Line Rate Throughput** | $\ge 100.0 \text{ Mbps}$ | **122.88 Mbps** | **PASS** |
| **Ingest Latency (p95)** | $\le 250.0 \text{ ms}$ | **50.91 ms** | **PASS** |
| **Packet Loss Rate** | $\le 0.10\%$ | **0.00%** (0 drops) | **PASS** |
| **Test Suite Health** | 100% pass | **148 / 148 Tests Passed** | **PASS** |

---

## 4. Quickstart

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Git

### Start Infrastructure
```bash
# Windows
.\scripts\start_infrastructure.ps1

# Linux / macOS
chmod +x ./scripts/*.sh
./scripts/start_infrastructure.sh
```

### Run Tests & Benchmark
```bash
pytest
python tests/throughput_benchmark.py
```
