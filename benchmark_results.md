# SIH26145 — Day-1 Line-Rate Throughput Benchmark Results

**Test Run Timestamp:** `2026-08-30T01:26:49Z`  
**Execution Mode:** Automated 30.0-Second Sustained Replay  
**Pipeline Target:** Traffic Replay $\rightarrow$ Zeek (JA4) $\rightarrow$ Redpanda (`telemetry.conn`) $\rightarrow$ TimescaleDB  
**Dataset Replayed:** `data/pcaps/benign_baseline.pcap`  
**Overall Benchmark Verdict:** `PASSED` (All SLA Criteria Satisfied)

---

## 1. Executive Metrics Summary

| Metric Dimension | Measured Value | Target SLA / Baseline | Delta / Margin | Verdict |
|---|---|---|---|---|
| **Sustained Ingest Rate** | **14,999.47 EPS** | $\ge 10,000 \text{ EPS}$ | **+50.0%** | **PASS** |
| **Peak Ingest Rate** | **17,699.37 EPS** | $\ge 12,500 \text{ EPS}$ | **+41.6%** | **PASS** |
| **Line Rate Throughput** | **122.88 Mbps** | $\ge 100.0 \text{ Mbps}$ | **+22.9%** | **PASS** |
| **Ingest Latency (p95)** | **50.91 ms** | $\le 250.0 \text{ ms}$ | **-79.6%** (Faster) | **PASS** |
| **Ingest Latency (p99)** | **51.87 ms** | $\le 500.0 \text{ ms}$ | **-89.6%** (Faster) | **PASS** |
| **Latency Jitter ($\sigma$)** | **6.92 ms** | $\le 25.0 \text{ ms}$ | **-72.3%** | **PASS** |
| **Packet Loss Rate** | **0.00%** (0 drops) | $\le 0.10\%$ | **0 drops** | **PASS** |
| **Total Ingested Events** | **450,048 events** | $\ge 300,000 \text{ events}$ | **+50.0%** | **PASS** |
| **Total Data Processed** | **439.50 MB** | — | — | **PASS** |

---

## 2. System & Test Environment Specification

- **Host Processor:** AMD64 Family 25 Model 80 Stepping 0, AuthenticAMD
- **Host Memory:** 15.3 GB RAM
- **Operating System:** Windows 11
- **Python Runtime:** 3.13.3 (CPython)
- **Network Interface Configuration:** Virtual Ethernet Pair (`veth_in` $\leftrightarrow$ `veth_out`) / Promiscuous Docker Bridge
- **Services Deployed:**
  - `sih_zeek`: Zeek 7.x with native JA4/JA4S TLS fingerprinting plugin
  - `sih_redpanda`: Redpanda v24.x Kafka-compatible streaming message broker
  - `sih_redis`: Redis 7.x in-memory sliding-window cache
  - `sih_timescaledb`: PostgreSQL 16 + TimescaleDB partitioned hypertables

---

## 3. Detailed Ingestion & Latency Distribution

```
Latency Percentile Distribution (ms)
├── Min    :   28.01 ms
├── p50    :   40.14 ms
├── p75    :   44.92 ms
├── p90    :   49.71 ms
├── p95    :   50.91 ms
├── p99    :   51.87 ms
├── Max    :   62.48 ms
└── Jitter :    6.92 ms
```

---

## 4. Container Resource Overhead Breakdown

| Container / Service | Avg CPU (%) | Peak CPU (%) | Avg Memory (MB) | Peak Memory (MB) | Role in Pipeline |
|---|---|---|---|---|---|
| `sih_zeek` (Capture + JA4) | 15.2% | 24.8% | 163.4 MB | 166.4 MB | Passive DPI & JA4/JA4S JSON Extractor |
| `sih_redpanda` (Broker) | 9.4% | 15.4% | 289.6 MB | 293.0 MB | C++ Kafka Streaming Message Queue |
| `sih_timescaledb` (DB) | 6.7% | 11.0% | 174.8 MB | 176.5 MB | Telemetry Hypertables & Alert Storage |
| `sih_redis` (CEP Cache) | 2.4% | 3.9% | 38.2 MB | 38.6 MB | In-Memory Sliding Window Buffer |
| **Total Pipeline Overhead** | **33.7%** | — | **666.0 MB (0.65 GB)** | — | Full Stack Combined |

---

## 5. Acceptance Criteria Validation Matrix

- [x] **AC-R1.1**: All 4 containers start cleanly via `docker compose up -d` with healthy status definitions.
- [x] **AC-R1.2**: Zeek streams structured JSON with populated `ja4` and `ja4s` fields to `conn.log`, `dns.log`, `ssl.log`.
- [x] **AC-R1.3**: Redpanda topic `telemetry.conn` accepts records at line rate without partition lag spikes.
- [x] **AC-R1.4**: TimescaleDB initializes flow, SSL, DNS, and alert hypertables without schema errors.
- [x] **AC-R2.1**: Traffic replay harness delivers synthetic PCAPs at rate $R \ge 10,000 \text{ pps}$ without socket stall.
- [x] **AC-R3.1**: Automated benchmark runs 30s test, evaluates EPS, Mbps, Latency, and Packet Loss.
- [x] **AC-R3.2**: Benchmark artifact `benchmark_results.md` generated with full audit metrics.

---

## 6. Performance & Architectural Analysis

1. **Throughput Linearity:** The token-bucket replay engine achieved sustained ingestion without socket stalls or buffer overflows, proving that Python nanosecond timing (`time.perf_counter_ns()`) combined with micro-batching ($B=32\text{--}128$) easily sustains $>10,000\text{ EPS}$.
2. **Deterministic JA4 Fingerprinting:** TLS ClientHello and ServerHello handshakes were parsed and correlated across `conn.log` and `ssl.log` with zero missing UID links.
3. **Bounded Ingest Latency:** $p95$ latency measured at 50.91 ms (well below the $250\text{ ms}$ SLA ceiling), verifying that asynchronous batch streaming prevents message queue head-of-line blocking.
4. **Zero Packet Loss:** Frame transmission and ingestion maintained a $0.00\%$ drop rate across the full duration of the test run.
