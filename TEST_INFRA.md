# Test Architecture & 4-Tier Test Infrastructure Specification

## SIH26145 Passive Network Monitoring System — Phase 0

---

## 1. Overview & Quality Mandate

Phase 0 of the SIH26145 Passive Network Monitoring System establishes the containerized foundation, high-speed deterministic traffic replay engine, and Day-1 throughput benchmark suite. To ensure industrial-grade reliability and defense-readiness in a passive data diode monitoring enclave, all testing follows a rigorous **4-Tier Test Methodology**.

### Core Integrity Rules
- **No Facade Tests**: Zero mock passes that do not exercise real protocol logic, token-bucket math, DDL structures, or cryptographic hash routines.
- **Progressive Testability**: All tests are runnable against Phase 0 artifacts without forward-dependency on unbuilt ML detection phases.
- **Deterministic Oracles**: Expected outputs are derived directly from RFCs (TLS 1.2/1.3, JA4 FoxIO standard, libpcap format), SQL standards, and `PROJECT.md` interface contracts.

---

## 2. 4-Tier Test Methodology

| Tier | Category | Minimum Requirement | Purpose |
|---|---|---|---|
| **Tier 1** | **Core Feature Coverage** | $\ge 5$ tests per feature | Validate primary functional paths, container definitions, topic creation, and wire formats. |
| **Tier 2** | **Boundary & Corner Cases** | $\ge 5$ tests per feature | Test extremes ($1\text{ pps} \to 50,000+\text{ pps}$), GREASE filtering, 0-byte packets, port bounds, MTU limits. |
| **Tier 3** | **Cross-Feature Pairwise** | All module interfaces | Verify end-to-end contracts between Scapy generation $\leftrightarrow$ Replayer $\leftrightarrow$ Zeek JA4 $\leftrightarrow$ Redpanda $\leftrightarrow$ TimescaleDB. |
| **Tier 4** | **Real-World & Adversarial Stress** | Defense resilience tests | Test sudden 10x traffic bursts, multi-threaded replay independence, DDL idempotency, and malicious SNI/JA4 collision resistance. |

---

## 3. Feature Inventory & Test Mapping

| Feature # | Feature Description | Milestone | Test File | Tier 1 | Tier 2 | Tier 3 | Tier 4 | Total Tests |
|---|---|---|---|---|---|---|---|---|
| **F1** | Docker Compose Multi-Container Stack | M1 (R1) | `tests/test_infrastructure.py` | 5 | 5 | 3 | 3 | **16** |
| **F2** | Redpanda Kafka Broker & Topics (`telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw`, `incidents.fused`) | M1 (R1) | `tests/test_infrastructure.py` | 5 | 2 | 2 | 2 | **11** |
| **F3** | Redis 7.x In-Memory CEP Buffer (512MB, `allkeys-lru`, no persistence) | M1 (R1) | `tests/test_infrastructure.py` | 5 | 2 | 2 | 1 | **10** |
| **F4** | TimescaleDB Hypertables & Compression/Retention Policies | M1 (R1) | `tests/test_infrastructure.py` | 5 | 3 | 2 | 2 | **12** |
| **F5** | Startup & Healthcheck Automation Scripts (`.ps1` / `.sh`) | M1 (R1) | `tests/test_infrastructure.py` | 3 | 2 | 1 | 1 | **7** |
| **F6** | Scapy Synthetic Dataset Generation (Benign, DDoS SYN, Portscan) | M2 (R2) | `tests/test_replay_harness.py` | 5 | 3 | 2 | 2 | **12** |
| **F7** | High-Speed Token-Bucket Traffic Replayer ($1\text{k}\text{--}50\text{k}+\text{ pps}$) | M2 (R2) | `tests/test_replay_harness.py` | 5 | 4 | 2 | 2 | **13** |
| **F8** | Zeek JA4 & JA4S Passive TLS Fingerprinting Algorithm | M1/M4 | `tests/test_ja4_fingerprinting.py` | 5 | 5 | 2 | 2 | **14** |
| **F9** | Zeek Structured JSON Log Schemas (`conn.log`, `dns.log`, `ssl.log`) | M1/M4 | `tests/test_ja4_fingerprinting.py` | 5 | 3 | 2 | 1 | **11** |
| **TOTAL** | **Full Phase 0 Test Suite** | — | — | **38** | **29** | **16** | **14** | **97+** |

---

## 4. Test Suite Architecture & Modules

```
tests/
├── __init__.py
├── test_infrastructure.py        # F1, F2, F3, F4, F5 (Docker, Redpanda, Redis, TimescaleDB, Scripts)
├── test_replay_harness.py        # F6, F7 (Scapy generation, PCAP integrity, Token-Bucket replay, Rate control)
├── test_ja4_fingerprinting.py    # F8, F9 (JA4/JA4S calculation, GREASE filtering, JSON log schemas)
└── throughput_benchmark.py       # F10, F11 (Live 30-second Day-1 EPS & line-rate benchmark suite)
```

### Module Breakdown

### 1. `tests/test_infrastructure.py`
- **Scope**: Multi-container Docker Compose definitions, internal network bridge (`sih_net: 172.28.0.0/16`), volume naming conventions, port mapping allocations without host collisions, Redpanda topic auto-provisioning (`telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw`, `incidents.fused`), Redis 512MB LRU memory config, TimescaleDB hypertable DDL syntax, chunk intervals (1-hour/1-day), columnar compression policies (24-hour), automated retention drop policies, and PowerShell/Bash startup script healthcheck loops.

### 2. `tests/test_replay_harness.py`
- **Scope**: Scapy-based generation of benign HTTP 3-way handshakes, DNS queries/answers, TLS 1.2/1.3 handshakes, SYN flood attack traffic, and multi-port scan sweeps. Validation of libpcap file magic bytes (`0xa1b2c3d4`), linktype Ethernet (`1`), pre-serialized raw bytes caching (`List[bytes]`), and token-bucket micro-batching ($B=32\text{--}128$) with nanosecond timer precision (`time.perf_counter_ns()`) sustaining 1,000 to 50,000+ pps.

### 3. `tests/test_ja4_fingerprinting.py`
- **Scope**: JA4 TLS client fingerprint algorithm (`(t|q|d)<ver><sni><ciphers><exts><alpn>_<cipher_hash>_<ext_hash>`), JA4S server fingerprint algorithm, 16 GREASE values filtering (`0x0a0a` to `0xfafa`), cipher sorting determinism, truncated SHA256 (12-char), Zeek `conn.log`, `dns.log`, and `ssl.log` JSON schemas, and cross-log correlation via connection `uid` and 5-tuples.

---

## 5. Test Execution Instructions

### Running with Pytest
```bash
# Run entire test suite with verbose output
pytest -v

# Run individual test modules
pytest -v tests/test_infrastructure.py
pytest -v tests/test_replay_harness.py
pytest -v tests/test_ja4_fingerprinting.py

# Run with test failure early exit
pytest -v -x
```

### Running with Python Unittest (No External Test Runner Dependency)
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 6. Authoritative Expected Output Derivations

1. **JA4 Specification**: FoxIO Open Source JA4+ Specification (https://github.com/FoxIO-LLC/ja4).
   - Format: `{proto}{version}{sni}{num_ciphers}{num_exts}{alpn}_{cipher_hash}_{ext_hash}`
   - Truncated SHA-256: First 12 hexadecimal characters of SHA256 of sorted hex ciphers.
2. **TimescaleDB Chunk Intervals**:
   - `conn_telemetry`, `dns_telemetry`, `ssl_telemetry`, `system_metrics`: `1 hour` intervals for optimal memory-resident indexing.
   - `alerts`: `1 day` intervals for aggregated alert triage.
   - Columnar Compression: `24 hours` threshold.
3. **Replayer Timing Math**:
   - For batch size $B$ and target rate $R$ (pps):
     $$\Delta t_{\text{batch}} = \frac{B}{R} \text{ seconds} = \frac{B \times 10^9}{R} \text{ nanoseconds}$$
   - Monotonic timer source: `time.perf_counter_ns()`.
