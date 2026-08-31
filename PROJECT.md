# Project: SIH26145 Passive Network Threat Detection System (Phase 1 & Phase 2)

## Architecture
The SIH26145 platform is a high-throughput, passive network monitoring and threat detection system operating under a strict **data diode / read-only tap** architecture.

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       ZEEK NETWORK MONITORING SENSOR                                      │
│                                 (conn.log, dns.log, ssl.log + JA4/JA4S Plugin)                            │
└─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                      │ (JSON Stream Tailer)
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    PHASE 1: INGESTION & PARTITIONING PIPELINE                             │
│  - JSON Deserialization & Event Normalization (ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent)  │
│  - Deterministic Source-IP Partitioning: partition_id = Murmur3(src_ip) % 4                              │
│  - Redpanda / Kafka Topics: telemetry.conn, telemetry.dns, telemetry.ssl                                 │
└─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                      │ (Partitioned Telemetry Streams)
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   PHASE 2: SIX STREAMING THREAT DETECTORS                                 │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │ 1. Volumetric & Protocol DDoS: Sliding Shannon Entropy H(X_dport) + EWMA Rate Variance Z-Score       │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 2. Port Scanning & Recon: Dual-Bucket Slotted HyperLogLog (HLL) Cardinality in 10s Rolling Windows   │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 3. Data Exfiltration: Per-Host Asymmetric Byte-Ratio (R_out/in) + Streaming P² Quantile Baselining    │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 4. DGA & DNS Tunnelling: ONNX Char-BiLSTM (<1ms) + Subdomain Shannon Entropy + NXDOMAIN Spikes       │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 5. Encrypted Malware: JA4/JA4S Threat Intel Hash Matching + 5-Feature TLS Handshake Anomaly Scoring   │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 6. C2 Beaconing: Delta-T Circular Buffer (N=25) Periodicity CV = sigma/mu < 0.15 + MAD Dispersion   │ │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                      │ (Normalized Raw Alerts)
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                              OUTPUT BUS & STORAGE                                         │
│  - Topic: alerts.raw                                                                                      │
│  - Storage: TimescaleDB 'alerts' Hypertable                                                               │
│  - Downstream: Redis Sliding Buffer & CEP Incidents Fusion                                                │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| 1 | Zeek Log Ingest & Normalization | Tail and parse Zeek JSON `conn.log`, `dns.log`, `ssl.log` into normalized Pydantic events | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Deterministic Source-IP Partitioning | Hash source IP (`Murmur3(src_ip) % 4`) to ensure zero-lock per-host stateful locality | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Streaming Bus Abstraction | Redpanda/Kafka producer with seamless `InMemoryStreamingBus` fallback | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Volumetric & Protocol DDoS Detector | $O(1)$ Differential Shannon Entropy of target ports + EWMA rate variance $Z$-score | M2 | ORIGINAL_REQUEST §R2.1 |
| 5 | Port Scanning & Recon Detector | Dual-Bucket Slotted HyperLogLog (HLL, $p=10$) for 10s rolling distinct IP/port cardinality | M2 | ORIGINAL_REQUEST §R2.2 |
| 6 | Data Exfiltration Detector | Directional asymmetric byte-ratio $R_{\text{out/in}}$ with streaming per-host $P^2$ quantile baselining | M2 | ORIGINAL_REQUEST §R2.3 |
| 7 | DGA & DNS Tunnelling Detector | Pretrained Char-BiLSTM ONNX model ($<1\text{ ms}$) + Subdomain Shannon entropy + NXDOMAIN spike scoring | M3 | ORIGINAL_REQUEST §R2.4 |
| 8 | Encrypted Malware Detector | Curated JA4/JA4S threat intelligence database matching + 5-feature TLS anomaly scoring | M3 | ORIGINAL_REQUEST §R2.5 |
| 9 | C2 Beaconing Detector | Streaming inter-arrival time ($\Delta T$) circular buffer evaluating $CV = \sigma/\mu < 0.15$ + MAD jitter | M3 | ORIGINAL_REQUEST §R2.6 |
| 10 | Standardized Raw Alert Serialization | Generate JSON alerts conforming strictly to `alerts.raw` schema with mathematical evidence payloads | M2, M3 | ORIGINAL_REQUEST §R2 |
| 11 | End-to-End Latency & Performance Verification | Verify $< 500\text{ ms}$ streaming latency, $\ge 50,000\text{ EPS}$ throughput, zero memory leaks | M4 | ORIGINAL_REQUEST §R3 |
| 12 | Comprehensive Test Suite & Accuracy Verification | Pytest automated test harness validating 100% pass rate, TPR $\ge 98\%$, FPR $\le 1\%$ across all 6 detectors | M4 | ORIGINAL_REQUEST §R3 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| M1 | Ingestion & Partitioning Pipeline | Zeek log tailing, normalized Pydantic telemetry models, deterministic partitioning, streaming bus | Phase 0 baseline | DONE |
| M2 | Core Threat Detectors 1-3 | Detector 1 (DDoS Entropy/EWMA), Detector 2 (PortScan HLL), Detector 3 (Exfiltration Ratio/P²), `alerts.raw` schema | M1 | DONE |
| M3 | Advanced Threat Detectors 4-6 | Detector 4 (DGA ONNX/Entropy), Detector 5 (JA4/TLS Anomaly), Detector 6 (C2 Beaconing CV), ONNX model & Threat DB | M1 | DONE |
| M4 | Integration, Latency Profiling & Verification | 100% E2E test suite pass across all 6 detectors, sub-500ms latency verification, TPR/FPR accuracy validation | M1, M2, M3 | DONE |

---

## Interface Contracts

### 1. Ingestion ↔ Detectors (`telemetry.*`)
- **Topic `telemetry.conn`**:
  `ConnTelemetryEvent(event_id, ts, uid, src_ip, src_port, dst_ip, dst_port, proto, service, duration, orig_bytes, resp_bytes, conn_state, orig_pkts, resp_pkts, history)`
- **Topic `telemetry.dns`**:
  `DnsTelemetryEvent(event_id, ts, uid, src_ip, src_port, dst_ip, dst_port, trans_id, query, qtype_name, rcode_name, answers, ttls, subdomain, subdomain_entropy)`
- **Topic `telemetry.ssl`**:
  `SslTelemetryEvent(event_id, ts, uid, src_ip, src_port, dst_ip, dst_port, version, cipher, server_name, ja4, ja4s, established, subject, issuer)`
- **Partition Key**: `source_ip` (string). Guarantees that all events for a given source host route to the exact same partition index.

### 2. Detectors ↔ Storage & Downstream Bus (`alerts.raw`)
- **Topic `alerts.raw`**:
  `RawAlert(alert_id, timestamp, detector_id, threat_class, severity, confidence, source_ip, target_ip, target_port, protocol, flow_id, window_duration_sec, evidence, recommended_mitigation)`
- **Evidence Fields**:
  - `ddos_entropy`: `{current_rate_pps, ewma_rate_pps, rate_z_score, port_entropy, normalized_port_entropy, syn_only_ratio}`
  - `portscan_hll`: `{scan_type, hll_distinct_ports, hll_distinct_hosts, hll_distinct_endpoints, failure_ratio}`
  - `exfil_ratio`: `{orig_bytes, resp_bytes, ratio_out_in, host_baseline_p95_ratio, host_baseline_p99_ratio, egress_velocity_mbps}`
  - `dga_lstm`: `{domain, onnx_dga_prob, subdomain, subdomain_entropy, is_nxdomain, qtype, nxdomain_ratio_30s}`
  - `ja4_malware`: `{matched_ja4, matched_ja4s, malware_family, threat_actor, tls_anomaly_score, anomaly_reasons}`
  - `c2_beacon`: `{cv, mean_interval_sec, std_dev_sec, median_interval_sec, mad_sec, sample_count, jitter_ratio}`

---

## Code Layout
```
src/
├── ingestion/
│   ├── __init__.py
│   ├── models.py                  # Pydantic schemas for Telemetry & Alerts
│   ├── zeek_log_tailer.py         # Streaming Zeek log tailer
│   ├── kafka_producer.py          # Deterministic partition producer
│   └── streaming_bus.py           # Unified Redpanda / In-Memory streaming bus
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # BaseDetector abstract class & state management
│   ├── ddos_entropy.py            # Detector 1: Volumetric & Protocol DDoS
│   ├── portscan_hll.py            # Detector 2: Port Scanning & Recon (HLL)
│   ├── exfil_ratio.py             # Detector 3: Data Exfiltration (Asymmetric Ratio & P²)
│   ├── dga_tunneling.py           # Detector 4: DGA & DNS Tunnelling (ONNX BiLSTM)
│   ├── encrypted_malware.py       # Detector 5: Encrypted Malware (JA4/JA4S & TLS Anomaly)
│   ├── c2_beaconing.py            # Detector 6: C2 Beaconing (Delta-T Circular Buffer)
│   └── detector_manager.py        # Multi-detector worker process orchestrator
├── models/
│   ├── dga_char_lstm.onnx         # Genuine ONNX model for DGA inference
│   └── dga_tokenizer.json         # Vocabulary mapping for character tokenization
├── threat_intel/
│   └── ja4_malware_database.json  # Curated JA4/JA4S malware fingerprint catalog
├── storage/
│   └── db.py                      # TimescaleDB / PostgreSQL hypertable storage
└── utils/
    ├── metrics_calculator.py      # Line-rate EPS, Mbps, and latency profiling
    └── p2_quantile.py             # P² algorithm for streaming percentile estimation
scripts/
├── train_dga_model.py             # Script to train and export genuine ONNX model
├── generate_datasets.py           # Synthetic PCAP and log generator
└── replay_traffic.py              # Token-bucket packet replay engine
tests/
├── test_ingestion_pipeline.py     # Phase 1 Ingestion & Partitioning tests
├── test_detector_ddos.py          # Detector 1 tests
├── test_detector_portscan.py      # Detector 2 tests
├── test_detector_exfil.py         # Detector 3 tests
├── test_detector_dga.py           # Detector 4 tests
├── test_detector_malware.py       # Detector 5 tests
├── test_detector_beaconing.py     # Detector 6 tests
├── test_detectors_latency.py      # Sub-500ms latency verification
└── test_detectors_e2e.py          # End-to-end multi-detector integration tests
```
