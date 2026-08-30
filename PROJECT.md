# Project: SIH26145 Passive Network Monitoring System — Phase 0

## Architecture
Phase 0 establishes the foundational high-throughput, containerized telemetry ingestion pipeline, deterministic traffic generation and replay harness, and Day-1 line-rate benchmark validation suite for the SIH26145 Passive Network Monitoring System.

The architecture operates in a read-only data diode monitoring enclave:
1. **Traffic Replay & Ingestion**:
   - `scripts/replay_traffic.py`: High-performance Python token-bucket replay engine delivering 1,000 to 50,000+ pps with nanosecond timing precision (`time.perf_counter_ns()`).
   - `scripts/generate_datasets.py`: Scapy-based PCAP generator for synthetic benign baseline traffic (HTTP/1.1, DNS, TLS 1.2/1.3 handshakes with realistic JA4/JA4S fingerprints) and attack scenarios (SYN flood, TCP/UDP port scans).
2. **Containerized Ingestion Stack (`docker-compose.yml`)**:
   - **Zeek 7.x (`sih_zeek`)**: Native passive deep packet inspection with JA4 plugin enabled, streaming structured JSON logs for `conn.log`, `dns.log`, and `ssl.log`.
   - **Redpanda (`sih_redpanda`)**: C++ Kafka-compatible high-throughput streaming message broker with pre-provisioned topics: `telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw`, `incidents.fused`.
   - **Redis 7.x (`sih_redis`)**: In-memory sliding-window cache configured with LRU eviction for real-time CEP and state buffering.
   - **PostgreSQL 16 + TimescaleDB (`sih_timescaledb`)**: Telemetry store with hypertable partitions for network flows, alerts, and system metrics.
   - **Init & Healthchecks**: `scripts/start_infrastructure.ps1` and `scripts/start_infrastructure.sh` with automated healthchecks.
3. **Day-1 Line-Rate Benchmark Suite**:
   - `tests/throughput_benchmark.py`: End-to-end performance benchmarking harness measuring sustained Events Per Second (EPS), Line-Rate (Mbps), End-to-End Ingest Latency distribution ($p50, p90, p95, p99$), CPU/Memory utilization, and Packet Loss Rate over a 30-second sustained run.
   - Automated output of `benchmark_results.md`.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| 1 | Docker Compose Multi-Container Stack | Orchestrates Zeek, Redpanda, Redis, and TimescaleDB with port isolation and network bridges | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 2 | Zeek 7.x with JA4 Plugin | Passive packet capture producing streaming JSON logs for conn, dns, ssl with JA4/JA4S fingerprints | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 3 | Redpanda Streaming Broker & Topics | Kafka-compatible broker initialized with `telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw` | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 4 | Redis 7.x Memory Buffer | In-memory sliding window cache tuned for high-throughput CEP buffering | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 5 | TimescaleDB Hypertables Schema | PostgreSQL 16 schema with TimescaleDB hypertables, chunking, compression, and retention | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 6 | Single-Command Startup & Healthchecks | Scripts (`.ps1` / `.sh`) verifying healthcheck statuses of all containers | M1 (R1) | ORIGINAL_REQUEST §R1 |
| 7 | High-Speed Traffic Replay Harness | Python token-bucket / raw socket replayer supporting 1,000–50,000+ pps deterministically | M2 (R2) | ORIGINAL_REQUEST §R2 |
| 8 | Synthetic Baseline PCAP Generator | Scapy generator creating benign HTTP, DNS, and TLS handshakes with valid JA4 fingerprints | M2 (R2) | ORIGINAL_REQUEST §R2 |
| 9 | Synthetic Attack PCAP Generator | Scapy generator creating SYN flood and TCP/UDP port scan PCAPs | M2 (R2) | ORIGINAL_REQUEST §R2 |
| 10 | Day-1 Throughput Benchmark Harness | Python script `tests/throughput_benchmark.py` running 30s benchmark measuring EPS, Mbps, Latency, Loss | M3 (R3) | ORIGINAL_REQUEST §R3 |
| 11 | Real-Time Benchmark Dashboard & Reporter | Terminal CLI monitor and automatic `benchmark_results.md` generator | M3 (R3) | ORIGINAL_REQUEST §R3 |
| 12 | Comprehensive E2E Verification Suite | Opaque-box test suite verifying service orchestration, JA4 logging, Redpanda ingest, and metrics | M4 (E2E) | ORIGINAL_REQUEST §Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| M1 | Containerized Infrastructure & Pipeline Stack (R1) | Docker Compose, Zeek 7.x + JA4, Redpanda, Redis 7.x, TimescaleDB SQL DDL schemas, Startup scripts | none | DONE |
| M2 | Passive Traffic Replay Harness & Dataset Generator (R2) | Python token-bucket replay script (1k-50k+ pps), Scapy dataset generator (benign baseline, SYN flood, port scan) | none | DONE |
| M3 | Day-1 Line-Rate Benchmark Suite (R3) | `tests/throughput_benchmark.py`, metrics calculations (EPS, Mbps, latency, CPU/RAM, loss), `benchmark_results.md` generation | M1, M2 | DONE |
| M4 | Final E2E Test Pass & Coverage Hardening (Acceptance) | Run complete E2E test suite (Tiers 1-4), verify 100% acceptance criteria pass, adversarial coverage verification | M1, M2, M3 | DONE |

## Interface Contracts

### 1. Packet Replay ↔ Zeek Capture
- **Interface**: Network socket / virtual ethernet interface or PCAP ingestion (`/pcaps/*.pcap`).
- **Data Format**: Standard Ethernet/IP/TCP/UDP raw frames.
- **Rate**: Configurable from 1,000 pps to 50,000+ pps.
- **Contract**: Replayer emits valid Ethernet/IP frames; Zeek captures and extracts connection and TLS metadata without frame drop or parser crash.

### 2. Zeek ↔ Streaming JSON Logs / Redpanda
- **Log Files**: `/logs/conn.log`, `/logs/dns.log`, `/logs/ssl.log`.
- **JSON Format**:
  - `conn.log`: `{"ts": float, "uid": str, "id.orig_h": str, "id.orig_p": int, "id.resp_h": str, "id.resp_p": int, "proto": str, "service": str, "duration": float, "orig_bytes": int, "resp_bytes": int, "conn_state": str, ...}`
  - `ssl.log`: `{"ts": float, "uid": str, "id.orig_h": str, "id.orig_p": int, "id.resp_h": str, "id.resp_p": int, "version": str, "cipher": str, "server_name": str, "ja4": str, "ja4s": str, ...}`
  - `dns.log`: `{"ts": float, "uid": str, "id.orig_h": str, "id.orig_p": int, "id.resp_h": str, "id.resp_p": int, "proto": str, "query": str, "qtype_name": str, "rcode_name": str, "answers": list, ...}`
- **Redpanda Topic**: `telemetry.conn`, `telemetry.dns`, `telemetry.ssl`.
- **Message Payload**: JSON UTF-8 encoded string matching Zeek structured log format with added ingestion timestamp `ingest_ts`.

### 3. Redpanda / Ingestion ↔ TimescaleDB
- **Database Name**: `sih26145`
- **Tables / Hypertables**:
  - `conn_telemetry`: `(time TIMESTAMPTZ, uid TEXT, src_ip INET, src_port INT, dst_ip INET, dst_port INT, proto VARCHAR(10), service VARCHAR(20), duration REAL, orig_bytes BIGINT, resp_bytes BIGINT, conn_state VARCHAR(10), missed_bytes BIGINT)`
  - `ssl_telemetry`: `(time TIMESTAMPTZ, uid TEXT, src_ip INET, src_port INT, dst_ip INET, dst_port INT, version VARCHAR(20), cipher VARCHAR(100), server_name TEXT, ja4 VARCHAR(64), ja4s VARCHAR(64))`
  - `dns_telemetry`: `(time TIMESTAMPTZ, uid TEXT, src_ip INET, src_port INT, dst_ip INET, dst_port INT, proto VARCHAR(10), query TEXT, qtype VARCHAR(10), rcode VARCHAR(20), answers TEXT[])`
  - `alerts`: `(time TIMESTAMPTZ, alert_id UUID, detector VARCHAR(50), severity VARCHAR(20), confidence REAL, src_ip INET, dst_ip INET, title TEXT, details JSONB)`
  - `system_metrics`: `(time TIMESTAMPTZ, host TEXT, eps INT, mbps REAL, latency_p50_ms REAL, latency_p95_ms REAL, cpu_utilization REAL, memory_utilization REAL, packet_loss_rate REAL)`

### 4. Benchmark Harness ↔ Pipeline & Output
- **CLI**: `python tests/throughput_benchmark.py --duration <seconds> --pps <rate> --pcap <path> --output <report_path>`
- **Output File**: `benchmark_results.md` containing formatted markdown tables with Sustained EPS, Throughput (Mbps), Latency percentiles ($p50, p90, p95, p99$), CPU/Memory utilization, and Packet Loss Rate.

## Code Layout
```
c:/Users/qamba/OneDrive/Desktop/SIH/
├── docker-compose.yml
├── .env.example
├── config/
│   ├── zeek/
│   │   ├── Dockerfile
│   │   ├── local.zeek
│   │   ├── ja4.zeek
│   │   └── entrypoint.sh
│   ├── redpanda/
│   │   └── redpanda.yaml
│   ├── redis/
│   │   └── redis.conf
│   └── timescale/
│       ├── init.sql
│       └── timescaledb.conf
├── scripts/
│   ├── generate_datasets.py
│   ├── replay_traffic.py
│   ├── start_infrastructure.ps1
│   ├── start_infrastructure.sh
│   ├── stop_infrastructure.ps1
│   └── stop_infrastructure.sh
├── data/
│   └── pcaps/
│       ├── benign_baseline.pcap
│       ├── ddos_syn_flood.pcap
│       └── portscan_nmap.pcap
├── src/
│   ├── __init__.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── zeek_log_tailer.py
│   │   └── kafka_producer.py
│   ├── utils/
│   │   ├── __init__.py
│   │   └── metrics_calculator.py
│   └── storage/
│       ├── __init__.py
│       └── db.py
├── tests/
│   ├── __init__.py
│   ├── throughput_benchmark.py
│   ├── test_infrastructure.py
│   ├── test_replay_harness.py
│   ├── test_ja4_fingerprinting.py
│   ├── test_ja4_protocol_deep.py
│   ├── test_benchmark_suite.py
│   ├── test_ingestion_storage.py
│   └── test_stress_boundary.py
├── benchmark_results.md
├── PROJECT.md
├── TEST_INFRA.md
└── TEST_READY.md
```
