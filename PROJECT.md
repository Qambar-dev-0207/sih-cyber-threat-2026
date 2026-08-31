# Project: SIH26145 Passive Network Threat Detection System (Phase 3 & Phase 4)

## Architecture
The SIH26145 platform is a high-throughput, passive network monitoring, complex event processing (CEP), and agentic incident triage system operating under a strict **air-gapped data diode / read-only tap** architecture.

```
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       PHASE 2: SIX PARALLEL DETECTORS                                     │
│  (DDoS Entropy, PortScan HLL, Exfil Ratio/P², DGA BiLSTM, Encrypted Malware JA4, C2 Beaconing Delta-T)   │
└─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                      │ (Normalized Raw Alerts JSON)
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   PHASE 3: FAST IN-MEMORY CEP AGGREGATOR                                  │
│  - Alert Ingestion Topic: alerts.raw                                                                      │
│  - In-Memory Sliding Window: 30s–120s rolling window indexed by source_ip and /24 subnet                  │
│  - Alert Deduplication: Flow signature hashing + 5s coalescing buckets                                    │
│  - Burst Rate-Limiting: Token-bucket limiter collapsing 1,000+ raw flood alerts                           │
│  - Confidence-Weighted Fusion: C_fused = 1 - ∏(1 - c_i) with multi-detector synergy boost                 │
│  - Output Topic: incidents.fused                                                                          │
└─────────────────────────────────────────────────────┬─────────────────────────────────────────────────────┘
                                                      │ (Structured Fused Incidents)
                                                      ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 PHASE 4: LANGGRAPH AGENTIC TRIAGE ENGINE                                  │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │ 1. Correlation Node: Chronological timeline synthesis + Host telemetry correlation (Asset alpha)     │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 2. Explainable Risk Scoring Node: Transparent score (0.0–100.0) with mathematical derivation w_i*c_i │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 3. Classification & MITRE Node: MITRE ATT&CK mapping (T1595, T1568, T1071, T1048) + Narrative Synth  │ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 4. Countermeasure Node: Jinja2 artifact generation (iptables, nftables, Cisco ACL, RPZ, Snort, STIX)│ │
│  ├──────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │ 5. Storage Handoff Node: TimescaleDB persistence + Out-of-band Webhook (HMAC-SHA256)                 │ │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
│  - Air-Gap Safety: requires_human_approval = True, status = PENDING_REVIEW, zero return-path active probing│
│  - Execution SLA: < 2.0s per incident deterministic execution without external internet access           │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| 1 | Raw Alert Stream Ingest & Validation | Ingest raw streaming alerts from `alerts.raw` published by the 6 parallel detectors | M1 | ORIGINAL_REQUEST §R1 |
| 2 | In-Memory Sliding Window Buffer | 30s–120s rolling window buffer grouping alerts by `source_ip` and subnet (`/24`) | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Alert Deduplication & Coalescing | Flow signature fingerprint hashing and 5s coalescing buckets to collapse duplicates | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Burst Rate-Limiting & Flood Shield | Token-bucket rate limiter collapsing 1,000+ raw alert floods without memory leaks | M1 | ORIGINAL_REQUEST §R1 |
| 5 | Multi-Detector Signal Fusion | Fuse multi-detector signals (Recon -> DGA -> JA4 C2 -> Exfil) with confidence math $C_{\text{fused}} = 1 - \prod(1 - c_i)$ | M1 | ORIGINAL_REQUEST §R1 |
| 6 | Fused Incident Serialization & Bus Dispatch | Publish structured multi-stage incident contexts to `incidents.fused` | M1 | ORIGINAL_REQUEST §R1 |
| 7 | LangGraph State Machine Architecture | Modular 5-node LangGraph state machine (`src/agentic_triage/graph.py`) using `StateGraph` | M2 | ORIGINAL_REQUEST §R2 |
| 8 | Chronological Correlation Node | Synthesize chronological attack timelines from fused alerts and historical host metrics | M2 | ORIGINAL_REQUEST §R2.1 |
| 9 | Explainable Risk Scoring Node | Compute deterministic $0.0 - 100.0$ risk score with transparent mathematical breakdown $w_i \cdot \text{confidence}_i$ | M2 | ORIGINAL_REQUEST §R2.2 |
| 10 | MITRE ATT&CK Classification Node | Map attack intent to MITRE ATT&CK technique IDs (`T1595`, `T1568.002`, `T1071.001`, `T1048`, `T1498`) | M2 | ORIGINAL_REQUEST §R2.3 |
| 11 | Executive Attack Narrative Generator | Deterministic military/SOC-grade executive attack narrative generator with optional offline LLM fallback | M2 | ORIGINAL_REQUEST §R2.4 |
| 12 | Linux Firewall Artifact Generators | Generate syntax-valid Linux `iptables` and `nftables` blocking and rate-limiting rules | M3 | ORIGINAL_REQUEST §R3 |
| 13 | Cisco IOS ACL Generator | Generate syntax-valid Cisco IOS Extended ACL definitions with calculated inverse wildcard masks | M3 | ORIGINAL_REQUEST §R3 |
| 14 | DNS RPZ & Local-Zone Generator | Generate syntax-valid BIND 9 RPZ blocklists (RFC 1035 CNAME) and Unbound local-zone directives | M3 | ORIGINAL_REQUEST §R3 |
| 15 | IDS Signature Generator | Generate syntax-valid Snort 3 and Suricata rules with JA4 fingerprint matching and MITRE tags | M3 | ORIGINAL_REQUEST §R3 |
| 16 | OASIS STIX 2.1 Threat Intel Bundle | Generate fully valid STIX 2.1 JSON Threat Intelligence Bundles with SCOs, SDOs, and SROs | M3 | ORIGINAL_REQUEST §R3 |
| 17 | Strict Data Diode Safety Enforcement | Strictly enforce `requires_human_approval = True`, status `'PENDING_REVIEW'`, and zero return-path active probing | M3 | ORIGINAL_REQUEST §R3 |
| 18 | TimescaleDB Persistence & Out-of-Band Webhook | Write completed incident records to TimescaleDB `incidents` and dispatch HMAC-SHA256 signed webhooks | M3 | ORIGINAL_REQUEST §R3 |
| 19 | Comprehensive Pytest Test Suite | Automated test suite across `test_cep_aggregator.py`, `test_agentic_triage.py`, `test_countermeasures.py`, `test_incident_e2e.py` | M4 | ORIGINAL_REQUEST §R4 |
| 20 | Flood Scenario Simulation & Latency SLA | Validate collapsing of 1,000+ alert floods, sub-second latency (<2.0s per incident), and 100% repo-wide test pass rate | M4 | ORIGINAL_REQUEST §R4 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| M1 | Fast In-Memory CEP Aggregator & Incident Fusion (Phase 3) | Ingestion from `alerts.raw`, sliding window buffer, alert dedup, burst rate limiter, confidence fusion, `incidents.fused` | Baseline Phase 1/2 | PLANNED |
| M2 | LangGraph Agentic Triage & Explainable Risk Scoring (Phase 4) | LangGraph state machine, Correlation Node, Explainable Risk Scoring Node, MITRE Mapping Node, Narrative Generator | M1 | PLANNED |
| M3 | Deterministic Countermeasure Artifacts & Out-of-Band Handoff (Phase 4) | Jinja2 templates (iptables, nftables, Cisco ACL, DNS RPZ, Snort/Suricata, STIX 2.1), Diode safety enforcement, TimescaleDB & Webhooks | M2 | PLANNED |
| M4 | Complete Test Suite & Incident Simulation E2E Validation (Phase 3+4) | End-to-end integration tests, flood scenario harness (1,000+ alerts), latency SLA (<2.0s), 100% full test suite pass | M1, M2, M3 | PLANNED |

---

## Interface Contracts

### 1. Detectors ↔ CEP Engine (`alerts.raw`)
- **Topic**: `alerts.raw`
- **Schema**: `RawAlert` (Pydantic)
  - `alert_id`: str (UUID4)
  - `timestamp`: float (Unix timestamp)
  - `detector_id` / `detector_name`: str (`ddos_entropy`, `portscan_hll`, `exfil_ratio`, `dga_tunneling`, `encrypted_malware`, `c2_beaconing`)
  - `threat_class`: str (`VOLUMETRIC_DDOS`, `PORT_SCAN_RECON`, `DATA_EXFILTRATION`, `DGA_TUNNELLING`, `ENCRYPTED_MALWARE`, `C2_BEACONING`)
  - `severity`: str (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `confidence`: float ($0.0 - 1.0$)
  - `source_ip`: str
  - `target_ip`: str
  - `target_port`: int
  - `evidence`: dict
  - `recommended_mitigation`: str

### 2. CEP Engine ↔ LangGraph Triage Engine (`incidents.fused`)
- **Topic**: `incidents.fused`
- **Schema**: `FusedIncident` (Pydantic)
  - `incident_id`: str (UUID4, e.g. `INC-20260831-XXXX`)
  - `created_at`: float
  - `updated_at`: float
  - `primary_source_ip`: str
  - `source_subnet`: str (e.g. `192.168.1.0/24`)
  - `target_ips`: list[str]
  - `target_ports`: list[int]
  - `participating_detectors`: list[str]
  - `threat_classes`: list[str]
  - `raw_alert_count`: int
  - `fused_confidence`: float ($0.0 - 1.0$)
  - `severity`: str (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
  - `alerts`: list[RawAlert]
  - `attack_stage`: str (`RECONNAISSANCE`, `WEAPONIZATION`, `DELIVERY`, `C2_COMMUNICATION`, `EXFILTRATION`, `MULTI_STAGE_APT`)

### 3. LangGraph Triage Engine State (`TriageStateDict`)
- **Schema**:
  - `incident`: FusedIncident
  - `timeline`: list[TimelineStep]
  - `host_metrics`: dict
  - `asset_criticality`: float ($\alpha \in [1.0, 2.0]$)
  - `overall_risk_score`: float ($0.0 - 100.0$)
  - `risk_breakdown`: RiskBreakdown
  - `mitre_techniques`: list[MitreMapping]
  - `attack_narrative`: str
  - `countermeasure_artifacts`: CountermeasureBundle
  - `requires_human_approval`: bool (strictly `True`)
  - `status`: str (`PENDING_REVIEW`)
  - `persisted_id`: str

### 4. Countermeasures & Out-of-Band Handoff
- **Countermeasure Bundle**:
  - `iptables_rules`: str
  - `nftables_rules`: str
  - `cisco_acl_rules`: str
  - `dns_rpz_records`: str
  - `unbound_zone_records`: str
  - `snort3_rules`: str
  - `suricata_rules`: str
  - `stix_bundle_json`: str (valid STIX 2.1 JSON)
- **Safety**: `requires_human_approval = True`, `zero_return_path = True`
- **Audit Storage**: TimescaleDB `incidents` table with JSONB risk breakdown & countermeasure payloads.

---

## Code Layout
```
src/
├── cep/
│   ├── __init__.py
│   ├── models.py                  # FusedIncident, AggregationBuffer, DeduplicationRecord
│   ├── sliding_window.py          # 30s-120s Rolling window indexed by src_ip & /24 subnet
│   ├── deduplicator.py            # Flow fingerprint hashing & 5s coalescing buckets
│   ├── burst_limiter.py           # Token-bucket rate limiter collapsing 1000+ flood alerts
│   ├── correlator.py              # Multi-detector fusion & confidence-weighted scoring
│   └── engine.py                  # Main CEPAggregatorEngine orchestrating ingest & fusion
├── agentic_triage/
│   ├── __init__.py
│   ├── state.py                   # Pydantic schemas (TriageStateDict, TimelineStep, RiskBreakdown)
│   ├── graph.py                   # LangGraph StateGraph assembly & compilation
│   ├── knowledge/
│   │   ├── __init__.py
│   │   └── mitre_catalog.py       # Curated MITRE ATT&CK technique catalog & tactics
│   ├── templates/
│   │   ├── __init__.py
│   │   └── narrative_templates.py # Executive attack narrative templates (military/SOC format)
│   └── nodes/
│       ├── __init__.py
│       ├── correlation_node.py    # Node 1: Chronological timeline & host telemetry fusion
│       ├── risk_scoring_node.py   # Node 2: Transparent mathematical risk calculation (0-100)
│       ├── classification_node.py # Node 3: MITRE ATT&CK mapping & narrative generation
│       ├── countermeasure_node.py # Node 4: Jinja2 countermeasure artifact generation
│       └── handoff_node.py        # Node 5: TimescaleDB persistence & webhook dispatch
├── countermeasures/
│   ├── __init__.py
│   ├── models.py                  # CountermeasureArtifact, CountermeasureBundle models
│   ├── generators.py              # iptables, nftables, Cisco ACL, DNS RPZ, Snort/Suricata generators
│   ├── stix_generator.py          # OASIS STIX 2.1 JSON Threat Intelligence Bundle generator
│   ├── validator.py               # Syntax & schema validation oracles
│   ├── diode_dispatcher.py        # Out-of-band webhook dispatcher with HMAC-SHA256 signing
│   └── templates/
│       ├── iptables.j2
│       ├── nftables.j2
│       ├── cisco_acl.j2
│       ├── dns_rpz.j2
│       ├── unbound_zone.j2
│       ├── snort3.j2
│       └── suricata.j2
tests/
├── test_cep_aggregator.py         # M1: Ingestion, sliding window, dedup, flood collapsing, fusion
├── test_agentic_triage.py         # M2: LangGraph nodes, risk scoring math, MITRE mapping, latency SLA
├── test_countermeasures.py        # M3: Countermeasure syntax validation, STIX 2.1 schema, diode safety
└── test_incident_e2e.py           # M4: End-to-end detector -> CEP -> LangGraph -> Countermeasures
```
