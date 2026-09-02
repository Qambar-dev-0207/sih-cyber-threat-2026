# Project: SIH26145 Phase 6 — APT Simulation, Stress Invariants & Judge Demo

## Architecture
- **Passive Ingestion**: Zeek connection, DNS, SSL telemetry normalized and partitioned by host affinity (MurmurHash3 / CRC32).
- **6 Parallel Streaming Threat Detectors**: `ddos_entropy`, `portscan_hll`, `exfil_ratio`, `dga_lstm`, `ja4_malware`, `c2_beacon`.
- **Fast In-Memory CEP Aggregation Engine**: Sliding window buffers, Token Bucket burst limiter, deduplicator, confidence fuser with multi-stage kill-chain synergy escalation.
- **LangGraph 5-Node StateGraph Triage Engine**: CorrelationNode -> RiskScoringNode -> ClassificationNode -> CountermeasureNode -> HandoffNode.
- **Countermeasure Generators**: Deterministic out-of-band artifact generation (`iptables`, `nftables`, `cisco_acl`, `dns_rpz`, `snort3`, `stix_bundle`) with strict `requires_human_approval: true`.
- **FastAPI / WebSocket Layer**: In-memory ring buffer (bounded 500 items), `/ws/telemetry` and `/ws/incidents` real-time push.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---|---|---|---|
| F1 | 4-Stage APT Telemetry Generator | Injects Recon (SYN scan T1595.001), DGA (T1568.002), JA4 Malware (T1071.001), C2 Beaconing (CV < 0.15 T1071.001) | M1 | ORIGINAL_REQUEST §R1 |
| F2 | E2E Fusion & Collapsing Engine | Fuses 4 stages into 1 incident context in < 1.5s total latency | M1 | ORIGINAL_REQUEST §R1 |
| F3 | Fused Risk Score & Synergy | Calculates risk score >= 85.0 (CRITICAL) with multi-stage synergy bonus | M1 | ORIGINAL_REQUEST §R1 |
| F4 | 6 Countermeasure Artifacts | Generates iptables, nftables, cisco_acl, dns_rpz, snort3, stix_bundle with requires_human_approval: true | M1 | ORIGINAL_REQUEST §R1 |
| F5 | Standalone Rehearsal CLI Script | `scripts/rehearse_demo.py` for automated end-to-end replay | M1 | ORIGINAL_REQUEST §R1 |
| F6 | Sustained Line-Rate Stress Harness | Ingests >= 15,000 EPS sustained load with 0 dropped frames | M2 | ORIGINAL_REQUEST §R2 |
| F7 | Zero Memory Leak & Bounded Buffers | Verifies < 10MB heap growth during 25k event load and ring buffer strictly bounded at 500 | M2 | ORIGINAL_REQUEST §R2 |
| F8 | Latency SLAs Verification | Invariant check: < 500ms ingest-to-alert, < 2.0s agentic triage | M2 | ORIGINAL_REQUEST §R2 |
| F9 | Strict Data-Diode Invariant Trap | Programmatic audit asserting 0 outbound sockets, HTTP requests, packet injections, or exec calls | M2 | ORIGINAL_REQUEST §R2 |
| F10 | Interactive Judge Demo Runner CLI | `scripts/demo_runner.py` colorized CLI with 4 1-click execution options, live latency, risk breakdown | M3 | ORIGINAL_REQUEST §R3 |
| F11 | Dual Mode Support | Offline in-memory simulation mode & live Docker Compose environment support | M3 | ORIGINAL_REQUEST §R3 |
| F12 | Hackathon Presentation Runbook | `docs/DEMO_RUNBOOK.md` with 5-minute timed script, troubleshooting, and port cheat-sheet | M3 | ORIGINAL_REQUEST §R3 |
| F13 | Full 100% Repository Test Pass | `pytest tests/` passes 100% across all phases (Phases 0-6) with 0 failures | M4 | ORIGINAL_REQUEST §Acceptance Criteria |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|---|---|---|---|
| M1 | R1: E2E Multi-Stage APT Simulation & Rehearsal | `tests/test_phase6_e2e_rehearsal.py`, `scripts/rehearse_demo.py` | none | DONE |
| M2 | R2: Line-Rate Stress & Zero Return-Path Diode Invariants | `tests/test_phase6_stress_and_invariants.py` | M1 | IN_PROGRESS |
| M3 | R3: Interactive Demo Runner & Pitch Runbook | `scripts/demo_runner.py`, `docs/DEMO_RUNBOOK.md` | M1, M2 | IN_PROGRESS |
| M4 | Final: Full Test Suite Verification (Phases 0-6) | Full test verification under `pytest tests/` + adversarial coverage check | M1, M2, M3 | PLANNED |

## Code Layout
- `src/`: Ingest models, streaming bus, 6 detectors, CEP engine, LangGraph triage, countermeasure generators, FastAPI backend.
- `tests/`: Unit, integration, stress, adversarial, and Phase 6 tests (`test_phase6_e2e_rehearsal.py`, `test_phase6_stress_and_invariants.py`).
- `scripts/`: Rehearsal and demo scripts (`rehearse_demo.py`, `demo_runner.py`).
- `docs/`: Presentation runbook and documentation (`DEMO_RUNBOOK.md`).

## Interface Contracts
### Telemetry -> DetectorManager
- Input: `ConnTelemetryEvent`, `DnsTelemetryEvent`, `SslTelemetryEvent`.
- Output: `List[RawAlert]` dispatched to `InMemoryStreamingBus` topic `alerts.raw`.

### RawAlerts -> CEPAggregatorEngine
- Input: `RawAlert` events.
- Output: `FusedIncident` with correlation metadata, deduplicated count, burst status.

### FusedIncident -> LangGraph Triage
- Input: `FusedIncident` or `TriageStateDict`.
- Output: `TriageStateDict` with risk score, severity, MITRE techniques, and 6 countermeasure artifacts.

### Countermeasure Artifacts
- All 6 artifacts must have: `content: str`, `syntax_valid: bool = True`, `requires_human_approval: bool = True`.
