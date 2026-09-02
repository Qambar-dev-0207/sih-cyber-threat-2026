# E2E Test Infra: SIH26145 Phase 6

## Test Philosophy
- Opaque-box and requirement-driven verification of Phase 6 deliverables.
- Methodologies: Category-Partition, Boundary Value Analysis, Pairwise Combinatorial Testing, and Real-World APT Rehearsal.

## Feature Inventory & Test Mapping
| # | Feature | Source | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (Scenario) |
|---|---|---|:---:|:---:|:---:|:---:|
| F1 | 4-Stage APT Telemetry Generator | ORIGINAL_REQUEST §R1 | ✓ | ✓ | ✓ | ✓ |
| F2 | E2E Pipeline Fusion & Collapse | ORIGINAL_REQUEST §R1 | ✓ | ✓ | ✓ | ✓ |
| F3 | Fused Risk Score (>= 85.0) & Synergy | ORIGINAL_REQUEST §R1 | ✓ | ✓ | ✓ | ✓ |
| F4 | 6 Countermeasures & Human Approval | ORIGINAL_REQUEST §R1 | ✓ | ✓ | ✓ | ✓ |
| F5 | Standalone Rehearsal Script | ORIGINAL_REQUEST §R1 | ✓ | ✓ | ✓ | ✓ |
| F6 | Sustained Line-Rate Stress (>= 15k EPS) | ORIGINAL_REQUEST §R2 | ✓ | ✓ | ✓ | ✓ |
| F7 | Zero Memory Leaks (< 10MB) & 500-Item Ring Buffer | ORIGINAL_REQUEST §R2 | ✓ | ✓ | ✓ | ✓ |
| F8 | Latency SLAs (< 500ms Ingest, < 2.0s Triage) | ORIGINAL_REQUEST §R2 | ✓ | ✓ | ✓ | ✓ |
| F9 | Strict Passive Data-Diode Invariant Trap | ORIGINAL_REQUEST §R2 | ✓ | ✓ | ✓ | ✓ |
| F10 | Interactive Demo Runner CLI | ORIGINAL_REQUEST §R3 | ✓ | ✓ | ✓ | ✓ |
| F11 | Dual Mode (Offline & Live Docker) | ORIGINAL_REQUEST §R3 | ✓ | ✓ | ✓ | ✓ |
| F12 | Hackathon Presentation Runbook | ORIGINAL_REQUEST §R3 | ✓ | ✓ | ✓ | ✓ |
| F13 | Full 100% Repository Test Pass (Phases 0-6) | ORIGINAL_REQUEST §Acceptance Criteria | ✓ | ✓ | ✓ | ✓ |

## Test Architecture & Runners
- Test Runner: `pytest tests/`
- Target Phase 6 Suites:
  - `tests/test_phase6_e2e_rehearsal.py`
  - `tests/test_phase6_stress_and_invariants.py`
- Rehearsal and Demo Scripts:
  - `scripts/rehearse_demo.py`
  - `scripts/demo_runner.py`
- Presentation Guide:
  - `docs/DEMO_RUNBOOK.md`
