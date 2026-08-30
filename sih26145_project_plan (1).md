# SIH26145 — Full Project Plan
### The Problem, How We're Solving It, and the Complete Build Process

**Sponsoring org:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity
**Idea submission deadline:** 20 September 2026

---

## 1. The Problem

Critical-infrastructure operators watch their gateway and peering links using **data diodes** — hardware that copies traffic into a monitoring enclave in one direction only. The enclave sees everything crossing the link but has **no physical or protocol-level path back** into the production network. This is deliberate: it removes an entire class of attack where a compromised monitoring/analytics system becomes a pivot into the core network, and it preserves a clean forensic chain of custody.

The task: build an AI/ML pipeline that ingests this one-directional stream and detects, classifies, and scores six classes of threat in near real time, using **only passively observed data**:

- Volumetric/protocol DDoS
- Botnet C2 beaconing
- DGA domains & DNS tunnelling
- Malware inside encrypted sessions (metadata only, no decryption)
- Reconnaissance/port scanning
- Data exfiltration

**Hard constraints (non-negotiable, stated explicitly in the PS):**
1. Read-only ingest — no return path, no probes, no inline block
2. No payload decryption — TLS/QUIC analyzed from metadata only
3. Streaming, not batch — bounded latency, not an end-of-run report
4. A stated, *demonstrated* throughput number
5. A standardized alert schema (timestamp, flow ID, threat class, confidence score, evidence)

---

## 2. The Constraint That Shapes Everything

Before describing the solution, one design decision needs to be explicit, because it's the most common way a team loses this problem statement:

**The system can never act back into the network it's watching — not even to stop an attack it's certain about.**

This isn't a limitation we're working around; it's the entire point of a data diode. If the monitoring system could block traffic, it would need a path back into production — and a compromised monitoring system with actuation power is exactly the pivot-attack the diode architecture exists to prevent, as the PS states outright.

So "counteracting the attack" in this system means something specific:

- The AI **detects, classifies, and scores** the threat.
- The AI **generates a concrete, ready-to-use countermeasure** — a firewall rule, an IDS signature, a blocklist entry, an isolation runbook — as a structured artifact.
- The AI **hands that artifact off** to a human analyst or a separately-secured, out-of-band system on the production side.
- **The AI never executes it itself, and never crosses back through the diode.**

This is not a weaker version of "stop the attack." It's the same amount of intelligence work — detection, classification, risk scoring, and a concrete recommended fix — stopping at the one line the architecture cannot cross. It also matches how real enterprise NDR/SOAR systems handle this exact scenario: autonomous *decision-support*, human- or separately-authorized *execution*.

---

## 3. Solution — High-Level Concept

A five-stage pipeline: **passive capture → streaming detection (six parallel detectors) → agentic triage & risk scoring → countermeasure generation → human/out-of-band handoff.**

Nothing in this system assumes it can talk back to the network it's watching. Its entire output is a stream of structured, evidence-backed, actionable records — the system's job ends the moment it has told a human exactly what's happening and exactly what to do about it.

```
Data Diode / Mirror Port (read-only, one-way — hardware enforced)
        │
        ▼
   Zeek Sensor            → passive capture: conn/dns/ssl/x509 logs,
   (ingest layer)            native JA4 fingerprints, per-connection UID
        │
        ▼
   Kafka Backbone          → decouples ingest rate from detector rate;
                              this is what the throughput number is tested against
        │
        ├── DDoS / Volumetric Detector        (entropy + EWMA)
        ├── C2 Beaconing Detector               (streaming periodicity score)
        ├── DGA / DNS Tunnel Detector            (char-LSTM on dns.log)
        ├── Encrypted Malware Detector           (JA4 fingerprint + anomaly)
        ├── Recon / Port Scan Detector           (HyperLogLog fan-out)
        └── Exfiltration Detector                (byte-ratio baseline)
                        │  raw per-detector alerts
                        ▼
        Agentic Triage & Risk-Scoring Layer     ← THE differentiator
        (LangGraph-orchestrated agent pipeline)
        - correlates alerts into one incident
        - assigns a confidence-weighted risk score
        - classifies the attack type and likely intent
        - generates a concrete countermeasure artifact
                        │
                        ▼
        Alert + Recommendation Store (Postgres/Timescale)
                        │
                        ▼
        Dashboard (Next.js + FastAPI)  →  human analyst sees the incident,
                                            evidence, and the ready-to-deploy fix
                        │
                        ▼
        Out-of-band handoff (webhook / SOC ticket / email / Slack)
        to a SEPARATE, non-diode system for execution — never automated
        by this system, never crossing back through the diode
```

---

## 4. Why This Beats a Static "Score and Display" System

Most teams tackling this PS will stop at: detect → score → show on a dashboard. That satisfies the PS but gives an analyst six numbers and no next step. Our system does the same detection work, but the agentic layer turns raw detections into **decision-ready output**:

- Instead of "DGA probability 0.91 on domain X" → *"Host 10.2.4.17 is very likely running a DGA-based C2 beacon. Recommended action: block DNS resolution for the flagged domain pattern at the resolver; isolate host 10.2.4.17 pending investigation. Suggested firewall rule attached."*
- Instead of six separate medium-confidence alerts for the same host → **one fused, high-confidence incident** with a kill-chain narrative and one recommended response plan.

This is the genuine novelty: not a new detection algorithm (those are all proven, published techniques — see Section 9), but an **agentic decision-support layer** that does the last mile of an analyst's job, safely, without ever needing to act back into the network itself.

---

## 5. The Six Detectors (unchanged science, proven techniques)

| Threat class | Technique | Why it works |
|---|---|---|
| DDoS / volumetric | Shannon entropy of source-IP distribution over sliding windows + EWMA baselining | Standard, cheap, provably real-time; proven enough to be offloaded into P4 switches in research settings |
| C2 beaconing | Streaming periodicity/dispersion scoring on short rolling time buckets | Fixes the batch-only limitation of tools like RITA (documented ~2-minute connection floor), which this PS's "streaming, not batch" requirement rules out |
| DGA / DNS tunnelling | Character-level LSTM on live DNS queries (~98% TPR / 0.1% FPR baseline, Woodbridge et al.) + entropy/NXDOMAIN-rate for tunnelling | Published, reproducible baseline; add a word-embedding path for dictionary-style DGAs, which char-level models underperform on |
| Encrypted malware | JA4/JA4S fingerprint match + metadata-only packet-size/timing anomaly scoring | JA4 is randomization-resistant (fixes JA3's weakness against Chrome's randomized ClientHello); Zeek has native JA4 support (Jan 2026) — no TLS decryption needed |
| Recon / port scanning | HyperLogLog-based fan-out cardinality per source | Approximate counting is the only way this scales to a real throughput target — exact counting doesn't |
| Data exfiltration | Per-host baseline of outbound/inbound byte ratio, EWMA/percentile-based | Flags asymmetric spikes relative to a host's *own* history, not a global threshold |

Ingest layer: **Zeek**, pointed at the diode's mirrored output. Don't rebuild packet parsing — Zeek is purpose-built for exactly this passive, one-way use case and gives JA4 fingerprints, connection logs, and a per-flow UID out of the box.

---

## 6. Agentic Triage & Response-Recommendation Layer (the core build)

This is where your original idea lives, made diode-compliant. Built as a LangGraph agent graph, since this maps directly to existing tooling fluency.

**Stage 1 — Correlation.** Collects raw alerts from all six detectors for a given host/flow over a rolling window. Groups related signals (e.g., a scan → a DGA query → a beacon from the same source, in sequence) into a single incident context.

**Stage 2 — Risk scoring.** A weighted-evidence model (not a black box) assigns a confidence-weighted risk score to the incident. Weighted-evidence is deliberate: it's explainable by construction, which satisfies the PS's "supporting evidence" requirement literally, and it's defensible when a judge asks "how did you get this number" — a GNN or opaque model is not, under hackathon time pressure.

**Stage 3 — Classification.** The agent labels the likely attack pattern (e.g., "reconnaissance → C2 establishment," "volumetric DDoS," "slow exfiltration") using the fused evidence, not a single detector's output in isolation.

**Stage 4 — Countermeasure generation.** The agent produces a **concrete, structured artifact** appropriate to the classified attack — not a vague suggestion:
- Recon/scan → suggested firewall/ACL rule blocking the offending source
- DGA/C2 → suggested DNS resolver blocklist entry + suggested host isolation
- DDoS → suggested rate-limit rule or upstream blackhole route recommendation
- Exfiltration → suggested egress rule + flagged destination for review

**Stage 5 — Handoff.** The artifact is written to the alert store and pushed via an out-of-band channel (webhook, SOC ticketing integration, Slack/email) to a system or person authorized to act on the production network. **This is the hard boundary — nothing here reaches back through the diode.**

---

## 7. Alert & Recommendation Schema

```json
{
  "timestamp": "ISO-8601",
  "incident_id": "string",
  "flow_ids": ["zeek community-id or UID", "..."],
  "threat_class": "ddos | c2_beacon | dga | dns_tunnel | encrypted_malware | port_scan | exfiltration | fused_incident",
  "attack_narrative": "human-readable kill-chain summary generated by the agent",
  "confidence_score": 0.0,
  "severity": "low | medium | high | critical",
  "source_ip": "string",
  "destination_ip": "string",
  "supporting_evidence": [
    {"feature": "string", "value": "string/number", "detector": "string"}
  ],
  "host_risk_score": 0.0,
  "recommended_action": {
    "action_type": "firewall_rule | dns_blocklist | isolation | rate_limit | manual_review",
    "artifact": "the generated rule/signature/runbook text",
    "requires_human_approval": true
  }
}
```

`requires_human_approval` defaults to `true` for every action type, always. There is no field or flag that allows this system to execute its own recommendation.

---

## 8. Data & Training Plan

**Synthetic/lab traffic (per the PS's own suggested tooling):**
- Benign load: iperf3, Ostinato, TRex
- Attacks: hping3 (SYN/UDP floods), Slowloris, dnscat2/iodine (DNS tunnelling), DGA samples from published algorithms or a sandboxed C2 emulator

**Public dataset pretraining:**
- CIC-IDS2018 / CICFlowMeter features for general IDS pretraining
- CTU-13 for botnet C2 behavioral patterns
- A published DGA domain corpus for the DGA classifier

**Approach:** pretrain each ML component on public data, fine-tune/validate on synthetic replay to close the sim-to-real gap. Handle class imbalance explicitly — attack traffic is a small minority by design, and this is a well-documented IDS failure mode if ignored.

---

## 9. Throughput Plan

Do this on **Day 1**, before any detector or agent code: stand up Zeek → Kafka with nothing else attached, replay traffic via TRex/iperf3, and measure the real sustained rate. This is the number the PS asks you to state and demonstrate — it has to be tested, not estimated.

If pure Python can't hold the target: move hot-path stateful counters (entropy, HLL cardinality) into Cython or a small Go/Rust sidecar, keep ML inference and the agent layer in Python (ONNX export for the LSTM keeps inference fast). Shard by source-IP hash across Kafka consumers if needed.

---

## 10. Tech Stack

| Layer | Tool | Why |
|---|---|---|
| Ingest | Zeek | Purpose-built for passive capture, native JA4 |
| Streaming backbone | Kafka | Decouples ingest from detector rate, benchmarkable |
| Detectors | Python | Fast iteration; upgrade hot paths only if benchmark demands it |
| Agentic layer | **LangGraph** | Existing fluency; natural fit for a multi-stage correlate → score → classify → recommend pipeline |
| ML models | LSTM (DGA), ONNX export | Published baseline, fast inference |
| Alert store | PostgreSQL / TimescaleDB | Time-series friendly |
| Dashboard backend | FastAPI | Existing fluency |
| Dashboard frontend | Next.js + WebSocket | Existing fluency |
| Handoff | Webhook / Slack / email / ticketing API | Out-of-band by design — physically separate from the diode path |

---

## 11. Build Process — Day by Day

| Days | Focus |
|---|---|
| **Day 1** | Zeek → Kafka pipeline up, throughput benchmark with zero detectors attached. Get a real number before writing anything else. |
| **Day 2–3** | DDoS, port-scan, and exfiltration detectors — cheapest, most standard techniques, get early wins working end-to-end. |
| **Day 3–4** | DGA classifier (pretrain on public data first), JA4 fingerprint matching against a maintained bad-fingerprint feed. |
| **Day 4–5** | C2 beaconing streaming detector — the hardest one; this is where the "streaming not batch" requirement actually gets tested. |
| **Day 5–6** | Build the LangGraph agentic layer: correlation → risk scoring → classification → countermeasure generation. This is the flagship demo component — give it real time. |
| **Day 6–7** | Dashboard, out-of-band handoff integration (even a Slack webhook is enough for a demo), live replay run, throughput re-verification, pitch rehearsal. |

---

## 12. Honest Risk Register

| Risk | Status | Mitigation |
|---|---|---|
| Thin novelty margin vs. existing NDR products | **Improved** — the agentic recommendation layer is a real differentiator most open-source/commercial tools don't do cleanly | Lead the pitch with a live incident → recommendation demo, not a detector-by-detector walkthrough |
| Unverified throughput claim | Still open | Benchmark Day 1, before any detector code |
| Domain skills mismatch (network flow analysis vs. team's agentic AI background) | **Reduced** — the flagship component (agentic layer) now plays directly to existing strength; the network-flow detectors lean on well-published, implementable techniques rather than novel research | Still assign explicit ownership of the Zeek/flow-analysis pieces to whoever ramps fastest on it |
| Temptation to over-promise autonomous blocking in the pitch | **New — watch this** | Be explicit and confident about the human-in-the-loop boundary in the pitch itself; framing it as a deliberate security decision (not a limitation) is a stronger position than dodging the question |
| License exposure (RITA/Corelight as reference points) | Still open | Reimplement from published statistical approaches; confirm licensing before reusing any RITA source |

---

## 13. Differentiation Pitch (for judges)

> Every detector in this system uses a proven, published technique — we didn't reinvent DDoS entropy scoring or JA4 fingerprinting. What we built instead is the piece we think is actually missing from the open-source landscape: a genuinely streaming detection layer, fused into one scored incident instead of six disconnected alerts, handed to an AI agent that classifies the attack and generates a concrete, ready-to-deploy countermeasure — firewall rule, blocklist entry, isolation runbook — for a human to approve and execute. The system never acts back into the network it's watching, by design, because a monitoring system that can act back is exactly the pivot-attack risk a data diode exists to eliminate. We're not weakening "stop the attack" — we're doing all the intelligence work up to the one line this architecture cannot cross, and stopping there on purpose.

---

## 14. References (for further reading, no content reproduced)

- Zeek — https://zeek.org
- RITA (Active Countermeasures) — https://github.com/activecm/rita
- Corelight (Zeek-based NDR, unidirectional/ICS-OT deployments) — https://corelight.com
- JA4+ fingerprinting suite (FoxIO) — https://github.com/FoxIO-LLC/ja4
- Zeek JA4 integration announcement — https://zeek.org/2026/01/how-to-use-ja4-network-fingerprints-in-zeek/
- Woodbridge et al., LSTM-based DGA classification (baseline technique referenced in multiple surveys)
- Koh & Rhodes, "Inline Detection of Domain Generation Algorithms with Context-Sensitive Word Embeddings" — https://arxiv.org/pdf/1811.08705
- Hofstede et al., "Towards Real-Time Intrusion Detection for NetFlow and IPFIX" — https://cnsm-conf.org/2013/documents/papers/CNSM/p227-hofstede.pdf
- Kentik, flow-based DDoS detection methodology — https://www.kentik.com/kentipedia/detect-ddos-attacks-flow-analytics/
