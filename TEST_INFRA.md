# Test Architecture & 4-Tier Test Infrastructure Specification

## SIH26145 Passive Network Threat Detection System — Phase 1 & Phase 2

---

## 1. Overview & Quality Mandate

The SIH26145 platform is a high-throughput, passive network monitoring and real-time threat detection system designed for air-gapped / data diode defense enclaves. Operating under strict zero-loss, zero-decryption, and read-only constraints, the system comprises:
- **Phase 1: Streaming Ingestion & Partitioning Pipeline**: Real-time Zeek JSON log tailing (`conn.log`, `dns.log`, `ssl.log`), Pydantic event normalization, deterministic `Murmur3(source_ip) % 4` partitioning, and high-throughput streaming bus integration (`telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw`).
- **Phase 2: Six Parallel Streaming Threat Detectors**:
  1. *Volumetric & Protocol DDoS*: Sliding Shannon entropy $H(X_{\text{dport}})$ + EWMA flow rate variance $Z$-score.
  2. *Port Scanning & Reconnaissance*: Dual-Bucket Slotted HyperLogLog (HLL, $p=10$) for 10s rolling distinct port/host cardinality.
  3. *Data Exfiltration*: Asymmetric directional byte-ratio $R_{\text{out/in}}$ with streaming per-host $P^2$ quantile baselining ($p_{95}, p_{99}$).
  4. *DGA & DNS Tunnelling*: Pretrained Char-BiLSTM ONNX inference ($< 1\text{ ms}$) + Subdomain Shannon entropy $+ \text{NXDOMAIN}$ spike tracking.
  5. *Encrypted Malware (Metadata Only)*: Curated JA4/JA4S threat intelligence database matching + 5-feature TLS handshake anomaly scoring.
  6. *C2 Beaconing*: Streaming inter-arrival time ($\Delta T$) circular buffer calculating Coefficient of Variation ($CV = \sigma/\mu < 0.15$), median interval, and MAD dispersion.

### Core Integrity Rules
1. **No Facade Tests**: Zero mock passes that do not exercise real protocol logic, token-bucket math, DDL structures, or cryptographic hash routines.
2. **Progressive Testability**: All tests are runnable against completed milestones without forward-dependency on unbuilt downstream components.
3. **Deterministic Oracles**: Expected outputs are derived directly from RFCs (TLS 1.2/1.3, JA4 FoxIO standard, DNS wire formats), SQL standards, and `PROJECT.md` mathematical interface contracts.
4. **Sub-500ms Streaming SLA**: All detector pipelines must process telemetry and emit raw alerts within $< 500\text{ ms}$ of ingestion without batching bottlenecks.
5. **Strict Schema Compliance**: Every emitted alert must conform strictly to the standardized `RawAlert` schema with complete mathematical evidence payloads.

---

## 2. The 4-Tier Test Methodology Architecture

All testing across Phase 1 and Phase 2 adheres to the 4-Tier Test Methodology:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               4-TIER TEST PYRAMID                                │
├──────────────────────────────────────────────────────────────────────────────────┤
│  TIER 4: REAL-WORLD & ADVERSARIAL STRESS                                         │
│  - Full PCAP Replay (Benign baseline, SYN flood, Nmap stealth, C2 jitter)        │
│  - Line-rate latency assertions (p50 < 5ms, p99 < 50ms, Max < 500ms)             │
│  - 0% False Positive Rate on benign traffic / >= 98% True Positive Rate          │
├──────────────────────────────────────────────────────────────────────────────────┤
│  TIER 3: CROSS-FEATURE & END-TO-END INTEGRATION                                  │
│  - Ingestion -> Partitioning -> Bus -> 6 Parallel Detectors -> alerts.raw        │
│  - Multi-stream correlation (conn.log + dns.log + ssl.log on matching UID/Host) │
│  - Zero-lock stateful locality across 4 deterministic partitions                 │
├──────────────────────────────────────────────────────────────────────────────────┤
│  TIER 2: BOUNDARY & CORNER CASES (>= 5 tests per feature)                        │
│  - Extreme rates (1 pps -> 50,000+ pps), zero-byte packets, empty logs           │
│  - HLL register saturation, zero vs max entropy, single-flow cold-start P²       │
│  - Negative/zero delta intervals, clock jumps, malformed JSON, GREASE filtering  │
├──────────────────────────────────────────────────────────────────────────────────┤
│  TIER 1: CORE FEATURE COVERAGE (>= 5 tests per feature)                          │
│  - Primary functional paths for Ingestion, Partitioning, and all 6 Detectors    │
│  - Data model validation, serialization, and mathematical oracle checks          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

| Tier | Category | Minimum Requirement | Purpose |
|---|---|---|---|
| **Tier 1** | **Core Feature Coverage** | $\ge 5$ tests per feature | Validate primary functional paths, normalization models, deterministic partitioning, and mathematical detection logic for all 6 detectors. |
| **Tier 2** | **Boundary & Corner Cases** | $\ge 5$ tests per feature | Test extremes (0-byte packets, empty fields, single packet vs 100k packets, 0-entropy vs max entropy, zero interval $\Delta t = 0$, cold-start quantile baselines). |
| **Tier 3** | **Cross-Feature Pairwise** | All module interfaces | Verify end-to-end data contracts between Log Tailers $\leftrightarrow$ Pydantic Normalizers $\leftrightarrow$ Partitioned Bus $\leftrightarrow$ 6 Detector Workers $\leftrightarrow$ `alerts.raw` $\leftrightarrow$ TimescaleDB. |
| **Tier 4** | **Real-World & Adversarial Stress** | Defense resilience tests | Test synthetic/real PCAP replays (Benign, DDoS SYN Flood, Nmap Port Scan, Exfil, DGA, JA4 Malware, C2 Jittered Beaconing), line-rate latency ($< 500\text{ ms}$), and accuracy (TPR $\ge 98\%$, FPR $\le 1\%$). |

---

## 3. Feature Inventory & Exhaustive 4-Tier Test Matrix

| Feature ID | Feature Name | Component | Tier 1 (Core) | Tier 2 (Boundary) | Tier 3 (Cross) | Tier 4 (Adversarial) | Total Tests |
|---|---|---|---|---|---|---|---|
| **F1** | Zeek Log Ingestion & Normalization (`conn.log`, `dns.log`, `ssl.log`) | `src.ingestion.zeek_log_tailer`, `src.ingestion.models` | 6 | 6 | 3 | 3 | **18** |
| **F2** | Deterministic Source-IP Partitioning (`Murmur3(src_ip) % 4`) | `src.ingestion.streaming_bus`, `src.ingestion.kafka_producer` | 5 | 5 | 3 | 2 | **15** |
| **F3** | Streaming Bus Abstraction (`InMemoryStreamingBus` & Kafka) | `src.ingestion.streaming_bus` | 6 | 5 | 3 | 3 | **17** |
| **F4** | Detector 1: Volumetric & Protocol DDoS (Entropy + EWMA) | `src.detectors.ddos_entropy` | 6 | 6 | 3 | 3 | **18** |
| **F5** | Detector 2: Port Scanning & Recon (Dual-Bucket HLL $p=10$) | `src.detectors.portscan_hll` | 6 | 6 | 3 | 3 | **18** |
| **F6** | Detector 3: Data Exfiltration ($R_{\text{out/in}}$ + $P^2$ Baselining) | `src.detectors.exfil_ratio` | 6 | 6 | 3 | 3 | **18** |
| **F7** | Detector 4: DGA & DNS Tunnelling (ONNX BiLSTM + Subdomain Entropy) | `src.detectors.dga_tunneling` | 6 | 6 | 3 | 3 | **18** |
| **F8** | Detector 5: Encrypted Malware (JA4/JA4S Threat Intel + TLS Anomaly) | `src.detectors.encrypted_malware` | 6 | 6 | 3 | 3 | **18** |
| **F9** | Detector 6: C2 Beaconing ($\Delta T$ Circular Buffer $CV < 0.15$) | `src.detectors.c2_beaconing` | 6 | 6 | 3 | 3 | **18** |
| **F10** | Standardized `RawAlert` Schema Serialization (`alerts.raw`) | `src.ingestion.models` | 5 | 5 | 3 | 2 | **15** |
| **F11** | End-to-End Streaming Latency ($< 500\text{ ms}$) & Line-Rate Throughput | `src.utils.metrics_calculator`, `tests.test_e2e_opaque_box` | 5 | 5 | 3 | 4 | **17** |
| **TOTAL** | **Phase 1 & Phase 2 Master Test Matrix** | — | **63** | **60** | **33** | **31** | **187+** |

---

## 4. Detailed Test Breakdown by Feature & Tier

### Feature 1: Zeek Log Ingestion & Normalization
- **Tier 1 (Core)**:
  1. `test_conn_log_normalization`: Parse valid `conn.log` JSON record into `ConnTelemetryEvent`.
  2. `test_dns_log_normalization`: Parse valid `dns.log` JSON record into `DnsTelemetryEvent` with automatic subdomain extraction.
  3. `test_ssl_log_normalization`: Parse valid `ssl.log` JSON record into `SslTelemetryEvent` with JA4 fingerprints.
  4. `test_zeek_log_tailer_batch_reading`: Tail simulated log file and read lines in batch mode.
  5. `test_multi_zeek_log_tailer_orchestration`: Tail `conn.log`, `dns.log`, and `ssl.log` simultaneously from directory.
  6. `test_event_serialization_roundtrip`: Verify `model_dump()`, `model_dump_json()`, and `from_zeek_dict()` consistency.
- **Tier 2 (Boundary & Corner)**:
  1. `test_empty_and_comment_lines`: Ignore blank lines and `#fields` header comments without error.
  2. `test_missing_optional_fields`: Handle missing `service`, `community_id`, `subdomain`, `ja4` gracefully.
  3. `test_dash_and_null_coercion`: Coerce Zeek dash entries (`"-"`) to appropriate numeric `0` or `None`.
  4. `test_malformed_json_resilience`: Skip corrupt JSON lines without crashing the streaming tailer.
  5. `test_extreme_port_bounds`: Validate rejection or normalization of invalid port numbers ($<0$ or $>65535$).
  6. `test_log_rotation_and_truncation`: Verify tailer re-opens file upon inode change or size truncation.
- **Tier 3 (Cross-Feature)**:
  1. `test_tailer_to_pydantic_pipeline`: Direct streaming from `ZeekLogTailer` into Pydantic models.
  2. `test_conn_and_ssl_uid_correlation`: Join `ConnTelemetryEvent` and `SslTelemetryEvent` across matching `uid`.
  3. `test_dns_query_to_conn_5tuple_matching`: Match DNS resolutions to subsequent TCP connections.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_high_frequency_log_tailing_burst`: Tail 50,000 log lines in under 1 second.
  2. `test_adversarial_unicode_in_dns_query`: Handle null bytes, control characters, and punycode in domain queries.
  3. `test_concurrent_multi_file_tailing_stress`: Tail 3 logs concurrently under intense write load.

---

### Feature 2: Deterministic Source-IP Partitioning
- **Tier 1 (Core)**:
  1. `test_murmur3_partition_deterministic`: Verify `Murmur3(ip) % 4` produces identical partition across runs.
  2. `test_source_ip_extraction_from_models`: Correctly extract `src_ip` from `ConnTelemetryEvent`, `DnsTelemetryEvent`, and `SslTelemetryEvent`.
  3. `test_source_ip_extraction_from_dict`: Extract `id.orig_h`, `orig_h`, `src_ip`, and `source_ip` keys.
  4. `test_even_partition_distribution`: Verify ~25% distribution across 4 partitions for 1,000 random IPs.
  5. `test_partition_range_strictness`: Assert all partition indices fall strictly in $[0, 3]$.
- **Tier 2 (Boundary & Corner)**:
  1. `test_empty_or_none_source_ip`: Fall back to default partition `0` for empty/None strings.
  2. `test_ipv6_partitioning`: Deterministically partition IPv6 addresses (e.g. `2001:db8::1`).
  3. `test_loopback_and_multicast_ips`: Partition `127.0.0.1`, `224.0.0.1`, `255.255.255.255`.
  4. `test_single_partition_edge_case`: Handle `num_partitions = 1` returning partition `0`.
  5. `test_unparseable_string_partitioning`: Handle arbitrary non-IP strings without exception.
- **Tier 3 (Cross-Feature)**:
  1. `test_per_host_stateful_locality`: Verify 100% of packets from `192.168.1.105` route to the exact same queue.
  2. `test_multi_host_partition_isolation`: Verify packets from different hosts route independently without cross-talk.
  3. `test_bus_and_producer_partition_agreement`: Assert `calculate_partition_key` and `get_source_ip_partition` match.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_spoofed_ddos_partition_spread`: Verify randomized source IP flood distributes evenly across all 4 partitions.
  2. `test_10k_host_partition_performance`: Partition 10,000 IPs in $< 10\text{ ms}$.

---

### Feature 3: Streaming Bus Abstraction (`InMemoryStreamingBus` & Kafka)
- **Tier 1 (Core)**:
  1. `test_in_memory_bus_publish_and_consume`: Publish to `telemetry.conn` and consume from partition.
  2. `test_in_memory_bus_all_topics`: Verify pre-provisioning of `telemetry.conn`, `telemetry.dns`, `telemetry.ssl`, `alerts.raw`, `incidents.fused`.
  3. `test_publish_batch_throughput`: Publish batch of 1,000 events and verify atomic delivery.
  4. `test_consume_all_partitions`: Consume aggregated records across all 4 partitions.
  5. `test_topic_size_and_metrics`: Verify queue size tracking and operational metrics payload.
  6. `test_bus_clear_and_close`: Reset topics and clean up resources safely.
- **Tier 2 (Boundary & Corner)**:
  1. `test_consume_empty_queue_timeout`: Timeout cleanly when consuming from empty queue.
  2. `test_publish_unregistered_topic`: Auto-provision new topic with 4 partitions on demand.
  3. `test_consume_invalid_partition_index`: Modulo clamp out-of-bounds partition indices.
  4. `test_raw_string_and_dict_publishing`: Publish Pydantic model, raw dictionary, and JSON string.
  5. `test_queue_full_and_growth`: Verify memory bus handles queue growth up to 100,000 items.
- **Tier 3 (Cross-Feature)**:
  1. `test_streaming_bus_with_producer_adapter`: Seamless fallback from Kafka producer to `InMemoryStreamingBus`.
  2. `test_detector_worker_partition_subscription`: Simulate 4 parallel detector threads reading from partition queues.
  3. `test_alerts_raw_emission_and_consumption`: Emit `RawAlert` and consume from `alerts.raw`.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_multithreaded_concurrent_publish_consume`: 8 threads publishing and 4 consuming simultaneously (>100k EPS).
  2. `test_zero_loss_under_buffer_pressure`: Verify 0 dropped events during sudden 50,000 packet burst.
  3. `test_bus_latency_overhead`: Measure publish-to-consume latency overhead ($< 50\ \mu\text{s}$).

---

### Feature 4: Detector 1: Volumetric & Protocol DDoS
- **Tier 1 (Core)**:
  1. `test_shannon_entropy_calculation`: Calculate $H(X)$ for uniform vs concentrated distributions.
  2. `test_o1_differential_entropy_update`: Verify sliding window differential update matches batch $O(N)$ calculation.
  3. `test_ewma_rate_and_zscore`: Verify EWMA rate smoothing and $Z$-score anomaly calculation.
  4. `test_syn_flood_detection_trigger`: Detect high-rate SYN flood targeting port 80 ($Z \ge 3.5, H < 1.2$).
  5. `test_udp_port_sweep_ddos_trigger`: Detect randomized UDP flood ($H_{\text{norm}} > 0.90, Z \ge 4.0$).
  6. `test_ddos_alert_evidence_payload`: Verify `current_rate_pps`, `ewma_rate_pps`, `rate_z_score`, `port_entropy`, `syn_only_ratio`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_zero_entropy_single_port`: Target port 80 repeatedly $\implies H(X) = 0.0$.
  2. `test_max_entropy_uniform_ports`: Uniform target ports across 65536 $\implies H(X) = 16.0$.
  3. `test_cold_start_insufficient_samples`: Do not trigger alert during initial warm-up ($N < 50$ packets).
  4. `test_zero_variance_epsilon_protection`: Prevent division by zero when $\sigma_t^2 = 0$.
  5. `test_sliding_window_eviction_exactness`: Verify sliding window state retains exactly $N$ entries.
  6. `test_single_packet_arrival`: Handle isolated single-packet flows without rate spikes.
- **Tier 3 (Cross-Feature)**:
  1. `test_ddos_pipeline_integration`: Ingest `conn.log` stream $\to$ partition $\to$ DDoS worker $\to$ `alerts.raw`.
  2. `test_ddos_alert_to_timescale_db`: Insert emitted `VOLUMETRIC_DDOS` alert into database schema.
  3. `test_ddos_and_portscan_coexistence`: Differentiate high-rate DDoS flood from low-rate port scan.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_pcap_ddos_syn_flood_replay`: Replay `ddos_syn_flood.pcap` $\implies$ trigger CRITICAL alert within $< 500\text{ ms}$.
  2. `test_benign_web_traffic_ddos_silence`: Replay `benign_baseline.pcap` $\implies$ 0 DDoS alerts.
  3. `test_slowloris_low_rate_rejection`: Ignore slow HTTP traffic with normal entropy and $Z < 2.0$.

---

### Feature 5: Detector 2: Port Scanning & Reconnaissance
- **Tier 1 (Core)**:
  1. `test_hyperloglog_cardinality_accuracy`: Verify HLL ($p=10$) estimates 1,000 distinct ports with error $< 5\%$.
  2. `test_slotted_dual_bucket_10s_window`: Verify rolling 10s window via register-wise maximum union.
  3. `test_vertical_port_scan_detection`: Flag source scanning $> 30$ ports on single target within 10s.
  4. `test_horizontal_subnet_sweep_detection`: Flag source scanning $> 25$ distinct IPs on port 22 within 10s.
  5. `test_strobe_matrix_scan_detection`: Flag source probing $> 50$ distinct `(dst_ip, dst_port)` pairs.
  6. `test_portscan_evidence_payload`: Verify `scan_type`, `hll_distinct_ports`, `hll_distinct_hosts`, `failure_ratio`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_hll_zero_elements`: HLL cardinality for 0 items returns exactly 0.
  2. `test_hll_single_repeated_port`: 10,000 packets to port 443 returns cardinality $\approx 1$.
  3. `test_hll_linear_counting_small_range`: Verify exactness under small cardinalities ($n \le 2.5m$).
  4. `test_connection_state_failure_weighting`: Verify `S0`, `REJ`, `RSTO` boost confidence to $\ge 0.90$.
  5. `test_dual_bucket_rotation_boundary`: Verify seamless state transition when rotating 5s sub-windows.
  6. `test_extreme_cardinality_saturation`: Estimate 65535 distinct ports without register overflow.
- **Tier 3 (Cross-Feature)**:
  1. `test_portscan_pipeline_integration`: Ingest `conn.log` stream $\to$ partition $\to$ Portscan worker $\to$ `alerts.raw`.
  2. `test_portscan_alert_to_timescale_db`: Insert `PORT_SCAN_RECON` alert into database.
  3. `test_host_state_ttl_eviction`: Verify inactive scanning hosts are evicted from LRU cache after TTL.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_pcap_portscan_nmap_replay`: Replay `portscan_nmap.pcap` $\implies$ trigger `PORT_SCAN_RECON` alert.
  2. `test_benign_baseline_portscan_silence`: Replay `benign_baseline.pcap` $\implies$ 0 port scan alerts.
  3. `test_slow_stealth_scan_boundary`: Differentiate stealthy scan vs normal multi-tab browser connection bursts.

---

### Feature 6: Detector 3: Data Exfiltration
- **Tier 1 (Core)**:
  1. `test_asymmetric_byte_ratio_calculation`: Compute $R_{\text{out/in}} = \frac{\text{orig\_bytes}}{\text{resp\_bytes} + 1024}$.
  2. `test_streaming_p2_quantile_estimation`: Verify $P^2$ markers estimate $p_{95}$ and $p_{99}$ with streaming updates.
  3. `test_massive_single_flow_exfiltration`: Detect single external flow with $\text{orig\_bytes} \ge 50\text{ MB}$ and $R_{\text{out/in}} \ge 10.0$.
  4. `test_rolling_window_ratio_spike`: Detect 60s window ratio exceeding $3.0 \times P_{95}$ baseline with $> 5\text{ MB}$ egress.
  5. `test_sustained_low_and_slow_exfiltration`: Detect $\ge 5$ min continuous egress with cumulative $> 20\text{ MB}$.
  6. `test_exfil_evidence_payload`: Verify `orig_bytes`, `resp_bytes`, `ratio_out_in`, `host_baseline_p95_ratio`, `egress_velocity_mbps`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_zero_orig_bytes_download_flow`: Handle pure download flows ($R_{\text{out/in}} \approx 0.0$).
  2. `test_zero_resp_bytes_laplace_smoothing`: Prevent division by zero with Laplace $\epsilon = 1024\text{ bytes}$.
  3. `test_rfc1918_internal_traffic_filter`: Ignore high-volume internal backup traffic between private IPs.
  4. `test_cold_start_p2_markers`: Initialize 5 markers cleanly on first 5 observed flows.
  5. `test_symmetric_flow_rejection`: Reject balanced bidirectional protocols (e.g. interactive SSH, VoIP).
  6. `test_extreme_byte_counts_int64`: Handle multi-gigabyte byte counters without overflow.
- **Tier 3 (Cross-Feature)**:
  1. `test_exfil_pipeline_integration`: Ingest `conn.log` stream $\to$ partition $\to$ Exfil worker $\to$ `alerts.raw`.
  2. `test_exfil_and_ssl_service_correlation`: Enrich exfiltration alert with SSL/TLS metadata if available.
  3. `test_exfil_alert_to_timescale_db`: Insert `DATA_EXFILTRATION` alert into database.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_https_post_exfiltration_simulation`: Simulate staged encrypted POST upload $\implies$ trigger alert.
  2. `test_benign_web_browsing_exfil_silence`: Normal web surfing (high inbound, low outbound) triggers 0 alerts.
  3. `test_chunked_exfiltration_evasion`: Catch split chunked uploads aggregated over rolling window.

---

### Feature 7: Detector 4: DGA & DNS Tunnelling
- **Tier 1 (Core)**:
  1. `test_subdomain_shannon_entropy`: Calculate entropy of normal vs random base32/hex subdomains.
  2. `test_char_bilstm_onnx_inference`: Run ONNX inference on DGA domains, asserting $P_{\text{DGA}} \ge 0.85$ and latency $< 1\text{ ms}$.
  3. `test_dns_tunneling_txt_query_detection`: Flag long subdomains ($L \ge 45$) querying TXT/NULL records.
  4. `test_nxdomain_error_spike_tracking`: Detect $R_{\text{NXDOMAIN}} \ge 0.75$ across rolling 30s window.
  5. `test_dga_trigger_composite_decision`: Evaluate multi-feature decision rule (ONNX, entropy, TXT, NXDOMAIN).
  6. `test_dga_evidence_payload`: Verify `domain`, `onnx_dga_prob`, `subdomain_entropy`, `is_nxdomain`, `qtype`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_empty_and_root_subdomain`: Handle queries without subdomain (e.g. `google.com`, `localhost`).
  2. `test_maximum_domain_length_253_chars`: Handle RFC 1035 max FQDN and max label lengths.
  3. `test_all_numeric_and_hyphenated_domains`: Score domains with numbers and hyphens accurately.
  4. `test_onnx_model_fallback_mode`: Gracefully fall back to character n-gram entropy if ONNX model is missing.
  5. `test_cname_and_ipv6_records`: Handle AAAA and CNAME queries correctly.
  6. `test_vocabulary_out_of_bounds_tokens`: Map unknown Unicode or non-ASCII characters to `<UNK>` token.
- **Tier 3 (Cross-Feature)**:
  1. `test_dga_pipeline_integration`: Ingest `dns.log` stream $\to$ partition $\to$ DGA worker $\to$ `alerts.raw`.
  2. `test_dga_and_conn_flow_correlation`: Correlate DGA alert with subsequent connection attempts in `conn.log`.
  3. `test_dga_alert_to_timescale_db`: Insert `DGA_TUNNELLING` alert into database.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_conficker_zeus_dga_dataset`: Score genuine Conficker, GameOver Zeus, and Locky DGA domains (TPR $\ge 98\%$).
  2. `test_alexa_top_1k_dga_silence`: Score top 1,000 benign domains (FPR $\le 0.5\%$).
  3. `test_dnscat2_tunneling_replay`: Detect simulated Base64 dnscat2 tunneling stream.

---

### Feature 8: Detector 5: Encrypted Malware (JA4 / TLS Metadata)
- **Tier 1 (Core)**:
  1. `test_ja4_threat_intel_exact_match`: Match Cobalt Strike / Sliver / Trickbot JA4 hashes with 100% confidence.
  2. `test_ja4s_server_fingerprint_matching`: Match malicious server TLS responses.
  3. `test_tls_handshake_anomaly_scoring`: Evaluate 5-feature score (self-signed, IP SNI, deprecated cipher, etc.).
  4. `test_self_signed_cert_detection`: Flag `issuer == subject` or self-signed validation status.
  5. `test_deprecated_cipher_flagging`: Flag RC4, 3DES, CBC cipher suites.
  6. `test_malware_evidence_payload`: Verify `matched_ja4`, `matched_ja4s`, `malware_family`, `tls_anomaly_score`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_missing_ja4_fingerprint`: Handle legacy SSL sessions without JA4 string gracefully.
  2. `test_unestablished_tls_sessions`: Score failed handshakes (`established: false`) appropriately.
  3. `test_ip_sni_vs_domain_sni`: Flag connections using raw IP literals in SNI.
  4. `test_sparse_tls_extensions`: Score ClientHello with $\le 3$ extensions as anomalous.
  5. `test_grease_cipher_filtering_in_scoring`: Ensure GREASE ciphers do not distort anomaly score.
  6. `test_malformed_threat_db_json`: Handle missing or corrupted threat intel database file safely.
- **Tier 3 (Cross-Feature)**:
  1. `test_malware_pipeline_integration`: Ingest `ssl.log` stream $\to$ partition $\to$ Malware worker $\to$ `alerts.raw`.
  2. `test_malware_and_conn_uid_join`: Correlate SSL malware alert with connection byte metrics.
  3. `test_malware_alert_to_timescale_db`: Insert `ENCRYPTED_MALWARE` alert into database.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_cobalt_strike_malleable_c2_detection`: Match Cobalt Strike default JA4 `t13d1516h2_8daaf6152771_e562703ab85e`.
  2. `test_benign_browser_ja4_silence`: Normal Chrome/Firefox JA4 hashes trigger 0 malware alerts.
  3. `test_zero_day_tls_anomaly_detection`: Flag novel unclassified malware using TLS anomaly score $\ge 0.70$.

---

### Feature 9: Detector 6: C2 Beaconing Detector
- **Tier 1 (Core)**:
  1. `test_delta_t_circular_buffer_calculation`: Compute sequence of inter-arrival intervals $\Delta t_i$.
  2. `test_coefficient_of_variation_calculation`: Compute $CV = \sigma_{\Delta t} / \mu_{\Delta t}$.
  3. `test_strict_periodic_beacon_detection`: Trigger alert on strict 10.0s beacon ($CV \approx 0.005 < 0.15$).
  4. `test_median_and_mad_dispersion`: Compute median interval $\tilde{M}_{\Delta t}$ and MAD jitter.
  5. `test_c2_jitter_tolerance_up_to_20_percent`: Trigger alert on beacon with 15% random sleep jitter ($CV \approx 0.088 < 0.15$).
  6. `test_c2_evidence_payload`: Verify `cv`, `mean_interval_sec`, `std_dev_sec`, `median_interval_sec`, `sample_count`.
- **Tier 2 (Boundary & Corner)**:
  1. `test_insufficient_samples_under_15`: Do not trigger alert before accumulating $N \ge 15$ intervals.
  2. `test_zero_delta_duplicate_timestamps`: Handle simultaneous packet arrivals ($\Delta t = 0$) safely.
  3. `test_minimum_interval_filter_under_1s`: Reject high-frequency asset bursts ($\mu_{\Delta t} < 1.0\text{ s}$).
  4. `test_maximum_interval_filter_over_1hr`: Reject intervals exceeding 3,600 seconds.
  5. `test_poisson_random_traffic_rejection`: Verify exponentially distributed intervals ($CV \approx 1.0$) are rejected.
  6. `test_circular_buffer_fixed_memory_n25`: Ensure deque never exceeds max capacity $N=25$.
- **Tier 3 (Cross-Feature)**:
  1. `test_c2_pipeline_integration`: Ingest `conn.log` stream $\to$ partition $\to$ C2 worker $\to$ `alerts.raw`.
  2. `test_c2_and_ssl_ja4_multi_alert_correlation`: Trigger both C2 Beaconing and JA4 Malware alerts for persistent agent.
  3. `test_c2_alert_to_timescale_db`: Insert `C2_BEACONING` alert into database.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_simulated_c2_beacon_10s_stream`: Feed 25 periodic flows $\implies$ alert emitted with $CV < 0.05$.
  2. `test_benign_poisson_web_browsing_silence`: Feed 100 random web requests $\implies$ 0 C2 beacon alerts.
  3. `test_evasion_jitter_boundary_analysis`: Verify detection boundary transitions at $J \approx 25\%$ ($CV \approx 0.144$).

---

### Feature 10: Standardized `RawAlert` Schema Serialization
- **Tier 1 (Core)**:
  1. `test_raw_alert_pydantic_instantiation`: Instantiate valid `RawAlert` with all required fields.
  2. `test_raw_alert_json_serialization`: Validate JSON output conforming to JSON schema standard.
  3. `test_raw_alert_threat_classes_enum`: Validate all 6 threat classes (`VOLUMETRIC_DDOS`, `PORT_SCAN_RECON`, `DATA_EXFILTRATION`, `DGA_TUNNELLING`, `ENCRYPTED_MALWARE`, `C2_BEACONING`).
  4. `test_raw_alert_severity_levels`: Validate severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  5. `test_raw_alert_confidence_range`: Enforce $0.0 \le \text{confidence} \le 1.0$.
- **Tier 2 (Boundary & Corner)**:
  1. `test_raw_alert_missing_optional_fields`: Handle null `target_ip`, `target_port`, `flow_id`.
  2. `test_raw_alert_auto_title_generation`: Verify default title auto-generation when title is omitted.
  3. `test_raw_alert_evidence_arbitrary_payload`: Accept arbitrary nested dictionary evidence payloads.
  4. `test_raw_alert_uuid_format_validation`: Validate auto-generated UUIDv4 format for `alert_id`.
  5. `test_raw_alert_timestamp_utc_epoch`: Validate timestamp formatting and serialization.
- **Tier 3 (Cross-Feature)**:
  1. `test_all_6_detectors_emit_valid_raw_alerts`: Verify alerts from all 6 detectors pass Pydantic validation.
  2. `test_raw_alert_deserialization_from_bus`: Consume JSON string from bus and parse into `RawAlert`.
  3. `test_raw_alert_timescale_db_insert_compatibility`: Validate schema mapping to `alerts` table columns.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_adversarial_special_chars_in_evidence`: Serialize evidence with escaped JSON, unicode, and raw hex.
  2. `test_high_volume_alert_serialization`: Serialize 10,000 `RawAlert` instances in $< 50\text{ ms}$.

---

### Feature 11: End-to-End Latency & Performance Verification
- **Tier 1 (Core)**:
  1. `test_single_event_streaming_latency`: Ingest event $\to$ detect $\to$ emit alert in $< 500\text{ ms}$.
  2. `test_metrics_calculator_latency_percentiles`: Compute $p50, p90, p95, p99$ from nanosecond timestamps.
  3. `test_line_rate_eps_calculation`: Measure Events Per Second accurately over sliding time intervals.
  4. `test_mbps_throughput_calculation`: Measure Megabits Per Second from byte counts.
  5. `test_memory_growth_stability`: Assert zero memory growth over 10,000 processed streaming events.
- **Tier 2 (Boundary & Corner)**:
  1. `test_latency_under_empty_pipeline`: Latency of zero-load pass-through is $< 100\ \mu\text{s}$.
  2. `test_burst_latency_under_10k_events`: Assert max latency during 10,000-event burst remains $< 500\text{ ms}$.
  3. `test_metrics_calculator_zero_duration`: Prevent division by zero when duration is 0.
  4. `test_nanosecond_precision_timer`: Verify monotonic clock precision with `time.perf_counter_ns()`.
  5. `test_lru_cache_bounded_memory`: Verify host state cache stays strictly within memory limits.
- **Tier 3 (Cross-Feature)**:
  1. `test_e2e_pipeline_latency_from_log_tail_to_alert`: Measure full pipeline time from log write to alert consumption.
  2. `test_parallel_4_worker_throughput_scaling`: Verify throughput scales linearly across 4 partitions.
  3. `test_pipeline_bridge_with_metrics_reporting`: Verify real-time metrics generation during continuous streaming.
- **Tier 4 (Real-World & Adversarial)**:
  1. `test_sustained_50k_eps_line_rate`: Sustain $\ge 50,000\text{ EPS}$ throughput for 10 seconds.
  2. `test_latency_percentiles_sla_compliance`: Assert $p50 < 5\text{ ms}$, $p95 < 25\text{ ms}$, $p99 < 50\text{ ms}$, $\text{Max} < 500\text{ ms}$.
  3. `test_simultaneous_multi_attack_under_load`: Run all 6 attack scenarios concurrently under line-rate load.
  4. `test_zero_event_loss_under_full_load`: Verify 100% accounting of all ingested records with zero packet drops.

---

## 5. Authoritative Expected Output Derivations & Mathematical Oracles

| Detector / Feature | Metric / Formula | Decision Threshold / Expected Output | Reference / Oracle |
|---|---|---|---|
| **DDoS (F4)** | $H(X) = \log_2 N - \frac{1}{N}\sum c_i \log_2 c_i$ | Targeted: $H < 1.2 \land Z \ge 3.5 \land r_t > 500\text{ pps}$<br>Random: $H_{\text{norm}} > 0.90 \land Z \ge 4.0$<br>SYN Flood: $\text{SYN Ratio} \ge 0.85 \land Z \ge 3.0$ | Shannon Information Theory, EWMA $Z$-score |
| **Portscan (F5)** | $E = \alpha_m m^2 \left(\sum 2^{-M[j]}\right)^{-1}$ | Vertical: $C_{\text{ports}} \ge 30 \land C_{\text{hosts}} \le 3$<br>Horizontal: $C_{\text{hosts}} \ge 25 \land C_{\text{ports}} \le 2$<br>Strobe: $C_{\text{endpoints}} \ge 50$ in 10s | Flajolet et al. HyperLogLog (2007) ($p=10, \sigma_{\text{err}} \approx 3.25\%$) |
| **Exfiltration (F6)** | $R_{\text{out/in}} = \frac{\text{orig\_bytes}}{\text{resp\_bytes} + 1024}$ | Ratio Spike: $R \ge 5.0 \land R \ge 3.0 \times P_{95} \land \text{Bytes} \ge 5\text{MB}$<br>Single Flow: $\text{Bytes} \ge 50\text{MB} \land R \ge 10.0$ | Directional Traffic Asymmetry + $P^2$ Quantile Estimation |
| **DGA / DNS (F7)** | $H(S) = -\sum P(c) \log_2 P(c)$<br>$P_{\text{DGA}} = \text{ONNX}(D)$ | $P_{\text{DGA}} \ge 0.85 \lor (H(S) \ge 4.0 \land L_{\text{sub}} \ge 35) \lor (R_{\text{NXDOMAIN}} \ge 0.75 \land N \ge 10)$ | Character-level BiLSTM ONNX model + RFC 1035 |
| **Malware (F8)** | JA4 string exact match<br>$S_{\text{anomaly}} = \sum w_k A_k$ | Threat Match: Confidence = 1.0 (Critical)<br>Anomaly: $S \ge 0.70$ (High), $S \ge 0.50$ (Medium) | FoxIO JA4 Specification + TLS 1.3 RFC 8446 |
| **C2 Beacon (F9)** | $CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$ | Strict: $CV < 0.15 \land N \ge 15 \land 1\text{s} \le \mu \le 3600\text{s}$<br>Jittered ($J \le 20\%$): $CV_{\text{uniform}} = \frac{J}{\sqrt{3}} \approx 0.115 < 0.15$ | Inter-Arrival Dispersion Statistics |

---

## 6. Test Suite Structure & Execution Instructions

```
tests/
├── __init__.py
├── test_infrastructure.py           # Phase 0 Multi-container & DDL tests
├── test_replay_harness.py           # Phase 0 Traffic replay & token-bucket tests
├── test_ja4_fingerprinting.py       # Phase 0 JA4/JA4S reference oracle & log schemas
├── test_ja4_protocol_deep.py        # Phase 0 JA4 protocol depth & edge cases
├── test_ingestion_storage.py        # Phase 1 Ingestion tailer & storage tests
├── test_benchmark_suite.py          # Day-1 30-second benchmark suite
├── test_stress_boundary.py          # Stress & concurrency boundary tests
├── throughput_benchmark.py          # Standalone line-rate benchmark script
└── test_e2e_opaque_box.py           # Phase 1 & 2 Opaque-Box E2E Test Suite (All 4 Tiers)
```

### Running the Complete Test Suite
```powershell
# Run the complete test suite with verbose output
pytest -v

# Run the comprehensive Opaque-Box E2E Test Suite
pytest -v tests/test_e2e_opaque_box.py

# Run specific tiers within the Opaque-Box E2E suite
pytest -v tests/test_e2e_opaque_box.py -k "Tier1"
pytest -v tests/test_e2e_opaque_box.py -k "Tier2"
pytest -v tests/test_e2e_opaque_box.py -k "Tier3"
pytest -v tests/test_e2e_opaque_box.py -k "Tier4"

# Run with sub-500ms latency and throughput assertions
pytest -v tests/test_e2e_opaque_box.py -k "Latency or Throughput"
```
