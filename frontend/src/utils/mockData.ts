import { FusedIncident, TelemetryMetrics, ScenarioId } from '../types';

export const INITIAL_INCIDENTS: FusedIncident[] = [
  {
    incident_id: 'INC-2026-APT-8821',
    created_at: Date.now() - 145000,
    updated_at: Date.now() - 12000,
    source_ip: '198.51.100.44',
    subnet: '198.51.100.0/24',
    target_ips: ['10.0.1.15', '10.0.1.20', '10.0.2.55'],
    target_ports: [22, 443, 8080, 53],
    severity: 'CRITICAL',
    risk_score: 94.8,
    raw_alert_count: 38,
    requires_human_approval: true,
    status: 'PENDING_REVIEW',
    execution_latency_ms: 0.42,
    primary_threat_class: 'APT_MULTI_STAGE',
    primary_mitre_technique: 'T1071.001',
    attack_narrative:
      'Multi-stage adversary attack detected spanning external reconnaissance to covert exfiltration. Initial high-speed TCP SYN sweep was followed by establishing an encrypted TLS C2 channel (JA4 matched Sliver C2 framework) with 60-second jittered beaconing. Adversary subsequently staged encrypted database records into Base64-encoded DNS TXT queries for out-of-band exfiltration.',
    risk_breakdown: {
      base_risk_sum: 90.0,
      synergy_bonus: 20.0,
      asset_criticality_multiplier: 1.2,
      final_risk_score: 94.8,
      severity: 'CRITICAL',
      formula: 'min(100.0, (base_sum 90.0 + synergy 20.0) * criticality 1.20) = 94.8',
      synergy_reason: 'Correlated 3 distinct threat classes (Recon + C2 Beacon + DNS Exfiltration) within 300s window',
      evidence_breakdown: [
        {
          threat_class: 'RECON',
          detector: 'portscan_hll',
          base_weight: 25.0,
          confidence: 0.95,
          weighted_score: 23.75,
          metric_summary: 'HLL cardinality: 1,024 distinct ports scanned across 10.0.1.0/24 within 3.2s',
        },
        {
          threat_class: 'MALWARE_C2',
          detector: 'encrypted_malware',
          base_weight: 35.0,
          confidence: 0.98,
          weighted_score: 34.3,
          metric_summary: 'JA4: t13d1516h2_8daaf6152771_000000000000 matching Sliver C2 TLS profile',
        },
        {
          threat_class: 'EXFILTRATION',
          detector: 'dga_tunneling',
          base_weight: 30.0,
          confidence: 0.92,
          weighted_score: 27.6,
          metric_summary: 'High Shannon entropy DNS queries (H=4.82) with 64-byte payload subdomains',
        },
      ],
    },
    mitre_mappings: [
      {
        technique_id: 'T1595.001',
        technique_name: 'Port Scanning (HyperLogLog)',
        tactic_id: 'TA0043',
        tactic_name: 'Reconnaissance',
        kill_chain_phase: 'Reconnaissance',
        confidence: 0.95,
        matched_detector: 'portscan_hll',
        description: 'Algorithmic cardinality tracking observed 1,024 probed ports in 3.2s.',
      },
      {
        technique_id: 'T1071.001',
        technique_name: 'Web Protocols (JA4 TLS C2)',
        tactic_id: 'TA0011',
        tactic_name: 'Command and Control',
        kill_chain_phase: 'Command & Control',
        confidence: 0.98,
        matched_detector: 'encrypted_malware',
        description: 'TLS client hello signature matches known Sliver interactive agent.',
      },
      {
        technique_id: 'T1568.002',
        technique_name: 'Domain Generation Algorithms',
        tactic_id: 'TA0011',
        tactic_name: 'Command and Control',
        kill_chain_phase: 'Command & Control',
        confidence: 0.91,
        matched_detector: 'dga_tunneling',
        description: 'Periodic pseudo-random DGA domain lookups observed against non-delegated TLDs.',
      },
      {
        technique_id: 'T1048.002',
        technique_name: 'Exfiltration Over Asymmetric Network Protocol',
        tactic_id: 'TA0010',
        tactic_name: 'Exfiltration',
        kill_chain_phase: 'Exfiltration',
        confidence: 0.94,
        matched_detector: 'exfil_ratio',
        description: 'Covert channel payload encoded in DNS TXT queries with 34:1 out/in volume ratio.',
      },
    ],
    timeline: [
      {
        step_number: 1,
        timestamp: Date.now() - 145000,
        iso_time: new Date(Date.now() - 145000).toISOString(),
        relative_time_offset_sec: 0.0,
        stage: 'Reconnaissance',
        detector: 'portscan_hll',
        threat_class: 'RECON',
        summary: 'Mass SYN probe against core enclave subnet 10.0.1.0/24',
        target_ip: '10.0.1.15',
        target_port: 22,
        confidence: 0.95,
        evidence_snapshot: {
          scanned_ports: 1024,
          duration_sec: 3.2,
          hll_registers_set: 64,
          packet_rate_pps: 4200,
          zeek_uid: 'C8Xz91A1k99Q',
        },
      },
      {
        step_number: 2,
        timestamp: Date.now() - 95000,
        iso_time: new Date(Date.now() - 95000).toISOString(),
        relative_time_offset_sec: 50.0,
        stage: 'Initial Compromise / TLS Handshake',
        detector: 'encrypted_malware',
        threat_class: 'MALWARE_C2',
        summary: 'JA4 signature matched malicious Sliver implant handshake',
        target_ip: '10.0.1.20',
        target_port: 443,
        confidence: 0.98,
        evidence_snapshot: {
          ja4_fingerprint: 't13d1516h2_8daaf6152771_000000000000',
          tls_version: 'TLSv1.3',
          sni: 'telemetry-edge.service-sync.internal',
          cipher_suite: '0x1302',
          zeek_uid: 'C3bB004fJ8a1',
        },
      },
      {
        step_number: 3,
        timestamp: Date.now() - 48000,
        iso_time: new Date(Date.now() - 48000).toISOString(),
        relative_time_offset_sec: 97.0,
        stage: 'Command & Control Beaconing',
        detector: 'c2_beaconing',
        threat_class: 'MALWARE_C2',
        summary: 'Autoregressive IAT beaconing detected (interval 60s, jitter 8.2%)',
        target_ip: '198.51.100.44',
        target_port: 8080,
        confidence: 0.93,
        evidence_snapshot: {
          beacon_interval_sec: 60.0,
          jitter_pct: 8.2,
          fft_dominant_freq: 0.0167,
          flow_count: 14,
          zeek_uid: 'Cc4810Akla09',
        },
      },
      {
        step_number: 4,
        timestamp: Date.now() - 12000,
        iso_time: new Date(Date.now() - 12000).toISOString(),
        relative_time_offset_sec: 133.0,
        stage: 'Covert Data Exfiltration',
        detector: 'dga_tunneling',
        threat_class: 'EXFILTRATION',
        summary: 'Base64 DNS TXT tunneling query burst (Shannon entropy 4.82)',
        target_ip: '10.0.2.55',
        target_port: 53,
        confidence: 0.94,
        evidence_snapshot: {
          shannon_entropy: 4.82,
          query_sample: 'e30KZXhwZXJpbWVudGFsX2V4ZmlsdHJhdGlvbl9kYXRhCg.corp-sync-telemetry.net',
          query_type: 'TXT',
          subdomain_length: 58,
          zeek_uid: 'Cd91Xla0921B',
        },
      },
    ],
    countermeasures: [
      {
        countermeasure_type: 'iptables',
        target_entity: '198.51.100.44',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `# [SIH26145 DEFENSE ENCLAVE] iptables Host Boundary Quarantine
# Incident: INC-2026-APT-8821 | Source IP: 198.51.100.44
# Threat: APT Multi-Stage (Recon + Sliver C2 + DNS Tunneling)
# Generated: 2026-09-01T18:10:00Z | Status: REQUIRES_HUMAN_APPROVAL

iptables -I INPUT 1 -s 198.51.100.44 -j DROP -m comment --comment "SIH26145: APT C2 Block"
iptables -I FORWARD 1 -s 198.51.100.44 -j DROP -m comment --comment "SIH26145: APT C2 Block"
iptables -I OUTPUT 1 -d 198.51.100.44 -j REJECT -m comment --comment "SIH26145: Outbound Quarantine"
`,
      },
      {
        countermeasure_type: 'nftables',
        target_entity: '198.51.100.44',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `#!/usr/sbin/nft -f
# [SIH26145 DEFENSE ENCLAVE] nftables State Isolation Table
# Incident: INC-2026-APT-8821 | Target: 198.51.100.44

table inet sih26145_quarantine {
    chain inbound_filter {
        type filter hook input priority -100; policy accept;
        ip saddr 198.51.100.44 log prefix "[SIH-DROP-IN] " drop
    }
    chain outbound_filter {
        type filter hook output priority -100; policy accept;
        ip daddr 198.51.100.44 log prefix "[SIH-DROP-OUT] " reject
    }
}
`,
      },
      {
        countermeasure_type: 'cisco_acl',
        target_entity: '198.51.100.44',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `! [SIH26145 DEFENSE ENCLAVE] Cisco IOS Edge Firewall Access Control List
! Incident: INC-2026-APT-8821 | Timestamp: 2026-09-01T18:10:00Z
ip access-list extended ACL_SIH26145_DIODE_QUARANTINE
 remark *** BLOCK ADVERSARY SOURCE IP 198.51.100.44 ***
 10 deny ip host 198.51.100.44 any log-input
 20 deny ip any host 198.51.100.44 log-input
 remark *** BLOCK DNS EXFILTRATION COVERT RESOLVER ***
 30 deny udp any host 198.51.100.44 eq 53
 40 permit ip any any
! Apply to WAN border interface:
interface GigabitEthernet0/0/0
 ip access-group ACL_SIH26145_DIODE_QUARANTINE in
`,
      },
      {
        countermeasure_type: 'dns_rpz',
        target_entity: 'corp-sync-telemetry.net',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `; [SIH26145 DEFENSE ENCLAVE] BIND 9 Response Policy Zone (RPZ)
; Incident: INC-2026-APT-8821 | DGA Domain Quarantine
$TTL 30
@   IN  SOA localhost. root.localhost. ( 2026090101 1h 15m 30d 2h )
    IN  NS  localhost.

; Block DGA exfiltration apex domain and all encoded subdomains
corp-sync-telemetry.net        IN  CNAME   .
*.corp-sync-telemetry.net      IN  CNAME   .
*.service-sync.internal        IN  CNAME   .
`,
      },
      {
        countermeasure_type: 'snort3',
        target_entity: '198.51.100.44',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `# [SIH26145 DEFENSE ENCLAVE] Snort 3 Signature Ruleset
# Incident: INC-2026-APT-8821 | JA4 + DNS Tunneling Alerting

alert tcp 198.51.100.44 any -> $HOME_NET any (
    msg:"SIH26145-APT: Malicious C2 TLS Connection Detected (Sliver JA4)";
    flow:to_server,established;
    content:"|16 03 03|",depth 3;
    classtype:trojan-activity;
    sid:2614501;
    rev:1;
)

alert udp $HOME_NET any -> any 53 (
    msg:"SIH26145-APT: High Entropy Base64 DNS Tunneling Exfiltration";
    content:"corp-sync-telemetry"; nocase;
    dsize:>60;
    classtype:bad-traffic;
    sid:2614502;
    rev:1;
)
`,
      },
      {
        countermeasure_type: 'stix_bundle',
        target_entity: 'INC-2026-APT-8821',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: JSON.stringify(
          {
            type: 'bundle',
            id: 'bundle--49c18d18-971a-4c28-9844-90a8c467a7a1',
            spec_version: '2.1',
            objects: [
              {
                type: 'indicator',
                id: 'indicator--7a8d11c4-1234-4567-8901-abcdef012345',
                created: '2026-09-01T18:10:00.000Z',
                modified: '2026-09-01T18:10:00.000Z',
                name: 'SIH26145 APT C2 IP Indicator',
                description: 'Source IP actively coordinating multi-stage intrusion and C2 beaconing',
                pattern: "[ipv4-addr:value = '198.51.100.44']",
                pattern_type: 'stix',
                valid_from: '2026-09-01T18:00:00Z',
                confidence: 98,
              },
              {
                type: 'indicator',
                id: 'indicator--99fa0021-4321-7654-3210-fedcba543210',
                created: '2026-09-01T18:10:00.000Z',
                modified: '2026-09-01T18:10:00.000Z',
                name: 'SIH26145 DGA DNS Tunneling Domain',
                description: 'Adversary-controlled domain utilized for encoded payload exfiltration',
                pattern: "[domain-name:value = 'corp-sync-telemetry.net']",
                pattern_type: 'stix',
                valid_from: '2026-09-01T18:00:00Z',
                confidence: 94,
              },
              {
                type: 'attack-pattern',
                id: 'attack-pattern--mitre-t1071-001',
                created: '2026-09-01T18:10:00.000Z',
                modified: '2026-09-01T18:10:00.000Z',
                name: 'Web Protocols (JA4 TLS C2)',
                external_references: [
                  {
                    source_name: 'mitre-attack',
                    external_id: 'T1071.001',
                  },
                ],
              },
            ],
          },
          null,
          2
        ),
      },
    ],
  },
  {
    incident_id: 'INC-2026-DDOS-4019',
    created_at: Date.now() - 320000,
    updated_at: Date.now() - 25000,
    source_ip: '203.0.113.88',
    subnet: '203.0.113.0/24',
    target_ips: ['10.0.1.5', '10.0.1.6'],
    target_ports: [80, 443],
    severity: 'CRITICAL',
    risk_score: 89.2,
    raw_alert_count: 145,
    requires_human_approval: true,
    status: 'APPROVED',
    execution_latency_ms: 0.38,
    primary_threat_class: 'DDOS_VOLUMETRIC',
    primary_mitre_technique: 'T1498.001',
    attack_narrative:
      'High-velocity TCP SYN flood detected impacting DMZ load balancer. Shannon entropy of packet source ports and flags collapsed to 0.84, confirming an automated volumetric assault exceeding 24,000 pps.',
    risk_breakdown: {
      base_risk_sum: 80.0,
      synergy_bonus: 0.0,
      asset_criticality_multiplier: 1.15,
      final_risk_score: 89.2,
      severity: 'CRITICAL',
      formula: 'min(100.0, (base_sum 80.0 + synergy 0.0) * criticality 1.15) = 89.2',
      evidence_breakdown: [
        {
          threat_class: 'DDOS_VOLUMETRIC',
          detector: 'ddos_entropy',
          base_weight: 80.0,
          confidence: 0.97,
          weighted_score: 77.6,
          metric_summary: 'Packet rate: 24,500 pps, SYN/ACK ratio: 180:1, Header entropy: 0.84',
        },
      ],
    },
    mitre_mappings: [
      {
        technique_id: 'T1498.001',
        technique_name: 'Direct Network Flood',
        tactic_id: 'TA0040',
        tactic_name: 'Impact',
        kill_chain_phase: 'Impact',
        confidence: 0.97,
        matched_detector: 'ddos_entropy',
        description: 'Volumetric SYN flood saturating external ingress gateway.',
      },
    ],
    timeline: [
      {
        step_number: 1,
        timestamp: Date.now() - 320000,
        iso_time: new Date(Date.now() - 320000).toISOString(),
        relative_time_offset_sec: 0.0,
        stage: 'Ingress Volume Surge',
        detector: 'ddos_entropy',
        threat_class: 'DDOS_VOLUMETRIC',
        summary: 'Ingress packet rate breached 20k pps threshold',
        target_ip: '10.0.1.5',
        target_port: 443,
        confidence: 0.97,
        evidence_snapshot: {
          packet_rate_pps: 24500,
          shannon_entropy: 0.84,
          tcp_syn_flag_count: 24200,
          zeek_uid: 'C99A814B312',
        },
      },
    ],
    countermeasures: [
      {
        countermeasure_type: 'iptables',
        target_entity: '203.0.113.88',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `iptables -I INPUT 1 -s 203.0.113.88 -p tcp --syn -j DROP -m comment --comment "SIH26145: DDoS SYN Flood Block"`,
      },
      {
        countermeasure_type: 'nftables',
        target_entity: '203.0.113.88',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `table inet filter { chain input { ip saddr 203.0.113.88 tcp flags & (syn|ack) == syn drop; } }`,
      },
      {
        countermeasure_type: 'cisco_acl',
        target_entity: '203.0.113.88',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `ip access-list extended ACL_DDOS_BLOCK\n deny tcp host 203.0.113.88 any eq 443\n deny tcp host 203.0.113.88 any eq 80\n permit ip any any`,
      },
      {
        countermeasure_type: 'dns_rpz',
        target_entity: '203.0.113.88',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `; IP-based RPZ Passthrough\n32.88.113.0.203.rpz-ip.local IN CNAME .`,
      },
      {
        countermeasure_type: 'snort3',
        target_entity: '203.0.113.88',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `alert tcp 203.0.113.88 any -> $HOME_NET any (msg:"SIH26145-DDOS: SYN Flood Surge"; flags:S; threshold:type both, track by_src, count 1000, seconds 1; sid:2614510; rev:1;)`,
      },
      {
        countermeasure_type: 'stix_bundle',
        target_entity: 'INC-2026-DDOS-4019',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: JSON.stringify(
          {
            type: 'bundle',
            id: 'bundle--ddos-4019-stix-bundle',
            spec_version: '2.1',
            objects: [
              {
                type: 'indicator',
                id: 'indicator--ddos-203-0-113-88',
                created: '2026-09-01T18:00:00.000Z',
                modified: '2026-09-01T18:00:00.000Z',
                pattern: "[ipv4-addr:value = '203.0.113.88']",
                pattern_type: 'stix',
                name: 'DDoS SYN Flood Vector',
              },
            ],
          },
          null,
          2
        ),
      },
    ],
  },
  {
    incident_id: 'INC-2026-C2-3312',
    created_at: Date.now() - 540000,
    updated_at: Date.now() - 45000,
    source_ip: '192.0.2.190',
    subnet: '192.0.2.0/24',
    target_ips: ['10.0.3.12'],
    target_ports: [443],
    severity: 'HIGH',
    risk_score: 76.5,
    raw_alert_count: 19,
    requires_human_approval: true,
    status: 'PENDING_REVIEW',
    execution_latency_ms: 0.45,
    primary_threat_class: 'MALWARE_C2',
    primary_mitre_technique: 'T1071.001',
    attack_narrative:
      'Persistent TLS beaconing identified originating from internal engineering workstation 10.0.3.12 contacting external node 192.0.2.190 with 45s periodic cadence.',
    risk_breakdown: {
      base_risk_sum: 70.0,
      synergy_bonus: 0.0,
      asset_criticality_multiplier: 1.1,
      final_risk_score: 76.5,
      severity: 'HIGH',
      formula: 'min(100.0, (base_sum 70.0 + synergy 0.0) * criticality 1.10) = 76.5',
      evidence_breakdown: [
        {
          threat_class: 'MALWARE_C2',
          detector: 'c2_beaconing',
          base_weight: 70.0,
          confidence: 0.91,
          weighted_score: 63.7,
          metric_summary: 'Autoregressive IAT beaconing: 45.2s interval, 6.4% jitter, FFT power 0.88',
        },
      ],
    },
    mitre_mappings: [
      {
        technique_id: 'T1071.001',
        technique_name: 'Web Protocols (TLS C2 Beacon)',
        tactic_id: 'TA0011',
        tactic_name: 'Command and Control',
        kill_chain_phase: 'Command & Control',
        confidence: 0.91,
        matched_detector: 'c2_beaconing',
      },
    ],
    timeline: [
      {
        step_number: 1,
        timestamp: Date.now() - 540000,
        iso_time: new Date(Date.now() - 540000).toISOString(),
        relative_time_offset_sec: 0.0,
        stage: 'Periodic Beaconing Establishment',
        detector: 'c2_beaconing',
        threat_class: 'MALWARE_C2',
        summary: 'Low-jitter TLS flow observed contacting external C2',
        target_ip: '10.0.3.12',
        target_port: 443,
        confidence: 0.91,
        evidence_snapshot: {
          interval_sec: 45.2,
          jitter_pct: 6.4,
          zeek_uid: 'C81239Aa11B',
        },
      },
    ],
    countermeasures: [
      {
        countermeasure_type: 'iptables',
        target_entity: '192.0.2.190',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `iptables -I OUTPUT 1 -d 192.0.2.190 -j DROP -m comment --comment "SIH26145: C2 Beacon Outbound Drop"`,
      },
      {
        countermeasure_type: 'nftables',
        target_entity: '192.0.2.190',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `table inet filter { chain output { ip daddr 192.0.2.190 drop; } }`,
      },
      {
        countermeasure_type: 'cisco_acl',
        target_entity: '192.0.2.190',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `ip access-list extended ACL_C2_BLOCK\n deny ip any host 192.0.2.190\n permit ip any any`,
      },
      {
        countermeasure_type: 'dns_rpz',
        target_entity: 'c2-edge.shadow-ops.net',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `c2-edge.shadow-ops.net IN CNAME .`,
      },
      {
        countermeasure_type: 'snort3',
        target_entity: '192.0.2.190',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `alert tcp $HOME_NET any -> 192.0.2.190 443 (msg:"SIH26145: C2 Outbound Beacon"; sid:2614520; rev:1;)`,
      },
      {
        countermeasure_type: 'stix_bundle',
        target_entity: 'INC-2026-C2-3312',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: JSON.stringify(
          {
            type: 'bundle',
            id: 'bundle--c2-3312-stix',
            spec_version: '2.1',
            objects: [
              {
                type: 'indicator',
                id: 'indicator--c2-192-0-2-190',
                created: '2026-09-01T18:00:00Z',
                pattern: "[ipv4-addr:value = '192.0.2.190']",
                pattern_type: 'stix',
              },
            ],
          },
          null,
          2
        ),
      },
    ],
  },
  {
    incident_id: 'INC-2026-RECON-0921',
    created_at: Date.now() - 720000,
    updated_at: Date.now() - 90000,
    source_ip: '198.51.100.11',
    subnet: '198.51.100.0/24',
    target_ips: ['10.0.1.10', '10.0.1.11', '10.0.1.12'],
    target_ports: [21, 22, 23, 80, 443, 8080],
    severity: 'MEDIUM',
    risk_score: 52.4,
    raw_alert_count: 8,
    requires_human_approval: true,
    status: 'RESOLVED',
    execution_latency_ms: 0.35,
    primary_threat_class: 'RECON',
    primary_mitre_technique: 'T1595.001',
    attack_narrative:
      'HyperLogLog cardinality monitor triggered on high unique destination port count probe scanning 64 ports across DMZ gateway.',
    risk_breakdown: {
      base_risk_sum: 50.0,
      synergy_bonus: 0.0,
      asset_criticality_multiplier: 1.05,
      final_risk_score: 52.4,
      severity: 'MEDIUM',
      formula: 'min(100.0, (base_sum 50.0 + synergy 0.0) * criticality 1.05) = 52.4',
      evidence_breakdown: [
        {
          threat_class: 'RECON',
          detector: 'portscan_hll',
          base_weight: 50.0,
          confidence: 0.88,
          weighted_score: 44.0,
          metric_summary: 'HLL register cardinality count: 64 unique ports in 1.4s',
        },
      ],
    },
    mitre_mappings: [
      {
        technique_id: 'T1595.001',
        technique_name: 'Port Scanning (HyperLogLog)',
        tactic_id: 'TA0043',
        tactic_name: 'Reconnaissance',
        kill_chain_phase: 'Reconnaissance',
        confidence: 0.88,
        matched_detector: 'portscan_hll',
      },
    ],
    timeline: [
      {
        step_number: 1,
        timestamp: Date.now() - 720000,
        iso_time: new Date(Date.now() - 720000).toISOString(),
        relative_time_offset_sec: 0.0,
        stage: 'Reconnaissance Probe',
        detector: 'portscan_hll',
        threat_class: 'RECON',
        summary: 'TCP SYN port scan across DMZ nodes',
        target_ip: '10.0.1.10',
        target_port: 80,
        confidence: 0.88,
        evidence_snapshot: {
          scanned_ports: 64,
          zeek_uid: 'C10049Ak382',
        },
      },
    ],
    countermeasures: [
      {
        countermeasure_type: 'iptables',
        target_entity: '198.51.100.11',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `iptables -I INPUT 1 -s 198.51.100.11 -j DROP -m comment --comment "SIH26145: Recon Drop"`,
      },
      {
        countermeasure_type: 'nftables',
        target_entity: '198.51.100.11',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `table inet filter { chain input { ip saddr 198.51.100.11 drop; } }`,
      },
      {
        countermeasure_type: 'cisco_acl',
        target_entity: '198.51.100.11',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `ip access-list extended ACL_RECON_BLOCK\n deny ip host 198.51.100.11 any\n permit ip any any`,
      },
      {
        countermeasure_type: 'dns_rpz',
        target_entity: '198.51.100.11',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `; IP RPZ Block\n32.11.100.51.198.rpz-ip.local IN CNAME .`,
      },
      {
        countermeasure_type: 'snort3',
        target_entity: '198.51.100.11',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: `alert tcp 198.51.100.11 any -> $HOME_NET any (msg:"SIH26145: Recon Scan"; sid:2614530; rev:1;)`,
      },
      {
        countermeasure_type: 'stix_bundle',
        target_entity: 'INC-2026-RECON-0921',
        syntax_valid: true,
        requires_human_approval: true,
        artifact_content: JSON.stringify(
          {
            type: 'bundle',
            id: 'bundle--recon-0921-stix',
            spec_version: '2.1',
            objects: [
              {
                type: 'indicator',
                id: 'indicator--recon-198-51-100-11',
                created: '2026-09-01T18:00:00Z',
                pattern: "[ipv4-addr:value = '198.51.100.11']",
                pattern_type: 'stix',
              },
            ],
          },
          null,
          2
        ),
      },
    ],
  },
];

export function generateInitialTelemetry(): TelemetryMetrics {
  return {
    timestamp: Date.now(),
    events_per_sec: 24850,
    mbps: 186.4,
    packet_loss_pct: 0.0,
    pipeline_latency_ms: 0.38,
    buffer_utilization_pct: 12.4,
    total_events_processed: 1489200,
    active_detectors: {
      portscan_hll: true,
      dga_tunneling: true,
      encrypted_malware: true,
      c2_beaconing: true,
      exfil_ratio: true,
      ddos_entropy: true,
    },
  };
}

export function updateTelemetryMock(prev: TelemetryMetrics): TelemetryMetrics {
  // Realistic jitter around line-rate performance
  const epsNoise = (Math.random() - 0.48) * 800;
  const newEps = Math.max(19500, Math.min(32000, prev.events_per_sec + epsNoise));
  
  const mbpsNoise = (Math.random() - 0.48) * 6;
  const newMbps = Math.max(140, Math.min(260, prev.mbps + mbpsNoise));
  
  const latencyNoise = (Math.random() - 0.5) * 0.04;
  const newLatency = Math.max(0.24, Math.min(0.78, prev.pipeline_latency_ms + latencyNoise));
  
  const bufferNoise = (Math.random() - 0.5) * 1.5;
  const newBuffer = Math.max(4.0, Math.min(28.0, prev.buffer_utilization_pct + bufferNoise));

  return {
    timestamp: Date.now(),
    events_per_sec: Math.round(newEps),
    mbps: parseFloat(newMbps.toFixed(2)),
    packet_loss_pct: 0.0,
    pipeline_latency_ms: parseFloat(newLatency.toFixed(3)),
    buffer_utilization_pct: parseFloat(newBuffer.toFixed(1)),
    total_events_processed: prev.total_events_processed + Math.round(newEps * 0.5),
    active_detectors: {
      portscan_hll: true,
      dga_tunneling: true,
      encrypted_malware: true,
      c2_beaconing: true,
      exfil_ratio: true,
      ddos_entropy: true,
    },
  };
}

export function generateSyntheticIncident(scenario: ScenarioId): FusedIncident {
  const timestamp = Date.now();
  const hex = Math.floor(Math.random() * 0xffff).toString(16).toUpperCase().padStart(4, '0');
  const incident_id = `INC-2026-${scenario.toUpperCase()}-${hex}`;

  switch (scenario) {
    case 'apt':
      return {
        incident_id,
        created_at: timestamp,
        updated_at: timestamp,
        source_ip: `198.51.100.${Math.floor(Math.random() * 200) + 10}`,
        subnet: '198.51.100.0/24',
        target_ips: ['10.0.1.15', '10.0.1.20', '10.0.2.88'],
        target_ports: [22, 443, 8080, 53],
        severity: 'CRITICAL',
        risk_score: 96.4,
        raw_alert_count: 42,
        requires_human_approval: true,
        status: 'PENDING_REVIEW',
        execution_latency_ms: 0.41,
        primary_threat_class: 'APT_MULTI_STAGE',
        primary_mitre_technique: 'T1071.001',
        attack_narrative:
          'Simulated APT multi-stage attack executed: Port scan -> Sliver JA4 C2 -> High-entropy DNS TXT tunneling.',
        risk_breakdown: {
          base_risk_sum: 92.0,
          synergy_bonus: 20.0,
          asset_criticality_multiplier: 1.2,
          final_risk_score: 96.4,
          severity: 'CRITICAL',
          formula: 'min(100.0, (base_sum 92.0 + synergy 20.0) * criticality 1.20) = 96.4',
          synergy_reason: 'Correlated 3 threat classes (Recon + C2 Beacon + DNS Exfil) within 300s window',
          evidence_breakdown: [
            {
              threat_class: 'RECON',
              detector: 'portscan_hll',
              base_weight: 25.0,
              confidence: 0.96,
              weighted_score: 24.0,
              metric_summary: 'HLL cardinality: 1024 unique ports probed',
            },
            {
              threat_class: 'MALWARE_C2',
              detector: 'encrypted_malware',
              base_weight: 35.0,
              confidence: 0.99,
              weighted_score: 34.65,
              metric_summary: 'JA4 signature: t13d1516h2_8daaf6152771_000000000000 (Sliver C2)',
            },
            {
              threat_class: 'EXFILTRATION',
              detector: 'dga_tunneling',
              base_weight: 32.0,
              confidence: 0.94,
              weighted_score: 30.08,
              metric_summary: 'DNS tunneling query entropy H=4.89, subdomain len 62 bytes',
            },
          ],
        },
        mitre_mappings: [
          {
            technique_id: 'T1595.001',
            technique_name: 'Port Scanning (HyperLogLog)',
            tactic_id: 'TA0043',
            tactic_name: 'Reconnaissance',
            kill_chain_phase: 'Reconnaissance',
            confidence: 0.96,
            matched_detector: 'portscan_hll',
          },
          {
            technique_id: 'T1071.001',
            technique_name: 'Web Protocols (JA4 TLS C2)',
            tactic_id: 'TA0011',
            tactic_name: 'Command and Control',
            kill_chain_phase: 'Command & Control',
            confidence: 0.99,
            matched_detector: 'encrypted_malware',
          },
          {
            technique_id: 'T1568.002',
            technique_name: 'Domain Generation Algorithms',
            tactic_id: 'TA0011',
            tactic_name: 'Command and Control',
            kill_chain_phase: 'Command & Control',
            confidence: 0.94,
            matched_detector: 'dga_tunneling',
          },
          {
            technique_id: 'T1048.002',
            technique_name: 'Exfiltration Over Asymmetric Network Protocol',
            tactic_id: 'TA0010',
            tactic_name: 'Exfiltration',
            kill_chain_phase: 'Exfiltration',
            confidence: 0.95,
            matched_detector: 'exfil_ratio',
          },
        ],
        timeline: [
          {
            step_number: 1,
            timestamp: timestamp - 30000,
            iso_time: new Date(timestamp - 30000).toISOString(),
            relative_time_offset_sec: 0.0,
            stage: 'Reconnaissance',
            detector: 'portscan_hll',
            threat_class: 'RECON',
            summary: 'High-speed SYN probe across 10.0.1.0/24 subnet',
            confidence: 0.96,
            evidence_snapshot: { ports: 1024, duration: 2.8, zeek_uid: 'Ca019918K1' },
          },
          {
            step_number: 2,
            timestamp: timestamp - 18000,
            iso_time: new Date(timestamp - 18000).toISOString(),
            relative_time_offset_sec: 12.0,
            stage: 'C2 Handshake',
            detector: 'encrypted_malware',
            threat_class: 'MALWARE_C2',
            summary: 'TLS handshake with Sliver JA4 fingerprint',
            confidence: 0.99,
            evidence_snapshot: { ja4: 't13d1516h2_8daaf6152771_000000000000', zeek_uid: 'Cb028829J2' },
          },
          {
            step_number: 3,
            timestamp: timestamp - 5000,
            iso_time: new Date(timestamp - 5000).toISOString(),
            relative_time_offset_sec: 25.0,
            stage: 'DNS Exfiltration',
            detector: 'dga_tunneling',
            threat_class: 'EXFILTRATION',
            summary: 'Base64 TXT DNS tunnel streaming exfiltrated data',
            confidence: 0.94,
            evidence_snapshot: { entropy: 4.89, zeek_uid: 'Cc037738L3' },
          },
        ],
        countermeasures: INITIAL_INCIDENTS[0].countermeasures,
      };

    case 'ddos':
      return {
        incident_id,
        created_at: timestamp,
        updated_at: timestamp,
        source_ip: `203.0.113.${Math.floor(Math.random() * 200) + 10}`,
        subnet: '203.0.113.0/24',
        target_ips: ['10.0.1.5'],
        target_ports: [80, 443],
        severity: 'CRITICAL',
        risk_score: 91.0,
        raw_alert_count: 88,
        requires_human_approval: true,
        status: 'PENDING_REVIEW',
        execution_latency_ms: 0.36,
        primary_threat_class: 'DDOS_VOLUMETRIC',
        primary_mitre_technique: 'T1498.001',
        attack_narrative: 'Simulated high-velocity SYN flood with low flow entropy exceeding 25,000 pps.',
        risk_breakdown: {
          base_risk_sum: 82.0,
          synergy_bonus: 0.0,
          asset_criticality_multiplier: 1.15,
          final_risk_score: 91.0,
          severity: 'CRITICAL',
          formula: 'min(100.0, (base_sum 82.0 + synergy 0.0) * criticality 1.15) = 91.0',
          evidence_breakdown: [
            {
              threat_class: 'DDOS_VOLUMETRIC',
              detector: 'ddos_entropy',
              base_weight: 82.0,
              confidence: 0.98,
              weighted_score: 80.36,
              metric_summary: 'Packet rate: 26,200 pps, SYN flag entropy: 0.79',
            },
          ],
        },
        mitre_mappings: [
          {
            technique_id: 'T1498.001',
            technique_name: 'Direct Network Flood',
            tactic_id: 'TA0040',
            tactic_name: 'Impact',
            kill_chain_phase: 'Impact',
            confidence: 0.98,
            matched_detector: 'ddos_entropy',
          },
        ],
        timeline: [
          {
            step_number: 1,
            timestamp,
            iso_time: new Date(timestamp).toISOString(),
            relative_time_offset_sec: 0.0,
            stage: 'SYN Flood Ingress Surge',
            detector: 'ddos_entropy',
            threat_class: 'DDOS_VOLUMETRIC',
            summary: 'Volumetric packet flood breached threshold',
            confidence: 0.98,
            evidence_snapshot: { pps: 26200, entropy: 0.79, zeek_uid: 'Cd046647M4' },
          },
        ],
        countermeasures: INITIAL_INCIDENTS[1].countermeasures,
      };

    default:
      return {
        ...INITIAL_INCIDENTS[2],
        incident_id,
        created_at: timestamp,
        updated_at: timestamp,
      };
  }
}
