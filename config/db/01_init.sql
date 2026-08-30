-- ============================================================================
-- SIH26145 Passive Network Monitoring System — TimescaleDB / PostgreSQL 16 DDL
-- Initial Database & Hypertable Schema for High-Throughput Ingestion Enclave
-- ============================================================================

-- 1. Initialize Extensions
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 2. Connection Telemetry Hypertable (Zeek conn.log)
CREATE TABLE IF NOT EXISTS conn_telemetry (
    time TIMESTAMPTZ NOT NULL,
    uid VARCHAR(32) NOT NULL,
    community_id VARCHAR(64),
    orig_h INET NOT NULL,
    orig_p INTEGER NOT NULL,
    resp_h INET NOT NULL,
    resp_p INTEGER NOT NULL,
    proto VARCHAR(10) NOT NULL,
    service VARCHAR(32),
    duration DOUBLE PRECISION,
    orig_bytes BIGINT DEFAULT 0,
    resp_bytes BIGINT DEFAULT 0,
    conn_state VARCHAR(16),
    orig_pkts BIGINT DEFAULT 0,
    resp_pkts BIGINT DEFAULT 0,
    missed_bytes BIGINT DEFAULT 0,
    history VARCHAR(64),
    raw_json JSONB
);

-- Convert to Hypertable with 1-hour time chunks
SELECT create_hypertable('conn_telemetry', 'time', chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);

-- Telemetry Indexes
CREATE INDEX IF NOT EXISTS idx_conn_orig_h_time ON conn_telemetry (orig_h, time DESC);
CREATE INDEX IF NOT EXISTS idx_conn_resp_h_time ON conn_telemetry (resp_h, time DESC);
CREATE INDEX IF NOT EXISTS idx_conn_community_id ON conn_telemetry (community_id);
CREATE INDEX IF NOT EXISTS idx_conn_uid ON conn_telemetry (uid);

-- 3. DNS Telemetry Hypertable (Zeek dns.log)
CREATE TABLE IF NOT EXISTS dns_telemetry (
    time TIMESTAMPTZ NOT NULL,
    uid VARCHAR(32) NOT NULL,
    orig_h INET NOT NULL,
    orig_p INTEGER NOT NULL,
    resp_h INET NOT NULL,
    resp_p INTEGER NOT NULL,
    proto VARCHAR(10),
    trans_id INTEGER,
    query VARCHAR(512) NOT NULL,
    qclass_name VARCHAR(16),
    qtype_name VARCHAR(16),
    rcode_name VARCHAR(16),
    answers TEXT[],
    ttls DOUBLE PRECISION[],
    entropy DOUBLE PRECISION,
    is_dga BOOLEAN DEFAULT FALSE,
    raw_json JSONB
);

SELECT create_hypertable('dns_telemetry', 'time', chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_dns_query_trgm ON dns_telemetry USING gin (query gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_dns_orig_h_time ON dns_telemetry (orig_h, time DESC);
CREATE INDEX IF NOT EXISTS idx_dns_is_dga ON dns_telemetry (is_dga) WHERE is_dga = TRUE;

-- 4. SSL / TLS Telemetry Hypertable with JA4 (Zeek ssl.log)
CREATE TABLE IF NOT EXISTS ssl_telemetry (
    time TIMESTAMPTZ NOT NULL,
    uid VARCHAR(32) NOT NULL,
    orig_h INET NOT NULL,
    orig_p INTEGER NOT NULL,
    resp_h INET NOT NULL,
    resp_p INTEGER NOT NULL,
    version VARCHAR(20),
    cipher VARCHAR(100),
    server_name TEXT,
    ja4 VARCHAR(64),
    ja4s VARCHAR(64),
    ja4_match_threat VARCHAR(128),
    established BOOLEAN DEFAULT TRUE,
    raw_json JSONB
);

SELECT create_hypertable('ssl_telemetry', 'time', chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_ssl_ja4_time ON ssl_telemetry (ja4, time DESC);
CREATE INDEX IF NOT EXISTS idx_ssl_orig_h_time ON ssl_telemetry (orig_h, time DESC);
CREATE INDEX IF NOT EXISTS idx_ssl_server_name ON ssl_telemetry (server_name);

-- 5. Raw Alerts Hypertable (Produced by 6 Specialized Detectors)
CREATE TABLE IF NOT EXISTS alerts (
    time TIMESTAMPTZ NOT NULL,
    alert_id UUID DEFAULT uuid_generate_v4(),
    detector_name VARCHAR(64) NOT NULL,
    threat_class VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    source_ip INET NOT NULL,
    target_ip INET,
    target_port INTEGER,
    flow_id VARCHAR(64),
    evidence JSONB NOT NULL,
    fused_incident_id UUID,
    is_fused BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (alert_id, time)
);

SELECT create_hypertable('alerts', 'time', chunk_time_interval => INTERVAL '1 day', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip_time ON alerts (source_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts (threat_class, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_fused ON alerts (is_fused) WHERE is_fused = FALSE;

-- 6. Fused Incidents Table (LangGraph Agentic Triaged Incidents)
CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    primary_source_ip INET NOT NULL,
    target_ips INET[] DEFAULT '{}',
    threat_class VARCHAR(64) NOT NULL,
    overall_risk_score DOUBLE PRECISION NOT NULL,
    severity VARCHAR(16) NOT NULL,
    mitre_attack_technique VARCHAR(32),
    mitre_attack_tactic VARCHAR(64),
    kill_chain_phase VARCHAR(64),
    attack_narrative TEXT NOT NULL,
    risk_breakdown JSONB NOT NULL,
    associated_alert_ids UUID[] DEFAULT '{}',
    countermeasure_type VARCHAR(64) NOT NULL,
    countermeasure_artifact TEXT NOT NULL,
    requires_human_approval BOOLEAN DEFAULT TRUE,
    status VARCHAR(32) DEFAULT 'PENDING_REVIEW',
    out_of_band_dispatched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents (primary_source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);

-- 7. Live System Metrics Hypertable (Live Ingest & Line-Rate Gauge)
CREATE TABLE IF NOT EXISTS system_metrics (
    time TIMESTAMPTZ NOT NULL,
    host TEXT DEFAULT 'sih_sensor',
    events_per_second DOUBLE PRECISION NOT NULL,
    packets_per_second DOUBLE PRECISION NOT NULL,
    megabits_per_second DOUBLE PRECISION NOT NULL,
    latency_p50_ms DOUBLE PRECISION,
    latency_p90_ms DOUBLE PRECISION,
    latency_p95_ms DOUBLE PRECISION,
    latency_p99_ms DOUBLE PRECISION,
    kafka_lag BIGINT DEFAULT 0,
    active_flows BIGINT DEFAULT 0,
    cpu_utilization DOUBLE PRECISION,
    memory_mb DOUBLE PRECISION,
    memory_utilization DOUBLE PRECISION,
    packet_loss_rate DOUBLE PRECISION
);

SELECT create_hypertable('system_metrics', 'time', chunk_time_interval => INTERVAL '1 hour', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_system_metrics_time ON system_metrics (time DESC);

-- 8. Enable TimescaleDB Columnar Compression Policies
ALTER TABLE conn_telemetry SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'orig_h, proto',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('conn_telemetry', INTERVAL '24 hours', if_not_exists => TRUE);

ALTER TABLE dns_telemetry SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'orig_h',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('dns_telemetry', INTERVAL '24 hours', if_not_exists => TRUE);

ALTER TABLE ssl_telemetry SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'orig_h, ja4',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('ssl_telemetry', INTERVAL '24 hours', if_not_exists => TRUE);

-- 9. Automated Retention Policies (Drop chunks older than window)
SELECT add_retention_policy('conn_telemetry', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('dns_telemetry', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('ssl_telemetry', INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('alerts', INTERVAL '30 days', if_not_exists => TRUE);
SELECT add_retention_policy('system_metrics', INTERVAL '14 days', if_not_exists => TRUE);
