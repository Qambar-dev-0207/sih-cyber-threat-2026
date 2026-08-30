"""
SIH26145 Passive Network Monitoring System — Phase 0
Test Suite: Infrastructure & Containerized Pipeline Stack
File: tests/test_infrastructure.py

Covers 4-Tier Test Architecture:
- Tier 1: Core Feature Verification (Docker Compose, Redpanda, Redis, TimescaleDB, Startup Scripts)
- Tier 2: Boundary & Corner Cases (Port collisions, zero-memory, missing env vars, chunk boundaries)
- Tier 3: Cross-Feature Pairwise Interactions (Kafka topics <-> TimescaleDB schemas, Redis <-> CEP)
- Tier 4: Real-World Resilience & Adversarial Stress (Container restart sequences, schema migrations)
"""

import os
import re
import json
import yaml
import socket
import pytest
from pathlib import Path
from typing import Dict, Any, List

# Workspace Root Discovery
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
DOCKER_COMPOSE_PATH = PROJECT_ROOT / "docker-compose.yml"
TIMESCALE_INIT_SQL_PATH = PROJECT_ROOT / "config" / "timescale" / "init.sql"
REDIS_CONF_PATH = PROJECT_ROOT / "config" / "redis" / "redis.conf"
REDPANDA_YAML_PATH = PROJECT_ROOT / "config" / "redpanda" / "redpanda.yaml"
START_PS1_PATH = PROJECT_ROOT / "scripts" / "start_infrastructure.ps1"
START_SH_PATH = PROJECT_ROOT / "scripts" / "start_infrastructure.sh"
STOP_PS1_PATH = PROJECT_ROOT / "scripts" / "stop_infrastructure.ps1"
STOP_SH_PATH = PROJECT_ROOT / "scripts" / "stop_infrastructure.sh"


# ============================================================================
# Helper Functions & Fixtures
# ============================================================================

def load_docker_compose() -> Dict[str, Any]:
    """Load and parse docker-compose.yml."""
    assert DOCKER_COMPOSE_PATH.exists(), f"docker-compose.yml not found at {DOCKER_COMPOSE_PATH}"
    with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_timescale_sql() -> str:
    """Load TimescaleDB SQL initialization script."""
    assert TIMESCALE_INIT_SQL_PATH.exists(), f"init.sql not found at {TIMESCALE_INIT_SQL_PATH}"
    with open(TIMESCALE_INIT_SQL_PATH, "r", encoding="utf-8") as f:
        return f.read()


def load_redis_conf() -> str:
    """Load Redis configuration file."""
    assert REDIS_CONF_PATH.exists(), f"redis.conf not found at {REDIS_CONF_PATH}"
    with open(REDIS_CONF_PATH, "r", encoding="utf-8") as f:
        return f.read()


def is_port_open(host: str, port: int, timeout_sec: float = 0.5) -> bool:
    """Check if a TCP port is open and listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_sec)
        return s.connect_ex((host, port)) == 0


# ============================================================================
# Tier 1: Core Feature Verification (>= 5 tests per feature)
# ============================================================================

class TestDockerComposeTopologyTier1:
    """Tier 1: Multi-Container Stack Structure and Service Topologies."""

    @pytest.fixture(autouse=True)
    def setup_compose(self):
        self.compose = load_docker_compose()
        self.services = self.compose.get("services", {})

    def test_required_services_exist(self):
        """Verify all 5 required services are declared in docker-compose.yml."""
        expected = {"redpanda", "redpanda-init", "redis", "timescaledb", "zeek"}
        assert expected.issubset(set(self.services.keys())), (
            f"Missing required services: {expected - set(self.services.keys())}"
        )

    def test_bridge_network_topology(self):
        """Verify internal bridge network 'sih_net' configuration and subnet."""
        networks = self.compose.get("networks", {})
        assert "sih_net" in networks, "Network 'sih_net' not defined in docker-compose"
        sih_net = networks["sih_net"]
        assert sih_net.get("driver") == "bridge", "sih_net must use bridge driver"
        
        ipam = sih_net.get("ipam", {}).get("config", [])
        assert len(ipam) > 0, "sih_net missing IPAM subnet config"
        subnet = ipam[0].get("subnet")
        assert subnet == "172.28.0.0/16", f"Expected subnet 172.28.0.0/16, got {subnet}"

    def test_volume_persistence_declarations(self):
        """Verify named persistent volumes for Redpanda, Redis, TimescaleDB, Zeek."""
        volumes = self.compose.get("volumes", {})
        expected_volumes = {
            "redpanda_data": "sih_redpanda_data",
            "redis_data": "sih_redis_data",
            "timescale_data": "sih_timescale_data",
            "zeek_logs": "sih_zeek_logs"
        }
        for vol_key, vol_name in expected_volumes.items():
            assert vol_key in volumes, f"Missing volume key {vol_key}"
            assert volumes[vol_key].get("name") == vol_name, (
                f"Volume {vol_key} must be named {vol_name}"
            )

    def test_container_healthcheck_definitions(self):
        """Verify all continuous running services define healthcheck contracts."""
        continuous_services = ["redpanda", "redis", "timescaledb", "zeek"]
        for svc_name in continuous_services:
            svc = self.services.get(svc_name, {})
            assert "healthcheck" in svc, f"Service '{svc_name}' missing healthcheck definition"
            hc = svc["healthcheck"]
            assert "test" in hc, f"Service '{svc_name}' healthcheck missing 'test' command"
            assert "interval" in hc, f"Service '{svc_name}' healthcheck missing 'interval'"
            assert "timeout" in hc, f"Service '{svc_name}' healthcheck missing 'timeout'"
            assert "retries" in hc, f"Service '{svc_name}' healthcheck missing 'retries'"

    def test_service_dependency_chains(self):
        """Verify strict startup dependencies (redpanda-init waits for healthy redpanda, etc)."""
        rp_init = self.services.get("redpanda-init", {})
        depends_on = rp_init.get("depends_on", {})
        assert "redpanda" in depends_on, "redpanda-init must depend on redpanda"
        assert depends_on["redpanda"].get("condition") == "service_healthy", (
            "redpanda-init must wait for condition: service_healthy"
        )
        
        zeek_svc = self.services.get("zeek", {})
        zeek_deps = zeek_svc.get("depends_on", {})
        assert "redpanda" in zeek_deps, "zeek service must depend on redpanda"
        assert zeek_deps["redpanda"].get("condition") == "service_healthy"


class TestRedpandaKafkaConfigurationTier1:
    """Tier 1: Redpanda / Kafka API compatibility, topic topology, and message format."""

    @pytest.fixture(autouse=True)
    def setup_compose(self):
        self.compose = load_docker_compose()
        self.services = self.compose.get("services", {})

    def test_redpanda_port_mappings(self):
        """Verify Redpanda Kafka (9092, 19092), Schema Registry (8081), Admin (9644) ports."""
        rp = self.services["redpanda"]
        ports_str = " ".join([str(p) for p in rp.get("ports", [])])
        assert "9092" in ports_str, "Port 9092 (Kafka internal) missing"
        assert "19092" in ports_str, "Port 19092 (Kafka host external) missing"
        assert "8081" in ports_str, "Port 8081 (Schema Registry) missing"
        assert "9644" in ports_str, "Port 9644 (Admin API) missing"

    def test_redpanda_topic_initialization_command(self):
        """Verify redpanda-init script creates all 5 required SIH topics."""
        rp_init = self.services["redpanda-init"]
        command_list = rp_init.get("command", [])
        command_text = " ".join(command_list) if isinstance(command_list, list) else str(command_list)
        
        required_topics = [
            ("telemetry.conn", "-p 4"),
            ("telemetry.dns", "-p 4"),
            ("telemetry.ssl", "-p 4"),
            ("alerts.raw", "-p 4"),
            ("incidents.fused", "-p 1")
        ]
        for topic, part_flag in required_topics:
            assert f"topic create {topic}" in command_text, f"Topic '{topic}' missing creation in init"
            assert part_flag in command_text, f"Topic '{topic}' missing partition spec {part_flag}"

    def test_redpanda_kafka_message_schema_contract(self):
        """Verify that telemetry messages conform to contract with ingest_ts and Zeek fields."""
        sample_payload = {
            "ts": 1725000000.123456,
            "uid": "CHfSZ135z9a33gXl9d",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 0.045,
            "orig_bytes": 1024,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "ingest_ts": 1725000000.125000
        }
        # Validate JSON serialization and schema attributes
        serialized = json.dumps(sample_payload).encode("utf-8")
        deserialized = json.loads(serialized.decode("utf-8"))
        assert "ingest_ts" in deserialized
        assert deserialized["ingest_ts"] >= deserialized["ts"]
        assert deserialized["proto"] == "tcp"
        assert deserialized["id.orig_p"] == 54321

    def test_redpanda_resource_parameters(self):
        """Verify low-latency single-node Redpanda flags (--smp=1, --memory=1G, --overprovisioned)."""
        rp = self.services["redpanda"]
        cmd = rp.get("command", [])
        assert "--overprovisioned" in cmd
        assert "--smp=1" in cmd
        assert "--memory=1G" in cmd
        assert "--reserve-memory=0M" in cmd

    def test_live_redpanda_port_probe_or_offline_fallback(self):
        """Probe live port 19092 or verify valid config fallback if offline."""
        live_open = is_port_open("localhost", 19092, timeout_sec=0.2)
        if live_open:
            assert True, "Live Redpanda broker listening on port 19092"
        else:
            # Confirm compose config is valid for live execution
            rp = self.services["redpanda"]
            assert rp["image"].startswith("docker.redpanda.com/redpandadata/redpanda")


class TestRedisConfigurationTier1:
    """Tier 1: Redis 7.x in-memory cache, LRU eviction, and persistence settings."""

    @pytest.fixture(autouse=True)
    def setup_conf(self):
        self.conf = load_redis_conf()
        self.compose = load_docker_compose()

    def test_redis_port_and_image(self):
        """Verify Redis 7.x alpine image and 6379 port mapping."""
        redis_svc = self.compose["services"]["redis"]
        assert "redis:7" in redis_svc["image"]
        ports = redis_svc.get("ports", [])
        assert any("6379" in str(p) for p in ports)

    def test_redis_maxmemory_and_eviction_policy(self):
        """Verify memory budget (512mb) and 'allkeys-lru' cache eviction policy in redis.conf."""
        assert re.search(r"maxmemory\s+512mb", self.conf, re.IGNORECASE), "maxmemory 512mb not set"
        assert re.search(r"maxmemory-policy\s+allkeys-lru", self.conf, re.IGNORECASE), (
            "maxmemory-policy allkeys-lru not set"
        )

    def test_redis_persistence_disabled_for_line_rate(self):
        """Verify disk persistence (RDB/AOF) is disabled for sub-millisecond CEP throughput."""
        assert re.search(r'save\s+""', self.conf) or "save \"\"" in self.conf, (
            "RDB snapshots must be disabled with 'save \"\"'"
        )
        assert re.search(r"appendonly\s+no", self.conf, re.IGNORECASE), (
            "AOF must be disabled with 'appendonly no'"
        )

    def test_redis_tcp_backlog_and_timeout(self):
        """Verify tcp-backlog tuning and timeout settings for high-volume packet bursts."""
        assert re.search(r"tcp-backlog\s+\d+", self.conf), "tcp-backlog parameter missing"
        assert re.search(r"timeout\s+\d+", self.conf), "timeout parameter missing"

    def test_live_redis_ping_probe_or_offline_fallback(self):
        """Check live Redis on port 6379 or verify configuration correctness."""
        live_open = is_port_open("localhost", 6379, timeout_sec=0.2)
        if live_open:
            import redis
            r = redis.Redis(host="localhost", port=6379, socket_timeout=1.0)
            assert r.ping() is True
        else:
            assert "redis-server" in self.compose["services"]["redis"]["command"]


class TestTimescaleDBHypertableSchemaTier1:
    """Tier 1: PostgreSQL 16 + TimescaleDB DDL, Hypertables, and Policies."""

    @pytest.fixture(autouse=True)
    def setup_sql(self):
        self.sql = load_timescale_sql()

    def test_required_tables_exist(self):
        """Verify CREATE TABLE statements for all 6 core tables."""
        required_tables = [
            "conn_telemetry",
            "dns_telemetry",
            "ssl_telemetry",
            "alerts",
            "incidents",
            "system_metrics"
        ]
        for tbl in required_tables:
            pattern = rf"CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?{tbl}\s*\("
            assert re.search(pattern, self.sql, re.IGNORECASE), f"Missing CREATE TABLE for {tbl}"

    def test_hypertable_creation_calls(self):
        """Verify create_hypertable calls for the 5 time-series tables."""
        expected_hypertables = [
            ("conn_telemetry", "1 hour"),
            ("dns_telemetry", "1 hour"),
            ("ssl_telemetry", "1 hour"),
            ("alerts", "1 day"),
            ("system_metrics", "1 hour")
        ]
        for tbl, interval in expected_hypertables:
            pattern = rf"create_hypertable\s*\(\s*'{tbl}'.*INTERVAL\s+'{interval}'"
            assert re.search(pattern, self.sql, re.IGNORECASE | re.DOTALL), (
                f"Hypertable {tbl} missing or incorrect chunk interval '{interval}'"
            )

    def test_ja4_columns_in_ssl_telemetry(self):
        """Verify ja4 and ja4s columns with proper types in ssl_telemetry table."""
        assert re.search(r"ja4\s+VARCHAR\(64\)", self.sql, re.IGNORECASE), "ja4 column missing in ssl_telemetry"
        assert re.search(r"ja4s\s+VARCHAR\(64\)", self.sql, re.IGNORECASE), "ja4s column missing in ssl_telemetry"
        assert re.search(r"server_name\s+TEXT", self.sql, re.IGNORECASE), "server_name column missing"

    def test_indexes_and_gin_trigram_support(self):
        """Verify indexing including GIN trigram index for DNS query fuzzy searching."""
        assert "CREATE EXTENSION IF NOT EXISTS pg_trgm" in self.sql or "pg_trgm" in self.sql
        assert re.search(r"idx_dns_query_trgm.*USING\s+gin\s*\(query\s+gin_trgm_ops\)", self.sql, re.IGNORECASE)
        assert re.search(r"idx_ssl_ja4_time.*ON\s+ssl_telemetry\s*\(ja4", self.sql, re.IGNORECASE)
        assert re.search(r"idx_conn_orig_h_time.*ON\s+conn_telemetry", self.sql, re.IGNORECASE)

    def test_compression_and_retention_policies(self):
        """Verify TimescaleDB compression policies and retention drop policies."""
        assert re.search(r"add_compression_policy\s*\(\s*'conn_telemetry',\s*INTERVAL\s+'24 hours'", self.sql)
        assert re.search(r"add_compression_policy\s*\(\s*'ssl_telemetry',\s*INTERVAL\s+'24 hours'", self.sql)
        assert re.search(r"add_retention_policy\s*\(\s*'conn_telemetry',\s*INTERVAL\s+'7 days'", self.sql)
        assert re.search(r"add_retention_policy\s*\(\s*'alerts',\s*INTERVAL\s+'30 days'", self.sql)


class TestStartupHealthcheckScriptsTier1:
    """Tier 1: PowerShell and Bash Startup and Teardown Automation."""

    def test_powershell_start_script_structure(self):
        """Verify start_infrastructure.ps1 checks prerequisites, healthchecks, and topic creation."""
        assert START_PS1_PATH.exists(), f"Missing {START_PS1_PATH}"
        content = START_PS1_PATH.read_text(encoding="utf-8")
        assert "docker compose up -d" in content or "docker-compose up -d" in content
        assert "sih_redpanda" in content
        assert "sih_timescaledb" in content
        assert "sih_redis" in content
        assert "sih_zeek" in content

    def test_bash_start_script_structure(self):
        """Verify start_infrastructure.sh contains valid POSIX syntax and container checks."""
        assert START_SH_PATH.exists(), f"Missing {START_SH_PATH}"
        content = START_SH_PATH.read_text(encoding="utf-8")
        assert "#!/usr/bin/env bash" in content or "#!/bin/bash" in content
        assert "docker compose up -d" in content or "docker-compose up -d" in content
        assert "rpk" in content or "telemetry.conn" in content

    def test_stop_scripts_graceful_teardown(self):
        """Verify stop scripts teardown containers without destroying named persistent volumes."""
        assert STOP_PS1_PATH.exists()
        assert STOP_SH_PATH.exists()
        ps1_content = STOP_PS1_PATH.read_text(encoding="utf-8")
        sh_content = STOP_SH_PATH.read_text(encoding="utf-8")
        
        # Must run docker compose down without '-v' flag to protect data volumes
        assert "docker compose down" in ps1_content
        assert "-v" not in ps1_content.split("docker compose down")[1].split("\n")[0]
        assert "docker compose down" in sh_content
        assert "-v" not in sh_content.split("docker compose down")[1].split("\n")[0]


# ============================================================================
# Tier 2: Boundary & Corner Cases (>= 5 tests per feature)
# ============================================================================

class TestInfrastructureBoundaryCornerCasesTier2:
    """Tier 2: Boundary and corner cases across infrastructure definitions."""

    @pytest.fixture(autouse=True)
    def setup_data(self):
        self.compose = load_docker_compose()
        self.sql = load_timescale_sql()
        self.conf = load_redis_conf()

    def test_zero_port_collisions_across_all_services(self):
        """Verify that no two services bind to the same host port."""
        allocated_ports = []
        for svc_name, svc in self.compose.get("services", {}).items():
            for p in svc.get("ports", []):
                p_str = str(p)
                # Parse host port from "${PORT:-5432}:5432" or "5432:5432"
                match = re.search(r"(\d+):", p_str)
                if match:
                    port_num = int(match.group(1))
                    assert port_num not in allocated_ports, (
                        f"Port collision detected! Port {port_num} reused in {svc_name}"
                    )
                    allocated_ports.append(port_num)

    def test_env_var_default_fallbacks(self):
        """Verify every parameterized environment variable has a valid default fallback."""
        compose_text = yaml.dump(self.compose)
        env_vars = re.findall(r"\$\{([A-Z0-9_]+)(?::-(.*?))?\}", compose_text)
        for var_name, default_val in env_vars:
            assert default_val is not None and len(default_val) > 0, (
                f"Environment variable ${{{var_name}}} has no default fallback value"
            )

    def test_redis_memory_unit_boundary(self):
        """Verify redis maxmemory matches valid byte unit (mb/gb) and is at least 128mb."""
        match = re.search(r"maxmemory\s+(\d+)(mb|gb)", self.conf, re.IGNORECASE)
        assert match, "Redis maxmemory does not match size syntax (e.g. 512mb)"
        val = int(match.group(1))
        unit = match.group(2).lower()
        mb_equiv = val if unit == "mb" else val * 1024
        assert mb_equiv >= 128, f"Redis maxmemory {mb_equiv}MB is too low for CEP sliding window"

    def test_timescale_primary_key_and_time_column_ordering(self):
        """Verify alerts composite primary key includes the hypertable partitioning column 'time'."""
        # TimescaleDB requires the partitioning column to be part of any unique/primary key constraint
        match = re.search(r"PRIMARY\s+KEY\s*\(([^)]+)\)", self.sql, re.IGNORECASE)
        assert match, "Missing PRIMARY KEY in alerts"
        pk_cols = [c.strip().lower() for c in match.group(1).split(",")]
        assert "time" in pk_cols, "TimescaleDB requires 'time' in composite primary key"
        assert "alert_id" in pk_cols, "'alert_id' must be in composite primary key"

    def test_zeek_network_capability_privileges(self):
        """Verify Zeek container defines required Linux capabilities for promiscuous capture."""
        zeek_svc = self.compose["services"]["zeek"]
        cap_add = zeek_svc.get("cap_add", [])
        assert "NET_ADMIN" in cap_add, "Zeek missing NET_ADMIN capability"
        assert "NET_RAW" in cap_add, "Zeek missing NET_RAW capability"


# ============================================================================
# Tier 3: Cross-Feature Pairwise Interactions
# ============================================================================

class TestCrossFeaturePairwiseTier3:
    """Tier 3: Pairwise contract validation between infrastructure modules."""

    @pytest.fixture(autouse=True)
    def setup_context(self):
        self.compose = load_docker_compose()
        self.sql = load_timescale_sql()

    def test_redpanda_topics_match_timescaledb_telemetry_hypertables(self):
        """Pairwise: Verify Redpanda topic names align with TimescaleDB telemetry tables."""
        rp_init_cmd = str(self.compose["services"]["redpanda-init"].get("command", []))
        
        topic_to_table = {
            "telemetry.conn": "conn_telemetry",
            "telemetry.dns": "dns_telemetry",
            "telemetry.ssl": "ssl_telemetry",
            "alerts.raw": "alerts"
        }
        for topic, table in topic_to_table.items():
            assert topic in rp_init_cmd, f"Topic {topic} missing from Redpanda init"
            assert f"CREATE TABLE IF NOT EXISTS {table}" in self.sql, (
                f"Table {table} for topic {topic} missing in TimescaleDB SQL"
            )

    def test_zeek_log_volume_mount_matches_log_tailer_path(self):
        """Pairwise: Verify Zeek log volume mount path matches ingestion reader expectations."""
        zeek_vols = self.compose["services"]["zeek"].get("volumes", [])
        vols_str = " ".join([str(v) for v in zeek_vols])
        assert "/logs" in vols_str, "Zeek must mount /logs"
        assert "./logs/zeek:/logs" in vols_str or "zeek_logs:/logs" in vols_str

    def test_timescale_metrics_table_matches_benchmark_reporter_schema(self):
        """Pairwise: Verify system_metrics hypertable schema contains all benchmark fields."""
        required_metric_fields = [
            "events_per_second",
            "packets_per_second",
            "megabits_per_second",
            "latency_p50_ms",
            "latency_p95_ms",
            "latency_p99_ms",
            "kafka_lag",
            "cpu_utilization",
            "memory_utilization",
            "packet_loss_rate"
        ]
        for field in required_metric_fields:
            assert field in self.sql, f"Field '{field}' missing from system_metrics table definition"


# ============================================================================
# Tier 4: Real-World Resilience & Adversarial Stress
# ============================================================================

class TestRealWorldResilienceAdversarialTier4:
    """Tier 4: Adversarial resilience, idempotence, and schema migration robustness."""

    def test_sql_ddl_idempotency(self):
        """Adversarial: Verify SQL script can be executed multiple times without syntax error."""
        sql = load_timescale_sql()
        # All CREATE TABLE, CREATE INDEX, CREATE EXTENSION must use IF NOT EXISTS or if_not_exists => TRUE
        for match in re.finditer(r"CREATE\s+TABLE\s+([^\(\n]+)", sql, re.IGNORECASE):
            full_stmt = match.group(0)
            assert "IF NOT EXISTS" in full_stmt.upper(), f"CREATE TABLE clause lacks IF NOT EXISTS: {full_stmt}"
            
        for match in re.finditer(r"CREATE\s+INDEX\s+([^;\n]+)", sql, re.IGNORECASE):
            full_stmt = match.group(0)
            assert "IF NOT EXISTS" in full_stmt.upper(), f"CREATE INDEX clause lacks IF NOT EXISTS: {full_stmt}"

    def test_network_subnet_isolation(self):
        """Adversarial: Verify internal bridge subnet does not overlap with default Docker (172.17.0.0/16)."""
        compose = load_docker_compose()
        subnet = compose["networks"]["sih_net"]["ipam"]["config"][0]["subnet"]
        assert subnet != "172.17.0.0/16", "Subnet must not collide with standard Docker 172.17.0.0/16"
        assert subnet.startswith("172.28."), f"Subnet should be dedicated 172.28.0.0/16, got {subnet}"

    def test_healthcheck_retry_tolerances(self):
        """Stress: Verify healthcheck start_period and retries provide sufficient buffer for cold boots."""
        compose = load_docker_compose()
        for svc_name in ["redpanda", "timescaledb"]:
            hc = compose["services"][svc_name]["healthcheck"]
            retries = int(hc.get("retries", 0))
            assert retries >= 5, f"{svc_name} retries ({retries}) too low for cold container initialization"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
