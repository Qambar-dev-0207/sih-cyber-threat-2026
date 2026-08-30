"""
SIH26145 - TimescaleDB Storage & Ingestion Module
Provides connection pooling, batch hypertable ingestion, and query helpers for telemetry and alerts.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("timescale_db")


def normalize_timestamp(ts_val: Any) -> datetime:
    """Converts unix timestamp (float/int), ISO8601 string, or datetime to timezone-aware UTC datetime."""
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val
    if isinstance(ts_val, (int, float)):
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)
    if isinstance(ts_val, str):
        try:
            # Try ISO format
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            try:
                # Try float string
                return datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except Exception:
                pass
    return datetime.now(timezone.utc)


class TimescaleDatabase:
    """
    High-performance batch ingestion and query manager for PostgreSQL 16 + TimescaleDB.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        dbname: str = "sih26145",
        user: str = "postgres",
        password: str = "postgrespassword",
        min_connections: int = 2,
        max_connections: int = 10,
    ):
        self.host = os.getenv("POSTGRES_HOST", host)
        self.port = int(os.getenv("POSTGRES_PORT", port))
        self.dbname = os.getenv("POSTGRES_DB", dbname)
        self.user = os.getenv("POSTGRES_USER", user)
        self.password = os.getenv("POSTGRES_PASSWORD", password)
        self.min_connections = min_connections
        self.max_connections = max_connections

        self._pool = None
        self._is_connected = False
        self._init_pool()

    def _init_pool(self) -> None:
        """Initialize connection pool using psycopg2 or psycopg3."""
        try:
            import psycopg2
            from psycopg2 import pool

            self._pool = pool.ThreadedConnectionPool(
                minconn=self.min_connections,
                maxconn=self.max_connections,
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
            )
            self._driver = "psycopg2"
            self._is_connected = True
            logger.info(f"Initialized TimescaleDB connection pool connected to {self.host}:{self.port}/{self.dbname}")
            return
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"TimescaleDB connection failed ({e}). Falling back to mock/offline mode.")

        try:
            import psycopg
            from psycopg_pool import ConnectionPool

            conninfo = f"host={self.host} port={self.port} dbname={self.dbname} user={self.user} password={self.password}"
            self._pool = ConnectionPool(conninfo=conninfo, min_size=self.min_connections, max_size=self.max_connections)
            self._driver = "psycopg3"
            self._is_connected = True
            logger.info(f"Initialized psycopg3 ConnectionPool connected to {self.host}:{self.port}/{self.dbname}")
            return
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"psycopg3 connection failed ({e}). Falling back to mock/offline mode.")

        logger.warning("Running TimescaleDB database manager in mock/dry-run mode.")
        self._driver = "mock"
        self._is_connected = False

    def get_connection(self):
        """Borrow a connection from the pool."""
        if self._driver == "psycopg2" and self._pool:
            return self._pool.getconn()
        elif self._driver == "psycopg3" and self._pool:
            return self._pool.getconn()
        return None

    def release_connection(self, conn) -> None:
        """Return a connection back to the pool."""
        if self._driver == "psycopg2" and self._pool and conn:
            self._pool.putconn(conn)
        elif self._driver == "psycopg3" and self._pool and conn:
            self._pool.putconn(conn)

    def insert_conn_telemetry_batch(self, records: List[Dict[str, Any]]) -> int:
        """Batch insert connection flow records into conn_telemetry hypertable."""
        if not records:
            return 0
        if not self._is_connected:
            return len(records)

        conn = self.get_connection()
        if not conn:
            return 0

        inserted = 0
        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO conn_telemetry (
                    time, uid, community_id, orig_h, orig_p, resp_h, resp_p,
                    proto, service, duration, orig_bytes, resp_bytes,
                    conn_state, orig_pkts, resp_pkts, missed_bytes, history, raw_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            rows = []
            for r in records:
                t = normalize_timestamp(r.get("ts") or r.get("time") or time.time())
                uid = str(r.get("uid", ""))
                cid = r.get("community_id")
                orig_h = r.get("id.orig_h") or r.get("orig_h") or "0.0.0.0"
                orig_p = int(r.get("id.orig_p") or r.get("orig_p") or 0)
                resp_h = r.get("id.resp_h") or r.get("resp_h") or "0.0.0.0"
                resp_p = int(r.get("id.resp_p") or r.get("resp_p") or 0)
                proto = str(r.get("proto", "tcp")).lower()
                service = r.get("service")
                dur = float(r.get("duration", 0.0) or 0.0)
                orig_bytes = int(r.get("orig_bytes", 0) or 0)
                resp_bytes = int(r.get("resp_bytes", 0) or 0)
                conn_state = str(r.get("conn_state", ""))
                orig_pkts = int(r.get("orig_pkts", 0) or 0)
                resp_pkts = int(r.get("resp_pkts", 0) or 0)
                missed_bytes = int(r.get("missed_bytes", 0) or 0)
                hist = str(r.get("history", ""))
                raw_json = json.dumps(r)

                rows.append((
                    t, uid, cid, orig_h, orig_p, resp_h, resp_p,
                    proto, service, dur, orig_bytes, resp_bytes,
                    conn_state, orig_pkts, resp_pkts, missed_bytes, hist, raw_json
                ))

            if self._driver == "psycopg2":
                from psycopg2.extras import execute_batch
                execute_batch(cursor, query, rows, page_size=500)
            else:
                cursor.executemany(query, rows)

            conn.commit()
            cursor.close()
            inserted = len(rows)
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error inserting conn_telemetry batch: {e}")
        finally:
            self.release_connection(conn)

        return inserted

    def insert_dns_telemetry_batch(self, records: List[Dict[str, Any]]) -> int:
        """Batch insert DNS records into dns_telemetry hypertable."""
        if not records:
            return 0
        if not self._is_connected:
            return len(records)

        conn = self.get_connection()
        if not conn:
            return 0

        inserted = 0
        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO dns_telemetry (
                    time, uid, orig_h, orig_p, resp_h, resp_p,
                    proto, trans_id, query, qclass_name, qtype_name,
                    rcode_name, answers, entropy, is_dga, raw_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            rows = []
            for r in records:
                t = normalize_timestamp(r.get("ts") or r.get("time") or time.time())
                uid = str(r.get("uid", ""))
                orig_h = r.get("id.orig_h") or r.get("orig_h") or "0.0.0.0"
                orig_p = int(r.get("id.orig_p") or r.get("orig_p") or 0)
                resp_h = r.get("id.resp_h") or r.get("resp_h") or "0.0.0.0"
                resp_p = int(r.get("id.resp_p") or r.get("resp_p") or 0)
                proto = str(r.get("proto", "udp")).lower()
                trans_id = int(r.get("trans_id", 0) or 0)
                query_str = str(r.get("query", ""))
                qclass = str(r.get("qclass_name", ""))
                qtype = str(r.get("qtype_name", ""))
                rcode = str(r.get("rcode_name", ""))
                answers = r.get("answers") if isinstance(r.get("answers"), list) else []
                entropy = float(r.get("entropy", 0.0) or 0.0)
                is_dga = bool(r.get("is_dga", False))
                raw_json = json.dumps(r)

                rows.append((
                    t, uid, orig_h, orig_p, resp_h, resp_p,
                    proto, trans_id, query_str, qclass, qtype,
                    rcode, answers, entropy, is_dga, raw_json
                ))

            if self._driver == "psycopg2":
                from psycopg2.extras import execute_batch
                execute_batch(cursor, query, rows, page_size=500)
            else:
                cursor.executemany(query, rows)

            conn.commit()
            cursor.close()
            inserted = len(rows)
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error inserting dns_telemetry batch: {e}")
        finally:
            self.release_connection(conn)

        return inserted

    def insert_ssl_telemetry_batch(self, records: List[Dict[str, Any]]) -> int:
        """Batch insert SSL/TLS records with JA4 fingerprints into ssl_telemetry hypertable."""
        if not records:
            return 0
        if not self._is_connected:
            return len(records)

        conn = self.get_connection()
        if not conn:
            return 0

        inserted = 0
        try:
            cursor = conn.cursor()
            query = """
                INSERT INTO ssl_telemetry (
                    time, uid, orig_h, orig_p, resp_h, resp_p,
                    version, cipher, server_name, ja4, ja4s, ja4_match_threat, established, raw_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            rows = []
            for r in records:
                t = normalize_timestamp(r.get("ts") or r.get("time") or time.time())
                uid = str(r.get("uid", ""))
                orig_h = r.get("id.orig_h") or r.get("orig_h") or "0.0.0.0"
                orig_p = int(r.get("id.orig_p") or r.get("orig_p") or 0)
                resp_h = r.get("id.resp_h") or r.get("resp_h") or "0.0.0.0"
                resp_p = int(r.get("id.resp_p") or r.get("resp_p") or 0)
                version = str(r.get("version", ""))
                cipher = str(r.get("cipher", ""))
                server_name = r.get("server_name")
                ja4 = r.get("ja4")
                ja4s = r.get("ja4s")
                threat = r.get("ja4_match_threat")
                est = bool(r.get("established", True))
                raw_json = json.dumps(r)

                rows.append((
                    t, uid, orig_h, orig_p, resp_h, resp_p,
                    version, cipher, server_name, ja4, ja4s, threat, est, raw_json
                ))

            if self._driver == "psycopg2":
                from psycopg2.extras import execute_batch
                execute_batch(cursor, query, rows, page_size=500)
            else:
                cursor.executemany(query, rows)

            conn.commit()
            cursor.close()
            inserted = len(rows)
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error inserting ssl_telemetry batch: {e}")
        finally:
            self.release_connection(conn)

        return inserted

    def insert_alert(
        self,
        detector_name: str,
        threat_class: str,
        severity: str,
        confidence: float,
        source_ip: str,
        evidence: Dict[str, Any],
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        flow_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> bool:
        """Insert a single security alert into alerts hypertable."""
        if not self._is_connected:
            return True

        conn = self.get_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
            t = timestamp or datetime.now(timezone.utc)
            query = """
                INSERT INTO alerts (
                    time, detector_name, threat_class, severity,
                    confidence, source_ip, target_ip, target_port,
                    flow_id, evidence
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                query,
                (t, detector_name, threat_class, severity, confidence, source_ip, target_ip, target_port, flow_id, json.dumps(evidence)),
            )
            conn.commit()
            cursor.close()
            return True
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error inserting alert: {e}")
            return False
        finally:
            self.release_connection(conn)

    def record_system_metric(
        self,
        events_per_second: float,
        packets_per_second: float,
        megabits_per_second: float,
        host: str = "sih_sensor",
        latency_p50_ms: Optional[float] = None,
        latency_p90_ms: Optional[float] = None,
        latency_p95_ms: Optional[float] = None,
        latency_p99_ms: Optional[float] = None,
        kafka_lag: int = 0,
        active_flows: int = 0,
        cpu_utilization: Optional[float] = None,
        memory_mb: Optional[float] = None,
        memory_utilization: Optional[float] = None,
        packet_loss_rate: Optional[float] = None,
    ) -> bool:
        """Record live system performance metrics into system_metrics hypertable."""
        if not self._is_connected:
            return True

        conn = self.get_connection()
        if not conn:
            return False

        try:
            cursor = conn.cursor()
            t = datetime.now(timezone.utc)
            query = """
                INSERT INTO system_metrics (
                    time, host, events_per_second, packets_per_second, megabits_per_second,
                    latency_p50_ms, latency_p90_ms, latency_p95_ms, latency_p99_ms,
                    kafka_lag, active_flows, cpu_utilization, memory_mb, memory_utilization, packet_loss_rate
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                query,
                (
                    t, host, events_per_second, packets_per_second, megabits_per_second,
                    latency_p50_ms, latency_p90_ms, latency_p95_ms, latency_p99_ms,
                    kafka_lag, active_flows, cpu_utilization, memory_mb, memory_utilization, packet_loss_rate
                ),
            )
            conn.commit()
            cursor.close()
            return True
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Error recording system metric: {e}")
            return False
        finally:
            self.release_connection(conn)

    def close(self) -> None:
        """Close connection pool."""
        if self._pool:
            if hasattr(self._pool, "closeall"):
                self._pool.closeall()
            elif hasattr(self._pool, "close"):
                self._pool.close()
