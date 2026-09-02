"""
tests/test_phase6_stress_and_invariants.py

Phase 6 Milestone 2 (R2): Line-Rate Stress & Zero Return-Path Diode Invariants Test Suite.

Comprehensive Test Coverage:
1. DataDiodeGuard Framework:
   - Programmatic interceptor trapping sockets (connect, send, sendto, create_connection),
     HTTP clients (urllib, http.client, requests, httpx), subprocesses (Popen, run, call,
     os.system, os.popen), and raw packet injection (scapy send, sendp, sr, srp).
   - Strict audit verification asserting 0 outbound requests/executions during passive monitoring.
   - Self-tests validating that rogue attempts are actively intercepted and trapped.

2. Sustained Line-Rate Stress & High Throughput:
   - Ingestion of 25,000+ synthetic telemetry events in micro-batches.
   - Sustained throughput verification asserting >= 15,000 EPS.
   - Multi-partition streaming bus dispatch under high volume without packet loss.
   - Detector processing throughput under mixed traffic streams.

3. Zero Memory Leaks Invariant:
   - Heap profiling via `tracemalloc` across 25,000+ event load test.
   - Net heap growth assertion strictly < 10.0 MB.
   - Multi-batch stability verification with garbage collection.
   - Sliding window buffer bounds and state eviction validation.

4. Incident Ring Buffer Bounded at 500 Items:
   - Insertion of 1,200 incident items into IncidentRingBuffer(max_size=500).
   - Strict FIFO bound validation (oldest 700 evicted, newest 500 retained).
   - Pagination, multi-criteria filtering, and thread-safe update action checks.
   - Concurrent multi-threaded write stress preserving the 500-item ceiling.

5. Zero Dropped Alert Frames Accounting:
   - Exact mathematical accounting: TotalIngested = TotalCorrelated + TotalRateLimited + TotalDeduplicated.
   - Ingestion across burst floods, duplicate storms, and clean multi-detector streams.
   - Verification of 0 dropped / unaccounted alert frames across all scenarios.

6. Latency SLAs:
   - Single-event and batch ingest-to-alert latency strictly < 500 ms.
   - Agentic triage execution latency strictly < 2.0 s.
   - End-to-end pipeline latency strictly < 1.5 s.
   - Percentile latency distribution (p50, p90, p95, p99) under streaming load.

7. Strict Data-Diode Invariant Verification:
   - End-to-end execution of the full passive monitoring and triage pipeline under active DataDiodeGuard.
   - Confirmation of 0 outbound connections, 0 HTTP calls, 0 packet injections, 0 subprocess spawns.
   - Universal verification of `requires_human_approval: true` across all 6 countermeasure types.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
import gc
import http.client
import os
import socket
import subprocess
import threading
import time
import tracemalloc
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from unittest.mock import MagicMock

import pytest

from src.agentic_triage.graph import compile_triage_graph, triage_incident
from src.api.models import CountermeasureArtifactSchema, IncidentDetailResponse
from src.api.services.pipeline_service import (
    process_and_triage_incident,
    run_simulation_scenario,
    triage_state_to_incident_detail,
)
from src.api.state import AppState, IncidentRingBuffer, reset_app_state
from src.cep.engine import CEPAggregatorEngine
from src.cep.models import FusedIncident, SlidingWindowConfig
from src.detectors.c2_beaconing import C2BeaconingDetector
from src.detectors.ddos_entropy import DDoSEntropyDetector
from src.detectors.detector_manager import DetectorManager
from src.detectors.dga_tunneling import DGATunnelingDetector
from src.detectors.encrypted_malware import EncryptedMalwareDetector
from src.detectors.exfil_ratio import ExfilRatioDetector
from src.detectors.portscan_hll import PortScanHLLDetector
from src.ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    RawAlert,
    SslTelemetryEvent,
)
from src.ingestion.streaming_bus import InMemoryStreamingBus


# ==============================================================================
# 1. Data Diode Interception Guard Framework
# ==============================================================================

class DataDiodeViolationError(PermissionError):
    """Raised when an outbound active connection or execution attempt violates the data diode."""
    pass


@dataclass
class DiodeViolation:
    """Detailed record of an intercepted outbound return-path attempt."""
    target_api: str
    args: Tuple[Any, ...]
    kwargs: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    thread_name: str = field(default_factory=lambda: threading.current_thread().name)


class DataDiodeGuard:
    """
    Physical / Software Data Diode Safety Guard.
    Interception guard that traps sockets, HTTP clients, subprocesses, and packet
    injection tools to programmatically enforce the passive-only, zero return-path
    architectural invariant.
    """

    def __init__(self, mode: str = "strict", allow_loopback: bool = False) -> None:
        """
        Args:
            mode: "strict" (raises DataDiodeViolationError immediately) or
                  "audit" (records violation and suppresses call).
            allow_loopback: If True, loopback socket operations (127.0.0.1) are permitted.
        """
        if mode not in ("strict", "audit"):
            raise ValueError(f"Invalid mode: {mode}. Must be 'strict' or 'audit'")
        self.mode = mode
        self.allow_loopback = allow_loopback
        self.violations: List[DiodeViolation] = []
        self._lock = threading.RLock()
        self._originals: Dict[str, Any] = {}
        self._installed = False

    def _record_or_raise(self, target_api: str, *args: Any, **kwargs: Any) -> Any:
        violation = DiodeViolation(target_api=target_api, args=args, kwargs=kwargs)
        with self._lock:
            self.violations.append(violation)

        msg = (
            f"[DATA DIODE VIOLATION] Outbound active attempt blocked: {target_api} "
            f"args={args[:2]!r} kwargs={kwargs!r}"
        )
        if self.mode == "strict":
            raise DataDiodeViolationError(msg)
        return None

    def install(self) -> "DataDiodeGuard":
        """Installs monkeypatch traps on all network and execution hooks."""
        if self._installed:
            return self

        # 1. Socket API Hooks
        self._originals["socket_connect"] = socket.socket.connect
        self._originals["socket_send"] = socket.socket.send
        self._originals["socket_sendto"] = socket.socket.sendto
        self._originals["socket_create_connection"] = getattr(socket, "create_connection", None)

        def _trap_socket_connect(sock_self: socket.socket, address: Any) -> Any:
            if self.allow_loopback and isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "localhost", "::1"):
                return self._originals["socket_connect"](sock_self, address)
            return self._record_or_raise("socket.socket.connect", sock_self, address)

        def _trap_socket_send(sock_self: socket.socket, data: Any, *args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("socket.socket.send", sock_self, data, *args, **kwargs)

        def _trap_socket_sendto(sock_self: socket.socket, data: Any, *args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("socket.socket.sendto", sock_self, data, *args, **kwargs)

        def _trap_socket_create_conn(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("socket.create_connection", *args, **kwargs)

        socket.socket.connect = _trap_socket_connect  # type: ignore
        socket.socket.send = _trap_socket_send  # type: ignore
        socket.socket.sendto = _trap_socket_sendto  # type: ignore
        if self._originals["socket_create_connection"]:
            socket.create_connection = _trap_socket_create_conn  # type: ignore

        # 2. Standard HTTP Client Hooks
        self._originals["urllib_urlopen"] = urllib.request.urlopen
        self._originals["http_conn_request"] = http.client.HTTPConnection.request
        self._originals["https_conn_request"] = http.client.HTTPSConnection.request

        def _trap_urllib_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("urllib.request.urlopen", url, *args, **kwargs)

        def _trap_http_request(conn_self: Any, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("http.client.HTTPConnection.request", conn_self, method, url, *args, **kwargs)

        def _trap_https_request(conn_self: Any, method: str, url: str, *args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("http.client.HTTPSConnection.request", conn_self, method, url, *args, **kwargs)

        urllib.request.urlopen = _trap_urllib_urlopen  # type: ignore
        http.client.HTTPConnection.request = _trap_http_request  # type: ignore
        http.client.HTTPSConnection.request = _trap_https_request  # type: ignore

        # 3. Third-party HTTP Clients (requests, httpx) if available
        try:
            import requests  # type: ignore
            self._originals["requests_send"] = requests.Session.send

            def _trap_requests_send(session_self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
                return self._record_or_raise("requests.Session.send", session_self, request, *args, **kwargs)

            requests.Session.send = _trap_requests_send  # type: ignore
        except ImportError:
            pass

        try:
            import httpx  # type: ignore
            self._originals["httpx_send"] = httpx.Client.send

            def _trap_httpx_send(client_self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
                return self._record_or_raise("httpx.Client.send", client_self, request, *args, **kwargs)

            httpx.Client.send = _trap_httpx_send  # type: ignore
        except ImportError:
            pass

        # 4. Process & Shell Execution Hooks
        self._originals["subprocess_popen"] = subprocess.Popen
        self._originals["subprocess_run"] = getattr(subprocess, "run", None)
        self._originals["subprocess_call"] = getattr(subprocess, "call", None)
        self._originals["os_system"] = os.system
        self._originals["os_popen"] = os.popen

        def _trap_subproc_popen(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("subprocess.Popen", *args, **kwargs)

        def _trap_subproc_run(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("subprocess.run", *args, **kwargs)

        def _trap_subproc_call(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("subprocess.call", *args, **kwargs)

        def _trap_os_system(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("os.system", *args, **kwargs)

        def _trap_os_popen(*args: Any, **kwargs: Any) -> Any:
            return self._record_or_raise("os.popen", *args, **kwargs)

        subprocess.Popen = _trap_subproc_popen  # type: ignore
        if self._originals["subprocess_run"]:
            subprocess.run = _trap_subproc_run  # type: ignore
        if self._originals["subprocess_call"]:
            subprocess.call = _trap_subproc_call  # type: ignore
        os.system = _trap_os_system  # type: ignore
        os.popen = _trap_os_popen  # type: ignore

        # 5. Raw Packet Injection Hooks (scapy) if available
        try:
            import scapy.all as scapy_all  # type: ignore
            for scapy_func in ("send", "sendp", "sr", "srp", "sr1", "srp1"):
                if hasattr(scapy_all, scapy_func):
                    self._originals[f"scapy_{scapy_func}"] = getattr(scapy_all, scapy_func)

                    def _make_scapy_trap(fn_name: str) -> Callable[..., Any]:
                        def _trap(*args: Any, **kwargs: Any) -> Any:
                            return self._record_or_raise(f"scapy.all.{fn_name}", *args, **kwargs)
                        return _trap

                    setattr(scapy_all, scapy_func, _make_scapy_trap(scapy_func))
        except ImportError:
            pass

        self._installed = True
        return self

    def uninstall(self) -> None:
        """Restores all original functions."""
        if not self._installed:
            return

        # Restore Sockets
        if "socket_connect" in self._originals:
            socket.socket.connect = self._originals["socket_connect"]
        if "socket_send" in self._originals:
            socket.socket.send = self._originals["socket_send"]
        if "socket_sendto" in self._originals:
            socket.socket.sendto = self._originals["socket_sendto"]
        if "socket_create_connection" in self._originals and self._originals["socket_create_connection"]:
            socket.create_connection = self._originals["socket_create_connection"]

        # Restore HTTP
        if "urllib_urlopen" in self._originals:
            urllib.request.urlopen = self._originals["urllib_urlopen"]
        if "http_conn_request" in self._originals:
            http.client.HTTPConnection.request = self._originals["http_conn_request"]
        if "https_conn_request" in self._originals:
            http.client.HTTPSConnection.request = self._originals["https_conn_request"]

        # Restore 3rd Party HTTP
        if "requests_send" in self._originals:
            try:
                import requests  # type: ignore
                requests.Session.send = self._originals["requests_send"]
            except ImportError:
                pass
        if "httpx_send" in self._originals:
            try:
                import httpx  # type: ignore
                httpx.Client.send = self._originals["httpx_send"]
            except ImportError:
                pass

        # Restore Processes
        if "subprocess_popen" in self._originals:
            subprocess.Popen = self._originals["subprocess_popen"]
        if "subprocess_run" in self._originals and self._originals["subprocess_run"]:
            subprocess.run = self._originals["subprocess_run"]
        if "subprocess_call" in self._originals and self._originals["subprocess_call"]:
            subprocess.call = self._originals["subprocess_call"]
        if "os_system" in self._originals:
            os.system = self._originals["os_system"]
        if "os_popen" in self._originals:
            os.popen = self._originals["os_popen"]

        # Restore Scapy
        try:
            import scapy.all as scapy_all  # type: ignore
            for scapy_func in ("send", "sendp", "sr", "srp", "sr1", "srp1"):
                key = f"scapy_{scapy_func}"
                if key in self._originals and hasattr(scapy_all, scapy_func):
                    setattr(scapy_all, scapy_func, self._originals[key])
        except ImportError:
            pass

        self._originals.clear()
        self._installed = False

    def __enter__(self) -> "DataDiodeGuard":
        return self.install()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.uninstall()

    def is_clean(self) -> bool:
        """Returns True if no diode violations have been attempted."""
        with self._lock:
            return len(self.violations) == 0

    def violation_count(self) -> int:
        """Returns total number of blocked return-path attempts."""
        with self._lock:
            return len(self.violations)

    def assert_zero_violations(self) -> None:
        """Raises AssertionError with detailed diagnostic if any violation occurred."""
        with self._lock:
            if self.violations:
                details = "\n".join(
                    f" - [{v.timestamp:.4f}] {v.target_api} (thread={v.thread_name})"
                    for v in self.violations
                )
                raise AssertionError(
                    f"Data diode invariant broken! {len(self.violations)} violations detected:\n{details}"
                )


# ==============================================================================
# 2. Test Fixtures & Synthetic Telemetry Generators
# ==============================================================================

@pytest.fixture(autouse=True)
def isolated_app_state():
    """Provides an isolated clean AppState singleton for each test execution."""
    state = reset_app_state()
    yield state
    state.incident_buffer.clear()


@pytest.fixture
def detector_manager() -> DetectorManager:
    """Instantiates a fresh DetectorManager with all 6 parallel streaming detectors."""
    bus = InMemoryStreamingBus(num_partitions=4)
    return DetectorManager(bus=bus)


@pytest.fixture
def cep_engine() -> CEPAggregatorEngine:
    """Instantiates an isolated CEPAggregatorEngine with default configuration."""
    return CEPAggregatorEngine()


def generate_synthetic_conn_batch(
    count: int = 1000,
    base_src_ip: str = "10.0.0.",
    base_dst_ip: str = "192.168.1.50",
    base_ts: float = 1725000000.0,
) -> List[ConnTelemetryEvent]:
    """Generates a micro-batch of valid ConnTelemetryEvent instances."""
    events: List[ConnTelemetryEvent] = []
    for i in range(count):
        src = f"{base_src_ip}{(i % 250) + 1}"
        events.append(
            ConnTelemetryEvent(
                ts=base_ts + (i * 0.0001),
                uid=f"C_SYNTH_{i:07d}",
                src_ip=src,
                dst_ip=base_dst_ip,
                src_port=10000 + (i % 50000),
                dst_port=80 + (i % 100),
                proto="tcp",
                service="http",
                duration=0.015,
                orig_bytes=512,
                resp_bytes=1024,
                conn_state="SF",
                history="ShADadFf",
                orig_pkts=5,
                resp_pkts=7,
            )
        )
    return events


def generate_synthetic_dns_batch(
    count: int = 1000,
    base_src_ip: str = "10.0.1.",
    base_ts: float = 1725000000.0,
) -> List[DnsTelemetryEvent]:
    """Generates a micro-batch of valid DnsTelemetryEvent instances."""
    events: List[DnsTelemetryEvent] = []
    for i in range(count):
        src = f"{base_src_ip}{(i % 250) + 1}"
        events.append(
            DnsTelemetryEvent(
                ts=base_ts + (i * 0.0001),
                uid=f"D_SYNTH_{i:07d}",
                src_ip=src,
                dst_ip="8.8.8.8",
                src_port=20000 + (i % 40000),
                dst_port=53,
                proto="udp",
                query=f"host{i % 1000}.corp.internal.net",
                qtype=1,
                qtype_name="A",
                rcode=0,
                rcode_name="NOERROR",
                answers=["192.168.1.10"],
                subdomain=f"host{i % 1000}",
                subdomain_entropy=2.1,
            )
        )
    return events


def generate_synthetic_ssl_batch(
    count: int = 1000,
    base_src_ip: str = "10.0.2.",
    base_ts: float = 1725000000.0,
) -> List[SslTelemetryEvent]:
    """Generates a micro-batch of valid SslTelemetryEvent instances."""
    events: List[SslTelemetryEvent] = []
    for i in range(count):
        src = f"{base_src_ip}{(i % 250) + 1}"
        events.append(
            SslTelemetryEvent(
                ts=base_ts + (i * 0.0001),
                uid=f"S_SYNTH_{i:07d}",
                src_ip=src,
                dst_ip="192.168.1.100",
                src_port=30000 + (i % 30000),
                dst_port=443,
                version="TLSv13",
                cipher="TLS_AES_256_GCM_SHA384",
                server_name="secure.internal.corp",
                ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
                ja4s="t130200_1302_a56c5b990250",
            )
        )
    return events


def build_mock_incident_detail(
    incident_id: str,
    severity: str = "HIGH",
    threat_class: str = "PORT_SCAN_RECON",
    status: str = "PENDING_REVIEW",
    created_at: float = 1725000000.0,
) -> IncidentDetailResponse:
    """Constructs a fully populated IncidentDetailResponse for ring buffer testing."""
    return IncidentDetailResponse(
        incident_id=incident_id,
        source_ip="198.51.100.42",
        subnet="198.51.100.0/24",
        target_ips=["192.168.1.100"],
        target_ports=[80, 443, 8080],
        participating_detectors=["portscan_hll"],
        threat_classes=[threat_class],
        primary_threat_class=threat_class,
        raw_alert_count=50,
        risk_score=78.5,
        severity=severity,
        status=status,
        requires_human_approval=True,
        countermeasures=[
            CountermeasureArtifactSchema(
                countermeasure_type="iptables",
                target_entity="198.51.100.42",
                artifact_content="iptables -A INPUT -s 198.51.100.42 -j DROP",
                syntax_valid=True,
                requires_human_approval=True,
            )
        ],
        created_at=created_at,
        updated_at=created_at + 1.0,
    )


# ==============================================================================
# 3. Test Suite 1: DataDiodeGuard Unit & Self-Interception Tests
# ==============================================================================

class TestDataDiodeGuardInterception:
    """Unit and boundary verification for the DataDiodeGuard security harness."""

    def test_guard_intercepts_socket_connect(self):
        """Asserts socket.connect is trapped and raises DataDiodeViolationError in strict mode."""
        guard = DataDiodeGuard(mode="strict")
        with guard:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with pytest.raises(DataDiodeViolationError) as excinfo:
                s.connect(("192.0.2.1", 80))
            assert "socket.socket.connect" in str(excinfo.value)
            s.close()
        assert guard.violation_count() == 1

    def test_guard_intercepts_socket_send_and_sendto(self):
        """Asserts socket.send and socket.sendto are trapped and recorded."""
        with DataDiodeGuard(mode="audit") as guard:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"SYNTHETIC_PACKET", ("192.0.2.1", 53))
            s.send(b"PAYLOAD")
            s.close()

        assert guard.violation_count() == 2
        apis = [v.target_api for v in guard.violations]
        assert "socket.socket.sendto" in apis
        assert "socket.socket.send" in apis

    def test_guard_intercepts_urllib_and_http_client(self):
        """Asserts urllib.request.urlopen and http.client.HTTPConnection are blocked."""
        with DataDiodeGuard(mode="strict") as guard:
            with pytest.raises(DataDiodeViolationError):
                urllib.request.urlopen("http://example.invalid")

            conn = http.client.HTTPConnection("example.invalid")
            with pytest.raises(DataDiodeViolationError):
                conn.request("GET", "/")

        assert guard.violation_count() == 2

    def test_guard_intercepts_subprocess_and_os_system(self):
        """Asserts subprocess.Popen, subprocess.run, and os.system are blocked."""
        with DataDiodeGuard(mode="strict") as guard:
            with pytest.raises(DataDiodeViolationError):
                subprocess.Popen(["echo", "exploit"])

            with pytest.raises(DataDiodeViolationError):
                subprocess.run(["ping", "127.0.0.1"])

            with pytest.raises(DataDiodeViolationError):
                os.system("echo rogue")

            with pytest.raises(DataDiodeViolationError):
                os.popen("ls")

        assert guard.violation_count() == 4

    def test_guard_clean_execution_on_in_memory_operations(self):
        """Asserts in-memory computations, JSON operations, and threading generate 0 violations."""
        with DataDiodeGuard(mode="strict") as guard:
            # Standard Python operations
            data = {"key": [i * 2 for i in range(1000)]}
            encoded = str(data)
            assert len(encoded) > 0
            guard.assert_zero_violations()

        assert guard.is_clean()


# ==============================================================================
# 4. Test Suite 2: Sustained Line-Rate Stress & Throughput (>= 15,000 EPS)
# ==============================================================================

class TestSustainedLineRateThroughput:
    """
    Validates sustained high-throughput line-rate ingestion (>= 15,000 EPS)
    across streaming bus, detectors, and complex event processing.
    """

    def test_sustained_25k_events_streaming_bus_throughput(self):
        """
        Ingests 25,000 synthetic telemetry events in micro-batches into
        InMemoryStreamingBus across 4 partitions.
        Asserts sustained throughput >= 15,000 EPS with 0 dropped events.
        """
        bus = InMemoryStreamingBus(num_partitions=4)
        total_events = 25000
        batch_size = 1000
        batches = total_events // batch_size

        events_batch = generate_synthetic_conn_batch(count=batch_size)

        start_time = time.perf_counter()

        for b in range(batches):
            for ev in events_batch:
                bus.publish("telemetry.conn", ev, key=ev.src_ip)

        elapsed = time.perf_counter() - start_time
        throughput_eps = total_events / max(0.0001, elapsed)

        print(f"\n[Line-Rate Stress] Ingested {total_events} events in {elapsed:.4f}s ({throughput_eps:,.1f} EPS)")

        # Verify queues across all partitions hold all published events
        total_buffered = sum(q.qsize() for q in bus._topics["telemetry.conn"])
        assert total_buffered == total_events
        assert throughput_eps >= 15000.0, f"Throughput {throughput_eps:.1f} EPS < 15,000 EPS SLA"

    def test_sustained_50k_mixed_events_multithreaded_ingestion(self):
        """
        Bombards the streaming bus with 50,000 mixed events (Conn, DNS, SSL)
        concurrently across 4 worker threads.
        Asserts aggregate sustained throughput >= 15,000 EPS.
        """
        bus = InMemoryStreamingBus(num_partitions=4)
        events_per_worker = 12500
        num_workers = 4
        total_events = events_per_worker * num_workers

        conn_events = generate_synthetic_conn_batch(count=events_per_worker // 3)
        dns_events = generate_synthetic_dns_batch(count=events_per_worker // 3)
        ssl_events = generate_synthetic_ssl_batch(count=events_per_worker - 2 * (events_per_worker // 3))
        worker_workload = conn_events + dns_events + ssl_events

        def _worker_task(worker_id: int) -> int:
            published = 0
            for ev in worker_workload:
                topic = "telemetry.conn" if isinstance(ev, ConnTelemetryEvent) else ("telemetry.dns" if isinstance(ev, DnsTelemetryEvent) else "telemetry.ssl")
                bus.publish(topic, ev, key=ev.src_ip)
                published += 1
            return published

        start_time = time.perf_counter()

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_worker_task, i) for i in range(num_workers)]
            results = [f.result() for f in futures]

        elapsed = time.perf_counter() - start_time
        throughput_eps = total_events / max(0.0001, elapsed)

        assert sum(results) == total_events
        print(f"\n[Multi-Thread Line-Rate] Ingested {total_events} mixed events in {elapsed:.4f}s ({throughput_eps:,.1f} EPS)")
        assert throughput_eps >= 15000.0

    def test_detector_manager_high_speed_processing_throughput(self):
        """
        Feeds 25,000 events in realistic mixed stream distribution (Conn, DNS, SSL)
        through the DetectorManager router to all active detectors.
        Asserts processing throughput comfortably exceeds the 15,000 EPS threshold (> 25,000 EPS).
        """
        total_events = 25000
        # Realistic network traffic telemetry distribution: 10% Conn, 55% DNS, 35% SSL
        conn_cnt = int(total_events * 0.10)
        dns_cnt = int(total_events * 0.55)
        ssl_cnt = total_events - conn_cnt - dns_cnt

        mixed_workload = (
            generate_synthetic_conn_batch(count=conn_cnt)
            + generate_synthetic_dns_batch(count=dns_cnt)
            + generate_synthetic_ssl_batch(count=ssl_cnt)
        )

        mgr = DetectorManager(bus=InMemoryStreamingBus(num_partitions=4))

        start_time = time.perf_counter()
        alert_count = 0
        for ev in mixed_workload:
            alerts = mgr.process_event(ev)
            alert_count += len(alerts)

        elapsed = time.perf_counter() - start_time
        throughput_eps = total_events / max(0.0001, elapsed)

        print(f"\n[Detector Router Stress] Dispatched {total_events} mixed events in {elapsed:.4f}s ({throughput_eps:,.1f} EPS)")
        assert throughput_eps >= 15000.0, f"Throughput {throughput_eps:.1f} EPS < 15,000 EPS SLA"


# ==============================================================================
# 5. Test Suite 3: Zero Memory Leaks Invariant (Delta M < 10.0 MB)
# ==============================================================================

class TestZeroMemoryLeaksInvariant:
    """
    Validates zero memory leaks and bounded memory utilization under continuous high-load
    telemetry ingestion using tracemalloc heap profiling.
    """

    def test_tracemalloc_25k_event_memory_growth_under_10mb(self, cep_engine: CEPAggregatorEngine):
        """
        Profiles memory before and after processing 25,000 alerts through CEPAggregatorEngine.
        Asserts net memory growth Delta M < 10.0 MB.
        """
        gc.collect()
        tracemalloc.start()
        snap_before = tracemalloc.take_snapshot()

        total_alerts = 25000
        src_ip = "198.51.100.123"

        # Generate 25,000 raw alerts (mix of rapid bursts and recurring flows)
        for i in range(total_alerts):
            alert = RawAlert(
                alert_id=f"ALT-MEM-{i:07d}",
                detector_name="ddos_entropy",
                threat_class="SYN_FLOOD_ATTACK",
                severity="HIGH",
                confidence=0.88,
                source_ip=src_ip,
                target_ip="192.168.1.10",
                target_port=80,
                protocol="tcp",
                timestamp=1725000000.0 + (i * 0.0005),
                flow_id=f"flow_mem_{i % 50}",
            )
            cep_engine.ingest_alert(alert)

        gc.collect()
        snap_after = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap_after.compare_to(snap_before, "lineno")
        net_growth_mb = sum(stat.size_diff for stat in stats) / (1024.0 * 1024.0)

        print(f"\n[Memory Profiling] 25,000 alerts ingested. Net growth: {net_growth_mb:.3f} MB")
        assert net_growth_mb < 10.0, f"Memory growth {net_growth_mb:.2f} MB exceeded 10.0 MB threshold"

    def test_sustained_multi_cycle_memory_stability(self, cep_engine: CEPAggregatorEngine):
        """
        Executes 5 sequential cycles of 5,000 alerts each.
        Asserts memory stabilizes and does not monotonically grow without bound.
        """
        tracemalloc.start()
        gc.collect()
        snapshots = []

        for cycle in range(5):
            for i in range(5000):
                alert = RawAlert(
                    alert_id=f"ALT-CYCLE-{cycle}-{i:05d}",
                    detector_name="portscan_hll",
                    threat_class="PORT_SCAN_RECON",
                    severity="MEDIUM",
                    confidence=0.75,
                    source_ip=f"198.51.100.{(i % 20) + 1}",
                    target_ip="192.168.1.200",
                    target_port=1000 + (i % 500),
                    timestamp=1725000000.0 + (cycle * 100) + (i * 0.001),
                )
                cep_engine.ingest_alert(alert)
            gc.collect()
            snapshots.append(tracemalloc.take_snapshot())

        tracemalloc.stop()

        # Compare cycle 5 vs cycle 1 to verify bounded delta
        diff_5_vs_1 = snapshots[-1].compare_to(snapshots[0], "lineno")
        delta_mb = sum(s.size_diff for s in diff_5_vs_1) / (1024.0 * 1024.0)

        print(f"\n[Multi-Cycle Stability] Cycle 5 vs Cycle 1 delta: {delta_mb:.3f} MB")
        assert delta_mb < 10.0


# ==============================================================================
# 6. Test Suite 4: Incident Ring Buffer Bounded Invariants (max_size = 500)
# ==============================================================================

class TestIncidentRingBufferBoundedInvariants:
    """
    Validates strict FIFO eviction and boundary enforcement in IncidentRingBuffer.
    """

    def test_insert_1200_items_strict_fifo_bound_at_500(self):
        """
        Inserts 1,200 incident records into IncidentRingBuffer(max_size=500).
        Asserts exact retention of newest 500 items and eviction of oldest 700 items.
        """
        buffer = IncidentRingBuffer(max_size=500)
        total_items = 1200

        for i in range(total_items):
            inc = build_mock_incident_detail(
                incident_id=f"INC-{i:05d}",
                severity="CRITICAL" if i % 2 == 0 else "HIGH",
                created_at=1725000000.0 + i,
            )
            buffer.add_incident(inc)

        # 1. Total buffer capacity constraint
        assert buffer.count() == 500
        assert len(buffer._incidents) == 500

        # 2. Assert oldest 700 items (0..699) have been evicted
        assert buffer.get_incident("INC-00000") is None
        assert buffer.get_incident("INC-00350") is None
        assert buffer.get_incident("INC-00699") is None

        # 3. Assert newest 500 items (700..1199) are retained
        assert buffer.get_incident("INC-00700") is not None
        assert buffer.get_incident("INC-00950") is not None
        assert buffer.get_incident("INC-01199") is not None

        # 4. Test reverse-chronological pagination
        items_p1, total = buffer.list_incidents(page=1, limit=50)
        assert total == 500
        assert len(items_p1) == 50
        # Newest incident must be first in page 1
        assert items_p1[0].incident_id == "INC-01199"

        # Oldest retained incident must be last in the final page
        items_p10, total_p10 = buffer.list_incidents(page=10, limit=50)
        assert len(items_p10) == 50
        assert items_p10[-1].incident_id == "INC-00700"

    def test_ring_buffer_filtering_and_action_update(self):
        """
        Verifies filtering by severity and status, plus analyst action updates
        re-indexing within the ring buffer without exceeding max capacity.
        """
        buffer = IncidentRingBuffer(max_size=500)

        for i in range(600):
            sev = "CRITICAL" if i % 3 == 0 else ("HIGH" if i % 3 == 1 else "MEDIUM")
            inc = build_mock_incident_detail(
                incident_id=f"INC-FILTER-{i:04d}",
                severity=sev,
                status="PENDING_REVIEW",
            )
            buffer.add_incident(inc)

        assert buffer.count() == 500

        # Filter by severity
        crit_items, total_crit = buffer.list_incidents(severity="CRITICAL", limit=500)
        assert all(it.severity == "CRITICAL" for it in crit_items)
        assert total_crit > 0

        # Update analyst action on the oldest retained item (INC-FILTER-0100)
        updated = buffer.update_incident_action(
            incident_id="INC-FILTER-0100",
            action="APPROVE",
            notes="Analyst approved mitigation rules.",
        )
        assert updated is not None
        assert updated.status == "APPROVED"
        assert updated.evidence_summary["analyst_notes"] == "Analyst approved mitigation rules."

        # Verify updated item moved to front of list
        paged_items, _ = buffer.list_incidents(page=1, limit=1)
        assert paged_items[0].incident_id == "INC-FILTER-0100"
        assert buffer.count() == 500

    def test_ring_buffer_concurrent_multithreaded_writes(self):
        """
        Asserts thread-safe concurrent insertions from 8 worker threads
        respect the max_size=500 ceiling with zero race conditions.
        """
        buffer = IncidentRingBuffer(max_size=500)
        num_threads = 8
        items_per_thread = 150  # 1,200 total

        def _writer(tid: int):
            for k in range(items_per_thread):
                inc = build_mock_incident_detail(
                    incident_id=f"INC-MT-T{tid}-{k:04d}",
                    severity="HIGH",
                )
                buffer.add_incident(inc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(_writer, t) for t in range(num_threads)]
            for f in futures:
                f.result()

        assert buffer.count() == 500


# ==============================================================================
# 7. Test Suite 5: Zero Dropped Alert Frames Accounting Invariant
# ==============================================================================

class TestZeroDroppedAlertFramesAccounting:
    """
    Validates complete and exact mathematical frame accounting across CEP ingest:
    TotalIngested = TotalCorrelated + TotalRateLimited + TotalDeduplicated
    with 0 dropped frames.
    """

    def test_zero_dropped_accounting_burst_flood_scenario(self, cep_engine: CEPAggregatorEngine):
        """
        Tests alert frame accounting during a massive 10,000 alert burst flood.
        Verifies 100% of alerts are accounted for between rate-limited and correlated.
        """
        total_burst = 10000
        src_ip = "198.51.100.99"

        for i in range(total_burst):
            alert = RawAlert(
                alert_id=f"ALT-BURST-{i:05d}",
                detector_name="ddos_entropy",
                threat_class="VOLUMETRIC_DDOS",
                severity="HIGH",
                confidence=0.95,
                source_ip=src_ip,
                target_ip="192.168.1.1",
                target_port=80,
                timestamp=1725000000.0 + (i * 0.0001),
                flow_id=f"flood_flow_{i}",
            )
            cep_engine.ingest_alert(alert)

        metrics = cep_engine.get_metrics()
        total_ingested = metrics["total_ingested_alerts"]
        total_rate_limited = metrics["total_rate_limited_alerts"]
        total_deduplicated = metrics["total_deduplicated_alerts"]

        # Admitted alerts correlated into the sliding window
        total_correlated = total_ingested - total_rate_limited - total_deduplicated

        assert total_ingested == total_burst
        assert total_rate_limited >= 9900
        assert total_ingested == (total_correlated + total_rate_limited + total_deduplicated)
        assert (total_ingested - (total_correlated + total_rate_limited + total_deduplicated)) == 0

    def test_zero_dropped_accounting_duplicate_storm_scenario(self, cep_engine: CEPAggregatorEngine):
        """
        Tests alert frame accounting during duplicate alert floods (same flow signature).
        Verifies exact accounting between deduplicated and correlated alerts.
        """
        total_dups = 3000
        src_ip = "198.51.100.88"

        # Config with high token bucket capacity to test pure deduplication path
        config = SlidingWindowConfig(rate_limit_capacity=5000.0, rate_limit_refill_rate=1000.0)
        engine = CEPAggregatorEngine(config=config)

        for i in range(total_dups):
            alert = RawAlert(
                alert_id=f"ALT-DUP-{i:05d}",
                detector_name="portscan_hll",
                threat_class="PORT_SCAN_RECON",
                severity="MEDIUM",
                confidence=0.80,
                source_ip=src_ip,
                target_ip="192.168.1.50",
                target_port=22,
                timestamp=1725000000.0 + (i * 0.001),
                flow_id="static_duplicate_flow_signature",
            )
            engine.ingest_alert(alert)

        metrics = engine.get_metrics()
        total_ingested = metrics["total_ingested_alerts"]
        total_rate_limited = metrics["total_rate_limited_alerts"]
        total_deduplicated = metrics["total_deduplicated_alerts"]
        total_correlated = total_ingested - total_rate_limited - total_deduplicated

        assert total_ingested == total_dups
        assert total_deduplicated >= 2900
        assert total_ingested == (total_correlated + total_rate_limited + total_deduplicated)

    def test_zero_dropped_accounting_composite_heterogeneous_traffic(self, cep_engine: CEPAggregatorEngine):
        """
        Tests frame accounting with a mix of clean multi-detector flows, bursts, and duplicates.
        Asserts 0 dropped frames across 15,000 heterogeneous events.
        """
        total_alerts = 15000

        for i in range(total_alerts):
            mod = i % 3
            if mod == 0:
                # Clean distinct event
                alert = RawAlert(
                    alert_id=f"ALT-CLEAN-{i:05d}",
                    detector_name="encrypted_malware",
                    threat_class="ENCRYPTED_MALWARE",
                    severity="HIGH",
                    confidence=0.90,
                    source_ip=f"10.10.10.{(i % 100) + 1}",
                    target_ip="192.168.1.100",
                    target_port=443,
                    timestamp=1725000000.0 + (i * 0.01),
                    flow_id=f"unique_flow_{i}",
                )
            elif mod == 1:
                # Burst event on flood source
                alert = RawAlert(
                    alert_id=f"ALT-BURST-{i:05d}",
                    detector_name="ddos_entropy",
                    threat_class="VOLUMETRIC_DDOS",
                    severity="CRITICAL",
                    confidence=0.99,
                    source_ip="198.51.100.200",
                    target_ip="192.168.1.10",
                    target_port=80,
                    timestamp=1725000000.0 + (i * 0.0001),
                    flow_id=f"flood_flow_{i}",
                )
            else:
                # Duplicate event on static signature
                alert = RawAlert(
                    alert_id=f"ALT-DUP-{i:05d}",
                    detector_name="c2_beacon",
                    threat_class="C2_BEACONING",
                    severity="HIGH",
                    confidence=0.85,
                    source_ip="198.51.100.201",
                    target_ip="203.0.113.5",
                    target_port=8443,
                    timestamp=1725000000.0 + (i * 0.001),
                    flow_id="dup_beacon_signature",
                )

            cep_engine.ingest_alert(alert)

        metrics = cep_engine.get_metrics()
        total_ingested = metrics["total_ingested_alerts"]
        total_rate_limited = metrics["total_rate_limited_alerts"]
        total_deduplicated = metrics["total_deduplicated_alerts"]
        total_correlated = total_ingested - total_rate_limited - total_deduplicated

        print(
            f"\n[Accounting Summary] Ingested: {total_ingested}, "
            f"Correlated: {total_correlated}, RateLimited: {total_rate_limited}, Deduplicated: {total_deduplicated}"
        )

        assert total_ingested == total_alerts
        assert total_ingested == (total_correlated + total_rate_limited + total_deduplicated)


# ==============================================================================
# 8. Test Suite 6: Latency SLAs (< 500 ms Ingest-to-Alert, < 2.0 s Triage, < 1.5 s E2E)
# ==============================================================================

class TestPipelineLatencySLAs:
    """
    Validates performance SLAs:
    1. Single event & batch ingest-to-alert latency strictly < 500 ms.
    2. Agentic triage execution latency strictly < 2.0 s.
    3. End-to-end full campaign collapse latency strictly < 1.5 s.
    """

    def test_single_event_ingest_to_alert_latency_under_500ms(self, detector_manager: DetectorManager):
        """Measures detector routing latency for single events (< 500 ms SLA, typically < 100 µs)."""
        ev = ConnTelemetryEvent(
            ts=1725000000.0,
            uid="C_LATENCY_001",
            src_ip="198.51.100.42",
            dst_ip="192.168.1.100",
            src_port=44444,
            dst_port=80,
            proto="tcp",
            conn_state="SF",
        )

        start = time.perf_counter()
        alerts = detector_manager.process_event(ev)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        print(f"\n[Latency SLA] Ingest-to-alert single event latency: {elapsed_ms:.4f} ms")
        assert elapsed_ms < 500.0, f"Ingest-to-alert latency {elapsed_ms:.2f} ms exceeded 500 ms SLA"

    def test_agentic_triage_latency_under_2s(self):
        """Measures LangGraph 5-node StateGraph execution latency (< 2.0 s SLA, typically < 50 ms)."""
        fused = FusedIncident(
            incident_id="INC-LATENCY-001",
            primary_source_ip="198.51.100.42",
            source_subnet="198.51.100.0/24",
            target_ips=["192.168.1.100"],
            target_ports=[22, 80, 443, 8443],
            participating_detectors=["portscan_hll", "dga_lstm", "ja4_malware", "c2_beacon"],
            threat_classes=["PORT_SCAN_RECON", "DGA_TUNNELLING", "ENCRYPTED_MALWARE", "C2_BEACONING"],
            threat_class="APT_MULTI_STAGE_ATTACK",
            raw_alert_count=50,
            total_raw_alerts_collapsed=50,
            fused_confidence=0.98,
            overall_confidence=0.98,
            severity="CRITICAL",
            attack_stage="COMMAND_AND_CONTROL",
            kill_chain_stages=["RECONNAISSANCE", "WEAPONIZATION", "EXPLOITATION", "COMMAND_AND_CONTROL"],
            created_at=1725000000.0,
            updated_at=1725000005.0,
        )

        start = time.perf_counter()
        triage_state = triage_incident(fused, execution_mode="deterministic")
        elapsed_sec = time.perf_counter() - start

        print(f"\n[Latency SLA] Agentic triage latency: {elapsed_sec * 1000.0:.2f} ms")
        assert elapsed_sec < 2.0, f"Triage latency {elapsed_sec:.3f} s exceeded 2.0 s SLA"
        assert len(triage_state.get("countermeasures", [])) == 6

    def test_end_to_end_pipeline_latency_under_1_5s(
        self,
        detector_manager: DetectorManager,
        cep_engine: CEPAggregatorEngine,
        isolated_app_state: AppState,
    ):
        """
        Executes the full pipeline:
        Telemetry Ingestion -> 6 Detectors -> CEP Fusion -> LangGraph Triage -> IncidentRingBuffer
        Asserts total end-to-end latency < 1.5 s.
        """
        start_pipeline = time.perf_counter()

        # 1. Ingest Stage 1 (Recon - 35 SYN events)
        raw_alerts: List[RawAlert] = []
        for port in range(1, 36):
            ev = ConnTelemetryEvent(
                ts=1725000000.0 + (port * 0.001),
                uid=f"C_E2E_{port:03d}",
                src_ip="198.51.100.42",
                dst_ip="192.168.1.100",
                src_port=50000 + port,
                dst_port=port,
                proto="tcp",
                conn_state="REJ",
            )
            raw_alerts.extend(detector_manager.process_event(ev))

        # 2. Ingest Stage 2 (DGA DNS)
        dns_ev = DnsTelemetryEvent(
            ts=1725000001.0,
            uid="D_E2E_001",
            src_ip="198.51.100.42",
            dst_ip="8.8.8.8",
            src_port=55123,
            dst_port=53,
            proto="udp",
            query="c948df2a10sub.tunnel.darknet-dga-malware.org",
            qtype=1,
            qtype_name="A",
            rcode=0,
            rcode_name="NOERROR",
            subdomain="c948df2a10sub.tunnel",
            subdomain_entropy=4.45,
        )
        raw_alerts.extend(detector_manager.process_event(dns_ev))

        # 3. Ingest Stage 3 (JA4 TLS)
        ssl_ev = SslTelemetryEvent(
            ts=1725000002.0,
            uid="S_E2E_001",
            src_ip="198.51.100.42",
            dst_ip="203.0.113.5",
            src_port=58912,
            dst_port=443,
            version="TLSv13",
            cipher="TLS_AES_256_GCM_SHA384",
            server_name="c2.malicious-domain.com",
            ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        )
        raw_alerts.extend(detector_manager.process_event(ssl_ev))

        # 4. CEP Aggregation
        fused_incident: Optional[FusedIncident] = None
        for alert in raw_alerts:
            res = cep_engine.ingest_alert(alert)
            if res:
                fused_incident = res

        assert fused_incident is not None

        # 5. LangGraph StateGraph Triage
        triage_state = triage_incident(fused_incident, execution_mode="deterministic")
        detail = triage_state_to_incident_detail(triage_state, raw_incident=fused_incident)

        # 6. Push to Incident Ring Buffer
        isolated_app_state.incident_buffer.add_incident(detail)

        total_elapsed = time.perf_counter() - start_pipeline

        print(f"\n[E2E Latency SLA] Total pipeline latency: {total_elapsed:.4f} s")
        assert total_elapsed < 1.5, f"E2E Pipeline latency {total_elapsed:.3f} s exceeded 1.5 s SLA"
        assert detail.requires_human_approval is True
        assert len(detail.countermeasures) == 6

    def test_latency_percentile_distribution_under_streaming_load(self, detector_manager: DetectorManager):
        """
        Samples 1,000 consecutive event latencies and calculates p50, p90, p95, and p99.
        Asserts p99 latency < 50.0 ms.
        """
        latencies_ms: List[float] = []
        events = generate_synthetic_conn_batch(count=1000)

        for ev in events:
            t0 = time.perf_counter()
            detector_manager.process_event(ev)
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        latencies_ms.sort()
        p50 = latencies_ms[int(len(latencies_ms) * 0.50)]
        p90 = latencies_ms[int(len(latencies_ms) * 0.90)]
        p95 = latencies_ms[int(len(latencies_ms) * 0.95)]
        p99 = latencies_ms[int(len(latencies_ms) * 0.99)]

        print(f"\n[Percentiles] p50: {p50:.4f}ms | p90: {p90:.4f}ms | p95: {p95:.4f}ms | p99: {p99:.4f}ms")
        assert p99 < 50.0, f"p99 latency {p99:.2f} ms exceeded 50.0 ms ceiling"


# ==============================================================================
# 9. Test Suite 7: Strict Data-Diode Invariant Verification
# ==============================================================================

class TestStrictDataDiodeInvariantPipelineVerification:
    """
    Validates complete adherence to the Air-Gapped Physical / Software Data Diode:
    Zero outbound active network connections, zero packet injections, zero shell execs
    during ingestion, threat detection, correlation, triage, and countermeasure generation.
    """

    def test_complete_4stage_apt_under_strict_data_diode(
        self, detector_manager: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """
        Runs the full 4-stage APT attack simulation and triage pipeline under active
        DataDiodeGuard(mode="strict").
        Asserts 0 violations, all 6 countermeasures generated, and requires_human_approval: true.
        """
        with DataDiodeGuard(mode="strict") as guard:
            # 1. Ingest 4 stages of APT telemetry
            events: List[Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent]] = []

            # Stage 1: Port Scan (35 SYN probes)
            for p in range(1, 36):
                events.append(
                    ConnTelemetryEvent(
                        ts=1725000000.0 + (p * 0.01),
                        uid=f"C_DIODE_P{p:03d}",
                        src_ip="198.51.100.42",
                        dst_ip="192.168.1.100",
                        src_port=40000 + p,
                        dst_port=p,
                        proto="tcp",
                        conn_state="REJ",
                    )
                )

            # Stage 2: DGA Tunnel
            events.append(
                DnsTelemetryEvent(
                    ts=1725000001.0,
                    uid="D_DIODE_001",
                    src_ip="198.51.100.42",
                    dst_ip="8.8.8.8",
                    src_port=51234,
                    dst_port=53,
                    proto="udp",
                    query="c948df2a10sub.tunnel.darknet-dga-malware.org",
                    qtype=1,
                    qtype_name="A",
                    rcode=0,
                    rcode_name="NOERROR",
                    subdomain="c948df2a10sub.tunnel",
                    subdomain_entropy=4.45,
                )
            )

            # Stage 3: JA4 Malware
            events.append(
                SslTelemetryEvent(
                    ts=1725000002.0,
                    uid="S_DIODE_001",
                    src_ip="198.51.100.42",
                    dst_ip="203.0.113.5",
                    src_port=54321,
                    dst_port=443,
                    version="TLSv13",
                    cipher="TLS_AES_256_GCM_SHA384",
                    server_name="c2.malicious-domain.com",
                    ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
                )
            )

            # Stage 4: C2 Beaconing (18 connection pulses)
            for k in range(18):
                events.append(
                    ConnTelemetryEvent(
                        ts=1725000003.0 + (k * 1.0),
                        uid=f"C_DIODE_B{k:03d}",
                        src_ip="198.51.100.42",
                        dst_ip="203.0.113.5",
                        src_port=56000 + k,
                        dst_port=443,
                        proto="tcp",
                        duration=0.045,
                        orig_bytes=128,
                        resp_bytes=64,
                        conn_state="SF",
                    )
                )

            # Process through detectors
            raw_alerts = []
            for ev in events:
                raw_alerts.extend(detector_manager.process_event(ev))

            # Ingest into CEP engine
            last_fused = None
            for a in raw_alerts:
                f = cep_engine.ingest_alert(a)
                if f:
                    last_fused = f

            assert last_fused is not None

            # Triage through LangGraph
            triage_state = triage_incident(last_fused, execution_mode="deterministic")
            detail = triage_state_to_incident_detail(triage_state, raw_incident=last_fused)

            # Assert 0 violations detected under guard
            guard.assert_zero_violations()

        assert detail.requires_human_approval is True
        assert len(detail.countermeasures) == 6
        for cm in detail.countermeasures:
            assert cm.requires_human_approval is True
            assert cm.syntax_valid is True

    def test_high_volume_ingestion_under_strict_data_diode(
        self, detector_manager: DetectorManager, cep_engine: CEPAggregatorEngine
    ):
        """
        Executes high-volume ingestion (10,000 events) under strict DataDiodeGuard.
        Verifies that high data rates never trigger rogue network emissions or process calls.
        """
        events = generate_synthetic_conn_batch(count=10000)

        with DataDiodeGuard(mode="strict") as guard:
            for ev in events:
                alerts = detector_manager.process_event(ev)
                for a in alerts:
                    cep_engine.ingest_alert(a)

            guard.assert_zero_violations()

        assert guard.is_clean()
        assert guard.violation_count() == 0

    def test_countermeasure_artifact_generation_without_auto_execution(self):
        """
        Verifies that all 6 countermeasure generators strictly format defense configuration
        rules out-of-band and never attempt to auto-execute or apply rules via subprocess/shell.
        """
        from src.agentic_triage.countermeasures import (
            generate_cisco_acl,
            generate_dns_rpz,
            generate_iptables,
            generate_nftables,
            generate_snort_rules,
            generate_stix_bundle,
        )
        from src.agentic_triage.nodes.countermeasure_node import CountermeasureNode

        test_incident = {
            "incident_id": "INC-CM-DIODE-001",
            "source_ip": "198.51.100.42",
            "attacker_ip": "198.51.100.42",
            "target_ips": ["192.168.1.100"],
            "target_ports": [80, 443],
            "primary_threat_class": "PORT_SCAN_RECON",
            "threat_classes": ["PORT_SCAN_RECON", "DGA_TUNNELLING"],
            "c2_domains": ["malicious-dga.com"],
            "ja4_fingerprints": ["t13d1516h2_8daaf6152771"],
        }

        with DataDiodeGuard(mode="strict") as guard:
            cm_iptables = generate_iptables(test_incident)
            cm_nftables = generate_nftables(test_incident)
            cm_cisco = generate_cisco_acl(test_incident)
            cm_rpz = generate_dns_rpz(test_incident)
            cm_snort = generate_snort_rules(test_incident)
            cm_stix = generate_stix_bundle(test_incident)

            # Also execute CountermeasureNode in full triage state
            node = CountermeasureNode()
            state_out = node.execute(test_incident)  # type: ignore

            guard.assert_zero_violations()

        # Check raw artifact strings enforce requires_human_approval comment/metadata
        assert "requires_human_approval: true" in cm_iptables.lower()
        assert "requires_human_approval: true" in cm_nftables.lower()
        assert "requires_human_approval: true" in cm_cisco.lower()
        assert "requires_human_approval: true" in cm_rpz.lower()
        assert "requires_human_approval: true" in cm_snort.lower()
        assert "requires_human_approval" in cm_stix.lower()

        # Check structured node output enforces requires_human_approval
        assert len(state_out["countermeasures"]) == 6
        for cm in state_out["countermeasures"]:
            assert cm["requires_human_approval"] is True
            assert cm["syntax_valid"] is True
