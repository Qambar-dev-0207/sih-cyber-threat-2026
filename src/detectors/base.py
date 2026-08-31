"""
SIH26145 - Base Threat Detector Framework
Abstract Base Class for lock-free streaming threat detectors.
Provides standardized streaming ingestion, alert publishing to 'alerts.raw',
TTL / LRU host state eviction, and line-rate execution metrics.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Type, Union
from pydantic import BaseModel

from ..ingestion.models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
    RawAlert,
)
from ..ingestion.streaming_bus import (
    InMemoryStreamingBus,
    StreamingBus,
    get_streaming_bus,
    extract_record_source_ip,
)
from ..ingestion.kafka_producer import TelemetryKafkaProducer

logger = logging.getLogger("detectors.base")


class BaseDetector(ABC):
    """
    Abstract base class for streaming network threat detection workers.
    Features:
    - Lock-free, per-host stateful locality (partitioned by Murmur3(src_ip) % 4).
    - Dual ingestion support: push (`handle_event()`) and pull (`consume_and_process()`).
    - Standardized alert publication to topic 'alerts.raw'.
    - Time-to-Live (TTL) state eviction to maintain bounded O(1) memory per partition.
    - Microsecond-level latency and throughput metrics tracking.
    """

    def __init__(
        self,
        detector_id: str,
        input_topic: str = "telemetry.conn",
        output_topic: str = "alerts.raw",
        bus: Optional[StreamingBus] = None,
        producer: Optional[TelemetryKafkaProducer] = None,
        state_ttl_sec: float = 300.0,
        max_tracked_hosts: int = 100_000,
        enable_metrics: bool = True,
    ):
        self.detector_id = detector_id
        self.input_topic = input_topic
        self.output_topic = output_topic
        self.state_ttl_sec = state_ttl_sec
        self.max_tracked_hosts = max_tracked_hosts
        self.enable_metrics = enable_metrics

        # Streaming bus / Kafka producer configuration
        if bus is not None:
            self.bus: StreamingBus = bus
        elif producer is not None:
            self.bus = producer.in_memory_bus
        else:
            self.bus = InMemoryStreamingBus(num_partitions=4)

        self.producer = producer
        self._last_eviction_ts = time.time()
        self._eviction_interval_sec = 30.0

        # Operational metrics counters
        self._processed_events: int = 0
        self._dispatched_alerts: int = 0
        self._processing_errors: int = 0
        self._total_processing_time_ns: int = 0
        self._metrics_lock = threading.Lock()

        # Host state mapping and access timestamps for TTL eviction
        # Subclasses can maintain specific host state objects in their own dictionaries,
        # but can register them with the base class or manage them directly.
        self._host_last_seen: Dict[str, float] = {}

    @abstractmethod
    def process_event(
        self,
        event: Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any]],
    ) -> Optional[RawAlert]:
        """
        Core detection logic evaluated on a single streaming event.
        Must execute with sub-millisecond latency and zero inter-process locking.
        Returns a RawAlert instance if an anomaly/threat is detected, else None.
        """
        pass

    @abstractmethod
    def reset_state(self) -> None:
        """Clear all internal host state caches and metrics."""
        pass

    def update_host_liveness(self, host_ip: str, current_ts: Optional[float] = None) -> None:
        """Record the latest observation timestamp for a host for TTL management."""
        ts = current_ts if current_ts is not None else time.time()
        self._host_last_seen[host_ip] = ts

    def evict_expired_states(self, current_ts: Optional[float] = None) -> int:
        """
        Evict inactive host states older than state_ttl_sec.
        Can be overridden by subclasses to prune their specific state tables.
        Returns the count of evicted hosts.
        """
        now = current_ts if current_ts is not None else time.time()
        cutoff = now - self.state_ttl_sec

        expired_hosts = [
            host for host, last_seen in self._host_last_seen.items() if last_seen < cutoff
        ]

        # If cache exceeds maximum capacity, evict oldest entries
        if len(self._host_last_seen) - len(expired_hosts) > self.max_tracked_hosts:
            sorted_hosts = sorted(self._host_last_seen.items(), key=lambda x: x[1])
            excess = len(self._host_last_seen) - self.max_tracked_hosts
            for h, _ in sorted_hosts[:excess]:
                if h not in expired_hosts:
                    expired_hosts.append(h)

        for host in expired_hosts:
            self._host_last_seen.pop(host, None)
            self._on_host_evicted(host)

        self._last_eviction_ts = now
        return len(expired_hosts)

    def _on_host_evicted(self, host: str) -> None:
        """Hook called when a host state is evicted. Subclasses should override to free host state."""
        pass

    def check_eviction_trigger(self, current_ts: Optional[float] = None) -> None:
        """Periodically invoke TTL eviction."""
        now = current_ts if current_ts is not None else time.time()
        if (now - self._last_eviction_ts >= self._eviction_interval_sec) or (
            len(self._host_last_seen) > self.max_tracked_hosts
        ):
            self.evict_expired_states(now)

    def handle_event(
        self,
        event: Union[ConnTelemetryEvent, DnsTelemetryEvent, SslTelemetryEvent, Dict[str, Any], str],
    ) -> Optional[RawAlert]:
        """
        Push-based entrypoint: Normalizes the event, executes process_event(),
        automatically dispatches any generated RawAlert to 'alerts.raw', and tracks metrics.
        """
        t0 = time.perf_counter_ns()
        try:
            # Periodic state cleanup
            self.check_eviction_trigger()

            alert = self.process_event(event)
            if alert is not None:
                self.dispatch_alert(alert)

            t_elapsed_ns = time.perf_counter_ns() - t0
            if self.enable_metrics:
                with self._metrics_lock:
                    self._processed_events += 1
                    self._total_processing_time_ns += t_elapsed_ns

            return alert

        except Exception as e:
            logger.error(f"Detector {self.detector_id} error processing event: {e}", exc_info=True)
            with self._metrics_lock:
                self._processing_errors += 1
            return None

    def dispatch_alert(self, alert: Union[RawAlert, Dict[str, Any]]) -> bool:
        """
        Publishes a normalized RawAlert to topic 'alerts.raw'.
        """
        try:
            if isinstance(alert, dict):
                alert_obj = RawAlert.model_validate(alert)
            else:
                alert_obj = alert

            # Publish to producer or streaming bus
            if self.producer is not None:
                success = self.producer.send_alert(alert_obj)
            else:
                success = self.bus.publish(
                    topic=self.output_topic,
                    message=alert_obj,
                    key=alert_obj.source_ip,
                )

            if success:
                with self._metrics_lock:
                    self._dispatched_alerts += 1
            return success
        except Exception as e:
            logger.error(f"Detector {self.detector_id} failed to dispatch alert: {e}")
            with self._metrics_lock:
                self._processing_errors += 1
            return False

    def consume_and_process(
        self,
        partition: int = 0,
        max_records: int = 100,
        timeout: float = 0.0,
    ) -> List[RawAlert]:
        """
        Pull-based batch processing: Consumes records from input_topic partition
        and evaluates each event sequentially.
        """
        records = self.bus.consume(
            topic=self.input_topic,
            partition=partition,
            max_records=max_records,
            timeout=timeout,
        )
        alerts: List[RawAlert] = []
        for rec in records:
            alert = self.handle_event(rec)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational metrics for monitoring and benchmarking."""
        with self._metrics_lock:
            avg_latency_us = (
                (self._total_processing_time_ns / max(1, self._processed_events)) / 1_000.0
                if self._processed_events > 0
                else 0.0
            )
            return {
                "detector_id": self.detector_id,
                "processed_events": self._processed_events,
                "dispatched_alerts": self._dispatched_alerts,
                "processing_errors": self._processing_errors,
                "active_hosts_tracked": len(self._host_last_seen),
                "avg_processing_latency_us": round(avg_latency_us, 3),
            }
