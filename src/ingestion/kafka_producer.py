"""
SIH26145 - High-Throughput Kafka / Redpanda Producer
Streams parsed Zeek JSON telemetry to partitioned topics with host-affinity routing.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Union
from pydantic import BaseModel

from .models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
    RawAlert,
)
from .streaming_bus import (
    InMemoryStreamingBus,
    get_source_ip_partition,
    extract_record_source_ip,
    serialize_record,
)

logger = logging.getLogger("kafka_producer")


def calculate_partition_key(record: Union[Dict[str, Any], BaseModel, str]) -> str:
    """
    Computes host-affinity partition key from a record.
    Extracts 'id.orig_h', 'orig_h', 'source_ip', or 'src_ip'.
    """
    return extract_record_source_ip(record)


class TelemetryKafkaProducer:
    """
    Kafka/Redpanda producer tuned for line-rate (>50,000 EPS) network telemetry publishing.
    Features deterministic host-affinity source IP partitioning and offline in-memory fallback.
    """

    TOPIC_MAPPING = {
        "conn": "telemetry.conn",
        "dns": "telemetry.dns",
        "ssl": "telemetry.ssl",
        "alert": "alerts.raw",
        "alerts": "alerts.raw",
        "incident": "incidents.fused",
        "incidents": "incidents.fused",
    }

    def __init__(
        self,
        bootstrap_servers: str = "localhost:19092",
        client_id: str = "sih_telemetry_shipper",
        batch_size: int = 16384,
        linger_ms: int = 5,
        compression_type: Optional[str] = None,
        max_in_flight_requests: int = 5,
        num_partitions: int = 4,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self.batch_size = batch_size
        self.linger_ms = linger_ms
        self.compression_type = compression_type
        self.max_in_flight_requests = max_in_flight_requests
        self.num_partitions = num_partitions

        self._producer = None
        self._is_connected = False
        self._sent_count = 0
        self._error_count = 0
        self._driver = "mock"
        self._in_memory_bus = InMemoryStreamingBus(num_partitions=self.num_partitions)
        self._init_producer()

    def _init_producer(self) -> None:
        """Initialize underlying Kafka client (confluent-kafka or kafka-python with fallback)."""
        try:
            # Try confluent-kafka first
            import confluent_kafka

            conf = {
                "bootstrap.servers": self.bootstrap_servers,
                "client.id": self.client_id,
                "queue.buffering.max.messages": 100000,
                "queue.buffering.max.ms": self.linger_ms,
                "batch.num.messages": self.batch_size,
                "acks": "1",
            }
            if self.compression_type:
                conf["compression.type"] = self.compression_type
            self._producer = confluent_kafka.Producer(conf)
            self._driver = "confluent_kafka"
            self._is_connected = True
            logger.info(f"Initialized confluent_kafka Producer connected to {self.bootstrap_servers}")
            return
        except ImportError:
            pass

        try:
            # Try kafka-python
            from kafka import KafkaProducer

            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers.split(","),
                client_id=self.client_id,
                batch_size=self.batch_size,
                linger_ms=self.linger_ms,
                compression_type=self.compression_type,
                max_in_flight_requests_per_connection=self.max_in_flight_requests,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks=1,
            )
            self._driver = "kafka_python"
            self._is_connected = True
            logger.info(f"Initialized kafka-python Producer connected to {self.bootstrap_servers}")
            return
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Kafka broker connection failed ({e}). Falling back to mock/in-memory mode.")

        logger.info("Running Kafka Producer in in-memory / mock mode.")
        self._driver = "mock"
        self._is_connected = False

    def send_record(
        self,
        record_type: str,
        record: Union[BaseModel, Dict[str, Any], str],
        topic: Optional[str] = None,
        key: Optional[str] = None,
        callback: Optional[Callable] = None,
        partition: Optional[int] = None,
    ) -> bool:
        """
        Publish a single telemetry or alert record to the appropriate Kafka/Redpanda topic.
        """
        target_topic = topic or self.TOPIC_MAPPING.get(record_type.lower(), f"telemetry.{record_type}")
        partition_key = key if key is not None else calculate_partition_key(record)
        data = serialize_record(record)

        # Attach ingestion timestamp if not already present
        if "ingest_ts" not in data:
            data["ingest_ts"] = time.time()

        # Compute partition ID if not explicitly specified
        target_partition = partition if partition is not None else get_source_ip_partition(partition_key, self.num_partitions)

        try:
            if self._driver == "confluent_kafka" and self._producer:
                val_bytes = json.dumps(data).encode("utf-8")
                key_bytes = partition_key.encode("utf-8")
                self._producer.produce(
                    topic=target_topic,
                    key=key_bytes,
                    value=val_bytes,
                    partition=target_partition,
                    on_delivery=callback,
                )
                self._producer.poll(0)
                self._sent_count += 1
                return True

            elif self._driver == "kafka_python" and self._producer:
                future = self._producer.send(
                    target_topic,
                    key=partition_key,
                    value=data,
                    partition=target_partition,
                )
                if callback:
                    future.add_callback(callback)
                self._sent_count += 1
                return True

            else:
                # In-memory / Mock mode
                self._in_memory_bus.publish(
                    topic=target_topic,
                    message=data,
                    key=partition_key,
                    partition=target_partition,
                )
                self._sent_count += 1
                if callback:
                    try:
                        callback(None, {"topic": target_topic, "partition": target_partition, "key": partition_key})
                    except Exception:
                        pass
                return True

        except Exception as e:
            self._error_count += 1
            logger.error(f"Failed to publish record to {target_topic}: {e}")
            # Fallback to in-memory bus on error
            try:
                self._in_memory_bus.publish(
                    topic=target_topic,
                    message=data,
                    key=partition_key,
                    partition=target_partition,
                )
            except Exception:
                pass
            return False

    def send_batch(
        self,
        record_type: str,
        records: List[Union[BaseModel, Dict[str, Any], str]],
        topic: Optional[str] = None,
    ) -> int:
        """
        Publish a batch of records. Returns count of successfully queued records.
        """
        success_count = 0
        for rec in records:
            if self.send_record(record_type=record_type, record=rec, topic=topic):
                success_count += 1
        return success_count

    def send_alert(self, alert: Union[RawAlert, Dict[str, Any]]) -> bool:
        """Convenience method for sending a threat detector alert to alerts.raw."""
        return self.send_record(record_type="alert", record=alert, topic="alerts.raw")

    def flush(self, timeout: float = 5.0) -> None:
        """Flush internal buffers ensuring all queued messages are delivered."""
        if self._driver == "confluent_kafka" and self._producer:
            self._producer.flush(timeout)
        elif self._driver == "kafka_python" and self._producer:
            self._producer.flush(timeout=timeout)
        self._in_memory_bus.flush(timeout=timeout)

    def close(self) -> None:
        """Close producer connection."""
        self.flush()
        if self._driver == "kafka_python" and self._producer:
            self._producer.close()
        self._in_memory_bus.close()

    @property
    def in_memory_bus(self) -> InMemoryStreamingBus:
        """Access underlying in-memory bus for offline testing and verification."""
        return self._in_memory_bus

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return basic transmission metrics."""
        return {
            "sent_count": self._sent_count,
            "error_count": self._error_count,
            "driver": self._driver,
            "connected": self._is_connected,
            "in_memory_metrics": self._in_memory_bus.get_metrics(),
        }
