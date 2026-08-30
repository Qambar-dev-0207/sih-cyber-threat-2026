"""
SIH26145 - High-Throughput Kafka / Redpanda Producer
Streams parsed Zeek JSON telemetry to partitioned topics with host-affinity routing.
"""

import json
import zlib
import time
import logging
from typing import Dict, Any, Optional, List, Callable

logger = logging.getLogger("kafka_producer")


def calculate_partition_key(record: Dict[str, Any]) -> str:
    """
    Computes host-affinity partition key from record.
    Uses 'id.orig_h' or 'orig_h' or 'source_ip' or 'src_ip'.
    """
    source_ip = (
        record.get("id.orig_h")
        or record.get("orig_h")
        or record.get("source_ip")
        or record.get("src_ip")
        or "0.0.0.0"
    )
    return str(source_ip)


class TelemetryKafkaProducer:
    """
    Kafka/Redpanda producer tuned for line-rate (>50,000 EPS) network telemetry publishing.
    """

    TOPIC_MAPPING = {
        "conn": "telemetry.conn",
        "dns": "telemetry.dns",
        "ssl": "telemetry.ssl",
        "alert": "alerts.raw",
        "incident": "incidents.fused",
    }

    def __init__(
        self,
        bootstrap_servers: str = "localhost:19092",
        client_id: str = "sih_telemetry_shipper",
        batch_size: int = 16384,
        linger_ms: int = 5,
        compression_type: Optional[str] = None,
        max_in_flight_requests: int = 5,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.client_id = client_id
        self.batch_size = batch_size
        self.linger_ms = linger_ms
        self.compression_type = compression_type
        self.max_in_flight_requests = max_in_flight_requests

        self._producer = None
        self._is_connected = False
        self._sent_count = 0
        self._error_count = 0
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
            logger.warning(f"Kafka broker connection failed ({e}). Falling back to mock/offline mode.")

        logger.warning(
            "Running Kafka Producer in mock/offline mode."
        )
        self._driver = "mock"
        self._is_connected = False

    def send_record(
        self,
        record_type: str,
        record: Dict[str, Any],
        topic: Optional[str] = None,
        key: Optional[str] = None,
        callback: Optional[Callable] = None,
    ) -> bool:
        """
        Publish a single telemetry or alert record to the appropriate Kafka/Redpanda topic.
        """
        target_topic = topic or self.TOPIC_MAPPING.get(record_type, f"telemetry.{record_type}")
        partition_key = key or calculate_partition_key(record)

        # Attach ingestion timestamp if not already present
        if "ingest_ts" not in record:
            record["ingest_ts"] = time.time()

        try:
            if self._driver == "confluent_kafka":
                val_bytes = json.dumps(record).encode("utf-8")
                key_bytes = partition_key.encode("utf-8")
                self._producer.produce(
                    topic=target_topic,
                    key=key_bytes,
                    value=val_bytes,
                    on_delivery=callback,
                )
                self._producer.poll(0)
                self._sent_count += 1
                return True

            elif self._driver == "kafka_python":
                future = self._producer.send(
                    target_topic,
                    key=partition_key,
                    value=record,
                )
                if callback:
                    future.add_callback(callback)
                self._sent_count += 1
                return True

            else:
                # Mock mode
                self._sent_count += 1
                return True

        except Exception as e:
            self._error_count += 1
            logger.error(f"Failed to publish record to {target_topic}: {e}")
            return False

    def send_batch(
        self,
        record_type: str,
        records: List[Dict[str, Any]],
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

    def flush(self, timeout: float = 5.0) -> None:
        """Flush internal buffers ensuring all queued messages are delivered."""
        if self._driver == "confluent_kafka" and self._producer:
            self._producer.flush(timeout)
        elif self._driver == "kafka_python" and self._producer:
            self._producer.flush(timeout=timeout)

    def close(self) -> None:
        """Close producer connection."""
        self.flush()
        if self._driver == "kafka_python" and self._producer:
            self._producer.close()

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return basic transmission metrics."""
        return {
            "sent_count": self._sent_count,
            "error_count": self._error_count,
            "driver": self._driver,
            "connected": self._is_connected,
        }
