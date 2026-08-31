"""
SIH26145 - Ingestion package for Zeek structured JSON logs and streaming producers.
"""

from .models import (
    ConnTelemetryEvent,
    DnsTelemetryEvent,
    SslTelemetryEvent,
    RawAlert,
    calculate_shannon_entropy,
    extract_subdomain,
)
from .zeek_log_tailer import (
    ZeekLogTailer,
    MultiZeekLogTailer,
    normalize_zeek_record,
)
from .kafka_producer import (
    TelemetryKafkaProducer,
    calculate_partition_key,
)
from .streaming_bus import (
    StreamingBus,
    InMemoryStreamingBus,
    KafkaStreamingBus,
    get_streaming_bus,
    get_source_ip_partition,
    extract_record_source_ip,
)

__all__ = [
    # Models
    "ConnTelemetryEvent",
    "DnsTelemetryEvent",
    "SslTelemetryEvent",
    "RawAlert",
    "calculate_shannon_entropy",
    "extract_subdomain",
    # Tailers
    "ZeekLogTailer",
    "MultiZeekLogTailer",
    "normalize_zeek_record",
    # Producers
    "TelemetryKafkaProducer",
    "calculate_partition_key",
    # Streaming Bus
    "StreamingBus",
    "InMemoryStreamingBus",
    "KafkaStreamingBus",
    "get_streaming_bus",
    "get_source_ip_partition",
    "extract_record_source_ip",
]
