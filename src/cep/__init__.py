from __future__ import annotations

"""
SIH26145 - Fast In-Memory Complex Event Processing (CEP) & Incident Fusion Module
Exports sliding window buffers, flow deduplication, burst rate limiting,
multi-detector signal fusion, and the main CEPAggregatorEngine.
"""

from src.cep.burst_limiter import TokenBucket, TokenBucketBurstLimiter
from src.cep.correlator import ConfidenceFuser, SignalCorrelator
from src.cep.deduplicator import AlertDeduplicator, generate_flow_fingerprint
from src.cep.engine import CEPAggregator, CEPAggregatorEngine
from src.cep.models import (
    AggregationBuffer,
    AlertStormSummary,
    AttackStage,
    DeduplicatedAlert,
    DeduplicationRecord,
    FusedIncident,
    IncidentTimelineEntry,
    SlidingWindowConfig,
    SubnetAggregation,
)
from src.cep.sliding_window import (
    HostSlidingWindow,
    SlidingWindowBuffer,
    SubnetSlidingWindow,
    extract_subnet,
)

__all__ = [
    #Attack Models
    'AttackStage',
    'DeduplicationRecord',
    'DeduplicatedAlert',
    'IncidentTimelineEntry',
    'SlidingWindowConfig',
    'SubnetAggregation',
    'AggregationBuffer',
    'AlertStormSummary',
    'FusedIncident',
    #Sliding Windows
    'extract_subnet',
    'HostSlidingWindow',
    'SubnetSlidingWindow',
    'SlidingWindowBuffer',
    #Deduplication
    'generate_flow_fingerprint',
    'AlertDeduplicator',
    #Burst Limiting
    'TokenBucket',
    'TokenBucketBurstLimiter',
    #Correlation & Fusion
    'ConfidenceFuser',
    'SignalCorrelator',
    #Engine
    'CEPAggregatorEngine',
    'CEPAggregator',
]
