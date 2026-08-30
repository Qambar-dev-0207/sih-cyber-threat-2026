"""
SIH26145 - Pipeline Performance Metrics Calculator
Computes sustained EPS, line-rate throughput (Mbps), latency percentiles, and loss metrics.
"""

import time
import math
from typing import List, Dict, Any, Optional


class MetricsCalculator:
    """
    Calculates quantifiable streaming metrics for benchmarking and monitoring.
    """

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Reset all counters and latency buffers."""
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.total_events: int = 0
        self.total_bytes: int = 0
        self.total_packets_sent: int = 0
        self.total_packets_received: int = 0
        self.latencies_ms: List[float] = []

    def start(self) -> None:
        """Record start time."""
        self.start_time = time.perf_counter()

    def stop(self) -> None:
        """Record stop time."""
        self.end_time = time.perf_counter()

    def record_event(self, byte_size: int = 0, latency_ms: Optional[float] = None) -> None:
        """Record a single processed telemetry event."""
        self.total_events += 1
        self.total_bytes += byte_size
        if latency_ms is not None and latency_ms >= 0:
            self.latencies_ms.append(latency_ms)

    def record_batch(self, count: int, total_bytes: int = 0, latencies: Optional[List[float]] = None) -> None:
        """Record a batch of processed telemetry events."""
        self.total_events += count
        self.total_bytes += total_bytes
        if latencies:
            self.latencies_ms.extend([lat for lat in latencies if lat >= 0])

    def set_packet_counts(self, sent: int, received: int) -> None:
        """Set raw packet transmission counters for packet loss rate computation."""
        self.total_packets_sent = sent
        self.total_packets_received = received

    def calculate_percentiles(self, sample_window: Optional[int] = None) -> Dict[str, float]:
        """Compute latency percentiles (p50, p90, p95, p99, min, max, avg)."""
        if not self.latencies_ms:
            return {
                "p50_ms": 0.0,
                "p90_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "avg_ms": 0.0,
            }

        latencies = self.latencies_ms
        if sample_window is not None and sample_window > 0:
            latencies = self.latencies_ms[-sample_window:]

        if not latencies:
            return {
                "p50_ms": 0.0,
                "p90_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "avg_ms": 0.0,
            }

        sorted_lat = sorted(latencies)
        n = len(sorted_lat)

        def percentile(p: float) -> float:
            idx = int(math.ceil((p / 100.0) * n)) - 1
            idx = max(0, min(idx, n - 1))
            return sorted_lat[idx]

        return {
            "p50_ms": round(percentile(50), 3),
            "p90_ms": round(percentile(90), 3),
            "p95_ms": round(percentile(95), 3),
            "p99_ms": round(percentile(99), 3),
            "min_ms": round(sorted_lat[0], 3),
            "max_ms": round(sorted_lat[-1], 3),
            "avg_ms": round(sum(sorted_lat) / n, 3),
        }

    def summary(self) -> Dict[str, Any]:
        """Generate comprehensive metrics summary dictionary."""
        t_start = self.start_time or time.perf_counter()
        t_end = self.end_time or time.perf_counter()
        duration = max(t_end - t_start, 0.001)

        eps = self.total_events / duration
        mbps = (self.total_bytes * 8) / (duration * 1_000_000)

        # Calculate packet loss rate
        loss_rate = 0.0
        if self.total_packets_sent > 0:
            lost = max(0, self.total_packets_sent - self.total_packets_received)
            loss_rate = (lost / self.total_packets_sent) * 100.0

        percentiles = self.calculate_percentiles()

        return {
            "duration_sec": round(duration, 3),
            "total_events": self.total_events,
            "total_bytes": self.total_bytes,
            "sustained_eps": round(eps, 2),
            "throughput_mbps": round(mbps, 3),
            "packets_sent": self.total_packets_sent,
            "packets_received": self.total_packets_received,
            "packet_loss_rate_pct": round(loss_rate, 3),
            **percentiles,
        }

    def format_markdown_table(self) -> str:
        """Format metrics summary as a markdown table suitable for benchmark_results.md."""
        s = self.summary()
        return (
            "| Metric | Value | Unit |\n"
            "|---|---|---|\n"
            f"| Sustained Events-Per-Second (EPS) | {s['sustained_eps']:,} | events/sec |\n"
            f"| Throughput Line Rate | {s['throughput_mbps']:.2f} | Mbps |\n"
            f"| Ingest Latency (p50) | {s['p50_ms']:.3f} | ms |\n"
            f"| Ingest Latency (p90) | {s['p90_ms']:.3f} | ms |\n"
            f"| Ingest Latency (p95) | {s['p95_ms']:.3f} | ms |\n"
            f"| Ingest Latency (p99) | {s['p99_ms']:.3f} | ms |\n"
            f"| Total Events Processed | {s['total_events']:,} | records |\n"
            f"| Benchmark Run Duration | {s['duration_sec']:.2f} | seconds |\n"
            f"| Packet Loss Rate | {s['packet_loss_rate_pct']:.2f}% | % |\n"
        )
