#!/usr/bin/env python3
"""
scripts/run_30s_benchmark.py
Executes the full standard 30-second Day-1 Line-Rate Ingestion Throughput Benchmark.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.throughput_benchmark import ThroughputBenchmarkOrchestrator

if __name__ == "__main__":
    print("=================================================================")
    print("  SIH26145 - Launching 30-Second Line-Rate Benchmark Run...")
    print("=================================================================")
    orchestrator = ThroughputBenchmarkOrchestrator(
        duration_sec=30.0,
        target_pps=15000,
        pcap_path="data/pcaps/benign_baseline.pcap",
        topic="telemetry.conn",
        output_report="benchmark_results.md",
        quiet=False,
    )
    result = orchestrator.run_benchmark()
    print("=================================================================")
    print("  Benchmark Run Complete!")
    print("=================================================================")
