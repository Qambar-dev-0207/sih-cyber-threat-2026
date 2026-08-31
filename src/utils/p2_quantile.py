"""
SIH26145 - P² (Piecewise-Parabolic) Streaming Quantile Estimation
Implements the P² algorithm by Jain & Chlamtac (1985) for dynamically calculating
quantiles (e.g. p50, p90, p95, p99) in O(1) time and O(1) space per observation.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple, Union


class P2QuantileEstimator:
    """
    P² (Piecewise-Parabolic) streaming quantile estimation for a single target quantile p in (0, 1).
    Maintains 5 marker positions and heights to track the quantile with O(1) update and O(1) query time.
    """

    def __init__(self, p: float = 0.95):
        if not (0.0 < p < 1.0):
            raise ValueError(f"Target quantile p must be strictly between 0.0 and 1.0, got {p}")
        self.p: float = float(p)
        self.count: int = 0
        # Marker heights q_1, q_2, q_3, q_4, q_5
        self.q: List[float] = [0.0] * 5
        # Actual marker positions n_1, n_2, n_3, n_4, n_5 (1-based)
        self.n: List[int] = [0] * 5
        # Desired marker positions n'_1, n'_2, n'_3, n'_4, n'_5
        self.n_prime: List[float] = [0.0] * 5
        # Increments for desired positions dn'_1, dn'_2, dn'_3, dn'_4, dn'_5
        self.dn_prime: List[float] = [0.0] * 5
        # Buffer for the first 5 samples before marker initialization
        self._initial_samples: List[float] = []

    def reset(self) -> None:
        """Reset the estimator to its initial state."""
        self.count = 0
        self.q = [0.0] * 5
        self.n = [0] * 5
        self.n_prime = [0.0] * 5
        self.dn_prime = [0.0] * 5
        self._initial_samples.clear()

    def add(self, x: Union[int, float]) -> None:
        """
        Incorporate a new observation x into the streaming quantile estimate in O(1) time.
        """
        val = float(x)
        if math.isnan(val) or math.isinf(val):
            return

        if self.count < 5:
            self._initial_samples.append(val)
            self.count += 1
            if self.count == 5:
                # Sort the first 5 observations to initialize marker heights
                self._initial_samples.sort()
                self.q = list(self._initial_samples)
                self.n = [1, 2, 3, 4, 5]
                self.n_prime = [
                    1.0,
                    1.0 + 2.0 * self.p,
                    1.0 + 4.0 * self.p,
                    3.0 + 2.0 * self.p,
                    5.0,
                ]
                self.dn_prime = [
                    0.0,
                    self.p / 2.0,
                    self.p,
                    (1.0 + self.p) / 2.0,
                    1.0,
                ]
            return

        # Sample count >= 5
        self.count += 1

        # 1. Find cell k such that q_k <= x < q_{k+1}
        if val < self.q[0]:
            self.q[0] = val
            k = 0
        elif val < self.q[1]:
            k = 0
        elif val < self.q[2]:
            k = 1
        elif val < self.q[3]:
            k = 2
        elif val < self.q[4]:
            k = 3
        else:
            self.q[4] = val
            k = 3

        # 2. Increment actual positions of markers k+1 through 4
        for i in range(k + 1, 5):
            self.n[i] += 1

        # 3. Update desired marker positions
        for i in range(5):
            self.n_prime[i] += self.dn_prime[i]

        # 4. Adjust marker heights for internal markers i = 1, 2, 3 (indices 1, 2, 3)
        for i in range(1, 4):
            d = self.n_prime[i] - self.n[i]
            if (d >= 1.0 and self.n[i + 1] - self.n[i] > 1) or (
                d <= -1.0 and self.n[i - 1] - self.n[i] < -1
            ):
                s = 1 if d > 0 else -1

                # Parabolic formula
                n_curr = self.n[i]
                n_prev = self.n[i - 1]
                n_next = self.n[i + 1]
                q_curr = self.q[i]
                q_prev = self.q[i - 1]
                q_next = self.q[i + 1]

                denom = n_next - n_prev
                if denom > 0:
                    term1 = ((n_curr - n_prev + s) * (q_next - q_curr)) / (n_next - n_curr)
                    term2 = ((n_next - n_curr - s) * (q_curr - q_prev)) / (n_curr - n_prev)
                    q_new = q_curr + (float(s) / denom) * (term1 + term2)
                else:
                    q_new = q_curr

                # Check if monotonic condition q_{i-1} < q_new < q_{i+1} holds
                if q_prev < q_new < q_next:
                    self.q[i] = q_new
                else:
                    # Linear step fallback
                    n_step = self.n[i + s]
                    q_step = self.q[i + s]
                    if n_step != n_curr:
                        self.q[i] = q_curr + s * ((q_step - q_curr) / (n_step - n_curr))

                self.n[i] += s

    def get(self) -> float:
        """
        Returns the current estimated quantile value.
        """
        if self.count == 0:
            return 0.0
        if self.count < 5:
            sorted_samples = sorted(self._initial_samples)
            idx = int(round(self.p * (len(sorted_samples) - 1)))
            return sorted_samples[max(0, min(idx, len(sorted_samples) - 1))]
        return float(self.q[2])

    @property
    def min_val(self) -> float:
        """Returns the minimum observed value."""
        if self.count == 0:
            return 0.0
        if self.count < 5:
            return min(self._initial_samples)
        return float(self.q[0])

    @property
    def max_val(self) -> float:
        """Returns the maximum observed value."""
        if self.count == 0:
            return 0.0
        if self.count < 5:
            return max(self._initial_samples)
        return float(self.q[4])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state for inspection or persistence."""
        return {
            "p": self.p,
            "count": self.count,
            "q": list(self.q),
            "n": list(self.n),
            "n_prime": list(self.n_prime),
            "estimate": self.get(),
            "min": self.min_val,
            "max": self.max_val,
        }


class MultiQuantileTracker:
    """
    Tracks multiple streaming quantiles (e.g. p50, p90, p95, p99) simultaneously for a single host/entity.
    Also tracks sample count, running mean, running variance, and min/max.
    """

    def __init__(self, quantiles: Optional[List[float]] = None):
        target_quantiles = quantiles or [0.50, 0.90, 0.95, 0.99]
        self.estimators: Dict[float, P2QuantileEstimator] = {
            q: P2QuantileEstimator(p=q) for q in target_quantiles
        }
        self.total_count: int = 0
        self.total_sum: float = 0.0
        self.running_mean: float = 0.0
        self.running_m2: float = 0.0  # Welford algorithm for running variance

    def reset(self) -> None:
        """Reset all tracked quantiles and statistics."""
        for est in self.estimators.values():
            est.reset()
        self.total_count = 0
        self.total_sum = 0.0
        self.running_mean = 0.0
        self.running_m2 = 0.0

    def add(self, x: Union[int, float]) -> None:
        """Add observation to all quantile estimators and update online statistics."""
        val = float(x)
        if math.isnan(val) or math.isinf(val):
            return

        self.total_count += 1
        self.total_sum += val

        # Welford online mean and variance update
        delta = val - self.running_mean
        self.running_mean += delta / self.total_count
        delta2 = val - self.running_mean
        self.running_m2 += delta * delta2

        for est in self.estimators.values():
            est.add(val)

    def get_quantile(self, p: float) -> float:
        """Get estimate for a specific quantile."""
        if p in self.estimators:
            return self.estimators[p].get()
        # Find closest available or return 0.0
        return 0.0

    @property
    def p50(self) -> float:
        return self.get_quantile(0.50)

    @property
    def p90(self) -> float:
        return self.get_quantile(0.90)

    @property
    def p95(self) -> float:
        return self.get_quantile(0.95)

    @property
    def p99(self) -> float:
        return self.get_quantile(0.99)

    @property
    def mean(self) -> float:
        return self.running_mean if self.total_count > 0 else 0.0

    @property
    def variance(self) -> float:
        if self.total_count < 2:
            return 0.0
        return self.running_m2 / (self.total_count - 1)

    @property
    def std_dev(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    def summary(self) -> Dict[str, Any]:
        """Summary of all tracked quantiles and online metrics."""
        return {
            "count": self.total_count,
            "mean": round(self.mean, 4),
            "std_dev": round(self.std_dev, 4),
            "p50": round(self.p50, 4),
            "p90": round(self.p90, 4),
            "p95": round(self.p95, 4),
            "p99": round(self.p99, 4),
        }
