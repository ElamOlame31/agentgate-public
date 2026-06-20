"""
Rolling-window latency statistics for authorization pipeline components.

Tracks per-stage timing (in milliseconds) across a bounded sliding window so
operators can query live p50/p95/p99 breakdowns via GET /metrics without
writing anything to disk. Zero external dependencies.

Typical components:
  "policy"        — NL policy engine hard-block check
  "injection"     — inline content injection scan
  "trust"         — full 4-D trust scoring (compute_trust)
  "kill_chain"    — kill-chain multi-step pattern analysis
  "purpose_drift" — purpose drift cross-session query
  "audit_write"   — audit log enqueue
  "total"         — end-to-end authorize handler

Usage:
    from core import latency

    with latency.measure("policy"):
        result = check_policies(...)

    stats = latency.get_stats("policy")
    # {"component": "policy", "count": 412, "p50_ms": 0.3, "p95_ms": 1.1, ...}
"""

import math
import threading
import time
from collections import deque
from contextlib import contextmanager

# Maximum samples retained per component. Old samples are evicted automatically
# (deque maxlen). 1000 is enough for stable percentile estimation while keeping
# memory under 8 KB per component (1000 × 8-byte float).
MAX_SAMPLES: int = 1000

_lock = threading.Lock()
_buckets: dict[str, deque] = {}


def record(component: str, duration_ms: float) -> None:
    """Append one timing observation for the named pipeline component."""
    with _lock:
        if component not in _buckets:
            _buckets[component] = deque(maxlen=MAX_SAMPLES)
        _buckets[component].append(duration_ms)


@contextmanager
def measure(component: str):
    """
    Context manager that times the enclosed block and records it.

        with latency.measure("trust"):
            breakdown, flags = compute_trust(...)
    """
    t0 = time.monotonic()
    try:
        yield
    finally:
        record(component, (time.monotonic() - t0) * 1000.0)


def _percentile(sorted_samples: list, pct: float) -> float:
    """Nearest-rank percentile on a pre-sorted list. Returns 0.0 for empty list."""
    n = len(sorted_samples)
    if n == 0:
        return 0.0
    # Nearest-rank: index = ceil(pct/100 * n) - 1, clamped to [0, n-1]
    idx = max(0, math.ceil(pct / 100.0 * n) - 1)
    return round(sorted_samples[min(idx, n - 1)], 3)


def get_stats(component: str) -> dict:
    """
    Return latency statistics for one pipeline component.

    Returns a dict with keys: component, count, p50_ms, p95_ms, p99_ms,
    mean_ms, max_ms.  When count == 0, percentile fields are 0.0.
    """
    with _lock:
        samples = list(_buckets.get(component, []))
    n = len(samples)
    if n == 0:
        return {
            "component": component,
            "count": 0,
            "p50_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "mean_ms": 0.0,
            "max_ms": 0.0,
        }
    sorted_s = sorted(samples)
    return {
        "component": component,
        "count": n,
        "p50_ms": _percentile(sorted_s, 50),
        "p95_ms": _percentile(sorted_s, 95),
        "p99_ms": _percentile(sorted_s, 99),
        "mean_ms": round(sum(sorted_s) / n, 3),
        "max_ms": round(sorted_s[-1], 3),
    }


def all_stats() -> list[dict]:
    """Return stats for every tracked component, sorted alphabetically by name."""
    with _lock:
        components = sorted(_buckets.keys())
    return [get_stats(c) for c in components]


def component_names() -> list[str]:
    """Return the names of all components that have at least one observation."""
    with _lock:
        return sorted(k for k, v in _buckets.items() if v)


def reset() -> None:
    """Clear all recorded samples. Intended for tests and server restart."""
    with _lock:
        _buckets.clear()
