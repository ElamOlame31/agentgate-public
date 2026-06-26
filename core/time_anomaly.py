"""
Time-of-day behavioral anomaly detector for autonomous agents.

Agents that consistently operate during certain hours of the day establish a
temporal behavioral profile. Requests that arrive significantly outside that
profile may indicate the agent has been compromised or is being replayed by an
attacker operating in a different time zone.

Unlike behavioral_contract.allowed_time_windows (an explicit registration-time
restriction), this detector *infers* anomalous timing from the agent's own
historical pattern — no pre-configuration is required.

This detector emits ESCALATE-tier flags, not hard DENYs. A request arriving at
an unusual hour is suspicious but not conclusive — legitimate causes include
maintenance windows, time-zone-spanning deployments, and on-call responses.
The flag routes the decision to human review.
"""

import datetime
import time as _time_module

# ── Tuning constants ───────────────────────────────────────────────────────────

# Minimum number of history entries required before the profile is meaningful.
# Fewer entries and the "active hours" could be an artifact of a small sample.
MIN_HISTORY_FOR_PROFILE: int = 20

# Rolling window (seconds) callers should use when fetching history for this
# detector. Exported so trust_engine.py and tests share the same value.
# 7 days captures a full weekly cycle, including weekend vs. weekday patterns.
BASELINE_WINDOW_SECONDS: float = float(7 * 86_400)

# Tolerance in hours around the established active window.  Prevents
# false-positives from minor scheduling drift (e.g., an agent that normally
# starts at 09:00 UTC but sometimes starts at 08:45 UTC).
HOUR_TOLERANCE: int = 1

# Fraction of the 24 hours that must be "dark" (no historical requests) for the
# temporal profile to be meaningful.  Agents that operate across most hours have
# no distinguishable temporal pattern and are not flagged.
# 0.25 → at least 6 of 24 hours must be consistently idle.
MIN_DARK_FRACTION: float = 0.25

# Flag namespace — kept in the BEHAVIORAL: scope used by the trust engine.
_FLAG_PREFIX: str = "BEHAVIORAL:AFTER_HOURS_ANOMALY"


# ── Internal helpers ───────────────────────────────────────────────────────────

def _utc_hour(timestamp: float) -> int:
    """Return the UTC hour (0–23) for a Unix timestamp. Stdlib only."""
    return datetime.datetime.fromtimestamp(
        timestamp, tz=datetime.timezone.utc
    ).hour


# ── Public API ─────────────────────────────────────────────────────────────────

def detect_time_anomaly(
    history: list[dict],
    current_timestamp: float | None = None,
) -> list[str]:
    """
    Return BEHAVIORAL:AFTER_HOURS_ANOMALY flags when *current_timestamp*
    falls outside the agent's established operating-hour profile.

    Parameters
    ----------
    history:
        List of request dicts, each containing at least a ``'timestamp'`` key
        (a Unix float). Should span BASELINE_WINDOW_SECONDS. Ordering does not
        matter. Entries with a missing or non-numeric timestamp are skipped.
    current_timestamp:
        Unix timestamp of the current request. Defaults to ``time.time()``.

    Returns
    -------
    A list containing at most one flag string, or an empty list.
    """
    if len(history) < MIN_HISTORY_FOR_PROFILE:
        return []

    now = current_timestamp if current_timestamp is not None else _time_module.time()
    current_hour = _utc_hour(now)

    # ── Build per-hour request count from history ─────────────────────────────
    hour_counts: list[int] = [0] * 24
    for entry in history:
        try:
            ts = float(entry["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
        hour_counts[_utc_hour(ts)] += 1

    # ── Check whether a meaningful temporal profile exists ────────────────────
    active_hours = [h for h in range(24) if hour_counts[h] > 0]
    if not active_hours:
        return []  # all timestamps were unparseable

    dark_fraction = (24 - len(active_hours)) / 24.0
    if dark_fraction < MIN_DARK_FRACTION:
        # Agent operates too broadly across the day to distinguish a pattern.
        return []

    # ── Check whether the current request is within the established window ────
    if hour_counts[current_hour] > 0:
        return []  # active hour — no anomaly

    # Apply tolerance: adjacent hours within ±HOUR_TOLERANCE are not flagged.
    for offset in range(1, HOUR_TOLERANCE + 1):
        if hour_counts[(current_hour - offset) % 24] > 0:
            return []
        if hour_counts[(current_hour + offset) % 24] > 0:
            return []

    # ── Anomaly: request is outside the established operating hours ───────────
    min_h = min(active_hours)
    max_h = max(active_hours)
    dark_count = 24 - len(active_hours)

    flag = (
        f"{_FLAG_PREFIX}"
        f":hour={current_hour:02d}UTC"
        f"|profile={min_h:02d}h-{max_h:02d}h_UTC"
        f"|dark_hours={dark_count}"
        f"|history_samples={len(history)}"
    )
    return [flag]
