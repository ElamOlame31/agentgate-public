"""
Kill chain detector — identifies multi-step attack patterns across a request sequence.

Each individual request may pass every single-request check cleanly.
This module examines the full sequence to catch patterns that only become
visible across multiple calls — reconnaissance → exfiltration, gradual
sensitivity escalation, read-then-destroy, and broad directory sweeps.

Flags are tiered:
  KILL_CHAIN:BULK_READ_THEN_*               hard DENY — bulk reads (5-min) before exfil/destroy
  KILL_CHAIN:READ_THEN_DELETE               hard DENY — read a resource, then delete it (5-min)
  KILL_CHAIN:SENSITIVITY_RAMP              ESCALATE  — progressive sensitivity increase (5-min)
  KILL_CHAIN:DIRECTORY_SWEEP               ESCALATE  — broad cross-directory recon (5-min)
  KILL_CHAIN:CROSS_SESSION:BULK_READ_*     hard DENY — slow APT-style bulk-read then exfil/destroy (24h)
  KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE hard DENY — read+delete same resource across sessions
  KILL_CHAIN:CROSS_SESSION:SENSITIVITY_RAMP ESCALATE — 4-hour progressive sensitivity ramp
"""

import time
import posixpath
from urllib.parse import unquote
from core import audit
from core.models import ResourceSensitivity, EXFILTRATION_ACTIONS as _EXFIL_ACTIONS
from core.lateral_movement import detect_lateral_movement

# Maximum query window — one DB round-trip per authorize call; filter in-process per detector.
# Cross-session history survives server restarts because request_history is SQLite-backed.
KILL_CHAIN_WINDOW_SECONDS = 86_400.0   # 24 hours

# Sub-window constants used internally for per-detector filtering
_FAST_WINDOW = 300.0     # 5 min — real-time attack detection
_RAMP_WINDOW = 14_400.0  # 4 h  — cross-session sensitivity ramp

# Reads in the 5-min fast window that triggers bulk-read-then-X
BULK_READ_THRESHOLD = 10

# Reads across 24h that triggers the cross-session slow variant
BULK_READ_THRESHOLD_24H = 30

# Distinct top-level resource prefixes that signal directory reconnaissance (fast window)
SWEEP_PREFIX_THRESHOLD = 6

# Minimum low/medium requests before a sensitivity ramp fires on a first CRITICAL hit
SENSITIVITY_RAMP_MIN_HISTORY = 5

_DESTRUCTIVE_ACTIONS = {
    "delete", "remove", "drop", "truncate",
    "wipe", "purge", "destroy", "overwrite",
}


def _normalize_path(resource: str) -> str:
    """URL-decode then POSIX-normalize and lowercase to prevent bypass via encoding or casing."""
    return posixpath.normpath(unquote(resource)).lower()


def _top_prefix(resource: str) -> str:
    """Extract the first path component: /reports/q3/q3.pdf → /reports"""
    parts = _normalize_path(resource).split("/")
    return "/" + parts[1] if len(parts) > 1 and parts[1] else "/"


def _sensitivity(resource: str, action: str) -> ResourceSensitivity:
    from core.trust_engine import classify_resource_sensitivity
    return classify_resource_sensitivity(resource, action)


def analyze_kill_chain(agent_id: str, action: str, resource: str) -> list[str]:
    """
    Examine the agent's 24-hour request history for multi-step attack patterns.
    Single DB query with max window; each detector filters its own sub-window in process.
    History is ordered most-recent first. Returns KILL_CHAIN:* flags.
    """
    history = audit.get_agent_request_history(
        agent_id, window_seconds=KILL_CHAIN_WINDOW_SECONDS
    )
    if not history:
        return []

    now = time.time()
    h_fast = [h for h in history if now - h["timestamp"] <= _FAST_WINDOW]
    h_ramp = [h for h in history if now - h["timestamp"] <= _RAMP_WINDOW]

    flags: list[str] = []
    action_lower = action.lower()

    # ── Detector 1: Bulk read → destructive or exfiltration ──────────────────
    # Fast (5-min): many reads in a burst before exfil/destroy — immediate DENY.
    # Slow (24h): reads spread over a workday before exfil — cross-session DENY.
    if action_lower in _EXFIL_ACTIONS or action_lower in _DESTRUCTIVE_ACTIONS:
        category = "EXFIL" if action_lower in _EXFIL_ACTIONS else "DESTROY"

        reads_fast = sum(1 for h in h_fast if h["action"].lower() == "read")
        if reads_fast >= BULK_READ_THRESHOLD:
            flags.append(f"KILL_CHAIN:BULK_READ_THEN_{category}:{reads_fast}_reads_in_5min")
        else:
            reads_24h = sum(1 for h in history if h["action"].lower() == "read")
            if reads_24h >= BULK_READ_THRESHOLD_24H:
                flags.append(
                    f"KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_{category}"
                    f":{reads_24h}_reads_in_24h"
                )

    # ── Detector 2: Read → delete same resource ───────────────────────────────
    # Fast (5-min): read then delete within the burst window.
    # Slow (24h): read early, come back hours later to delete (cover-tracks APT pattern).
    if action_lower in _DESTRUCTIVE_ACTIONS:
        target = _normalize_path(resource)

        fast_reads = [
            h for h in h_fast
            if h["action"].lower() == "read" and _normalize_path(h["resource"]) == target
        ]
        if fast_reads:
            flags.append(f"KILL_CHAIN:READ_THEN_DELETE:{resource}")
        else:
            all_prior_reads = [
                h for h in history
                if h["action"].lower() == "read" and _normalize_path(h["resource"]) == target
            ]
            if all_prior_reads:
                flags.append(f"KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE:{resource}")

    # ── Detector 3: Sensitivity ramp to CRITICAL ──────────────────────────────
    # Fast (5-min): agent probes low/medium resources then hits CRITICAL.
    # Slow (4h): same pattern at a slower cadence — requires 2× the history baseline.
    if _sensitivity(resource, action) == ResourceSensitivity.CRITICAL:
        fast_recent = h_fast[:15]
        past_fast = [_sensitivity(h["resource"], h["action"]) for h in fast_recent]
        crit_fast = sum(1 for s in past_fast if s == ResourceSensitivity.CRITICAL)
        low_med_fast = sum(
            1 for s in past_fast
            if s in (ResourceSensitivity.LOW, ResourceSensitivity.MEDIUM)
        )
        if crit_fast == 0 and low_med_fast >= SENSITIVITY_RAMP_MIN_HISTORY:
            flags.append(
                f"KILL_CHAIN:SENSITIVITY_RAMP"
                f":{low_med_fast}_low_med_before_first_critical"
            )
        else:
            ramp_recent = h_ramp[:30]
            past_ramp = [_sensitivity(h["resource"], h["action"]) for h in ramp_recent]
            crit_ramp = sum(1 for s in past_ramp if s == ResourceSensitivity.CRITICAL)
            low_med_ramp = sum(
                1 for s in past_ramp
                if s in (ResourceSensitivity.LOW, ResourceSensitivity.MEDIUM)
            )
            if crit_ramp == 0 and low_med_ramp >= SENSITIVITY_RAMP_MIN_HISTORY * 2:
                flags.append(
                    f"KILL_CHAIN:CROSS_SESSION:SENSITIVITY_RAMP"
                    f":{low_med_ramp}_low_med_in_4h"
                )

    # ── Detector 4: Directory sweep ───────────────────────────────────────────
    # Fast window only — sweeps are inherently rapid recon bursts.
    prefixes = {_top_prefix(h["resource"]) for h in h_fast}
    prefixes.add(_top_prefix(resource))
    if len(prefixes) >= SWEEP_PREFIX_THRESHOLD:
        flags.append(f"KILL_CHAIN:DIRECTORY_SWEEP:{len(prefixes)}_prefixes")

    # ── Detectors 5 & 6: Lateral movement (credential harvest + namespace sweep)
    flags.extend(detect_lateral_movement(action, resource, history))

    return flags
