"""
Lateral movement detector — cross-session namespace sweep and credential harvest.

Detects two attack patterns that emerge across an agent's request history:

  KILL_CHAIN:CREDENTIAL_HARVEST              — ESCALATE
      Agent accesses 3+ distinct credential/secret resource paths within the
      5-minute fast window. Catches the enumeration phase before any exfil
      attempt (distinct from BULK_READ_THEN_EXFIL, which requires the export
      action itself). Even if each path is in-scope, systematic credential
      enumeration warrants human review.

  KILL_CHAIN:CROSS_SESSION:NAMESPACE_SWEEP   — ESCALATE
      Agent accesses 4+ distinct top-level organizational namespaces with at
      least 3 resources each over the 24-hour window. Detects APT-style slow
      lateral movement — patient, methodical exploration of organizational
      structure that deliberately stays below burst-based DIRECTORY_SWEEP
      thresholds.

Both return ESCALATE signals, not hard DENYs. A broad-scope agent doing
legitimate cross-department work could trigger NAMESPACE_SWEEP; human-in-the-
loop review is appropriate rather than an automatic block.

Zero external dependencies — stdlib only. Designed for direct import by
kill_chain.py and for standalone stdlib-only testing.
"""

import posixpath
import time
from urllib.parse import unquote

# ── Namespace sweep constants ─────────────────────────────────────────────────

# Minimum number of distinct resources per namespace that indicate intentional
# exploration (not just an incidental access).
NAMESPACE_DEPTH_THRESHOLD: int = 3

# Minimum number of namespaces with NAMESPACE_DEPTH_THRESHOLD+ resources needed
# to signal lateral movement over the 24h window.
NAMESPACE_SWEEP_THRESHOLD: int = 4

# Time window for cross-session sweep detection.
NAMESPACE_SWEEP_WINDOW_SECONDS: float = 86_400.0  # 24 hours

# ── Credential harvest constants ──────────────────────────────────────────────

# Minimum distinct credential-related resource paths in the fast window to flag.
CREDENTIAL_HARVEST_THRESHOLD: int = 3

# Time window for credential harvest burst detection.
CREDENTIAL_HARVEST_WINDOW_SECONDS: float = 300.0  # 5 minutes

# Resource path substrings that indicate credential or secret content.
# Mirror of trust_engine._CRITICAL_KEYWORDS but kept stdlib-only here.
_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset({
    "password", "passwd", "credential", "cred", "secret", "token",
    "api_key", "apikey", "private_key", "privatekey",
    "id_rsa", "id_ed25519", "id_ecdsa",
    ".pem", ".p12", ".pfx", ".key",
    ".env", "vault", "keystore",
    "salary", "payroll",
    "mfa", "totp", "oauth", "jwt_secret", "session_secret",
    "db_export", ".dump", ".bak",
})


# ── Path helpers ──────────────────────────────────────────────────────────────

def _normalize_path(resource: str) -> str:
    """Double URL-decode, strip null bytes, POSIX-normalize, lowercase."""
    decoded = unquote(unquote(resource)).replace("\x00", "").lower()
    return posixpath.normpath(decoded)


def _top_prefix(resource: str) -> str:
    """
    Extract the first path component as the namespace key.
    /reports/q3/q3.pdf  →  /reports
    /hr/salary.xlsx     →  /hr
    /                   →  /
    """
    parts = _normalize_path(resource).split("/")
    return "/" + parts[1] if len(parts) > 1 and parts[1] else "/"


def _is_credential_path(resource: str) -> bool:
    """Return True when the resource path contains any credential keyword."""
    lower = _normalize_path(resource)
    return any(kw in lower for kw in _CREDENTIAL_KEYWORDS)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_lateral_movement(
    action: str,
    resource: str,
    history: list[dict],
) -> list[str]:
    """
    Analyse the agent's request history for lateral movement patterns.

    Parameters
    ----------
    action   : Current request action (e.g. "read").
    resource : Current request resource path.
    history  : Prior history entries from audit.get_agent_request_history —
               each a dict with at minimum "action", "resource", "timestamp".
               Ordering (newest-first or oldest-first) does not affect results.

    Returns
    -------
    List of ``KILL_CHAIN:*`` flag strings. Empty when no patterns are detected.
    """
    flags: list[str] = []
    now = time.time()

    # ── Detector A: Credential harvest burst ─────────────────────────────────
    # Distinct credential/secret paths accessed in the 5-min fast window.
    h_fast = [
        h for h in history
        if now - h["timestamp"] <= CREDENTIAL_HARVEST_WINDOW_SECONDS
    ]

    cred_paths: set[str] = {
        _normalize_path(h["resource"])
        for h in h_fast
        if _is_credential_path(h["resource"])
    }
    # Include the current request
    if _is_credential_path(resource):
        cred_paths.add(_normalize_path(resource))

    if len(cred_paths) >= CREDENTIAL_HARVEST_THRESHOLD:
        flags.append(
            f"KILL_CHAIN:CREDENTIAL_HARVEST"
            f":{len(cred_paths)}_credential_paths_in_5min"
        )

    # ── Detector B: Cross-session namespace sweep ─────────────────────────────
    # Count how many distinct top-level namespaces the agent has explored with
    # sufficient depth (NAMESPACE_DEPTH_THRESHOLD resources each) over 24h.
    h_24h = [
        h for h in history
        if now - h["timestamp"] <= NAMESPACE_SWEEP_WINDOW_SECONDS
    ]

    namespace_counts: dict[str, int] = {}
    for h in h_24h:
        prefix = _top_prefix(h["resource"])
        namespace_counts[prefix] = namespace_counts.get(prefix, 0) + 1
    # Count the current request
    current_prefix = _top_prefix(resource)
    namespace_counts[current_prefix] = namespace_counts.get(current_prefix, 0) + 1

    deep_namespaces = sum(
        1 for count in namespace_counts.values()
        if count >= NAMESPACE_DEPTH_THRESHOLD
    )

    if deep_namespaces >= NAMESPACE_SWEEP_THRESHOLD:
        flags.append(
            f"KILL_CHAIN:CROSS_SESSION:NAMESPACE_SWEEP"
            f":{deep_namespaces}_namespaces_x{NAMESPACE_DEPTH_THRESHOLD}+_resources"
        )

    return flags
