import fnmatch
import posixpath
import re
import unicodedata
import urllib.parse
from datetime import datetime, timezone
from core.models import (
    AgentRegistration, AuthorizationRequest,
    TrustBreakdown, ResourceSensitivity, Decision,
    EXFILTRATION_ACTIONS,
)
from core.purpose_engine import compute_purpose_score
from core import audit
from core.kill_chain import analyze_kill_chain
from core.time_anomaly import detect_time_anomaly as _detect_time_anomaly, BASELINE_WINDOW_SECONDS as _TIME_BASELINE_WINDOW

# Sensitivity thresholds: minimum trust score required to PERMIT
SENSITIVITY_THRESHOLDS = {
    ResourceSensitivity.LOW: 40.0,
    ResourceSensitivity.MEDIUM: 60.0,
    ResourceSensitivity.HIGH: 75.0,
    ResourceSensitivity.CRITICAL: 90.0,
}

# Secret patterns to detect in resource paths and justifications
_SECRETS_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE KEY"),
    re.compile(r"password\s*[=:]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"(?<!\w)secret\s*[=:]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[=:]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
]

# Score weights
W_IDENTITY = 0.25
W_DELEGATION = 0.25
W_PURPOSE = 0.30
W_BEHAVIORAL = 0.20

# Velocity: global fallback threshold for agents with no baseline yet
GLOBAL_MAX_RPM = 20
# Minimum requests before we trust the baseline over the global threshold
BASELINE_MIN_REQUESTS = 10
# How many standard deviations above baseline before we flag HIGH_VELOCITY
BASELINE_SPIKE_MULTIPLIER = 2.5


def _detect_secrets(text: str) -> bool:
    # Normalize before matching so homoglyph variants don't bypass patterns
    normalized = unicodedata.normalize("NFKC", text)
    return any(p.search(normalized) for p in _SECRETS_PATTERNS)


_CRITICAL_KEYWORDS = {
    # Credentials and secrets
    "salary", "payroll", "password", "passwd", "cred", "credential",
    "secret", "private_key", "privatekey", "token", "api_key", "apikey",
    # Cryptographic material
    "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".p12", ".pfx", ".key",
    "ssh", "tls_cert", "ssl_cert", "ca_bundle",
    # Auth and identity
    "mfa", "totp", "seed", "oauth", "jwt_secret", "session_secret",
    # Env and config with secrets
    ".env", ".env.prod", ".env.local", "vault", "keystore",
    # Database dumps and backups
    ".sql", ".dump", ".bak", ".backup", "db_export",
    # Encryption keys
    ".gpg", ".asc", "pgp", "keyring",
}

_HIGH_KEYWORDS = {
    "confidential", "hr", "finance", "admin", "root", "audit",
    "employee", "medical", "health", "pii", "gdpr", "compliance",
    "legal", "contract", "nda", "executive", "board", "merger",
    "acquisition", "strategy",
}

_MEDIUM_KEYWORDS = {
    "internal", "personal", "user", "config", "configuration",
    "settings", "profile", "account", "billing", "invoice",
    "analytics", "roadmap",
}


def classify_resource_sensitivity(resource: str, action: str = "") -> ResourceSensitivity:
    if action.lower() in EXFILTRATION_ACTIONS:
        return ResourceSensitivity.CRITICAL
    r = resource.lower()
    if any(kw in r for kw in _CRITICAL_KEYWORDS):
        return ResourceSensitivity.CRITICAL
    if any(kw in r for kw in _HIGH_KEYWORDS):
        return ResourceSensitivity.HIGH
    if any(kw in r for kw in _MEDIUM_KEYWORDS):
        return ResourceSensitivity.MEDIUM
    return ResourceSensitivity.LOW


def score_identity(agent: AgentRegistration, request: AuthorizationRequest) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    # Token validity is enforced at the API layer (401 before trust scoring).
    # No secondary check here — agent.token is a SHA-256 hash and request.token
    # is plaintext, so a direct comparison would always false-flag valid requests.

    # Check if action is in authorized actions
    if request.action.lower() not in [a.lower() for a in agent.authorized_actions]:
        flags.append(f"UNAUTHORIZED_ACTION:{request.action}")
        score -= 40.0

    # Check if resource matches any authorized pattern.
    # Also match the directory itself when pattern ends with /*
    # e.g. "/documents" should match "/documents/*"
    def _normalize(path: str) -> str:
        decoded = urllib.parse.unquote(urllib.parse.unquote(path))
        decoded = decoded.replace("\x00", "")
        normalized = posixpath.normpath(decoded)
        return normalized if normalized.startswith("/") else "/" + normalized

    def _matches(resource: str, pattern: str) -> bool:
        resource = _normalize(resource)
        pattern = _normalize(pattern)
        if fnmatch.fnmatch(resource, pattern):
            return True
        if pattern.endswith("/*"):
            parent = pattern[:-2]
            if resource == parent or resource == parent + "/":
                return True
        return False

    resource_allowed = any(
        _matches(request.resource, pattern)
        for pattern in agent.authorized_resources
    )
    if not resource_allowed:
        flags.append(f"RESOURCE_OUT_OF_SCOPE:{request.resource}")
        score -= 35.0

    return max(0.0, score), flags


def score_delegation(
    agent: AgentRegistration,
    request: "AuthorizationRequest",
    agents: dict,
) -> tuple[float, list[str]]:
    from core.delegation import (
        check_chain_scope, compute_chain_trust_multiplier, MAX_DELEGATION_DEPTH
    )
    flags = []
    score = 100.0
    depth = agent.delegation_depth

    # Penalize deep delegation chains
    if depth > 0:
        score -= depth * 15.0

    # Orphan delegation — parent claimed but not present in registry
    # Chain cannot be verified → unverifiable delegation is treated as a violation
    if depth > 0 and agent.delegated_by and agent.delegated_by not in agents:
        flags.append("ORPHAN_DELEGATION")
        score = 0.0  # hard zero — unverifiable chain

    # Walk full chain — block if request exceeds any ancestor's scope
    if depth > 0 and "ORPHAN_DELEGATION" not in flags:
        chain_ok, chain_error = check_chain_scope(
            agent.agent_id, request.action, request.resource, agents
        )
        if not chain_ok:
            flags.append("CHAIN_SCOPE_VIOLATION")
            flags.append(f"VIOLATION_DETAIL:{chain_error[:80]}")
            score = 0.0  # hard zero — cannot proceed

    # Legacy single-level scope check
    if agent.delegated_by and agent.scope_at_delegation:
        current_scope = set(agent.authorized_actions)
        parent_scope = set(agent.scope_at_delegation)
        if not current_scope.issubset(parent_scope):
            flags.append("SCOPE_ESCALATION_AT_DELEGATION")
            score -= 50.0

    if depth > MAX_DELEGATION_DEPTH:
        flags.append(f"EXCESSIVE_DELEGATION_DEPTH:{depth}")
        score = 0.0

    # Apply chain trust decay
    multiplier = compute_chain_trust_multiplier(depth)
    score = score * multiplier

    # Trust ceiling: delegated agents cannot exceed the ceiling set by the parent
    # at delegation time. Prevents trust-washing — a bad actor cannot spawn a
    # sub-agent and accumulate trust the parent was never permitted to hold.
    if agent.trust_ceiling is not None:
        score = min(score, agent.trust_ceiling)
        if agent.trust_ceiling < 50.0:
            flags.append(f"TRUST_CEILING_ACTIVE:{round(agent.trust_ceiling)}")

    return max(0.0, score), flags


def check_behavioral_contract(
    agent: AgentRegistration,
    action: str,
    history: list[dict],
) -> list[str]:
    """
    Deterministic checks against the agent's declared behavioral contract.

    Unlike the probabilistic velocity scorer, violations here are binary: the agent
    declared a hard limit at registration time and is now exceeding it. The contract
    terms appear verbatim in the audit log so violations are always explainable.
    """
    flags = []

    if agent.max_requests_per_minute is not None:
        rpm = len(history)
        if rpm >= agent.max_requests_per_minute:
            flags.append(f"CONTRACT_RPM_EXCEEDED:{rpm}/{agent.max_requests_per_minute}")

    if agent.allowed_time_windows:
        now_utc = datetime.now(timezone.utc)
        current_hm = now_utc.strftime("%H:%M")
        in_window = False
        for window in agent.allowed_time_windows:
            try:
                start, end = window.strip().split("-")
                start, end = start.strip(), end.strip()
                if start <= end:
                    if start <= current_hm <= end:
                        in_window = True
                        break
                else:
                    # Window crosses midnight — e.g. "22:00-06:00"
                    if current_hm >= start or current_hm <= end:
                        in_window = True
                        break
            except Exception:
                pass  # malformed window — fail open for this entry
        if not in_window:
            flags.append(f"CONTRACT_OUTSIDE_TIME_WINDOW:{current_hm}_UTC")

    if agent.max_consecutive_same_action is not None:
        limit = agent.max_consecutive_same_action
        recent = [h["action"] for h in history[:limit]]
        if len(recent) >= limit and all(a == action for a in recent):
            flags.append(f"CONTRACT_CONSECUTIVE_ACTION:{action}:{limit}")

    return flags


def score_behavioral(agent_id: str, action: str) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    history = audit.get_agent_request_history(agent_id, window_seconds=60.0)
    rpm = len(history)

    # Use per-agent baseline if the agent has enough history; fall back to global threshold
    baseline = audit.get_agent_baseline(agent_id)
    if baseline and baseline["total_requests"] >= BASELINE_MIN_REQUESTS:
        agent_avg_rpm = baseline["avg_rpm"]
        # Effective ceiling: agent's own average * spike multiplier, floor at GLOBAL_MAX_RPM
        effective_max = max(GLOBAL_MAX_RPM, agent_avg_rpm * BASELINE_SPIKE_MULTIPLIER)
        anomaly_ratio = rpm / max(agent_avg_rpm, 0.1)

        if rpm > effective_max:
            excess_ratio = rpm / effective_max
            penalty = min(90.0, (excess_ratio - 1.0) * 45.0)
            score -= penalty
            if anomaly_ratio > 5.0:
                flags.append(f"CRITICAL_VELOCITY:{rpm}_RPM|BASELINE:{round(agent_avg_rpm,1)}")
            else:
                flags.append(f"HIGH_VELOCITY:{rpm}_RPM|BASELINE:{round(agent_avg_rpm,1)}")
    else:
        # Cold start: use global threshold
        if rpm > GLOBAL_MAX_RPM:
            excess = rpm - GLOBAL_MAX_RPM
            penalty = min(90.0, excess * 5.0)
            score -= penalty
            if rpm > GLOBAL_MAX_RPM * 2:
                flags.append(f"CRITICAL_VELOCITY:{rpm}_RPM")
            else:
                flags.append(f"HIGH_VELOCITY:{rpm}_RPM")

    # Check for repeated identical actions (replay-style behavior)
    recent_actions = [h["action"] for h in history[:10]]
    if recent_actions.count(action) > 5:
        flags.append(f"REPETITIVE_ACTION:{action}")
        score -= 25.0

    # Only update baseline with clean observations — prevents gradual baseline poisoning
    if not any("VELOCITY" in f for f in flags):
        audit.update_agent_baseline(agent_id, float(rpm))

    return max(0.0, score), flags


def compute_trust(
    agent: AgentRegistration,
    request: AuthorizationRequest,
    agents: dict = None,
    injection_risk: float = 0.0,
    contagion_penalty: float = 0.0,
    contagion_flags: list = None,
) -> tuple[TrustBreakdown, list[str]]:
    all_flags = []

    # Secrets in args — check each field independently AND their no-space concatenation.
    # Space-joined combined string misses secrets split at the boundary (sk- in resource,
    # remaining chars in justification). No-space concat closes that gap.
    _just = request.justification or ""
    if (_detect_secrets(request.resource) or
            _detect_secrets(_just) or
            _detect_secrets(request.resource + _just)):
        all_flags.append("SECRETS_IN_ARGS")

    # Exfiltration action flag
    if request.action.lower() in EXFILTRATION_ACTIONS:
        all_flags.append(f"EXFILTRATION_ACTION:{request.action}")

    id_score, id_flags = score_identity(agent, request)
    all_flags.extend(id_flags)

    del_score, del_flags = score_delegation(agent, request, agents or {})
    all_flags.extend(del_flags)

    purpose_score = compute_purpose_score(
        agent.declared_purpose,
        request.action,
        request.resource,
        request.justification or ""
    )

    # Behavioral contract check: deterministic against declared registration-time limits
    contract_history = audit.get_agent_request_history(agent.agent_id, window_seconds=60.0)
    contract_flags = check_behavioral_contract(agent, request.action, contract_history)
    all_flags.extend(contract_flags)

    kc_flags = analyze_kill_chain(agent.agent_id, request.action, request.resource)
    all_flags.extend(kc_flags)

    # Time-of-day behavioral anomaly: inferred from 7-day history, no registration-time
    # configuration required. Emits ESCALATE-tier flag when the request hour falls
    # significantly outside the agent's established operating pattern.
    _time_history = audit.get_agent_request_history(
        agent.agent_id, window_seconds=_TIME_BASELINE_WINDOW
    )
    all_flags.extend(_detect_time_anomaly(_time_history))

    beh_score, beh_flags = score_behavioral(agent.agent_id, request.action)
    # Penalize behavioral score when a prior injection scan flagged this agent
    if injection_risk > 0.5:
        penalty = min(50.0, (injection_risk - 0.5) * 100.0)
        beh_score = max(0.0, beh_score - penalty)
        beh_flags.append(f"PRIOR_INJECTION_RISK:{round(injection_risk * 100)}%")
    # Penalize behavioral score when a delegation neighbour is compromised (trust contagion)
    if contagion_penalty > 0:
        beh_score = max(0.0, beh_score - contagion_penalty)
        beh_flags.extend(contagion_flags or [])
    all_flags.extend(beh_flags)

    sensitivity = classify_resource_sensitivity(request.resource, request.action)
    threshold = SENSITIVITY_THRESHOLDS[sensitivity]

    final = (
        id_score * W_IDENTITY +
        del_score * W_DELEGATION +
        purpose_score * W_PURPOSE +
        beh_score * W_BEHAVIORAL
    )
    final = round(final, 2)

    breakdown = TrustBreakdown(
        identity_score=round(id_score, 2),
        delegation_score=round(del_score, 2),
        purpose_alignment_score=round(purpose_score, 2),
        behavioral_score=round(beh_score, 2),
        resource_sensitivity=sensitivity,
        final_score=final,
        threshold_required=threshold,
    )

    return breakdown, all_flags


def make_decision(breakdown: TrustBreakdown, flags: list[str]) -> Decision:
    score = breakdown.final_score
    threshold = breakdown.threshold_required

    # Hard deny on high-confidence kill chain patterns — both fast (5-min) and
    # cross-session (24h) variants. SENSITIVITY_RAMP and DIRECTORY_SWEEP use scores.
    if any("BULK_READ_THEN_" in f for f in flags):
        return Decision.DENY
    if any("READ_THEN_DELETE" in f for f in flags):
        return Decision.DENY

    # Hard deny on behavioral contract violations — agent exceeded its own declared limits
    if any(f.startswith("CONTRACT_") for f in flags):
        return Decision.DENY

    # Hard deny on secrets detected in resource path or justification
    if any("SECRETS_IN_ARGS" in f for f in flags):
        return Decision.DENY

    # Hard deny on critical velocity
    if any("CRITICAL_VELOCITY" in f for f in flags):
        return Decision.DENY

    # Hard deny on delegation chain violations — always, regardless of sensitivity
    if any("CHAIN_SCOPE_VIOLATION" in f for f in flags):
        return Decision.DENY

    # Hard deny on orphan delegation — parent claimed but not in registry
    if any("ORPHAN_DELEGATION" in f for f in flags):
        return Decision.DENY

    # Hard deny when delegation depth exceeds the configured maximum
    if any("EXCESSIVE_DELEGATION_DEPTH" in f for f in flags):
        return Decision.DENY

    # Hard deny on unauthorized action — agent doing something outside its contract
    if any("UNAUTHORIZED_ACTION" in f for f in flags):
        return Decision.DENY

    # Hard deny when agent accesses resources outside its declared scope
    if any("RESOURCE_OUT_OF_SCOPE" in f for f in flags):
        return Decision.DENY

    # Hard deny on critical security flags for sensitive resources
    critical_flags = [f for f in flags if any(kw in f for kw in [
        "TOKEN_MISMATCH", "SCOPE_ESCALATION"
    ])]
    if critical_flags and breakdown.resource_sensitivity in (
        ResourceSensitivity.HIGH, ResourceSensitivity.CRITICAL
    ):
        return Decision.DENY

    if score >= threshold:
        if flags:
            return Decision.ESCALATE
        return Decision.PERMIT
    elif score >= threshold * 0.6:
        return Decision.ESCALATE
    else:
        return Decision.DENY
