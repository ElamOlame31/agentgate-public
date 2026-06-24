"""
Lethal Trifecta detector — identifies the highest-risk agent configuration.

An agent is in the lethal trifecta when it simultaneously holds:

  1. EXPOSURE  — processes untrusted external content (emails, file uploads,
                 web pages, tool outputs from third-party APIs)
  2. REACH     — is authorized to access HIGH or CRITICAL sensitivity resources
                 (credentials, salary data, PII, financial records, admin systems)
  3. EGRESS    — is authorized to send data outside the system
                 (email, upload, webhook, export, publish)

Any individual condition is manageable:
  - Exposure alone: reading external content is normal.
  - Reach alone: accessing sensitive data with no way to send it is safe.
  - Egress alone: external comms without sensitive data access is safe.

All three together create the attack path documented in 2026 incident research:
  indirect prompt injection → agent reads sensitive data → agent exfiltrates it.
  Every individual step may appear authorized. The combination is the attack.

This detector examines the agent's REGISTRATION — its declared capabilities — not
just the current request. A trifecta-capable agent is one instruction away from
exfiltration, regardless of how the current request looks individually.

Flags returned:
  LETHAL_TRIFECTA:EXFIL — all three conditions active, current action is exfiltration.
                           Route: hard DENY. The action IS the final exfil step.
  LETHAL_TRIFECTA:RISK  — all three conditions active, action is non-read non-exfil.
                           Route: ESCALATE. High-risk mutation without confirmed exfil.
  []                    — trifecta not active, or action is safe read-only.
"""

# Exfiltration action verbs.
# Must stay in sync with EXFILTRATION_ACTIONS in core/models.py.
# Duplicated here so this module remains importable without pydantic
# (for standalone tooling and stdlib-only tests).
_EXFILTRATION_ACTIONS: frozenset[str] = frozenset({
    "send", "email", "upload", "post", "forward", "export", "transfer", "publish",
})

# Read-only actions: safe even in a trifecta-capable agent.
_READ_ONLY_ACTIONS: frozenset[str] = frozenset({
    "read", "search", "query", "list", "get", "fetch", "view", "load",
    "browse", "find", "describe", "inspect",
})

# Resource path keywords that indicate HIGH or CRITICAL sensitivity.
# Reflects the keyword sets in core/trust_engine.classify_resource_sensitivity().
_SENSITIVE_RESOURCE_KEYWORDS: frozenset[str] = frozenset({
    # CRITICAL — credentials, key material, secrets
    "salary", "payroll", "password", "passwd", "credential", "secret",
    "private_key", "privatekey", "api_key", "apikey", "token",
    "id_rsa", "id_ed25519", ".pem", ".key", "vault", "keystore",
    # HIGH — PII, finance, legal, medical
    "confidential", "hr", "finance", "admin", "employee", "medical",
    "health", "pii", "gdpr", "legal", "contract", "nda", "merger",
    "acquisition", "executive", "board",
})

LETHAL_TRIFECTA_EXFIL = "LETHAL_TRIFECTA:EXFIL"
LETHAL_TRIFECTA_RISK = "LETHAL_TRIFECTA:RISK"


def _has_sensitive_reach(authorized_resources: list[str]) -> bool:
    """True if the agent's declared scope includes HIGH or CRITICAL sensitivity paths."""
    for resource in authorized_resources:
        r_lower = resource.lower()
        if any(kw in r_lower for kw in _SENSITIVE_RESOURCE_KEYWORDS):
            return True
    return False


def _has_egress(authorized_actions: list[str]) -> bool:
    """True if the agent is authorized to send data outside the system."""
    return bool({a.lower() for a in authorized_actions} & _EXFILTRATION_ACTIONS)


def detect_lethal_trifecta(
    processes_external_content: bool,
    authorized_resources: list[str],
    authorized_actions: list[str],
    action: str,
) -> list[str]:
    """
    Return LETHAL_TRIFECTA:* flags when all three trifecta conditions are active
    and the current action falls into the EXFIL or RISK category.

    Args:
        processes_external_content: agent.processes_external_content
        authorized_resources:       agent.authorized_resources
        authorized_actions:         agent.authorized_actions
        action:                     the action in the current authorization request

    Returns:
        list of zero or one LETHAL_TRIFECTA:* flags
    """
    # Condition 1: external content exposure
    if not processes_external_content:
        return []

    # Condition 2: sensitive reach
    if not _has_sensitive_reach(authorized_resources):
        return []

    # Condition 3: egress capability
    if not _has_egress(authorized_actions):
        return []

    # All three conditions are active — evaluate the current action
    action_lower = action.lower()

    if action_lower in _EXFILTRATION_ACTIONS:
        # The action IS the final exfil step: hard deny
        return [LETHAL_TRIFECTA_EXFIL]

    if action_lower not in _READ_ONLY_ACTIONS:
        # Mutation action in a trifecta-capable agent: escalate
        return [LETHAL_TRIFECTA_RISK]

    # Read-only action: no additional flag (configuration risk is present but
    # this specific request is the safe step in the attack chain, not the dangerous one)
    return []
