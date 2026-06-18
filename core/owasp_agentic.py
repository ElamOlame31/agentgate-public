"""
OWASP Top 10 for Agentic Applications 2026 — AgentGate coverage mapping.

Provides a machine-readable compliance report mapping all 10 OWASP Agentic
Security Initiative (ASI) risks to the specific AgentGate components that
enforce or detect each category.

Official taxonomy:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Coverage levels:
  FULL    — AgentGate provides deterministic, pre-execution enforcement for this risk.
  PARTIAL — AgentGate addresses one or more sub-scenarios; some attack surfaces
            fall outside a runtime authorization layer by architecture.
  NONE    — Not covered.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


_FRAMEWORK = "OWASP Top 10 for Agentic Applications"
_FRAMEWORK_VERSION = "2026"
_TAXONOMY_URL = (
    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"
)


class CoverageLevel(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    NONE = "NONE"


@dataclass
class RiskEntry:
    code: str
    name: str
    description: str
    coverage: CoverageLevel
    mechanisms: list[str]
    notes: str = ""


# ── OWASP ASI01–ASI10 mapping ─────────────────────────────────────────────────

_RISKS: list[RiskEntry] = [
    RiskEntry(
        code="ASI01:2026",
        name="Agent Goal Hijack",
        description=(
            "Attackers redirect an agent's goals through prompt injection "
            "(direct or indirect), malicious tool outputs, or poisoned system prompts."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "injection_detector: keyword regex + semantic embedding scan detects goal-hijacking "
            "phrases in external content before the agent reads them",
            "mcp_descriptor_guard: blocks goal hijacking via poisoned MCP tool descriptions "
            "on first-call (descriptor poisoning) and on mutation (rug-pull)",
            "purpose_engine: purpose alignment score (30% of trust) drops sharply when the "
            "inferred goal diverges from the agent's declared purpose",
        ],
    ),
    RiskEntry(
        code="ASI02:2026",
        name="Tool Misuse & Exploitation",
        description=(
            "Agents use legitimate tools in unintended ways — e.g., using read access "
            "to enumerate and exfiltrate data, or using code execution beyond declared scope."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "trust_engine: authorized_actions whitelist enforced per-request; "
            "UNAUTHORIZED_ACTION is always DENY regardless of trust score",
            "kill_chain: BULK_READ_THEN_EXFIL and BULK_READ_THEN_DESTROY detectors catch "
            "systematic tool misuse patterns across 5-min and 24-h windows",
            "purpose_engine: action+resource embedding scored against declared purpose; "
            "out-of-scope tool use depresses the 30% purpose dimension",
            "mcp_descriptor_guard: catches tool description mutation (rug-pull) that would "
            "silently change tool behavior after approval",
        ],
    ),
    RiskEntry(
        code="ASI03:2026",
        name="Agent Identity & Privilege Abuse",
        description=(
            "Agents impersonate other agents, claim unauthorized roles, or escalate "
            "their privilege level beyond what was granted at registration."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "token: Ed25519-signed JWTs bind every agent to its registered identity; "
            "tokens are short-lived and revocable",
            "delegation: full chain walk enforces scope attenuation — a child agent can "
            "never exceed the resources or actions its parent was granted; "
            "CHAIN_SCOPE_VIOLATION is always DENY",
            "trust_engine: identity dimension (25%) validates token signature, expiry, "
            "and action/resource match against declared scope on every request",
            "server: UNREGISTERED_AGENT denial for any agent_id not in the registry",
        ],
    ),
    RiskEntry(
        code="ASI04:2026",
        name="Agentic Supply Chain Compromise",
        description=(
            "Compromised MCP servers, tool registries, model providers, or agent packages "
            "introduce malicious behavior through the agent's dependency graph."
        ),
        coverage=CoverageLevel.PARTIAL,
        mechanisms=[
            "mcp_descriptor_guard: detects descriptor poisoning (malicious instructions "
            "embedded in tool descriptions/schemas on first call) and rug-pull attacks "
            "(tool description mutation after approval) using SHA-256 hash tracking",
        ],
        notes=(
            "Covers the MCP tool supply chain. Compromised model weights, npm/pip packages, "
            "or infrastructure-level supply chain are outside the runtime authorization layer."
        ),
    ),
    RiskEntry(
        code="ASI05:2026",
        name="Unexpected Code Execution",
        description=(
            "Agents generate or execute arbitrary code outside their intended scope, "
            "often triggered by prompt injection in external content."
        ),
        coverage=CoverageLevel.PARTIAL,
        mechanisms=[
            "injection_detector: semantic + keyword scan catches injection attempts that "
            "would trigger unintended code execution paths",
            "trust_engine: authorized_actions whitelist blocks code execution action verbs "
            "for agents that did not declare them",
            "purpose_engine: code-execution actions penalised heavily for non-coding-purpose "
            "agents via the action penalty multiplier",
        ],
        notes=(
            "Detects injection-driven and out-of-scope execution attempts. "
            "Sandboxing or containerising the execution environment itself is the host "
            "application's responsibility and outside the authorization layer."
        ),
    ),
    RiskEntry(
        code="ASI06:2026",
        name="Memory & Context Poisoning",
        description=(
            "Attackers corrupt the agent's memory, RAG store, conversation history, "
            "or external document inputs to alter future behaviour."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "injection_detector: scans document/tool-output content before the agent "
            "processes it when processes_external_content=True; catches both keyword "
            "and semantic redirection attempts",
            "mcp_descriptor_guard: prevents tool descriptions from poisoning the agent's "
            "context window via descriptor injection or mutation",
            "output_sanitizer: sanitises agent output before it propagates to downstream "
            "agents or storage, breaking the poisoning chain",
        ],
    ),
    RiskEntry(
        code="ASI07:2026",
        name="Insecure Inter-Agent Communication",
        description=(
            "Agents communicate without authentication or integrity checks; "
            "inter-agent messages can be spoofed, replayed, or tampered with."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "token: Ed25519-signed tokens required for every agent-to-agent delegation; "
            "unsigned or expired tokens fail validation",
            "delegation: delegation chain stored and verified on every /authorize call; "
            "CHAIN_SCOPE_VIOLATION blocks any request that exceeds the verified chain",
            "trust_engine: delegation dimension (25%) gives full score only when the "
            "complete ancestry chain is verified; unverified inter-agent hops lose points",
            "audit: every inter-agent delegation is HMAC-chained and pre-execution sealed",
        ],
    ),
    RiskEntry(
        code="ASI08:2026",
        name="Cascading Agent Failures",
        description=(
            "One agent's failure or compromise propagates through the multi-agent "
            "graph, causing cascading harm across the system."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "quarantine: quarantined agents are immediately denied all further requests; "
            "blast radius is contained at the individual agent level",
            "contagion: propagates behavioral score penalties through the delegation graph "
            "on quarantine — parent gets -15 pts, children get -30 pts — so adjacent "
            "agents are automatically downgraded without manual intervention",
            "trust_ceiling: delegated agents inherit a trust ceiling from their parent; "
            "a compromised parent cannot spawn children that earn higher trust scores",
        ],
    ),
    RiskEntry(
        code="ASI09:2026",
        name="Human-Agent Trust Exploitation",
        description=(
            "Agents manipulate humans into approving harmful actions, or humans "
            "over-trust agent outputs without adequate oversight gates."
        ),
        coverage=CoverageLevel.PARTIAL,
        mechanisms=[
            "approvals: ESCALATE decision tier routes high-stakes or ambiguous actions "
            "to a human-in-the-loop approval queue before execution",
            "hitl_timeout: pending approvals auto-deny after 90 seconds so agents cannot "
            "stall indefinitely waiting for a human to approve a harmful action",
            "requires_human_approval flag: operators can mandate human approval for any "
            "agent or action class at registration time",
        ],
        notes=(
            "Enforces human approval gates for uncertain or high-stakes decisions. "
            "Cannot prevent a human approver from being deceived by a well-crafted "
            "agent explanation — that requires separate output verification tooling."
        ),
    ),
    RiskEntry(
        code="ASI10:2026",
        name="Rogue Agents",
        description=(
            "An agent operates entirely outside its sanctioned purpose and boundaries, "
            "pursuing goals not in its charter — often across many sessions."
        ),
        coverage=CoverageLevel.FULL,
        mechanisms=[
            "kill_chain: four behavioral detectors (bulk-read-then-exfil/destroy, "
            "read-then-delete, sensitivity ramp, directory sweep) span both 5-min and "
            "24-h windows to catch rogue behaviour at any pace",
            "purpose_engine: purpose alignment score collapses toward zero when an agent "
            "systematically pursues goals misaligned with its declared purpose",
            "trust_engine: behavioral dimension (20%) tracks request velocity and patterns "
            "against per-agent baselines; anomalies push the score below thresholds",
            "quarantine + contagion: confirmed rogue agents are quarantined and their "
            "delegation network receives automatic contagion penalties",
        ],
    ),
]


# ── Public API ────────────────────────────────────────────────────────────────

def get_risks() -> list[RiskEntry]:
    """Return the full ordered list of OWASP Agentic risk entries."""
    return list(_RISKS)


def get_risk(code: str) -> Optional[RiskEntry]:
    """Return the entry for a specific risk code (e.g. 'ASI01:2026'), or None."""
    needle = code.upper()
    for r in _RISKS:
        if r.code.upper() == needle:
            return r
    return None


def generate_compliance_report(include_mechanisms: bool = True) -> dict:
    """
    Return a structured OWASP Agentic Top 10 compliance report.

    Args:
        include_mechanisms: include the list of AgentGate mechanisms per risk.
                            Set False for a compact summary response.
    """
    full = [r for r in _RISKS if r.coverage == CoverageLevel.FULL]
    partial = [r for r in _RISKS if r.coverage == CoverageLevel.PARTIAL]
    none_ = [r for r in _RISKS if r.coverage == CoverageLevel.NONE]

    # Score: FULL = 1.0 point, PARTIAL = 0.5 points
    raw_score = len(full) * 1.0 + len(partial) * 0.5
    coverage_pct = round(raw_score / len(_RISKS) * 100, 1)

    risks_out = []
    for r in _RISKS:
        entry: dict = {
            "code": r.code,
            "name": r.name,
            "description": r.description,
            "coverage": r.coverage.value,
        }
        if r.notes:
            entry["notes"] = r.notes
        if include_mechanisms:
            entry["agentgate_mechanisms"] = r.mechanisms
        risks_out.append(entry)

    return {
        "framework": _FRAMEWORK,
        "framework_version": _FRAMEWORK_VERSION,
        "taxonomy_url": _TAXONOMY_URL,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "coverage_score_pct": coverage_pct,
            "risks_fully_covered": len(full),
            "risks_partially_covered": len(partial),
            "risks_not_covered": len(none_),
            "total_risks": len(_RISKS),
        },
        "risks": risks_out,
    }
