"""
Fail-mode configuration for the AgentGate authorization pipeline.

Controls what happens when the trust-scoring pipeline raises an unexpected
exception inside /authorize:

  AGENTGATE_FAIL_MODE=closed  (default)
      Return DENY with FAIL_CLOSED attack flag.  Safe for production.
      Authorization infrastructure must never grant access as a side-effect
      of its own failure.

  AGENTGATE_FAIL_MODE=open
      Re-raise the exception so FastAPI returns HTTP 500.
      Use only in development to surface pipeline errors in logs.

The CISA/NSA joint guidance on securing agentic AI (May 2026) and the EU AI
Act Article 9 (risk management) both require fail-safe defaults for systems
that make authorization decisions on behalf of automated processes.  The
closed default satisfies that requirement without additional operator config.
"""

import os

FAIL_CLOSED_FLAG = "FAIL_CLOSED"
FAIL_CLOSED_EXPLANATION = (
    "Authorization denied: internal error in trust-scoring pipeline. "
    "The system failed closed (safe default). "
    "Check server logs for details. "
    "Set AGENTGATE_FAIL_MODE=open only for debugging."
)


def is_fail_closed() -> bool:
    """
    Return True if /authorize should DENY on any internal pipeline error.
    Return False only when AGENTGATE_FAIL_MODE=open is explicitly set.

    Reading from the environment at call time (not module load time) lets
    tests override the value without reimporting the module.
    """
    return os.getenv("AGENTGATE_FAIL_MODE", "closed").lower().strip() != "open"
