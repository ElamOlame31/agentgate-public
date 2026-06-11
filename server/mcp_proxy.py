"""
AgentGate MCP Authorization Proxy

Drop-in HTTP proxy that sits between any LLM agent and any MCP server.
Every tools/call and resources/read is intercepted, submitted to AgentGate
for authorization, then forwarded (PERMIT) or blocked (DENY/ESCALATE) before
the upstream MCP server ever sees the request.

On the RESPONSE side the proxy now scans tool output for MCP tool poisoning
before handing it back to the agent:

  INSTRUCTION_TAG / IMPERATIVE_INJECT in the tool response → hard block.
    A legitimate file reader does not instruct the LLM to "ignore previous
    instructions". This is the canonical tool-poisoning attack vector.

  CREDENTIAL_LEAK / PII / EXFIL_URL in the tool response → redact in place.
    The upstream tool leaked sensitive material (possibly unintentionally).
    The agent receives the response with threats replaced by [REDACTED:…].

Architecture:
  Agent → MCP Proxy (this) → AgentGate /authorize → Upstream MCP Server
                           ← scan response ←

Configuration (env vars):
  AGENTGATE_URL          AgentGate PDP base URL       (default: http://localhost:8000)
  AGENTGATE_API_KEY      API key for AgentGate         (default: empty — dev mode)
  MCP_UPSTREAM_URL       Upstream MCP server URL       (required)
  MCP_PROXY_PORT         Port this proxy listens on    (default: 8001)

Per-request identity (set by the LLM agent via request headers, stripped before forwarding):
  X-AgentGate-Agent-Id   Registered AgentGate agent ID
  X-AgentGate-Token      JWT token issued at registration
  X-AgentGate-Purpose    Optional justification for this request

JSON-RPC methods intercepted:
  tools/call       → action=<tool_name>, resource=/tools/<tool_name>
  resources/read   → action=read,        resource=<uri>

All other MCP methods are forwarded transparently.
"""

import json
import os
import sys

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

AGENTGATE_URL = os.getenv("AGENTGATE_URL", "http://localhost:8000").rstrip("/")
AGENTGATE_API_KEY = os.getenv("AGENTGATE_API_KEY", "")
MCP_UPSTREAM_URL = os.getenv("MCP_UPSTREAM_URL", "").rstrip("/")

app = FastAPI(title="AgentGate MCP Proxy", version="1.2.0")

# Methods that require AgentGate authorization before forwarding
_INTERCEPTED = {"tools/call", "resources/read"}

# Methods where the proxy scans the RESPONSE (forwarded first, scanned before returning)
_RESPONSE_SCANNED = {"tools/list"}

# Threat categories that indicate active tool poisoning — hard block.
# A file-reader or search tool has no legitimate reason to include LLM
# control tags or imperative redirect phrases in its output.
_POISON_CATEGORIES = frozenset({"INSTRUCTION_TAG", "IMPERATIVE_INJECT"})

# Threat categories to redact in place rather than block entirely.
# These may be accidental (e.g., a code snippet that contains an API key).
_REDACT_CATEGORIES = frozenset({"CREDENTIAL_LEAK", "PII", "EXFIL_URL"})


def _jsonrpc_error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _extract_auth_target(method: str, params: dict) -> tuple[str, str]:
    """
    Map an MCP method + params to (action, resource) for AgentGate.

    tools/call   → action=<tool_name>, resource=/tools/<tool_name>
    resources/read → action=read,     resource=<uri from params>
    """
    if method == "tools/call":
        tool_name = (params or {}).get("name", "unknown_tool")
        return tool_name, f"/tools/{tool_name}"
    if method == "resources/read":
        uri = (params or {}).get("uri", "/resources/unknown")
        return "read", uri
    return method, "/"


async def _authorize(
    agent_id: str,
    token: str,
    action: str,
    resource: str,
    justification: str = "",
) -> tuple[str, str]:
    """
    Call AgentGate /authorize. Returns (decision, explanation).
    decision is one of: PERMIT, DENY, ESCALATE, PENDING
    """
    headers = {"Content-Type": "application/json"}
    if AGENTGATE_API_KEY:
        headers["X-API-Key"] = AGENTGATE_API_KEY

    payload = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "token": token,
        "justification": justification,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{AGENTGATE_URL}/authorize", json=payload, headers=headers)
    data = resp.json()
    return data.get("decision", "DENY"), data.get("explanation", "")


async def _forward(request_body: dict, strip_headers: dict) -> dict:
    """Forward JSON-RPC payload to upstream MCP server, return the JSON-RPC response."""
    if not MCP_UPSTREAM_URL:
        return _jsonrpc_error(
            request_body.get("id"), -32000,
            "MCP_UPSTREAM_URL not configured — set it in the environment"
        )
    # Forward all original headers except the AgentGate identity headers
    forward_headers = {"Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(MCP_UPSTREAM_URL, json=request_body, headers=forward_headers)
    try:
        return resp.json()
    except Exception:
        return _jsonrpc_error(request_body.get("id"), -32000, "Upstream returned non-JSON response")


# ── MCP tool poisoning detection ───────────────────────────────────────────────

def _extract_mcp_text(result: dict) -> list[tuple[str, str, int]]:
    """
    Extract (location_key, field, index) tuples identifying text in an MCP result.
    Returns list of (text_value, location_path) so we can replace in-place.

    tools/call → result.content[i].text   (type=="text")
    resources/read → result.contents[i].text
    """
    extracts: list[tuple[str, str, int]] = []  # (text, "content"|"contents", index)
    for i, item in enumerate(result.get("content") or []):
        if isinstance(item, dict) and item.get("type") == "text":
            extracts.append((item.get("text", ""), "content", i))
    for i, item in enumerate(result.get("contents") or []):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            extracts.append((item.get("text", ""), "contents", i))
    return extracts


def _scan_tool_response(mcp_result: dict) -> tuple[dict, bool, str, list]:
    """
    Scan the MCP tool response for injection and data-exposure threats.

    Returns:
      (result, blocked, reason, threat_categories)
      - result: original or redacted mcp_result dict
      - blocked: True if the response must be suppressed entirely
      - reason: human-readable explanation of what was found
      - threat_categories: list of detected category strings
    """
    try:
        from core.output_sanitizer import sanitize as _sanitize
    except ImportError:
        # Not co-located with AgentGate core — skip scanning
        return mcp_result, False, "", []

    extracts = _extract_mcp_text(mcp_result)
    if not extracts:
        return mcp_result, False, "", []

    all_threats = []
    poison_count = 0
    redact_count = 0

    for text, loc, idx in extracts:
        if not text:
            continue
        scan = _sanitize(text)
        if not scan.threats:
            continue
        poison = [t for t in scan.threats if t.category in _POISON_CATEGORIES]
        redact = [t for t in scan.threats if t.category in _REDACT_CATEGORIES]
        all_threats.extend(scan.threats)
        if poison:
            poison_count += len(poison)
        if redact:
            redact_count += len(redact)

    if not all_threats:
        return mcp_result, False, "", []

    categories = list(dict.fromkeys(t.category for t in all_threats))  # dedup, preserve order

    if poison_count:
        reason = (
            f"MCP tool poisoning detected: {poison_count} injection pattern(s) "
            f"in tool response [{', '.join(categories)}]"
        )
        return mcp_result, True, reason, categories

    # Only redactable threats — apply in-place redaction
    import copy
    result_copy = copy.deepcopy(mcp_result)
    for text, loc, idx in extracts:
        if not text:
            continue
        scan = _sanitize(text)
        if scan.threats:
            if loc == "content" and result_copy.get("content"):
                result_copy["content"][idx]["text"] = scan.sanitized
            elif loc == "contents" and result_copy.get("contents"):
                result_copy["contents"][idx]["text"] = scan.sanitized

    reason = (
        f"Tool response redacted: {redact_count} sensitive item(s) removed "
        f"[{', '.join(categories)}]"
    )
    return result_copy, False, reason, categories


async def _report_to_agentgate(
    agent_id: str,
    token: str,
    tool_name: str,
    reason: str,
    blocked: bool,
    threat_categories: list,
) -> None:
    """
    Fire-and-forget: report the tool poisoning event to AgentGate for audit
    and dashboard broadcast. Failures are silently swallowed.
    """
    try:
        headers = {"Content-Type": "application/json"}
        if AGENTGATE_API_KEY:
            headers["X-API-Key"] = AGENTGATE_API_KEY
        payload = {
            "agent_id": agent_id,
            "token": token,
            "content": (
                f"[MCP_TOOL_POISON:{'BLOCKED' if blocked else 'REDACTED'}] "
                f"tool={tool_name} categories={','.join(threat_categories)} {reason}"
            ),
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{AGENTGATE_URL}/sanitize", json=payload, headers=headers)
    except Exception:
        pass  # logging failure must not affect proxy operation


@app.post("/")
async def mcp_proxy(request: Request):
    # Extract AgentGate identity headers (stripped before forwarding)
    agent_id = request.headers.get("X-AgentGate-Agent-Id", "")
    token = request.headers.get("X-AgentGate-Token", "")
    justification = request.headers.get("X-AgentGate-Purpose", "")

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_jsonrpc_error(None, -32700, "Parse error — invalid JSON"))

    method = body.get("method", "")
    req_id = body.get("id")

    # tools/list: forward first, then scan the response for descriptor
    # poisoning and rug-pull mutations before returning to the agent.
    if method in _RESPONSE_SCANNED:
        upstream = await _forward(body, {})
        rpc_result = upstream.get("result")
        if isinstance(rpc_result, dict):
            try:
                from core.mcp_descriptor_guard import scan_tool_descriptions
                safe_result, reason, categories = scan_tool_descriptions(
                    rpc_result, MCP_UPSTREAM_URL
                )
                if safe_result is None:
                    print(
                        f"[AgentGate MCP] DESCRIPTOR_THREAT BLOCKED — "
                        f"upstream={MCP_UPSTREAM_URL} categories={categories}",
                        flush=True,
                    )
                    import asyncio
                    asyncio.create_task(
                        _report_to_agentgate(
                            agent_id or "unknown", token or "", method,
                            reason, True, categories,
                        )
                    )
                    return JSONResponse(
                        _jsonrpc_error(req_id, -32009, f"DESCRIPTOR_THREAT_BLOCKED: {reason}")
                    )
            except Exception as exc:
                # Guard failure must never silently pass poisoned descriptions —
                # fail closed: block the response so the agent cannot proceed with
                # unverified tool descriptions.
                print(
                    f"[AgentGate MCP] descriptor guard error (fail-closed): {exc}",
                    flush=True,
                )
                return JSONResponse(
                    _jsonrpc_error(req_id, -32000,
                                   f"Descriptor guard error — tools/list blocked: {exc}")
                )
        return JSONResponse(upstream)

    # Pass through non-intercepted methods immediately
    if method not in _INTERCEPTED:
        result = await _forward(body, {})
        return JSONResponse(result)

    # Require identity for intercepted methods
    if not agent_id or not token:
        return JSONResponse(
            _jsonrpc_error(
                req_id, -32001,
                "AgentGate identity required: set X-AgentGate-Agent-Id and X-AgentGate-Token headers"
            )
        )

    params = body.get("params") or {}
    action, resource = _extract_auth_target(method, params)

    try:
        decision, explanation = await _authorize(agent_id, token, action, resource, justification)
    except Exception as exc:
        # AgentGate unreachable — fail closed (deny by default)
        return JSONResponse(
            _jsonrpc_error(
                req_id, -32000,
                f"AgentGate authorization service unreachable — request blocked: {exc}"
            )
        )

    if decision == "PERMIT":
        upstream = await _forward(body, {})

        # ── MCP tool poisoning scan ────────────────────────────────────────────
        rpc_result = upstream.get("result")
        if isinstance(rpc_result, dict):
            scanned_result, blocked, reason, categories = _scan_tool_response(rpc_result)
            if reason:
                # Report to AgentGate asynchronously (dashboard + audit log)
                import asyncio
                asyncio.create_task(
                    _report_to_agentgate(agent_id, token, action, reason, blocked, categories)
                )
            if blocked:
                print(
                    f"[AgentGate MCP] TOOL_POISONING BLOCKED — agent={agent_id} "
                    f"tool={action} categories={categories}",
                    flush=True,
                )
                return JSONResponse(
                    _jsonrpc_error(req_id, -32008, f"TOOL_POISONING_BLOCKED: {reason}")
                )
            if reason:
                # Redacted — return the sanitized response with a warning header
                print(
                    f"[AgentGate MCP] TOOL_RESPONSE REDACTED — agent={agent_id} "
                    f"tool={action} categories={categories}",
                    flush=True,
                )
                response = JSONResponse({**upstream, "result": scanned_result})
                response.headers["X-AgentGate-Redacted"] = reason
                return response
        # ── End tool poisoning scan ───────────────────────────────────────────

        return JSONResponse(upstream)

    # DENY / ESCALATE / PENDING → block with JSON-RPC error
    code_map = {"DENY": -32002, "ESCALATE": -32003, "PENDING": -32004}
    msg = f"AgentGate {decision}: {explanation}"
    return JSONResponse(_jsonrpc_error(req_id, code_map.get(decision, -32002), msg))


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "agentgate_url": AGENTGATE_URL,
        "upstream_configured": bool(MCP_UPSTREAM_URL),
        "tool_poisoning_scan": "enabled",
        "descriptor_guard": "enabled",
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("MCP_PROXY_PORT", 8001))
    uvicorn.run("server.mcp_proxy:app", host="0.0.0.0", port=port, reload=False)
