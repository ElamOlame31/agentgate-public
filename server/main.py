import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import hmac
import json
import posixpath
import re
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

load_dotenv()

# ── API Key Auth ─────────────────────────────────────────────────────────────

def _get_api_key() -> str | None:
    key = os.getenv("AGENTGATE_API_KEY", "").strip()
    env = os.getenv("AGENTGATE_ENV", "development").lower()
    if not key:
        if env != "development":
            raise RuntimeError(
                "AGENTGATE_API_KEY is required when AGENTGATE_ENV != development. "
                "Set AGENTGATE_ENV=development only for local-only testing."
            )
        return None
    if len(key) < 24:
        raise RuntimeError("AGENTGATE_API_KEY must be at least 24 characters")
    return key


def _get_admin_key() -> str | None:
    key = os.getenv("AGENTGATE_ADMIN_KEY", "").strip()
    return key or None


async def require_api_key(request: Request):
    api_key = _get_api_key()
    if api_key is None:
        return  # auth disabled — development mode only
    provided = request.headers.get("X-API-Key", "") or request.query_params.get("key", "")
    if not hmac.compare_digest(provided, api_key):
        client = request.client.host if request.client else "unknown"
        print(f"[AgentGate] AUTH FAIL — {request.method} {request.url.path} from {client}", flush=True)
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


async def require_admin_key(request: Request):
    """
    Approval/deny endpoints require a separate admin credential.
    If AGENTGATE_ADMIN_KEY is set, it must be provided as X-Admin-Key header or admin_key param.
    If not set, falls back to AGENTGATE_API_KEY so existing single-key setups keep working.
    """
    admin_key = _get_admin_key()
    if admin_key is not None:
        provided = request.headers.get("X-Admin-Key", "") or request.query_params.get("admin_key", "")
        if not hmac.compare_digest(provided, admin_key):
            raise HTTPException(status_code=401, detail="Invalid or missing admin key.")
    else:
        # Fall back to API key check so single-key dev setups are not broken
        await require_api_key(request)


from core.models import (
    AgentRegistration, AuthorizationRequest, AuthorizationResponse, Decision,
    ContentScanRequest, ContentScanResponse, OutputSanitizeRequest,
)
from core import audit, trust_engine, latency as _latency
from core.audit import hash_token
from core.token import (
    issue_agent_token, verify_agent_jwt, get_public_key_pem,
    is_jwt_format, is_jti,
)
import jwt as _jwt
from core.explainer import generate_explanation
from core.policy_engine import (
    create_policy, get_all_policies, delete_policy,
    check_policies, Policy, init_policy_table
)
from core.alerts import (
    fire_alert, fire_siem_event, fire_approval_request,
    alerts_configured, alert_status, siem_configured, siem_status,
)
from core.report import generate_pdf, generate_csv
from core import approvals
from core import quarantine as _quarantine
from core import contagion as _contagion
from core.delegation import validate_delegation, chain_summary, MAX_DELEGATION_DEPTH

# Persistent agent registry (loaded from SQLite on startup)
_agents: dict[str, AgentRegistration] = {}

# Recent scan results per agent — used to link /scan stage into /authorize
# { agent_id: { "score": float, "level": str, "ts": float } }
_recent_scans: dict[str, dict] = {}
_SCAN_TTL = 120.0  # seconds before a scan result expires


_MAX_WS_CONNECTIONS = 100


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> bool:
        if len(self._connections) >= _MAX_WS_CONNECTIONS:
            await ws.close(code=1008, reason="Server at capacity")
            return False
        await ws.accept()
        self._connections.append(ws)
        return True

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        msg = json.dumps(data)
        for ws in self._connections:
            try:
                # Timeout prevents a slow or stalled client from blocking all broadcasts.
                await asyncio.wait_for(ws.send_text(msg), timeout=5.0)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


manager = ConnectionManager()


async def _ws_broadcast(data: dict):
    await manager.broadcast(data)


async def _periodic_cleanup():
    import asyncio
    while True:
        await asyncio.sleep(3600)
        await asyncio.to_thread(audit.cleanup_old_history, max_age_seconds=3600.0)
        await asyncio.to_thread(audit.cleanup_old_audit_log)
        # Evict expired scan results to prevent unbounded memory growth
        now = time.time()
        expired = [aid for aid, s in _recent_scans.items() if now - s["ts"] > _SCAN_TTL]
        for aid in expired:
            _recent_scans.pop(aid, None)
        # Evict resolved approval records older than 1 hour
        approvals.cleanup_resolved(max_age_seconds=3600.0)
        # Prune expired quarantine rows from SQLite
        await asyncio.to_thread(audit.cleanup_expired_quarantines)
        # Seal any full Merkle batches accumulated since last cycle
        await asyncio.to_thread(audit.seal_merkle_batch)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import asyncio
    audit.init_db()
    await asyncio.to_thread(audit.cleanup_old_history, max_age_seconds=3600.0)
    await asyncio.to_thread(audit.cleanup_old_audit_log)
    await asyncio.to_thread(audit.cleanup_expired_quarantines)
    await asyncio.to_thread(audit.cleanup_old_request_history)
    init_policy_table()
    _agents.update(audit.load_all_agents())
    _quarantine.load_from_persistence(audit.load_active_quarantines())
    approvals.set_broadcast_callback(_ws_broadcast)
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    api_key = _get_api_key()
    admin_key = _get_admin_key()
    if api_key:
        print("[AgentGate] Auth ON  — API key required on all endpoints")
        if admin_key:
            print("[AgentGate] Admin key configured — approval endpoints require X-Admin-Key")
        else:
            print("[AgentGate] WARNING — AGENTGATE_ADMIN_KEY not set; approval endpoints use API key (set it to prevent self-approval)")
    else:
        print("[AgentGate] Auth OFF — set AGENTGATE_API_KEY in .env to enable")
    if alerts_configured():
        print(f"[AgentGate] Alerts ON -> {alert_status()}")
    else:
        print("[AgentGate] Alerts OFF — set AGENTGATE_ALERT_TOPIC in .env to enable")
    if siem_configured():
        for dest in siem_status():
            print(f"[AgentGate] SIEM ON -> {dest}")
    else:
        print("[AgentGate] SIEM OFF — set AGENTGATE_SPLUNK_HEC_URL or AGENTGATE_SENTINEL_WORKSPACE_ID to enable")
    yield
    # Drain the async audit write queue before shutdown so in-flight entries are persisted.
    await asyncio.to_thread(audit.flush_audit_queue)
    cleanup_task.cancel()


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="AgentGate PDP", version="0.2.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    lambda req, exc: JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}),
)
app.add_middleware(SlowAPIMiddleware)

_ALLOWED_ORIGINS = [o.strip() for o in os.getenv("AGENTGATE_CORS_ORIGINS", "http://localhost:8000").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type"],
)


_CSP = (
    "default-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
    "font-src https://fonts.gstatic.com; "
    "connect-src 'self' ws: wss:; "
    "script-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["Server"] = "AgentGate"
    # HSTS: instruct browsers to enforce HTTPS-only for 1 year.
    # Only meaningful when deployed behind TLS — harmless in plain HTTP dev.
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ── Health ──────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "alerts": alert_status(),
        "siem": siem_status() or "not configured",
    }


@app.get("/metrics", dependencies=[Depends(require_api_key)])
async def get_metrics():
    """
    Live latency percentiles (p50/p95/p99) per authorization pipeline stage.

    Metrics are computed from the last 1 000 observations per component and
    reset on server restart (in-memory only — nothing written to disk).

    Components:
      total        — end-to-end /authorize latency (ms)
      trust        — 4-D trust scoring (SQLite queries + scoring)
      policy       — NL policy hard-block check
      audit_write  — audit log enqueue
    """
    return {"latency_ms": _latency.all_stats()}


# ── Agent Registration ──────────────────────────────────────────────────────

_RESERVED_IDS = {"admin", "system", "root", "agentgate", "superuser", "anonymous", "null", "undefined"}
_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]{3,64}$')


@app.post("/agents/register", response_model=dict, dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def register_agent(request: Request, reg: AgentRegistration):
    if not _AGENT_ID_RE.match(reg.agent_id):
        raise HTTPException(status_code=400, detail="agent_id must be 3-64 chars, alphanumeric/hyphens/underscores only")
    if reg.agent_id.lower() in _RESERVED_IDS:
        raise HTTPException(status_code=400, detail=f"agent_id '{reg.agent_id}' is reserved")
    if reg.agent_id in _agents:
        raise HTTPException(status_code=409, detail=f"Agent '{reg.agent_id}' already registered")
    # Server always controls these fields — never trust client-supplied values.
    # Allowing clients to set delegated_by/token would let anyone forge a delegation chain.
    reg.delegated_by = None
    reg.delegation_depth = 0
    reg.scope_at_delegation = None
    jwt_token, jti, expires_at = issue_agent_token(
        agent_id=reg.agent_id,
        declared_purpose=reg.declared_purpose,
        authorized_resources=reg.authorized_resources,
        authorized_actions=reg.authorized_actions,
    )
    reg.token = jti               # store JTI (UUID), verified against JWT claim on auth
    reg.token_expires_at = expires_at
    _agents[reg.agent_id] = reg
    audit.save_agent(reg)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    return {"agent_id": reg.agent_id, "token": jwt_token, "status": "registered"}


@app.get("/agents", response_model=list, dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def list_agents(request: Request):
    return _agent_list()


class DelegationRequest(BaseModel):
    parent_agent_id: str
    parent_token: str
    child_agent_id: str
    child_name: str = Field(max_length=128)
    child_declared_purpose: str = Field(max_length=500)
    child_resources: list[str] = Field(max_length=100)
    child_actions: list[str] = Field(max_length=50)


@app.post("/agents/delegate", response_model=dict, dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def delegate_agent(request: Request, req: DelegationRequest):
    if req.parent_agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Parent agent not found")

    if req.parent_agent_id == req.child_agent_id:
        raise HTTPException(status_code=400, detail="Cannot delegate to self")

    if not _AGENT_ID_RE.match(req.child_agent_id):
        raise HTTPException(status_code=400, detail="child_agent_id must be 3-64 chars, alphanumeric/hyphens/underscores only")
    if req.child_agent_id.lower() in _RESERVED_IDS:
        raise HTTPException(status_code=400, detail=f"child_agent_id '{req.child_agent_id}' is reserved")
    if req.child_agent_id in _agents:
        raise HTTPException(status_code=409, detail=f"Agent '{req.child_agent_id}' already exists")

    parent = _agents[req.parent_agent_id]

    if parent.token:
        if is_jti(parent.token):
            # JWT path: verify signature, then match jti claim
            if not is_jwt_format(req.parent_token):
                raise HTTPException(status_code=401, detail="Invalid parent agent token")
            try:
                claims = verify_agent_jwt(req.parent_token)
            except _jwt.InvalidTokenError:
                raise HTTPException(status_code=401, detail="Invalid parent agent token")
            if not hmac.compare_digest(claims.get("jti", ""), parent.token):
                raise HTTPException(status_code=401, detail="Invalid parent agent token")
        else:
            # Legacy path: SHA-256 hash compare
            if not hmac.compare_digest(hash_token(req.parent_token), parent.token):
                raise HTTPException(status_code=401, detail="Invalid parent agent token")

    if parent.delegation_depth >= MAX_DELEGATION_DEPTH:
        raise HTTPException(
            status_code=400,
            detail=f"Max delegation depth ({MAX_DELEGATION_DEPTH}) reached — chain too deep"
        )

    valid, error = validate_delegation(
        parent.authorized_resources, parent.authorized_actions,
        req.child_resources, req.child_actions,
    )
    if not valid:
        raise HTTPException(status_code=400, detail=f"Scope violation: {error}")

    # Trust ceiling: child inherits the parent's current trust baseline as its ceiling.
    # If the parent has no baseline yet, default to 80.0 — conservative but not punishing.
    parent_baseline = audit.get_agent_baseline(req.parent_agent_id)
    parent_trust_score = parent_baseline["avg_rpm"] if parent_baseline else None
    # avg_rpm is a velocity metric, not a 0-100 score. Use parent's trust_ceiling if set,
    # otherwise cap the child at 80 to enforce conservative delegation by default.
    child_trust_ceiling = min(
        parent.trust_ceiling if parent.trust_ceiling is not None else 80.0,
        80.0,
    )

    child_depth = parent.delegation_depth + 1
    child_jwt, child_jti, child_expires_at = issue_agent_token(
        agent_id=req.child_agent_id,
        declared_purpose=req.child_declared_purpose,
        authorized_resources=req.child_resources,
        authorized_actions=req.child_actions,
        delegation_depth=child_depth,
        delegated_by=req.parent_agent_id,
    )
    child = AgentRegistration(
        agent_id=req.child_agent_id,
        name=req.child_name,
        declared_purpose=req.child_declared_purpose,
        authorized_resources=req.child_resources,
        authorized_actions=req.child_actions,
        delegated_by=req.parent_agent_id,
        delegation_depth=child_depth,
        scope_at_delegation=parent.authorized_actions,
        token=child_jti,
        token_expires_at=child_expires_at,
        trust_ceiling=child_trust_ceiling,
    )
    _agents[child.agent_id] = child
    audit.save_agent(child)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    print(
        f"[AgentGate] Delegated: {req.parent_agent_id} -> {req.child_agent_id} "
        f"(depth {child.delegation_depth})",
        flush=True
    )
    return {
        "agent_id": child.agent_id,
        "token": child_jwt,
        "delegation_depth": child.delegation_depth,
        "delegated_by": child.delegated_by,
        "status": "delegated",
    }


@app.delete("/agents/{agent_id}", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def deregister_agent(request: Request, agent_id: str):
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    del _agents[agent_id]
    audit.delete_agent(agent_id)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    return {"status": "deregistered"}


@app.get("/agents/public-key", dependencies=[Depends(require_api_key)])
async def public_key():
    """Return the server's Ed25519 public key in PEM format for offline token verification."""
    return {"public_key_pem": get_public_key_pem(), "algorithm": "EdDSA"}


@app.post("/agents/{agent_id}/revoke", dependencies=[Depends(require_api_key)])
@limiter.limit("20/minute")
async def revoke_agent(request: Request, agent_id: str):
    """Revoke a single agent's token — the agent remains registered but its JWT is invalidated."""
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent = _agents[agent_id]
    # Issue a tombstone: clear token so every future auth fails with 401
    agent.token = None
    agent.token_expires_at = None
    _agents[agent_id] = agent
    audit.save_agent(agent)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    print(f"[AgentGate] REVOKED token for {agent_id}", flush=True)
    return {"status": "revoked", "agent_id": agent_id}


@app.post("/agents/{agent_id}/revoke_chain", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def revoke_agent_chain(request: Request, agent_id: str):
    """
    Atomically revoke an agent and every descendant that delegated from it.
    Walks the delegated_by pointers to find all children. Returns the list of revoked agents.
    """
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")

    # BFS: collect the agent + all descendants
    to_revoke: list[str] = []
    queue: list[str] = [agent_id]
    while queue:
        current = queue.pop(0)
        to_revoke.append(current)
        children = [aid for aid, a in _agents.items() if a.delegated_by == current]
        queue.extend(children)

    for aid in to_revoke:
        agent = _agents[aid]
        agent.token = None
        agent.token_expires_at = None
        _agents[aid] = agent
        audit.save_agent(agent)

    await manager.broadcast({"type": "agents", "data": _agent_list()})
    print(
        f"[AgentGate] REVOKE_CHAIN: {agent_id} + {len(to_revoke)-1} descendants revoked",
        flush=True,
    )
    return {
        "status": "revoked",
        "root": agent_id,
        "revoked": to_revoke,
        "count": len(to_revoke),
    }


# ── Quarantine Endpoints ────────────────────────────────────────────────────

@app.get("/quarantines", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def list_quarantines(request: Request):
    """List all active quarantines."""
    return _quarantine.get_all()


@app.get("/agents/{agent_id}/quarantine", dependencies=[Depends(require_api_key)])
async def get_quarantine(agent_id: str):
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    rec = _quarantine.get_record(agent_id)
    if rec is None:
        return {"quarantined": False, "agent_id": agent_id}
    return {"quarantined": True, **rec.to_dict()}


class QuarantineManualRequest(BaseModel):
    trigger: str = "MANUAL"
    permanent: bool = False


@app.post("/agents/{agent_id}/quarantine", dependencies=[Depends(require_admin_key)])
@limiter.limit("20/minute")
async def quarantine_agent(request: Request, agent_id: str, body: QuarantineManualRequest):
    """Manually quarantine an agent (admin only)."""
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    rec = _quarantine.quarantine(agent_id, body.trigger, permanent=body.permanent)
    await asyncio.to_thread(audit.save_quarantine, rec)
    await manager.broadcast({"type": "quarantine", "data": {"event": "manual", **rec.to_dict()}})
    print(f"[AgentGate] MANUAL QUARANTINE {agent_id} trigger={body.trigger}", flush=True)
    _affected = _contagion.propagate_quarantine(agent_id, _agents)
    if _affected:
        await manager.broadcast({
            "type": "contagion",
            "data": {"source_agent_id": agent_id, "affected_agent_ids": _affected, "trigger": body.trigger},
        })
    return rec.to_dict()


@app.delete("/agents/{agent_id}/quarantine", dependencies=[Depends(require_admin_key)])
@limiter.limit("20/minute")
async def release_quarantine(request: Request, agent_id: str):
    """Release an agent from quarantine (admin only)."""
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    released = _quarantine.release(agent_id)
    if not released:
        raise HTTPException(status_code=404, detail="Agent is not currently quarantined")
    await asyncio.to_thread(audit.delete_quarantine, agent_id)
    _contagion.clear_contagion(agent_id)
    await manager.broadcast({"type": "quarantine", "data": {"event": "released", "agent_id": agent_id}})
    print(f"[AgentGate] QUARANTINE RELEASED {agent_id}", flush=True)
    return {"status": "released", "agent_id": agent_id}


# ── Trust Contagion Endpoints ───────────────────────────────────────────────

@app.get("/contagion", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def list_contagion(request: Request):
    """Return all active contagion records (agents penalised due to a neighbour being quarantined)."""
    return _contagion.get_all()


@app.post("/agents/{agent_id}/contagion/clear", dependencies=[Depends(require_admin_key)])
@limiter.limit("20/minute")
async def clear_agent_contagion(request: Request, agent_id: str):
    """Manually clear contagion penalties propagated FROM this agent (admin only)."""
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    _contagion.clear_contagion(agent_id)
    return {"status": "cleared", "agent_id": agent_id}


def _agent_list():
    quarantined_ids = {r["agent_id"] for r in _quarantine.get_all()}
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "declared_purpose": a.declared_purpose,
            "delegation_depth": a.delegation_depth,
            "delegated_by": a.delegated_by,
            "chain": chain_summary(a.agent_id, _agents),
            "quarantined": a.agent_id in quarantined_ids,
        }
        for a in _agents.values()
    ]


# ── Authorization (PDP) ─────────────────────────────────────────────────────

def _normalize_resource(resource: str) -> str:
    """
    Normalize a resource path before policy evaluation.

    Prevents scope bypass via URL-encoded traversal sequences like
    /reports/%2e%2e/confidential/ that evade the literal '..' check but
    resolve to an out-of-scope path after decoding.

    Steps:
      1. URL-decode (%2e%2e → .., %2F → /, etc.) — handles single and double encoding
      2. Strip null bytes
      3. Normalize path with posixpath (resolve .., collapse //, etc.)
      4. Guarantee a leading /
    """
    # Double-decode to catch %252e%252e → %2e%2e → ..
    decoded = urllib.parse.unquote(urllib.parse.unquote(resource))
    # Strip null bytes
    decoded = decoded.replace("\x00", "")
    # Normalize (resolves .., //, ./ etc.) — posixpath is OS-independent
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


@app.post("/authorize", response_model=AuthorizationResponse, dependencies=[Depends(require_api_key)])
@limiter.limit("200/minute")
async def authorize(request: Request, body: AuthorizationRequest):
    _t_authorize_start = time.monotonic()
    # Always generate server-side — client-supplied IDs would allow audit log
    # manipulation and replay attacks via predictable or colliding request IDs.
    body.request_id = str(uuid.uuid4())

    # Reject traversal attempts before normalization — check the decoded raw input
    # so encoded variants (%2e%2e, %252e%252e, etc.) are all caught.
    _raw_decoded = urllib.parse.unquote(urllib.parse.unquote(body.resource)).replace("\x00", "")
    if ".." in _raw_decoded:
        raise HTTPException(status_code=400, detail="Resource path traversal not allowed")

    # Normalize resource path — resolves URL-encoded sequences, collapses //, etc.
    body.resource = _normalize_resource(body.resource)

    # Unknown agent → deny immediately
    if body.agent_id not in _agents:
        response = _build_unknown_agent_response(body)
        audit.log_decision_queued(response, False)
        await manager.broadcast({"type": "decision", "data": response.model_dump()})
        return response

    agent = _agents[body.agent_id]

    # ── Token validation ──────────────────────────────────────────────────
    # token=None means the agent was explicitly revoked — deny immediately.
    if agent.token is None:
        raise HTTPException(status_code=401, detail="Agent token has been revoked")

    if agent.token:
        if is_jti(agent.token):
            # JWT path: verify signature + claims, then match stored jti
            incoming = body.token or ""
            if not is_jwt_format(incoming):
                raise HTTPException(status_code=401, detail="Invalid agent token")
            try:
                claims = verify_agent_jwt(incoming)
            except _jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Agent token expired — re-register")
            except _jwt.InvalidTokenError:
                raise HTTPException(status_code=401, detail="Invalid agent token")
            if not hmac.compare_digest(claims.get("jti", ""), agent.token):
                raise HTTPException(status_code=401, detail="Invalid agent token")
        else:
            # Legacy path: SHA-256 hash compare
            if not hmac.compare_digest(hash_token(body.token or ""), agent.token):
                raise HTTPException(status_code=401, detail="Invalid agent token")
            if agent.token_expires_at and time.time() > agent.token_expires_at:
                raise HTTPException(status_code=401, detail="Agent token expired — re-register")

    # ── Quarantine check — hard block before scoring ──────────────────────
    q_record = _quarantine.get_record(body.agent_id)
    if q_record:
        from core.models import TrustBreakdown, ResourceSensitivity
        from core.trust_engine import classify_resource_sensitivity, SENSITIVITY_THRESHOLDS
        sensitivity = classify_resource_sensitivity(body.resource, body.action)
        breakdown = TrustBreakdown(
            identity_score=0, delegation_score=0,
            purpose_alignment_score=0, behavioral_score=0,
            resource_sensitivity=sensitivity,
            final_score=0, threshold_required=SENSITIVITY_THRESHOLDS[sensitivity],
        )
        remaining = int(q_record.remaining_seconds())
        response = AuthorizationResponse(
            request_id=body.request_id,
            agent_id=body.agent_id,
            action=body.action,
            resource=body.resource,
            decision=Decision.DENY,
            trust_breakdown=breakdown,
            explanation=(
                f"Agent quarantined — all actions blocked for {remaining}s. "
                f"Trigger: {q_record.trigger}. "
                f"Release via dashboard or DELETE /agents/{body.agent_id}/quarantine."
            ),
            attack_flags=["QUARANTINED", f"QUARANTINE_TRIGGER:{q_record.trigger}"],
        )
        audit.log_decision_queued(response)
        await manager.broadcast({"type": "decision", "data": response.model_dump()})
        fire_alert(
            "DENY", body.agent_id, body.action, body.resource,
            response.explanation, response.attack_flags, 0,
        )
        return response

    # ── Policy check FIRST (hard rules override trust score) ──────────────
    with _latency.measure("policy"):
        policy_match = check_policies(body.agent_id, body.action, body.resource)
    if policy_match.matched:
        response = _build_policy_blocked_response(body, agent, policy_match)
        audit.log_decision_queued(response)
        await manager.broadcast({"type": "decision", "data": response.model_dump()})
        fire_alert(
            response.decision.value, body.agent_id,
            body.action, body.resource,
            response.explanation, response.attack_flags,
            response.trust_breakdown.final_score,
        )
        fire_siem_event(
            response.decision.value, body.agent_id,
            body.action, body.resource,
            response.explanation, response.attack_flags,
            response.trust_breakdown.final_score,
            breakdown=response.trust_breakdown.model_dump(),
            request_id=response.request_id,
        )
        return response

    # ── Inline injection scan (when content is passed with the request) ────────
    # Agents with processes_external_content=True can submit the document/tool
    # output directly in the authorization request — no separate /scan call needed.
    if agent.processes_external_content and body.content:
        from core.injection_detector import scan_content as _scan_content
        scan_result = await asyncio.to_thread(_scan_content, body.content, agent.declared_purpose)
        _recent_scans[body.agent_id] = {
            "score": scan_result.confidence,
            "level": scan_result.level,
            "ts": time.time(),
        }
        await manager.broadcast({
            "type": "injection",
            "data": {
                "agent_id": body.agent_id,
                "level": scan_result.level,
                "confidence": scan_result.confidence,
                "evidence": scan_result.evidence,
                "timestamp": time.time(),
            }
        })
        if scan_result.level == "injection":
            from core.models import TrustBreakdown
            from core.trust_engine import classify_resource_sensitivity, SENSITIVITY_THRESHOLDS
            sensitivity = classify_resource_sensitivity(body.resource, body.action)
            breakdown = TrustBreakdown(
                identity_score=100, delegation_score=100,
                purpose_alignment_score=100, behavioral_score=0,
                resource_sensitivity=sensitivity,
                final_score=0, threshold_required=SENSITIVITY_THRESHOLDS[sensitivity],
            )
            response = AuthorizationResponse(
                request_id=body.request_id,
                agent_id=body.agent_id,
                action=body.action,
                resource=body.resource,
                decision=Decision.DENY,
                trust_breakdown=breakdown,
                explanation=f"Denied: injection detected in provided content (confidence {round(scan_result.confidence * 100)}%). {scan_result.evidence}",
                attack_flags=["INJECTION_DETECTED", f"INJECTION_CONFIDENCE:{round(scan_result.confidence * 100)}%"],
                injection_score=scan_result.confidence,
            )
            audit.log_decision_queued(response)
            await manager.broadcast({"type": "decision", "data": response.model_dump()})
            fire_alert(
                "DENY", body.agent_id, body.action, body.resource,
                response.explanation, response.attack_flags, 0,
            )
            fire_siem_event(
                "DENY", body.agent_id, body.action, body.resource,
                response.explanation, response.attack_flags, 0,
                breakdown=response.trust_breakdown.model_dump(),
                request_id=response.request_id,
            )
            return response

    # ── Trust scoring ──────────────────────────────────────────────────────
    # Pull injection risk from a recent /scan call for this agent (if any)
    injection_risk = 0.0
    recent_scan = _recent_scans.get(body.agent_id)
    if recent_scan and (time.time() - recent_scan["ts"]) < _SCAN_TTL and recent_scan["level"] != "clean":
        injection_risk = recent_scan["score"]

    # Trust contagion: apply penalty if a delegation neighbour is quarantined
    contagion_penalty, contagion_flags = _contagion.get_contagion_penalty(body.agent_id)

    # compute_trust calls SQLite (request history, baselines) — run in thread pool
    with _latency.measure("trust"):
        breakdown, flags = await asyncio.to_thread(
            trust_engine.compute_trust, agent, body, _agents, injection_risk,
            contagion_penalty, contagion_flags,
        )
    decision = trust_engine.make_decision(breakdown, flags)
    explanation = generate_explanation(
        agent.name, body.action, body.resource,
        breakdown, decision, flags
    )

    # ── Human-in-the-loop: pause ESCALATE for manual review ───────────────
    if decision == Decision.ESCALATE and agent.requires_human_approval:
        pending = approvals.create_pending(
            request_id=body.request_id,
            agent_id=body.agent_id,
            action=body.action,
            resource=body.resource,
            explanation=explanation,
            trust_score=breakdown.final_score,
        )
        await manager.broadcast({"type": "pending", "data": pending.to_dict()})
        fire_approval_request(
            body.request_id, body.agent_id,
            body.action, body.resource,
            explanation, breakdown.final_score,
        )
        response = AuthorizationResponse(
            request_id=body.request_id,
            agent_id=body.agent_id,
            action=body.action,
            resource=body.resource,
            decision=Decision.PENDING,
            trust_breakdown=breakdown,
            explanation=f"[PENDING HUMAN APPROVAL] {explanation}",
            attack_flags=flags,
            injection_score=injection_risk if injection_risk > 0 else None,
        )
        audit.log_decision_queued(response)
        return response

    response = AuthorizationResponse(
        request_id=body.request_id,
        agent_id=body.agent_id,
        action=body.action,
        resource=body.resource,
        decision=decision,
        trust_breakdown=breakdown,
        explanation=explanation,
        attack_flags=flags,
        injection_score=injection_risk if injection_risk > 0 else None,
    )

    # ── Quarantine triggers ────────────────────────────────────────────────
    if decision == Decision.DENY:
        q_trigger = _quarantine.should_quarantine_on_flags(flags)
        if q_trigger is None:
            q_trigger = _quarantine.record_deny(body.agent_id)
        if q_trigger:
            q_rec = _quarantine.quarantine(body.agent_id, q_trigger)
            await asyncio.to_thread(audit.save_quarantine, q_rec)
            print(
                f"[AgentGate] QUARANTINED {body.agent_id} "
                f"trigger={q_trigger} expires_in={int(q_rec.remaining_seconds())}s",
                flush=True,
            )
            await manager.broadcast({
                "type": "quarantine",
                "data": {
                    "event": "quarantined" if q_rec.violation_count == 1 else "extended",
                    **q_rec.to_dict(),
                },
            })
            # Propagate trust contagion to delegation neighbours
            _affected = _contagion.propagate_quarantine(body.agent_id, _agents)
            if _affected:
                print(
                    f"[AgentGate] CONTAGION propagated from {body.agent_id} "
                    f"to {_affected}",
                    flush=True,
                )
                await manager.broadcast({
                    "type": "contagion",
                    "data": {
                        "source_agent_id": body.agent_id,
                        "affected_agent_ids": _affected,
                        "trigger": q_trigger,
                    },
                })
            fire_alert(
                "QUARANTINE", body.agent_id, body.action, body.resource,
                f"Agent quarantined: {q_trigger}",
                ["QUARANTINED", f"QUARANTINE_TRIGGER:{q_trigger}"],
                0,
            )

    with _latency.measure("audit_write"):
        audit.log_decision_queued(response)
    await manager.broadcast({"type": "decision", "data": response.model_dump()})
    fire_alert(
        decision.value, body.agent_id,
        body.action, body.resource,
        explanation, flags,
        breakdown.final_score,
    )
    fire_siem_event(
        decision.value, body.agent_id,
        body.action, body.resource,
        explanation, flags,
        breakdown.final_score,
        breakdown=breakdown.model_dump(),
        request_id=body.request_id,
    )
    _latency.record("total", (time.monotonic() - _t_authorize_start) * 1000.0)
    return response


# ── Content Scan (Injection Detection) ─────────────────────────────────────

@app.post("/scan", response_model=ContentScanResponse, dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def scan_content_endpoint(request: Request, body: ContentScanRequest):
    from core.injection_detector import scan_content

    agent = _agents.get(body.agent_id)
    if agent is None:
        return ContentScanResponse(
            level="clean", confidence=0.0,
            evidence="Agent not registered — scan skipped",
            scanned=False,
        )

    result = scan_content(body.content, agent.declared_purpose)

    # Cache result so /authorize can factor in injection risk from this scan
    _recent_scans[body.agent_id] = {
        "score": result.confidence,
        "level": result.level,
        "ts": time.time(),
    }

    # Broadcast to dashboard
    await manager.broadcast({
        "type": "injection",
        "data": {
            "agent_id": body.agent_id,
            "level": result.level,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "timestamp": __import__("time").time(),
        }
    })

    # Fire alert on injection detection
    if result.level in ("injection", "suspicious"):
        fire_alert(
            "INJECTION_" + result.level.upper(),
            body.agent_id, "content_scan", "external_content",
            result.evidence, [f"INJECTION_{result.level.upper()}"],
            round(result.confidence * 100, 1),
        )

    return ContentScanResponse(
        level=result.level,
        confidence=result.confidence,
        evidence=result.evidence,
        scanned=True,
    )


# ── Output Sanitization ─────────────────────────────────────────────────────

@app.post("/sanitize", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def sanitize_output_endpoint(request: Request, body: OutputSanitizeRequest):
    """
    Scan agent-produced content for credential leaks, PII, instruction tags,
    imperative injection phrases, and exfiltration URLs. Returns a sanitized
    copy of the content with all findings redacted.
    """
    from core.output_sanitizer import sanitize as _sanitize

    agent = _agents.get(body.agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not registered")

    # Token validation — same guard as /authorize
    if agent.token is None:
        raise HTTPException(status_code=401, detail="Agent token has been revoked")
    if agent.token:
        if is_jti(agent.token):
            incoming = body.token or ""
            if not is_jwt_format(incoming):
                raise HTTPException(status_code=401, detail="Invalid agent token")
            try:
                claims = verify_agent_jwt(incoming)
            except _jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Agent token expired — re-register")
            except _jwt.InvalidTokenError:
                raise HTTPException(status_code=401, detail="Invalid agent token")
            if not hmac.compare_digest(claims.get("jti", ""), agent.token):
                raise HTTPException(status_code=401, detail="Invalid agent token")
        else:
            if not hmac.compare_digest(hash_token(body.token or ""), agent.token):
                raise HTTPException(status_code=401, detail="Invalid agent token")
            if agent.token_expires_at and time.time() > agent.token_expires_at:
                raise HTTPException(status_code=401, detail="Agent token expired — re-register")

    result = await asyncio.to_thread(_sanitize, body.content)
    request_id = str(uuid.uuid4())
    ts = time.time()

    threat_dicts = [
        {
            "category":    t.category,
            "subcategory": t.subcategory,
            "severity":    t.severity,
            "excerpt":     t.excerpt,
        }
        for t in result.threats
    ]

    await manager.broadcast({
        "type": "sanitize",
        "data": {
            "request_id":         request_id,
            "agent_id":           body.agent_id,
            "threat_count":       result.threat_count,
            "highest_severity":   result.highest_severity,
            "categories_detected": result.categories_detected,
            "original_length":    result.original_length,
            "timestamp":          ts,
        },
    })

    if result.highest_severity in ("high", "critical"):
        fire_alert(
            "OUTPUT_" + result.highest_severity.upper(),
            body.agent_id, "output_sanitize", "agent_output",
            f"Output contains {result.threat_count} threat(s): "
            f"{', '.join(result.categories_detected)}",
            [f"OUTPUT_{c}" for c in result.categories_detected],
            0,
        )

    return {
        "request_id":         request_id,
        "agent_id":           body.agent_id,
        "sanitized":          result.sanitized,
        "threat_count":       result.threat_count,
        "highest_severity":   result.highest_severity,
        "categories_detected": result.categories_detected,
        "threats":            threat_dicts,
        "original_length":    result.original_length,
        "timestamp":          ts,
    }


def _build_unknown_agent_response(request: AuthorizationRequest) -> AuthorizationResponse:
    from core.models import TrustBreakdown, ResourceSensitivity
    breakdown = TrustBreakdown(
        identity_score=0, delegation_score=0,
        purpose_alignment_score=0, behavioral_score=0,
        resource_sensitivity=ResourceSensitivity.CRITICAL,
        final_score=0, threshold_required=90,
    )
    return AuthorizationResponse(
        request_id=request.request_id or str(uuid.uuid4()),
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=Decision.DENY,
        trust_breakdown=breakdown,
        explanation="Denied: agent is not registered in AgentGate — identity cannot be verified.",
        attack_flags=["UNREGISTERED_AGENT"],
    )


def _build_policy_blocked_response(
    request: AuthorizationRequest,
    agent: AgentRegistration,
    policy_match
) -> AuthorizationResponse:
    from core.models import TrustBreakdown, ResourceSensitivity
    from core.trust_engine import classify_resource_sensitivity
    sensitivity = classify_resource_sensitivity(request.resource)
    breakdown = TrustBreakdown(
        identity_score=100, delegation_score=100,
        purpose_alignment_score=100, behavioral_score=100,
        resource_sensitivity=sensitivity,
        final_score=100, threshold_required=0,
    )
    decision = Decision.DENY if policy_match.policy.effect == "DENY" else Decision.ESCALATE
    return AuthorizationResponse(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=decision,
        trust_breakdown=breakdown,
        explanation=f"Policy block: {policy_match.reason}",
        attack_flags=[f"POLICY_VIOLATION:{policy_match.policy.id}"],
    )


# ── Policy Engine ───────────────────────────────────────────────────────────

class PolicyRequest(BaseModel):
    rule: str


@app.post("/policies", response_model=Policy, dependencies=[Depends(require_api_key)])
async def add_policy(body: PolicyRequest):
    policy = create_policy(body.rule)
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return policy


@app.get("/policies", response_model=list[Policy], dependencies=[Depends(require_api_key)])
async def list_policies():
    return get_all_policies()


@app.delete("/policies/{policy_id}", dependencies=[Depends(require_api_key)])
async def remove_policy(policy_id: str):
    if not delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return {"status": "deleted"}


# ── Human Approval Endpoints ────────────────────────────────────────────────

@app.get("/decisions/pending", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def list_pending(request: Request):
    return approvals.get_all_pending()


@app.get("/decisions/{decision_id}", dependencies=[Depends(require_api_key)])
@limiter.limit("60/minute")
async def get_decision(request: Request, decision_id: str):
    a = approvals.get_pending(decision_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    return a.to_dict()


@app.post("/decisions/{decision_id}/approve", dependencies=[Depends(require_admin_key)])
@limiter.limit("20/minute")
async def approve_decision(request: Request, decision_id: str):
    if not approvals.approve(decision_id):
        raise HTTPException(status_code=404, detail="Decision not found or already resolved")
    print(f"[AgentGate] Human APPROVED {decision_id}", flush=True)
    return {"status": "approved", "decision_id": decision_id}


@app.post("/decisions/{decision_id}/deny", dependencies=[Depends(require_admin_key)])
@limiter.limit("20/minute")
async def deny_decision(request: Request, decision_id: str):
    if not approvals.deny(decision_id):
        raise HTTPException(status_code=404, detail="Decision not found or already resolved")
    print(f"[AgentGate] Human DENIED {decision_id}", flush=True)
    return {"status": "denied", "decision_id": decision_id}


# ── Audit & Stats ───────────────────────────────────────────────────────────

@app.get("/audit/recent", dependencies=[Depends(require_api_key)])
async def recent_audit(limit: int = Query(default=50, ge=1, le=1000)):
    return audit.get_recent_decisions(limit)


@app.get("/audit/agent/{agent_id}", dependencies=[Depends(require_api_key)])
async def agent_audit(agent_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    return audit.get_agent_decisions(agent_id, limit)


@app.get("/audit/stats", dependencies=[Depends(require_api_key)])
async def stats():
    return audit.get_stats()


_MAX_EXPORT_DAYS = 90
_MAX_EXPORT_ROWS = 10_000


@app.get("/audit/export", dependencies=[Depends(require_api_key)])
async def export_audit(
    format: str = Query("pdf", pattern="^(pdf|csv)$"),
    from_ts: float = Query(None, description="Start Unix timestamp (default: 30 days ago)"),
    to_ts:   float = Query(None, description="End Unix timestamp (default: now)"),
):
    import time as _time
    now   = _time.time()
    to_ts   = to_ts   or now
    from_ts = from_ts or (now - 30 * 86400)

    if to_ts <= from_ts:
        raise HTTPException(status_code=400, detail="to_ts must be after from_ts")
    if (to_ts - from_ts) > _MAX_EXPORT_DAYS * 86400:
        raise HTTPException(
            status_code=400,
            detail=f"Date range too large — maximum {_MAX_EXPORT_DAYS} days per export"
        )

    rows  = audit.get_decisions_in_range(from_ts, to_ts)
    if len(rows) > _MAX_EXPORT_ROWS:
        raise HTTPException(
            status_code=400,
            detail=f"Query returned {len(rows)} rows — maximum {_MAX_EXPORT_ROWS} per export; narrow the date range"
        )
    stats = audit.get_stats()

    if format == "csv":
        csv_data = generate_csv(rows)
        filename = f"agentgate_audit_{int(from_ts)}_{int(to_ts)}.csv"
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    pdf_bytes = generate_pdf(rows, stats, from_ts, to_ts)
    filename  = f"agentgate_audit_{int(from_ts)}_{int(to_ts)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/audit/verify", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def verify_audit_chain(request: Request):
    """Verify cryptographic integrity of the audit log HMAC chain."""
    return audit.verify_chain()


@app.get("/audit/merkle/status", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def merkle_status(request: Request):
    """Return Merkle checkpoint status: batch count, pending entries, latest root hash."""
    return await asyncio.to_thread(audit.get_merkle_status)


@app.get("/audit/merkle/verify/{entry_id}", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def merkle_verify_entry(request: Request, entry_id: str):
    """Return the Merkle inclusion proof for a specific audit entry."""
    result = await asyncio.to_thread(audit.get_merkle_proof, entry_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Entry not found or not yet sealed into a Merkle batch."
        )
    return result


@app.post("/audit/merkle/seal", dependencies=[Depends(require_admin_key)])
@limiter.limit("10/minute")
async def merkle_seal(request: Request):
    """Force-seal the current pending entries into a Merkle batch (admin only)."""
    result = await asyncio.to_thread(audit.seal_merkle_batch, True)
    if result is None:
        return {"sealed": False, "message": "No pending entries to seal."}
    return {"sealed": True, **result}


@app.post("/templates/{name}/apply", dependencies=[Depends(require_api_key)])
@limiter.limit("10/minute")
async def apply_template(request: Request, name: str):
    """Apply a compliance policy template (soc2, hipaa, gdpr, financial_services)."""
    import yaml
    from pathlib import Path
    valid = {"soc2", "hipaa", "gdpr", "financial_services"}
    if name not in valid:
        raise HTTPException(
            status_code=404,
            detail=f"Template '{name}' not found. Choose from: {', '.join(sorted(valid))}"
        )
    template_path = Path(__file__).parent.parent / "templates" / f"{name}.yaml"
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="Template file missing from server")
    with open(template_path) as f:
        data = yaml.safe_load(f)
    created = []
    for p in data.get("policies", []):
        rule = p.get("rule", "").strip()
        if rule:
            policy = create_policy(rule)
            created.append(policy.model_dump())
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return {
        "template": name,
        "display_name": data.get("name", name),
        "policies_created": len(created),
        "policies": created,
    }


@app.get("/audit/baselines", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def all_baselines(request: Request):
    return audit.get_all_baselines()


@app.get("/audit/baselines/{agent_id}", dependencies=[Depends(require_api_key)])
@limiter.limit("30/minute")
async def agent_baseline(request: Request, agent_id: str):
    b = audit.get_agent_baseline(agent_id)
    if b is None:
        raise HTTPException(status_code=404, detail="No baseline data for this agent yet")
    return b


# ── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, key: str = Query(default="")):
    # CSWSH protection: reject connections from untrusted origins.
    # Browsers always send Origin; non-browser WebSocket clients (SDK, curl) don't,
    # so we only block when Origin is present and not in the allow-list.
    origin = ws.headers.get("origin", "")
    _allowed_origins_lower = {o.lower() for o in _ALLOWED_ORIGINS}
    if origin and origin.lower() not in _allowed_origins_lower:
        await ws.close(code=4003)
        return

    api_key = _get_api_key()
    if api_key is not None and not hmac.compare_digest(key, api_key):
        await ws.accept()
        await ws.close(code=4001)
        return
    if not await manager.connect(ws):
        return
    try:
        await ws.send_text(json.dumps({"type": "stats", "data": audit.get_stats()}))
        await ws.send_text(json.dumps({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Dashboard ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard", "index.html"
    )
    with open(dashboard_path, "r", encoding="utf-8") as f:
        html = f.read()
    return html


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("AGENTGATE_PORT", 8000))
    uvicorn.run("server.main:app", host="0.0.0.0", port=port, reload=True)
