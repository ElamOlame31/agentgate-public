import hashlib
import hmac as _hmac_mod
import os
import queue as _queue
import re
import sqlite3
import json
import threading
import time
import uuid
from pathlib import Path
from core.models import AuthorizationResponse, AgentRegistration

_LOG_KEY = os.getenv("AGENTGATE_LOG_KEY", "agentgate-log-integrity-default").encode()

# Regex that matches a UUID v4 — tokens stored before H2 are plaintext UUIDs.
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE
)


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token. Used for storage and comparison."""
    return hashlib.sha256(token.encode()).hexdigest()

DB_PATH = Path(__file__).parent.parent / "agentgate_audit.db"


def _open_db(path: Path | None = None) -> sqlite3.Connection:
    """Open a connection with per-connection performance pragmas.

    journal_mode=WAL persists in the DB file (set once in init_db).
    synchronous=NORMAL does not persist — set it on every write connection
    to skip unnecessary fsync calls while remaining safe under WAL.
    """
    conn = sqlite3.connect(path or DB_PATH)
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    conn = sqlite3.connect(DB_PATH)
    # WAL mode: readers never block writers and writers never block readers.
    # NORMAL sync is safe with WAL — survives OS crash; a power loss at the exact
    # wrong moment could lose the last committed transaction (acceptable for an
    # authorization log; better than the throughput cost of FULL sync).
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA wal_autocheckpoint=200")  # checkpoint every ~800 KB
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            decision TEXT,
            trust_score REAL,
            identity_score REAL,
            delegation_score REAL,
            purpose_score REAL,
            behavioral_score REAL,
            resource_sensitivity TEXT,
            explanation TEXT,
            attack_flags TEXT,
            full_json TEXT,
            entry_hash TEXT DEFAULT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pending_approvals (
            request_id TEXT PRIMARY KEY,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            explanation TEXT,
            trust_score REAL,
            status TEXT DEFAULT 'PENDING',
            created_at REAL,
            resolved_at REAL DEFAULT NULL,
            expires_at REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            name TEXT,
            declared_purpose TEXT,
            authorized_resources TEXT,
            authorized_actions TEXT,
            delegated_by TEXT,
            delegation_depth INTEGER,
            token TEXT,
            registered_at REAL,
            token_expires_at REAL DEFAULT NULL,
            processes_external_content INTEGER DEFAULT 0,
            requires_human_approval INTEGER DEFAULT 0,
            scope_at_delegation TEXT DEFAULT NULL
        )
    """)
    # Migrate audit_log to add entry_hash column
    try:
        conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT DEFAULT NULL")
    except Exception:
        pass  # already exists
    # Migrate existing tables that predate these columns
    _allowed_migrations = {
        "processes_external_content": "0",
        "requires_human_approval": "0",
        "scope_at_delegation": "NULL",
        "token_expires_at": "NULL",
    }
    for col, default in _allowed_migrations.items():
        try:
            conn.execute(f"ALTER TABLE agents ADD COLUMN {col} TEXT DEFAULT {default}")
        except Exception:
            pass  # column already exists
    try:
        conn.execute("ALTER TABLE agents ADD COLUMN behavioral_contract TEXT DEFAULT NULL")
    except Exception:
        pass  # column already exists
    try:
        conn.execute("ALTER TABLE agents ADD COLUMN trust_ceiling REAL DEFAULT NULL")
    except Exception:
        pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS request_history (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            timestamp REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_baselines (
            agent_id TEXT PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            avg_rpm REAL DEFAULT 0.0,
            peak_rpm REAL DEFAULT 0.0,
            last_updated REAL DEFAULT 0.0,
            window_start REAL DEFAULT 0.0,
            window_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_quarantine (
            agent_id        TEXT PRIMARY KEY,
            quarantined_at  REAL NOT NULL,
            expires_at      REAL NOT NULL,
            trigger         TEXT NOT NULL,
            violation_count INTEGER DEFAULT 1,
            extended_count  INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_checkpoints (
            batch_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            from_rowid  INTEGER NOT NULL,
            to_rowid    INTEGER NOT NULL,
            root_hash   TEXT NOT NULL,
            sealed_at   REAL NOT NULL,
            entry_count INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_mc_rowid
        ON merkle_checkpoints(from_rowid, to_rowid)
    """)
    # Indexes — all idempotent (IF NOT EXISTS), safe to run on existing DBs.
    # request_history: queried by agent_id + timestamp on every /authorize call.
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_rh_agent_ts
        ON request_history(agent_id, timestamp DESC)
    """)
    # audit_log: queried by agent_id for per-agent history and by timestamp for
    # recency/range queries, and by entry_hash for chain verification.
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_al_agent
        ON audit_log(agent_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_al_ts
        ON audit_log(timestamp DESC)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_al_entry_hash
        ON audit_log(entry_hash)
        WHERE entry_hash IS NOT NULL
    """)
    conn.commit()
    conn.close()


def _get_last_entry_hash(conn) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else "genesis"


def _compute_entry_hash(prev_hash: str, entry_json: str) -> str:
    msg = (prev_hash + entry_json).encode()
    return _hmac_mod.new(_LOG_KEY, msg, hashlib.sha256).hexdigest()


def log_decision(response: AuthorizationResponse, record_history: bool = True):
    conn = _open_db()
    try:
        # IMMEDIATE lock serializes the read→hash→write so concurrent requests
        # cannot both read the same prev_hash and produce a branched chain.
        # In WAL mode IMMEDIATE still allows concurrent readers (unlike EXCLUSIVE).
        conn.execute("BEGIN IMMEDIATE")
        entry_json = response.model_dump_json()
        prev_hash  = _get_last_entry_hash(conn)
        entry_hash = _compute_entry_hash(prev_hash, entry_json)
        conn.execute("""
            INSERT INTO audit_log
            (id, timestamp, agent_id, action, resource, decision, trust_score,
             identity_score, delegation_score, purpose_score, behavioral_score,
             resource_sensitivity, explanation, attack_flags, full_json, entry_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            response.request_id,
            response.timestamp,
            response.agent_id,
            response.action,
            response.resource,
            response.decision.value,
            response.trust_breakdown.final_score,
            response.trust_breakdown.identity_score,
            response.trust_breakdown.delegation_score,
            response.trust_breakdown.purpose_alignment_score,
            response.trust_breakdown.behavioral_score,
            response.trust_breakdown.resource_sensitivity.value,
            response.explanation,
            json.dumps(response.attack_flags),
            entry_json,
            entry_hash,
        ))
        # Don't record unregistered-agent probes in request_history — they would
        # poison the velocity baseline for any agent later registered with that ID.
        if record_history:
            conn.execute("""
                INSERT INTO request_history VALUES (?,?,?,?,?)
            """, (str(uuid.uuid4()), response.agent_id, response.action, response.resource, response.timestamp))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_recent_decisions(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_decisions_in_range(from_ts: float, to_ts: float) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp DESC",
        (from_ts, to_ts)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_agent_decisions(agent_id: str, limit: int = 100) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE agent_id=? ORDER BY timestamp DESC LIMIT ?",
        (agent_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_request_history(agent_id: str, action: str, resource: str):
    """Record a single request in the history window (used by trust engine + tests)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO request_history VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), agent_id, action, resource, time.time())
    )
    conn.commit()
    conn.close()


def get_agent_request_history(agent_id: str, window_seconds: float = 60.0) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cutoff = time.time() - window_seconds
    rows = conn.execute(
        "SELECT * FROM request_history WHERE agent_id=? AND timestamp>? ORDER BY timestamp DESC",
        (agent_id, cutoff)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup_old_request_history(retention_seconds: float = 86_400.0) -> int:
    """Delete request_history rows older than retention_seconds. Returns row count deleted."""
    cutoff = time.time() - retention_seconds
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute("DELETE FROM request_history WHERE timestamp < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


# ── Merkle tree audit batching ─────────────────────────────────────────────────

MERKLE_BATCH_SIZE = int(os.getenv("AGENTGATE_MERKLE_BATCH_SIZE", "16"))


def _merkle_pending(conn) -> list[tuple[int, str]]:
    """Return (rowid, full_json) for entries not yet covered by a checkpoint."""
    last = conn.execute(
        "SELECT to_rowid FROM merkle_checkpoints ORDER BY batch_id DESC LIMIT 1"
    ).fetchone()
    min_rowid = (last[0] + 1) if last else 1
    rows = conn.execute(
        "SELECT rowid, full_json FROM audit_log WHERE rowid >= ? ORDER BY rowid ASC",
        (min_rowid,)
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def seal_merkle_batch(force: bool = False) -> dict | None:
    """
    Seal the next MERKLE_BATCH_SIZE pending entries into a Merkle checkpoint.
    Returns the checkpoint dict, or None if not enough entries (unless force=True).
    force=True seals whatever is pending, even a partial batch.
    """
    from core.merkle import merkle_root as _root, leaf_hash as _leaf
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("BEGIN EXCLUSIVE")
        pending = _merkle_pending(conn)
        batch = pending[:MERKLE_BATCH_SIZE]
        if not force and len(batch) < MERKLE_BATCH_SIZE:
            conn.rollback()
            return None
        if not batch:
            conn.rollback()
            return None
        leaf_hashes = [_leaf(json_str) for _, json_str in batch]
        root = _root(leaf_hashes)
        from_rowid, to_rowid = batch[0][0], batch[-1][0]
        conn.execute(
            "INSERT INTO merkle_checkpoints"
            "(from_rowid, to_rowid, root_hash, sealed_at, entry_count)"
            " VALUES (?,?,?,?,?)",
            (from_rowid, to_rowid, root, time.time(), len(batch)),
        )
        conn.commit()
        return {
            "root_hash": root,
            "from_rowid": from_rowid,
            "to_rowid": to_rowid,
            "entry_count": len(batch),
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_merkle_status() -> dict:
    conn = sqlite3.connect(DB_PATH)
    try:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        batch_count = conn.execute("SELECT COUNT(*) FROM merkle_checkpoints").fetchone()[0]
        latest = conn.execute(
            "SELECT batch_id, root_hash, sealed_at, entry_count, to_rowid"
            " FROM merkle_checkpoints ORDER BY batch_id DESC LIMIT 1"
        ).fetchone()
        if latest:
            sealed_count = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE rowid <= ?", (latest[4],)
            ).fetchone()[0]
            pending = total - sealed_count
        else:
            pending = total
        return {
            "total_audit_entries": total,
            "total_batches": batch_count,
            "pending_entries": pending,
            "batch_size": MERKLE_BATCH_SIZE,
            "latest_batch": {
                "batch_id": latest[0],
                "root_hash": latest[1],
                "sealed_at": latest[2],
                "entry_count": latest[3],
            } if latest else None,
        }
    finally:
        conn.close()


def get_merkle_proof(entry_id: str) -> dict | None:
    """
    Return an inclusion proof for the given audit entry.
    Returns None if the entry is not found or not yet sealed.
    """
    from core.merkle import merkle_proof as _proof, leaf_hash as _leaf, verify_proof as _verify
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT rowid, full_json FROM audit_log WHERE id=?", (entry_id,)
        ).fetchone()
        if not row:
            return None
        entry_rowid, entry_json = row
        batch = conn.execute(
            "SELECT batch_id, from_rowid, to_rowid, root_hash, entry_count"
            " FROM merkle_checkpoints"
            " WHERE from_rowid <= ? AND to_rowid >= ? LIMIT 1",
            (entry_rowid, entry_rowid),
        ).fetchone()
        if not batch:
            return None
        batch_id, from_rowid, to_rowid, root_hash, entry_count = batch
        entries = conn.execute(
            "SELECT rowid, full_json FROM audit_log"
            " WHERE rowid >= ? AND rowid <= ? ORDER BY rowid ASC",
            (from_rowid, to_rowid),
        ).fetchall()
        leaf_hashes = [_leaf(r[1]) for r in entries]
        index = next(i for i, r in enumerate(entries) if r[0] == entry_rowid)
        proof = _proof(leaf_hashes, index)
        this_leaf = _leaf(entry_json)
        valid = _verify(this_leaf, proof, root_hash)
        return {
            "entry_id": entry_id,
            "batch_id": batch_id,
            "leaf_hash": this_leaf,
            "proof": proof,
            "root_hash": root_hash,
            "entry_count": entry_count,
            "valid": valid,
        }
    finally:
        conn.close()


TOKEN_TTL = max(60.0, float(os.getenv("AGENTGATE_TOKEN_TTL", str(24 * 3600))))


def save_agent(agent: AgentRegistration):
    # Store the hash of the token, never the plaintext.
    # agent.token at this point is already a SHA-256 hex digest (set by the server
    # endpoints before calling save_agent), so we write it directly.
    behavioral_contract = None
    contract_data = {
        "max_requests_per_minute": agent.max_requests_per_minute,
        "allowed_time_windows": agent.allowed_time_windows,
        "max_consecutive_same_action": agent.max_consecutive_same_action,
    }
    if any(v is not None for v in contract_data.values()):
        behavioral_contract = json.dumps(contract_data)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO agents
        (agent_id, name, declared_purpose, authorized_resources, authorized_actions,
         delegated_by, delegation_depth, token, registered_at, token_expires_at,
         processes_external_content, requires_human_approval, scope_at_delegation,
         behavioral_contract, trust_ceiling)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        agent.agent_id, agent.name, agent.declared_purpose,
        json.dumps(agent.authorized_resources),
        json.dumps(agent.authorized_actions),
        agent.delegated_by, agent.delegation_depth,
        agent.token, time.time(),
        agent.token_expires_at if agent.token_expires_at is not None else time.time() + TOKEN_TTL,
        int(agent.processes_external_content),
        int(agent.requires_human_approval),
        json.dumps(agent.scope_at_delegation) if agent.scope_at_delegation else None,
        behavioral_contract,
        agent.trust_ceiling,
    ))
    conn.commit()
    conn.close()


def load_all_agents() -> dict[str, AgentRegistration]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM agents").fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            d["authorized_resources"] = json.loads(d["authorized_resources"])
            d["authorized_actions"] = json.loads(d["authorized_actions"])
            d["processes_external_content"] = bool(d.get("processes_external_content", 0))
            d["requires_human_approval"] = bool(d.get("requires_human_approval", 0))
            raw_scope = d.get("scope_at_delegation")
            d["scope_at_delegation"] = json.loads(raw_scope) if raw_scope else None
            raw_contract = d.pop("behavioral_contract", None)
            if raw_contract:
                contract = json.loads(raw_contract)
                d["max_requests_per_minute"] = contract.get("max_requests_per_minute")
                d["allowed_time_windows"] = contract.get("allowed_time_windows")
                d["max_consecutive_same_action"] = contract.get("max_consecutive_same_action")
            # trust_ceiling comes directly from the column (float or None)
            d["trust_ceiling"] = d.get("trust_ceiling")
            d.pop("registered_at", None)
            # Migrate: tokens stored before H2 are plaintext UUIDs. Hash them now and
            # persist so future restarts don't need to re-migrate.
            if d.get("token") and _UUID_RE.match(d["token"]):
                hashed = hash_token(d["token"])
                conn.execute(
                    "UPDATE agents SET token=? WHERE agent_id=?",
                    (hashed, d["agent_id"])
                )
                d["token"] = hashed
            result[d["agent_id"]] = AgentRegistration(**d)
        conn.commit()
        return result
    finally:
        conn.close()


def delete_agent(agent_id: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
    conn.execute("DELETE FROM agent_baselines WHERE agent_id=?", (agent_id,))
    conn.execute("DELETE FROM request_history WHERE agent_id=?", (agent_id,))
    conn.commit()
    conn.close()


def _ensure_baseline_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_baselines (
            agent_id TEXT PRIMARY KEY,
            total_requests INTEGER DEFAULT 0,
            avg_rpm REAL DEFAULT 0.0,
            peak_rpm REAL DEFAULT 0.0,
            last_updated REAL DEFAULT 0.0,
            window_start REAL DEFAULT 0.0,
            window_count INTEGER DEFAULT 0
        )
    """)


def update_agent_baseline(agent_id: str, current_rpm: float):
    """
    Exponential moving average of RPM per agent.
    alpha=0.1 means the baseline updates slowly — 10 requests in before it shifts significantly.
    This intentionally makes sudden spikes stand out against a stable baseline.
    """
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM agent_baselines WHERE agent_id=?", (agent_id,)
    ).fetchone()

    now = time.time()
    if row is None:
        conn.execute(
            "INSERT INTO agent_baselines VALUES (?,?,?,?,?,?,?)",
            (agent_id, 1, current_rpm, current_rpm, now, now, 1)
        )
    else:
        alpha = 0.15
        new_avg = alpha * current_rpm + (1 - alpha) * row["avg_rpm"]
        new_peak = max(row["peak_rpm"], current_rpm)
        new_total = row["total_requests"] + 1
        conn.execute(
            """UPDATE agent_baselines SET
               total_requests=?, avg_rpm=?, peak_rpm=?, last_updated=?
               WHERE agent_id=?""",
            (new_total, round(new_avg, 3), round(new_peak, 3), now, agent_id)
        )
    conn.commit()
    conn.close()


_TRUST_DECAY_RATE = float(os.getenv("AGENTGATE_TRUST_DECAY_RATE", "2.0"))  # pts per hour of inactivity
_TRUST_DECAY_FLOOR = 20.0   # avg_rpm never decays below this floor


def get_agent_baseline(agent_id: str) -> dict | None:
    """
    Return the agent's behavioral baseline, applying time-based trust decay.

    Agents that go quiet — no positive signals — have their effective baseline
    decayed linearly at AGENTGATE_TRUST_DECAY_RATE points/hour, floored at
    _TRUST_DECAY_FLOOR. This prevents a known-good baseline from being exploited
    after a long dormancy period, and mirrors how human trust works: sustained
    inactivity followed by sudden high-volume activity is itself a signal.
    Decay is applied at read time and persisted, so no background job is needed.
    """
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM agent_baselines WHERE agent_id=?", (agent_id,)
    ).fetchone()
    if row is None:
        conn.close()
        return None

    baseline = dict(row)
    now = time.time()
    hours_idle = (now - baseline["last_updated"]) / 3600.0

    if hours_idle > 1.0 and baseline["avg_rpm"] > _TRUST_DECAY_FLOOR:
        decay = _TRUST_DECAY_RATE * hours_idle
        decayed_avg = max(_TRUST_DECAY_FLOOR, baseline["avg_rpm"] - decay)
        if decayed_avg != baseline["avg_rpm"]:
            conn.execute(
                "UPDATE agent_baselines SET avg_rpm=?, last_updated=? WHERE agent_id=?",
                (round(decayed_avg, 3), now, agent_id),
            )
            conn.commit()
            baseline["avg_rpm"] = decayed_avg

    conn.close()
    return baseline


def get_all_baselines() -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    _ensure_baseline_table(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agent_baselines").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cleanup_old_history(max_age_seconds: float = 3600.0):
    """Prune request_history older than max_age_seconds to prevent unbounded growth."""
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - max_age_seconds
    conn.execute("DELETE FROM request_history WHERE timestamp<?", (cutoff,))
    conn.commit()
    conn.close()


def cleanup_old_audit_log(max_age_days: int = 90):
    """Prune audit_log entries older than max_age_days to cap database size."""
    days = max(1, int(os.getenv("AGENTGATE_AUDIT_RETENTION_DAYS", str(max_age_days))))
    conn = sqlite3.connect(DB_PATH)
    cutoff = time.time() - days * 86400
    conn.execute("DELETE FROM audit_log WHERE timestamp<?", (cutoff,))
    conn.commit()
    conn.close()


def verify_chain() -> dict:
    """Walk the HMAC chain and return whether the audit log is intact."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT id, full_json, entry_hash FROM audit_log "
        "WHERE entry_hash IS NOT NULL ORDER BY timestamp ASC"
    ).fetchall()
    conn.close()
    if not rows:
        return {"valid": True, "entries_verified": 0, "broken_at": None,
                "message": "No signed entries yet — entries are signed from this version forward"}
    prev_hash = "genesis"
    for row in rows:
        expected = _compute_entry_hash(prev_hash, row["full_json"])
        if not _hmac_mod.compare_digest(expected, row["entry_hash"]):
            return {"valid": False, "entries_verified": 0, "broken_at": row["id"],
                    "message": "Audit log integrity violation detected"}
        prev_hash = row["entry_hash"]
    return {"valid": True, "entries_verified": len(rows), "broken_at": None,
            "message": f"Audit chain verified — {len(rows)} signed entries are intact"}


# ── Persistent pending approvals ──────────────────────────────────────────────

def save_pending_approval(request_id: str, agent_id: str, action: str,
                           resource: str, explanation: str, trust_score: float,
                           expires_at: float):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR IGNORE INTO pending_approvals
        (request_id, agent_id, action, resource, explanation, trust_score,
         status, created_at, expires_at)
        VALUES (?,?,?,?,?,?,'PENDING',?,?)
    """, (request_id, agent_id, action, resource, explanation, trust_score,
          time.time(), expires_at))
    conn.commit()
    conn.close()


def resolve_pending_approval(request_id: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE pending_approvals SET status=?, resolved_at=? WHERE request_id=?",
        (status, time.time(), request_id)
    )
    conn.commit()
    conn.close()


def load_active_pending_approvals() -> list[dict]:
    """Return pending approvals that haven't expired yet (for startup reload)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM pending_approvals WHERE status='PENDING' AND expires_at > ?",
        (time.time(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Quarantine Persistence ────────────────────────────────────────────────────

def save_quarantine(record) -> None:
    """Upsert a quarantine record. Accepts QuarantineRecord or dict."""
    if hasattr(record, "to_dict"):
        d = record.to_dict()
    else:
        d = record
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO agent_quarantine
        (agent_id, quarantined_at, expires_at, trigger, violation_count, extended_count)
        VALUES (?,?,?,?,?,?)
    """, (
        d["agent_id"], d["quarantined_at"], d["expires_at"],
        d["trigger"], d["violation_count"], d["extended_count"],
    ))
    conn.commit()
    conn.close()


def load_active_quarantines() -> list:
    """Return quarantine records whose expires_at > now (startup reload)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM agent_quarantine WHERE expires_at > ?", (time.time(),)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_quarantine(agent_id: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM agent_quarantine WHERE agent_id=?", (agent_id,))
    conn.commit()
    conn.close()


def cleanup_expired_quarantines() -> None:
    """Prune quarantine rows that have expired — called by the hourly cleanup task."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM agent_quarantine WHERE expires_at <= ?", (time.time(),))
    conn.commit()
    conn.close()


# ── Async write queue ─────────────────────────────────────────────────────────
#
# Decouples authorization latency from audit-write latency. The hot /authorize
# path enqueues an entry and returns immediately; a single background thread
# drains the queue in FIFO order, which preserves the HMAC chain sequence
# without needing the BEGIN EXCLUSIVE lock that serialised all decisions before.
#
# Crash semantics: entries in the queue at process death are lost (at-most-once).
# The authorization DECISION has already been returned to the caller at that
# point, so the security guarantee is unaffected — only the audit record is at
# risk. The queue is bounded at 10 000 entries; if it fills the write falls back
# to the synchronous path (same behaviour as before this change).

_AUDIT_QUEUE_MAXSIZE = int(os.getenv("AGENTGATE_AUDIT_QUEUE_SIZE", "10000"))
_audit_queue: _queue.Queue = _queue.Queue(maxsize=_AUDIT_QUEUE_MAXSIZE)
_writer_lock = threading.Lock()
_writer_thread: threading.Thread | None = None


def _ensure_writer_started() -> None:
    global _writer_thread
    if _writer_thread is not None and _writer_thread.is_alive():
        return
    with _writer_lock:
        if _writer_thread is not None and _writer_thread.is_alive():
            return
        t = threading.Thread(
            target=_audit_writer_loop,
            daemon=True,
            name="agentgate-audit-writer",
        )
        t.start()
        _writer_thread = t


def _audit_writer_loop() -> None:
    while True:
        item = _audit_queue.get()
        if item is None:
            _audit_queue.task_done()
            break
        response, record_history = item
        try:
            log_decision(response, record_history)
        except Exception as exc:
            print(f"[AgentGate] audit write error: {exc}", flush=True)
        finally:
            _audit_queue.task_done()


def log_decision_queued(response: AuthorizationResponse, record_history: bool = True) -> None:
    """Non-blocking audit log write. Returns immediately after enqueueing.

    The background writer thread processes entries in FIFO order, preserving
    the HMAC chain sequence that log_decision() requires. Falls back to a
    synchronous write when the queue is full so no entries are ever silently
    dropped.
    """
    _ensure_writer_started()
    try:
        _audit_queue.put_nowait((response, record_history))
    except _queue.Full:
        # Backlog > AGENTGATE_AUDIT_QUEUE_SIZE — fall back to synchronous write.
        # The IMMEDIATE lock in log_decision() ensures chain integrity even when
        # mixing queued and direct writes.
        print(
            f"[AgentGate] audit queue full ({_AUDIT_QUEUE_MAXSIZE} entries) — "
            "writing synchronously",
            flush=True,
        )
        log_decision(response, record_history)


def flush_audit_queue() -> None:
    """Block until all queued entries are persisted to SQLite.

    Call this before process shutdown or in tests that read DB state after
    log_decision_queued() to avoid a race between the writer thread and the
    assertion.
    """
    _audit_queue.join()


def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    permits = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='PERMIT'").fetchone()[0]
    denials = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='DENY'").fetchone()[0]
    escalations = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='ESCALATE'").fetchone()[0]
    avg_score = conn.execute("SELECT AVG(trust_score) FROM audit_log").fetchone()[0] or 0
    attacks = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE attack_flags != '[]'"
    ).fetchone()[0]
    conn.close()
    return {
        "total_requests": total,
        "permits": permits,
        "denials": denials,
        "escalations": escalations,
        "avg_trust_score": round(avg_score, 1),
        "attack_flags_raised": attacks,
    }
