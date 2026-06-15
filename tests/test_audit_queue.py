"""
Tests for the async audit write queue and WAL mode.

Covers:
- WAL journal mode is enabled by init_db()
- log_decision_queued() returns immediately and persists asynchronously
- flush_audit_queue() blocks until all queued entries are written
- HMAC chain integrity is preserved when entries arrive via log_decision_queued()
- Queue full → synchronous fallback (no entries lost)
- Concurrent queued writes produce a valid, unbroken chain
"""

import json
import sqlite3
import time
import uuid
import threading
import pytest

import core.audit as _audit
from core.audit import (
    init_db,
    log_decision,
    log_decision_queued,
    flush_audit_queue,
    verify_chain,
    get_recent_decisions,
    DB_PATH,
)
from core.models import (
    AuthorizationResponse, Decision, TrustBreakdown, ResourceSensitivity,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response(
    decision: str = "PERMIT",
    agent_id: str | None = None,
) -> AuthorizationResponse:
    """Build a minimal AuthorizationResponse for use in tests."""
    agent_id = agent_id or f"test-{uuid.uuid4().hex[:8]}"
    breakdown = TrustBreakdown(
        identity_score=100.0,
        delegation_score=100.0,
        purpose_alignment_score=100.0,
        behavioral_score=100.0,
        final_score=100.0,
        threshold_required=70.0,
        resource_sensitivity=ResourceSensitivity.LOW,
    )
    return AuthorizationResponse(
        request_id=str(uuid.uuid4()),
        agent_id=agent_id,
        action="read",
        resource="/data/test.pdf",
        decision=Decision(decision),
        trust_breakdown=breakdown,
        explanation="test entry",
        attack_flags=[],
        timestamp=time.time(),
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Each test gets its own SQLite file so row counts are deterministic."""
    old_path = _audit.DB_PATH
    _audit.DB_PATH = tmp_path / "test_queue.db"
    init_db()
    yield
    # Drain queue before restoring path so the writer thread doesn't write to
    # the temp DB after it has been reclaimed by pytest.
    flush_audit_queue()
    _audit.DB_PATH = old_path


# ── WAL mode ──────────────────────────────────────────────────────────────────

class TestWALMode:
    def test_journal_mode_is_wal(self):
        conn = sqlite3.connect(_audit.DB_PATH)
        row = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        assert row[0].upper() == "WAL", f"Expected WAL, got {row[0]}"

    def test_synchronous_is_normal(self):
        conn = sqlite3.connect(_audit.DB_PATH)
        row = conn.execute("PRAGMA synchronous").fetchone()
        conn.close()
        # 1 = NORMAL in SQLite pragma integer encoding
        assert row[0] == 1, f"Expected NORMAL (1), got {row[0]}"

    def test_reader_does_not_block_during_exclusive_write(self):
        """With WAL mode, a reader connection can open while a write lock is held."""
        writer = sqlite3.connect(_audit.DB_PATH)
        writer.execute("BEGIN IMMEDIATE")
        # A second connection should be able to read without timing out
        reader = sqlite3.connect(_audit.DB_PATH, timeout=1.0)
        count = reader.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        reader.close()
        writer.rollback()
        writer.close()
        assert isinstance(count, int)


# ── Queued writes ──────────────────────────────────────────────────────────────

class TestLogDecisionQueued:
    def test_returns_before_write_completes(self):
        """log_decision_queued should return without waiting for SQLite."""
        resp = _make_response()
        start = time.monotonic()
        log_decision_queued(resp)
        elapsed = time.monotonic() - start
        # Enqueue should be sub-millisecond; SQLite write takes longer
        assert elapsed < 0.05, f"Enqueue took {elapsed:.3f}s — should be instant"

    def test_entry_persisted_after_flush(self):
        resp = _make_response()
        log_decision_queued(resp)
        flush_audit_queue()
        rows = get_recent_decisions(limit=10)
        ids = {r["id"] for r in rows}
        assert resp.request_id in ids

    def test_multiple_entries_all_persisted(self):
        responses = [_make_response() for _ in range(20)]
        for r in responses:
            log_decision_queued(r)
        flush_audit_queue()
        rows = get_recent_decisions(limit=30)
        written_ids = {r["id"] for r in rows}
        for r in responses:
            assert r.request_id in written_ids

    def test_decision_field_is_correct(self):
        deny_resp = _make_response(decision="DENY")
        log_decision_queued(deny_resp)
        flush_audit_queue()
        rows = get_recent_decisions(limit=5)
        row = next(r for r in rows if r["id"] == deny_resp.request_id)
        assert row["decision"] == "DENY"

    def test_writer_thread_is_daemon(self):
        """Writer thread must not prevent process shutdown."""
        log_decision_queued(_make_response())
        flush_audit_queue()
        assert _audit._writer_thread is not None
        assert _audit._writer_thread.daemon is True

    def test_writer_thread_name(self):
        log_decision_queued(_make_response())
        flush_audit_queue()
        assert _audit._writer_thread is not None
        assert "audit" in _audit._writer_thread.name


# ── HMAC chain integrity ───────────────────────────────────────────────────────

class TestChainIntegrity:
    def test_chain_valid_after_queued_writes(self):
        for _ in range(10):
            log_decision_queued(_make_response())
        flush_audit_queue()
        result = verify_chain()
        assert result["valid"] is True
        assert result["entries_verified"] == 10

    def test_chain_valid_mixing_sync_and_queued(self):
        """Sync writes followed by queued writes must form one unbroken chain."""
        # Two synchronous writes first
        log_decision(_make_response())
        log_decision(_make_response())
        # Three queued writes
        for _ in range(3):
            log_decision_queued(_make_response())
        flush_audit_queue()
        result = verify_chain()
        assert result["valid"] is True
        assert result["entries_verified"] == 5

    def test_chain_order_matches_queue_order(self):
        """Entries must appear in the DB in the same order they were enqueued."""
        sentinel = "order-marker"
        first = _make_response(agent_id=sentinel)
        second = _make_response()
        log_decision_queued(first)
        log_decision_queued(second)
        flush_audit_queue()
        rows = get_recent_decisions(limit=10)
        # get_recent_decisions returns most-recent-first
        ids_in_order = [r["id"] for r in reversed(rows)][-2:]
        assert ids_in_order[0] == first.request_id
        assert ids_in_order[1] == second.request_id

    def test_concurrent_queued_writes_chain_unbroken(self):
        """Many threads submitting to the queue concurrently — chain must survive."""
        n = 50
        responses = [_make_response() for _ in range(n)]
        threads = [
            threading.Thread(target=log_decision_queued, args=(r,))
            for r in responses
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        flush_audit_queue()
        result = verify_chain()
        assert result["valid"] is True
        assert result["entries_verified"] == n


# ── Queue full fallback ────────────────────────────────────────────────────────

class TestQueueFullFallback:
    def test_fallback_writes_synchronously_when_queue_full(self, monkeypatch):
        """When the queue is full, log_decision_queued falls back to synchronous write."""
        import queue as _q

        full_queue = _q.Queue(maxsize=0)  # maxsize=0 means unbounded — use put_nowait to force Full

        # Monkeypatch put_nowait to always raise Full
        def always_full(item):
            raise _q.Full()

        monkeypatch.setattr(_audit._audit_queue, "put_nowait", always_full)

        resp = _make_response()
        log_decision_queued(resp)  # should not raise; falls back to sync write

        rows = get_recent_decisions(limit=5)
        ids = {r["id"] for r in rows}
        assert resp.request_id in ids


# ── flush_audit_queue ─────────────────────────────────────────────────────────

class TestFlushAuditQueue:
    def test_flush_with_empty_queue_returns_immediately(self):
        start = time.monotonic()
        flush_audit_queue()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    def test_flush_waits_for_all_entries(self):
        n = 30
        for _ in range(n):
            log_decision_queued(_make_response())
        flush_audit_queue()
        rows = get_recent_decisions(limit=n + 5)
        assert len(rows) >= n

    def test_flush_idempotent(self):
        log_decision_queued(_make_response())
        flush_audit_queue()
        flush_audit_queue()  # second call should not block or raise
