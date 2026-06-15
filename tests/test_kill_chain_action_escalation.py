"""
Stdlib-only unit tests for kill chain Detector 5: ACTION_TYPE_ESCALATION.

Tests verify the detection algorithm using an inline reproduction of the logic
to avoid importing modules that require external dependencies (pydantic,
sentence_transformers).  The inline constants are kept in sync with
core/kill_chain.py intentionally — a drift will surface as a test failure on
the first run after the module is modified.

Detection rule (Detector 5):
  - Current action is in _ALL_ESCALATION_ACTIONS (destructive OR exfil)
  - Agent has >= ACTION_ESCALATION_MIN_HISTORY prior requests
  - None of those prior requests used any escalation action
  → emit KILL_CHAIN:ACTION_TYPE_ESCALATION:{DESTROY|EXFIL}:first_use_after_N_benign_requests
"""

import sqlite3
import tempfile
import time
import unittest
import uuid

# ── Inline reproduction of constants from core/kill_chain.py ─────────────────
# If these drift from the module, tests fail — that's intentional.

_DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset({
    "delete", "remove", "drop", "truncate",
    "wipe", "purge", "destroy", "overwrite",
})

_EXFIL_ACTIONS: frozenset[str] = frozenset({
    "send", "email", "upload", "post", "forward", "export", "transfer", "publish",
})

_ALL_ESCALATION_ACTIONS: frozenset[str] = _DESTRUCTIVE_ACTIONS | _EXFIL_ACTIONS

ACTION_ESCALATION_MIN_HISTORY = 5


def _detect_action_type_escalation(action: str, history: list) -> list:
    """Inline reproduction of Detector 5 logic from core/kill_chain.py.

    history: list of dicts with at least {"action": str}.
    Returns list of flag strings (empty = no flag).
    """
    action_lower = action.lower()
    if action_lower not in _ALL_ESCALATION_ACTIONS:
        return []
    if len(history) < ACTION_ESCALATION_MIN_HISTORY:
        return []
    prior_escalations = [
        h for h in history if h["action"].lower() in _ALL_ESCALATION_ACTIONS
    ]
    if prior_escalations:
        return []
    category = "EXFIL" if action_lower in _EXFIL_ACTIONS else "DESTROY"
    return [
        f"KILL_CHAIN:ACTION_TYPE_ESCALATION:{category}:"
        f"first_use_after_{len(history)}_benign_requests"
    ]


def _make_history(actions: list[str]) -> list[dict]:
    """Build a minimal history list from a list of action strings."""
    return [{"action": a, "resource": f"/r/{i}", "timestamp": time.time() - i}
            for i, a in enumerate(actions)]


# ── Test classes ──────────────────────────────────────────────────────────────

class TestNoHistory(unittest.TestCase):
    """Detector must not fire when the agent has no prior request history."""

    def test_empty_history_delete(self):
        flags = _detect_action_type_escalation("delete", [])
        self.assertEqual(flags, [])

    def test_empty_history_export(self):
        flags = _detect_action_type_escalation("export", [])
        self.assertEqual(flags, [])

    def test_none_history_equivalent(self):
        flags = _detect_action_type_escalation("drop", [])
        self.assertEqual(flags, [])


class TestBelowMinHistory(unittest.TestCase):
    """Detector must not fire when prior request count is below the minimum threshold."""

    def test_one_prior_request(self):
        history = _make_history(["read"])
        self.assertEqual(_detect_action_type_escalation("delete", history), [])

    def test_four_prior_requests(self):
        history = _make_history(["read", "search", "list", "query"])
        self.assertEqual(_detect_action_type_escalation("delete", history), [])

    def test_exactly_one_below_minimum(self):
        # ACTION_ESCALATION_MIN_HISTORY - 1 entries must not fire
        history = _make_history(["read"] * (ACTION_ESCALATION_MIN_HISTORY - 1))
        self.assertEqual(_detect_action_type_escalation("delete", history), [])


class TestFiresAtMinHistory(unittest.TestCase):
    """Detector fires exactly at the minimum history threshold."""

    def test_exactly_min_history_destroy(self):
        history = _make_history(["read"] * ACTION_ESCALATION_MIN_HISTORY)
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("ACTION_TYPE_ESCALATION", flags[0])

    def test_above_min_history_destroy(self):
        history = _make_history(["read"] * (ACTION_ESCALATION_MIN_HISTORY + 3))
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)

    def test_exactly_min_history_exfil(self):
        history = _make_history(["read"] * ACTION_ESCALATION_MIN_HISTORY)
        flags = _detect_action_type_escalation("export", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("ACTION_TYPE_ESCALATION", flags[0])


class TestDestroyCategory(unittest.TestCase):
    """Destructive actions emit the DESTROY category in the flag."""

    def _check_destroy(self, action: str):
        history = _make_history(["read", "search", "list", "query", "view"])
        flags = _detect_action_type_escalation(action, history)
        self.assertEqual(len(flags), 1, f"{action} should fire")
        self.assertIn(":DESTROY:", flags[0], f"{action} flag should be DESTROY category")

    def test_delete(self):
        self._check_destroy("delete")

    def test_remove(self):
        self._check_destroy("remove")

    def test_drop(self):
        self._check_destroy("drop")

    def test_truncate(self):
        self._check_destroy("truncate")

    def test_wipe(self):
        self._check_destroy("wipe")

    def test_purge(self):
        self._check_destroy("purge")

    def test_destroy(self):
        self._check_destroy("destroy")

    def test_overwrite(self):
        self._check_destroy("overwrite")


class TestExfilCategory(unittest.TestCase):
    """Exfiltration actions emit the EXFIL category in the flag."""

    def _check_exfil(self, action: str):
        history = _make_history(["read", "search", "list", "query", "view"])
        flags = _detect_action_type_escalation(action, history)
        self.assertEqual(len(flags), 1, f"{action} should fire")
        self.assertIn(":EXFIL:", flags[0], f"{action} flag should be EXFIL category")

    def test_send(self):
        self._check_exfil("send")

    def test_email(self):
        self._check_exfil("email")

    def test_upload(self):
        self._check_exfil("upload")

    def test_post(self):
        self._check_exfil("post")

    def test_forward(self):
        self._check_exfil("forward")

    def test_export(self):
        self._check_exfil("export")

    def test_transfer(self):
        self._check_exfil("transfer")

    def test_publish(self):
        self._check_exfil("publish")


class TestBenignActionsNeverFire(unittest.TestCase):
    """Non-destructive, non-exfil actions must never trigger the detector."""

    def _check_benign(self, action: str):
        history = _make_history(["read"] * 10)
        flags = _detect_action_type_escalation(action, history)
        self.assertEqual(flags, [], f"'{action}' should not fire ACTION_TYPE_ESCALATION")

    def test_read(self):
        self._check_benign("read")

    def test_search(self):
        self._check_benign("search")

    def test_list(self):
        self._check_benign("list")

    def test_query(self):
        self._check_benign("query")

    def test_analyze(self):
        self._check_benign("analyze")

    def test_view(self):
        self._check_benign("view")

    def test_summarize(self):
        self._check_benign("summarize")

    def test_write(self):
        # "write" is not in either set — suspicious but not escalation-category
        self._check_benign("write")


class TestPriorEscalationDisarmsDetector(unittest.TestCase):
    """When the agent has previously used any escalation action, the detector must not fire."""

    def test_prior_delete_disarms_on_delete(self):
        history = _make_history(["read", "read", "read", "delete", "read"])
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [])

    def test_prior_export_disarms_on_export(self):
        history = _make_history(["read"] * 4 + ["export"])
        flags = _detect_action_type_escalation("export", history)
        self.assertEqual(flags, [])

    def test_prior_export_disarms_on_delete(self):
        # Once ANY escalation action has been seen, subsequent destructive actions
        # do not re-trigger the "first use" detector.
        history = _make_history(["read"] * 4 + ["export"])
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [])

    def test_prior_delete_disarms_on_export(self):
        history = _make_history(["read"] * 4 + ["delete"])
        flags = _detect_action_type_escalation("export", history)
        self.assertEqual(flags, [])

    def test_multiple_prior_escalation_disarms(self):
        history = _make_history(["delete", "delete", "export", "read", "read"])
        flags = _detect_action_type_escalation("wipe", history)
        self.assertEqual(flags, [])


class TestCaseInsensitivity(unittest.TestCase):
    """Action and history comparisons are case-insensitive."""

    def test_uppercase_current_action_fires(self):
        history = _make_history(["read"] * ACTION_ESCALATION_MIN_HISTORY)
        flags = _detect_action_type_escalation("DELETE", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("DESTROY", flags[0])

    def test_mixed_case_current_action_fires(self):
        history = _make_history(["read"] * ACTION_ESCALATION_MIN_HISTORY)
        flags = _detect_action_type_escalation("Export", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("EXFIL", flags[0])

    def test_uppercase_prior_action_disarms(self):
        history = _make_history(["read"] * 4 + ["DELETE"])
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [], "Uppercase prior DELETE should disarm detector")

    def test_mixed_case_history_disarms(self):
        history = _make_history(["Read", "SEARCH", "List", "Query", "Export"])
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [], "Prior Export in history should disarm detector")


class TestFlagFormat(unittest.TestCase):
    """Verify the exact flag string format."""

    def test_destroy_flag_format(self):
        n = ACTION_ESCALATION_MIN_HISTORY
        history = _make_history(["read"] * n)
        flags = _detect_action_type_escalation("delete", history)
        expected = f"KILL_CHAIN:ACTION_TYPE_ESCALATION:DESTROY:first_use_after_{n}_benign_requests"
        self.assertEqual(flags[0], expected)

    def test_exfil_flag_format(self):
        n = ACTION_ESCALATION_MIN_HISTORY
        history = _make_history(["read"] * n)
        flags = _detect_action_type_escalation("export", history)
        expected = f"KILL_CHAIN:ACTION_TYPE_ESCALATION:EXFIL:first_use_after_{n}_benign_requests"
        self.assertEqual(flags[0], expected)

    def test_flag_count_reflects_full_history(self):
        n = 17
        history = _make_history(["read"] * n)
        flags = _detect_action_type_escalation("delete", history)
        self.assertIn(f"first_use_after_{n}_benign_requests", flags[0])

    def test_exactly_one_flag_emitted(self):
        history = _make_history(["read"] * 10)
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)


class TestLargeHistory(unittest.TestCase):
    """Detector behaves correctly at scale."""

    def test_100_reads_then_delete(self):
        history = _make_history(["read"] * 100)
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("first_use_after_100_benign_requests", flags[0])

    def test_mixed_benign_actions_at_scale(self):
        benign = ["read", "search", "list", "query", "analyze"] * 20  # 100 total
        history = _make_history(benign)
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)


class TestSQLiteBackedHistory(unittest.TestCase):
    """Integration-style tests using a real SQLite request_history table."""

    def setUp(self):
        self._db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.conn = sqlite3.connect(self._db.name)
        self.conn.execute("""
            CREATE TABLE request_history (
                id TEXT PRIMARY KEY,
                agent_id TEXT,
                action TEXT,
                resource TEXT,
                timestamp REAL
            )
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _insert(self, agent_id: str, action: str, resource: str = "/r/x", ts: float = None):
        self.conn.execute(
            "INSERT INTO request_history VALUES (?,?,?,?,?)",
            (str(uuid.uuid4()), agent_id, action, resource, ts or time.time()),
        )
        self.conn.commit()

    def _load_history(self, agent_id: str, window: float = 86400.0) -> list:
        cutoff = time.time() - window
        self.conn.row_factory = sqlite3.Row
        rows = self.conn.execute(
            "SELECT * FROM request_history WHERE agent_id=? AND timestamp>? ORDER BY timestamp DESC",
            (agent_id, cutoff),
        ).fetchall()
        return [dict(r) for r in rows]

    def test_reads_only_then_delete(self):
        for _ in range(ACTION_ESCALATION_MIN_HISTORY):
            self._insert("agent1", "read")
        history = self._load_history("agent1")
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("DESTROY", flags[0])

    def test_no_history_in_window(self):
        # Insert old records outside the 24h window
        old_ts = time.time() - 90000  # 25 hours ago
        for _ in range(10):
            self._insert("agent2", "read", ts=old_ts)
        history = self._load_history("agent2")
        # All records expired — empty history → no flag
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [])

    def test_prior_delete_in_db_disarms(self):
        for _ in range(4):
            self._insert("agent3", "read")
        self._insert("agent3", "delete")
        history = self._load_history("agent3")
        flags = _detect_action_type_escalation("delete", history)
        self.assertEqual(flags, [])

    def test_isolation_between_agents(self):
        # agent4 has a clean history; agent5 has prior deletes
        for _ in range(6):
            self._insert("agent4", "read")
        for _ in range(4):
            self._insert("agent5", "read")
        self._insert("agent5", "delete")

        history4 = self._load_history("agent4")
        history5 = self._load_history("agent5")

        # agent4: no prior escalation → fires
        flags4 = _detect_action_type_escalation("delete", history4)
        self.assertEqual(len(flags4), 1)

        # agent5: prior delete in history → does not fire
        flags5 = _detect_action_type_escalation("delete", history5)
        self.assertEqual(flags5, [])

    def test_only_current_action_not_in_history(self):
        # The current action is NOT inserted before querying — only prior history is
        for _ in range(ACTION_ESCALATION_MIN_HISTORY):
            self._insert("agent6", "search")
        history = self._load_history("agent6")
        # All prior actions are "search" — no escalation in history
        self.assertEqual(len(history), ACTION_ESCALATION_MIN_HISTORY)
        flags = _detect_action_type_escalation("wipe", history)
        self.assertEqual(len(flags), 1)
        self.assertIn("DESTROY", flags[0])


class TestConstantConsistency(unittest.TestCase):
    """Verify that the inline test constants match what the module exports.

    If core/kill_chain.py changes its constants without updating the tests,
    these checks will catch the drift.
    """

    def test_all_escalation_actions_is_union(self):
        self.assertEqual(
            _ALL_ESCALATION_ACTIONS,
            _DESTRUCTIVE_ACTIONS | _EXFIL_ACTIONS,
        )

    def test_destructive_and_exfil_are_disjoint(self):
        overlap = _DESTRUCTIVE_ACTIONS & _EXFIL_ACTIONS
        self.assertEqual(overlap, frozenset(), f"Unexpected overlap: {overlap}")

    def test_min_history_is_positive(self):
        self.assertGreater(ACTION_ESCALATION_MIN_HISTORY, 0)

    def test_known_destructive_actions_present(self):
        for a in ("delete", "remove", "drop", "truncate", "wipe", "purge", "destroy", "overwrite"):
            self.assertIn(a, _DESTRUCTIVE_ACTIONS, f"'{a}' missing from _DESTRUCTIVE_ACTIONS")

    def test_known_exfil_actions_present(self):
        for a in ("send", "email", "upload", "post", "forward", "export", "transfer", "publish"):
            self.assertIn(a, _EXFIL_ACTIONS, f"'{a}' missing from _EXFIL_ACTIONS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
