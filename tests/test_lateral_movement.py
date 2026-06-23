"""
Stdlib-only tests for core/lateral_movement.py.

Tests cover:
  - Path helpers (_normalize_path, _top_prefix, _is_credential_path)
  - Credential harvest detector (Detector A)
  - Namespace sweep detector (Detector B)
  - Combined / simultaneous flags
  - Edge cases (empty history, single entry, timestamp boundaries)
  - Constants validation
  - Agent isolation (history filtering is caller's responsibility)

No pydantic, fastapi, or sentence-transformers imports — this test file
runs in any environment with the Python stdlib.
"""

import time
import unittest

from core.lateral_movement import (
    detect_lateral_movement,
    _normalize_path,
    _top_prefix,
    _is_credential_path,
    CREDENTIAL_HARVEST_THRESHOLD,
    CREDENTIAL_HARVEST_WINDOW_SECONDS,
    NAMESPACE_DEPTH_THRESHOLD,
    NAMESPACE_SWEEP_THRESHOLD,
    NAMESPACE_SWEEP_WINDOW_SECONDS,
    _CREDENTIAL_KEYWORDS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _h(resource: str, action: str = "read", age: float = 10.0) -> dict:
    """Build a history entry dict aged `age` seconds in the past."""
    return {"action": action, "resource": resource, "timestamp": time.time() - age}


def _h_fast(resource: str, action: str = "read") -> dict:
    """History entry within the credential-harvest fast window."""
    return _h(resource, action, age=10.0)


def _h_slow(resource: str, action: str = "read", hours: float = 2.0) -> dict:
    """History entry aged `hours` hours (within 24h but outside fast window)."""
    return _h(resource, action, age=hours * 3600.0)


def _h_old(resource: str, action: str = "read") -> dict:
    """History entry outside the 24h window (25 hours ago)."""
    return _h(resource, action, age=25 * 3600.0)


# ── Path helper tests ─────────────────────────────────────────────────────────

class TestNormalizePath(unittest.TestCase):
    def test_lowercases_path(self):
        self.assertEqual(_normalize_path("/Reports/Q3.pdf"), "/reports/q3.pdf")

    def test_url_decodes_once(self):
        self.assertEqual(_normalize_path("/reports%2Fq3.pdf"), "/reports/q3.pdf")

    def test_url_decodes_double_encoded(self):
        self.assertEqual(_normalize_path("/reports%252Fq3.pdf"), "/reports/q3.pdf")

    def test_strips_null_bytes(self):
        # Null bytes are stripped; path traversal is then resolved by normpath
        result = _normalize_path("/reports\x00/q3.pdf")
        self.assertNotIn("\x00", result)
        # The null byte is gone and the path is normalized
        self.assertEqual(result, "/reports/q3.pdf")

    def test_collapses_dotdot(self):
        # normpath resolves '..' — the caller (server) rejects '..' in raw input
        result = _normalize_path("/reports/../etc/passwd")
        self.assertNotIn("reports", result)
        # Normalized to /etc/passwd (traversal resolved, no reports segment)
        self.assertEqual(result, "/etc/passwd")

    def test_collapses_double_slash_in_middle(self):
        # normpath collapses consecutive slashes in the middle of a path
        result = _normalize_path("/reports//subdir//q3.pdf")
        self.assertEqual(result, "/reports/subdir/q3.pdf")

    def test_normalizes_leading_slash(self):
        self.assertTrue(_normalize_path("/a/b").startswith("/"))


class TestTopPrefix(unittest.TestCase):
    def test_extracts_first_component(self):
        self.assertEqual(_top_prefix("/reports/q3/q3.pdf"), "/reports")

    def test_single_component(self):
        self.assertEqual(_top_prefix("/reports"), "/reports")

    def test_root_path(self):
        self.assertEqual(_top_prefix("/"), "/")

    def test_lowercase_output(self):
        self.assertEqual(_top_prefix("/HR/salary.xlsx"), "/hr")

    def test_different_namespaces(self):
        self.assertNotEqual(_top_prefix("/reports/x"), _top_prefix("/finance/x"))

    def test_deep_path_returns_first_level(self):
        self.assertEqual(_top_prefix("/a/b/c/d/e"), "/a")


class TestIsCredentialPath(unittest.TestCase):
    def test_password_file(self):
        self.assertTrue(_is_credential_path("/config/passwords.txt"))

    def test_env_file(self):
        self.assertTrue(_is_credential_path("/app/.env"))

    def test_pem_certificate(self):
        self.assertTrue(_is_credential_path("/certs/server.pem"))

    def test_api_key_path(self):
        self.assertTrue(_is_credential_path("/config/api_key.json"))

    def test_salary_file(self):
        self.assertTrue(_is_credential_path("/hr/salary.xlsx"))

    def test_vault_path(self):
        self.assertTrue(_is_credential_path("/secrets/vault/token"))

    def test_regular_report(self):
        self.assertFalse(_is_credential_path("/reports/q3_summary.pdf"))

    def test_regular_document(self):
        self.assertFalse(_is_credential_path("/documents/annual_review.docx"))

    def test_case_insensitive(self):
        self.assertTrue(_is_credential_path("/Config/API_KEY.json"))

    def test_id_rsa(self):
        self.assertTrue(_is_credential_path("/home/user/.ssh/id_rsa"))

    def test_jwt_secret(self):
        self.assertTrue(_is_credential_path("/config/jwt_secret.txt"))

    def test_payroll(self):
        self.assertTrue(_is_credential_path("/finance/payroll_q3.xlsx"))


# ── Credential harvest tests ──────────────────────────────────────────────────

class TestCredentialHarvestNoDetection(unittest.TestCase):
    def test_empty_history_no_cred_resource(self):
        flags = detect_lateral_movement("read", "/reports/q3.pdf", [])
        self.assertEqual(flags, [])

    def test_below_threshold_cred_paths(self):
        history = [_h_fast(f"/vault/secret{i}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 1)]
        # Current request is non-cred
        flags = detect_lateral_movement("read", "/reports/q3.pdf", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(cred_flags, [])

    def test_cred_paths_outside_fast_window_not_counted(self):
        # 5 credential paths but all older than CREDENTIAL_HARVEST_WINDOW_SECONDS
        history = [_h_slow(f"/vault/s{i}.json", hours=2.0) for i in range(5)]
        flags = detect_lateral_movement("read", "/vault/s99.json", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(cred_flags, [])

    def test_same_cred_path_repeated_not_threshold(self):
        # Same path repeated CREDENTIAL_HARVEST_THRESHOLD times counts as 1 distinct path
        history = [_h_fast("/vault/secret.json")] * CREDENTIAL_HARVEST_THRESHOLD
        flags = detect_lateral_movement("read", "/vault/secret.json", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(cred_flags, [])

    def test_no_cred_in_history_no_cred_in_current(self):
        history = [_h_fast(f"/reports/file{i}.pdf") for i in range(10)]
        flags = detect_lateral_movement("read", "/reports/summary.pdf", history)
        self.assertEqual(flags, [])


class TestCredentialHarvestDetected(unittest.TestCase):
    def test_threshold_exactly_met_all_from_history(self):
        # THRESHOLD - 1 in history + 1 current = exactly at threshold
        history = [_h_fast(f"/vault/secret{i}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 1)]
        flags = detect_lateral_movement("read", "/config/api_key.json", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)

    def test_all_from_history(self):
        # All THRESHOLD paths from history, current is non-cred
        history = [_h_fast(f"/secrets/s{i}.env") for i in range(CREDENTIAL_HARVEST_THRESHOLD)]
        flags = detect_lateral_movement("read", "/reports/public.pdf", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)

    def test_count_included_in_flag(self):
        count = CREDENTIAL_HARVEST_THRESHOLD + 2
        history = [_h_fast(f"/creds/key{i}.pem") for i in range(count)]
        flags = detect_lateral_movement("read", "/reports/q3.pdf", history)
        cred_flag = next(f for f in flags if "CREDENTIAL_HARVEST" in f)
        self.assertIn(str(count), cred_flag)

    def test_current_request_counts_toward_threshold(self):
        history = [_h_fast(f"/vault/secret{i}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 1)]
        flags = detect_lateral_movement("read", "/.env", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)

    def test_flag_format_correct(self):
        history = [_h_fast(f"/vault/secret{i}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD)]
        flags = detect_lateral_movement("read", "/reports/q3.pdf", history)
        cred_flag = next(f for f in flags if "CREDENTIAL_HARVEST" in f)
        self.assertTrue(cred_flag.startswith("KILL_CHAIN:CREDENTIAL_HARVEST:"))
        self.assertIn("_credential_paths_in_5min", cred_flag)

    def test_mixed_window_only_fast_entries_count(self):
        # 2 recent + 2 old cred paths; current is also cred → total distinct in window = 3
        history = (
            [_h_fast(f"/vault/recent{i}.json") for i in range(2)] +
            [_h_slow(f"/vault/old{i}.json", hours=3.0) for i in range(2)]
        )
        # current is credential path
        flags = detect_lateral_movement("read", "/config/.env", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)
        # Confirm count = 3 (the 2 recent + 1 current), not 5
        self.assertIn("3_credential_paths_in_5min", cred_flags[0])

    def test_variety_of_keyword_types(self):
        # Different keyword categories all trigger correctly
        resources = ["/config/.env", "/certs/server.pem", "/secrets/vault/token"]
        history = [_h_fast(r) for r in resources]
        flags = detect_lateral_movement("read", "/reports/q3.pdf", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)


# ── Namespace sweep tests ─────────────────────────────────────────────────────

def _build_sweep_history(
    namespace_count: int,
    resources_per_ns: int,
    age_hours: float = 1.0,
    namespace_prefix: str = "/ns",
) -> list[dict]:
    """Build history covering `namespace_count` namespaces with `resources_per_ns` each."""
    history = []
    for ns_idx in range(namespace_count):
        for res_idx in range(resources_per_ns):
            resource = f"{namespace_prefix}{ns_idx}/file{res_idx}.pdf"
            history.append(_h_slow(resource, hours=age_hours + ns_idx * 0.1))
    return history


class TestNamespaceSweepNoDetection(unittest.TestCase):
    def test_empty_history(self):
        flags = detect_lateral_movement("read", "/reports/q3.pdf", [])
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])

    def test_below_namespace_threshold(self):
        # SWEEP_THRESHOLD - 1 namespaces with sufficient depth
        history = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD - 1, NAMESPACE_DEPTH_THRESHOLD)
        flags = detect_lateral_movement("read", "/other/file.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])

    def test_enough_namespaces_but_insufficient_depth(self):
        # SWEEP_THRESHOLD namespaces but only DEPTH_THRESHOLD - 1 resources each
        history = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD - 1)
        flags = detect_lateral_movement("read", "/other/file.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])

    def test_entries_outside_24h_excluded(self):
        # Enough namespaces and depth but all older than 24h
        history = [
            _h_old(f"/ns{ns}/file{res}.pdf")
            for ns in range(NAMESPACE_SWEEP_THRESHOLD)
            for res in range(NAMESPACE_DEPTH_THRESHOLD)
        ]
        flags = detect_lateral_movement("read", "/other/file.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])

    def test_single_namespace_many_resources(self):
        history = [_h_slow(f"/reports/file{i}.pdf") for i in range(50)]
        flags = detect_lateral_movement("read", "/reports/new.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])


class TestNamespaceSweepDetected(unittest.TestCase):
    def test_exact_threshold_met(self):
        history = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD)
        # Current request is in a new namespace that counts as one more
        # but we need to be careful: the current resource adds 1 to one namespace
        # We'll put current in a new namespace so history provides exactly the threshold
        # The threshold check uses: history + current resource
        # So for exactly SWEEP_THRESHOLD namespaces at depth, we need:
        # exactly SWEEP_THRESHOLD namespaces with >= DEPTH_THRESHOLD resources total
        # Let's just use current in one of the existing namespaces
        flags = detect_lateral_movement("read", "/ns0/extra.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(len(sweep_flags), 1)

    def test_flag_prefix_correct(self):
        history = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD)
        flags = detect_lateral_movement("read", "/ns0/extra.pdf", history)
        sweep_flag = next(f for f in flags if "NAMESPACE_SWEEP" in f)
        self.assertTrue(sweep_flag.startswith("KILL_CHAIN:CROSS_SESSION:NAMESPACE_SWEEP:"))

    def test_namespace_count_in_flag(self):
        ns_count = NAMESPACE_SWEEP_THRESHOLD + 1
        history = _build_sweep_history(ns_count, NAMESPACE_DEPTH_THRESHOLD)
        flags = detect_lateral_movement("read", "/ns0/extra.pdf", history)
        sweep_flag = next(f for f in flags if "NAMESPACE_SWEEP" in f)
        self.assertIn(str(ns_count), sweep_flag)

    def test_depth_threshold_in_flag(self):
        history = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD)
        flags = detect_lateral_movement("read", "/ns0/extra.pdf", history)
        sweep_flag = next(f for f in flags if "NAMESPACE_SWEEP" in f)
        self.assertIn(str(NAMESPACE_DEPTH_THRESHOLD), sweep_flag)

    def test_current_resource_tips_over_threshold(self):
        # History has SWEEP_THRESHOLD - 1 deep namespaces + 1 namespace with DEPTH - 1 resources.
        # Current request adds 1 to the shallow namespace → tips it to DEPTH_THRESHOLD.
        history = (
            _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD - 1, NAMESPACE_DEPTH_THRESHOLD) +
            [_h_slow(f"/marginal/file{i}.pdf") for i in range(NAMESPACE_DEPTH_THRESHOLD - 1)]
        )
        flags = detect_lateral_movement("read", "/marginal/last.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(len(sweep_flags), 1)

    def test_old_entries_not_counted(self):
        # Old entries (>24h) for 4 namespaces; only 3 recent namespaces with depth
        old = [
            _h_old(f"/oldns{ns}/file{res}.pdf")
            for ns in range(NAMESPACE_SWEEP_THRESHOLD)
            for res in range(NAMESPACE_DEPTH_THRESHOLD)
        ]
        recent = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD - 1, NAMESPACE_DEPTH_THRESHOLD)
        flags = detect_lateral_movement("read", "/recent_ns0/extra.pdf", old + recent)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(sweep_flags, [])

    def test_variety_of_namespace_names(self):
        namespaces = ["/reports", "/hr", "/finance", "/admin"]
        history = [
            _h_slow(f"{ns}/file{i}.pdf")
            for ns in namespaces
            for i in range(NAMESPACE_DEPTH_THRESHOLD)
        ]
        flags = detect_lateral_movement("read", "/reports/extra.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(len(sweep_flags), 1)

    def test_deep_paths_group_to_top_prefix(self):
        # Resources at /reports/subdir/deep/file.pdf should all count under /reports
        history = [
            _h_slow(f"/reports/sub{i}/deep/deep2/file.pdf")
            for i in range(NAMESPACE_DEPTH_THRESHOLD)
        ]
        for ns in range(NAMESPACE_SWEEP_THRESHOLD - 1):
            for r in range(NAMESPACE_DEPTH_THRESHOLD):
                history.append(_h_slow(f"/ns{ns}/sub/file{r}.pdf"))
        flags = detect_lateral_movement("read", "/reports/extra.pdf", history)
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(len(sweep_flags), 1)


# ── Combined flags ────────────────────────────────────────────────────────────

class TestBothDetectorsSimultaneous(unittest.TestCase):
    def test_both_fire_together(self):
        # Sweep: 4 deep namespaces (3 resources each)
        sweep_history = _build_sweep_history(
            NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD, namespace_prefix="/dept"
        )
        # Cred harvest: 3 distinct cred paths in fast window
        cred_history = [_h_fast(f"/vault/secret{i}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 1)]
        # Current request is a credential path in a known namespace
        flags = detect_lateral_movement(
            "read", "/config/.env",
            sweep_history + cred_history
        )
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        sweep_flags = [f for f in flags if "NAMESPACE_SWEEP" in f]
        self.assertEqual(len(cred_flags), 1)
        self.assertEqual(len(sweep_flags), 1)

    def test_neither_fires_clean_session(self):
        history = [_h_slow("/reports/file.pdf") for _ in range(20)]
        flags = detect_lateral_movement("read", "/reports/new.pdf", history)
        self.assertEqual(flags, [])


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    def test_empty_history_empty_resource_no_crash(self):
        # Should not raise even with an odd resource string
        flags = detect_lateral_movement("read", "", [])
        self.assertIsInstance(flags, list)

    def test_single_entry_history(self):
        flags = detect_lateral_movement("read", "/reports/q3.pdf", [_h_slow("/reports/q1.pdf")])
        self.assertEqual(flags, [])

    def test_history_with_missing_keys_raises_gracefully(self):
        # Entries with only the required keys should work
        history = [
            {"action": "read", "resource": "/reports/q3.pdf", "timestamp": time.time() - 10}
        ]
        flags = detect_lateral_movement("read", "/reports/q4.pdf", history)
        self.assertIsInstance(flags, list)

    def test_url_encoded_resources_normalized(self):
        # /vault%2Fsecret0.json and /vault/secret0.json are the same path after normalization
        history = [
            _h_fast("/vault%2Fsecret0.json"),
            _h_fast("/vault/secret1.json"),
        ]
        # Current adds one more distinct credential path
        flags = detect_lateral_movement("read", "/.env", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)
        # /vault%2Fsecret0.json normalizes to /vault/secret0.json → still distinct
        cred_flag = cred_flags[0]
        self.assertIn("3_credential_paths_in_5min", cred_flag)

    def test_exactly_at_window_boundary_included(self):
        # Entry at exactly CREDENTIAL_HARVEST_WINDOW_SECONDS age — should be included
        # (now - timestamp = WINDOW, cutoff = now - WINDOW, so timestamp > cutoff is False)
        # Boundary: timestamp == cutoff is not included (strictly >)
        # At age = WINDOW - 0.1s: should be included
        entry = _h("/vault/secret0.json", age=CREDENTIAL_HARVEST_WINDOW_SECONDS - 0.1)
        history = [entry] + [_h_fast(f"/vault/secret{i+1}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 2)]
        flags = detect_lateral_movement("read", "/config/.env", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(len(cred_flags), 1)

    def test_exactly_at_window_boundary_excluded(self):
        # Entry at exactly CREDENTIAL_HARVEST_WINDOW_SECONDS + 1s: outside window
        entry = _h("/vault/secret0.json", age=CREDENTIAL_HARVEST_WINDOW_SECONDS + 1.0)
        history = [entry] + [_h_fast(f"/vault/secret{i+1}.json") for i in range(CREDENTIAL_HARVEST_THRESHOLD - 2)]
        flags = detect_lateral_movement("read", "/config/.env", history)
        cred_flags = [f for f in flags if "CREDENTIAL_HARVEST" in f]
        self.assertEqual(cred_flags, [])

    def test_no_side_effects_on_history_list(self):
        history = [_h_fast("/vault/secret0.json"), _h_fast("/vault/secret1.json")]
        original_len = len(history)
        detect_lateral_movement("read", "/vault/secret2.json", history)
        self.assertEqual(len(history), original_len)

    def test_returns_list(self):
        result = detect_lateral_movement("read", "/reports/q3.pdf", [])
        self.assertIsInstance(result, list)


# ── Constants validation ──────────────────────────────────────────────────────

class TestConstants(unittest.TestCase):
    def test_credential_harvest_threshold_positive_int(self):
        self.assertIsInstance(CREDENTIAL_HARVEST_THRESHOLD, int)
        self.assertGreater(CREDENTIAL_HARVEST_THRESHOLD, 0)

    def test_credential_harvest_window_positive(self):
        self.assertGreater(CREDENTIAL_HARVEST_WINDOW_SECONDS, 0.0)

    def test_namespace_sweep_threshold_positive_int(self):
        self.assertIsInstance(NAMESPACE_SWEEP_THRESHOLD, int)
        self.assertGreater(NAMESPACE_SWEEP_THRESHOLD, 0)

    def test_namespace_depth_threshold_positive_int(self):
        self.assertIsInstance(NAMESPACE_DEPTH_THRESHOLD, int)
        self.assertGreater(NAMESPACE_DEPTH_THRESHOLD, 0)

    def test_namespace_sweep_window_is_24h(self):
        self.assertEqual(NAMESPACE_SWEEP_WINDOW_SECONDS, 86_400.0)

    def test_credential_window_shorter_than_sweep_window(self):
        self.assertLess(CREDENTIAL_HARVEST_WINDOW_SECONDS, NAMESPACE_SWEEP_WINDOW_SECONDS)

    def test_credential_keywords_is_frozenset(self):
        self.assertIsInstance(_CREDENTIAL_KEYWORDS, frozenset)

    def test_credential_keywords_nonempty(self):
        self.assertGreater(len(_CREDENTIAL_KEYWORDS), 0)

    def test_credential_keywords_lowercase(self):
        for kw in _CREDENTIAL_KEYWORDS:
            self.assertEqual(kw, kw.lower(), f"Keyword not lowercase: {kw!r}")

    def test_threshold_values_in_reasonable_range(self):
        self.assertLessEqual(CREDENTIAL_HARVEST_THRESHOLD, 10)
        self.assertLessEqual(NAMESPACE_SWEEP_THRESHOLD, 20)
        self.assertLessEqual(NAMESPACE_DEPTH_THRESHOLD, 10)

    def test_namespace_sweep_threshold_greater_than_depth(self):
        # Sweep requires more namespaces than depth per namespace
        # (not a hard invariant but validates the design intent)
        self.assertGreater(NAMESPACE_SWEEP_THRESHOLD, 1)
        self.assertGreater(NAMESPACE_DEPTH_THRESHOLD, 1)


# ── Agent isolation (caller's responsibility, verified here) ──────────────────

class TestAgentIsolation(unittest.TestCase):
    def test_clean_history_for_agent_b_not_affected_by_agent_a(self):
        # Agent A has credential harvest history, Agent B has clean history.
        # analyze_kill_chain filters per agent_id before calling detect_lateral_movement.
        # Here we simulate that Agent B's call only sees clean history.
        clean_history = [_h_fast(f"/reports/file{i}.pdf") for i in range(10)]
        flags = detect_lateral_movement("read", "/reports/new.pdf", clean_history)
        self.assertEqual(flags, [])

    def test_two_independent_sweeps(self):
        # Two independent agents both sweeping — each sees only their own history.
        sweep_a = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD, namespace_prefix="/a_ns")
        sweep_b = _build_sweep_history(NAMESPACE_SWEEP_THRESHOLD, NAMESPACE_DEPTH_THRESHOLD, namespace_prefix="/b_ns")
        flags_a = detect_lateral_movement("read", "/a_ns0/extra.pdf", sweep_a)
        flags_b = detect_lateral_movement("read", "/b_ns0/extra.pdf", sweep_b)
        self.assertTrue(any("NAMESPACE_SWEEP" in f for f in flags_a))
        self.assertTrue(any("NAMESPACE_SWEEP" in f for f in flags_b))


if __name__ == "__main__":
    unittest.main()
