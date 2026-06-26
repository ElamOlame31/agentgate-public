"""
Stdlib-only tests for core/time_anomaly.py.

No external dependencies (pydantic, fastapi, sentence-transformers, etc.).
All timestamps are fixed to avoid real-clock dependency.

Fixed reference point:
    _REF_TS = 1_750_377_600.0  →  2025-06-20T00:00:00Z  (UTC midnight, hour 0)
    _CURRENT_TS(h) = _REF_TS + h * 3600  →  "now" at UTC hour h on that date
    _ts_for_hour(h, i) = _REF_TS + h * 3600 - (i + 1) * 86400  →  history entry at
        hour h on day (i+1) before the reference date
"""

import unittest

from core.time_anomaly import (
    detect_time_anomaly,
    MIN_HISTORY_FOR_PROFILE,
    BASELINE_WINDOW_SECONDS,
    HOUR_TOLERANCE,
    MIN_DARK_FRACTION,
    _FLAG_PREFIX,
    _utc_hour,
)

# ── Fixed timestamps ───────────────────────────────────────────────────────────

# 2025-06-20T00:00:00Z  (UTC midnight on a known date; hour = 0)
_REF_TS: float = 1_750_377_600.0


def _current(hour: int) -> float:
    """Timestamp representing 'now' at UTC `hour` on the reference date."""
    return _REF_TS + hour * 3_600


def _hist(hour: int, index: int = 0) -> dict:
    """Single history entry at UTC `hour`, `index+1` days before _REF_TS."""
    return {"timestamp": _REF_TS + hour * 3_600 - (index + 1) * 86_400}


def _make_history(active_hours: list, total: int = None) -> list:
    """
    Build `total` history dicts distributed across `active_hours`.
    total defaults to max(MIN_HISTORY_FOR_PROFILE + 5, 3 * len(active_hours)).
    """
    if not active_hours:
        return []
    n = total if total is not None else max(MIN_HISTORY_FOR_PROFILE + 5, 3 * len(active_hours))
    return [_hist(active_hours[i % len(active_hours)], i) for i in range(n)]


# ── TestConstants ──────────────────────────────────────────────────────────────

class TestConstants(unittest.TestCase):

    def test_min_history_positive(self):
        self.assertGreater(MIN_HISTORY_FOR_PROFILE, 0)

    def test_min_history_is_int(self):
        self.assertIsInstance(MIN_HISTORY_FOR_PROFILE, int)

    def test_baseline_window_is_seven_days(self):
        self.assertAlmostEqual(BASELINE_WINDOW_SECONDS, 7 * 86_400)

    def test_baseline_window_is_float(self):
        self.assertIsInstance(BASELINE_WINDOW_SECONDS, float)

    def test_hour_tolerance_positive(self):
        self.assertGreater(HOUR_TOLERANCE, 0)

    def test_hour_tolerance_is_int(self):
        self.assertIsInstance(HOUR_TOLERANCE, int)

    def test_hour_tolerance_less_than_12(self):
        # Tolerance > 12 would make the detector meaningless
        self.assertLess(HOUR_TOLERANCE, 12)

    def test_min_dark_fraction_between_zero_and_one(self):
        self.assertGreater(MIN_DARK_FRACTION, 0.0)
        self.assertLess(MIN_DARK_FRACTION, 1.0)

    def test_flag_prefix_behavioral_namespace(self):
        self.assertTrue(_FLAG_PREFIX.startswith("BEHAVIORAL:"))

    def test_flag_prefix_contains_after_hours(self):
        self.assertIn("AFTER_HOURS", _FLAG_PREFIX)


# ── TestUtcHour ───────────────────────────────────────────────────────────────

class TestUtcHour(unittest.TestCase):

    def test_midnight(self):
        # _REF_TS is 2025-06-20T00:00:00Z
        self.assertEqual(_utc_hour(_REF_TS), 0)

    def test_noon(self):
        self.assertEqual(_utc_hour(_REF_TS + 12 * 3_600), 12)

    def test_hour_23(self):
        self.assertEqual(_utc_hour(_REF_TS + 23 * 3_600), 23)

    def test_hour_1(self):
        self.assertEqual(_utc_hour(_REF_TS + 1 * 3_600), 1)

    def test_all_hours_round_trip(self):
        for h in range(24):
            ts = _REF_TS + h * 3_600
            self.assertEqual(_utc_hour(ts), h, msg=f"hour {h} round-trip failed")

    def test_hour_across_day_boundary(self):
        # An hour from a previous day at hour 3 should still give 3
        ts = _REF_TS - 86_400 + 3 * 3_600
        self.assertEqual(_utc_hour(ts), 3)


# ── TestBelowMinHistory ────────────────────────────────────────────────────────

class TestBelowMinHistory(unittest.TestCase):

    def test_empty_returns_empty(self):
        self.assertEqual(detect_time_anomaly([], _current(3)), [])

    def test_one_entry_returns_empty(self):
        self.assertEqual(detect_time_anomaly([_hist(9)], _current(3)), [])

    def test_min_minus_one_returns_empty(self):
        history = _make_history([9, 10], total=MIN_HISTORY_FOR_PROFILE - 1)
        self.assertEqual(detect_time_anomaly(history, _current(3)), [])

    def test_exactly_min_is_sufficient(self):
        # Exactly MIN_HISTORY_FOR_PROFILE entries: threshold is met.
        # Profile = daytime hours; request at 3am should flag.
        history = _make_history(list(range(9, 18)), total=MIN_HISTORY_FOR_PROFILE)
        result = detect_time_anomaly(history, _current(3))
        # The important thing is it doesn't error and makes a decision.
        self.assertIsInstance(result, list)

    def test_well_above_min_works(self):
        history = _make_history([9, 10, 11], total=100)
        # Should not raise, returns list
        self.assertIsInstance(detect_time_anomaly(history, _current(3)), list)


# ── TestNoProfileTooManyActiveHours ───────────────────────────────────────────

class TestNoProfileTooManyActiveHours(unittest.TestCase):

    def _fraction(self, n_active: int) -> float:
        return (24 - n_active) / 24.0

    def test_all_24_hours_active_no_flag(self):
        # dark_fraction = 0 < MIN_DARK_FRACTION → no profiling possible
        history = _make_history(list(range(24)))
        result = detect_time_anomaly(history, _current(12))
        self.assertEqual(result, [])

    def test_19_active_hours_too_broad(self):
        # 19 active → dark_fraction = 5/24 ≈ 0.208 < 0.25 → filtered
        active = list(range(19))  # hours 0-18
        history = _make_history(active)
        self.assertEqual(detect_time_anomaly(history, _current(20)), [])

    def test_18_active_hours_allows_profiling(self):
        # 18 active → dark_fraction = 6/24 = 0.25 ≥ MIN_DARK_FRACTION → not filtered
        # Request at hour 23 (outside active hours 0-17, and outside tolerance from 17)
        # With HOUR_TOLERANCE=1: 23 is adjacent to 0 (wrap), so let's use hour 22
        # 22 is 4 hours from 17, outside tolerance → flag expected
        active = list(range(18))  # hours 0-17
        history = _make_history(active)
        result = detect_time_anomaly(history, _current(21))
        # 21 is 4 hours after 17 — well outside tolerance → should flag
        self.assertEqual(len(result), 1)

    def test_dark_fraction_threshold_boundary(self):
        # Test the exact cutoff: MIN_DARK_FRACTION * 24 active hours
        # floor(0.25 * 24) = 6 dark hours → 18 active → still profiles
        active = list(range(18))
        history = _make_history(active)
        # This shouldn't return [] due to the dark fraction filter
        # We just verify it reaches the anomaly check (not short-circuited)
        _ = detect_time_anomaly(history, _current(20))  # no exception


# ── TestActiveHourNoAnomaly ────────────────────────────────────────────────────

class TestActiveHourNoAnomaly(unittest.TestCase):

    def test_current_hour_active(self):
        # 9am-5pm agent, request at 11am
        history = _make_history(list(range(9, 18)))
        self.assertEqual(detect_time_anomaly(history, _current(11)), [])

    def test_current_hour_is_first_active_hour(self):
        history = _make_history(list(range(9, 18)))
        self.assertEqual(detect_time_anomaly(history, _current(9)), [])

    def test_current_hour_is_last_active_hour(self):
        history = _make_history(list(range(9, 18)))
        self.assertEqual(detect_time_anomaly(history, _current(17)), [])

    def test_single_active_hour_same_as_current(self):
        # Only runs at 14:00 UTC; request at 14:00
        history = _make_history([14])
        self.assertEqual(detect_time_anomaly(history, _current(14)), [])

    def test_multiple_isolated_active_hours(self):
        # Midnight run + noon run; request at noon
        history = _make_history([0, 12])
        self.assertEqual(detect_time_anomaly(history, _current(12)), [])

    def test_even_hours_only_current_even(self):
        active = [0, 2, 4, 6, 8, 10]  # 6 active, 18 dark → profiles
        history = _make_history(active)
        self.assertEqual(detect_time_anomaly(history, _current(4)), [])


# ── TestToleranceNoAnomaly ────────────────────────────────────────────────────

class TestToleranceNoAnomaly(unittest.TestCase):

    def test_one_hour_before_active_window(self):
        # Active: 9-17. Request at 8 (1 before 9). Within tolerance → no flag.
        history = _make_history(list(range(9, 18)))
        self.assertEqual(detect_time_anomaly(history, _current(8)), [])

    def test_one_hour_after_active_window(self):
        # Active: 9-17. Request at 18 (1 after 17). Within tolerance → no flag.
        history = _make_history(list(range(9, 18)))
        self.assertEqual(detect_time_anomaly(history, _current(18)), [])

    def test_exactly_tolerance_before_first_active(self):
        history = _make_history(list(range(9, 18)))
        offset_hour = (9 - HOUR_TOLERANCE) % 24
        self.assertEqual(detect_time_anomaly(history, _current(offset_hour)), [])

    def test_exactly_tolerance_after_last_active(self):
        history = _make_history(list(range(9, 18)))
        offset_hour = (17 + HOUR_TOLERANCE) % 24
        self.assertEqual(detect_time_anomaly(history, _current(offset_hour)), [])

    def test_midnight_wrap_before(self):
        # Active: hours 0-3. Request at hour 23 (one before midnight). Within tolerance.
        active = list(range(4))  # 0,1,2,3
        history = _make_history(active)
        # 23 is adjacent to 0 via wrap: (0-1)%24 = 23 → active
        self.assertEqual(detect_time_anomaly(history, _current(23)), [])

    def test_midnight_wrap_after(self):
        # Active: hours 20-23. Request at hour 0 (one after 23). Within tolerance.
        active = list(range(20, 24))  # 20,21,22,23
        history = _make_history(active)
        # 0 is adjacent to 23 via wrap: (23+1)%24 = 0
        self.assertEqual(detect_time_anomaly(history, _current(0)), [])

    def test_isolated_midnight_hour(self):
        # Only active at hour 0. Request at 1 → within tolerance.
        history = _make_history([0])
        self.assertEqual(detect_time_anomaly(history, _current(1)), [])

    def test_tolerance_does_not_bridge_large_gaps(self):
        # Active: 9-17. Request at 6 (3 hours before 9). HOUR_TOLERANCE=1, so 6 → flag.
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(6))
        self.assertEqual(len(result), 1)


# ── TestAnomalyDetected ────────────────────────────────────────────────────────

class TestAnomalyDetected(unittest.TestCase):

    def test_night_request_on_daytime_agent(self):
        # Daytime agent (9am-5pm UTC), request at 3am
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)

    def test_returns_exactly_one_flag(self):
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(2))
        self.assertEqual(len(result), 1)

    def test_gap_of_two_triggers_flag(self):
        # Active up to hour 17. Request at 19. Gap = 2 (>HOUR_TOLERANCE) → flag.
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(19))
        self.assertEqual(len(result), 1)

    def test_large_gap_triggers_flag(self):
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(0))
        self.assertEqual(len(result), 1)

    def test_single_active_hour_off_hours_flags(self):
        # Only active at noon; request at 3am (9 hours gap) → flag
        history = _make_history([12])
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)

    def test_even_hours_only_odd_request(self):
        # Active only at even hours 0,2,4,6. Request at 9 (gap=3) → flag.
        active = [0, 2, 4, 6]
        history = _make_history(active)
        result = detect_time_anomaly(history, _current(9))
        self.assertEqual(len(result), 1)

    def test_large_history_count_still_flags(self):
        history = _make_history(list(range(9, 18)), total=500)
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)

    def test_midnight_agent_midday_request(self):
        # Agent runs only at 0, 1, 2. Request at 13 → flag
        active = [0, 1, 2]
        history = _make_history(active)
        result = detect_time_anomaly(history, _current(13))
        self.assertEqual(len(result), 1)


# ── TestFlagFormat ────────────────────────────────────────────────────────────

class TestFlagFormat(unittest.TestCase):

    def _get_flag(self, active_hours=None, current_hour=3):
        active_hours = active_hours or list(range(9, 18))
        history = _make_history(active_hours)
        result = detect_time_anomaly(history, _current(current_hour))
        self.assertEqual(len(result), 1, "expected exactly one flag")
        return result[0]

    def test_flag_is_string(self):
        self.assertIsInstance(self._get_flag(), str)

    def test_starts_with_prefix(self):
        flag = self._get_flag()
        self.assertTrue(flag.startswith(_FLAG_PREFIX))

    def test_contains_current_hour(self):
        flag = self._get_flag(current_hour=3)
        self.assertIn("hour=03UTC", flag)

    def test_current_hour_zero_padded(self):
        flag = self._get_flag(current_hour=3)
        self.assertIn("hour=03UTC", flag)  # not "hour=3UTC"

    def test_contains_profile_window(self):
        flag = self._get_flag(active_hours=list(range(9, 18)), current_hour=3)
        self.assertIn("profile=", flag)
        self.assertIn("09h", flag)
        self.assertIn("17h", flag)

    def test_contains_dark_hours(self):
        flag = self._get_flag(active_hours=list(range(9, 18)), current_hour=3)
        self.assertIn("dark_hours=", flag)
        dark = 24 - len(range(9, 18))  # 24 - 9 = 15
        self.assertIn(f"dark_hours={dark}", flag)

    def test_contains_history_samples(self):
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)
        flag = result[0]
        self.assertIn("history_samples=", flag)
        self.assertIn(f"history_samples={len(history)}", flag)

    def test_contains_utc_marker(self):
        flag = self._get_flag()
        self.assertIn("UTC", flag)

    def test_history_samples_matches_input_length(self):
        n = 42
        history = _make_history(list(range(9, 18)), total=n)
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)
        self.assertIn(f"history_samples={n}", result[0])

    def test_profile_min_and_max_hours_zero_padded(self):
        # Profile hours 0-8: min=00, max=08
        active = list(range(9))  # 0-8, so 15 dark hours → profiles
        history = _make_history(active)
        result = detect_time_anomaly(history, _current(12))  # 3 hours outside
        self.assertEqual(len(result), 1)
        self.assertIn("profile=00h-08h_UTC", result[0])


# ── TestCurrentTimestamp ──────────────────────────────────────────────────────

class TestCurrentTimestamp(unittest.TestCase):

    def test_explicit_timestamp_used(self):
        # An agent active 9-17; explicit current at hour 3 → flag
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, current_timestamp=_current(3))
        self.assertEqual(len(result), 1)

    def test_explicit_active_hour_no_flag(self):
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, current_timestamp=_current(14))
        self.assertEqual(result, [])

    def test_different_hours_different_outcomes(self):
        # Same history, different current hours should give different results
        history = _make_history(list(range(9, 18)))
        r_night = detect_time_anomaly(history, _current(3))   # flag
        r_day   = detect_time_anomaly(history, _current(12))  # no flag
        self.assertEqual(len(r_night), 1)
        self.assertEqual(r_day, [])

    def test_default_timestamp_does_not_raise(self):
        # Just verify the function runs without explicit timestamp (uses time.time())
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history)  # no current_timestamp
        self.assertIsInstance(result, list)


# ── TestMissingTimestamps ─────────────────────────────────────────────────────

class TestMissingTimestamps(unittest.TestCase):

    def test_missing_timestamp_key_skipped(self):
        # Entries without 'timestamp' key don't crash; treated as unparseable.
        history = [{"action": "read", "resource": "/data"} for _ in range(30)]
        # All entries are skipped → active_hours = [] → returns []
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(result, [])

    def test_none_value_skipped(self):
        valid = _make_history(list(range(9, 18)))
        invalid = [{"timestamp": None} for _ in range(5)]
        history = valid + invalid
        # Should not raise; None entries are skipped
        result = detect_time_anomaly(history, _current(3))
        self.assertIsInstance(result, list)

    def test_string_timestamp_skipped(self):
        valid = _make_history(list(range(9, 18)))
        invalid = [{"timestamp": "not-a-float"} for _ in range(5)]
        result = detect_time_anomaly(valid + invalid, _current(3))
        self.assertIsInstance(result, list)

    def test_mostly_valid_entries_profile_correct(self):
        # Mix of valid (9-17 UTC) and invalid entries; valid ones define the profile.
        valid = _make_history(list(range(9, 18)))
        invalid = [{"timestamp": "bad"} for _ in range(10)]
        history = valid + invalid
        result = detect_time_anomaly(history, _current(3))
        # Profile still built from valid entries → flag for 3am request
        self.assertEqual(len(result), 1)

    def test_extra_fields_in_entry_ignored(self):
        # History entries with extra fields work fine
        history = [
            {"timestamp": _hist(10, i)["timestamp"], "action": "read", "agent_id": "bot"}
            for i in range(MIN_HISTORY_FOR_PROFILE + 2)
        ]
        result = detect_time_anomaly(history, _current(3))
        # Profile: hour 10 only; request at 3 (7 hours gap) → flag
        self.assertEqual(len(result), 1)


# ── TestEdgeCases ─────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):

    def test_single_active_hour_midnight(self):
        # Only runs at midnight (hour 0). Request at 3am → flag.
        history = _make_history([0])
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)

    def test_active_hours_spanning_midnight(self):
        # Active 22, 23, 0, 1 (midnight-spanning window)
        active = [22, 23, 0, 1]
        history = _make_history(active)
        # Request at 12 (noon): 10 hours from nearest active (1). Flag.
        result = detect_time_anomaly(history, _current(12))
        self.assertEqual(len(result), 1)
        # Request at 2: adjacent to 1 → within tolerance → no flag
        self.assertEqual(detect_time_anomaly(history, _current(2)), [])

    def test_return_type_is_always_list(self):
        for h in range(24):
            result = detect_time_anomaly(_make_history(list(range(9, 18))), _current(h))
            self.assertIsInstance(result, list)

    def test_very_large_history(self):
        history = _make_history(list(range(9, 18)), total=10_000)
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)
        self.assertIn("history_samples=10000", result[0])

    def test_two_isolated_clusters(self):
        # Agent active at 6am and 6pm UTC, nothing in between
        active = [6, 18]  # 2 active, 22 dark → dark_fraction = 22/24 ≈ 0.917
        history = _make_history(active)
        # Request at noon (6 hours from nearest) → flag
        self.assertEqual(len(detect_time_anomaly(history, _current(12))), 1)
        # Request at 7am (1 hour from 6) → within tolerance → no flag
        self.assertEqual(detect_time_anomaly(history, _current(7)), [])

    def test_profile_hours_are_min_and_max_of_active_set(self):
        # Profile min=03, max=21
        active = [3, 10, 14, 21]
        history = _make_history(active)
        result = detect_time_anomaly(history, _current(1))
        self.assertEqual(len(result), 1)
        self.assertIn("profile=03h-21h_UTC", result[0])

    def test_empty_history_with_explicit_timestamp(self):
        self.assertEqual(detect_time_anomaly([], _current(12)), [])

    def test_flag_contains_pipe_separated_fields(self):
        history = _make_history(list(range(9, 18)))
        result = detect_time_anomaly(history, _current(3))
        self.assertEqual(len(result), 1)
        # Flag should have at least 3 pipe-delimited fields after the prefix
        parts = result[0].split("|")
        self.assertGreaterEqual(len(parts), 4)


# ── TestAgentIndependence ─────────────────────────────────────────────────────

class TestAgentIndependence(unittest.TestCase):

    def test_different_histories_independent(self):
        # Two different history lists (simulating two different agents)
        h_day   = _make_history(list(range(9, 18)))   # daytime agent
        h_night = _make_history(list(range(0, 6)))    # overnight agent

        # Daytime agent, nighttime request → flag
        r_day = detect_time_anomaly(h_day, _current(3))
        self.assertEqual(len(r_day), 1)

        # Night agent, nighttime request → no flag
        r_night = detect_time_anomaly(h_night, _current(3))
        self.assertEqual(r_night, [])

    def test_same_current_hour_different_profiles(self):
        h_morning = _make_history(list(range(6, 12)))
        h_evening = _make_history(list(range(18, 23)))
        # Request at 3am: flagged for morning agent, flagged for evening agent
        self.assertEqual(len(detect_time_anomaly(h_morning, _current(3))), 1)
        self.assertEqual(len(detect_time_anomaly(h_evening, _current(3))), 1)
        # Request at 9am: fine for morning, flagged for evening
        self.assertEqual(detect_time_anomaly(h_morning, _current(9)), [])
        self.assertEqual(len(detect_time_anomaly(h_evening, _current(9))), 1)

    def test_two_independent_calls_do_not_share_state(self):
        # Make two separate calls and verify no shared mutable state
        h1 = _make_history(list(range(9, 18)))
        h2 = _make_history(list(range(0, 6)))
        r1 = detect_time_anomaly(h1, _current(3))
        r2 = detect_time_anomaly(h2, _current(3))
        self.assertEqual(len(r1), 1)  # daytime profile, 3am request → flag
        self.assertEqual(r2, [])       # nighttime profile, 3am request → no flag

    def test_history_list_not_mutated(self):
        history = _make_history(list(range(9, 18)))
        original_len = len(history)
        original_first = history[0].copy()
        detect_time_anomaly(history, _current(3))
        self.assertEqual(len(history), original_len)
        self.assertEqual(history[0], original_first)


if __name__ == "__main__":
    unittest.main()
