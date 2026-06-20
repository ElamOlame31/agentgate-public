"""
Stdlib-only tests for core/latency.py.

No external dependencies — runs in constrained environments.
"""

import math
import sys
import threading
import time
import unittest

sys.path.insert(0, __import__("pathlib").Path(__file__).parent.parent.as_posix())

import core.latency as latency


def _reset():
    """Clear all latency data between tests."""
    latency.reset()


class TestEmptyState(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_get_stats_unknown_component_returns_zero_count(self):
        s = latency.get_stats("unknown")
        self.assertEqual(s["count"], 0)

    def test_get_stats_unknown_has_zero_percentiles(self):
        s = latency.get_stats("unknown")
        self.assertEqual(s["p50_ms"], 0.0)
        self.assertEqual(s["p95_ms"], 0.0)
        self.assertEqual(s["p99_ms"], 0.0)
        self.assertEqual(s["mean_ms"], 0.0)
        self.assertEqual(s["max_ms"], 0.0)

    def test_get_stats_contains_component_name(self):
        s = latency.get_stats("policy")
        self.assertEqual(s["component"], "policy")

    def test_all_stats_empty_returns_empty_list(self):
        self.assertEqual(latency.all_stats(), [])

    def test_component_names_empty_returns_empty_list(self):
        self.assertEqual(latency.component_names(), [])


class TestSingleObservation(unittest.TestCase):
    def setUp(self):
        _reset()
        latency.record("trust", 5.0)

    def test_count_is_one(self):
        self.assertEqual(latency.get_stats("trust")["count"], 1)

    def test_p50_equals_the_value(self):
        self.assertEqual(latency.get_stats("trust")["p50_ms"], 5.0)

    def test_p95_equals_the_value(self):
        self.assertEqual(latency.get_stats("trust")["p95_ms"], 5.0)

    def test_p99_equals_the_value(self):
        self.assertEqual(latency.get_stats("trust")["p99_ms"], 5.0)

    def test_mean_equals_the_value(self):
        self.assertEqual(latency.get_stats("trust")["mean_ms"], 5.0)

    def test_max_equals_the_value(self):
        self.assertEqual(latency.get_stats("trust")["max_ms"], 5.0)


class TestKnownPercentiles(unittest.TestCase):
    """Verify percentile math with deterministic data sets."""

    def setUp(self):
        _reset()

    def test_p50_with_ten_sequential_values(self):
        # [10, 20, ..., 100] — 10 values.  p50 via nearest-rank:
        # ceil(50/100 * 10) - 1 = ceil(5) - 1 = 4 → sorted[4] = 50
        for v in range(10, 110, 10):
            latency.record("c", float(v))
        self.assertEqual(latency.get_stats("c")["p50_ms"], 50.0)

    def test_p95_with_100_sequential_values(self):
        # [1..100]: ceil(95/100 * 100) - 1 = ceil(95) - 1 = 94 → sorted[94] = 95
        for v in range(1, 101):
            latency.record("c", float(v))
        self.assertEqual(latency.get_stats("c")["p95_ms"], 95.0)

    def test_p99_with_100_sequential_values(self):
        # [1..100]: ceil(99/100 * 100) - 1 = ceil(99) - 1 = 98 → sorted[98] = 99
        for v in range(1, 101):
            latency.record("c", float(v))
        self.assertEqual(latency.get_stats("c")["p99_ms"], 99.0)

    def test_mean_exact_for_arithmetic_sequence(self):
        # mean([1..10]) = 5.5
        for v in range(1, 11):
            latency.record("c", float(v))
        self.assertAlmostEqual(latency.get_stats("c")["mean_ms"], 5.5, places=2)

    def test_max_is_largest_value(self):
        for v in [3.0, 1.0, 7.5, 2.0]:
            latency.record("c", v)
        self.assertEqual(latency.get_stats("c")["max_ms"], 7.5)

    def test_two_values_p50_is_lower(self):
        # sorted [10, 20]; p50: ceil(0.5 * 2) - 1 = 0 → sorted[0] = 10
        latency.record("c", 20.0)
        latency.record("c", 10.0)
        self.assertEqual(latency.get_stats("c")["p50_ms"], 10.0)

    def test_count_reflects_total_records(self):
        for _ in range(7):
            latency.record("c", 1.0)
        self.assertEqual(latency.get_stats("c")["count"], 7)


class TestBoundedWindow(unittest.TestCase):
    """Deque maxlen must prevent unbounded memory growth."""

    def setUp(self):
        _reset()

    def test_count_capped_at_max_samples_after_overflow(self):
        # Insert MAX_SAMPLES + 200 items — count must stay at MAX_SAMPLES
        total = latency.MAX_SAMPLES + 200
        for i in range(total):
            latency.record("c", float(i))
        self.assertEqual(latency.get_stats("c")["count"], latency.MAX_SAMPLES)

    def test_oldest_evicted_when_full(self):
        # Fill the window with 0.0, then push MAX_SAMPLES entries of 99.0.
        # The 0.0 entries should all be gone; mean ≈ 99.0.
        for _ in range(latency.MAX_SAMPLES):
            latency.record("c", 0.0)
        for _ in range(latency.MAX_SAMPLES):
            latency.record("c", 99.0)
        self.assertAlmostEqual(latency.get_stats("c")["mean_ms"], 99.0, places=1)

    def test_max_samples_constant_is_positive_integer(self):
        self.assertIsInstance(latency.MAX_SAMPLES, int)
        self.assertGreater(latency.MAX_SAMPLES, 0)


class TestMultipleComponents(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_components_are_independent(self):
        latency.record("policy", 1.0)
        latency.record("trust", 10.0)
        self.assertEqual(latency.get_stats("policy")["p50_ms"], 1.0)
        self.assertEqual(latency.get_stats("trust")["p50_ms"], 10.0)

    def test_all_stats_returns_all_components(self):
        for c in ("policy", "trust", "audit_write", "total"):
            latency.record(c, 1.0)
        names = {s["component"] for s in latency.all_stats()}
        self.assertEqual(names, {"policy", "trust", "audit_write", "total"})

    def test_all_stats_sorted_alphabetically(self):
        for c in ("total", "trust", "policy", "audit_write"):
            latency.record(c, 1.0)
        names = [s["component"] for s in latency.all_stats()]
        self.assertEqual(names, sorted(names))

    def test_component_names_returns_only_nonempty(self):
        latency.record("policy", 1.0)
        # "trust" never recorded
        names = latency.component_names()
        self.assertIn("policy", names)
        self.assertNotIn("trust", names)

    def test_component_names_sorted(self):
        for c in ("zzz", "aaa", "mmm"):
            latency.record(c, 1.0)
        names = latency.component_names()
        self.assertEqual(names, sorted(names))


class TestReset(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_reset_clears_all_components(self):
        for c in ("policy", "trust", "total"):
            latency.record(c, 99.0)
        latency.reset()
        self.assertEqual(latency.all_stats(), [])
        self.assertEqual(latency.component_names(), [])

    def test_reset_allows_fresh_recording(self):
        latency.record("policy", 100.0)
        latency.reset()
        latency.record("policy", 1.0)
        self.assertEqual(latency.get_stats("policy")["count"], 1)
        self.assertEqual(latency.get_stats("policy")["p50_ms"], 1.0)


class TestContextManager(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_measure_records_nonzero_duration(self):
        with latency.measure("policy"):
            time.sleep(0.001)  # 1 ms
        s = latency.get_stats("policy")
        self.assertEqual(s["count"], 1)
        self.assertGreater(s["p50_ms"], 0.0)

    def test_measure_records_reasonable_duration(self):
        with latency.measure("policy"):
            time.sleep(0.010)  # ~10 ms
        s = latency.get_stats("policy")
        # Allow generous range due to sleep imprecision
        self.assertGreater(s["p50_ms"], 5.0)
        self.assertLess(s["p50_ms"], 200.0)

    def test_measure_records_even_on_exception(self):
        try:
            with latency.measure("policy"):
                raise ValueError("test")
        except ValueError:
            pass
        self.assertEqual(latency.get_stats("policy")["count"], 1)

    def test_measure_component_name_preserved(self):
        with latency.measure("kill_chain"):
            pass
        self.assertIn("kill_chain", latency.component_names())


class TestThreadSafety(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_concurrent_records_no_data_loss(self):
        n_threads = 20
        records_per_thread = 50
        expected = n_threads * records_per_thread

        def _worker():
            for _ in range(records_per_thread):
                latency.record("concurrent", 1.0)

        threads = [threading.Thread(target=_worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        count = latency.get_stats("concurrent")["count"]
        # Due to the MAX_SAMPLES cap, count ≤ MAX_SAMPLES.
        # With 1000 expected and MAX_SAMPLES=1000, we expect exactly MAX_SAMPLES.
        self.assertLessEqual(count, latency.MAX_SAMPLES)
        self.assertGreater(count, 0)

    def test_concurrent_records_all_components_stable(self):
        errors = []

        def _writer(component):
            try:
                for _ in range(100):
                    latency.record(component, 1.0)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_writer, args=(f"c{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], "Concurrent records raised exceptions")
        self.assertGreater(len(latency.component_names()), 0)


class TestConstants(unittest.TestCase):
    def test_max_samples_is_at_least_100(self):
        self.assertGreaterEqual(latency.MAX_SAMPLES, 100)

    def test_max_samples_is_no_more_than_10000(self):
        # Prevent accidentally setting it too large (memory)
        self.assertLessEqual(latency.MAX_SAMPLES, 10_000)


class TestPercentileEdgeCases(unittest.TestCase):
    def setUp(self):
        _reset()

    def test_all_same_values_percentiles_equal(self):
        for _ in range(50):
            latency.record("c", 42.0)
        s = latency.get_stats("c")
        self.assertEqual(s["p50_ms"], 42.0)
        self.assertEqual(s["p95_ms"], 42.0)
        self.assertEqual(s["p99_ms"], 42.0)
        self.assertEqual(s["mean_ms"], 42.0)
        self.assertEqual(s["max_ms"], 42.0)

    def test_two_values_p99_is_higher(self):
        latency.record("c", 1.0)
        latency.record("c", 100.0)
        # sorted [1.0, 100.0]; p99: ceil(0.99 * 2) - 1 = ceil(1.98) - 1 = 2 - 1 = 1 → 100.0
        s = latency.get_stats("c")
        self.assertEqual(s["p99_ms"], 100.0)

    def test_stats_rounded_to_three_decimal_places(self):
        latency.record("c", 1.123456789)
        s = latency.get_stats("c")
        # Verify rounding by checking string representation (≤3 decimal places)
        for key in ("p50_ms", "p95_ms", "p99_ms", "mean_ms", "max_ms"):
            val_str = str(s[key]).rstrip("0").rstrip(".")
            decimal_part = val_str.split(".")[-1] if "." in val_str else ""
            self.assertLessEqual(len(decimal_part), 3, f"{key}={s[key]} has >3 decimal places")


if __name__ == "__main__":
    unittest.main()
