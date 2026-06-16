"""
Stdlib-only tests for the fail-closed behavior module (core/fail_mode.py).

Tests verify:
  - Default is fail-closed (no env var required)
  - AGENTGATE_FAIL_MODE=open disables fail-closed
  - Case and whitespace handling
  - Public constant shapes
  - FAIL_CLOSED_EXPLANATION does not expose exception internals

No external dependencies — runs in environments without pydantic/fastapi.
Integration tests covering the /authorize endpoint behavior (which require
the full dependency stack) live in test_comprehensive.py.
"""

import os
import sys
import unittest


def _import_fail_mode():
    """Import (or re-import) fail_mode with the current env var in effect."""
    # Remove cached module so env changes are visible
    sys.modules.pop("core.fail_mode", None)
    # Ensure the project root is on sys.path
    proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if proj_root not in sys.path:
        sys.path.insert(0, proj_root)
    from core import fail_mode
    return fail_mode


class TestIsFailClosedDefault(unittest.TestCase):
    """is_fail_closed() reads the env var at call time — verify defaults."""

    def setUp(self):
        os.environ.pop("AGENTGATE_FAIL_MODE", None)

    def tearDown(self):
        os.environ.pop("AGENTGATE_FAIL_MODE", None)

    def test_default_is_closed(self):
        fm = _import_fail_mode()
        self.assertTrue(fm.is_fail_closed())

    def test_explicit_closed_is_closed(self):
        os.environ["AGENTGATE_FAIL_MODE"] = "closed"
        fm = _import_fail_mode()
        self.assertTrue(fm.is_fail_closed())

    def test_open_disables_fail_closed(self):
        os.environ["AGENTGATE_FAIL_MODE"] = "open"
        fm = _import_fail_mode()
        self.assertFalse(fm.is_fail_closed())

    def test_unknown_value_defaults_to_closed(self):
        # Anything other than "open" is treated as closed (safe default).
        for value in ("", "CLOSED", "disabled", "false", "0", "none"):
            os.environ["AGENTGATE_FAIL_MODE"] = value
            fm = _import_fail_mode()
            self.assertTrue(fm.is_fail_closed(), f"Expected closed for AGENTGATE_FAIL_MODE={value!r}")

    def test_open_is_case_insensitive(self):
        for value in ("OPEN", "Open", "oPeN"):
            os.environ["AGENTGATE_FAIL_MODE"] = value
            fm = _import_fail_mode()
            self.assertFalse(fm.is_fail_closed(), f"Expected open for AGENTGATE_FAIL_MODE={value!r}")

    def test_open_with_surrounding_whitespace(self):
        os.environ["AGENTGATE_FAIL_MODE"] = "  open  "
        fm = _import_fail_mode()
        self.assertFalse(fm.is_fail_closed())

    def test_closed_with_surrounding_whitespace(self):
        os.environ["AGENTGATE_FAIL_MODE"] = "  closed  "
        fm = _import_fail_mode()
        self.assertTrue(fm.is_fail_closed())

    def test_env_change_reflected_without_reimport(self):
        # is_fail_closed() reads env at call time — verify live updates.
        fm = _import_fail_mode()
        os.environ.pop("AGENTGATE_FAIL_MODE", None)
        self.assertTrue(fm.is_fail_closed())
        os.environ["AGENTGATE_FAIL_MODE"] = "open"
        self.assertFalse(fm.is_fail_closed())
        os.environ.pop("AGENTGATE_FAIL_MODE", None)
        self.assertTrue(fm.is_fail_closed())


class TestFailClosedConstants(unittest.TestCase):
    """Verify the public constants have the required shape and content."""

    def setUp(self):
        os.environ.pop("AGENTGATE_FAIL_MODE", None)

    def tearDown(self):
        os.environ.pop("AGENTGATE_FAIL_MODE", None)

    def test_flag_is_string(self):
        fm = _import_fail_mode()
        self.assertIsInstance(fm.FAIL_CLOSED_FLAG, str)

    def test_flag_is_nonempty(self):
        fm = _import_fail_mode()
        self.assertTrue(fm.FAIL_CLOSED_FLAG.strip())

    def test_flag_starts_with_fail(self):
        fm = _import_fail_mode()
        self.assertTrue(fm.FAIL_CLOSED_FLAG.upper().startswith("FAIL_"))

    def test_explanation_is_string(self):
        fm = _import_fail_mode()
        self.assertIsInstance(fm.FAIL_CLOSED_EXPLANATION, str)

    def test_explanation_is_nonempty(self):
        fm = _import_fail_mode()
        self.assertTrue(fm.FAIL_CLOSED_EXPLANATION.strip())

    def test_explanation_does_not_leak_exception_class_names(self):
        # The explanation string is returned directly to callers and must not
        # expose internal Python exception class names or tracebacks.
        fm = _import_fail_mode()
        for bad_term in ("Traceback", "traceback", "Error:", "Exception:", "line ", "File "):
            self.assertNotIn(
                bad_term, fm.FAIL_CLOSED_EXPLANATION,
                f"FAIL_CLOSED_EXPLANATION must not contain {bad_term!r}",
            )

    def test_explanation_mentions_fail_closed(self):
        fm = _import_fail_mode()
        self.assertIn("closed", fm.FAIL_CLOSED_EXPLANATION.lower())

    def test_explanation_mentions_internal_error(self):
        fm = _import_fail_mode()
        self.assertIn("internal error", fm.FAIL_CLOSED_EXPLANATION.lower())

    def test_explanation_guides_operator(self):
        # Must tell the operator where to look — logs are the right place.
        fm = _import_fail_mode()
        self.assertIn("log", fm.FAIL_CLOSED_EXPLANATION.lower())

    def test_explanation_references_fail_mode_setting(self):
        fm = _import_fail_mode()
        self.assertIn("AGENTGATE_FAIL_MODE", fm.FAIL_CLOSED_EXPLANATION)


class TestFailModeDocstring(unittest.TestCase):
    """Verify the module is documented — auditors and integrators read it."""

    def test_module_has_docstring(self):
        fm = _import_fail_mode()
        self.assertTrue(
            fm.__doc__ and fm.__doc__.strip(),
            "core/fail_mode.py must have a module-level docstring",
        )

    def test_is_fail_closed_has_docstring(self):
        fm = _import_fail_mode()
        self.assertTrue(
            fm.is_fail_closed.__doc__ and fm.is_fail_closed.__doc__.strip(),
            "is_fail_closed() must have a docstring",
        )


if __name__ == "__main__":
    unittest.main()
