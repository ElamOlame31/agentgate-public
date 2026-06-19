"""
Stdlib-only tests for core/trifecta.py — lethal trifecta detection.

No pydantic / fastapi / sentence-transformers required.
Tests cover all three trifecta conditions, both flag variants (EXFIL / RISK),
safe read-only suppression, helper functions, and constant invariants.
"""

import unittest

from core.trifecta import (
    detect_lethal_trifecta,
    _has_sensitive_reach,
    _has_egress,
    _EXFILTRATION_ACTIONS,
    _READ_ONLY_ACTIONS,
    _SENSITIVE_RESOURCE_KEYWORDS,
    LETHAL_TRIFECTA_EXFIL,
    LETHAL_TRIFECTA_RISK,
)

# ── Shared fixtures ──────────────────────────────────────────────────────────

# Agent with all three trifecta conditions
_TRIFECTA_RESOURCES = ["/hr/salary.csv", "/documents/public/*"]
_TRIFECTA_ACTIONS   = ["read", "email"]

# Incomplete configurations — one condition absent each time
_NO_SENSITIVE_RESOURCES = ["/documents/public/*", "/reports/quarterly/*"]
_NO_EGRESS_ACTIONS      = ["read", "search"]


class TestConditionsMissing(unittest.TestCase):
    """No flags are returned when one or more trifecta conditions are absent."""

    def test_external_content_false_suppresses_all(self):
        flags = detect_lethal_trifecta(
            processes_external_content=False,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertEqual(flags, [])

    def test_no_sensitive_reach_suppresses_all(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertEqual(flags, [])

    def test_no_egress_suppresses_all(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="email",
        )
        self.assertEqual(flags, [])

    def test_only_external_condition_active(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="read",
        )
        self.assertEqual(flags, [])

    def test_only_reach_condition_active(self):
        flags = detect_lethal_trifecta(
            processes_external_content=False,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="read",
        )
        self.assertEqual(flags, [])

    def test_only_egress_condition_active(self):
        flags = detect_lethal_trifecta(
            processes_external_content=False,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertEqual(flags, [])

    def test_none_of_the_conditions_active(self):
        flags = detect_lethal_trifecta(
            processes_external_content=False,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="read",
        )
        self.assertEqual(flags, [])

    def test_two_conditions_missing_exfil_action(self):
        # Even though the action is exfil, two conditions are absent — no flag
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="upload",
        )
        self.assertEqual(flags, [])

    def test_external_and_egress_but_no_reach(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_NO_SENSITIVE_RESOURCES,
            authorized_actions=["read", "send"],
            action="send",
        )
        self.assertEqual(flags, [])

    def test_external_and_reach_but_no_egress(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_NO_EGRESS_ACTIONS,
            action="read",
        )
        self.assertEqual(flags, [])


class TestExfilVariant(unittest.TestCase):
    """LETHAL_TRIFECTA:EXFIL fires when all three conditions + exfil action."""

    def test_email_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_upload_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/hr/*"],
            authorized_actions=["read", "upload"],
            action="upload",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_send_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/confidential/*"],
            authorized_actions=["read", "send"],
            action="send",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_export_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/finance/q3.xlsx"],
            authorized_actions=["read", "export"],
            action="export",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_publish_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/salary.csv"],
            authorized_actions=["read", "publish"],
            action="publish",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_forward_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/hr/employees.xlsx"],
            authorized_actions=["read", "forward"],
            action="forward",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_transfer_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/vault/keys/*"],
            authorized_actions=["read", "transfer"],
            action="transfer",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_post_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/pii/customer_data/*"],
            authorized_actions=["read", "post"],
            action="post",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_exfil_flag_is_single_item(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertEqual(len(flags), 1)

    def test_exfil_action_uppercase_normalised(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="EMAIL",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_exfil_action_mixed_case_normalised(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="Upload",
        )
        self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_no_risk_flag_on_exfil(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="email",
        )
        self.assertNotIn(LETHAL_TRIFECTA_RISK, flags)

    def test_all_exfiltration_actions_fire_exfil(self):
        for exfil_action in _EXFILTRATION_ACTIONS:
            with self.subTest(action=exfil_action):
                flags = detect_lethal_trifecta(
                    processes_external_content=True,
                    authorized_resources=_TRIFECTA_RESOURCES,
                    authorized_actions=["read", exfil_action],
                    action=exfil_action,
                )
                self.assertIn(LETHAL_TRIFECTA_EXFIL, flags)


class TestRiskVariant(unittest.TestCase):
    """LETHAL_TRIFECTA:RISK fires when all three conditions + non-read, non-exfil action."""

    def test_write_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["read", "write", "email"],
            action="write",
        )
        self.assertIn(LETHAL_TRIFECTA_RISK, flags)

    def test_delete_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["read", "delete", "send"],
            action="delete",
        )
        self.assertIn(LETHAL_TRIFECTA_RISK, flags)

    def test_admin_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/hr/employees/*"],
            authorized_actions=["read", "admin", "upload"],
            action="admin",
        )
        self.assertIn(LETHAL_TRIFECTA_RISK, flags)

    def test_update_action(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=["/finance/*"],
            authorized_actions=["read", "update", "export"],
            action="update",
        )
        self.assertIn(LETHAL_TRIFECTA_RISK, flags)

    def test_risk_flag_is_single_item(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["read", "write", "send"],
            action="write",
        )
        self.assertEqual(len(flags), 1)

    def test_no_exfil_flag_on_risk(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["read", "write", "send"],
            action="write",
        )
        self.assertNotIn(LETHAL_TRIFECTA_EXFIL, flags)

    def test_risk_action_uppercase_normalised(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["read", "write", "send"],
            action="WRITE",
        )
        self.assertIn(LETHAL_TRIFECTA_RISK, flags)


class TestSafeReadActions(unittest.TestCase):
    """No flags when all three conditions are active but action is read-only."""

    def test_read_action_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="read",
        )
        self.assertEqual(flags, [])

    def test_search_action_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["search", "send"],
            action="search",
        )
        self.assertEqual(flags, [])

    def test_list_action_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["list", "upload"],
            action="list",
        )
        self.assertEqual(flags, [])

    def test_query_action_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["query", "email"],
            action="query",
        )
        self.assertEqual(flags, [])

    def test_get_action_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=["get", "export"],
            action="get",
        )
        self.assertEqual(flags, [])

    def test_all_read_only_actions_produce_no_flags(self):
        for ro_action in _READ_ONLY_ACTIONS:
            with self.subTest(action=ro_action):
                flags = detect_lethal_trifecta(
                    processes_external_content=True,
                    authorized_resources=_TRIFECTA_RESOURCES,
                    authorized_actions=[ro_action, "upload"],
                    action=ro_action,
                )
                self.assertEqual(
                    flags, [],
                    msg=f"Read-only action '{ro_action}' should produce no flag",
                )

    def test_read_action_uppercase_no_flag(self):
        flags = detect_lethal_trifecta(
            processes_external_content=True,
            authorized_resources=_TRIFECTA_RESOURCES,
            authorized_actions=_TRIFECTA_ACTIONS,
            action="READ",
        )
        self.assertEqual(flags, [])


class TestHasSensitiveReach(unittest.TestCase):
    """Unit tests for the _has_sensitive_reach helper."""

    def test_salary_path(self):
        self.assertTrue(_has_sensitive_reach(["/hr/salary.csv"]))

    def test_confidential_path(self):
        self.assertTrue(_has_sensitive_reach(["/confidential/reports/*"]))

    def test_finance_path(self):
        self.assertTrue(_has_sensitive_reach(["/finance/q3.xlsx"]))

    def test_pii_path(self):
        self.assertTrue(_has_sensitive_reach(["/data/pii_exports/*"]))

    def test_hr_path(self):
        self.assertTrue(_has_sensitive_reach(["/hr/employees/*"]))

    def test_medical_path(self):
        self.assertTrue(_has_sensitive_reach(["/health/records/*"]))

    def test_credential_path(self):
        self.assertTrue(_has_sensitive_reach(["/credentials/db_password"]))

    def test_vault_path(self):
        self.assertTrue(_has_sensitive_reach(["/vault/secrets/*"]))

    def test_nda_path(self):
        self.assertTrue(_has_sensitive_reach(["/legal/nda_template.docx"]))

    def test_merger_path(self):
        self.assertTrue(_has_sensitive_reach(["/corp/merger_docs/*"]))

    def test_gdpr_path(self):
        self.assertTrue(_has_sensitive_reach(["/compliance/gdpr_report.pdf"]))

    def test_public_reports_not_sensitive(self):
        self.assertFalse(_has_sensitive_reach(["/reports/public/*", "/documents/*"]))

    def test_empty_resources_not_sensitive(self):
        self.assertFalse(_has_sensitive_reach([]))

    def test_mixed_list_sensitive_if_any_match(self):
        self.assertTrue(_has_sensitive_reach(["/public/*", "/hr/salary.csv"]))

    def test_keyword_as_substring(self):
        self.assertTrue(_has_sensitive_reach(["/org/payroll_system/*"]))

    def test_case_insensitive(self):
        self.assertTrue(_has_sensitive_reach(["/HR/SALARY.CSV"]))

    def test_admin_path_is_sensitive(self):
        self.assertTrue(_has_sensitive_reach(["/admin/settings"]))


class TestHasEgress(unittest.TestCase):
    """Unit tests for the _has_egress helper."""

    def test_email_is_egress(self):
        self.assertTrue(_has_egress(["read", "email"]))

    def test_upload_is_egress(self):
        self.assertTrue(_has_egress(["upload"]))

    def test_send_is_egress(self):
        self.assertTrue(_has_egress(["send"]))

    def test_export_is_egress(self):
        self.assertTrue(_has_egress(["read", "export"]))

    def test_forward_is_egress(self):
        self.assertTrue(_has_egress(["forward"]))

    def test_publish_is_egress(self):
        self.assertTrue(_has_egress(["publish"]))

    def test_transfer_is_egress(self):
        self.assertTrue(_has_egress(["transfer"]))

    def test_post_is_egress(self):
        self.assertTrue(_has_egress(["read", "post"]))

    def test_read_only_not_egress(self):
        self.assertFalse(_has_egress(["read", "search", "query", "list"]))

    def test_empty_actions_not_egress(self):
        self.assertFalse(_has_egress([]))

    def test_case_insensitive(self):
        self.assertTrue(_has_egress(["READ", "UPLOAD"]))

    def test_mixed_case_action(self):
        self.assertTrue(_has_egress(["Email"]))


class TestConstants(unittest.TestCase):
    """Invariants on the module-level constants."""

    def test_exfil_flag_starts_with_lethal_trifecta(self):
        self.assertTrue(LETHAL_TRIFECTA_EXFIL.startswith("LETHAL_TRIFECTA:"))

    def test_risk_flag_starts_with_lethal_trifecta(self):
        self.assertTrue(LETHAL_TRIFECTA_RISK.startswith("LETHAL_TRIFECTA:"))

    def test_flags_are_distinct(self):
        self.assertNotEqual(LETHAL_TRIFECTA_EXFIL, LETHAL_TRIFECTA_RISK)

    def test_exfil_flag_contains_exfil(self):
        self.assertIn("EXFIL", LETHAL_TRIFECTA_EXFIL)

    def test_risk_flag_contains_risk(self):
        self.assertIn("RISK", LETHAL_TRIFECTA_RISK)

    def test_exfiltration_actions_non_empty(self):
        self.assertGreater(len(_EXFILTRATION_ACTIONS), 0)

    def test_read_only_actions_non_empty(self):
        self.assertGreater(len(_READ_ONLY_ACTIONS), 0)

    def test_sensitive_keywords_non_empty(self):
        self.assertGreater(len(_SENSITIVE_RESOURCE_KEYWORDS), 0)

    def test_exfil_and_read_only_disjoint(self):
        overlap = _EXFILTRATION_ACTIONS & _READ_ONLY_ACTIONS
        self.assertEqual(overlap, frozenset(), msg=f"Sets must not overlap: {overlap}")

    def test_exfiltration_actions_are_lowercase(self):
        for action in _EXFILTRATION_ACTIONS:
            self.assertEqual(action, action.lower(), msg=f"'{action}' must be lowercase")

    def test_read_only_actions_are_lowercase(self):
        for action in _READ_ONLY_ACTIONS:
            self.assertEqual(action, action.lower(), msg=f"'{action}' must be lowercase")

    def test_sensitive_keywords_are_lowercase(self):
        for kw in _SENSITIVE_RESOURCE_KEYWORDS:
            self.assertEqual(kw, kw.lower(), msg=f"'{kw}' must be lowercase")


if __name__ == "__main__":
    unittest.main(verbosity=2)
