"""
Tests for core/owasp_agentic.py — OWASP Agentic Top 10 compliance mapping.

All tests are stdlib-only: no fastapi, sentence-transformers, or pydantic required.
The module itself has zero external dependencies.
"""

import time
import unittest
from core.owasp_agentic import (
    CoverageLevel,
    RiskEntry,
    get_risks,
    get_risk,
    generate_compliance_report,
    _RISKS,
    _FRAMEWORK,
    _FRAMEWORK_VERSION,
)


# ── Taxonomy structure ────────────────────────────────────────────────────────

class TestTaxonomyStructure(unittest.TestCase):
    def test_exactly_ten_risks(self):
        assert len(_RISKS) == 10

    def test_codes_are_unique(self):
        codes = [r.code for r in _RISKS]
        assert len(codes) == len(set(codes))

    def test_codes_follow_asi_scheme(self):
        for r in _RISKS:
            assert r.code.startswith("ASI"), f"{r.code} does not start with ASI"
            assert ":2026" in r.code, f"{r.code} missing :2026 suffix"

    def test_codes_are_sequential_01_to_10(self):
        for i, r in enumerate(_RISKS, start=1):
            expected_prefix = f"ASI{i:02d}:2026"
            assert r.code == expected_prefix, (
                f"Position {i}: expected {expected_prefix}, got {r.code}"
            )

    def test_all_risks_have_non_empty_name(self):
        for r in _RISKS:
            assert r.name.strip(), f"{r.code} has empty name"

    def test_all_risks_have_non_empty_description(self):
        for r in _RISKS:
            assert r.description.strip(), f"{r.code} has empty description"

    def test_all_risks_have_at_least_one_mechanism_or_notes_on_partial(self):
        for r in _RISKS:
            if r.coverage in (CoverageLevel.FULL, CoverageLevel.PARTIAL):
                assert r.mechanisms, f"{r.code} is {r.coverage} but has no mechanisms"

    def test_partial_risks_have_notes(self):
        for r in _RISKS:
            if r.coverage == CoverageLevel.PARTIAL:
                assert r.notes.strip(), f"{r.code} is PARTIAL but has no notes explaining limitation"

    def test_coverage_values_are_valid_enum_members(self):
        valid = {CoverageLevel.FULL, CoverageLevel.PARTIAL, CoverageLevel.NONE}
        for r in _RISKS:
            assert r.coverage in valid, f"{r.code} has invalid coverage {r.coverage}"


# ── Specific risk coverage assertions ─────────────────────────────────────────

class TestSpecificRiskCoverage(unittest.TestCase):
    """Verify that the risks we claim as FULL are actually FULL, and partials have the right ones."""

    def _get(self, code: str) -> RiskEntry:
        r = get_risk(code)
        assert r is not None, f"{code} not found"
        return r

    def test_asi01_goal_hijack_is_full(self):
        assert self._get("ASI01:2026").coverage == CoverageLevel.FULL

    def test_asi02_tool_misuse_is_full(self):
        assert self._get("ASI02:2026").coverage == CoverageLevel.FULL

    def test_asi03_identity_abuse_is_full(self):
        assert self._get("ASI03:2026").coverage == CoverageLevel.FULL

    def test_asi04_supply_chain_is_partial(self):
        assert self._get("ASI04:2026").coverage == CoverageLevel.PARTIAL

    def test_asi05_code_execution_is_partial(self):
        assert self._get("ASI05:2026").coverage == CoverageLevel.PARTIAL

    def test_asi06_memory_poisoning_is_full(self):
        assert self._get("ASI06:2026").coverage == CoverageLevel.FULL

    def test_asi07_inter_agent_comms_is_full(self):
        assert self._get("ASI07:2026").coverage == CoverageLevel.FULL

    def test_asi08_cascading_failures_is_full(self):
        assert self._get("ASI08:2026").coverage == CoverageLevel.FULL

    def test_asi09_human_trust_is_partial(self):
        assert self._get("ASI09:2026").coverage == CoverageLevel.PARTIAL

    def test_asi10_rogue_agents_is_full(self):
        assert self._get("ASI10:2026").coverage == CoverageLevel.FULL

    def test_seven_full_three_partial_zero_none(self):
        full = sum(1 for r in _RISKS if r.coverage == CoverageLevel.FULL)
        partial = sum(1 for r in _RISKS if r.coverage == CoverageLevel.PARTIAL)
        none_ = sum(1 for r in _RISKS if r.coverage == CoverageLevel.NONE)
        assert full == 7
        assert partial == 3
        assert none_ == 0


# ── get_risks / get_risk helpers ──────────────────────────────────────────────

class TestGetHelpers(unittest.TestCase):
    def test_get_risks_returns_copy(self):
        a = get_risks()
        b = get_risks()
        assert a is not b            # new list object each call
        assert a == b                # same content

    def test_get_risks_length_is_ten(self):
        assert len(get_risks()) == 10

    def test_get_risk_known_code(self):
        r = get_risk("ASI01:2026")
        assert r is not None
        assert r.code == "ASI01:2026"

    def test_get_risk_case_insensitive(self):
        r = get_risk("asi01:2026")
        assert r is not None
        assert r.code == "ASI01:2026"

    def test_get_risk_unknown_returns_none(self):
        assert get_risk("ASI99:2026") is None
        assert get_risk("") is None
        assert get_risk("OWASP01") is None

    def test_get_risk_all_codes_resolvable(self):
        for r in _RISKS:
            found = get_risk(r.code)
            assert found is not None
            assert found.code == r.code


# ── generate_compliance_report ────────────────────────────────────────────────

class TestComplianceReport(unittest.TestCase):
    def test_report_has_required_top_level_keys(self):
        report = generate_compliance_report()
        for key in ("framework", "framework_version", "taxonomy_url", "generated_at", "summary", "risks"):
            assert key in report, f"Missing key: {key}"

    def test_framework_name_correct(self):
        report = generate_compliance_report()
        assert report["framework"] == _FRAMEWORK

    def test_framework_version_correct(self):
        report = generate_compliance_report()
        assert report["framework_version"] == _FRAMEWORK_VERSION

    def test_generated_at_is_recent_utc(self):
        before = time.time()
        report = generate_compliance_report()
        after = time.time()
        ts = time.strptime(report["generated_at"], "%Y-%m-%dT%H:%M:%SZ")
        ts_epoch = time.mktime(ts)  # local TZ conversion; close enough for a ±5s window
        # Allow 60s slack for test environment timezone offset
        assert abs(ts_epoch - before) < 120

    def test_summary_counts_match_expected(self):
        s = generate_compliance_report()["summary"]
        assert s["risks_fully_covered"] == 7
        assert s["risks_partially_covered"] == 3
        assert s["risks_not_covered"] == 0
        assert s["total_risks"] == 10

    def test_coverage_score_is_85_percent(self):
        s = generate_compliance_report()["summary"]
        assert s["coverage_score_pct"] == 85.0

    def test_risks_list_length_is_ten(self):
        report = generate_compliance_report()
        assert len(report["risks"]) == 10

    def test_risks_include_mechanisms_by_default(self):
        report = generate_compliance_report()
        for r in report["risks"]:
            if r["coverage"] in ("FULL", "PARTIAL"):
                assert "agentgate_mechanisms" in r, f"{r['code']} missing mechanisms"
                assert len(r["agentgate_mechanisms"]) > 0

    def test_risks_omit_mechanisms_when_disabled(self):
        report = generate_compliance_report(include_mechanisms=False)
        for r in report["risks"]:
            assert "agentgate_mechanisms" not in r

    def test_risks_always_have_code_name_description_coverage(self):
        report = generate_compliance_report()
        for r in report["risks"]:
            for key in ("code", "name", "description", "coverage"):
                assert key in r and r[key], f"{r.get('code', '?')} missing or empty {key}"

    def test_partial_risks_include_notes(self):
        report = generate_compliance_report()
        for r in report["risks"]:
            if r["coverage"] == "PARTIAL":
                assert "notes" in r and r["notes"].strip(), (
                    f"{r['code']} is PARTIAL but missing notes"
                )

    def test_full_risks_do_not_require_notes(self):
        report = generate_compliance_report()
        full_risks = [r for r in report["risks"] if r["coverage"] == "FULL"]
        # Notes are optional for FULL coverage; just confirm no exception raised
        assert len(full_risks) == 7

    def test_risk_codes_in_report_are_sequential(self):
        report = generate_compliance_report()
        codes = [r["code"] for r in report["risks"]]
        for i, code in enumerate(codes, start=1):
            assert code == f"ASI{i:02d}:2026", f"Position {i}: unexpected code {code}"

    def test_report_is_serialisable_as_json(self):
        import json
        report = generate_compliance_report()
        serialised = json.dumps(report)   # raises if anything is not JSON-serialisable
        roundtrip = json.loads(serialised)
        assert roundtrip["summary"]["coverage_score_pct"] == 85.0

    def test_report_is_deterministic(self):
        r1 = generate_compliance_report()
        r2 = generate_compliance_report()
        # generated_at may differ by a second; compare everything else
        r1.pop("generated_at")
        r2.pop("generated_at")
        assert r1 == r2


# ── Key mechanism keyword checks ──────────────────────────────────────────────

class TestMechanismKeywords(unittest.TestCase):
    """Verify that key AgentGate component names appear in the right risks."""

    def _mechanisms_text(self, code: str) -> str:
        r = get_risk(code)
        assert r is not None
        return " ".join(r.mechanisms).lower()

    def test_asi01_mentions_injection_detector(self):
        assert "injection_detector" in self._mechanisms_text("ASI01:2026")

    def test_asi01_mentions_mcp_descriptor_guard(self):
        assert "mcp_descriptor_guard" in self._mechanisms_text("ASI01:2026")

    def test_asi02_mentions_kill_chain(self):
        assert "kill_chain" in self._mechanisms_text("ASI02:2026")

    def test_asi03_mentions_delegation(self):
        assert "delegation" in self._mechanisms_text("ASI03:2026")

    def test_asi03_mentions_token(self):
        assert "token" in self._mechanisms_text("ASI03:2026")

    def test_asi04_mentions_mcp_descriptor_guard(self):
        assert "mcp_descriptor_guard" in self._mechanisms_text("ASI04:2026")

    def test_asi06_mentions_output_sanitizer(self):
        assert "output_sanitizer" in self._mechanisms_text("ASI06:2026")

    def test_asi07_mentions_delegation(self):
        assert "delegation" in self._mechanisms_text("ASI07:2026")

    def test_asi08_mentions_contagion(self):
        assert "contagion" in self._mechanisms_text("ASI08:2026")

    def test_asi08_mentions_quarantine(self):
        assert "quarantine" in self._mechanisms_text("ASI08:2026")

    def test_asi10_mentions_kill_chain(self):
        assert "kill_chain" in self._mechanisms_text("ASI10:2026")

    def test_asi10_mentions_purpose_engine(self):
        assert "purpose_engine" in self._mechanisms_text("ASI10:2026")
