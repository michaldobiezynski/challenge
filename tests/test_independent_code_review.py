"""Rule tests for the Independent Code Review control, using a stubbed engine.

The engine (perception) is stubbed with canned PR fact sheets so the suite is
offline and deterministic; the tests exercise the decision rules.
"""

from __future__ import annotations

from audit_agent.controls import independent_code_review as icr
from audit_agent.engine import StubEngine
from audit_agent.schema import Conclusion, FindingType
from conftest import ICR_REAL

SAMPLE = ICR_REAL / "samples" / "sample-1" if ICR_REAL.exists() else None


def _engine(facts):
    return StubEngine(responses=lambda *a: facts)


def _alternating(facts_a, facts_b):
    state = {"n": 0}

    def fn(*a):
        state["n"] += 1
        return facts_a if state["n"] % 2 == 1 else facts_b

    return StubEngine(responses=fn)


def _assess(engine, sample_dir):
    return {a.attribute_id: a for a in icr.assess(sample_dir, engine)}


TYPESCRIPT_LIKE = {
    "repo": "microsoft/TypeScript", "pr_number": 62754, "pr_author": "jakebailey",
    "merged": True, "merge_actor": "jakebailey",
    "reviews": [{"reviewer": "RyanCavanaugh", "is_bot": False, "state": "APPROVED",
                 "before_merge": True}],
    "checks_status": "passing", "coverage_report_present": True,
    "coverage": {"line": 89.96, "branch": 89.49, "function": 84.79, "statement": 84.42},
    "change_categories": [], "notes": None,
}
DENO_LIKE = {
    "repo": "denoland/deno", "pr_number": 31272, "pr_author": "bartlomieju",
    "merged": True, "merge_actor": "bartlomieju",
    "reviews": [
        {"reviewer": "dsherret", "is_bot": False, "state": "APPROVED", "before_merge": True},
        {"reviewer": "Copilot", "is_bot": True, "state": "COMMENTED", "before_merge": True},
    ],
    "checks_status": "passing", "coverage_report_present": False, "coverage": {},
    "change_categories": [], "notes": "no coverage report visible",
}


def _run(facts, tmp_path):
    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG\r\n")  # bytes only needed for the inputs hash
    return _assess(_engine(facts), tmp_path)


def test_typescript_like_all_pass(tmp_path):
    res = _run(TYPESCRIPT_LIKE, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.SUCCESS
    assert res["ICR-b"].conclusion is Conclusion.SUCCESS
    assert res["ICR-c"].conclusion is Conclusion.SUCCESS


def test_deno_like_independent_but_testing_needs_evidence(tmp_path):
    res = _run(DENO_LIKE, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.SUCCESS
    assert res["ICR-b"].conclusion is Conclusion.SUCCESS  # Copilot excluded, dsherret counts
    assert res["ICR-c"].conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


def test_bot_only_approval_fails_independence(tmp_path):
    facts = dict(DENO_LIKE, reviews=[
        {"reviewer": "dependabot", "is_bot": True, "state": "APPROVED", "before_merge": True}])
    res = _run(facts, tmp_path)
    assert res["ICR-b"].conclusion is Conclusion.FAIL


def test_self_approval_fails_independence(tmp_path):
    facts = dict(TYPESCRIPT_LIKE, pr_author="jakebailey", reviews=[
        {"reviewer": "jakebailey", "is_bot": False, "state": "APPROVED", "before_merge": True}])
    res = _run(facts, tmp_path)
    assert res["ICR-b"].conclusion is Conclusion.FAIL


def test_merged_without_review_fails(tmp_path):
    facts = dict(TYPESCRIPT_LIKE, reviews=[])
    res = _run(facts, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.FAIL


def test_approval_after_merge_fails_timing(tmp_path):
    facts = dict(TYPESCRIPT_LIKE, reviews=[
        {"reviewer": "RyanCavanaugh", "is_bot": False, "state": "APPROVED",
         "before_merge": False}])
    res = _run(facts, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.FAIL


def test_coverage_below_threshold_fails(tmp_path):
    facts = dict(TYPESCRIPT_LIKE,
                 coverage={"line": 65.0, "branch": 50.0, "function": 60.0})
    res = _run(facts, tmp_path)
    assert res["ICR-c"].conclusion is Conclusion.FAIL


def test_docs_only_change_is_exempt(tmp_path):
    facts = dict(DENO_LIKE, change_categories=["docs-only"], coverage_report_present=False)
    res = _run(facts, tmp_path)
    assert res["ICR-c"].conclusion is Conclusion.SUCCESS


def test_unstable_extraction_is_further_evidence(tmp_path):
    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG\r\n")
    other = dict(TYPESCRIPT_LIKE, pr_author="someone-else", merged=False)
    res = _assess(_alternating(TYPESCRIPT_LIKE, other), tmp_path)
    assert all(a.conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED for a in res.values())
    assert any(f.type is FindingType.UNSTABLE_EXTRACTION
               for a in res.values() for f in a.agent_findings)
