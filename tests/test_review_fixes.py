"""Regression tests added in response to the deep-review findings.

Each test maps to a confirmed finding (Fnn) so the fix cannot silently rot.
"""

from __future__ import annotations

import json
import types
from datetime import date

import pytest

from audit_agent import engine as engine_mod
from audit_agent.controls import detect_control
from audit_agent.controls import independent_code_review as icr
from audit_agent.controls import user_access_review as uar
from audit_agent.engine import ClaudeCPEngine, StubEngine
from audit_agent.evidence import load_key_value, load_table
from audit_agent.schema import Conclusion, FindingType


def _by_id(results):
    return {a.attribute_id: a for a in results}


def _active(email, name="Test User", role="A/R Clerk", mfa="Yes", last="2026-06-01"):
    return {"Username": email.split("@")[0], "Full Name": name, "Email": email,
            "Role": role, "Account Status": "Active", "MFA Enabled": mfa, "Last Login": last}


def _emp(email, status, first="Test", last="User", title="Clerk",
         hire=date(2020, 1, 1), term=""):
    return {"Work Email": email, "First Name": first, "Last Name": last,
            "Job Title": title, "Employment Status": status, "Hire Date": hire,
            "Termination Date": term}


# --- F22 / F25: UAR-a and UAR-b decision logic and a FURTHER_EVIDENCE outcome ---

def test_uar_a_further_evidence_without_period(make_sample):
    sample = make_sample(access=[], review=[], hris=[],
                         cover={"Reviewer / Approver": "Jane Owner (System Owner)",
                                "Reviewer Sign-off:": "Approved by Jane."})
    a = _by_id(uar.assess(sample))["UAR-a"]
    assert a.conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


def test_uar_b_further_evidence_without_owner(make_sample):
    sample = make_sample(access=[], review=[], hris=[],
                         cover={"Review Period": "Q2 2026", "Review Completed": date(2026, 6, 30)})
    b = _by_id(uar.assess(sample))["UAR-b"]
    assert b.conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


# --- F4: a duplicated worksheet email must not drop a Revoke decision ---

def test_duplicate_revoke_not_dropped(make_sample):
    email = "dup@corp.com"
    sample = make_sample(
        access=[_active(email)],
        review=[
            {"Email": email, "Name": "Dup", "Role": "A/R Clerk", "Account Status": "Active",
             "Reviewer Decision": "Revoke", "Reviewer Comment": "ticket raised"},
            {"Email": email, "Name": "Dup", "Role": "A/R Clerk", "Account Status": "Active",
             "Reviewer Decision": "Retain", "Reviewer Comment": "duplicate row"},
        ],
        hris=[_emp(email, "Terminated", term=date(2022, 1, 1))],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert "dup@corp.com" in c.extracted_facts["reviewer_revoked"]
    assert c.extracted_facts["missed_by_reviewer"] == []


# --- F3: a concurrent active spell must not be flagged as terminated ---

def test_concurrent_active_spell_with_later_terminated_hire(make_sample):
    email = "concurrent@corp.com"
    sample = make_sample(
        access=[_active(email)], review=[],
        hris=[
            _emp(email, "Active", hire=date(2019, 1, 1)),
            _emp(email, "Terminated", hire=date(2021, 1, 1), term=date(2021, 6, 1)),
        ],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert not any(f.type is FindingType.TERMINATED_ACTIVE for f in c.agent_findings)


# --- F7: timeliness of remediation is actually evaluated ---

def test_agreed_exception_without_remediation_is_further_evidence(make_sample):
    email = "flagged@corp.com"
    sample = make_sample(
        access=[_active(email)],
        review=[{"Email": email, "Name": "F", "Role": "A/R Clerk", "Account Status": "Active",
                 "Reviewer Decision": "Revoke", "Reviewer Comment": "will look into it"}],
        hris=[_emp(email, "Terminated", term=date(2022, 1, 1))],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert c.conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


def test_agreed_exception_with_remediation_is_success(make_sample):
    email = "flagged@corp.com"
    sample = make_sample(
        access=[_active(email)],
        review=[{"Email": email, "Name": "F", "Role": "A/R Clerk", "Account Status": "Active",
                 "Reviewer Decision": "Revoke",
                 "Reviewer Comment": "deprovisioning ticket ITSM-1 raised"}],
        hris=[_emp(email, "Terminated", term=date(2022, 1, 1))],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert c.conclusion is Conclusion.SUCCESS


# --- F23: non-APPROVED review states are not counted as approvals ---

BASE_FACTS = {
    "repo": "x/y", "pr_number": 1, "pr_author": "alice", "merged": True,
    "merge_actor": "alice", "reviews": [], "checks_status": "passing",
    "coverage_report_present": True,
    "coverage": {"line": 90, "branch": 90, "function": 90}, "change_categories": [],
}


def _run_icr(facts, tmp_path):
    (tmp_path / "s.png").write_bytes(b"\x89PNG")
    eng = StubEngine(responses=lambda *a: facts)
    return _by_id(icr.assess(tmp_path, eng))


def test_changes_requested_is_not_an_approval(tmp_path):
    facts = dict(BASE_FACTS, reviews=[
        {"reviewer": "bob", "is_bot": False, "state": "CHANGES_REQUESTED", "before_merge": True}])
    res = _run_icr(facts, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.FAIL  # merged with no valid approval


def test_commented_only_is_not_an_approval(tmp_path):
    facts = dict(BASE_FACTS, reviews=[
        {"reviewer": "bob", "is_bot": False, "state": "COMMENTED", "before_merge": True}])
    res = _run_icr(facts, tmp_path)
    assert res["ICR-b"].conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


# --- F2: instability on a decision-critical field flips that attribute to FER,
#         but a harmless confidence-only difference does not. ---

def _alternating_assess(facts_a, facts_b, tmp_path):
    (tmp_path / "s.png").write_bytes(b"\x89PNG")
    state = {"n": 0}

    def fn(*a):
        state["n"] += 1
        return facts_a if state["n"] % 2 == 1 else facts_b

    return _by_id(icr.assess(tmp_path, StubEngine(responses=fn)))


def test_before_merge_flip_makes_timing_unstable(tmp_path):
    a = dict(BASE_FACTS, reviews=[{"reviewer": "b", "is_bot": False, "state": "APPROVED",
                                   "before_merge": True}])
    b = dict(BASE_FACTS, reviews=[{"reviewer": "b", "is_bot": False, "state": "APPROVED",
                                   "before_merge": False}])
    res = _alternating_assess(a, b, tmp_path)
    assert res["ICR-a"].conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED
    assert res["ICR-b"].conclusion is Conclusion.SUCCESS  # independence verdict unaffected


def test_coverage_threshold_crossing_makes_testing_unstable(tmp_path):
    a = dict(BASE_FACTS, coverage={"line": 79.6, "branch": 90, "function": 90})
    b = dict(BASE_FACTS, coverage={"line": 80.4, "branch": 90, "function": 90})
    res = _alternating_assess(a, b, tmp_path)
    assert res["ICR-c"].conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED


def test_confidence_only_difference_is_still_stable(tmp_path):
    # One pass reads the approver, the other is unsure on before_merge; both still
    # conclude an independent approval before merge, so the verdict is stable.
    a = dict(BASE_FACTS, reviews=[{"reviewer": "b", "is_bot": False, "state": "APPROVED",
                                   "before_merge": True}])
    b = dict(BASE_FACTS, reviews=[{"reviewer": "b", "is_bot": False, "state": "APPROVED",
                                   "before_merge": None}])
    res = _alternating_assess(a, b, tmp_path)
    # ICR-a: pass1 SUCCESS (before True), pass2 FER (ordering unknown) -> unstable.
    # ICR-b: both SUCCESS (independent approval) -> stable SUCCESS.
    assert res["ICR-b"].conclusion is Conclusion.SUCCESS


# --- F5 / F19: engine robustness ---

def test_empty_stub_engine_raises_clear_error():
    eng = StubEngine(responses={}, route=lambda *a: None)
    with pytest.raises(RuntimeError, match="no canned response"):
        eng.extract("sys", "usr", ["/tmp/x.png"], {})


def test_claude_cp_grants_no_tools_and_sends_inline_image(monkeypatch, tmp_path):
    # The security boundary: no Read tool, no bypassPermissions; image inlined.
    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n")
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["stdin"] = kw.get("input", "")
        line = json.dumps({"type": "result", "is_error": False,
                           "structured_output": {"ok": True},
                           "modelUsage": {"claude-haiku-4-5-20251001": {},
                                          "claude-opus-4-8": {}}})
        return types.SimpleNamespace(returncode=0, stdout=line + "\n", stderr="")

    monkeypatch.setattr(engine_mod.subprocess, "run", fake_run)
    res = ClaudeCPEngine().extract("sys", "usr", [str(png)], {"type": "object"})
    assert res.data == {"ok": True}
    assert res.model_id == "claude-opus-4-8"  # the non-Haiku model is reported
    cmd = captured["cmd"]
    assert "Read" not in cmd and "bypassPermissions" not in cmd
    assert cmd[cmd.index("--allowedTools") + 1] == ""  # no tools granted
    assert '"type": "image"' in captured["stdin"]  # image inlined, not @path


def test_recover_json_from_prose_result():
    assert engine_mod._recover_json("```json\n{\"a\": 1}\n```") == {"a": 1}
    assert engine_mod._recover_json("here you go: {\"b\": 2} cheers") == {"b": 2}
    assert engine_mod._recover_json("no json at all") is None


def test_claude_cp_recovers_when_structured_output_null(monkeypatch):
    # The model occasionally answers in prose with a null structured_output.
    line = json.dumps({"type": "result", "is_error": False, "structured_output": None,
                       "result": "Sure:\n```json\n{\"ok\": true}\n```",
                       "modelUsage": {"claude-opus-4-8": {}}})

    def fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=line + "\n", stderr="")

    monkeypatch.setattr(engine_mod.subprocess, "run", fake_run)
    res = ClaudeCPEngine(retries=0).extract("sys", "usr", [], {"type": "object"})
    assert res.data == {"ok": True}


def test_icr_extraction_failure_yields_further_evidence(tmp_path):
    (tmp_path / "s.png").write_bytes(b"\x89PNG")

    class FailingEngine:
        name = "failing"

        def extract(self, *a, **k):
            raise RuntimeError("perception broke")

    res = _by_id(icr.assess(tmp_path, FailingEngine()))
    assert all(v.conclusion is Conclusion.FURTHER_EVIDENCE_REQUIRED for v in res.values())
    assert all(any(f.type is FindingType.UNSTABLE_EXTRACTION for f in v.agent_findings)
               for v in res.values())


# --- F30: core helpers and routing ---

def test_detect_control_by_name():
    from pathlib import Path
    assert detect_control(Path("x/user-access-review")) == "user-access-review"
    assert detect_control(Path("x/independent-code-review")) == "independent-code-review"


def test_load_table_and_cell_ref(make_sample):
    sample = make_sample(access=[_active("a@corp.com")], review=[], hris=[])
    table = load_table(sample / "uar-netsuite-q2-2026.xlsx",
                       ["System Access Export"], uar.ACCESS_MANIFEST)
    assert len(table.records) == 1
    ref = table.cell_ref("email", table.records[0])
    assert ref.startswith("uar-netsuite-q2-2026.xlsx!System Access Export!")


def test_load_key_value_cover(make_sample):
    sample = make_sample(access=[], review=[], hris=[])
    cover = load_key_value(sample / "uar-netsuite-q2-2026.xlsx", ["Cover"])
    assert "Review Period" in cover
    assert cover["Review Period"][0] == "Q2 2026"
