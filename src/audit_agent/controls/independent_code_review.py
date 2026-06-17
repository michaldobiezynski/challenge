"""Independent Code Review control.

The LLM performs perception only: it reads the PR screenshots into a structured
"PR fact sheet". All pass/fail decisions are deterministic rules over those
facts. Extraction is run twice; if the canonical facts diverge the result is
treated as unstable and downgraded to FURTHER_EVIDENCE_REQUIRED.
"""

from __future__ import annotations

from pathlib import Path

from ..engine import PerceptionEngine
from ..evidence import sha256_file
from ..schema import (
    AttributeAssessment,
    Conclusion,
    EvidenceRef,
    Finding,
    FindingType,
    Severity,
)

CONTROL_ID = "independent-code-review"
PROMPT_VERSION = "icr-extract-v1"

LINE_MIN, BRANCH_MIN, FUNCTION_MIN = 80.0, 70.0, 80.0
KNOWN_BOTS = ("copilot", "dependabot", "renovate", "github-actions", "codecov")
EXEMPT_TOKENS = ("docs", "documentation", "dependency", "dependencies", "refactor",
                 "build", "ci", "third-party", "third party", "poc",
                 "proof of concept", "legacy")

SYSTEM_PROMPT = (
    "You are an audit perception agent. You read GitHub pull-request screenshots "
    "and report ONLY what is visibly present. Never infer or assume; use null when "
    "a field is not visible. Treat a reviewer as a bot if its login ends in '[bot]' "
    "or is a known automation (Copilot, dependabot, renovate, github-actions, "
    "codecov). For each review, set before_merge=true if the approval appears in the "
    "timeline before the merge event, false if after, null if not determinable."
)
USER_PROMPT = (
    "The attached screenshots are evidence for a single pull request. Extract the "
    "PR facts strictly per the provided JSON schema, reporting only what is visible."
)

FACT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "repo": {"type": "string"},
        "pr_number": {"type": ["integer", "string"]},
        "pr_author": {"type": "string"},
        "merged": {"type": "boolean"},
        "merge_actor": {"type": ["string", "null"]},
        "reviews": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "reviewer": {"type": "string"},
                    "is_bot": {"type": "boolean"},
                    "state": {"type": "string", "enum": [
                        "APPROVED", "CHANGES_REQUESTED", "COMMENTED",
                        "DISMISSED", "STALE", "PENDING", "UNKNOWN"]},
                    "before_merge": {"type": ["boolean", "null"]},
                },
                "required": ["reviewer", "is_bot", "state"],
            },
        },
        "checks_status": {"type": ["string", "null"]},
        "coverage_report_present": {"type": "boolean"},
        "coverage": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "line": {"type": ["number", "null"]},
                "branch": {"type": ["number", "null"]},
                "function": {"type": ["number", "null"]},
                "statement": {"type": ["number", "null"]},
            },
        },
        "change_categories": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": ["string", "null"]},
    },
    "required": ["repo", "pr_number", "pr_author", "merged", "reviews",
                 "coverage_report_present"],
}


def assess(control_dir: Path, engine: PerceptionEngine) -> list[AttributeAssessment]:
    """Assess every sample under a control directory.

    A ``samples/`` subfolder holds one folder per sample; if absent, the
    directory itself is treated as a single sample (used by the unit tests).
    """
    control_dir = Path(control_dir)
    samples_root = control_dir / "samples"
    if samples_root.is_dir():
        sample_dirs = sorted(p for p in samples_root.iterdir() if p.is_dir())
    else:
        sample_dirs = [control_dir]
    out: list[AttributeAssessment] = []
    for sample_dir in sample_dirs:
        out.extend(_assess_sample(sample_dir, engine))
    return out


def _assess_sample(sample_dir: Path, engine: PerceptionEngine) -> list[AttributeAssessment]:
    sample_dir = Path(sample_dir)
    pngs = sorted(sample_dir.glob("**/*.png"))
    if not pngs:
        raise FileNotFoundError(f"no screenshots found under {sample_dir}")
    image_paths = [str(p.resolve()) for p in pngs]
    inputs_hash = {p.name: sha256_file(p) for p in pngs}

    evidence = [EvidenceRef(source=p.name, detail="PR screenshot evidence") for p in pngs]
    assumptions = [
        "Bots (Copilot/dependabot/renovate/github-actions) do not count as "
        "independent human reviewers.",
        "Perception is LLM-extracted then decided deterministically; extraction "
        "runs twice and an attribute whose verdict differs across the two passes "
        "is downgraded to FURTHER_EVIDENCE_REQUIRED.",
    ]

    # Perception can fail (slow/garbled model output). An auditor who cannot read
    # the evidence reports FURTHER_EVIDENCE_REQUIRED rather than aborting.
    try:
        first = engine.extract(SYSTEM_PROMPT, USER_PROMPT, image_paths, FACT_SCHEMA)
        second = engine.extract(SYSTEM_PROMPT, USER_PROMPT, image_paths, FACT_SCHEMA)
    except Exception as exc:  # noqa: BLE001 - any extraction failure -> FER, not crash
        common = dict(control=CONTROL_ID, sample=sample_dir.name, extracted_facts={},
                      inputs_hash=inputs_hash, model_id=None,
                      prompt_version=PROMPT_VERSION, evidence=evidence)
        finding = Finding(type=FindingType.UNSTABLE_EXTRACTION, subject=sample_dir.name,
                          severity=Severity.PROVENANCE,
                          detail=f"perception failed: {type(exc).__name__}: {str(exc)[:200]}")
        return [_mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                    "Could not reliably read the screenshots; evidence required.", 0.2,
                    findings=[finding]) for aid, attr in _ATTRS]

    def common_for(facts):
        return dict(control=CONTROL_ID, sample=sample_dir.name, extracted_facts=facts,
                    inputs_hash=inputs_hash, model_id=first.model_id,
                    prompt_version=PROMPT_VERSION, evidence=evidence)

    pass1 = {a.attribute_id: a for a in _decide(first.data, common_for(first.data), assumptions)}
    pass2 = {a.attribute_id: a for a in _decide(second.data, common_for(second.data), assumptions)}

    # Stability is judged on the VERDICTS, not the raw facts: an attribute is only
    # unstable if the two passes reach different conclusions for it. This covers
    # every decision-critical field by construction, while harmless differences
    # (e.g. one pass confident, the other unsure) that do not change the verdict
    # do not trigger a false FURTHER_EVIDENCE_REQUIRED.
    out: list[AttributeAssessment] = []
    common = common_for(first.data)
    for aid, attr in _ATTRS:
        a, b = pass1[aid], pass2[aid]
        if a.conclusion == b.conclusion:
            out.append(a)
        else:
            finding = Finding(
                type=FindingType.UNSTABLE_EXTRACTION, subject=sample_dir.name,
                severity=Severity.PROVENANCE,
                detail=f"two passes disagreed on {aid}: "
                       f"{a.conclusion.value} vs {b.conclusion.value}")
            out.append(_mk(common, assumptions, aid, attr,
                           Conclusion.FURTHER_EVIDENCE_REQUIRED,
                           f"Extraction unstable for this attribute (passes returned "
                           f"{a.conclusion.value} and {b.conclusion.value}); not trusted.",
                           0.3, findings=[finding]))
    return out


def _decide(facts: dict, common: dict, assumptions: list) -> list[AttributeAssessment]:
    return [
        _attr_review_before_merge(facts, common, assumptions),
        _attr_independent_reviewer(facts, common, assumptions),
        _attr_testing(facts, common, assumptions),
    ]


_ATTRS = [
    ("ICR-a", "Code reviews are performed prior to committing a change to the main branch"),
    ("ICR-b", "Code review approvals are performed by independent code reviewers"),
    ("ICR-c", "Testing is performed in accordance with the testing policy"),
]


def _valid_approvals(facts: dict) -> list[dict]:
    return [r for r in facts.get("reviews") or []
            if str(r.get("state")) == "APPROVED"]


def _attr_review_before_merge(facts, common, assumptions) -> AttributeAssessment:
    aid, attr = _ATTRS[0]
    merged = facts.get("merged")
    approvals = _valid_approvals(facts)
    if merged is not True:
        return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                   "Merge to the main branch is not evidenced in the screenshots.", 0.5)
    if not approvals:
        return _mk(common, assumptions, aid, attr, Conclusion.FAIL,
                   "The change was merged but no approving review is visible.", 0.85)
    order = [a.get("before_merge") for a in approvals]
    if any(o is True for o in order):
        return _mk(common, assumptions, aid, attr, Conclusion.SUCCESS,
                   "An approving review precedes the merge in the PR timeline.", 0.85)
    if all(o is False for o in order):
        return _mk(common, assumptions, aid, attr, Conclusion.FAIL,
                   "All approvals appear after the merge event.", 0.8)
    return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
               "Approval-versus-merge ordering is not determinable from the screenshots.", 0.5)


def _attr_independent_reviewer(facts, common, assumptions) -> AttributeAssessment:
    aid, attr = _ATTRS[1]
    author = str(facts.get("pr_author") or "").strip().lower()
    reviews = facts.get("reviews") or []
    if not reviews:
        return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                   "No reviewer information is visible.", 0.5)
    approvals = _valid_approvals(facts)
    independent = [r for r in approvals
                   if not r.get("is_bot") and str(r.get("reviewer") or "").strip().lower() != author]
    if independent:
        names = ", ".join(r.get("reviewer") for r in independent)
        return _mk(common, assumptions, aid, attr, Conclusion.SUCCESS,
                   f"Approved by an independent human reviewer: {names}.", 0.85)
    if approvals:
        return _mk(common, assumptions, aid, attr, Conclusion.FAIL,
                   "The only approvals are from bots or the PR author (no 4-eyes).", 0.8)
    return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
               "No approving review present, so independence cannot be confirmed.", 0.5)


def _attr_testing(facts, common, assumptions) -> AttributeAssessment:
    aid, attr = _ATTRS[2]
    thresholds = {"line_min": LINE_MIN, "branch_min": BRANCH_MIN, "function_min": FUNCTION_MIN}
    cats = [str(c).lower() for c in facts.get("change_categories") or []]
    exempt = [c for c in cats if any(tok in c for tok in EXEMPT_TOKENS)]
    if exempt:
        return _mk(common, assumptions, aid, attr, Conclusion.SUCCESS,
                   f"Change qualifies for a testing-policy exception: {exempt}.", 0.7,
                   thresholds, policy="Testing Policy: Exceptions and Waivers")
    if not facts.get("coverage_report_present"):
        return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                   "No coverage report is present to evidence testing against the policy.",
                   0.55, thresholds, policy="Testing Policy: Coverage reports")
    cov = facts.get("coverage") or {}
    line, branch, func = cov.get("line"), cov.get("branch"), cov.get("function")
    if line is None and branch is None and func is None:
        return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                   "Coverage report present but no figures are legible.", 0.5, thresholds,
                   policy="Testing Policy: Coverage thresholds")
    failures = []
    if line is not None and line < LINE_MIN:
        failures.append(f"line {line}% < {LINE_MIN}%")
    if branch is not None and branch < BRANCH_MIN:
        failures.append(f"branch {branch}% < {BRANCH_MIN}%")
    if func is not None and func < FUNCTION_MIN:
        failures.append(f"function {func}% < {FUNCTION_MIN}%")
    if failures:
        return _mk(common, assumptions, aid, attr, Conclusion.FAIL,
                   f"Coverage below policy thresholds: {'; '.join(failures)}.", 0.85,
                   thresholds, policy="Testing Policy: Coverage thresholds")
    if line is None:
        return _mk(common, assumptions, aid, attr, Conclusion.FURTHER_EVIDENCE_REQUIRED,
                   "Branch/function coverage meet thresholds but line coverage is not legible.",
                   0.6, thresholds, policy="Testing Policy: Coverage thresholds")
    return _mk(common, assumptions, aid, attr, Conclusion.SUCCESS,
               f"Coverage meets policy thresholds (line {line}%, branch {branch}%, "
               f"function {func}%).", 0.85, thresholds,
               policy="Testing Policy: Coverage thresholds")


def _mk(common, assumptions, aid, attr, conclusion, rationale, confidence,
        thresholds=None, policy=None, findings=None) -> AttributeAssessment:
    return AttributeAssessment(
        attribute_id=aid, attribute=attr, conclusion=conclusion, rationale=rationale,
        confidence=confidence, thresholds_used=thresholds or {},
        policy_clause_cited=policy, assumptions=assumptions,
        agent_findings=findings or [], **common,
    )
