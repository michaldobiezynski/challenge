"""User Access Review control: a reperformance test.

The reviewer's worksheet is treated as a claim to be checked, not trusted.
We independently reconcile the NetSuite access export against the Workday HRIS
roster (pure deterministic code, no LLM), compute our own exception set, and
compare it to the reviewer's conclusions. Attribute (c) fails if we find any
exception the reviewer did not.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from ..engine import PerceptionEngine
from ..evidence import (
    coerce_date,
    load_key_value,
    load_table,
    normalise_email,
    sha256_file,
)
from ..schema import (
    AttributeAssessment,
    Conclusion,
    EvidenceRef,
    Finding,
    FindingType,
    Severity,
)

CONTROL_ID = "user-access-review"
PROMPT_VERSION = None  # no LLM perception is used for this control

# Tunable thresholds, surfaced in every assessment's thresholds_used.
DORMANT_DAYS = 180
PRIVILEGED_ROLE_TOKENS = ("administrator", "admin")
# Tokens that evidence remediation having been initiated for a flagged exception.
REMEDIATION_TOKENS = ("ticket", "itsm", "deprovision", "revoke", "raised", "removed",
                      "disabled", "jira", "snow")

ACCESS_MANIFEST = {
    "username": ["Username", "User Name", "Login"],
    "full_name": ["Full Name", "Name"],
    "email": ["Email", "Email Address", "User Email"],
    "role": ["Role", "Roles"],
    "status": ["Account Status", "Status"],
    "mfa": ["MFA Enabled", "MFA", "Multi-factor"],
    "last_login": ["Last Login", "Last Logon", "Last Sign In"],
}
REVIEW_MANIFEST = {
    "email": ["Email", "Email Address"],
    "name": ["Name", "Full Name"],
    "role": ["Role"],
    "status": ["Account Status", "Status"],
    "decision": ["Reviewer Decision", "Decision"],
    "comment": ["Reviewer Comment", "Comment", "Notes"],
}
HRIS_MANIFEST = {
    "email": ["Work Email", "Email", "Email Address"],
    "first_name": ["First Name"],
    "last_name": ["Last Name"],
    "job_title": ["Job Title", "Title"],
    "employment_status": ["Employment Status", "Status"],
    "hire_date": ["Hire Date"],
    "termination_date": ["Termination Date", "Term Date"],
}


def _is_service_account(rec: dict) -> bool:
    """Detect service/integration accounts by several independent signals."""
    username = str(rec.get("username") or "").lower()
    role = str(rec.get("role") or "").lower()
    full_name = str(rec.get("full_name") or "").lower()
    return (
        username.startswith("svc-")
        or username.startswith("svc.")
        or "service account" in full_name
        or any(tok in role for tok in ("integration", "web services", "service", "system"))
    )


def _truthy_mfa(value: object) -> bool:
    return str(value).strip().lower() in {"yes", "true", "enabled", "y", "1"}


def _is_privileged(role: object) -> bool:
    text = str(role or "").lower()
    return any(tok in text for tok in PRIVILEGED_ROLE_TOKENS)


def _hris_primary(records: list[dict]) -> dict:
    """Pick the record for the latest employment spell (handles rehires)."""
    if len(records) == 1:
        return records[0]

    def sort_key(r: dict):
        hire = coerce_date(r.get("hire_date")) or date.min
        active = str(r.get("employment_status") or "").strip().lower() != "terminated"
        return (hire, active)

    return max(records, key=sort_key)


def assess(sample_dir: Path, engine: PerceptionEngine | None = None) -> list[AttributeAssessment]:
    sample_dir = Path(sample_dir)
    uar_path = _find_one(sample_dir, ("*uar*.xlsx", "*netsuite*.xlsx", "*access*.xlsx"))
    hris_path = _find_one(sample_dir, ("*hris*.xlsx", "*employee*.xlsx", "*workday*.xlsx"))

    inputs_hash = {uar_path.name: sha256_file(uar_path), hris_path.name: sha256_file(hris_path)}

    access = load_table(uar_path, ["System Access Export", "Access Export", "Users"], ACCESS_MANIFEST)
    review = load_table(uar_path, ["Access Review", "Review", "Worksheet"], REVIEW_MANIFEST)
    hris = load_table(hris_path, ["Employees", "Workers", "Roster"], HRIS_MANIFEST)
    cover = load_key_value(uar_path, ["Cover", "Summary", "Overview"])

    hris_by_email: dict[str, list[dict]] = {}
    hris_by_name: dict[str, list[dict]] = {}
    for rec in hris.records:
        hris_by_email.setdefault(normalise_email(rec.get("email")), []).append(rec)
        nm = f"{rec.get('first_name')} {rec.get('last_name')}".strip().lower()
        hris_by_name.setdefault(nm, []).append(rec)

    # Build the reviewer's revoke set from ALL worksheet rows, not a deduped
    # email->row map: a duplicated email must not let a later Retain silently
    # overwrite (and drop) an earlier Revoke decision.
    revoke_records = [r for r in review.records
                      if str(r.get("decision") or "").strip().lower() == "revoke"]
    reviewer_revoked = {normalise_email(r.get("email")) for r in revoke_records}
    revoke_by_email = {normalise_email(r.get("email")): r for r in revoke_records}

    review_end = coerce_date(cover.get("Review Completed", (None,))[0])  # None if absent
    findings: list[Finding] = []
    service_accounts: list[str] = []
    in_scope = 0

    for acc in access.records:
        email = normalise_email(acc.get("email"))
        if _is_service_account(acc):
            service_accounts.append(email)
            continue
        in_scope += 1
        if str(acc.get("status") or "").strip().lower() != "active":
            continue  # inactive/disabled accounts grant no live access

        src = access.cell_ref("email", acc)
        matches = hris_by_email.get(email)
        low_confidence = False
        if not matches:
            name_key = str(acc.get("full_name") or "").strip().lower()
            name_matches = hris_by_name.get(name_key)
            if name_matches:
                matches = name_matches
                low_confidence = True
                findings.append(Finding(
                    type=FindingType.LOW_CONFIDENCE_MATCH, subject=email,
                    severity=Severity.PROVENANCE,
                    detail=f"no email match; matched by name '{name_key}' instead",
                    evidence=[EvidenceRef(source=src, detail=str(acc.get("email")))],
                ))
            else:
                findings.append(Finding(
                    type=FindingType.ORPHAN_NO_HRIS, subject=email,
                    severity=Severity.EXCEPTION,
                    detail="active account with no matching HRIS worker (possible orphan)",
                    evidence=[EvidenceRef(source=src, detail=str(acc.get("email")))],
                ))
                continue

        # Classify by the full set of HRIS spells for this worker: any current
        # (Active/On Leave) spell means the worker is employed, even if an older
        # Terminated spell also exists (rehire / concurrent spells). Only flag
        # when there is NO current spell and a Terminated one exists.
        statuses = {str(m.get("employment_status") or "").strip().lower() for m in matches}
        currently_employed = bool(statuses & {"active", "on leave", "on-leave", "leave"})
        if not currently_employed and "terminated" in statuses:
            terminated = [m for m in matches
                          if str(m.get("employment_status") or "").strip().lower() == "terminated"]
            primary = _hris_primary(terminated or matches)
            term = coerce_date(primary.get("termination_date"))
            findings.append(Finding(
                type=FindingType.TERMINATED_ACTIVE, subject=email,
                severity=Severity.EXCEPTION,
                detail=(f"active NetSuite access for worker terminated in HRIS"
                        f"{f' on {term.isoformat()}' if term else ''}"),
                evidence=[
                    EvidenceRef(source=src, detail="Account Status=Active"),
                    EvidenceRef(source=hris.cell_ref("employment_status", primary),
                                detail="HRIS Employment Status=Terminated"),
                ],
            ))
            continue

        # Worker is current (Active/On Leave). Run conservative advisory checks.
        if not low_confidence:
            _advisory_checks(acc, access, review_end, findings)

    reviewer_findings = [
        {"email": e, "decision": "Revoke",
         "comment": str(revoke_by_email[e].get("comment") or ""),
         "source": review.cell_ref("decision", revoke_by_email[e])}
        for e in sorted(reviewer_revoked)
    ]

    thresholds = {
        "dormant_days": DORMANT_DAYS,
        "privileged_role_tokens": list(PRIVILEGED_ROLE_TOKENS),
    }
    common = dict(
        inputs_hash=inputs_hash, thresholds_used=thresholds,
        model_id="deterministic", prompt_version=PROMPT_VERSION,
        reviewer_findings=reviewer_findings,
    )
    assumptions = [
        "Service/integration accounts are out of scope per the review scope; "
        "they are detected by multiple signals and reported, not silently dropped.",
        "ROLE_TITLE_MISMATCH and SOD_CONFLICT are not auto-evaluated: no "
        "role-to-job-title mapping or segregation-of-duties matrix is provided, "
        "so firing them would risk false positives.",
        "Inactive/disabled accounts are not treated as live-access exceptions.",
    ]

    return [
        _attr_periodic(sample_dir, cover, common, assumptions),
        _attr_owner(sample_dir, cover, common, assumptions),
        _attr_remediation(sample_dir, findings, reviewer_revoked, revoke_by_email,
                          service_accounts, in_scope, common, assumptions),
    ]


def _has_remediation_evidence(comment: object) -> bool:
    text = str(comment or "").lower()
    return any(tok in text for tok in REMEDIATION_TOKENS)


def _advisory_checks(acc: dict, access, review_end: date | None, findings: list[Finding]) -> None:
    email = normalise_email(acc.get("email"))
    last_login = coerce_date(acc.get("last_login"))
    # Dormancy is measured against the review end date; if that is unknown we
    # cannot judge dormancy reliably (do not silently fall back to today()).
    if review_end and last_login and (review_end - last_login).days > DORMANT_DAYS:
        findings.append(Finding(
            type=FindingType.DORMANT, subject=email, severity=Severity.ADVISORY,
            detail=f"last login {last_login.isoformat()} exceeds {DORMANT_DAYS}-day dormancy threshold",
            evidence=[EvidenceRef(source=access.cell_ref("last_login", acc),
                                  detail=str(acc.get("last_login")))],
            thresholds_used={"dormant_days": DORMANT_DAYS},
        ))
    if _is_privileged(acc.get("role")) and not _truthy_mfa(acc.get("mfa")):
        findings.append(Finding(
            type=FindingType.MFA_DISABLED_PRIVILEGED, subject=email, severity=Severity.ADVISORY,
            detail=f"privileged role '{acc.get('role')}' without MFA enabled",
            evidence=[EvidenceRef(source=access.cell_ref("mfa", acc), detail=str(acc.get("mfa")))],
        ))


def _attr_periodic(sample_dir, cover, common, assumptions) -> AttributeAssessment:
    period = cover.get("Review Period")
    rtype = cover.get("Review Type")
    completed = cover.get("Review Completed")
    evidence = [EvidenceRef(source=v[1], detail=str(v[0]))
                for v in (period, rtype, completed) if v]
    has_period = period and period[0]
    has_completed = completed and completed[0]
    if has_period and has_completed:
        conclusion = Conclusion.SUCCESS
        rationale = (f"Review performed on a periodic basis: period={period[0]!r}, "
                     f"type={rtype[0] if rtype else 'n/a'!r}, completed {completed[0]}.")
        confidence = 0.95
    else:
        conclusion = Conclusion.FURTHER_EVIDENCE_REQUIRED
        rationale = "Cover sheet does not evidence a defined review period and completion date."
        confidence = 0.5
    return AttributeAssessment(
        control=CONTROL_ID, sample=Path(sample_dir).name,
        attribute_id="UAR-a",
        attribute="Access reviews are performed on a periodic basis (e.g. quarterly)",
        conclusion=conclusion, rationale=rationale, confidence=confidence,
        extracted_facts={k: (v[0] if v else None) for k, v in {
            "review_period": period, "review_type": rtype, "review_completed": completed}.items()},
        evidence=evidence, policy_clause_cited="Control attribute (a): periodic review",
        assumptions=assumptions, **common,
    )


def _attr_owner(sample_dir, cover, common, assumptions) -> AttributeAssessment:
    approver = cover.get("Reviewer / Approver") or cover.get("Reviewer/Approver") \
        or cover.get("Reviewer") or cover.get("Approver")
    signoff = cover.get("Reviewer Sign-off") or cover.get("Sign-off") or cover.get("Approval")
    evidence = [EvidenceRef(source=v[1], detail=str(v[0])) for v in (approver, signoff) if v]
    approver_text = str(approver[0]).lower() if approver and approver[0] else ""
    is_owner = "owner" in approver_text or "director" in approver_text
    if approver and approver[0] and signoff and signoff[0] and is_owner:
        conclusion = Conclusion.SUCCESS
        rationale = (f"Reviewed and approved by an appropriate owner: {approver[0]}. "
                     f"Sign-off: {signoff[0]}.")
        confidence = 0.9
    elif approver and approver[0]:
        conclusion = Conclusion.FURTHER_EVIDENCE_REQUIRED
        rationale = (f"An approver is named ({approver[0]}) but owner authority or "
                     "sign-off evidence is incomplete.")
        confidence = 0.5
    else:
        conclusion = Conclusion.FURTHER_EVIDENCE_REQUIRED
        rationale = "No system/data owner approval is evidenced on the Cover sheet."
        confidence = 0.4
    return AttributeAssessment(
        control=CONTROL_ID, sample=Path(sample_dir).name,
        attribute_id="UAR-b",
        attribute="Access is reviewed and approved by an appropriate system or data owner",
        conclusion=conclusion, rationale=rationale, confidence=confidence,
        extracted_facts={"approver": approver[0] if approver else None,
                         "sign_off": signoff[0] if signoff else None},
        evidence=evidence, policy_clause_cited="Control attribute (b): owner approval",
        assumptions=assumptions, **common,
    )


def _attr_remediation(sample_dir, findings, reviewer_revoked, revoke_by_email,
                      service_accounts, in_scope, common, assumptions) -> AttributeAssessment:
    exceptions = [f for f in findings if f.severity == Severity.EXCEPTION]
    advisories = [f for f in findings if f.severity == Severity.ADVISORY]
    missed = [f for f in exceptions if f.subject not in reviewer_revoked]
    agreed = [f for f in exceptions if f.subject in reviewer_revoked]
    # An agreed exception is "remediated" only if its worksheet comment evidences
    # remediation having been initiated (a ticket, deprovisioning, etc.).
    unremediated = [f for f in agreed
                    if not _has_remediation_evidence(
                        (revoke_by_email.get(f.subject) or {}).get("comment"))]

    evidence = [e for f in exceptions for e in f.evidence]
    discrepancy = bool(missed)

    if missed:
        conclusion = Conclusion.FAIL
        names = ", ".join(f.subject for f in missed)
        rationale = (
            f"Reperformance found {len(exceptions)} exception(s) "
            f"({', '.join(f.subject for f in exceptions)}); the reviewer flagged "
            f"only {len(reviewer_revoked)} ({', '.join(sorted(reviewer_revoked)) or 'none'}). "
            f"Inappropriate access NOT identified or remediated for: {names}. "
            "Control attribute fails: excessive access was not caught and remediated."
        )
        confidence = 0.95
    elif exceptions and unremediated:
        conclusion = Conclusion.FURTHER_EVIDENCE_REQUIRED
        rationale = (
            f"All {len(exceptions)} exception(s) were flagged by the reviewer, but "
            f"remediation is not evidenced for: {', '.join(f.subject for f in unremediated)}. "
            "Timeliness of remediation cannot be confirmed from the worksheet."
        )
        confidence = 0.6
    elif exceptions:
        conclusion = Conclusion.SUCCESS
        rationale = (
            f"All {len(exceptions)} exception(s) found on reperformance were also "
            f"flagged by the reviewer for revocation, with remediation evidenced: "
            f"{', '.join(f.subject for f in agreed)}."
        )
        confidence = 0.85
    else:
        conclusion = Conclusion.SUCCESS
        rationale = ("No inappropriate or excessive access identified on reperformance; "
                     "agent and reviewer agree.")
        confidence = 0.85

    return AttributeAssessment(
        control=CONTROL_ID, sample=Path(sample_dir).name,
        attribute_id="UAR-c",
        attribute=("Inappropriate or excessive access identified during the review is "
                   "remediated in a timely manner"),
        conclusion=conclusion, rationale=rationale, confidence=confidence,
        extracted_facts={
            "in_scope_accounts": in_scope,
            "service_accounts_out_of_scope": service_accounts,
            "exceptions_found": [f.subject for f in exceptions],
            "advisories": [{"type": f.type.value, "subject": f.subject} for f in advisories],
            "reviewer_revoked": sorted(reviewer_revoked),
            "missed_by_reviewer": [f.subject for f in missed],
        },
        evidence=evidence, policy_clause_cited="Control attribute (c): timely remediation",
        agent_findings=findings, discrepancy_with_reviewer=discrepancy,
        assumptions=assumptions, **common,
    )


def _find_one(folder: Path, patterns: tuple[str, ...]) -> Path:
    for pat in patterns:
        hits = sorted(folder.glob(pat))
        if hits:
            return hits[0]
    raise FileNotFoundError(f"no file matching {patterns} in {folder}")
