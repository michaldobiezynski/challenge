"""Output schema for audit assessments.

One :class:`AttributeAssessment` is emitted per (control, sample, attribute).
The schema deliberately separates raw perception (``extracted_facts``) from
the decision, and carries enough provenance for an auditor to trace a verdict
back to a rule, a fact, and a specific cell or screenshot field.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Conclusion(str, Enum):
    """The three permitted assessment outcomes.

    The verdict rule is consistent across every control:
    SUCCESS = evidence present and the control is satisfied;
    FAIL = evidence present and it contradicts the control;
    FURTHER_EVIDENCE_REQUIRED = evidence absent, illegible, or ambiguous.
    """

    SUCCESS = "SUCCESS"
    FAIL = "FAIL"
    FURTHER_EVIDENCE_REQUIRED = "FURTHER_EVIDENCE_REQUIRED"


class FindingType(str, Enum):
    """Categories of exception an auditor may raise during reperformance."""

    # Definitive exceptions: high precision, drive a control attribute to FAIL.
    TERMINATED_ACTIVE = "TERMINATED_ACTIVE"
    ORPHAN_NO_HRIS = "ORPHAN_NO_HRIS"
    # Advisory exceptions: reported for human attention; conservative thresholds.
    DORMANT = "DORMANT"
    MFA_DISABLED_PRIVILEGED = "MFA_DISABLED_PRIVILEGED"
    # Declared but not auto-fired without a mapping/matrix (see control docs).
    ROLE_TITLE_MISMATCH = "ROLE_TITLE_MISMATCH"
    SOD_CONFLICT = "SOD_CONFLICT"
    # Provenance / data-quality flags.
    LOW_CONFIDENCE_MATCH = "LOW_CONFIDENCE_MATCH"
    UNSTABLE_EXTRACTION = "UNSTABLE_EXTRACTION"


class Severity(str, Enum):
    EXCEPTION = "exception"
    ADVISORY = "advisory"
    PROVENANCE = "provenance"


class EvidenceRef(BaseModel):
    """A pointer to the precise evidence behind a claim.

    ``source`` is a traceable locator such as ``file.xlsx!Sheet!B12`` or
    ``screenshot.png#reviewers``; ``detail`` is the observed value.
    """

    source: str
    detail: str


class Finding(BaseModel):
    type: FindingType
    subject: str
    severity: Severity
    detail: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    thresholds_used: dict = Field(default_factory=dict)


class AttributeAssessment(BaseModel):
    control: str
    sample: str
    attribute_id: str
    attribute: str
    conclusion: Conclusion
    rationale: str
    extracted_facts: dict = Field(default_factory=dict)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    policy_clause_cited: str | None = None
    assumptions: list[str] = Field(default_factory=list)
    thresholds_used: dict = Field(default_factory=dict)
    agent_findings: list[Finding] = Field(default_factory=list)
    reviewer_findings: list[dict] = Field(default_factory=list)
    discrepancy_with_reviewer: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    inputs_hash: dict[str, str] = Field(default_factory=dict)
    model_id: str | None = None
    prompt_version: str | None = None
