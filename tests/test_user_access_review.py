"""Reperformance tests for the User Access Review control."""

from __future__ import annotations

from datetime import date

import pytest

from audit_agent.controls import user_access_review as uar
from audit_agent.schema import Conclusion, FindingType
from conftest import UAR_REAL


def _by_id(results):
    return {a.attribute_id: a for a in results}


# --- Real-data ground-truth tests ------------------------------------------

@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_real_data_catches_reviewer_miss_kevin_lewis():
    """The headline reperformance result: the reviewer missed kevin.lewis."""
    res = _by_id(uar.assess(UAR_REAL))
    c = res["UAR-c"]
    found = set(c.extracted_facts["exceptions_found"])
    assert "danielle.goodwin@northpeakfinancial.com" in found
    assert "kevin.lewis@northpeakfinancial.com" in found
    assert c.extracted_facts["missed_by_reviewer"] == ["kevin.lewis@northpeakfinancial.com"]
    assert c.conclusion is Conclusion.FAIL
    assert c.discrepancy_with_reviewer is True


@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_real_data_danielle_is_agreement_not_miss():
    res = _by_id(uar.assess(UAR_REAL))
    revoked = set(res["UAR-c"].extracted_facts["reviewer_revoked"])
    assert "danielle.goodwin@northpeakfinancial.com" in revoked


@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_real_data_service_accounts_out_of_scope_not_dropped():
    res = _by_id(uar.assess(UAR_REAL))
    svc = res["UAR-c"].extracted_facts["service_accounts_out_of_scope"]
    assert len(svc) == 2
    assert all("svc-" in s for s in svc)


@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_real_data_periodic_and_owner_attributes_pass():
    res = _by_id(uar.assess(UAR_REAL))
    assert res["UAR-a"].conclusion is Conclusion.SUCCESS
    assert res["UAR-b"].conclusion is Conclusion.SUCCESS


# --- Synthetic mutant tests (generalisation beyond the two samples) --------

def _active(email, name="Test User", role="A/R Clerk", mfa="Yes", last="2026-06-01"):
    return {"Username": email.split("@")[0], "Full Name": name, "Email": email,
            "Role": role, "Account Status": "Active", "MFA Enabled": mfa,
            "Last Login": last}


def _emp(email, status, first="Test", last="User", title="Clerk",
         hire=date(2020, 1, 1), term=""):
    return {"Work Email": email, "First Name": first, "Last Name": last,
            "Job Title": title, "Employment Status": status, "Hire Date": hire,
            "Termination Date": term}


def test_terminated_active_missed_is_fail(make_sample):
    email = "ghost@corp.com"
    sample = make_sample(
        access=[_active(email)],
        review=[{"Email": email, "Name": "Ghost", "Role": "A/R Clerk",
                 "Account Status": "Active", "Reviewer Decision": "Retain",
                 "Reviewer Comment": "looks fine"}],
        hris=[_emp(email, "Terminated", term=date(2022, 1, 1))],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert c.conclusion is Conclusion.FAIL
    assert c.discrepancy_with_reviewer is True
    assert any(f.type is FindingType.TERMINATED_ACTIVE for f in c.agent_findings)


def test_rehire_is_not_flagged(make_sample):
    """Terminated then rehired (later Active spell) must not be an exception."""
    email = "rehired@corp.com"
    sample = make_sample(
        access=[_active(email)],
        review=[],
        hris=[
            _emp(email, "Terminated", hire=date(2018, 1, 1), term=date(2019, 6, 1)),
            _emp(email, "Active", hire=date(2021, 1, 1)),
        ],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert not any(f.type is FindingType.TERMINATED_ACTIVE for f in c.agent_findings)
    assert c.conclusion is Conclusion.SUCCESS


def test_orphan_account_is_exception(make_sample):
    email = "nobody@corp.com"
    sample = make_sample(access=[_active(email, name="No Match")], review=[], hris=[])
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert any(f.type is FindingType.ORPHAN_NO_HRIS for f in c.agent_findings)
    assert c.conclusion is Conclusion.FAIL


def test_name_fallback_is_low_confidence(make_sample):
    """No email match but a name match should be flagged, not treated as orphan."""
    sample = make_sample(
        access=[_active("k.lewis@corp.com", name="Kevin Lewis")],
        review=[],
        hris=[_emp("kevin.lewis@corp.com", "Active", first="Kevin", last="Lewis")],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    types = {f.type for f in c.agent_findings}
    assert FindingType.LOW_CONFIDENCE_MATCH in types
    assert FindingType.ORPHAN_NO_HRIS not in types


def test_mfa_disabled_privileged_is_advisory_not_fail(make_sample):
    email = "admin@corp.com"
    sample = make_sample(
        access=[_active(email, role="Administrator", mfa="No")],
        review=[],
        hris=[_emp(email, "Active", title="IT Admin")],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert any(f.type is FindingType.MFA_DISABLED_PRIVILEGED for f in c.agent_findings)
    assert c.conclusion is Conclusion.SUCCESS  # advisories do not fail the control


def test_dormant_account_is_advisory(make_sample):
    email = "sleepy@corp.com"
    sample = make_sample(
        access=[_active(email, last="2024-01-01")],  # long before 2026-06-30 review end
        review=[],
        hris=[_emp(email, "Active")],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert any(f.type is FindingType.DORMANT for f in c.agent_findings)


def test_service_account_detected_by_role(make_sample):
    sample = make_sample(
        access=[{"Username": "integration1", "Full Name": "Service Account - X",
                 "Email": "integration1@corp.com", "Role": "Web Services (Integration)",
                 "Account Status": "Active", "MFA Enabled": "No", "Last Login": "2026-06-01"}],
        review=[], hris=[],
    )
    c = _by_id(uar.assess(sample))["UAR-c"]
    assert "integration1@corp.com" in c.extracted_facts["service_accounts_out_of_scope"]
    assert c.extracted_facts["exceptions_found"] == []
