from datetime import date, datetime

import pytest

from audit_agent.evidence import (
    MissingColumnError,
    canon,
    coerce_date,
    normalise_email,
    resolve_columns,
)


def test_normalise_email_strips_and_lowercases():
    assert normalise_email("  Kevin.Lewis@NorthPeak.com ") == "kevin.lewis@northpeak.com"
    assert normalise_email(None) == ""


def test_resolve_columns_fuzzy_match():
    header = ["Work Email", "First Name", "Employment Status"]
    manifest = {
        "email": ["Email", "Work Email"],
        "first_name": ["First Name"],
        "employment_status": ["Employment Status", "Status"],
    }
    resolved = resolve_columns(header, manifest)
    assert resolved == {"email": 0, "first_name": 1, "employment_status": 2}


def test_resolve_columns_missing_raises():
    with pytest.raises(MissingColumnError):
        resolve_columns(["Name"], {"email": ["Email"]})


def test_coerce_date_handles_datetime_serial_and_string():
    assert coerce_date(datetime(2021, 12, 3)) == date(2021, 12, 3)
    # Serial path uses the 1899-12-30 epoch (round-trip a known date).
    serial = (date(2021, 12, 3) - date(1899, 12, 30)).days
    assert coerce_date(serial) == date(2021, 12, 3)
    assert coerce_date("2021-12-03") == date(2021, 12, 3)
    assert coerce_date(None) is None


def test_canon():
    assert canon("Reviewer / Approver") == "reviewerapprover"


def test_coerce_date_is_british_day_first():
    # 03/12/2021 must read as 3 December (DD/MM), not 12 March, per conventions.
    assert coerce_date("03/12/2021") == date(2021, 12, 3)


def test_short_alias_does_not_misbind():
    # "name" must not bind to "Username"; exact match keeps them distinct.
    header = ["Username", "Full Name"]
    manifest = {"username": ["Username"], "full_name": ["Full Name", "Name"]}
    resolved = resolve_columns(header, manifest)
    assert resolved == {"username": 0, "full_name": 1}
