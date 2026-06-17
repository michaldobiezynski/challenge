"""End-to-end CLI test: the UAR control runs offline and emits valid JSON."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from audit_agent.cli import app
from conftest import UAR_REAL

runner = CliRunner()


@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_cli_assess_uar_emits_valid_json():
    result = runner.invoke(app, ["assess", str(UAR_REAL), "--engine", "stub"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert isinstance(payload, list) and len(payload) == 3
    by_id = {a["attribute_id"]: a for a in payload}
    assert set(by_id) == {"UAR-a", "UAR-b", "UAR-c"}
    # Specific expected verdicts on the real data, not a vacuous enum check.
    assert by_id["UAR-a"]["conclusion"] == "SUCCESS"
    assert by_id["UAR-b"]["conclusion"] == "SUCCESS"
    assert by_id["UAR-c"]["conclusion"] == "FAIL"
    assert by_id["UAR-c"]["discrepancy_with_reviewer"] is True
    assert "kevin.lewis@northpeakfinancial.com" in by_id["UAR-c"]["extracted_facts"]["missed_by_reviewer"]
    for a in payload:
        assert a["inputs_hash"]  # provenance present


@pytest.mark.skipif(not UAR_REAL.exists(), reason="challenge data not present")
def test_cli_rejects_stub_engine_for_screenshot_control():
    from conftest import ICR_REAL
    if not ICR_REAL.exists():
        pytest.skip("ICR data not present")
    result = runner.invoke(app, ["assess", str(ICR_REAL), "--engine", "stub"])
    assert result.exit_code != 0
    assert "perceive" in result.output.lower() or "claude-cp" in result.output.lower()
