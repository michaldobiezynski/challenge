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
    ids = {a["attribute_id"] for a in payload}
    assert ids == {"UAR-a", "UAR-b", "UAR-c"}
    for a in payload:
        assert a["conclusion"] in {"SUCCESS", "FAIL", "FURTHER_EVIDENCE_REQUIRED"}
        assert a["inputs_hash"]  # provenance present
