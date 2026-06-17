# Bead Audit Agent

An audit agent that assesses the two sample controls in `data/` and emits, for
each sample and control attribute, a structured JSON verdict of `SUCCESS`,
`FAIL`, or `FURTHER_EVIDENCE_REQUIRED` with detailed, auditable reasoning.

## Approach

Each control is a plug-in with three stages:

```
EXTRACT (perception)  ->  EVALUATE (deterministic rules)  ->  EMIT (validated JSON)
```

The guiding principle is **the model perceives, the code decides**. A large
language model is used only for perception (reading the PR screenshots and
interpreting fuzzy fields). Every pass/fail decision lives in plain
deterministic Python, so conclusions are consistent, reproducible, and
traceable. The User Access Review control uses **no model at all**: it is a pure
reconciliation.

The **verdict rule** is the same for every attribute:

- `SUCCESS` - evidence is present and the control is satisfied.
- `FAIL` - evidence is present and it contradicts the control.
- `FURTHER_EVIDENCE_REQUIRED` - evidence is absent, illegible, or ambiguous.

## Requirements

- Python 3.11 or newer.
- For Control 1 only (the screenshot control): the Claude Code CLI (`claude`)
  installed and authenticated, used in headless mode with Opus 4.8. Control 2
  needs no model and runs fully offline.

## Setup

```bash
cd /path/to/challenge
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the package and the `audit` command.

## Running against the sample data

```bash
# Control 2 - User Access Review (deterministic, no model needed)
audit assess data/user-access-review

# Control 1 - Independent Code Review (reads the PR screenshots with Claude)
audit assess data/independent-code-review --engine claude-cp

# Both controls at once
audit assess data --all --engine claude-cp

# Write output to a file instead of stdout
audit assess data/user-access-review --out out.json
```

Useful options:

- `--control auto|user-access-review|independent-code-review` (default `auto`,
  detected from the folder).
- `--engine claude-cp|stub` (default `claude-cp`). `stub` returns no perception
  and is intended for offline runs of Control 2 and for the test suite.
- `--all` assess every control subfolder under the given path.

The output is a JSON array of assessment objects, one per (sample, attribute).

## Output schema

Each assessment carries enough provenance to trace a verdict back to a rule, a
fact, and a specific cell or screenshot:

| Field | Meaning |
| --- | --- |
| `control`, `sample`, `attribute_id`, `attribute` | what was assessed |
| `conclusion` | `SUCCESS` / `FAIL` / `FURTHER_EVIDENCE_REQUIRED` |
| `rationale` | human-readable explanation of the decision |
| `extracted_facts` | raw perception, kept separate from the decision |
| `evidence[]` | `{source, detail}` citations (e.g. `file.xlsx!Sheet!B12`) |
| `policy_clause_cited` | the control attribute or policy clause applied |
| `assumptions[]` | explicit assumptions made |
| `thresholds_used` | the numeric thresholds applied |
| `agent_findings` vs `reviewer_findings` | reperformance diff |
| `discrepancy_with_reviewer` | true when the agent disagrees with the reviewer |
| `confidence` | 0.0 to 1.0 |
| `inputs_hash` | SHA-256 of each evidence file |
| `model_id`, `prompt_version` | reproducibility metadata |

## The two controls

### Independent Code Review (`independent-code-review`)

For each sample, the screenshots are read into a structured PR fact sheet
(author, merge actor, reviewers and whether each is a bot, review states and
ordering relative to the merge, coverage figures). Extraction is run **twice**;
if the canonical facts diverge the result is downgraded to
`FURTHER_EVIDENCE_REQUIRED` (`UNSTABLE_EXTRACTION`). Deterministic rules then
assess three attributes: review before merge, independent (human, non-author)
approval, and testing against `testing-policy.md` (line >= 80%, branch >= 70%,
function >= 80%), honouring the policy's exception categories.

### User Access Review (`user-access-review`)

A **reperformance** test. The reviewer's worksheet is treated as a claim to be
checked, not trusted. The NetSuite access export is reconciled against the
Workday HRIS roster (join on normalised email, with a reported name-based
fallback), HRIS rows are de-duplicated to the latest employment spell (rehire
aware), and an independent exception set is computed. Attribute (c) **fails if
the agent finds any exception the reviewer did not** (this is what catches the
account the reviewer missed).

## Design decisions and limitations

- **openpyxl, not pandas, for loading**: it preserves cell coordinates so every
  finding can cite an exact cell, which a DataFrame loses. pandas was therefore
  not needed and is not a dependency.
- **Sheets and columns are resolved by fuzzy header match** against a required
  column manifest; a missing required column fails loudly rather than producing
  a silent wrong answer. Counts, sheet names, and the `svc-` prefix are not
  hard-coded.
- **`ROLE_TITLE_MISMATCH` and `SOD_CONFLICT` are declared but not auto-fired**:
  no role-to-job-title mapping or segregation-of-duties matrix is provided, so
  firing naive heuristics would create false positives. `DORMANT` and
  `MFA_DISABLED_PRIVILEGED` are reported as conservative advisories and do not by
  themselves fail a control.
- **Determinism with a model in the loop**: `claude -p` exposes no temperature
  control, so reproducibility comes from schema-constrained output plus the
  double-extraction stability check. Decisions are pure functions of the
  extracted facts.

## Security note (threat model)

Control 1 sends auditee-supplied PR screenshots to `claude -p` running with
`--permission-mode bypassPermissions` and the `Read` tool. A maliciously crafted
screenshot could attempt prompt injection to make the agent read other files.
The evidence is **untrusted input**. Run this tool in an isolated environment
(a container or throwaway working directory containing only the evidence), not
with access to secrets or a home directory. The XLSX loader applies a basic
file-size guard, and image paths containing a double quote are rejected. Fully
sandboxing the `Read` tool to the evidence directory is tracked as future work.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite runs offline (the perception engine is stubbed). It includes the
mandatory regression that the agent independently catches the account the
reviewer missed and disagrees with the reviewer's conclusion, plus synthetic
mutants (rehire, alias email, orphan, dormant, MFA-off privileged, service
account, self-approval, bot-only approval, coverage below threshold, unstable
extraction) to guard against over-fitting to the two provided samples.
