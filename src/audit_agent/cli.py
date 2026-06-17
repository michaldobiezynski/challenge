"""Command-line interface for the audit agent.

Examples
--------
    audit assess data/user-access-review
    audit assess data/independent-code-review --engine claude-cp
    audit assess data --all --engine stub
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from .controls import REGISTRY, detect_control
from .engine import ClaudeCPEngine, PerceptionEngine, StubEngine

# Controls that need an LLM to perceive their evidence (so the stub cannot serve).
PERCEPTION_CONTROLS = {"independent-code-review"}

app = typer.Typer(add_completion=False, help="Bead audit agent")


@app.callback()
def main() -> None:
    """Bead audit agent: assess controls against evidence and emit JSON verdicts."""


def _make_engine(name: str) -> PerceptionEngine:
    if name == "claude-cp":
        return ClaudeCPEngine()
    if name == "stub":
        # An empty stub; only valid for controls that need no perception.
        return StubEngine(responses={}, route=lambda *a: None)
    raise typer.BadParameter(f"unknown engine {name!r} (use claude-cp or stub)")


def _assess_dir(path: Path, control: str, engine: PerceptionEngine) -> list[dict]:
    assess = REGISTRY[control]
    results = assess(path, engine)
    return [a.model_dump(mode="json") for a in results]


@app.command()
def assess(
    path: Path = typer.Argument(..., exists=True, help="A control folder, or the data/ root with --all"),
    control: str = typer.Option("auto", help="Control id, or 'auto' to detect"),
    engine: str = typer.Option("claude-cp", help="Perception engine: claude-cp or stub"),
    run_all: bool = typer.Option(False, "--all", help="Assess every control subfolder under path"),
    indent: int = typer.Option(2, help="JSON indent"),
    out: Path = typer.Option(None, help="Write JSON here instead of stdout"),
) -> None:
    """Assess one or all controls and emit JSON assessments."""
    eng = _make_engine(engine)
    assessments: list[dict] = []

    if run_all:
        targets = sorted(p for p in path.iterdir() if p.is_dir())
    else:
        targets = [path]

    for target in targets:
        cid = detect_control(target) if control == "auto" else control
        if cid not in REGISTRY:
            if run_all:
                continue
            raise typer.BadParameter(f"could not resolve a control for {target}")
        if cid in PERCEPTION_CONTROLS and engine == "stub":
            raise typer.BadParameter(
                f"control {cid!r} reads screenshots and needs perception; "
                "use --engine claude-cp (the stub engine cannot perceive evidence)"
            )
        assessments.extend(_assess_dir(target, cid, eng))

    if not assessments:
        typer.echo("no assessments produced", err=True)
        raise typer.Exit(code=1)

    payload = json.dumps(assessments, indent=indent)
    if out:
        out.write_text(payload + "\n")
        typer.echo(f"wrote {len(assessments)} assessment(s) to {out}", err=True)
    else:
        sys.stdout.write(payload + "\n")


if __name__ == "__main__":
    app()
