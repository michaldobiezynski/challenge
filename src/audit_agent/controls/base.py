"""Control plug-in protocol and registry."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..engine import PerceptionEngine
from ..schema import AttributeAssessment


class Control(Protocol):
    id: str
    directory_name: str

    def assess(self, sample_dir: Path, engine: PerceptionEngine) -> list[AttributeAssessment]:
        ...


def detect_control(path: Path) -> str | None:
    """Best-effort detection of which control a folder holds."""
    name = path.name.lower()
    if "user-access" in name or "access-review" in name:
        return "user-access-review"
    if "code-review" in name or "independent" in name:
        return "independent-code-review"
    if any(path.glob("*.xlsx")):
        return "user-access-review"
    if any(path.glob("**/*.png")):
        return "independent-code-review"
    return None
