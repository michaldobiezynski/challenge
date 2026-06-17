"""Pluggable perception engine.

The audit logic depends only on the :class:`PerceptionEngine` protocol, never
on a concrete LLM. ``ClaudeCPEngine`` drives Claude Opus 4.8 through the
``claude -p`` CLI using a verified invocation; ``StubEngine`` returns canned
fact sheets so the test suite runs offline and deterministically.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable


@dataclass
class ExtractionResult:
    data: dict
    model_id: str | None
    raw: dict = field(default_factory=dict)


@runtime_checkable
class PerceptionEngine(Protocol):
    name: str

    def extract(self, system_prompt: str, user_prompt: str,
                image_paths: list[str], json_schema: dict) -> ExtractionResult:
        ...


def _image_mentions(image_paths: list[str]) -> str:
    # The verified vision recipe references each image by an @"<absolute path>"
    # mention; Claude reads the file via its Read tool. A double quote in a path
    # would break the mention, so reject such paths rather than emit a broken one.
    for p in image_paths:
        if '"' in p:
            raise ValueError(f"image path contains a double quote, which cannot be "
                             f"safely referenced: {p!r}")
    return " ".join(f'@"{p}"' for p in image_paths)


class ClaudeCPEngine:
    """Calls Claude Opus 4.8 via ``claude -p`` with schema-constrained output.

    Verified invocation (claude v2.1.179): vision through @"path" mentions,
    ``--allowedTools Read --permission-mode bypassPermissions`` so file reads
    do not prompt, ``--output-format json --json-schema <schema>`` so the
    validated object lands in ``envelope["structured_output"]`` (the ``result``
    field may wrap JSON in markdown fences, so it is never parsed). There is no
    temperature/seed flag; reproducibility comes from schema-constrained output
    plus the caller's double-extraction stability check.
    """

    name = "claude-cp"

    def __init__(self, model: str = "claude-opus-4-8", timeout: int = 600,
                 binary: str = "claude", retries: int = 2):
        self.model = model
        self.timeout = timeout
        self.binary = binary
        self.retries = retries

    def extract(self, system_prompt: str, user_prompt: str,
                image_paths: list[str], json_schema: dict) -> ExtractionResult:
        prompt = f"{_image_mentions(image_paths)}\n\n{user_prompt}".strip()
        cmd = [
            self.binary, "-p",
            "--model", self.model,
            "--allowedTools", "Read",
            "--permission-mode", "bypassPermissions",
            "--output-format", "json",
            "--json-schema", json.dumps(json_schema),
        ]
        if system_prompt:
            cmd += ["--append-system-prompt", system_prompt]

        # A real multi-image Opus vision call can be slow or, occasionally, return
        # its answer as prose in `result` with a null structured_output. Both are
        # transient, so retry rather than abort the whole run on a single bad pass.
        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            try:
                return self._run_once(cmd, prompt)
            except (subprocess.TimeoutExpired, RuntimeError) as exc:
                last_error = exc
        raise last_error

    def _run_once(self, cmd: list[str], prompt: str) -> ExtractionResult:
        proc = subprocess.run(cmd, input=prompt, capture_output=True,
                              text=True, timeout=self.timeout)
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"claude -p output was not JSON: {proc.stdout[:300]}"
            ) from exc
        if envelope.get("is_error"):
            raise RuntimeError(f"claude -p reported an error: {envelope.get('result')}")
        data = envelope.get("structured_output")
        if data is None:
            # Fall back to recovering JSON embedded in the prose result field.
            data = _recover_json(envelope.get("result"))
        if not isinstance(data, dict):
            raise RuntimeError(
                "claude -p returned no usable structured output; "
                f"result was {str(envelope.get('result'))[:300]}"
            )
        return ExtractionResult(data=data, model_id=_resolve_model_id(envelope, self.model),
                                raw=envelope)


def _recover_json(result: object) -> dict | None:
    """Best-effort recovery of a JSON object from a prose `result` string.

    Handles the case where the model emits its answer in a ```json fenced block
    or as a bare object rather than populating structured_output.
    """
    if not isinstance(result, str):
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", result, re.DOTALL)
    candidate = fence.group(1) if fence else None
    if candidate is None:
        start = result.find("{")
        end = result.rfind("}")
        candidate = result[start:end + 1] if 0 <= start < end else None
    if candidate is None:
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _resolve_model_id(envelope: dict, requested: str) -> str:
    usage = envelope.get("modelUsage") or {}
    # Every call also bills a small Haiku classifier turn; report the primary
    # (non-Haiku) model that actually did the work.
    primary = [m for m in usage if "haiku" not in m.lower()]
    return primary[0] if primary else requested


class StubEngine:
    """Returns canned extraction results for offline, deterministic tests.

    Construct with either a dict keyed by a routing key, or a callable that
    maps (system_prompt, user_prompt, image_paths) -> dict.
    """

    name = "stub"

    def __init__(self, responses: dict | Callable, model_id: str = "stub-model",
                 route: Callable[[str, str, list[str]], str] | None = None):
        self._responses = responses
        self._model_id = model_id
        self._route = route

    def extract(self, system_prompt: str, user_prompt: str,
                image_paths: list[str], json_schema: dict) -> ExtractionResult:
        if callable(self._responses):
            data = self._responses(system_prompt, user_prompt, image_paths)
        else:
            key = self._route(system_prompt, user_prompt, image_paths) if self._route else None
            if key is not None:
                data = self._responses[key]
            elif self._responses:
                data = next(iter(self._responses.values()))
            else:
                raise RuntimeError(
                    "StubEngine has no canned response: it cannot perceive "
                    "evidence. Use the 'claude-cp' engine for controls that need "
                    "perception (e.g. independent-code-review)."
                )
        return ExtractionResult(data=dict(data), model_id=self._model_id, raw={})
