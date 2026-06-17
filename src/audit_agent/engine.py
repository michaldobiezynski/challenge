"""Pluggable perception engine.

The audit logic depends only on the :class:`PerceptionEngine` protocol, never
on a concrete LLM. ``ClaudeCPEngine`` drives Claude Opus 4.8 through the
``claude -p`` CLI using a verified invocation; ``StubEngine`` returns canned
fact sheets so the test suite runs offline and deterministically.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

_MEDIA_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".gif": "image/gif", ".webp": "image/webp"}


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


def _media_type(path: str) -> str:
    return _MEDIA_TYPES.get(os.path.splitext(path)[1].lower(), "image/png")


class ClaudeCPEngine:
    """Calls Claude Opus 4.8 via ``claude -p`` with schema-constrained output.

    Images are sent INLINE as base64 content blocks over a stream-json stdin
    message, and the call grants NO tools (``--allowedTools ""``). This is the
    security boundary: because the model has no Read/Bash tool, a maliciously
    crafted screenshot cannot make the agent read or exfiltrate other files
    (prompt injection has nothing to act with). Contrast the simpler but unsafe
    ``@"path"`` + ``--allowedTools Read --permission-mode bypassPermissions``
    recipe, which grants whole-filesystem read access to untrusted input.

    ``--json-schema`` puts the validated object in the stream-json result
    message's ``structured_output``; ``result`` is prose (possibly fenced JSON)
    used only as a recovery fallback. There is no temperature/seed flag, so
    reproducibility comes from schema-constrained output plus the caller's
    double-extraction stability check. Verified on claude CLI v2.1.179.
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
        text = f"{system_prompt}\n\n{user_prompt}".strip() if system_prompt else user_prompt
        content: list[dict] = [{"type": "text", "text": text}]
        for path in image_paths:
            with open(path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode()
            content.append({"type": "image", "source": {
                "type": "base64", "media_type": _media_type(path), "data": b64}})
        stdin_msg = json.dumps(
            {"type": "user", "message": {"role": "user", "content": content}}) + "\n"

        cmd = [
            self.binary, "-p",
            "--model", self.model,
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--verbose",
            "--allowedTools", "",   # grant NO tools: untrusted images cannot read files
            "--json-schema", json.dumps(json_schema),
        ]

        # A real multi-image Opus vision call can be slow or, occasionally, return
        # its answer as prose in `result` with a null structured_output. Both are
        # transient, so retry rather than abort the whole run on a single bad pass.
        last_error: Exception | None = None
        for _ in range(self.retries + 1):
            try:
                return self._run_once(cmd, stdin_msg)
            except (subprocess.TimeoutExpired, RuntimeError) as exc:
                last_error = exc
        raise last_error

    def _run_once(self, cmd: list[str], stdin_msg: str) -> ExtractionResult:
        proc = subprocess.run(cmd, input=stdin_msg, capture_output=True,
                              text=True, timeout=self.timeout)
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )
        # stream-json output is one JSON object per line; the final one of
        # type "result" carries the outcome.
        result = None
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("type") == "result":
                result = obj
        if result is None:
            raise RuntimeError(
                f"claude -p produced no result message: {proc.stdout[:300]}"
            )
        if result.get("is_error"):
            raise RuntimeError(f"claude -p reported an error: {result.get('result')}")
        data = result.get("structured_output")
        if data is None:
            # Fall back to recovering JSON embedded in the prose result field.
            data = _recover_json(result.get("result"))
        if not isinstance(data, dict):
            raise RuntimeError(
                "claude -p returned no usable structured output; "
                f"result was {str(result.get('result'))[:300]}"
            )
        return ExtractionResult(data=data, model_id=_resolve_model_id(result, self.model),
                                raw=result)


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
