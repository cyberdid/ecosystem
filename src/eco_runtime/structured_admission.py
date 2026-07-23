from __future__ import annotations

"""P2 structured-output model admission probe.

A model is admitted for typed work only if it can produce output that validates
against a pinned schema. Two steps are deliberately separate:

1. **Extraction is liberal.** Real models return the same object many ways —
   clean, wrapped in a ``` ```json ``` fence, surrounded by prose, or after a
   ``<think>`` block. The extractor works with all of them: it strips fences and
   pulls the first balanced JSON object/array. Refusing a model for a markdown
   fence would be brittle and wrong; that is normalization, not a defect.
2. **Validation is strict.** Once a candidate object is extracted, it must
   validate against the COMPLETE schema (the wire schema is only the grammar-safe
   projection sent to the model). A wrong shape, missing key or out-of-bounds
   value is denied — that is a real contract violation, not a formatting quirk.

The verdict reports whether normalization was needed, so a model that is merely
untidy (``normalized=True``) is distinguished from one that is clean, and both
from one that genuinely cannot produce the typed object.

This is the deterministic core: given a candidate output it decides admission
offline. Driving a real deployment to produce that candidate is the live probe.
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

import jsonschema

from .adapters import grammar_safe_response_schema

_FENCE_RE = re.compile(r"```(?:[a-zA-Z0-9_-]+)?\s*(.*?)```", re.DOTALL)
_THINK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.DOTALL | re.IGNORECASE)


class StructuredAdmissionError(Exception):
    """Typed, fail-closed admission error. Carries a stable code only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AdmissionVerdict:
    admitted: bool
    code: str
    normalized: bool = False

    def as_record(self) -> dict[str, Any]:
        return {"admitted": self.admitted, "code": self.code, "normalized": self.normalized}


def wire_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """The grammar-safe projection sent over the wire (never the admission authority)."""

    if not isinstance(schema, Mapping):
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID")
    return grammar_safe_response_schema(schema)


def _first_balanced_json(text: str) -> str | None:
    """Return the first balanced ``{...}`` or ``[...]`` substring, or None.

    String contents and escapes are respected so braces inside strings do not
    break balancing.
    """

    start = None
    opener = closer = ""
    for index, char in enumerate(text):
        if char in "{[":
            start, opener, closer = index, char, ("}" if char == "{" else "]")
            break
    if start is None:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _repair_json_escapes(text: str) -> str:
    """Drop backslashes that do not form a valid JSON escape.

    Small models (notably gemma) markdown-escape underscores, emitting ``\\_``,
    which is not a legal JSON escape and fails ``json.loads``. This keeps valid
    escapes (``\\n``, ``\\"``, ``\\\\``) intact and only removes the stray
    backslash of an invalid one.
    """

    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in '"\\/bfnrtu':
                out.append(char)
                out.append(nxt)
            else:
                out.append(nxt)
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _parseable_form(candidate: str) -> str:
    """Return the candidate, or its escape-repaired form when only that parses."""

    try:
        json.loads(candidate)
        return candidate
    except (ValueError, TypeError):
        pass
    repaired = _repair_json_escapes(candidate)
    if repaired != candidate:
        try:
            json.loads(repaired)
            return repaired
        except (ValueError, TypeError):
            pass
    return candidate


def extract_json_candidate(text: str) -> tuple[str | None, bool]:
    """Pull a JSON candidate out of a real model output.

    Returns ``(candidate, normalized)``. ``normalized`` is True when the raw
    output was not already a bare JSON value (fences/prose/thinking removed).
    Works with clean JSON, markdown-fenced JSON, prose-wrapped JSON and
    ``<think>``-prefixed reasoning output.
    """

    if not isinstance(text, str):
        return None, False
    raw = text.strip()
    # A bare JSON value is the clean, un-normalized case.
    try:
        json.loads(raw)
        return raw, False
    except (ValueError, TypeError):
        pass
    stripped = _THINK_RE.sub("", text)
    # Prefer the content of a fenced block if present.
    for match in _FENCE_RE.finditer(stripped):
        inner = _first_balanced_json(match.group(1))
        if inner is not None:
            return _parseable_form(inner), True
    inner = _first_balanced_json(stripped)
    if inner is not None:
        return _parseable_form(inner), True
    return None, False


def probe_structured_output(candidate_output: str, schema: Mapping[str, Any]) -> AdmissionVerdict:
    """Decide admission: extract liberally, then validate strictly.

    Fail-closed: a genuine failure (no object, or a real schema violation) denies
    admission with a stable code and never raises into the caller's happy path.
    """

    if not isinstance(candidate_output, str) or not isinstance(schema, Mapping):
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID")
    # The wire projection must itself be well-formed; a schema that cannot be
    # projected is not admissible material.
    wire_schema(schema)
    candidate, normalized = extract_json_candidate(candidate_output)
    if candidate is None:
        return AdmissionVerdict(False, "ECO_ADMISSION_NO_JSON", normalized=False)
    try:
        parsed = json.loads(candidate)
    except (ValueError, TypeError):
        return AdmissionVerdict(False, "ECO_ADMISSION_NOT_JSON", normalized=normalized)
    try:
        jsonschema.validate(parsed, dict(schema))
    except jsonschema.ValidationError:
        return AdmissionVerdict(False, "ECO_ADMISSION_SCHEMA_MISMATCH", normalized=normalized)
    except jsonschema.SchemaError as exc:  # pragma: no cover - defensive
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID") from exc
    return AdmissionVerdict(True, "ECO_ADMISSION_OK", normalized=normalized)
