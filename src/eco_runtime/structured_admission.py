from __future__ import annotations

"""P2 structured-output model admission probe.

A model is admitted for typed work only if it can produce output that validates
against a pinned schema. The wire schema is the grammar-safe projection (it drops
keywords real grammar engines cannot express — ``minLength``/``maxLength``/
``uniqueItems`` — per the M6 dogfood finding), but the authoritative admission
check validates the candidate against the COMPLETE schema. Wrapper objects,
thinking prose, or missing keys fail admission closed.

This is the deterministic core: given a candidate output it decides admission
offline. Driving a real deployment to produce that candidate is the live probe,
deferred with the same dependency as the M6 five-role run.
"""

import json
from dataclasses import dataclass
from typing import Any, Mapping

import jsonschema

from .adapters import grammar_safe_response_schema


class StructuredAdmissionError(Exception):
    """Typed, fail-closed admission error. Carries a stable code only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AdmissionVerdict:
    admitted: bool
    code: str

    def as_record(self) -> dict[str, Any]:
        return {"admitted": self.admitted, "code": self.code}


def wire_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """The grammar-safe projection sent over the wire (never the admission authority)."""

    if not isinstance(schema, Mapping):
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID")
    return grammar_safe_response_schema(schema)


def probe_structured_output(candidate_output: str, schema: Mapping[str, Any]) -> AdmissionVerdict:
    """Decide admission for one candidate output against the complete schema.

    Fail-closed: any parse or validation failure denies admission with a stable
    code and never raises into the caller's happy path.
    """

    if not isinstance(candidate_output, str) or not isinstance(schema, Mapping):
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID")
    # The wire projection must itself be well-formed; a schema that cannot be
    # projected is not admissible material.
    wire_schema(schema)
    try:
        parsed = json.loads(candidate_output)
    except (ValueError, TypeError):
        return AdmissionVerdict(False, "ECO_ADMISSION_NOT_JSON")
    try:
        jsonschema.validate(parsed, dict(schema))
    except jsonschema.ValidationError:
        return AdmissionVerdict(False, "ECO_ADMISSION_SCHEMA_MISMATCH")
    except jsonschema.SchemaError as exc:  # pragma: no cover - defensive
        raise StructuredAdmissionError("ECO_ADMISSION_INVALID") from exc
    return AdmissionVerdict(True, "ECO_ADMISSION_OK")
