from __future__ import annotations

import copy
import json
from datetime import datetime
from importlib import resources
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from eco_runtime.digests import semantic_digest

FLOW_API_VERSION = "flow.ai.ecosystem/v1alpha1"
FLOW_CONTRACT_PROFILE = "flow-projection-v1alpha1"
FLOW_RECORD_DOMAIN = "eco-flow-projection-v1alpha1"
_FORMAT_CHECKER = FormatChecker()


class FlowContractError(ValueError):
    """Sanitized fail-closed projection validation error."""

    def __init__(self, errors: list[str]):
        self.errors = tuple(errors)
        super().__init__("; ".join(errors))


@_FORMAT_CHECKER.checks("date-time")
def _is_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _schema() -> dict[str, Any]:
    source = resources.files("eco_flow").joinpath(
        "schemas", "flow-projection.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def flow_projection_digest(record: Mapping[str, Any]) -> str:
    candidate = copy.deepcopy(dict(record))
    metadata = candidate.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {
            "domain": FLOW_RECORD_DOMAIN,
            "profile": FLOW_CONTRACT_PROFILE,
            "record": candidate,
        }
    )


def _path(parts: list[Any]) -> str:
    return "$" + "".join(
        f"[{part}]" if isinstance(part, int) else f".{part}" for part in parts
    )


def _message(validator: str | None) -> str:
    return {
        "additionalProperties": "contains an unexpected property",
        "const": "does not match the required constant",
        "enum": "is not an allowed value",
        "format": "has an invalid format",
        "maxItems": "contains too many items",
        "maxLength": "is too long",
        "minLength": "is too short",
        "minimum": "is below the allowed minimum",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "has the wrong type",
        "oneOf": "does not match exactly one allowed shape",
    }.get(validator, "failed validation")


def flow_contract_errors(record: Any) -> list[str]:
    if not isinstance(record, dict):
        return ["FlowProjection$: has the wrong type"]
    errors = sorted(
        Draft202012Validator(
            _schema(), format_checker=_FORMAT_CHECKER
        ).iter_errors(record),
        key=lambda error: (list(error.absolute_path), str(error.validator)),
    )
    result = [
        f"FlowProjection{_path(list(error.absolute_path))}: {_message(error.validator)}"
        for error in errors
    ]
    if result:
        return result

    nodes = record["spec"]["nodes"]
    edges = record["spec"]["edges"]
    node_ids = [node["id"] for node in nodes]
    sequences = [node["sequence"] for node in nodes]
    edge_ids = [edge["id"] for edge in edges]
    semantic: list[str] = []
    if len(node_ids) != len(set(node_ids)):
        semantic.append("FlowProjection$.spec.nodes: failed validation")
    if sequences != list(range(1, len(nodes) + 1)):
        semantic.append("FlowProjection$.spec.nodes: failed validation")
    if len(edge_ids) != len(set(edge_ids)):
        semantic.append("FlowProjection$.spec.edges: failed validation")
    known = set(node_ids)
    if any(edge["from"] not in known or edge["to"] not in known for edge in edges):
        semantic.append("FlowProjection$.spec.edges: failed validation")
    summary = record["spec"]["summary"]
    if summary != {
        "nodeCount": len(nodes),
        "edgeCount": len(edges),
        "failedNodeCount": sum(node["status"] == "failed" for node in nodes),
        "deniedNodeCount": sum(node["status"] == "denied" for node in nodes),
    }:
        semantic.append("FlowProjection$.spec.summary: failed validation")
    if record["metadata"]["recordDigest"] != flow_projection_digest(record):
        semantic.append("FlowProjection$.metadata.recordDigest: failed validation")
    return semantic


def validate_flow_projection(record: Any) -> dict[str, Any]:
    errors = flow_contract_errors(record)
    if errors:
        raise FlowContractError(errors)
    return record


def replay_projection(payload: str | bytes | Mapping[str, Any]) -> dict[str, Any]:
    """Replay one immutable export without granting authority or running work."""

    try:
        if isinstance(payload, bytes):
            candidate = json.loads(payload.decode("utf-8"))
        elif isinstance(payload, str):
            candidate = json.loads(payload)
        else:
            candidate = copy.deepcopy(dict(payload))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise FlowContractError(["FlowProjection$: invalid JSON export"]) from exc
    return validate_flow_projection(candidate)
