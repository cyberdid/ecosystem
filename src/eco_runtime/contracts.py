from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .digests import semantic_digest
from .errors import ContractValidationError
from .team_identity import AUTHORITY_SCHEMA_BY_KIND, authority_contract_errors

API_VERSION = "runtime.ai.ecosystem/v1alpha1"

RUNTIME_SCHEMA_BY_KIND = {
    "RunRequest": "run-request.schema.json",
    "RunPlan": "run-plan.schema.json",
    "NoModelRunRequest": "no-model-run-request.schema.json",
    "NoModelRunPlan": "no-model-run-plan.schema.json",
    "NoModelReadRequest": "no-model-read-request.schema.json",
    "WikiHealthRunEvidence": "wiki-health-run-evidence.v1.schema.json",
    "WikiHealthPromotionReport": "wiki-health-promotion-report.v1.schema.json",
    "ToolRequest": "tool-request.schema.json",
    "PolicyDecision": "policy-decision.schema.json",
    "RunEvent": "run-event.schema.json",
    "ArtifactRecord": "artifact-record.schema.json",
    "ErrorRecord": "error-record.schema.json",
    "AdapterConformanceProfile": "adapter-conformance.schema.json",
    "PlatformBackendConformanceProfile": "platform-backend-conformance.schema.json",
    "EndpointBinding": "endpoint-binding.schema.json",
    "ModelRequest": "model-request.schema.json",
    "ModelResult": "model-result.schema.json",
    "RepositorySnapshot": "repository-snapshot.schema.json",
    "ToolExecutionIntent": "tool-execution-intent.schema.json",
    "RepositoryReadReceipt": "repository-read-receipt.schema.json",
    "ToolExecutionOutcome": "tool-execution-outcome.schema.json",
    "RunCheckpoint": "run-checkpoint.schema.json",
    "WorkspaceChangeProposal": "workspace-change-proposal.schema.json",
    "ApprovalRequest": "approval-request.schema.json",
    "ApprovalGrant": "approval-grant.schema.json",
    "WorkspaceWriteIntent": "workspace-write-intent.schema.json",
    "WorkspaceWriteReceipt": "workspace-write-receipt.schema.json",
    "WorkspaceRollbackReceipt": "workspace-rollback-receipt.schema.json",
}
# Backward-compatible runtime registry. Authority schemas deliberately live in a
# separate registry so existing M4 schema snapshots remain byte-for-byte stable.
SCHEMA_BY_KIND = RUNTIME_SCHEMA_BY_KIND

TOOL_ARGUMENT_SCHEMAS = {
    "repository.read": "repository-read.schema.json",
    "repository.write": "repository-write.schema.json",
}

CONTRACT_PROFILE = "runtime-contracts-v1alpha1"

RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
FORMAT_CHECKER = FormatChecker()

PLATFORM_BACKEND_PROBE_IDS = (
    "clean-environment-and-fs-boundary",
    "network-namespace-deny",
    "output-and-deadline-bounds",
    "read-only-workdir",
    "stdin-closed",
)
PLATFORM_BACKEND_CAPABILITIES = (
    "backend.clean-environment",
    "backend.landlock-workdir-boundary",
    "backend.network-namespace-deny",
    "backend.output-deadline-bounded",
    "backend.read-only-workdir",
    "backend.stdin-closed",
)


@FORMAT_CHECKER.checks("date-time")
def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _load_schema(kind: str) -> dict[str, Any]:
    name = SCHEMA_BY_KIND[kind]
    source = resources.files("eco_runtime").joinpath("schemas", name)
    return json.loads(source.read_text(encoding="utf-8"))


def _load_tool_schema(tool_id: str) -> dict[str, Any]:
    name = TOOL_ARGUMENT_SCHEMAS[tool_id]
    source = resources.files("eco_runtime").joinpath("schemas", "tools", name)
    return json.loads(source.read_text(encoding="utf-8"))


def schema_bundle_digest() -> str:
    return semantic_digest(
        {
            "records": {
                kind: _load_schema(kind) for kind in sorted(RUNTIME_SCHEMA_BY_KIND)
            },
            "tools": {tool_id: _load_tool_schema(tool_id) for tool_id in sorted(TOOL_ARGUMENT_SCHEMAS)},
        }
    )


def _json_path(parts: Any) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _sanitized_message(validator: str | None) -> str:
    messages = {
        "additionalProperties": "contains an unexpected property",
        "const": "does not match the required constant",
        "enum": "is not an allowed value",
        "format": "has an invalid format",
        "maxItems": "contains too many items",
        "maxLength": "is too long",
        "maximum": "is above the allowed maximum",
        "minItems": "contains too few items",
        "minLength": "is too short",
        "minimum": "is below the allowed minimum",
        "not": "contains a forbidden value",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "has the wrong type",
        "uniqueItems": "contains duplicate items",
    }
    return messages.get(validator, "failed validation")


def contract_errors(document: Any) -> list[str]:
    """Return deterministic errors without echoing untrusted record values."""

    if not isinstance(document, dict):
        return ["record$: has the wrong type"]

    kind = document.get("kind")
    if not isinstance(kind, str) or (
        kind not in RUNTIME_SCHEMA_BY_KIND and kind not in AUTHORITY_SCHEMA_BY_KIND
    ):
        return ["record$.kind: is not a supported record kind"]

    if kind in AUTHORITY_SCHEMA_BY_KIND:
        return authority_contract_errors(document)

    validator = Draft202012Validator(_load_schema(kind), format_checker=FORMAT_CHECKER)
    errors = sorted(
        validator.iter_errors(document),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    structural = [
        f"{kind}{_json_path(error.absolute_path)}: {_sanitized_message(error.validator)}"
        for error in errors
    ]
    if structural or kind != "PlatformBackendConformanceProfile":
        return structural

    metadata = document["metadata"]
    spec = document["spec"]
    probes = spec["probes"]
    probe_ids = [item["id"] for item in probes]
    status = spec["status"]
    semantic: list[str] = []
    if metadata["platformProfileId"] != spec["platform"]["id"]:
        semantic.append(f"{kind}$.metadata.platformProfileId: failed validation")
    platform = spec["platform"]
    expected_context = {
        "linux-native": "native",
        "wsl": "wsl",
        "macos": "native",
        "windows-native": "native",
        "container": "container",
        "hosted-ci": "hosted-ci",
    }[platform["id"]]
    if platform["context"] != expected_context:
        semantic.append(f"{kind}$.spec.platform.context: failed validation")
    if status in {"pass", "fail"} and not (
        platform["id"] in {"linux-native", "wsl"}
        and platform["operatingSystem"] == "linux"
        and platform["architecture"] in {"x86_64", "aarch64"}
    ):
        semantic.append(f"{kind}$.spec.platform: failed validation")
    if spec["suite"]["probeIds"] != list(PLATFORM_BACKEND_PROBE_IDS):
        semantic.append(f"{kind}$.spec.suite.probeIds: failed validation")
    if probe_ids != list(PLATFORM_BACKEND_PROBE_IDS):
        semantic.append(f"{kind}$.spec.probes: failed validation")
    if status == "pass" and (
        any(item["status"] != "pass" for item in probes)
        or spec["observedCapabilities"] != list(PLATFORM_BACKEND_CAPABILITIES)
        or spec["deviationCodes"]
    ):
        semantic.append(f"{kind}$.spec.status: failed validation")
    if status == "fail" and (
        not any(item["status"] == "fail" for item in probes)
        or any(item["status"] == "not-run" for item in probes)
        or spec["observedCapabilities"]
        or not spec["deviationCodes"]
    ):
        semantic.append(f"{kind}$.spec.status: failed validation")
    if status == "unsupported" and (
        any(item["status"] != "not-run" for item in probes)
        or spec["observedCapabilities"]
        or not spec["deviationCodes"]
    ):
        semantic.append(f"{kind}$.spec.status: failed validation")
    return semantic


def validate_record(document: Any) -> dict[str, Any]:
    """Validate a supported runtime or authority record unchanged on success."""

    errors = contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return document


def tool_argument_errors(tool_id: str, arguments: Any) -> list[str]:
    """Validate untrusted tool arguments against a broker-owned schema."""

    if tool_id not in TOOL_ARGUMENT_SCHEMAS:
        return ["tool$: is not a supported runtime tool"]
    validator = Draft202012Validator(_load_tool_schema(tool_id), format_checker=FORMAT_CHECKER)
    errors = sorted(
        validator.iter_errors(arguments),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    structural_errors = [
        f"{tool_id}{_json_path(error.absolute_path)}: {_sanitized_message(error.validator)}"
        for error in errors
    ]
    if structural_errors:
        return structural_errors
    if tool_id in {"repository.read", "repository.write"}:
        path = arguments["path"]
        invalid_path = (
            len(path.encode("utf-8")) > 4096
            or path == "."
            or path.startswith("./")
            or path.endswith("/")
            or "//" in path
            or any(segment in {"", ".", ".."} for segment in path.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or unicodedata.normalize("NFC", path) != path
        )
        if invalid_path:
            return [f"{tool_id}$.path: is not a canonical repository-relative path"]
    return []


def validate_tool_arguments(tool_id: str, arguments: Any) -> dict[str, Any]:
    errors = tool_argument_errors(tool_id, arguments)
    if errors:
        raise ContractValidationError(errors)
    return arguments
