from __future__ import annotations

import copy
import json
from datetime import datetime
from importlib import resources
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError


ROUTING_API_VERSION = "routing.ai.ecosystem/v1alpha1"
ROUTING_CONTRACT_PROFILE = "model-routing-contracts-v1alpha1"
ROUTING_RECORD_DOMAIN = "eco-model-routing-record-v1alpha1"
CANONICAL_MODEL_ROLES = (
    "eco-orchestrator",
    "eco-worker",
    "eco-grader",
    "eco-researcher",
    "eco-coder",
)
ROUTING_SCHEMA_BY_KIND = {
    "ModelRoutingPolicy": "model-routing-policy.schema.json",
    "ObservedModelCapabilities": "observed-model-capabilities.schema.json",
    "TrustedPriceCatalog": "trusted-price-catalog.schema.json",
    "ModelRouteRequest": "model-route-request.schema.json",
    "ModelRouteDecision": "model-route-decision.schema.json",
    "RoutingExplain": "routing-explain.schema.json",
}
_COMMON_SCHEMA = "common.schema.json"
_DEFINITIONS = {"ModelRoutingPolicy", "TrustedPriceCatalog"}
_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _is_date_time(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _load_schema_file(name: str) -> dict[str, Any]:
    source = resources.files("eco_routing").joinpath("schemas", name)
    return json.loads(source.read_text(encoding="utf-8"))


def _registry() -> Registry:
    schemas = [_load_schema_file(_COMMON_SCHEMA)] + [
        _load_schema_file(name) for name in ROUTING_SCHEMA_BY_KIND.values()
    ]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def routing_schema_bundle_digest() -> str:
    return semantic_digest(
        {
            "profile": ROUTING_CONTRACT_PROFILE,
            "common": _load_schema_file(_COMMON_SCHEMA),
            "records": {
                kind: _load_schema_file(ROUTING_SCHEMA_BY_KIND[kind])
                for kind in sorted(ROUTING_SCHEMA_BY_KIND)
            },
        }
    )


def routing_record_digest(record: dict[str, Any]) -> str:
    projected = copy.deepcopy(record)
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {
            "domain": ROUTING_RECORD_DOMAIN,
            "profile": ROUTING_CONTRACT_PROFILE,
            "record": projected,
        }
    )


def seal_routing_record(record: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(record)
    sealed.setdefault("metadata", {})["recordDigest"] = routing_record_digest(sealed)
    return sealed


def _path(parts: Iterable[Any]) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _semantic_errors(kind: str, document: dict[str, Any]) -> list[str]:
    metadata = document["metadata"]
    spec = document["spec"]
    errors: list[str] = []
    if metadata["recordDigest"] != routing_record_digest(document):
        errors.append(f"{kind}$.metadata.recordDigest: failed validation")
    if kind in _DEFINITIONS and "revision" not in metadata:
        errors.append(f"{kind}$.metadata.revision: failed validation")

    if kind == "ModelRoutingPolicy":
        roles = spec["roles"]
        if tuple(item["role"] for item in roles) != CANONICAL_MODEL_ROLES:
            errors.append(f"{kind}$.spec.roles: failed validation")
        for index, role in enumerate(roles):
            for field in (
                "requiredCapabilities",
                "allowedActionClasses",
                "allowedDataClasses",
                "allowedZones",
                "allowedRetentions",
            ):
                if role[field] != sorted(role[field]):
                    errors.append(f"{kind}$.spec.roles[{index}].{field}: failed validation")
            retryable = role["fallback"]["retryableFailureClasses"]
            if retryable != sorted(retryable):
                errors.append(
                    f"{kind}$.spec.roles[{index}].fallback.retryableFailureClasses: failed validation"
                )

    elif kind == "ObservedModelCapabilities":
        if spec["capabilities"] != sorted(spec["capabilities"]):
            errors.append(f"{kind}$.spec.capabilities: failed validation")
        if _parse_time(spec["validUntil"]) <= _parse_time(spec["observedAt"]):
            errors.append(f"{kind}$.spec.validUntil: failed validation")

    elif kind == "TrustedPriceCatalog":
        if _parse_time(spec["validUntil"]) <= _parse_time(spec["validFrom"]):
            errors.append(f"{kind}$.spec.validUntil: failed validation")
        identities = [
            (item["deploymentId"], item["deploymentIdentityDigest"])
            for item in spec["entries"]
        ]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            errors.append(f"{kind}$.spec.entries: failed validation")

    elif kind == "ModelRouteRequest":
        for field in (
            "requiredCapabilities",
            "allowedZones",
            "allowedRetentions",
        ):
            if spec[field] != sorted(spec[field]):
                errors.append(f"{kind}$.spec.{field}: failed validation")
        if _parse_time(spec["deadlineAt"]) <= _parse_time(metadata["createdAt"]):
            errors.append(f"{kind}$.spec.deadlineAt: failed validation")

    elif kind == "ModelRouteDecision":
        allowed = spec["decision"] == "allowed"
        if allowed != (spec["selected"] is not None):
            errors.append(f"{kind}$.spec.selected: failed validation")
        if allowed != (spec["reasonCode"] == "eligible"):
            errors.append(f"{kind}$.spec.reasonCode: failed validation")
        if _parse_time(spec["validUntil"]) <= _parse_time(metadata["createdAt"]):
            errors.append(f"{kind}$.spec.validUntil: failed validation")
        if (spec["routeAttempt"] == 1) != (spec["fallbackFromDigest"] is None):
            errors.append(f"{kind}$.spec.fallbackFromDigest: failed validation")

    elif kind == "RoutingExplain":
        candidates = spec["candidates"]
        if [item["candidateDigest"] for item in candidates] != sorted(
            item["candidateDigest"] for item in candidates
        ):
            errors.append(f"{kind}$.spec.candidates: failed validation")
        if any(item["reasonCodes"] != sorted(item["reasonCodes"]) for item in candidates):
            errors.append(f"{kind}$.spec.candidates: failed validation")
        allowed = spec["decision"] == "allowed"
        if allowed != (spec["selectedCandidateDigest"] is not None):
            errors.append(f"{kind}$.spec.selectedCandidateDigest: failed validation")
    return errors


def routing_contract_errors(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["RoutingRecord$: failed validation"]
    kind = document.get("kind")
    if kind not in ROUTING_SCHEMA_BY_KIND:
        return ["RoutingRecord$.kind: failed validation"]
    schema = _load_schema_file(ROUTING_SCHEMA_BY_KIND[kind])
    validator = Draft202012Validator(
        schema,
        registry=_registry(),
        format_checker=_FORMAT_CHECKER,
    )
    errors = [
        f"{kind}{_path(error.absolute_path)}: failed validation"
        for error in sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    ]
    if not errors:
        errors.extend(_semantic_errors(kind, document))
    return errors


def validate_routing_record(document: Any) -> dict[str, Any]:
    errors = routing_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return copy.deepcopy(document)
