from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError


MEMORY_API_VERSION = "memory.ai.ecosystem/v1alpha1"
MEMORY_CONTRACT_PROFILE = "private-memory-contracts-v1alpha1"
MEMORY_RECORD_DOMAIN = "eco-private-memory-record-v1alpha1"
MEMORY_TYPES = (
    "fact",
    "claim",
    "decision",
    "constraint",
    "open-question",
    "failed-approach",
    "summary",
)
DATA_CLASSES = ("D0", "D1", "D2", "D3")
PRIVACY_LEVELS = ("P0", "P1", "P2", "P3")
LINK_RELATIONS = ("supersedes", "refutes", "conflicts")
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


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads(resources.files("eco_memory").joinpath("schemas", name).read_text("utf-8"))


def _registry() -> Registry:
    registry = Registry()
    for name in ("common.schema.json", "memory-record.schema.json"):
        schema = _load_schema(name)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def memory_schema_bundle_digest() -> str:
    return semantic_digest(
        {
            "profile": MEMORY_CONTRACT_PROFILE,
            "common": _load_schema("common.schema.json"),
            "record": _load_schema("memory-record.schema.json"),
        }
    )


def memory_record_digest(record: Mapping[str, Any]) -> str:
    projected = copy.deepcopy(dict(record))
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {"domain": MEMORY_RECORD_DOMAIN, "profile": MEMORY_CONTRACT_PROFILE, "record": projected}
    )


def seal_memory_record(record: Mapping[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(dict(record))
    sealed.setdefault("metadata", {})["recordDigest"] = memory_record_digest(sealed)
    return sealed


def _path(parts: Iterable[Any]) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def memory_contract_errors(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["MemoryRecord$: failed validation"]
    schema = _load_schema("memory-record.schema.json")
    validator = Draft202012Validator(schema, registry=_registry(), format_checker=_FORMAT_CHECKER)
    errors = [
        f"MemoryRecord{_path(error.absolute_path)}: failed validation"
        for error in sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    ]
    if errors:
        return errors
    metadata = document["metadata"]
    spec = document["spec"]
    digest = metadata["recordDigest"]
    if digest != memory_record_digest(document):
        errors.append("MemoryRecord$.metadata.recordDigest: failed validation")
    if spec["expiresAt"] is not None and _parse_time(spec["expiresAt"]) <= _parse_time(metadata["createdAt"]):
        errors.append("MemoryRecord$.spec.expiresAt: failed validation")
    for name in LINK_RELATIONS:
        values = spec["links"][name]
        if values != sorted(set(values)) or digest in values:
            errors.append(f"MemoryRecord$.spec.links.{name}: failed validation")
    artifacts = spec["sourceArtifacts"]
    if artifacts != sorted(artifacts, key=lambda item: (item["sha256"], item["storageRef"])):
        errors.append("MemoryRecord$.spec.sourceArtifacts: failed validation")
    if len({item["sha256"] for item in artifacts}) != len(artifacts):
        errors.append("MemoryRecord$.spec.sourceArtifacts: failed validation")
    compaction = spec["compaction"]
    if (spec["memoryType"] == "summary") != (compaction is not None):
        errors.append("MemoryRecord$.spec.compaction: failed validation")
    if compaction is not None:
        sources = compaction["sourceRecordDigests"]
        if sources != sorted(set(sources)) or digest in sources:
            errors.append("MemoryRecord$.spec.compaction.sourceRecordDigests: failed validation")
        compact_artifacts = compaction["sourceArtifacts"]
        if compact_artifacts != sorted(compact_artifacts, key=lambda item: (item["sha256"], item["storageRef"])):
            errors.append("MemoryRecord$.spec.compaction.sourceArtifacts: failed validation")
        if len({item["sha256"] for item in compact_artifacts}) != len(compact_artifacts):
            errors.append("MemoryRecord$.spec.compaction.sourceArtifacts: failed validation")
        relations = compaction["preservedRelations"]
        relation_keys = [(item["from"], item["relation"], item["to"]) for item in relations]
        if relation_keys != sorted(set(relation_keys)):
            errors.append("MemoryRecord$.spec.compaction.preservedRelations: failed validation")
        source_set = set(sources)
        if any(item["from"] not in source_set for item in relations):
            errors.append("MemoryRecord$.spec.compaction.preservedRelations: failed validation")
    return errors


def validate_memory_record(document: Any) -> dict[str, Any]:
    errors = memory_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return copy.deepcopy(document)
