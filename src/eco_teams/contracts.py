from __future__ import annotations

"""Strict, content-free contracts for embedded general team orchestration."""

import copy
import hashlib
import json
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import ContractValidationError
from eco_runtime.team_access import ACTION_PROFILE

API_VERSION = "teams.ai.ecosystem/v1alpha1"
PROFILE = "bounded-agent-team-v1"
SCHEMAS = {
    "AgentTeamManifest": "agent-team-manifest.schema.json",
    "TeamTask": "team-task.schema.json",
    "TeamHandoff": "team-handoff.schema.json",
    "TeamRunResult": "team-run-result.schema.json",
}
_FORMAT = FormatChecker()


def _load(name: str) -> dict[str, Any]:
    return json.loads(
        resources.files("eco_teams").joinpath("schemas", name).read_text(encoding="utf-8")
    )


def _registry() -> Registry:
    registry = Registry()
    for name in ("common.schema.json", *SCHEMAS.values()):
        schema = _load(name)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def schema_bundle_digest() -> str:
    payload = {
        name: _load(name)
        for name in sorted({"common.schema.json", *SCHEMAS.values()})
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def record_digest(record: Mapping[str, Any]) -> str:
    candidate = copy.deepcopy(dict(record))
    metadata = candidate.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest({"profile": "eco-team-record-v1", "record": candidate})


def seal_record(record: Mapping[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(dict(record))
    candidate.setdefault("metadata", {})["recordDigest"] = record_digest(candidate)
    return candidate


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp")
    return parsed.astimezone(timezone.utc)


def _schema_errors(record: Any) -> list[str]:
    if not isinstance(record, dict) or record.get("kind") not in SCHEMAS:
        return ["TeamRecord$: unknown or invalid kind"]
    validator = Draft202012Validator(
        _load(SCHEMAS[record["kind"]]), registry=_registry(), format_checker=_FORMAT
    )
    errors = sorted(validator.iter_errors(record), key=lambda error: list(error.absolute_path))
    return [
        f"{record['kind']}$.{'.'.join(map(str, error.absolute_path))}: contract validation failed"
        for error in errors
    ]


def _sorted_unique(values: list[str]) -> bool:
    return values == sorted(values) and len(values) == len(set(values))


def _manifest_errors(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    spec = record["spec"]
    roles = spec["roles"]
    role_ids = [role["id"] for role in roles]
    if not _sorted_unique(role_ids):
        errors.append("AgentTeamManifest$.spec.roles: roles must be sorted and unique")
    by_id = {role["id"]: role for role in roles}
    try:
        created = _time(record["metadata"]["createdAt"])
        deadline = _time(spec["deadline"])
        if created >= deadline:
            errors.append("AgentTeamManifest$.spec.deadline: must be after creation")
        for role in roles:
            if role["principal"]["kind"] != "PrincipalIdentity" or role["membership"]["kind"] != "MembershipBinding":
                errors.append(f"AgentTeamManifest$.spec.roles.{role['id']}: invalid M5 identity binding")
            for field in ("actions", "dataClasses", "toolIds", "zones", "delegatesTo"):
                if not _sorted_unique(role[field]):
                    errors.append(f"AgentTeamManifest$.spec.roles.{role['id']}.{field}: must be sorted and unique")
            if _time(role["notAfter"]) > deadline:
                errors.append(f"AgentTeamManifest$.spec.roles.{role['id']}.notAfter: exceeds team deadline")
            if role["id"] in role["delegatesTo"] or not set(role["delegatesTo"]) <= set(by_id):
                errors.append(f"AgentTeamManifest$.spec.roles.{role['id']}.delegatesTo: invalid target")
            budget = role["budget"]
            if budget["maxTokens"] > spec["budget"]["maxTotalTokens"] or budget["maxCostMicrousd"] > spec["budget"]["maxCostMicrousd"]:
                errors.append(f"AgentTeamManifest$.spec.roles.{role['id']}.budget: exceeds team budget")
        for source in roles:
            for target_id in source["delegatesTo"]:
                target = by_id[target_id]
                if (
                    not set(target["actions"]) <= set(source["actions"])
                    or not set(target["dataClasses"]) <= set(source["dataClasses"])
                    or not set(target["toolIds"]) <= set(source["toolIds"])
                    or not set(target["zones"]) <= set(source["zones"])
                    or _time(target["notAfter"]) > _time(source["notAfter"])
                    or target["budget"]["maxTokens"] > source["budget"]["maxTokens"]
                    or target["budget"]["maxCostMicrousd"] > source["budget"]["maxCostMicrousd"]
                    or target["budget"]["maxDurationSeconds"] > source["budget"]["maxDurationSeconds"]
                ):
                    errors.append(
                        f"AgentTeamManifest$.spec.roles.{source['id']}.delegatesTo: target expands authority"
                    )
    except (KeyError, TypeError, ValueError):
        errors.append("AgentTeamManifest$: semantic validation failed")
    return errors


def _task_errors(record: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    spec = record["spec"]
    task_id = record["metadata"]["id"]
    dependencies = spec["dependencies"]
    if not _sorted_unique(dependencies) or task_id in dependencies:
        errors.append("TeamTask$.spec.dependencies: must be sorted, unique, and exclude self")
    if spec["parentTaskId"] == task_id:
        errors.append("TeamTask$.spec.parentTaskId: cannot reference self")
    expected = ACTION_PROFILE.get(spec["action"])
    if expected is None or spec["resource"]["kind"] != expected[1]:
        errors.append("TeamTask$.spec.resource: does not match action profile")
    if spec["action"] == "model.invoke" and (
        spec["routeDecision"] is None
        or spec["routeDecision"]["kind"] != "ModelRouteDecision"
    ):
        errors.append("TeamTask$.spec.routeDecision: model.invoke requires an exact route binding")
    if spec["action"] != "model.invoke" and spec["routeDecision"] is not None:
        errors.append("TeamTask$.spec.routeDecision: non-model tasks cannot carry model routes")
    if spec["action"].startswith("repository.") and spec["toolId"] != spec["action"]:
        errors.append("TeamTask$.spec.toolId: repository action requires its exact tool id")
    try:
        if _time(record["metadata"]["createdAt"]) >= _time(spec["notAfter"]):
            errors.append("TeamTask$.spec.notAfter: must be after creation")
    except (TypeError, ValueError):
        errors.append("TeamTask$.spec.notAfter: invalid timestamp")
    return errors


def _handoff_errors(record: Mapping[str, Any]) -> list[str]:
    spec = record["spec"]
    if spec["fromTaskId"] == spec["toTaskId"]:
        return ["TeamHandoff$.spec: self handoff is invalid"]
    return []


def _result_errors(record: Mapping[str, Any]) -> list[str]:
    spec = record["spec"]
    tasks = spec["tasks"]
    ids = [task["id"] for task in tasks]
    errors: list[str] = []
    if not _sorted_unique(ids):
        errors.append("TeamRunResult$.spec.tasks: must be sorted and unique")
    statuses = [task["status"] for task in tasks]
    expected = (
        "ambiguous" if "ambiguous" in statuses else
        "succeeded" if all(item == "succeeded" for item in statuses) else
        "cancelled" if all(item == "cancelled" for item in statuses) else
        "failed" if all(item == "failed" for item in statuses) else
        "partial-failure"
    )
    if spec["status"] != expected:
        errors.append("TeamRunResult$.spec.status: does not truthfully summarize task outcomes")
    if spec["usage"]["tokens"] != sum(task["chargedTokens"] for task in tasks) or spec["usage"]["costMicrousd"] != sum(task["chargedCostMicrousd"] for task in tasks):
        errors.append("TeamRunResult$.spec.usage: does not equal task usage")
    for task in tasks:
        if task["status"] in {"succeeded", "failed"} and task["outcomeDigest"] is None:
            errors.append("TeamRunResult$.spec.tasks: completed task lacks outcome digest")
    return errors


def validate_record(record: Any) -> dict[str, Any]:
    candidate = copy.deepcopy(record)
    errors = _schema_errors(candidate)
    if not errors and candidate["metadata"]["recordDigest"] != record_digest(candidate):
        errors.append(f"{candidate['kind']}$.metadata.recordDigest: digest mismatch")
    if not errors:
        errors.extend({
            "AgentTeamManifest": _manifest_errors,
            "TeamTask": _task_errors,
            "TeamHandoff": _handoff_errors,
            "TeamRunResult": _result_errors,
        }[candidate["kind"]](candidate))
    if errors:
        raise ContractValidationError(errors)
    return candidate
