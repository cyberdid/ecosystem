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

ORCHESTRATION_API_VERSION = "orchestration.ai.ecosystem/v1alpha1"
ORCHESTRATION_CONTRACT_PROFILE = "orchestration-contracts-v1alpha1"
ORCHESTRATION_RECORD_DOMAIN = "eco-orchestration-record-v1alpha1"
ORCHESTRATION_ROUTE_DOMAIN = "eco-orchestration-route-v1alpha1"

ORCHESTRATION_SCHEMA_BY_KIND = {
    "RoleProfile": "role-profile.schema.json",
    "TeamManifest": "team-manifest.schema.json",
    "LoopDefinition": "loop-definition.schema.json",
    "SourceBundle": "source-bundle.schema.json",
    "TeamRunRequest": "team-run-request.schema.json",
    "TeamRunPlan": "team-run-plan.schema.json",
    "RouteDecision": "route-decision.schema.json",
    "RoleAttemptResult": "role-attempt-result.schema.json",
    "HandoffRecord": "handoff-record.schema.json",
    "ClaimRecord": "claim-record.schema.json",
    "EvidenceRecord": "evidence-record.schema.json",
    "VerificationRecord": "verification-record.schema.json",
    "ReviewRecord": "review-record.schema.json",
    "TeamRunResult": "team-run-result.schema.json",
    "OrchestrationEvent": "orchestration-event.schema.json",
}

_COMMON_SCHEMA = "common.schema.json"
_DEFINITION_KINDS = {"RoleProfile", "TeamManifest", "LoopDefinition"}
_ROLE_ORDER = ("planner", "analyst", "verifier", "synthesizer", "reviewer")
_ROLE_EDGES = tuple(zip(_ROLE_ORDER, _ROLE_ORDER[1:]))
_EXECUTION_SLOTS = (
    ("planner", 1),
    ("analyst", 1),
    ("verifier", 1),
    ("synthesizer", 1),
    ("reviewer", 1),
    ("synthesizer", 2),
    ("reviewer", 2),
)
_HANDOFF_SLOTS = (
    (0, "planner", 1, "analyst", 1),
    (0, "analyst", 1, "verifier", 1),
    (0, "verifier", 1, "synthesizer", 1),
    (0, "synthesizer", 1, "reviewer", 1),
    (1, "reviewer", 1, "synthesizer", 2),
    (1, "synthesizer", 2, "reviewer", 2),
)
_FORMAT_CHECKER = FormatChecker()


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


def _load_schema_file(name: str) -> dict[str, Any]:
    source = resources.files("eco_orchestration").joinpath("schemas", name)
    return json.loads(source.read_text(encoding="utf-8"))


def _load_schema(kind: str) -> dict[str, Any]:
    return _load_schema_file(ORCHESTRATION_SCHEMA_BY_KIND[kind])


def _schema_registry() -> Registry:
    schemas = [_load_schema_file(_COMMON_SCHEMA)] + [
        _load_schema(kind) for kind in ORCHESTRATION_SCHEMA_BY_KIND
    ]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def orchestration_schema_bundle_digest() -> str:
    """Return a digest for only the additive M6 registry."""

    return semantic_digest(
        {
            "profile": ORCHESTRATION_CONTRACT_PROFILE,
            "common": _load_schema_file(_COMMON_SCHEMA),
            "records": {
                kind: _load_schema(kind)
                for kind in sorted(ORCHESTRATION_SCHEMA_BY_KIND)
            },
        }
    )


def orchestration_record_digest(record: dict[str, Any]) -> str:
    """Bind a record to the M6 profile without creating a self-digest cycle."""

    projected = copy.deepcopy(record)
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {
            "domain": ORCHESTRATION_RECORD_DOMAIN,
            "profile": ORCHESTRATION_CONTRACT_PROFILE,
            "record": projected,
        }
    )


def orchestration_route_digest(route_decision: dict[str, Any]) -> str:
    """Digest the non-cyclic route snapshot embedded by a parent plan."""

    spec = route_decision["spec"]
    return semantic_digest(
        {
            "domain": ORCHESTRATION_ROUTE_DOMAIN,
            "profile": ORCHESTRATION_CONTRACT_PROFILE,
            "route": {
                "roleId": spec["roleId"],
                "attempt": spec["attempt"],
                "decision": spec["decision"],
                "reasonCode": spec["reasonCode"],
                "deployment": copy.deepcopy(spec["deployment"]),
                "validUntil": spec["validUntil"],
                "fallbackPolicy": spec["fallbackPolicy"],
            },
        }
    )


def _json_path(parts: Iterable[Any]) -> str:
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
        "oneOf": "does not match exactly one allowed shape",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "has the wrong type",
        "uniqueItems": "contains duplicate items",
    }
    return messages.get(validator, "failed validation")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _binding_error(
    errors: list[str], kind: str, path: str, binding: dict[str, Any], expected: str
) -> None:
    if binding["kind"] != expected:
        errors.append(f"{kind}${path}: failed validation")


def _budget_fits(child: dict[str, int], parent: dict[str, int]) -> bool:
    return all(child[name] <= parent[name] for name in parent)


def _semantic_errors(kind: str, document: dict[str, Any]) -> list[str]:
    metadata = document["metadata"]
    spec = document["spec"]
    errors: list[str] = []
    if kind in _DEFINITION_KINDS and metadata["runId"] != "definition":
        errors.append(f"{kind}$.metadata.runId: failed validation")
    if metadata["recordDigest"] != orchestration_record_digest(document):
        errors.append(f"{kind}$.metadata.recordDigest: failed validation")

    if kind == "RoleProfile":
        if spec["allowedCapabilities"] != sorted(spec["allowedCapabilities"]):
            errors.append(f"{kind}$.spec.allowedCapabilities: failed validation")
        if spec["allowedDataClasses"] != sorted(spec["allowedDataClasses"]):
            errors.append(f"{kind}$.spec.allowedDataClasses: failed validation")
        if spec["modelRequirements"]["capabilityIds"] != sorted(
            spec["modelRequirements"]["capabilityIds"]
        ):
            errors.append(f"{kind}$.spec.modelRequirements.capabilityIds: failed validation")

    elif kind == "TeamManifest":
        roles = spec["roles"]
        if tuple(item["roleId"] for item in roles) != _ROLE_ORDER:
            errors.append(f"{kind}$.spec.roles: failed validation")
        if any(item["profile"]["kind"] != "RoleProfile" for item in roles):
            errors.append(f"{kind}$.spec.roles: failed validation")
        edges = tuple((item["from"], item["to"]) for item in spec["edges"])
        if edges != _ROLE_EDGES:
            errors.append(f"{kind}$.spec.edges: failed validation")

    elif kind == "LoopDefinition":
        _binding_error(errors, kind, ".spec.teamManifest", spec["teamManifest"], "TeamManifest")
        if spec["hardStops"] != sorted(spec["hardStops"]):
            errors.append(f"{kind}$.spec.hardStops: failed validation")

    elif kind == "SourceBundle":
        entries = spec["entries"]
        entry_ids = [item["id"] for item in entries]
        if entry_ids != sorted(entry_ids) or len(entry_ids) != len(set(entry_ids)):
            errors.append(f"{kind}$.spec.entries: failed validation")
        if sum(item["artifact"]["byteLength"] for item in entries) != spec["totalByteLength"]:
            errors.append(f"{kind}$.spec.totalByteLength: failed validation")
        if any(item["artifact"]["dataClass"] != spec["dataClass"] for item in entries):
            errors.append(f"{kind}$.spec.entries: failed validation")
        question = [item for item in entries if item["id"] == spec["questionEntryId"]]
        if len(question) != 1 or question[0]["mediaType"] not in {"text/plain", "text/markdown"}:
            errors.append(f"{kind}$.spec.questionEntryId: failed validation")
        for index, entry in enumerate(entries):
            provenance = entry["provenance"]
            has_git_fields = (
                provenance["remoteIdentityDigest"] is not None
                and provenance["commitDigest"] is not None
            )
            if (provenance["kind"] == "git") != has_git_fields:
                errors.append(f"{kind}$.spec.entries[{index}].provenance: failed validation")
            if provenance["kind"] == "research-web" and has_git_fields:
                errors.append(f"{kind}$.spec.entries[{index}].provenance: failed validation")

    elif kind == "TeamRunRequest":
        _binding_error(errors, kind, ".spec.sourceBundle", spec["sourceBundle"], "SourceBundle")
        _binding_error(errors, kind, ".spec.teamManifest", spec["teamManifest"], "TeamManifest")
        _binding_error(errors, kind, ".spec.loopDefinition", spec["loopDefinition"], "LoopDefinition")
        if _parse_timestamp(spec["deadlineAt"]) <= _parse_timestamp(metadata["createdAt"]):
            errors.append(f"{kind}$.spec.deadlineAt: failed validation")

    elif kind == "TeamRunPlan":
        for field, expected in (
            ("request", "TeamRunRequest"),
            ("sourceBundle", "SourceBundle"),
            ("teamManifest", "TeamManifest"),
            ("loopDefinition", "LoopDefinition"),
        ):
            _binding_error(errors, kind, f".spec.{field}", spec[field], expected)
        steps = spec["steps"]
        expected_predecessors = ((), ("planner",), ("analyst",), ("verifier",), ("synthesizer",))
        if tuple(item["roleId"] for item in steps) != _ROLE_ORDER:
            errors.append(f"{kind}$.spec.steps: failed validation")
        if tuple(item["ordinal"] for item in steps) != (1, 2, 3, 4, 5):
            errors.append(f"{kind}$.spec.steps: failed validation")
        if tuple(tuple(item["predecessors"]) for item in steps) != expected_predecessors:
            errors.append(f"{kind}$.spec.steps: failed validation")
        if any(item["profile"]["kind"] != "RoleProfile" for item in steps):
            errors.append(f"{kind}$.spec.steps: failed validation")
        expected_route_attempts = ((1,), (1,), (1,), (1, 2), (1, 2))
        if tuple(
            tuple(route["attempt"] for route in item["routes"])
            for item in steps
        ) != expected_route_attempts:
            errors.append(f"{kind}$.spec.steps: failed validation")
        all_routes = [route for item in steps for route in item["routes"]]
        if (
            len({item["decisionId"] for item in all_routes}) != 7
            or len({item["routeDigest"] for item in all_routes}) != 7
        ):
            errors.append(f"{kind}$.spec.steps: failed validation")
        if any(not _budget_fits(item["budget"], spec["aggregateBudget"]) for item in steps):
            errors.append(f"{kind}$.spec.aggregateBudget: failed validation")
        if _parse_timestamp(spec["deadlineAt"]) <= _parse_timestamp(metadata["createdAt"]):
            errors.append(f"{kind}$.spec.deadlineAt: failed validation")

    elif kind == "RouteDecision":
        if spec["routeDigest"] != orchestration_route_digest(document):
            errors.append(f"{kind}$.spec.routeDigest: failed validation")
        if spec["decision"] == "denied" and spec["reasonCode"] == "eligible":
            errors.append(f"{kind}$.spec.reasonCode: failed validation")
        if _parse_timestamp(spec["validUntil"]) <= _parse_timestamp(metadata["createdAt"]):
            errors.append(f"{kind}$.spec.validUntil: failed validation")

    elif kind == "RoleAttemptResult":
        _binding_error(errors, kind, ".spec.routeDecision", spec["routeDecision"], "RouteDecision")
        if _parse_timestamp(spec["finishedAt"]) < _parse_timestamp(spec["startedAt"]):
            errors.append(f"{kind}$.spec.finishedAt: failed validation")

    elif kind == "HandoffRecord":
        _binding_error(errors, kind, ".spec.roleAttemptResult", spec["roleAttemptResult"], "RoleAttemptResult")
        cycle, from_role, _, to_role, to_attempt = _HANDOFF_SLOTS[spec["ordinal"] - 1]
        if (
            spec["cycle"],
            spec["fromRoleId"],
            spec["toRoleId"],
            spec["toAttempt"],
        ) != (cycle, from_role, to_role, to_attempt):
            errors.append(f"{kind}$.spec: failed validation")
        for field, expected in (
            ("claims", "ClaimRecord"),
            ("evidence", "EvidenceRecord"),
            ("verifications", "VerificationRecord"),
        ):
            if any(item["kind"] != expected for item in spec[field]):
                errors.append(f"{kind}$.spec.{field}: failed validation")

    elif kind == "ClaimRecord":
        _binding_error(errors, kind, ".spec.sourceBundle", spec["sourceBundle"], "SourceBundle")

    elif kind == "EvidenceRecord":
        _binding_error(errors, kind, ".spec.sourceBundle", spec["sourceBundle"], "SourceBundle")

    elif kind == "VerificationRecord":
        _binding_error(errors, kind, ".spec.claim", spec["claim"], "ClaimRecord")
        if any(item["kind"] != "EvidenceRecord" for item in spec["evidence"]):
            errors.append(f"{kind}$.spec.evidence: failed validation")
        if spec["status"] == "verified" and not spec["evidence"]:
            errors.append(f"{kind}$.spec.status: failed validation")

    elif kind == "ReviewRecord":
        _binding_error(errors, kind, ".spec.reviewerAttempt", spec["reviewerAttempt"], "RoleAttemptResult")

    elif kind == "TeamRunResult":
        for field, expected in (
            ("plan", "TeamRunPlan"),
            ("request", "TeamRunRequest"),
            ("sourceBundle", "SourceBundle"),
            ("terminalEvent", "OrchestrationEvent"),
        ):
            _binding_error(errors, kind, f".spec.{field}", spec[field], expected)
        for field, expected in (
            ("reviews", "ReviewRecord"),
            ("claims", "ClaimRecord"),
            ("evidence", "EvidenceRecord"),
            ("verifications", "VerificationRecord"),
            ("routeDecisions", "RouteDecision"),
            ("roleAttempts", "RoleAttemptResult"),
            ("handoffs", "HandoffRecord"),
        ):
            if any(item["kind"] != expected for item in spec[field]):
                errors.append(f"{kind}$.spec.{field}: failed validation")

    elif kind == "OrchestrationEvent":
        previous = spec["previousEventDigest"]
        if (spec["sequence"] == 1) != (previous is None):
            errors.append(f"{kind}$.spec.previousEventDigest: failed validation")

    return errors


def orchestration_contract_errors(document: Any) -> list[str]:
    """Return stable validation failures without echoing untrusted values."""

    if not isinstance(document, dict):
        return ["record$: has the wrong type"]
    kind = document.get("kind")
    if not isinstance(kind, str) or kind not in ORCHESTRATION_SCHEMA_BY_KIND:
        return ["record$.kind: is not a supported orchestration record kind"]
    validator = Draft202012Validator(
        _load_schema(kind),
        registry=_schema_registry(),
        format_checker=_FORMAT_CHECKER,
    )
    failures = sorted(
        validator.iter_errors(document),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    structural = [
        f"{kind}{_json_path(error.absolute_path)}: {_sanitized_message(error.validator)}"
        for error in failures
    ]
    if structural:
        return structural
    return _semantic_errors(kind, document)


def validate_orchestration_record(document: Any) -> dict[str, Any]:
    errors = orchestration_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return document


def _record_bindings(value: Any, path: str = "$") -> Iterable[tuple[str, dict[str, str]]]:
    if isinstance(value, dict):
        if set(value) == {"kind", "id", "digest"}:
            yield path, value
            return
        for name in sorted(value):
            yield from _record_bindings(value[name], f"{path}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _record_bindings(item, f"{path}[{index}]")


def orchestration_record_set_errors(records: Any) -> list[str]:
    """Validate one complete, closed M6.1 same-namespace evidence graph.

    Individual records and streaming prefixes use ``orchestration_contract_errors``;
    this entry point deliberately requires the terminal graph and exact roots.
    """

    if not isinstance(records, list):
        return ["records$: has the wrong type"]
    errors: list[str] = []
    valid: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        item_errors = orchestration_contract_errors(record)
        if item_errors:
            errors.append(f"records$[{index}]: failed validation")
        else:
            valid.append(record)
    if errors:
        return errors

    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    digests: set[str] = set()
    for index, record in enumerate(valid):
        key = (record["kind"], record["metadata"]["id"])
        digest = record["metadata"]["recordDigest"]
        if key in by_key or digest in digests:
            errors.append(f"records$[{index}]: failed validation")
        by_key[key] = record
        digests.add(digest)
    if errors:
        return errors

    exact_counts = {
        "RoleProfile": 5,
        "TeamManifest": 1,
        "LoopDefinition": 1,
        "SourceBundle": 1,
        "TeamRunRequest": 1,
        "TeamRunPlan": 1,
        "RouteDecision": 7,
        "TeamRunResult": 1,
    }
    counts = {
        kind: sum(record["kind"] == kind for record in valid)
        for kind in ORCHESTRATION_SCHEMA_BY_KIND
    }
    for kind, expected in exact_counts.items():
        if counts[kind] != expected:
            errors.append(f"records$.{kind}: failed validation")
    if counts["OrchestrationEvent"] < 1:
        errors.append("records$.OrchestrationEvent: failed validation")
    profiles = [record for record in valid if record["kind"] == "RoleProfile"]
    if len(profiles) == 5 and tuple(sorted(item["spec"]["roleId"] for item in profiles)) != tuple(sorted(_ROLE_ORDER)):
        errors.append("records$.RoleProfile: failed validation")
    if errors:
        return errors

    run_namespaces = {
        (
            record["metadata"]["projectId"],
            record["metadata"]["teamId"],
            record["metadata"]["runId"],
        )
        for record in valid
        if record["kind"] not in _DEFINITION_KINDS
    }
    if len(run_namespaces) > 1:
        errors.append("records$: failed validation")
    if run_namespaces:
        project_id, team_id, _ = next(iter(run_namespaces))
        if any(
            record["metadata"]["projectId"] != project_id
            or record["metadata"]["teamId"] != team_id
            for record in valid
        ):
            errors.append("records$: failed validation")

    for index, record in enumerate(valid):
        for path, binding in _record_bindings(record):
            target = by_key.get((binding["kind"], binding["id"]))
            if target is None or target["metadata"]["recordDigest"] != binding["digest"]:
                errors.append(f"records$[{index}]{path[1:]}: failed validation")
    if errors:
        return errors

    def target(binding: dict[str, str]) -> dict[str, Any] | None:
        return by_key.get((binding["kind"], binding["id"]))

    for team in (record for record in valid if record["kind"] == "TeamManifest"):
        for index, role in enumerate(team["spec"]["roles"]):
            profile = target(role["profile"])
            if profile is None or profile["spec"]["roleId"] != role["roleId"]:
                errors.append(f"TeamManifest$.spec.roles[{index}].profile: failed validation")

    for loop in (record for record in valid if record["kind"] == "LoopDefinition"):
        team = target(loop["spec"]["teamManifest"])
        if (
            team is None
            or team["spec"]["gate"]["rubric"]["contentDigest"]
            != loop["spec"]["gate"]["rubricDigest"]
        ):
            errors.append("LoopDefinition$.spec.gate.rubricDigest: failed validation")

    plans = [record for record in valid if record["kind"] == "TeamRunPlan"]
    if len(plans) == 1:
        plan = plans[0]
        plan_id = plan["metadata"]["id"]
        plan_digest = plan["metadata"]["recordDigest"]
        request = target(plan["spec"]["request"])
        loop = target(plan["spec"]["loopDefinition"])
        team = target(plan["spec"]["teamManifest"])
        if request is None or (
            request["spec"]["sourceBundle"] != plan["spec"]["sourceBundle"]
            or request["spec"]["teamManifest"] != plan["spec"]["teamManifest"]
            or request["spec"]["loopDefinition"] != plan["spec"]["loopDefinition"]
            or request["spec"]["policySnapshotDigest"] != plan["spec"]["policySnapshotDigest"]
            or not _budget_fits(plan["spec"]["aggregateBudget"], request["spec"]["budget"])
            or _parse_timestamp(plan["spec"]["deadlineAt"])
            > _parse_timestamp(request["spec"]["deadlineAt"])
        ):
            errors.append("TeamRunPlan$.spec.request: failed validation")
        if loop is None or (
            not _budget_fits(plan["spec"]["aggregateBudget"], loop["spec"]["budget"])
            or plan["spec"]["gate"]["rubricDigest"]
            != loop["spec"]["gate"]["rubricDigest"]
        ):
            errors.append("TeamRunPlan$.spec.loopDefinition: failed validation")
        if team is None or (
            plan["spec"]["gate"]["rubricDigest"]
            != team["spec"]["gate"]["rubric"]["contentDigest"]
        ):
            errors.append("TeamRunPlan$.spec.teamManifest: failed validation")
        for index, step in enumerate(plan["spec"]["steps"]):
            profile = target(step["profile"])
            if profile is None or profile["spec"]["roleId"] != step["roleId"]:
                errors.append(f"TeamRunPlan$.spec.steps[{index}].profile: failed validation")
        route_by_slot = {
            (record["spec"]["roleId"], record["spec"]["attempt"]): record
            for record in valid
            if record["kind"] == "RouteDecision"
        }
        if len(route_by_slot) != 7:
            errors.append("RouteDecision$.spec.attempt: failed validation")
        for step_index, step in enumerate(plan["spec"]["steps"]):
            for route_index, planned_route in enumerate(step["routes"]):
                route = route_by_slot.get((step["roleId"], planned_route["attempt"]))
                if (
                    route is None
                    or route["metadata"]["id"] != planned_route["decisionId"]
                    or route["spec"]["routeDigest"] != planned_route["routeDigest"]
                ):
                    errors.append(
                        f"TeamRunPlan$.spec.steps[{step_index}].routes[{route_index}]: failed validation"
                    )
        for record in valid:
            spec = record.get("spec", {})
            if "planId" in spec and (
                spec["planId"] != plan_id or spec["planDigest"] != plan_digest
            ):
                errors.append(f"{record['kind']}$.spec.planDigest: failed validation")

        usage_to_budget = {
            "durationSeconds": "maxDurationSeconds",
            "attempts": "maxAttempts",
            "modelRequests": "maxModelRequests",
            "inputBytes": "maxInputBytes",
            "outputBytes": "maxOutputBytes",
            "totalTokens": "maxTotalTokens",
            "costMicrousd": "maxCostMicrousd",
        }
        step_by_role = {item["roleId"]: item for item in plan["spec"]["steps"]}
        attempts = [record for record in valid if record["kind"] == "RoleAttemptResult"]
        attempt_by_slot = {
            (item["spec"]["roleId"], item["spec"]["attempt"]): item
            for item in attempts
        }
        if len(attempt_by_slot) != len(attempts):
            errors.append("RoleAttemptResult$.spec.attempt: failed validation")
        for attempt in attempts:
            route = target(attempt["spec"]["routeDecision"])
            step = step_by_role[attempt["spec"]["roleId"]]
            if route is None or (
                route["spec"]["roleId"] != attempt["spec"]["roleId"]
                or route["spec"]["attempt"] != attempt["spec"]["attempt"]
                or route["spec"]["decision"] != "allowed"
            ):
                errors.append("RoleAttemptResult$.spec.routeDecision: failed validation")
            if any(
                attempt["spec"]["usage"][usage_name] > step["budget"][budget_name]
                for usage_name, budget_name in usage_to_budget.items()
            ):
                errors.append("RoleAttemptResult$.spec.usage: failed validation")

        for handoff in (record for record in valid if record["kind"] == "HandoffRecord"):
            attempt = target(handoff["spec"]["roleAttemptResult"])
            _, from_role, from_attempt, _, _ = _HANDOFF_SLOTS[handoff["spec"]["ordinal"] - 1]
            if attempt is None or (
                attempt["spec"]["roleId"] != handoff["spec"]["fromRoleId"]
                or attempt["spec"]["roleId"] != from_role
                or attempt["spec"]["attempt"] != from_attempt
            ):
                errors.append("HandoffRecord$.spec.roleAttemptResult: failed validation")

        synth_attempts = [
            item for item in attempts
            if item["spec"]["roleId"] == "synthesizer" and item["spec"]["status"] == "succeeded"
        ]
        for review in (record for record in valid if record["kind"] == "ReviewRecord"):
            reviewer_attempt = target(review["spec"]["reviewerAttempt"])
            expected_attempt = review["spec"]["cycle"] + 1
            if (
                reviewer_attempt is None
                or reviewer_attempt["spec"]["roleId"] != "reviewer"
                or reviewer_attempt["spec"]["attempt"] != expected_attempt
                or reviewer_attempt["spec"]["status"] != "succeeded"
                or not any(
                    item["spec"]["attempt"] == expected_attempt
                    and item["spec"]["output"] == review["spec"]["subject"]
                    for item in synth_attempts
                )
                or review["spec"]["rubricDigest"]
                != plan["spec"]["gate"]["rubricDigest"]
            ):
                errors.append("ReviewRecord$.spec: failed validation")

    bundles = [record for record in valid if record["kind"] == "SourceBundle"]
    if len(bundles) == 1:
        entries_by_id = {
            item["id"]: item for item in bundles[0]["spec"]["entries"]
        }
        claim_ids = {
            record["metadata"]["id"]
            for record in valid
            if record["kind"] == "ClaimRecord"
        }
        for record in valid:
            if record["kind"] == "EvidenceRecord":
                source_entry = entries_by_id.get(record["spec"]["sourceEntryId"])
                if (
                    source_entry is None
                    or record["spec"]["provenanceDigest"]
                    != source_entry["provenance"]["provenanceDigest"]
                    or any(item not in claim_ids for item in record["spec"]["claimIds"])
                ):
                    errors.append("EvidenceRecord$.spec: failed validation")

    verifications_by_claim: dict[str, list[dict[str, Any]]] = {}
    for verification in (record for record in valid if record["kind"] == "VerificationRecord"):
        claim = target(verification["spec"]["claim"])
        evidence_records = [target(item) for item in verification["spec"]["evidence"]]
        if claim is not None:
            verifications_by_claim.setdefault(claim["metadata"]["id"], []).append(
                verification
            )
        if (
            claim is None
            or verification["spec"]["rubricDigest"]
            != plan["spec"]["gate"]["rubricDigest"]
            or any(
                claim["metadata"]["id"] not in item["spec"]["claimIds"]
                for item in evidence_records
                if item is not None
            )
        ):
            errors.append("VerificationRecord$.spec.evidence: failed validation")
        if verification["spec"]["status"] == "verified" and (
            not any(
                item is not None and item["spec"]["relation"] == "supports"
                for item in evidence_records
            )
            or any(
                item is not None and item["spec"]["relation"] == "contradicts"
                for item in evidence_records
            )
        ):
            errors.append("VerificationRecord$.spec.status: failed validation")
    if any(len(items) != 1 for items in verifications_by_claim.values()):
        errors.append("VerificationRecord$.spec.claim: failed validation")

    terminal_event_types = {
        "succeeded": "run-succeeded",
        "incomplete": "run-incomplete",
        "failed": "run-failed",
        "denied": "run-denied",
        "exhausted": "run-exhausted",
        "cancelled": "run-cancelled",
    }
    for result in (record for record in valid if record["kind"] == "TeamRunResult"):
        result_spec = result["spec"]
        event = target(result_spec["terminalEvent"])
        if event is None or (
            event["spec"]["eventType"] != terminal_event_types[result_spec["status"]]
            or event["spec"]["reasonCode"] != result_spec["reasonCode"]
            or event["spec"]["subject"] != result_spec["plan"]
        ):
            errors.append("TeamRunResult$.spec.terminalEvent: failed validation")

        inventory_fields = {
            "roleAttempts": "RoleAttemptResult",
            "handoffs": "HandoffRecord",
            "reviews": "ReviewRecord",
            "claims": "ClaimRecord",
            "evidence": "EvidenceRecord",
            "verifications": "VerificationRecord",
        }
        for field, record_kind in inventory_fields.items():
            inventory = {
                (item["kind"], item["metadata"]["id"], item["metadata"]["recordDigest"])
                for item in valid
                if item["kind"] == record_kind
            }
            references = {
                (item["kind"], item["id"], item["digest"])
                for item in result_spec[field]
            }
            if inventory != references or len(references) != len(result_spec[field]):
                errors.append(f"TeamRunResult$.spec.{field}: failed validation")

        execution_route_bindings = [
            {
                "kind": "RouteDecision",
                "id": route_by_slot[slot]["metadata"]["id"],
                "digest": route_by_slot[slot]["metadata"]["recordDigest"],
            }
            for slot in _EXECUTION_SLOTS
        ]
        if result_spec["routeDecisions"] != execution_route_bindings[: len(result_spec["routeDecisions"])]:
            errors.append("TeamRunResult$.spec.routeDecisions: failed validation")

        referenced_attempts = [target(item) for item in result_spec["roleAttempts"]]
        if event is not None and any(
            _parse_timestamp(event["spec"]["occurredAt"])
            < _parse_timestamp(item["spec"]["finishedAt"])
            for item in referenced_attempts
            if item is not None
        ):
            errors.append("TeamRunResult$.spec.terminalEvent: failed validation")
        observed_attempt_slots = [
            (item["spec"]["roleId"], item["spec"]["attempt"])
            for item in referenced_attempts
            if item is not None
        ]
        if observed_attempt_slots != list(_EXECUTION_SLOTS[: len(observed_attempt_slots)]):
            errors.append("TeamRunResult$.spec.roleAttempts: failed validation")
        if len(result_spec["routeDecisions"]) not in {
            len(result_spec["roleAttempts"]),
            len(result_spec["roleAttempts"]) + 1,
        }:
            errors.append("TeamRunResult$.spec.routeDecisions: failed validation")

        referenced_handoffs = [target(item) for item in result_spec["handoffs"]]
        if [
            item["spec"]["ordinal"] for item in referenced_handoffs if item is not None
        ] != list(range(1, len(referenced_handoffs) + 1)):
            errors.append("TeamRunResult$.spec.handoffs: failed validation")
        if len(referenced_handoffs) > min(len(referenced_attempts), 6):
            errors.append("TeamRunResult$.spec.handoffs: failed validation")

        referenced_reviews = [target(item) for item in result_spec["reviews"]]
        if [item["spec"]["cycle"] for item in referenced_reviews if item is not None] != list(
            range(len(referenced_reviews))
        ):
            errors.append("TeamRunResult$.spec.reviews: failed validation")
        if len(referenced_reviews) == 2 and referenced_reviews[0]["spec"]["verdict"] != "revision-required":
            errors.append("TeamRunResult$.spec.reviews: failed validation")
        if (
            len(result_spec["roleAttempts"]) > 5
            or len(result_spec["routeDecisions"]) > 5
            or len(result_spec["handoffs"]) > 4
        ) and (
            not referenced_reviews
            or referenced_reviews[0]["spec"]["verdict"] != "revision-required"
        ):
            errors.append("TeamRunResult$.spec.reviews: failed validation")

        aggregate_usage = {
            name: sum(item["spec"]["usage"][name] for item in referenced_attempts if item is not None)
            for name in result_spec["usage"]
        }
        if result_spec["usage"] != aggregate_usage or any(
            result_spec["usage"][usage_name] > plan["spec"]["aggregateBudget"][budget_name]
            for usage_name, budget_name in usage_to_budget.items()
        ):
            errors.append("TeamRunResult$.spec.usage: failed validation")

        latest_synthesis = next(
            (
                item["spec"]["output"]
                for item in reversed(referenced_attempts)
                if item is not None
                and item["spec"]["roleId"] == "synthesizer"
                and item["spec"]["status"] == "succeeded"
            ),
            None,
        )
        if result_spec["finalReport"] is not None and result_spec["finalReport"] != latest_synthesis:
            errors.append("TeamRunResult$.spec.finalReport: failed validation")

        history_shape = (
            len(result_spec["routeDecisions"]),
            len(result_spec["roleAttempts"]),
            len(result_spec["handoffs"]),
            len(result_spec["reviews"]),
        )
        if result_spec["status"] == "succeeded":
            result_claims = {item["id"]: item for item in result_spec["claims"]}
            result_verifications = [
                target(item) for item in result_spec["verifications"]
            ]
            verification_counts: dict[str, int] = {}
            verified_claims: set[str] = set()
            for verification in result_verifications:
                if verification is None:
                    continue
                claim_id = verification["spec"]["claim"]["id"]
                verification_counts[claim_id] = verification_counts.get(claim_id, 0) + 1
                if verification["spec"]["status"] == "verified":
                    verified_claims.add(claim_id)
            accepted_cycle_zero = (
                history_shape == (5, 5, 4, 1)
                and referenced_reviews[0]["spec"]["verdict"] == "accepted"
            )
            accepted_cycle_one = (
                history_shape == (7, 7, 6, 2)
                and referenced_reviews[0]["spec"]["verdict"] == "revision-required"
                and referenced_reviews[1]["spec"]["verdict"] == "accepted"
            )
            final_review = referenced_reviews[-1] if referenced_reviews else None
            if (
                result_spec["reasonCode"] != "accepted"
                or not (accepted_cycle_zero or accepted_cycle_one)
                or any(item["spec"]["status"] != "succeeded" for item in referenced_attempts)
                or any(item["spec"]["status"] != "ready" for item in referenced_handoffs)
                or final_review is None
                or final_review["spec"]["subject"] != result_spec["finalReport"]
                or not result_claims
                or not result_spec["evidence"]
                or not result_spec["verifications"]
                or set(result_claims) != set(verification_counts)
                or any(count != 1 for count in verification_counts.values())
                or set(result_claims) != verified_claims
            ):
                errors.append("TeamRunResult$.spec.status: failed validation")
        elif result_spec["reasonCode"] == "accepted":
            errors.append("TeamRunResult$.spec.reasonCode: failed validation")

        if result_spec["reasonCode"] in {"revision-exhausted", "no-progress"}:
            reports = [
                item["spec"]["output"]
                for item in referenced_attempts
                if item is not None and item["spec"]["roleId"] == "synthesizer"
            ]
            same_report = len(reports) == 2 and reports[0] == reports[1]
            if (
                result_spec["status"] != "exhausted"
                or history_shape != (7, 7, 6, 2)
                or any(item["spec"]["status"] != "succeeded" for item in referenced_attempts)
                or any(item["spec"]["status"] != "ready" for item in referenced_handoffs)
                or any(item["spec"]["verdict"] != "revision-required" for item in referenced_reviews)
                or (result_spec["reasonCode"] == "no-progress") != same_report
            ):
                errors.append("TeamRunResult$.spec.reasonCode: failed validation")

    events = sorted(
        (record for record in valid if record["kind"] == "OrchestrationEvent"),
        key=lambda item: item["spec"]["sequence"],
    )
    if events:
        if [item["spec"]["sequence"] for item in events] != list(range(1, len(events) + 1)):
            errors.append("OrchestrationEvent$.spec.sequence: failed validation")
        for previous, current in zip(events, events[1:]):
            if current["spec"]["previousEventDigest"] != previous["metadata"]["recordDigest"]:
                errors.append("OrchestrationEvent$.spec.previousEventDigest: failed validation")
        terminal_types = {
            "run-succeeded", "run-incomplete", "run-failed", "run-denied",
            "run-exhausted", "run-cancelled",
        }
        terminal_events = [item for item in events if item["spec"]["eventType"] in terminal_types]
        result = next(item for item in valid if item["kind"] == "TeamRunResult")
        terminal = target(result["spec"]["terminalEvent"])
        if len(terminal_events) != 1 or terminal is not events[-1]:
            errors.append("OrchestrationEvent$.spec.eventType: failed validation")
    return errors


def validate_orchestration_record_set(records: Any) -> list[dict[str, Any]]:
    errors = orchestration_record_set_errors(records)
    if errors:
        raise ContractValidationError(errors)
    return records
