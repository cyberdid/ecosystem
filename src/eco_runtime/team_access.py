from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .digests import semantic_digest
from .errors import ContractValidationError

TEAM_ACCESS_API_VERSION = "authority.ai.ecosystem/v1alpha1"
TEAM_ACCESS_PROFILE = "bounded-team-access-v1"
TEAM_ACCESS_SCHEMA = "team-access-policy.schema.json"

_ID = re.compile(r"^[a-z0-9][a-z0-9._:@-]{0,127}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FORMAT_CHECKER = FormatChecker()

ACTION_PROFILE: dict[str, tuple[str, str]] = {
    "identity.inspect": ("A0", "identity-record"),
    "policy.inspect": ("A0", "policy-record"),
    "model.invoke": ("A0", "deployment"),
    "run.plan": ("A0", "workflow"),
    "repository.read": ("A1", "repository-entry"),
    "run.activate": ("A1", "workflow"),
    "evaluation.run": ("A1", "workflow"),
    "repository.write": ("A2", "repository-entry"),
    "code.execute": ("A2", "project"),
    "external.write": ("A3", "external-service"),
    "production.change": ("A4", "production-target"),
}


@_FORMAT_CHECKER.checks("date-time")
def _date_time(value: object) -> bool:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").tzinfo is not None
    except ValueError:
        return False


def _schema() -> dict[str, Any]:
    source = resources.files("eco_runtime").joinpath("schemas", TEAM_ACCESS_SCHEMA)
    return json.loads(source.read_text(encoding="utf-8"))


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def team_access_policy_digest(policy: Mapping[str, Any]) -> str:
    projected = copy.deepcopy(dict(policy))
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest({"profile": "team-access-policy-record-v1", "record": projected})


def team_access_binding_id(
    principal: Mapping[str, Any], membership: Mapping[str, Any], role_id: str
) -> str:
    return "binding:" + semantic_digest(
        {
            "profile": "team-access-binding-id-v1",
            "principal": dict(principal),
            "membership": dict(membership),
            "roleId": role_id,
        }
    )


def _path(parts: Any) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _message(validator: str | None) -> str:
    return {
        "additionalProperties": "contains an unexpected property",
        "const": "does not match the required constant",
        "enum": "is not an allowed value",
        "format": "has an invalid format",
        "maxItems": "contains too many items",
        "minimum": "is below the allowed minimum",
        "minItems": "contains too few items",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "has the wrong type",
        "uniqueItems": "contains duplicate items",
    }.get(validator, "failed validation")


def team_access_contract_errors(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["TeamAccessPolicy$: has the wrong type"]
    structural = sorted(
        Draft202012Validator(_schema(), format_checker=_FORMAT_CHECKER).iter_errors(document),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    if structural:
        return [
            f"TeamAccessPolicy{_path(error.absolute_path)}: {_message(error.validator)}"
            for error in structural
        ]

    errors: list[str] = []
    if document["metadata"]["recordDigest"] != team_access_policy_digest(document):
        errors.append("TeamAccessPolicy$.metadata.recordDigest: failed validation")

    created = _parse_time(document["metadata"]["createdAt"])
    roles = document["spec"]["roles"]
    bindings = document["spec"]["bindings"]
    role_ids = [item["id"] for item in roles]
    binding_ids = [item["id"] for item in bindings]
    if role_ids != sorted(role_ids) or len(role_ids) != len(set(role_ids)):
        errors.append("TeamAccessPolicy$.spec.roles: failed validation")
    if binding_ids != sorted(binding_ids) or len(binding_ids) != len(set(binding_ids)):
        errors.append("TeamAccessPolicy$.spec.bindings: failed validation")

    role_set = set(role_ids)
    seen_actor_roles: set[tuple[str, str, str]] = set()
    for binding in bindings:
        expected_id = team_access_binding_id(
            binding["principal"], binding["membership"], binding["roleId"]
        )
        actor_role = (
            binding["principal"]["digest"],
            binding["membership"]["digest"],
            binding["roleId"],
        )
        if (
            binding["id"] != expected_id
            or binding["roleId"] not in role_set
            or actor_role in seen_actor_roles
        ):
            errors.append("TeamAccessPolicy$.spec.bindings: failed validation")
        seen_actor_roles.add(actor_role)

    for role_index, role in enumerate(roles):
        statements = role["statements"]
        statement_ids = [item["id"] for item in statements]
        if statement_ids != sorted(statement_ids) or len(statement_ids) != len(
            set(statement_ids)
        ):
            errors.append(
                f"TeamAccessPolicy$.spec.roles[{role_index}].statements: failed validation"
            )
        for statement_index, statement in enumerate(statements):
            expected_action_class, expected_resource_kind = ACTION_PROFILE[
                statement["action"]
            ]
            constraints = statement["constraints"]
            not_before = _parse_time(constraints["notBefore"])
            not_after = _parse_time(constraints["notAfter"])
            invalid = (
                statement["actionClass"] != expected_action_class
                or statement["resource"]["kind"] != expected_resource_kind
                or not not_before < not_after
                or created >= not_after
                or constraints["dataClasses"] != sorted(constraints["dataClasses"])
                or (
                    statement["effect"] == "allow"
                    and statement["actionClass"] == "A2"
                    and statement["approvalProfile"] is None
                )
                or (
                    (statement["effect"] != "allow"
                    or statement["actionClass"] != "A2")
                    and statement["approvalProfile"] is not None
                )
                or (
                    statement["effect"] == "allow"
                    and (
                        statement["actionClass"] in {"A3", "A4"}
                        or "D4" in constraints["dataClasses"]
                    )
                )
            )
            if invalid:
                errors.append(
                    "TeamAccessPolicy$.spec.roles"
                    f"[{role_index}].statements[{statement_index}]: failed validation"
                )
    return errors


def validate_team_access_policy(document: Any) -> dict[str, Any]:
    errors = team_access_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return document


@dataclass(frozen=True, slots=True)
class TeamAccessDecision:
    team_effect: str
    code: str
    policy_digest: str
    request_digest: str
    actor_binding_digest: str
    matched_statement_digests: tuple[str, ...] = field(default_factory=tuple)
    approval_profile_id: str | None = None
    approval_profile_digest: str | None = None
    narrowing_only: bool = field(default=True, init=False)
    effective_authorization: bool = field(default=False, init=False)
    runtime_authority_created: bool = field(default=False, init=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "teamEffect": self.team_effect,
            "code": self.code,
            "policyDigest": self.policy_digest,
            "requestDigest": self.request_digest,
            "actorBindingDigest": self.actor_binding_digest,
            "matchedStatementDigests": list(self.matched_statement_digests),
            "approvalProfileId": self.approval_profile_id,
            "approvalProfileDigest": self.approval_profile_digest,
            "narrowingOnly": self.narrowing_only,
            "effectiveAuthorization": self.effective_authorization,
            "runtimeAuthorityCreated": self.runtime_authority_created,
        }


def _exact_binding(value: object, kind: str) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"kind", "id", "digest"}
        and value.get("kind") == kind
        and isinstance(value.get("id"), str)
        and _ID.fullmatch(value["id"]) is not None
        and isinstance(value.get("digest"), str)
        and _DIGEST.fullmatch(value["digest"]) is not None
    )


def _decision(
    *, effect: str, code: str, policy_digest: str, request_digest: str,
    actor_digest: str, matches: tuple[str, ...] = (),
    approval_profile: Mapping[str, Any] | None = None,
) -> TeamAccessDecision:
    return TeamAccessDecision(
        team_effect=effect,
        code=code,
        policy_digest=policy_digest,
        request_digest=request_digest,
        actor_binding_digest=actor_digest,
        matched_statement_digests=matches,
        approval_profile_id=(
            approval_profile["id"] if approval_profile is not None else None
        ),
        approval_profile_digest=(
            approval_profile["digest"] if approval_profile is not None else None
        ),
    )


def evaluate_team_access(
    policy: Mapping[str, Any], request: Mapping[str, Any], *, now: datetime
) -> TeamAccessDecision:
    """Evaluate one narrowing team gate; an allow is never final runtime authority."""

    validated = validate_team_access_policy(copy.deepcopy(dict(policy)))
    policy_digest = validated["metadata"]["recordDigest"]
    invalid_digest = semantic_digest({"profile": "team-access-invalid-request-v1"})
    if not isinstance(now, datetime) or now.tzinfo is None:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_TIME_INVALID",
                         policy_digest=policy_digest, request_digest=invalid_digest,
                         actor_digest=invalid_digest)
    observed = now.astimezone(timezone.utc)
    if not isinstance(request, Mapping):
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_REQUEST_INVALID",
                         policy_digest=policy_digest, request_digest=invalid_digest,
                         actor_digest=invalid_digest)
    candidate = copy.deepcopy(dict(request))
    required = {"principal", "membership", "action", "actionClass", "resource",
                "projectId", "environmentId", "dataClass"}
    valid_request = (
        set(candidate) == required
        and _exact_binding(candidate.get("principal"), "PrincipalIdentity")
        and _exact_binding(candidate.get("membership"), "MembershipBinding")
        and isinstance(candidate.get("action"), str)
        and candidate["action"] in ACTION_PROFILE
        and candidate.get("actionClass") in {"A0", "A1", "A2", "A3", "A4"}
        and isinstance(candidate.get("resource"), dict)
        and set(candidate["resource"]) == {"kind", "id", "digest"}
        and isinstance(candidate["resource"].get("kind"), str)
        and isinstance(candidate["resource"].get("id"), str)
        and _ID.fullmatch(candidate["resource"]["id"]) is not None
        and isinstance(candidate["resource"].get("digest"), str)
        and _DIGEST.fullmatch(candidate["resource"]["digest"]) is not None
        and isinstance(candidate.get("projectId"), str)
        and _ID.fullmatch(candidate["projectId"]) is not None
        and isinstance(candidate.get("environmentId"), str)
        and _ID.fullmatch(candidate["environmentId"]) is not None
        and candidate.get("dataClass") in {"D0", "D1", "D2", "D3", "D4"}
    )
    if not valid_request:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_REQUEST_INVALID",
                         policy_digest=policy_digest, request_digest=invalid_digest,
                         actor_digest=invalid_digest)

    request_digest = semantic_digest({"profile": "team-access-request-v1", "request": candidate})
    actor_digest = semantic_digest({"profile": "team-access-actor-binding-v1",
                                    "principal": candidate["principal"],
                                    "membership": candidate["membership"]})
    expected_class, expected_resource = ACTION_PROFILE[candidate["action"]]
    if candidate["actionClass"] != expected_class or candidate["resource"]["kind"] != expected_resource:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_REQUEST_MISMATCH",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest)
    if candidate["actionClass"] in {"A3", "A4"}:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_HIGH_IMPACT_DENIED",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest)
    if candidate["dataClass"] == "D4":
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_D4_DENIED",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest)

    roles = {item["id"]: item for item in validated["spec"]["roles"]}
    assigned_role_ids = {
        item["roleId"] for item in validated["spec"]["bindings"]
        if item["principal"] == candidate["principal"]
        and item["membership"] == candidate["membership"]
    }
    if not assigned_role_ids:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_ACTOR_UNBOUND",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest)

    matches: list[tuple[str, str, Mapping[str, Any] | None]] = []
    for role_id in sorted(assigned_role_ids):
        for statement in roles[role_id]["statements"]:
            constraints = statement["constraints"]
            if (
                statement["action"] == candidate["action"]
                and statement["actionClass"] == candidate["actionClass"]
                and statement["resource"] == candidate["resource"]
                and constraints["projectId"] == candidate["projectId"]
                and constraints["environmentId"] == candidate["environmentId"]
                and candidate["dataClass"] in constraints["dataClasses"]
                and _parse_time(constraints["notBefore"]) <= observed < _parse_time(constraints["notAfter"])
            ):
                digest = semantic_digest({"profile": "team-access-statement-v1",
                                          "roleId": role_id, "statement": statement})
                matches.append(
                    (statement["effect"], digest, statement["approvalProfile"])
                )

    denies = tuple(sorted(item[1] for item in matches if item[0] == "deny"))
    if denies:
        return _decision(effect="deny", code="ECO_TEAM_ACCESS_EXPLICIT_DENY",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest, matches=denies)
    allows = tuple(sorted(item[1] for item in matches if item[0] == "allow"))
    if allows:
        approval_profiles = {
            (item[2]["id"], item[2]["digest"])
            for item in matches
            if item[0] == "allow" and item[2] is not None
        }
        if candidate["actionClass"] == "A2" and len(approval_profiles) != 1:
            return _decision(
                effect="deny",
                code="ECO_TEAM_ACCESS_APPROVAL_AMBIGUOUS",
                policy_digest=policy_digest,
                request_digest=request_digest,
                actor_digest=actor_digest,
                matches=allows,
            )
        selected_profile = (
            next(
                item[2]
                for item in matches
                if item[0] == "allow" and item[2] is not None
            )
            if approval_profiles
            else None
        )
        return _decision(effect="allow", code="ECO_TEAM_ACCESS_ALLOW_CANDIDATE",
                         policy_digest=policy_digest, request_digest=request_digest,
                         actor_digest=actor_digest, matches=allows,
                         approval_profile=selected_profile)
    return _decision(effect="deny", code="ECO_TEAM_ACCESS_DEFAULT_DENY",
                     policy_digest=policy_digest, request_digest=request_digest,
                     actor_digest=actor_digest)
