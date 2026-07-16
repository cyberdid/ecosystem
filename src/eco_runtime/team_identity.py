from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from .digests import semantic_digest
from .errors import ContractValidationError

AUTHORITY_API_VERSION = "authority.ai.ecosystem/v1alpha1"
AUTHORITY_CONTRACT_PROFILE = "team-authority-contracts-v1alpha1"
AUTHORITY_SCHEMA_BY_KIND = {
    "PrincipalIdentity": "principal-identity.schema.json",
    "TeamIdentity": "team-identity.schema.json",
    "MembershipBinding": "membership-binding.schema.json",
    "IdentityKey": "identity-key.schema.json",
    "TeamAccessPolicy": "team-access-policy.schema.json",
    "ApprovalProfile": "team-approval.schema.json",
    "TeamPolicyBundle": "team-policy-bundle.schema.json",
}

_CANONICAL_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _is_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _load_schema(kind: str) -> dict[str, Any]:
    source = resources.files("eco_runtime").joinpath(
        "schemas", AUTHORITY_SCHEMA_BY_KIND[kind]
    )
    return json.loads(source.read_text(encoding="utf-8"))


def _schema_registry() -> Registry:
    registry = Registry()
    for kind in AUTHORITY_SCHEMA_BY_KIND:
        schema = _load_schema(kind)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def authority_schema_bundle_digest() -> str:
    return semantic_digest(
        {
            "profile": AUTHORITY_CONTRACT_PROFILE,
            "records": {
                kind: _load_schema(kind) for kind in sorted(AUTHORITY_SCHEMA_BY_KIND)
            },
        }
    )


def authority_record_digest(record: dict[str, Any]) -> str:
    """Digest an authority record while excluding its self-describing digest field."""

    projected = copy.deepcopy(record)
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {"profile": "team-authority-record-v1", "record": projected}
    )


def membership_binding_id(team_id: str, principal_id: str) -> str:
    digest = semantic_digest(
        {
            "profile": "team-membership-id-v1",
            "teamId": team_id,
            "principalId": principal_id,
        }
    )
    return f"membership:{digest}"


def identity_key_fingerprint(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def identity_key_id(public_key: bytes) -> str:
    return f"ed25519:{identity_key_fingerprint(public_key)}"


def approval_policy_context_digest(
    *,
    bundle_id: str,
    bundle_revision: int,
    team: Mapping[str, Any],
    target_project_ids: list[str],
    access_policy_id: str,
    access_policy_revision: int,
) -> str:
    """Bind approvals to one signed bundle context without a digest cycle."""

    return semantic_digest(
        {
            "domain": "eco-team-approval-policy-context-v1",
            "bundleId": bundle_id,
            "bundleRevision": bundle_revision,
            "team": dict(team),
            "targetProjectIds": list(target_project_ids),
            "accessPolicyId": access_policy_id,
            "accessPolicyRevision": access_policy_revision,
        }
    )


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_base64url(value: str, *, expected_bytes: int) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("invalid base64url value")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc
    if len(raw) != expected_bytes or _encode_base64url(raw) != value:
        raise ValueError("invalid base64url value")
    return raw


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
        "oneOf": "does not match exactly one allowed shape",
        "pattern": "does not match the required pattern",
        "required": "is missing a required property",
        "type": "has the wrong type",
        "uniqueItems": "contains duplicate items",
    }
    return messages.get(validator, "failed validation")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _validity_errors(kind: str, document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    created_at = document["metadata"]["createdAt"]
    validity = document["spec"]["validity"]
    timestamp_fields = {
        f"{kind}$.metadata.createdAt": created_at,
        f"{kind}$.spec.validity.notBefore": validity["notBefore"],
        f"{kind}$.spec.validity.notAfter": validity["notAfter"],
    }
    if any(not _CANONICAL_TIMESTAMP.fullmatch(value) for value in timestamp_fields.values()):
        return [
            f"{path}: is not a canonical UTC timestamp"
            for path, value in timestamp_fields.items()
            if not _CANONICAL_TIMESTAMP.fullmatch(value)
        ]
    created = _parse_timestamp(created_at)
    not_before = _parse_timestamp(validity["notBefore"])
    not_after = _parse_timestamp(validity["notAfter"])
    if not not_before < not_after:
        errors.append(f"{kind}$.spec.validity: failed validation")
    if not not_before <= created < not_after:
        errors.append(f"{kind}$.metadata.createdAt: failed validation")
    return errors


def _base_semantic_errors(kind: str, document: dict[str, Any]) -> list[str]:
    errors = _validity_errors(kind, document)
    if document["metadata"]["recordDigest"] != authority_record_digest(document):
        errors.append(f"{kind}$.metadata.recordDigest: failed validation")
    return errors


def _identity_semantic_errors(kind: str, document: dict[str, Any]) -> list[str]:
    errors = _base_semantic_errors(kind, document)
    if kind == "PrincipalIdentity":
        principal_type = document["spec"]["type"]
        controller = document["spec"]["controller"]
        if (principal_type == "human") != (controller is None):
            errors.append(f"{kind}$.spec.controller: failed validation")
        if controller is not None and controller["id"] == document["metadata"]["id"]:
            errors.append(f"{kind}$.spec.controller: failed validation")
    return errors


def _key_semantic_errors(document: dict[str, Any]) -> list[str]:
    kind = "IdentityKey"
    errors = _base_semantic_errors(kind, document)
    try:
        public_key = decode_base64url(
            document["spec"]["publicKey"]["value"], expected_bytes=32
        )
    except ValueError:
        return errors + [f"{kind}$.spec.publicKey.value: failed validation"]
    expected_fingerprint = identity_key_fingerprint(public_key)
    if document["spec"]["fingerprint"]["digest"] != expected_fingerprint:
        errors.append(f"{kind}$.spec.fingerprint.digest: failed validation")
    if document["metadata"]["id"] != f"ed25519:{expected_fingerprint}":
        errors.append(f"{kind}$.metadata.id: failed validation")
    return errors


def _membership_semantic_errors(document: dict[str, Any]) -> list[str]:
    kind = "MembershipBinding"
    errors = _base_semantic_errors(kind, document)
    expected = membership_binding_id(
        document["spec"]["team"]["id"], document["spec"]["principal"]["id"]
    )
    if document["metadata"]["id"] != expected:
        errors.append(f"{kind}$.metadata.id: failed validation")
    return errors


def _binding_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        record["kind"],
        record["metadata"]["id"],
        record["metadata"]["recordDigest"],
    )


def _binding_tuple(binding: dict[str, Any]) -> tuple[str, str, str]:
    return binding["kind"], binding["id"], binding["digest"]


def _contains_validity(parent: dict[str, str], child: dict[str, str]) -> bool:
    return (
        _parse_timestamp(child["notBefore"]) <= _parse_timestamp(parent["notBefore"])
        and _parse_timestamp(parent["notAfter"]) <= _parse_timestamp(child["notAfter"])
    )


def _policy_semantic_errors(document: dict[str, Any]) -> list[str]:
    kind = "TeamPolicyBundle"
    errors = _base_semantic_errors(kind, document)
    metadata = document["metadata"]
    spec = document["spec"]
    previous = spec["previous"]
    if metadata["revision"] == 1:
        if previous is not None:
            errors.append(f"{kind}$.spec.previous: failed validation")
    elif previous is None or previous["revision"] != metadata["revision"] - 1:
        errors.append(f"{kind}$.spec.previous: failed validation")
    if spec["targetProjectIds"] != sorted(spec["targetProjectIds"]):
        errors.append(f"{kind}$.spec.targetProjectIds: failed validation")

    expected_kinds = {
        "teams": "TeamIdentity",
        "principals": "PrincipalIdentity",
        "memberships": "MembershipBinding",
        "keys": "IdentityKey",
    }
    if "accessPolicies" in spec["documents"]:
        expected_kinds["accessPolicies"] = "TeamAccessPolicy"
    if "approvalProfiles" in spec["documents"]:
        expected_kinds["approvalProfiles"] = "ApprovalProfile"
    catalogs: dict[str, list[dict[str, Any]]] = spec["documents"]
    all_records: dict[tuple[str, str, str], dict[str, Any]] = {}
    validated_catalogs: dict[str, list[dict[str, Any]]] = {
        name: [] for name in expected_kinds
    }
    for catalog_name, expected_kind in expected_kinds.items():
        records = catalogs[catalog_name]
        ids = [item.get("metadata", {}).get("id") for item in records]
        if (
            any(not isinstance(item, str) for item in ids)
            or ids != sorted(ids)
            or len(ids) != len(set(ids))
        ):
            errors.append(f"{kind}$.spec.documents.{catalog_name}: failed validation")
        for index, item in enumerate(records):
            if item.get("kind") != expected_kind:
                errors.append(
                    f"{kind}$.spec.documents.{catalog_name}[{index}]: failed validation"
                )
                continue
            nested_errors = authority_contract_errors(item)
            if nested_errors:
                errors.append(
                    f"{kind}$.spec.documents.{catalog_name}[{index}]: failed validation"
                )
                continue
            validated_catalogs[catalog_name].append(item)
            all_records[_binding_key(item)] = item

    team = all_records.get(_binding_tuple(spec["team"]))
    if team is None or team["spec"]["status"] != "active":
        errors.append(f"{kind}$.spec.team: failed validation")

    bundle_validity = spec["validity"]
    for record in all_records.values():
        record_validity = record["spec"].get("validity")
        if (
            record["kind"]
            in {"TeamIdentity", "PrincipalIdentity", "MembershipBinding", "IdentityKey"}
            and record_validity is not None
            and not _contains_validity(bundle_validity, record_validity)
        ):
            errors.append(f"{kind}$.spec.documents: failed validation")
            break

    for membership in validated_catalogs["memberships"]:
        team_record = all_records.get(_binding_tuple(membership["spec"]["team"]))
        principal = all_records.get(_binding_tuple(membership["spec"]["principal"]))
        if team_record is None or principal is None:
            errors.append(f"{kind}$.spec.documents.memberships: failed validation")
        elif membership["spec"]["status"] == "active" and (
            team_record["spec"]["status"] != "active"
            or principal["spec"]["status"] != "active"
            or not _contains_validity(
                membership["spec"]["validity"], team_record["spec"]["validity"]
            )
            or not _contains_validity(
                membership["spec"]["validity"], principal["spec"]["validity"]
            )
        ):
            errors.append(f"{kind}$.spec.documents.memberships: failed validation")

    for principal in validated_catalogs["principals"]:
        controller = principal.get("spec", {}).get("controller")
        if controller is not None:
            controller_record = all_records.get(_binding_tuple(controller))
            if controller_record is None or (
                principal["spec"]["status"] == "active"
                and (
                    controller_record["spec"]["status"] != "active"
                    or not _contains_validity(
                        principal["spec"]["validity"],
                        controller_record["spec"]["validity"],
                    )
                )
            ):
                errors.append(f"{kind}$.spec.documents.principals: failed validation")

    policy_signer_present = False
    for key in validated_catalogs["keys"]:
        subject = all_records.get(_binding_tuple(key["spec"]["subject"]))
        if subject is None:
            errors.append(f"{kind}$.spec.documents.keys: failed validation")
            continue
        if key["spec"]["status"] == "active" and (
            subject["spec"]["status"] != "active"
            or not _contains_validity(
                key["spec"]["validity"], subject["spec"]["validity"]
            )
        ):
            errors.append(f"{kind}$.spec.documents.keys: failed validation")
        if (
            key["spec"]["purpose"] == "policy-signing"
            and key["spec"]["status"] == "active"
            and _binding_tuple(key["spec"]["subject"]) == _binding_tuple(spec["team"])
        ):
            policy_signer_present = True
    if not policy_signer_present:
        errors.append(f"{kind}$.spec.documents.keys: failed validation")

    access_policies = validated_catalogs.get("accessPolicies", [])
    approval_profiles = validated_catalogs.get("approvalProfiles", [])
    if spec["profile"] == "identity-catalog-only":
        if (
            spec["authorityMode"] != "deny-all"
            or access_policies
            or approval_profiles
        ):
            errors.append(f"{kind}$.spec.profile: failed validation")
    else:
        if spec["authorityMode"] != "narrowing-only" or len(access_policies) != 1:
            errors.append(f"{kind}$.spec.profile: failed validation")
        for access_policy in access_policies:
            if access_policy["metadata"]["revision"] != metadata["revision"]:
                errors.append(
                    f"{kind}$.spec.documents.accessPolicies: failed validation"
                )
            statement_projects = {
                statement["constraints"]["projectId"]
                for role in access_policy["spec"]["roles"]
                for statement in role["statements"]
            }
            if not statement_projects or not statement_projects.issubset(
                set(spec["targetProjectIds"])
            ):
                errors.append(
                    f"{kind}$.spec.documents.accessPolicies: failed validation"
                )
            bundle_start = _parse_timestamp(spec["validity"]["notBefore"])
            bundle_end = _parse_timestamp(spec["validity"]["notAfter"])
            if any(
                not (
                    bundle_start
                    <= _parse_timestamp(statement["constraints"]["notBefore"])
                    < _parse_timestamp(statement["constraints"]["notAfter"])
                    <= bundle_end
                )
                for role in access_policy["spec"]["roles"]
                for statement in role["statements"]
            ):
                errors.append(
                    f"{kind}$.spec.documents.accessPolicies: failed validation"
                )
            for binding in access_policy["spec"]["bindings"]:
                principal = all_records.get(_binding_tuple(binding["principal"]))
                membership = all_records.get(_binding_tuple(binding["membership"]))
                if (
                    principal is None
                    or membership is None
                    or principal["spec"]["status"] != "active"
                    or membership["spec"]["status"] != "active"
                    or membership["spec"]["principal"] != binding["principal"]
                    or membership["spec"]["team"] != spec["team"]
                ):
                    errors.append(
                        f"{kind}$.spec.documents.accessPolicies: failed validation"
                    )
                    break
        access_policy = access_policies[0] if len(access_policies) == 1 else None
        for approval_profile in approval_profiles:
            profile_spec = approval_profile["spec"]
            expected_team = {
                "id": spec["team"]["id"],
                "digest": spec["team"]["digest"],
            }
            expected_policy = (
                {
                    "id": access_policy["metadata"]["id"],
                    "revision": access_policy["metadata"]["revision"],
                    "digest": approval_policy_context_digest(
                        bundle_id=metadata["id"],
                        bundle_revision=metadata["revision"],
                        team=spec["team"],
                        target_project_ids=spec["targetProjectIds"],
                        access_policy_id=access_policy["metadata"]["id"],
                        access_policy_revision=access_policy["metadata"]["revision"],
                    ),
                    "revocationEpoch": profile_spec["policy"]["revocationEpoch"],
                }
                if access_policy is not None
                else None
            )
            if (
                profile_spec["team"] != expected_team
                or expected_policy is None
                or profile_spec["policy"] != expected_policy
                or profile_spec["requiredApproverRole"]
                not in {role["id"] for role in access_policy["spec"]["roles"]}
                or not (
                    _parse_timestamp(spec["validity"]["notBefore"])
                    <= _parse_timestamp(profile_spec["validity"]["notBefore"])
                    < _parse_timestamp(profile_spec["validity"]["notAfter"])
                    <= _parse_timestamp(spec["validity"]["notAfter"])
                )
            ):
                errors.append(
                    f"{kind}$.spec.documents.approvalProfiles: failed validation"
                )
                break
        approval_bindings = {
            (
                profile["metadata"]["id"],
                profile["metadata"]["recordDigest"],
            ): profile["spec"]["purpose"]
            for profile in approval_profiles
        }
        for access_policy in access_policies:
            if any(
                statement["approvalProfile"] is not None
                and (
                    statement["approvalProfile"]["id"],
                    statement["approvalProfile"]["digest"],
                )
                not in approval_bindings
                or (
                    statement["approvalProfile"] is not None
                    and approval_bindings.get(
                        (
                            statement["approvalProfile"]["id"],
                            statement["approvalProfile"]["digest"],
                        )
                    )
                    != "runtime-action"
                )
                for role in access_policy["spec"]["roles"]
                for statement in role["statements"]
            ):
                errors.append(
                    f"{kind}$.spec.documents.accessPolicies: failed validation"
                )
                break
    return errors


def authority_contract_errors(document: Any) -> list[str]:
    """Return deterministic, value-free validation errors for authority records."""

    if not isinstance(document, dict):
        return ["record$: has the wrong type"]
    kind = document.get("kind")
    if not isinstance(kind, str) or kind not in AUTHORITY_SCHEMA_BY_KIND:
        return ["record$.kind: is not a supported authority record kind"]
    validator = Draft202012Validator(
        _load_schema(kind),
        format_checker=_FORMAT_CHECKER,
        registry=_schema_registry(),
    )
    structural = sorted(
        validator.iter_errors(document),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    if structural:
        return [
            f"{kind}{_json_path(error.absolute_path)}: {_sanitized_message(error.validator)}"
            for error in structural
        ]
    if kind in {"PrincipalIdentity", "TeamIdentity"}:
        return _identity_semantic_errors(kind, document)
    if kind == "MembershipBinding":
        return _membership_semantic_errors(document)
    if kind == "IdentityKey":
        return _key_semantic_errors(document)
    if kind == "TeamAccessPolicy":
        from .team_access import team_access_contract_errors

        return team_access_contract_errors(document)
    if kind == "ApprovalProfile":
        from .team_approval import approval_contract_errors

        return approval_contract_errors(document)
    return _policy_semantic_errors(document)


def validate_authority_record(document: Any) -> dict[str, Any]:
    errors = authority_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return document


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
