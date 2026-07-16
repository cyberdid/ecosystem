from __future__ import annotations

"""Closed, externally signed actor-authentication assertions for M5.

An assertion proves possession of one active ``workload-authentication`` key.
It is deliberately not an authorization decision: callers must still pass the
runtime-policy, team-policy, revocation, emergency and permit gates.
"""

import copy
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from .digests import canonical_json, semantic_digest
from .errors import RuntimePolicyError
from .team_identity import decode_base64url


ACTOR_ASSERTION_API_VERSION = "authority.ai.ecosystem/v1alpha1"
ACTOR_ASSERTION_KIND = "AuthenticatedActorAssertion"
ACTOR_ASSERTION_SIGNATURE_DOMAIN = b"eco-team-actor-assertion-signature-v1\x00"
ACTOR_ASSERTION_AUDIENCES = frozenset({"runtime-effect", "emergency-recovery"})
_ID = re.compile(r"^[a-z0-9][a-z0-9._:@/-]{0,127}$")
_KEY_ID = re.compile(r"^ed25519:[a-f0-9]{64}$")
_HEX = re.compile(r"^[a-f0-9]{64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _failure(code: str) -> RuntimePolicyError:
    return RuntimePolicyError(code, "Team actor authentication failed closed")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID") from exc
    return parsed.astimezone(timezone.utc)


def _binding(value: object, kind: str) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == {"kind", "id", "digest"}
        and value.get("kind") == kind
        and isinstance(value.get("id"), str)
        and _ID.fullmatch(value["id"]) is not None
        and isinstance(value.get("digest"), str)
        and _HEX.fullmatch(value["digest"]) is not None
    )


def validate_actor_assertion(assertion: object) -> dict[str, Any]:
    """Validate the exact assertion shape without establishing trust."""

    if not isinstance(assertion, dict) or set(assertion) != {
        "apiVersion", "kind", "spec",
    }:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    if (
        assertion.get("apiVersion") != ACTOR_ASSERTION_API_VERSION
        or assertion.get("kind") != ACTOR_ASSERTION_KIND
        or not isinstance(assertion.get("spec"), dict)
    ):
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    spec = assertion["spec"]
    if set(spec) != {
        "team", "projectId", "principal", "membership", "keyId", "audience",
        "operationDigest", "authoritySnapshotDigest", "nonceDigest", "issuedAt",
        "expiresAt", "signature",
    }:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    signature = spec.get("signature")
    valid = (
        _binding(spec.get("team"), "TeamIdentity")
        and _binding(spec.get("principal"), "PrincipalIdentity")
        and _binding(spec.get("membership"), "MembershipBinding")
        and isinstance(spec.get("projectId"), str)
        and _ID.fullmatch(spec["projectId"]) is not None
        and isinstance(spec.get("keyId"), str)
        and _KEY_ID.fullmatch(spec["keyId"]) is not None
        and spec.get("audience") in ACTOR_ASSERTION_AUDIENCES
        and isinstance(spec.get("operationDigest"), str)
        and _HEX.fullmatch(spec["operationDigest"]) is not None
        and isinstance(spec.get("authoritySnapshotDigest"), str)
        and _HEX.fullmatch(spec["authoritySnapshotDigest"]) is not None
        and isinstance(spec.get("nonceDigest"), str)
        and _HEX.fullmatch(spec["nonceDigest"]) is not None
        and isinstance(signature, dict)
        and set(signature) == {"algorithm", "value"}
        and signature.get("algorithm") == "Ed25519"
        and isinstance(signature.get("value"), str)
    )
    if not valid:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    issued_at = _parse_timestamp(spec.get("issuedAt"))
    expires_at = _parse_timestamp(spec.get("expiresAt"))
    try:
        decode_base64url(signature["value"], expected_bytes=64)
    except ValueError as exc:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID") from exc
    if not issued_at < expires_at:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    return copy.deepcopy(assertion)


def _shape_for_signing(assertion: Mapping[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(dict(assertion))
    spec = projected.get("spec")
    if not isinstance(spec, dict) or not isinstance(spec.get("signature"), dict):
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    spec["signature"]["value"] = "A" * 86
    validate_actor_assertion(projected)
    return projected


def actor_assertion_message(assertion: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated bytes signed by an actor key."""

    projected = _shape_for_signing(assertion)
    projected["spec"].pop("signature", None)
    return ACTOR_ASSERTION_SIGNATURE_DOMAIN + canonical_json(
        {"assertion": projected}
    ).encode("utf-8")


def runtime_actor_operation_digest(
    runtime_decision: Mapping[str, Any],
    runtime_subject: Mapping[str, Any],
    team_request: Mapping[str, Any],
) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-actor-runtime-operation-v1",
            "runtimeDecisionDigest": semantic_digest(runtime_decision),
            "runtimeSubjectDigest": semantic_digest(runtime_subject),
            "teamRequestDigest": semantic_digest(
                {"domain": "eco-team-runtime-request-v1", "request": team_request}
            ),
        }
    )


def recovery_actor_operation_digest(request_digest: str) -> str:
    if not isinstance(request_digest, str) or _HEX.fullmatch(request_digest) is None:
        raise _failure("ECO_TEAM_ACTOR_ASSERTION_INVALID")
    return semantic_digest(
        {
            "domain": "eco-team-actor-emergency-recovery-operation-v1",
            "requestDigest": request_digest,
        }
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedActorAssertion:
    record: Mapping[str, Any] = field(repr=False, compare=False)
    assertion_digest: str
    principal_id: str
    membership_id: str
    key_id: str
    audience: str
    operation_digest: str
    authority_snapshot_digest: str
    nonce_digest: str
    issued_at: datetime
    expires_at: datetime
    signature_verified: bool = field(default=True, init=False)
    authorization_created: bool = field(default=False, init=False)

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self.record)


def authenticated_actor_assertion(
    record: Mapping[str, Any], *, issued_at: datetime, expires_at: datetime
) -> AuthenticatedActorAssertion:
    spec = record["spec"]
    return AuthenticatedActorAssertion(
        record=_freeze(copy.deepcopy(dict(record))),
        assertion_digest=semantic_digest(record),
        principal_id=spec["principal"]["id"],
        membership_id=spec["membership"]["id"],
        key_id=spec["keyId"],
        audience=spec["audience"],
        operation_digest=spec["operationDigest"],
        authority_snapshot_digest=spec["authoritySnapshotDigest"],
        nonce_digest=spec["nonceDigest"],
        issued_at=issued_at,
        expires_at=expires_at,
    )


class ActorAuthenticator(Protocol):
    def verify_actor_assertion(
        self,
        assertion: Mapping[str, Any],
        *,
        expected_principal: Mapping[str, Any],
        expected_membership: Mapping[str, Any],
        expected_snapshot_digest: str,
        expected_audience: str,
        expected_operation_digest: str,
        now: datetime,
    ) -> AuthenticatedActorAssertion: ...
