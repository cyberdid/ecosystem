from __future__ import annotations

"""Verification-only M5 team approval primitives.

This module authenticates exact Ed25519 votes and derives an immutable,
content-free permit.  It deliberately does not persist or consume permits.
Durable single-use enforcement is delegated to ``PermitConsumptionHook``;
the hook must atomically record the permit and bind its downstream operation.
"""

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from importlib import resources
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .digests import canonical_json, semantic_digest
from .errors import ContractValidationError, RuntimePolicyError
from .team_identity import decode_base64url, identity_key_id


AUTHORITY_API_VERSION = "authority.ai.ecosystem/v1alpha1"
APPROVAL_RECORD_KINDS = frozenset(
    {"ApprovalProfile", "TeamApprovalRequest", "TeamApprovalVote", "TeamActionPermit"}
)
APPROVAL_SIGNATURE_DOMAIN = b"eco-team-approval-vote-signature-v1\x00"
APPROVAL_RECORD_PROFILE = "team-approval-record-v1"
_CANONICAL_ID = re.compile(r"^[a-z0-9][a-z0-9._:@/-]{0,127}$")
_CANONICAL_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX = re.compile(r"^[a-f0-9]{64}$")
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


def _failure(code: str) -> RuntimePolicyError:
    return RuntimePolicyError(code, "Team approval verification failed closed")


def _schema() -> dict[str, Any]:
    source = resources.files("eco_runtime").joinpath(
        "schemas", "team-approval.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _failure("ECO_TEAM_APPROVAL_TIME_INVALID")
    result = value.astimezone(timezone.utc)
    if result.microsecond:
        raise _failure("ECO_TEAM_APPROVAL_TIME_INVALID")
    return result


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not _CANONICAL_TIMESTAMP.fullmatch(value):
        raise _failure("ECO_TEAM_APPROVAL_TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _failure("ECO_TEAM_APPROVAL_TIME_INVALID") from exc


def _binding(record: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": record["kind"],
        "id": record["metadata"]["id"],
        "digest": record["metadata"]["recordDigest"],
    }


def approval_record_digest(record: Mapping[str, Any]) -> str:
    """Return the non-self-referential digest for one approval record."""

    projected = copy.deepcopy(dict(record))
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {"profile": APPROVAL_RECORD_PROFILE, "record": projected}
    )


def approval_vote_message(vote: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated bytes an external approver signs."""

    projected = copy.deepcopy(dict(vote))
    metadata = projected.get("metadata")
    spec = projected.get("spec")
    if not isinstance(metadata, dict) or not isinstance(spec, dict):
        raise _failure("ECO_TEAM_APPROVAL_INVALID")
    metadata.pop("recordDigest", None)
    spec.pop("signature", None)
    return APPROVAL_SIGNATURE_DOMAIN + canonical_json(
        {"vote": projected}
    ).encode("utf-8")


def _sanitized_schema_errors(record: object) -> list[str]:
    if not isinstance(record, dict):
        return ["TeamApprovalRecord$: has the wrong type"]
    kind = record.get("kind")
    if not isinstance(kind, str) or kind not in APPROVAL_RECORD_KINDS:
        return ["TeamApprovalRecord$.kind: is not a supported approval record kind"]
    errors = sorted(
        Draft202012Validator(
            _schema(), format_checker=_FORMAT_CHECKER
        ).iter_errors(record),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    if errors:
        return [f"{kind}$: failed structural validation"]
    return []


def _semantic_errors(record: dict[str, Any]) -> list[str]:
    kind = record["kind"]
    metadata = record["metadata"]
    spec = record["spec"]
    errors: list[str] = []
    try:
        created_at = _parse_timestamp(metadata["createdAt"])
        if kind == "ApprovalProfile":
            not_before = _parse_timestamp(spec["validity"]["notBefore"])
            not_after = _parse_timestamp(spec["validity"]["notAfter"])
            if not not_before <= created_at < not_after:
                errors.append(f"{kind}$.spec.validity: failed validation")
            if spec["purpose"] == "emergency-recovery" and spec["quorum"] < 2:
                errors.append(f"{kind}$.spec.quorum: failed validation")
        elif kind == "TeamApprovalRequest":
            expires_at = _parse_timestamp(spec["expiresAt"])
            if not created_at < expires_at:
                errors.append(f"{kind}$.spec.expiresAt: failed validation")
            if spec["profile"]["kind"] != "ApprovalProfile":
                errors.append(f"{kind}$.spec.profile: failed validation")
        elif kind == "TeamApprovalVote":
            issued_at = _parse_timestamp(spec["issuedAt"])
            expires_at = _parse_timestamp(spec["expiresAt"])
            if created_at != issued_at or not issued_at < expires_at:
                errors.append(f"{kind}$.spec: failed validation")
            if spec["profile"]["kind"] != "ApprovalProfile" or spec["request"][
                "kind"
            ] != "TeamApprovalRequest":
                errors.append(f"{kind}$.spec: failed validation")
            try:
                decode_base64url(spec["signature"]["value"], expected_bytes=64)
            except ValueError:
                errors.append(f"{kind}$.spec.signature: failed validation")
        else:
            issued_at = _parse_timestamp(spec["issuedAt"])
            expires_at = _parse_timestamp(spec["expiresAt"])
            principals = [item["principalId"] for item in spec["approvers"]]
            if not created_at == issued_at < expires_at:
                errors.append(f"{kind}$.spec: failed validation")
            if principals != sorted(principals) or len(principals) != len(
                set(principals)
            ):
                errors.append(f"{kind}$.spec.approvers: failed validation")
            if spec["quorum"] > len(principals):
                errors.append(f"{kind}$.spec.quorum: failed validation")
    except RuntimePolicyError:
        errors.append(f"{kind}$: failed time validation")
    if metadata["recordDigest"] != approval_record_digest(record):
        errors.append(f"{kind}$.metadata.recordDigest: failed validation")
    return errors


def approval_contract_errors(record: object) -> list[str]:
    errors = _sanitized_schema_errors(record)
    if errors:
        return errors
    return _semantic_errors(record)  # type: ignore[arg-type]


def validate_team_approval_record(record: object) -> dict[str, Any]:
    errors = approval_contract_errors(record)
    if errors:
        raise ContractValidationError(errors)
    return record  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ResolvedApprovalKey:
    """An active-key assertion returned by an external identity authority."""

    team_id: str
    principal_id: str
    key_id: str
    membership_digest: str
    roles: tuple[str, ...]
    policy_digest: str
    revocation_epoch: int
    not_before: datetime
    not_after: datetime
    public_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        public_key = bytes(self.public_key)
        roles = tuple(self.roles)
        valid = (
            bool(_CANONICAL_ID.fullmatch(self.team_id))
            and bool(_CANONICAL_ID.fullmatch(self.principal_id))
            and len(public_key) == 32
            and self.key_id == identity_key_id(public_key)
            and bool(_HEX.fullmatch(self.membership_digest))
            and roles == tuple(sorted(set(roles)))
            and bool(roles)
            and all(_CANONICAL_ID.fullmatch(role) for role in roles)
            and bool(_HEX.fullmatch(self.policy_digest))
            and type(self.revocation_epoch) is int
            and 0 <= self.revocation_epoch <= 2_147_483_647
        )
        not_before = _utc(self.not_before)
        not_after = _utc(self.not_after)
        if not valid or not not_before < not_after:
            raise _failure("ECO_TEAM_APPROVAL_KEY_UNTRUSTED")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "public_key", public_key)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)


class ActiveApprovalKeyResolver(Protocol):
    """Trusted external membership/key/revocation resolver interface."""

    def resolve_active_key(
        self,
        *,
        team_id: str,
        profile_id: str,
        profile_digest: str,
        required_role: str,
        quorum: int,
        principal_id: str,
        key_id: str,
        policy_digest: str,
        revocation_epoch: int,
        at: datetime,
    ) -> ResolvedApprovalKey | None: ...


@dataclass(frozen=True, slots=True)
class VerifiedApprovalVote:
    vote_id: str
    vote_digest: str
    profile_id: str
    profile_digest: str
    request_id: str
    request_digest: str
    principal_id: str
    key_id: str
    membership_digest: str
    decision: str
    issued_at: datetime
    expires_at: datetime
    signature_verified: bool = field(default=True, init=False)
    authority_created: bool = field(default=False, init=False)


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
class PermitConsumptionIntent:
    permit_digest: str
    request_digest: str
    action_digest: str
    resource_digest: str
    snapshot_digest: str
    policy_digest: str
    revocation_epoch: int
    consumption_nonce_digest: str
    expires_at: datetime
    consumed_at: datetime


class PermitConsumptionHook(Protocol):
    """Durable authority integration point.

    Implementations must atomically reject a repeated ``permit_digest`` or
    ``consumption_nonce_digest`` and bind the exact intent to the downstream
    operation in the same transaction.  Returning a receipt digest is the
    hook's attestation that this transaction committed.
    """

    def consume_team_action_permit(
        self, intent: PermitConsumptionIntent
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class ConsumedActionPermit:
    permit_digest: str
    consumed_at: datetime
    store_receipt_digest: str


@dataclass(frozen=True, slots=True)
class VerifiedActionPermit:
    record: Mapping[str, Any] = field(repr=False, compare=False)
    permit_digest: str
    expires_at: datetime
    signature_votes_verified: bool = field(default=True, init=False)
    single_use: bool = field(default=True, init=False)
    store_integration_required: bool = field(default=True, init=False)
    authority_created: bool = field(default=False, init=False)

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self.record)

    def consume_with(
        self, hook: PermitConsumptionHook, *, now: datetime
    ) -> ConsumedActionPermit:
        """Consume through a trusted atomic store hook; never in memory."""

        consumed_at = _utc(now)
        if consumed_at >= self.expires_at:
            raise _failure("ECO_TEAM_APPROVAL_EXPIRED")
        spec = self.record["spec"]
        intent = PermitConsumptionIntent(
            permit_digest=self.permit_digest,
            request_digest=spec["request"]["digest"],
            action_digest=spec["action"]["digest"],
            resource_digest=spec["resource"]["digest"],
            snapshot_digest=spec["snapshot"]["digest"],
            policy_digest=spec["policy"]["digest"],
            revocation_epoch=spec["policy"]["revocationEpoch"],
            consumption_nonce_digest=spec["constraints"][
                "consumptionNonceDigest"
            ],
            expires_at=self.expires_at,
            consumed_at=consumed_at,
        )
        try:
            receipt = hook.consume_team_action_permit(intent)
        except Exception as exc:
            raise _failure("ECO_TEAM_APPROVAL_STORE_REJECTED") from exc
        if not isinstance(receipt, str) or not _HEX.fullmatch(receipt):
            raise _failure("ECO_TEAM_APPROVAL_PERMIT_CONSUMED")
        return ConsumedActionPermit(self.permit_digest, consumed_at, receipt)


class TeamApprovalVerifier:
    def __init__(
        self,
        resolver: ActiveApprovalKeyResolver,
        *,
        maximum_clock_skew: timedelta = timedelta(seconds=60),
        maximum_vote_lifetime: timedelta = timedelta(minutes=30),
    ) -> None:
        if maximum_clock_skew < timedelta(0) or maximum_vote_lifetime <= timedelta(0):
            raise ValueError("approval verification windows are invalid")
        self._resolver = resolver
        self._maximum_clock_skew = maximum_clock_skew
        self._maximum_vote_lifetime = maximum_vote_lifetime

    def _validate_context(
        self,
        profile: dict[str, Any],
        request: dict[str, Any],
        *,
        expected_requester_principal_id: str,
        expected_requester_membership_digest: str,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        try:
            validate_team_approval_record(profile)
            validate_team_approval_record(request)
        except ContractValidationError as exc:
            raise _failure("ECO_TEAM_APPROVAL_INVALID") from exc
        if profile["kind"] != "ApprovalProfile" or request["kind"] != "TeamApprovalRequest":
            raise _failure("ECO_TEAM_APPROVAL_INVALID")
        observed_at = _utc(now)
        profile_start = _parse_timestamp(profile["spec"]["validity"]["notBefore"])
        profile_end = _parse_timestamp(profile["spec"]["validity"]["notAfter"])
        request_expiry = _parse_timestamp(request["spec"]["expiresAt"])
        if (
            not _CANONICAL_ID.fullmatch(expected_requester_principal_id)
            or not _HEX.fullmatch(expected_requester_membership_digest)
            or request["spec"]["requester"]
            != {
                "principalId": expected_requester_principal_id,
                "membershipDigest": expected_requester_membership_digest,
            }
            or not profile_start <= observed_at < profile_end
            or observed_at >= request_expiry
            or request["spec"]["profile"] != _binding(profile)
            or request["spec"]["policy"] != profile["spec"]["policy"]
        ):
            raise _failure("ECO_TEAM_APPROVAL_BINDING_INVALID")
        return observed_at, min(profile_end, request_expiry)

    def verify_vote(
        self,
        profile: dict[str, Any],
        request: dict[str, Any],
        vote: dict[str, Any],
        *,
        expected_requester_principal_id: str,
        expected_requester_membership_digest: str,
        now: datetime,
    ) -> VerifiedApprovalVote:
        observed_at, context_expiry = self._validate_context(
            profile,
            request,
            expected_requester_principal_id=expected_requester_principal_id,
            expected_requester_membership_digest=expected_requester_membership_digest,
            now=now,
        )
        try:
            validate_team_approval_record(vote)
        except ContractValidationError as exc:
            raise _failure("ECO_TEAM_APPROVAL_INVALID") from exc
        if vote["kind"] != "TeamApprovalVote":
            raise _failure("ECO_TEAM_APPROVAL_INVALID")
        spec = vote["spec"]
        approver = spec["approver"]
        issued_at = _parse_timestamp(spec["issuedAt"])
        expires_at = _parse_timestamp(spec["expiresAt"])
        request_created_at = _parse_timestamp(request["metadata"]["createdAt"])
        profile_not_before = _parse_timestamp(
            profile["spec"]["validity"]["notBefore"]
        )
        if (
            spec["profile"] != _binding(profile)
            or spec["request"] != _binding(request)
            or approver["principalId"] == request["spec"]["requester"]["principalId"]
        ):
            code = (
                "ECO_TEAM_APPROVAL_REQUESTER_CONFLICT"
                if approver["principalId"]
                == request["spec"]["requester"]["principalId"]
                else "ECO_TEAM_APPROVAL_BINDING_INVALID"
            )
            raise _failure(code)
        if (
            issued_at < max(profile_not_before, request_created_at)
            or issued_at > observed_at + self._maximum_clock_skew
            or observed_at >= expires_at
            or expires_at > context_expiry
            or expires_at - issued_at > self._maximum_vote_lifetime
        ):
            raise _failure("ECO_TEAM_APPROVAL_EXPIRED")
        policy = profile["spec"]["policy"]
        try:
            resolved = self._resolver.resolve_active_key(
                team_id=profile["spec"]["team"]["id"],
                profile_id=profile["metadata"]["id"],
                profile_digest=profile["metadata"]["recordDigest"],
                required_role=profile["spec"]["requiredApproverRole"],
                quorum=profile["spec"]["quorum"],
                principal_id=approver["principalId"],
                key_id=approver["keyId"],
                policy_digest=policy["digest"],
                revocation_epoch=policy["revocationEpoch"],
                at=observed_at,
            )
        except Exception as exc:
            raise _failure("ECO_TEAM_APPROVAL_KEY_UNTRUSTED") from exc
        if not isinstance(resolved, ResolvedApprovalKey):
            raise _failure("ECO_TEAM_APPROVAL_KEY_UNTRUSTED")
        expected = (
            resolved.team_id == profile["spec"]["team"]["id"]
            and resolved.principal_id == approver["principalId"]
            and resolved.key_id == approver["keyId"]
            and resolved.membership_digest == approver["membershipDigest"]
            and resolved.policy_digest == policy["digest"]
            and resolved.revocation_epoch == policy["revocationEpoch"]
            and profile["spec"]["requiredApproverRole"] in resolved.roles
            and resolved.not_before <= issued_at
            and observed_at < resolved.not_after
            and expires_at <= resolved.not_after
        )
        if not expected:
            raise _failure("ECO_TEAM_APPROVAL_KEY_UNTRUSTED")
        try:
            signature = decode_base64url(
                spec["signature"]["value"], expected_bytes=64
            )
            Ed25519PublicKey.from_public_bytes(resolved.public_key).verify(
                signature, approval_vote_message(vote)
            )
        except (InvalidSignature, ValueError) as exc:
            raise _failure("ECO_TEAM_APPROVAL_SIGNATURE_INVALID") from exc
        return VerifiedApprovalVote(
            vote_id=vote["metadata"]["id"],
            vote_digest=vote["metadata"]["recordDigest"],
            profile_id=spec["profile"]["id"],
            profile_digest=spec["profile"]["digest"],
            request_id=spec["request"]["id"],
            request_digest=spec["request"]["digest"],
            principal_id=approver["principalId"],
            key_id=approver["keyId"],
            membership_digest=approver["membershipDigest"],
            decision=spec["decision"],
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def build_action_permit(
        self,
        profile: dict[str, Any],
        request: dict[str, Any],
        votes: Sequence[dict[str, Any]],
        *,
        permit_id: str,
        consumption_nonce: bytes,
        expected_requester_principal_id: str,
        expected_requester_membership_digest: str,
        now: datetime,
    ) -> VerifiedActionPermit:
        observed_at, context_expiry = self._validate_context(
            profile,
            request,
            expected_requester_principal_id=expected_requester_principal_id,
            expected_requester_membership_digest=expected_requester_membership_digest,
            now=now,
        )
        if not _CANONICAL_ID.fullmatch(permit_id):
            raise _failure("ECO_TEAM_APPROVAL_INVALID")
        nonce = bytes(consumption_nonce)
        if len(nonce) != 32:
            raise _failure("ECO_TEAM_APPROVAL_INVALID")
        raw_votes = tuple(votes)
        if not raw_votes or len(raw_votes) > 16 or any(
            not isinstance(vote, dict) for vote in raw_votes
        ):
            raise _failure("ECO_TEAM_APPROVAL_QUORUM")
        vote_list = tuple(
            self.verify_vote(
                profile,
                request,
                vote,
                expected_requester_principal_id=expected_requester_principal_id,
                expected_requester_membership_digest=expected_requester_membership_digest,
                now=observed_at,
            )
            for vote in raw_votes
        )
        principals = [vote.principal_id for vote in vote_list]
        if len(principals) != len(set(principals)):
            raise _failure("ECO_TEAM_APPROVAL_DUPLICATE_PRINCIPAL")
        expected_profile = _binding(profile)
        expected_request = _binding(request)
        if any(
            vote.profile_id != expected_profile["id"]
            or vote.profile_digest != expected_profile["digest"]
            or vote.request_id != expected_request["id"]
            or vote.request_digest != expected_request["digest"]
            for vote in vote_list
        ):
            raise _failure("ECO_TEAM_APPROVAL_BINDING_INVALID")
        if any(vote.decision != "approve" for vote in vote_list):
            raise _failure("ECO_TEAM_APPROVAL_VOTE_DENIED")
        quorum = profile["spec"]["quorum"]
        if len(vote_list) < quorum:
            raise _failure("ECO_TEAM_APPROVAL_QUORUM")
        expires_at = min(context_expiry, *(vote.expires_at for vote in vote_list))
        if observed_at >= expires_at:
            raise _failure("ECO_TEAM_APPROVAL_EXPIRED")
        approvers = [
            {
                "principalId": vote.principal_id,
                "keyId": vote.key_id,
                "membershipDigest": vote.membership_digest,
                "vote": {
                    "kind": "TeamApprovalVote",
                    "id": vote.vote_id,
                    "digest": vote.vote_digest,
                },
            }
            for vote in sorted(vote_list, key=lambda item: item.principal_id)
        ]
        record: dict[str, Any] = {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "TeamActionPermit",
            "metadata": {
                "id": permit_id,
                "createdAt": _timestamp(observed_at),
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": expected_profile,
                "request": expected_request,
                "action": copy.deepcopy(request["spec"]["action"]),
                "resource": copy.deepcopy(request["spec"]["resource"]),
                "snapshot": copy.deepcopy(request["spec"]["snapshot"]),
                "policy": copy.deepcopy(request["spec"]["policy"]),
                "approvers": approvers,
                "quorum": quorum,
                "issuedAt": _timestamp(observed_at),
                "expiresAt": _timestamp(expires_at),
                "constraints": {
                    "singleUse": True,
                    "consumptionNonceDigest": hashlib.sha256(nonce).hexdigest(),
                },
                "safety": {
                    "storeIntegrationRequired": True,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
        record["metadata"]["recordDigest"] = approval_record_digest(record)
        try:
            validate_team_approval_record(record)
        except ContractValidationError as exc:
            raise _failure("ECO_TEAM_APPROVAL_INVALID") from exc
        return VerifiedActionPermit(
            record=_freeze(record),
            permit_digest=record["metadata"]["recordDigest"],
            expires_at=expires_at,
        )
