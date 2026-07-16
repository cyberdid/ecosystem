from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .digests import canonical_json, semantic_digest
from .errors import RuntimePolicyError
from .team_identity import (
    authority_record_digest,
    decode_base64url,
    identity_key_id,
    validate_authority_record,
)

POLICY_ENVELOPE_PROTOCOL = "eco-team-policy-envelope-v1"
POLICY_SIGNATURE_DOMAIN = b"eco-team-policy-signature-v1\x00"
MAX_POLICY_ENVELOPE_BYTES = 2 * 1024 * 1024
_CANONICAL_ID = re.compile(r"^[a-z0-9][a-z0-9._:@/-]{0,127}$")
_CANONICAL_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _failure(code: str) -> RuntimePolicyError:
    return RuntimePolicyError(code, "Team policy verification failed closed")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise _failure("ECO_TEAM_POLICY_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not _CANONICAL_TIMESTAMP.fullmatch(value):
        raise _failure("ECO_TEAM_POLICY_TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _failure("ECO_TEAM_POLICY_TIME_INVALID") from exc


def _strict_object(
    value: object, *, required: frozenset[str], code: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != required:
        raise _failure(code)
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class PolicyTrustAnchor:
    """Caller-supplied external trust; provenance is not established by this object."""

    team_id: str
    key_id: str
    public_key: bytes = field(repr=False)
    allowed_project_ids: tuple[str, ...]
    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        public_key = bytes(self.public_key)
        projects = tuple(self.allowed_project_ids)
        not_before = _utc(self.not_before)
        not_after = _utc(self.not_after)
        valid = (
            bool(_CANONICAL_ID.fullmatch(self.team_id))
            and len(public_key) == 32
            and self.key_id == identity_key_id(public_key)
            and projects
            and projects == tuple(sorted(set(projects)))
            and all(_CANONICAL_ID.fullmatch(item) for item in projects)
            and not_before < not_after
        )
        if not valid:
            raise _failure("ECO_TEAM_POLICY_TRUST_ANCHOR_INVALID")
        object.__setattr__(self, "public_key", public_key)
        object.__setattr__(self, "allowed_project_ids", projects)
        object.__setattr__(self, "not_before", not_before)
        object.__setattr__(self, "not_after", not_after)


@dataclass(frozen=True, slots=True)
class VerifiedPolicyBundle:
    envelope_id: str
    envelope_digest: str
    bundle_id: str
    bundle_digest: str
    revision: int
    issuer_team_id: str
    issuer_key_id: str
    target_project_ids: tuple[str, ...]
    issued_at: datetime
    not_before: datetime
    not_after: datetime
    bundle: Mapping[str, Any] = field(repr=False, compare=False)
    signature_verified: bool = field(default=True, init=False)
    activation_eligible: bool = field(default=False, init=False)
    authority_created: bool = field(default=False, init=False)
    currentness: str = field(default="not-established", init=False)


def policy_signature_message(envelope_body: Mapping[str, Any]) -> bytes:
    return POLICY_SIGNATURE_DOMAIN + canonical_json(dict(envelope_body)).encode("utf-8")


def _parse_canonical_json(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_POLICY_ENVELOPE_BYTES:
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_SIZE_INVALID")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_INVALID")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _failure("ECO_TEAM_POLICY_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        decoded = raw.decode("utf-8")
        document = json.loads(decoded, object_pairs_hook=no_duplicates)
    except RuntimePolicyError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_INVALID") from exc
    if not isinstance(document, dict):
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_INVALID")
    try:
        canonical = canonical_json(document).encode("utf-8")
    except RuntimePolicyError as exc:
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_INVALID") from exc
    if canonical != raw:
        raise _failure("ECO_TEAM_POLICY_ENVELOPE_NONCANONICAL")
    return document


class TeamPolicyVerifier:
    def __init__(
        self,
        trust_anchor: PolicyTrustAnchor,
        *,
        maximum_clock_skew: timedelta = timedelta(seconds=60),
        maximum_lifetime: timedelta = timedelta(days=31),
    ) -> None:
        if maximum_clock_skew < timedelta(0) or maximum_lifetime <= timedelta(0):
            raise ValueError("verification windows must be positive")
        self._anchor = trust_anchor
        self._maximum_clock_skew = maximum_clock_skew
        self._maximum_lifetime = maximum_lifetime

    def verify(
        self,
        raw: bytes,
        *,
        expected_project_id: str,
        now: datetime,
        expected_previous: tuple[int, str] | None = None,
    ) -> VerifiedPolicyBundle:
        observed_at = _utc(now)
        if not _CANONICAL_ID.fullmatch(expected_project_id):
            raise _failure("ECO_TEAM_POLICY_PROJECT_INVALID")
        envelope = _parse_canonical_json(raw)
        _strict_object(
            envelope,
            required=frozenset(
                {"protocol", "envelopeId", "issuer", "issuedAt", "subject", "bundle", "signature"}
            ),
            code="ECO_TEAM_POLICY_ENVELOPE_INVALID",
        )
        if envelope["protocol"] != POLICY_ENVELOPE_PROTOCOL or not isinstance(
            envelope["envelopeId"], str
        ) or not _CANONICAL_ID.fullmatch(envelope["envelopeId"]):
            raise _failure("ECO_TEAM_POLICY_ENVELOPE_INVALID")
        issuer = _strict_object(
            envelope["issuer"],
            required=frozenset({"teamId", "keyId"}),
            code="ECO_TEAM_POLICY_ISSUER_INVALID",
        )
        if (
            issuer["teamId"] != self._anchor.team_id
            or issuer["keyId"] != self._anchor.key_id
        ):
            raise _failure("ECO_TEAM_POLICY_ISSUER_UNTRUSTED")
        subject = _strict_object(
            envelope["subject"],
            required=frozenset({"kind", "id", "revision", "digest"}),
            code="ECO_TEAM_POLICY_SUBJECT_INVALID",
        )
        signature = _strict_object(
            envelope["signature"],
            required=frozenset({"algorithm", "value"}),
            code="ECO_TEAM_POLICY_SIGNATURE_INVALID",
        )
        if signature["algorithm"] != "Ed25519":
            raise _failure("ECO_TEAM_POLICY_ALGORITHM_UNSUPPORTED")
        try:
            signature_bytes = decode_base64url(signature["value"], expected_bytes=64)
        except ValueError as exc:
            raise _failure("ECO_TEAM_POLICY_SIGNATURE_INVALID") from exc
        body = {key: value for key, value in envelope.items() if key != "signature"}
        try:
            Ed25519PublicKey.from_public_bytes(self._anchor.public_key).verify(
                signature_bytes, policy_signature_message(body)
            )
        except (InvalidSignature, ValueError) as exc:
            raise _failure("ECO_TEAM_POLICY_SIGNATURE_INVALID") from exc

        bundle = envelope["bundle"]
        try:
            validate_authority_record(bundle)
        except Exception as exc:
            raise _failure("ECO_TEAM_POLICY_BUNDLE_INVALID") from exc
        if bundle["kind"] != "TeamPolicyBundle":
            raise _failure("ECO_TEAM_POLICY_BUNDLE_INVALID")
        metadata = bundle["metadata"]
        bundle_digest = authority_record_digest(bundle)
        expected_subject = {
            "kind": "TeamPolicyBundle",
            "id": metadata["id"],
            "revision": metadata["revision"],
            "digest": bundle_digest,
        }
        if subject != expected_subject:
            raise _failure("ECO_TEAM_POLICY_SUBJECT_INVALID")
        spec = bundle["spec"]
        if spec["team"]["id"] != self._anchor.team_id:
            raise _failure("ECO_TEAM_POLICY_TEAM_INVALID")
        projects = tuple(spec["targetProjectIds"])
        if (
            expected_project_id not in projects
            or any(item not in self._anchor.allowed_project_ids for item in projects)
        ):
            raise _failure("ECO_TEAM_POLICY_PROJECT_UNTRUSTED")

        signing_key = next(
            (
                item
                for item in spec["documents"]["keys"]
                if item["metadata"]["id"] == self._anchor.key_id
            ),
            None,
        )
        if signing_key is None:
            raise _failure("ECO_TEAM_POLICY_SIGNING_KEY_UNBOUND")
        try:
            embedded_public_key = decode_base64url(
                signing_key["spec"]["publicKey"]["value"], expected_bytes=32
            )
        except ValueError as exc:
            raise _failure("ECO_TEAM_POLICY_SIGNING_KEY_UNBOUND") from exc
        if (
            embedded_public_key != self._anchor.public_key
            or signing_key["spec"]["purpose"] != "policy-signing"
            or signing_key["spec"]["status"] != "active"
            or signing_key["spec"]["subject"] != spec["team"]
        ):
            raise _failure("ECO_TEAM_POLICY_SIGNING_KEY_UNBOUND")

        issued_at = _parse_time(envelope["issuedAt"])
        created_at = _parse_time(metadata["createdAt"])
        not_before = _parse_time(spec["validity"]["notBefore"])
        not_after = _parse_time(spec["validity"]["notAfter"])
        if (
            not not_before <= issued_at < not_after
            or created_at > issued_at
            or not_after - not_before > self._maximum_lifetime
            or issued_at > observed_at + self._maximum_clock_skew
            or observed_at < not_before - self._maximum_clock_skew
            or observed_at >= not_after
            or not self._anchor.not_before <= observed_at < self._anchor.not_after
            or not self._anchor.not_before <= issued_at < self._anchor.not_after
            or not self._anchor.not_before <= not_before
            or not_after > self._anchor.not_after
        ):
            raise _failure("ECO_TEAM_POLICY_EXPIRED_OR_NOT_YET_VALID")
        if expected_previous is not None:
            previous = spec["previous"]
            if previous is None or (
                previous["revision"], previous["digest"]
            ) != expected_previous:
                raise _failure("ECO_TEAM_POLICY_PREDECESSOR_MISMATCH")

        return VerifiedPolicyBundle(
            envelope_id=envelope["envelopeId"],
            envelope_digest=semantic_digest(envelope),
            bundle_id=metadata["id"],
            bundle_digest=bundle_digest,
            revision=metadata["revision"],
            issuer_team_id=issuer["teamId"],
            issuer_key_id=issuer["keyId"],
            target_project_ids=projects,
            issued_at=issued_at,
            not_before=not_before,
            not_after=not_after,
            bundle=_freeze(bundle),
        )
