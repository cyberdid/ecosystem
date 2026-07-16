from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from importlib import resources
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .digests import canonical_json, semantic_digest
from .errors import RuntimePolicyError
from .policy_bundle import PolicyTrustAnchor

TEAM_KEY_ROTATION_PROTOCOL = "eco-team-key-rotation-v1"
TEAM_KEY_ROTATION_SIGNATURE_DOMAIN = b"eco-team-key-rotation-signature-v1\x00"
TEAM_KEY_ROTATION_REPLAY_DOMAIN = "eco-team-key-rotation-replay-v1"
MAX_TEAM_KEY_ROTATION_BYTES = 64 * 1024

_CANONICAL_ID = re.compile(r"^[a-z0-9][a-z0-9._:@/-]{0,127}$")
_CANONICAL_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FORMAT_CHECKER = FormatChecker()


def _failure(code: str) -> RuntimePolicyError:
    return RuntimePolicyError(code, "Team key rotation verification failed closed")


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _failure("ECO_TEAM_ROTATION_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _canonical_time(value: datetime) -> str:
    normalized = _utc(value)
    if normalized.microsecond:
        raise _failure("ECO_TEAM_ROTATION_ANCHOR_INVALID")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not _CANONICAL_TIMESTAMP.fullmatch(value):
        raise _failure("ECO_TEAM_ROTATION_TIME_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _failure("ECO_TEAM_ROTATION_TIME_INVALID") from exc


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: object, *, expected_bytes: int, code: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise _failure(code)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise _failure(code) from exc
    if len(decoded) != expected_bytes or _encode_base64url(decoded) != value:
        raise _failure(code)
    return decoded


def _anchor_payload(anchor: PolicyTrustAnchor) -> dict[str, Any]:
    return {
        "profile": "eco-policy-trust-anchor-v1",
        "teamId": anchor.team_id,
        "keyId": anchor.key_id,
        "publicKey": {
            "algorithm": "Ed25519",
            "encoding": "raw-base64url",
            "value": _encode_base64url(anchor.public_key),
        },
        "allowedProjectIds": list(anchor.allowed_project_ids),
        "validity": {
            "notBefore": _canonical_time(anchor.not_before),
            "notAfter": _canonical_time(anchor.not_after),
        },
    }


def policy_trust_anchor_digest(anchor: PolicyTrustAnchor) -> str:
    """Return the digest used to bind an externally provisioned trust anchor."""

    return semantic_digest(_anchor_payload(anchor))


def team_key_rotation_replay_identity(claims: Mapping[str, Any]) -> str:
    """Derive a stable replay identity from the unsigned claims (without rotationId)."""

    return "rotation:" + semantic_digest(
        {"domain": TEAM_KEY_ROTATION_REPLAY_DOMAIN, "claims": dict(claims)}
    )


def team_key_rotation_signature_message(body: Mapping[str, Any]) -> bytes:
    """Return the exact domain-separated message both anchors must sign."""

    return TEAM_KEY_ROTATION_SIGNATURE_DOMAIN + canonical_json(dict(body)).encode(
        "utf-8"
    )


def _load_schema() -> dict[str, Any]:
    source = resources.files("eco_runtime").joinpath(
        "schemas", "team-key-rotation.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def _parse_canonical_json(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_TEAM_KEY_ROTATION_BYTES:
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_SIZE_INVALID")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_INVALID")

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _failure("ECO_TEAM_ROTATION_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except RuntimePolicyError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_INVALID") from exc
    if not isinstance(document, dict):
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_INVALID")
    try:
        encoded = canonical_json(document).encode("utf-8")
    except RuntimePolicyError as exc:
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_INVALID") from exc
    if encoded != raw:
        raise _failure("ECO_TEAM_ROTATION_ENVELOPE_NONCANONICAL")
    return document


@dataclass(frozen=True, slots=True)
class VerifiedTeamKeyRotation:
    """Sanitized proof only; authority-store activation remains a separate operation."""

    rotation_id: str
    replay_identity: str
    envelope_digest: str
    team_id: str
    project_ids: tuple[str, ...]
    old_anchor_digest: str
    old_key_id: str
    new_anchor_digest: str
    new_key_id: str
    issued_at: datetime
    new_not_before: datetime
    new_not_after: datetime
    signatures_verified: bool = field(default=True, init=False)
    activation_eligible: bool = field(default=False, init=False)
    authority_created: bool = field(default=False, init=False)
    currentness: str = field(default="not-established", init=False)


class TeamKeyRotationVerifier:
    """Verify dual possession relative to two caller-supplied external anchors."""

    def __init__(
        self,
        current_anchor: PolicyTrustAnchor,
        expected_new_anchor: PolicyTrustAnchor,
        *,
        maximum_clock_skew: timedelta = timedelta(seconds=60),
        maximum_rotation_age: timedelta = timedelta(minutes=15),
        maximum_new_anchor_lifetime: timedelta = timedelta(days=366),
    ) -> None:
        if (
            maximum_clock_skew < timedelta(0)
            or maximum_rotation_age <= timedelta(0)
            or maximum_new_anchor_lifetime <= timedelta(0)
        ):
            raise ValueError("verification windows must be positive")
        self._current_anchor = current_anchor
        self._expected_new_anchor = expected_new_anchor
        self._maximum_clock_skew = maximum_clock_skew
        self._maximum_rotation_age = maximum_rotation_age
        self._maximum_new_anchor_lifetime = maximum_new_anchor_lifetime

    def verify(
        self,
        raw: bytes,
        *,
        expected_project_id: str,
        now: datetime,
    ) -> VerifiedTeamKeyRotation:
        observed_at = _utc(now)
        if not isinstance(expected_project_id, str) or not _CANONICAL_ID.fullmatch(
            expected_project_id
        ):
            raise _failure("ECO_TEAM_ROTATION_PROJECT_INVALID")

        envelope = _parse_canonical_json(raw)
        if list(Draft202012Validator(
            _load_schema(), format_checker=_FORMAT_CHECKER
        ).iter_errors(envelope)):
            raise _failure("ECO_TEAM_ROTATION_SCHEMA_INVALID")
        if envelope["protocol"] != TEAM_KEY_ROTATION_PROTOCOL:
            raise _failure("ECO_TEAM_ROTATION_PROTOCOL_UNSUPPORTED")
        _decode_base64url(
            envelope["nonce"],
            expected_bytes=32,
            code="ECO_TEAM_ROTATION_NONCE_INVALID",
        )

        claims = {
            key: value
            for key, value in envelope.items()
            if key not in {"rotationId", "signatures"}
        }
        replay_identity = team_key_rotation_replay_identity(claims)
        if envelope["rotationId"] != replay_identity:
            raise _failure("ECO_TEAM_ROTATION_REPLAY_ID_INVALID")

        team_id = envelope["teamId"]
        projects = tuple(envelope["projectIds"])
        current = self._current_anchor
        expected_new = self._expected_new_anchor
        if (
            team_id != current.team_id
            or team_id != expected_new.team_id
            or current.team_id != expected_new.team_id
        ):
            raise _failure("ECO_TEAM_ROTATION_TEAM_INVALID")
        if (
            projects != tuple(sorted(set(projects)))
            or projects != expected_new.allowed_project_ids
            or expected_project_id not in projects
            or any(project not in current.allowed_project_ids for project in projects)
        ):
            raise _failure("ECO_TEAM_ROTATION_PROJECT_UNTRUSTED")
        if current.key_id == expected_new.key_id:
            raise _failure("ECO_TEAM_ROTATION_ANCHOR_MISMATCH")

        old_claim = envelope["oldAnchor"]
        new_claim = envelope["newAnchor"]
        if (
            old_claim["keyId"] != current.key_id
            or old_claim["anchorDigest"] != policy_trust_anchor_digest(current)
            or new_claim["keyId"] != expected_new.key_id
            or new_claim["anchorDigest"]
            != policy_trust_anchor_digest(expected_new)
        ):
            raise _failure("ECO_TEAM_ROTATION_ANCHOR_MISMATCH")
        new_public_key = new_claim["publicKey"]
        if new_public_key["algorithm"] != "Ed25519":
            raise _failure("ECO_TEAM_ROTATION_ALGORITHM_UNSUPPORTED")
        if new_public_key["encoding"] != "raw-base64url":
            raise _failure("ECO_TEAM_ROTATION_PUBLIC_KEY_INVALID")
        decoded_new_key = _decode_base64url(
            new_public_key["value"],
            expected_bytes=32,
            code="ECO_TEAM_ROTATION_PUBLIC_KEY_INVALID",
        )
        new_not_before = _parse_time(new_claim["validity"]["notBefore"])
        new_not_after = _parse_time(new_claim["validity"]["notAfter"])
        if (
            decoded_new_key != expected_new.public_key
            or new_not_before != expected_new.not_before
            or new_not_after != expected_new.not_after
        ):
            raise _failure("ECO_TEAM_ROTATION_ANCHOR_MISMATCH")

        issued_at = _parse_time(envelope["issuedAt"])
        if (
            issued_at > observed_at + self._maximum_clock_skew
            or observed_at - issued_at > self._maximum_rotation_age
            or not current.not_before <= issued_at < current.not_after
            or not current.not_before <= observed_at < current.not_after
            or not new_not_before <= issued_at < new_not_after
            or not new_not_before <= observed_at < new_not_after
            or new_not_after - new_not_before > self._maximum_new_anchor_lifetime
        ):
            raise _failure("ECO_TEAM_ROTATION_EXPIRED_OR_NOT_YET_VALID")

        body = {key: value for key, value in envelope.items() if key != "signatures"}
        message = team_key_rotation_signature_message(body)
        for name, public_key, expected_key_id in (
            ("old", current.public_key, current.key_id),
            ("new", expected_new.public_key, expected_new.key_id),
        ):
            signature = envelope["signatures"][name]
            if signature["algorithm"] != "Ed25519":
                raise _failure("ECO_TEAM_ROTATION_ALGORITHM_UNSUPPORTED")
            if signature["keyId"] != expected_key_id:
                raise _failure("ECO_TEAM_ROTATION_SIGNATURE_INVALID")
            signature_bytes = _decode_base64url(
                signature["value"],
                expected_bytes=64,
                code="ECO_TEAM_ROTATION_SIGNATURE_INVALID",
            )
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(
                    signature_bytes, message
                )
            except (InvalidSignature, ValueError) as exc:
                raise _failure("ECO_TEAM_ROTATION_SIGNATURE_INVALID") from exc

        return VerifiedTeamKeyRotation(
            rotation_id=envelope["rotationId"],
            replay_identity=replay_identity,
            envelope_digest=semantic_digest(envelope),
            team_id=team_id,
            project_ids=projects,
            old_anchor_digest=old_claim["anchorDigest"],
            old_key_id=current.key_id,
            new_anchor_digest=new_claim["anchorDigest"],
            new_key_id=expected_new.key_id,
            issued_at=issued_at,
            new_not_before=new_not_before,
            new_not_after=new_not_after,
        )
