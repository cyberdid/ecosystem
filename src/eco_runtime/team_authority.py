from __future__ import annotations

"""Embedded, same-host M5 team policy and revocation authority.

This module deliberately owns no private identity/policy signing key and grants
no runtime permission.  It verifies externally signed policy envelopes, then
serializes their activation and the local deny/revocation state in a private,
HMAC-authenticated SQLite journal.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .digests import canonical_json, semantic_digest
from .errors import RuntimePolicyError, RuntimeStoreError
from .policy_bundle import PolicyTrustAnchor, TeamPolicyVerifier
from .team_approval import (
    PermitConsumptionIntent,
    ResolvedApprovalKey,
    TeamApprovalVerifier,
    VerifiedActionPermit,
)
from .team_actor import (
    AuthenticatedActorAssertion,
    actor_assertion_message,
    authenticated_actor_assertion,
    recovery_actor_operation_digest,
    validate_actor_assertion,
)
from .team_identity import approval_policy_context_digest, decode_base64url
from .team_rotation import TeamKeyRotationVerifier


TEAM_AUTHORITY_APPLICATION_ID = 0x45434F35
TEAM_AUTHORITY_SCHEMA_VERSION = 2
GENESIS_DIGEST = "0" * 64
_GENERATION_PROFILES = frozenset({"root", "successor"})
_GENERATION_STATES = frozenset(
    {"active", "pending-successor", "rotation-pending", "retired"}
)
_ID = re.compile(r"[a-z0-9][a-z0-9._:@/-]{0,127}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REASON = re.compile(r"ECO_[A-Z0-9_]{1,96}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REVOCABLE = frozenset(
    {"TeamIdentity", "PrincipalIdentity", "MembershipBinding", "IdentityKey"}
)
_T = TypeVar("_T")


def _error(code: str, message: str = "Team authority operation failed closed") -> RuntimeStoreError:
    return RuntimeStoreError(code, message)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _error("ECO_TEAM_AUTHORITY_CLOCK_INVALID")
    return value.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
    if parsed.tzinfo is None:
        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
    return parsed.astimezone(timezone.utc)


def _epoch_us(value: datetime) -> int:
    return int(_utc(value).timestamp() * 1_000_000)


def _require_id(value: object, *, key: bool = False) -> str:
    pattern = _KEY_ID if key else _ID
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
    return value


def _require_digest(value: object) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
    return value


def _validate_authority_constructor_inputs(
    *,
    hmac_key: bytes,
    key_id: str,
    trust_anchor: PolicyTrustAnchor,
    project_id: str,
    store_id: str | None,
    generation_profile: str,
) -> None:
    """Validate constructor inputs without touching the authority path."""

    if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
        raise ValueError("hmac_key must contain at least 32 bytes")
    _require_id(key_id, key=True)
    if not isinstance(trust_anchor, PolicyTrustAnchor):
        raise TypeError("trust_anchor must be PolicyTrustAnchor")
    _require_id(project_id)
    if project_id not in trust_anchor.allowed_project_ids:
        raise _error("ECO_TEAM_AUTHORITY_PROJECT_UNTRUSTED")
    if store_id is not None:
        _require_id(store_id)
    if generation_profile not in _GENERATION_PROFILES:
        raise ValueError("generation_profile is invalid")


def _resolve_private_authority_path(
    path: str | os.PathLike[str],
    *,
    forbidden_root: str | os.PathLike[str] | None = None,
    require_absolute: bool = False,
) -> Path:
    """Resolve one non-symlink authority path and enforce location policy."""

    requested = Path(path).expanduser()
    try:
        if require_absolute and not requested.is_absolute():
            raise _error("ECO_TEAM_ROTATION_SUCCESSOR_PATH_INVALID")
        # ``exists()`` is false for a broken symlink, which is still unsafe.
        if requested.is_symlink():
            raise _error("ECO_TEAM_AUTHORITY_FILE_UNSAFE")
        requested_lexical = Path(os.path.abspath(requested))
        resolved = requested.resolve()
        if forbidden_root is None:
            return resolved
        forbidden = Path(forbidden_root).expanduser()
        forbidden_lexical = Path(os.path.abspath(forbidden))
        forbidden_resolved = forbidden.resolve()
        if requested_lexical.is_relative_to(
            forbidden_lexical
        ) or resolved.is_relative_to(forbidden_resolved):
            raise _error("ECO_TEAM_AUTHORITY_LOCATION_DENIED")
        return resolved
    except RuntimeStoreError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _error("ECO_TEAM_AUTHORITY_FILE_UNSAFE") from exc


def _prepare_private_authority_parent(path: Path) -> None:
    """Create/check the private parent shared by authority and staging files."""

    try:
        parent_existed = path.parent.exists()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            parent = path.parent.stat()
            if (parent.st_mode & 0o077) or parent.st_uid != os.getuid():
                raise _error("ECO_TEAM_AUTHORITY_PERMISSIONS")
            if not parent_existed:
                os.chmod(path.parent, 0o700)
    except RuntimeStoreError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _error("ECO_TEAM_AUTHORITY_PERMISSIONS") from exc


def _check_private_authority_file(path: Path) -> None:
    """Check the exact private-file invariants used by every authority open."""

    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise _error("ECO_TEAM_AUTHORITY_FILE_UNSAFE")
        if os.name == "posix":
            if details.st_uid != os.getuid() or details.st_mode & 0o077:
                raise _error("ECO_TEAM_AUTHORITY_PERMISSIONS")
            os.chmod(path, 0o600)
    except RuntimeStoreError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _error("ECO_TEAM_AUTHORITY_FILE_UNSAFE") from exc


def _preflight_successor_authority_path(
    path: str | os.PathLike[str],
    *,
    forbidden_root: str | os.PathLike[str] | None,
    allow_existing: bool,
) -> Path:
    """Reject predictable successor-path failures before rotation reservation."""

    resolved = _resolve_private_authority_path(
        path,
        forbidden_root=forbidden_root,
        require_absolute=True,
    )
    _prepare_private_authority_parent(resolved)
    if resolved.exists():
        if not allow_existing:
            raise _error("ECO_TEAM_ROTATION_SUCCESSOR_PATH_INVALID")
        _check_private_authority_file(resolved)
    return resolved


def policy_trust_anchor_digest(anchor: PolicyTrustAnchor) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-policy-trust-anchor-v1",
            "teamId": anchor.team_id,
            "keyId": anchor.key_id,
            "publicKeySha256": hashlib.sha256(anchor.public_key).hexdigest(),
            "allowedProjectIds": list(anchor.allowed_project_ids),
            "notBefore": _time_text(anchor.not_before),
            "notAfter": _time_text(anchor.not_after),
        }
    )


def _raw_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _path_identity(path: Path) -> tuple[int, int] | None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return None
    return details.st_dev, details.st_ino


def _unlink_owned(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None or _path_identity(path) != identity:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _private_staging_path(target: Path) -> Path:
    return target.with_name(
        f".{target.name}.eco-stage-{secrets.token_hex(16)}"
    )


def _publish_no_replace(
    staging: Path,
    target: Path,
    identity: tuple[int, int],
    *,
    conflict_code: str,
) -> None:
    if _path_identity(staging) != identity:
        raise _error("ECO_TEAM_AUTHORITY_STAGING_UNSAFE")
    try:
        os.link(staging, target)
    except FileExistsError as exc:
        raise _error(conflict_code) from exc
    except OSError as exc:
        raise _error("ECO_TEAM_AUTHORITY_PUBLISH_FAILED") from exc
    if _path_identity(target) != identity:
        raise _error("ECO_TEAM_AUTHORITY_PUBLISH_FAILED")
    _unlink_owned(staging, identity)
    if staging.exists():
        raise _error("ECO_TEAM_AUTHORITY_PUBLISH_FAILED")


def _event_digest(
    *, kind: str, identifier: str, object_digest: str, before: str, after: str
) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-authority-event-v1",
            "kind": kind,
            "id": identifier,
            "objectDigest": object_digest,
            "beforeSnapshotDigest": before,
            "afterSnapshotDigest": after,
        }
    )


def _successor_location_digest(path: str | os.PathLike[str]) -> str:
    """Bind a rotation to one canonical destination without disclosing it."""

    return semantic_digest(
        {
            "domain": "eco-team-successor-location-v1",
            "canonicalPath": str(Path(path).expanduser().resolve()),
        }
    )


def emergency_recovery_action_digest(
    *, store_id: str, authority_snapshot_digest: str
) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-emergency-recovery-action-v1",
            "storeId": store_id,
            "authoritySnapshotDigest": authority_snapshot_digest,
            "operation": "emergency.disable",
        }
    )


def emergency_recovery_resource_digest(
    *, store_id: str, emergency_head_digest: str, emergency_epoch: int
) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-emergency-recovery-resource-v1",
            "storeId": store_id,
            "emergencyHeadDigest": emergency_head_digest,
            "emergencyEpoch": emergency_epoch,
        }
    )


class SQLiteTeamAuthority:
    """Private embedded policy/revocation authority for one team and project."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        hmac_key: bytes,
        key_id: str,
        trust_anchor: PolicyTrustAnchor,
        project_id: str,
        forbidden_root: str | os.PathLike[str] | None = None,
        store_id: str | None = None,
        historical_hmac_keys: Mapping[str, bytes] | None = None,
        generation_profile: str = "root",
    ) -> None:
        _validate_authority_constructor_inputs(
            hmac_key=hmac_key,
            key_id=key_id,
            trust_anchor=trust_anchor,
            project_id=project_id,
            store_id=store_id,
            generation_profile=generation_profile,
        )

        self._anchor = trust_anchor
        self._anchor_digest = policy_trust_anchor_digest(trust_anchor)
        self._project_id = project_id
        self._requested_store_id = store_id
        self._requested_generation_profile = generation_profile
        self._audit_keys = dict(historical_hmac_keys or {})
        if key_id in self._audit_keys and self._audit_keys[key_id] != hmac_key:
            raise ValueError("active HMAC key conflicts with historical keyring")
        self._audit_keys[key_id] = bytes(hmac_key)
        if any(
            not isinstance(item, bytes) or len(item) < 32
            for item in self._audit_keys.values()
        ):
            raise ValueError("historical HMAC keys must contain at least 32 bytes")
        self._path = _resolve_private_authority_path(
            path, forbidden_root=forbidden_root
        )
        self._prepare_private_file()
        self._key_id = key_id
        self._hmac_key = bytes(hmac_key)
        self._verifier = TeamPolicyVerifier(trust_anchor)
        self._lock = threading.RLock()
        self._closed = False
        try:
            self._connection = sqlite3.connect(
                self._path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise _error("ECO_TEAM_AUTHORITY_UNAVAILABLE") from exc
        self._connection.row_factory = sqlite3.Row
        try:
            for statement in (
                "PRAGMA foreign_keys = ON",
                "PRAGMA busy_timeout = 5000",
                "PRAGMA trusted_schema = OFF",
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = FULL",
            ):
                self._connection.execute(statement)
            self._initialize_or_verify()
            self._check_private_file()
            self.verify()
        except (RuntimeStoreError, RuntimePolicyError):
            self._connection.close()
            raise
        except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError) as exc:
            self._connection.close()
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
        except Exception:
            self._connection.close()
            raise

    def _prepare_private_file(self) -> None:
        _prepare_private_authority_parent(self._path)
        if not self._path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            mode = 0o600 if os.name == "posix" else 0o666
            descriptor = os.open(self._path, flags, mode)
            os.close(descriptor)

    def _check_private_file(self) -> None:
        _check_private_authority_file(self._path)

    @property
    def store_id(self) -> str:
        return self._store_id

    @property
    def trust_anchor_digest(self) -> str:
        return self._anchor_digest

    @property
    def trust_anchor(self) -> PolicyTrustAnchor:
        return self._anchor

    def __enter__(self) -> "SQLiteTeamAuthority":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._connection.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                if "locked" in str(exc).lower():
                    raise _error("ECO_TEAM_AUTHORITY_BUSY") from exc
                raise
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _meta_payload(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": "eco-team-authority-meta-v1",
            "storeId": row["store_id"],
            "applicationId": row["application_id"],
            "schemaVersion": row["schema_version"],
            "teamId": row["team_id"],
            "projectId": row["project_id"],
            "trustAnchorDigest": row["trust_anchor_digest"],
            "auditKeyId": row["audit_key_id"],
            "generationProfile": row["generation_profile"],
            "createdAt": row["created_at"],
        }

    @staticmethod
    def _anchor_json(anchor: PolicyTrustAnchor) -> bytes:
        return canonical_json(
            {
                "teamId": anchor.team_id,
                "keyId": anchor.key_id,
                "publicKeyHex": anchor.public_key.hex(),
                "allowedProjectIds": list(anchor.allowed_project_ids),
                "notBefore": _time_text(anchor.not_before),
                "notAfter": _time_text(anchor.not_after),
            }
        ).encode("utf-8")

    @staticmethod
    def _anchor_from_json(raw: bytes) -> PolicyTrustAnchor:
        value = SQLiteTeamAuthority._document_like(raw)
        if frozenset(value) != frozenset(
            {
                "teamId",
                "keyId",
                "publicKeyHex",
                "allowedProjectIds",
                "notBefore",
                "notAfter",
            }
        ):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        try:
            public_key = bytes.fromhex(value["publicKeyHex"])
            return PolicyTrustAnchor(
                team_id=value["teamId"],
                key_id=value["keyId"],
                public_key=public_key,
                allowed_project_ids=tuple(value["allowedProjectIds"]),
                not_before=_parse_time(value["notBefore"]),
                not_after=_parse_time(value["notAfter"]),
            )
        except (TypeError, ValueError, RuntimePolicyError) as exc:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc

    def _lineage_payload(self, values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": "eco-team-authority-lineage-v1",
            "successorStoreId": self._store_id,
            "predecessorStoreId": values["predecessor_store_id"],
            "predecessorSnapshotDigest": values[
                "predecessor_snapshot_digest"
            ],
            "rotationId": values["rotation_id"],
            "rotationEnvelopeDigest": values["rotation_envelope_digest"],
            "rotationCommitmentDigest": values[
                "rotation_commitment_digest"
            ],
            "successorLocationDigest": values[
                "successor_location_digest"
            ],
            "rawRotationSha256": hashlib.sha256(
                bytes(values["raw_rotation"])
            ).hexdigest(),
            "oldAnchorSha256": hashlib.sha256(
                bytes(values["old_anchor_json"])
            ).hexdigest(),
            "newAnchorSha256": hashlib.sha256(
                bytes(values["new_anchor_json"])
            ).hexdigest(),
            "inheritedRevocationEpoch": values[
                "inherited_revocation_epoch"
            ],
            "inheritedRevocationHeadDigest": values[
                "inherited_revocation_head_digest"
            ],
            "inheritedRevocationSetDigest": values[
                "inherited_revocation_set_digest"
            ],
            "beforeSnapshotDigest": values["before_snapshot_digest"],
            "afterSnapshotDigest": values["after_snapshot_digest"],
            "recordedAt": values["recorded_at"],
            "keyId": values["key_id"],
        }

    def _inherited_revocation_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-inherited-revocation-v1",
            "storeId": self._store_id,
            "sourceRevocationId": values["source_revocation_id"],
            "subjectKind": values["subject_kind"],
            "subjectId": values["subject_id"],
            "subjectDigest": values["subject_digest"],
            "reasonCode": values["reason_code"],
            "sourceRevocationDigest": values["source_revocation_digest"],
            "keyId": values["key_id"],
        }

    def _rotation_reservation_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-rotation-reservation-v1",
            "predecessorStoreId": self._store_id,
            "rotationId": values["rotation_id"],
            "commitmentDigest": values["commitment_digest"],
            "rotationEnvelopeDigest": values["rotation_envelope_digest"],
            "successorStoreId": values["successor_store_id"],
            "successorLocationDigest": values[
                "successor_location_digest"
            ],
            "successorAnchorDigest": values["successor_anchor_digest"],
            "successorPolicyDigest": values["successor_policy_digest"],
            "predecessorSnapshotDigest": values[
                "predecessor_snapshot_digest"
            ],
            "inheritedRevocationEpoch": values[
                "inherited_revocation_epoch"
            ],
            "inheritedRevocationHeadDigest": values[
                "inherited_revocation_head_digest"
            ],
            "inheritedRevocationSetDigest": values[
                "inherited_revocation_set_digest"
            ],
            "rawRotationSha256": hashlib.sha256(
                bytes(values["raw_rotation"])
            ).hexdigest(),
            "newAnchorSha256": hashlib.sha256(
                bytes(values["new_anchor_json"])
            ).hexdigest(),
            "beforeSnapshotDigest": values["before_snapshot_digest"],
            "afterSnapshotDigest": values["after_snapshot_digest"],
            "eventDigest": values["event_digest"],
            "reservedAt": values["reserved_at"],
            "keyId": values["key_id"],
        }

    def _rotation_finalization_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-rotation-finalization-v1",
            "predecessorStoreId": self._store_id,
            "rotationId": values["rotation_id"],
            "commitmentDigest": values["commitment_digest"],
            "successorStoreId": values["successor_store_id"],
            "successorLocationDigest": values[
                "successor_location_digest"
            ],
            "successorSnapshotDigest": values[
                "successor_snapshot_digest"
            ],
            "beforeSnapshotDigest": values["before_snapshot_digest"],
            "afterSnapshotDigest": values["after_snapshot_digest"],
            "eventDigest": values["event_digest"],
            "finalizedAt": values["finalized_at"],
            "keyId": values["key_id"],
        }

    def _generation_finalization_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-generation-finalization-v1",
            "successorStoreId": self._store_id,
            "rotationCommitmentDigest": values[
                "rotation_commitment_digest"
            ],
            "successorLocationDigest": values[
                "successor_location_digest"
            ],
            "activePolicyDigest": values["active_policy_digest"],
            "beforeSnapshotDigest": values["before_snapshot_digest"],
            "afterSnapshotDigest": values["after_snapshot_digest"],
            "finalizedAt": values["finalized_at"],
            "keyId": values["key_id"],
        }

    def _sign(self, payload: Mapping[str, Any], *, key_id: str | None = None) -> str:
        selected = key_id or self._key_id
        key = self._audit_keys.get(selected)
        if key is None:
            raise _error("ECO_TEAM_AUTHORITY_KEY_UNKNOWN")
        return hmac.new(
            key, canonical_json(dict(payload)).encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _initialize_or_verify(self) -> None:
        app_id = self._connection.execute("PRAGMA application_id").fetchone()[0]
        version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if app_id not in {0, TEAM_AUTHORITY_APPLICATION_ID} or version not in {
            0,
            TEAM_AUTHORITY_SCHEMA_VERSION,
        }:
            raise _error("ECO_TEAM_AUTHORITY_PROFILE_MISMATCH")
        if version == 0:
            now = _time_text(datetime.now(timezone.utc))
            store_id = self._requested_store_id or f"team-authority:{secrets.token_hex(12)}"
            self._connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                CREATE TABLE store_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    store_id TEXT NOT NULL, application_id INTEGER NOT NULL,
                    schema_version INTEGER NOT NULL, team_id TEXT NOT NULL,
                    project_id TEXT NOT NULL, trust_anchor_digest TEXT NOT NULL,
                    audit_key_id TEXT NOT NULL, generation_profile TEXT NOT NULL
                    CHECK(generation_profile IN ('root','successor')),
                    created_at TEXT NOT NULL,
                    meta_hmac TEXT NOT NULL
                );
                CREATE TABLE authority_heads (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    state_revision INTEGER NOT NULL CHECK(state_revision>=0),
                    policy_epoch INTEGER NOT NULL CHECK(policy_epoch>=0),
                    identity_epoch INTEGER NOT NULL CHECK(identity_epoch>=0),
                    revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch>=0),
                    emergency_epoch INTEGER NOT NULL CHECK(emergency_epoch>=0),
                    active_policy_id TEXT, active_policy_revision INTEGER NOT NULL CHECK(active_policy_revision>=0),
                    active_policy_digest TEXT NOT NULL, identity_catalog_digest TEXT NOT NULL,
                    revocation_head_digest TEXT NOT NULL, emergency_deny INTEGER NOT NULL CHECK(emergency_deny IN (0,1)),
                    emergency_head_digest TEXT NOT NULL, snapshot_digest TEXT NOT NULL,
                    generation_status TEXT NOT NULL CHECK(generation_status IN
                        ('active','pending-successor','rotation-pending','retired')),
                    rotation_commitment_digest TEXT NOT NULL,
                    last_observed_epoch_us INTEGER NOT NULL CHECK(last_observed_epoch_us>=0),
                    updated_at TEXT NOT NULL, state_hmac TEXT NOT NULL
                );
                CREATE TABLE audit_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, transaction_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, action TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, previous_entry_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE, hmac_tag TEXT NOT NULL,
                    key_id TEXT NOT NULL, occurred_at TEXT NOT NULL
                );
                CREATE TABLE policy_activations (
                    activation_id TEXT PRIMARY KEY, envelope_id TEXT NOT NULL UNIQUE,
                    envelope_digest TEXT NOT NULL UNIQUE, bundle_id TEXT NOT NULL,
                    bundle_revision INTEGER NOT NULL UNIQUE CHECK(bundle_revision>=1),
                    bundle_digest TEXT NOT NULL UNIQUE, previous_revision INTEGER NOT NULL,
                    previous_digest TEXT NOT NULL, identity_catalog_digest TEXT NOT NULL,
                    raw_sha256 TEXT NOT NULL, raw_envelope BLOB NOT NULL,
                    before_snapshot_digest TEXT NOT NULL, after_snapshot_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL UNIQUE, activated_at TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence)
                );
                CREATE TABLE revocations (
                    revocation_id TEXT PRIMARY KEY, subject_kind TEXT NOT NULL,
                    subject_id TEXT NOT NULL, subject_digest TEXT NOT NULL,
                    reason_code TEXT NOT NULL, previous_head_digest TEXT NOT NULL,
                    revocation_digest TEXT NOT NULL UNIQUE,
                    before_snapshot_digest TEXT NOT NULL, after_snapshot_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL UNIQUE, revoked_at TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence),
                    UNIQUE(subject_kind,subject_id)
                );
                CREATE TABLE emergency_events (
                    event_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    reason_code TEXT NOT NULL, previous_head_digest TEXT NOT NULL,
                    emergency_digest TEXT NOT NULL UNIQUE,
                    before_snapshot_digest TEXT NOT NULL, after_snapshot_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL UNIQUE, occurred_at TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence)
                );
                CREATE TABLE rotation_reservations (
                    rotation_id TEXT PRIMARY KEY, commitment_digest TEXT NOT NULL UNIQUE,
                    rotation_envelope_digest TEXT NOT NULL, successor_store_id TEXT NOT NULL,
                    successor_location_digest TEXT NOT NULL,
                    successor_anchor_digest TEXT NOT NULL, successor_policy_digest TEXT NOT NULL,
                    predecessor_snapshot_digest TEXT NOT NULL,
                    inherited_revocation_epoch INTEGER NOT NULL,
                    inherited_revocation_head_digest TEXT NOT NULL,
                    inherited_revocation_set_digest TEXT NOT NULL,
                    raw_rotation BLOB NOT NULL, new_anchor_json BLOB NOT NULL,
                    before_snapshot_digest TEXT NOT NULL, after_snapshot_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL UNIQUE, reserved_at TEXT NOT NULL,
                    key_id TEXT NOT NULL, row_hmac TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence)
                );
                CREATE TABLE rotation_finalizations (
                    rotation_id TEXT PRIMARY KEY REFERENCES rotation_reservations(rotation_id),
                    commitment_digest TEXT NOT NULL UNIQUE, successor_store_id TEXT NOT NULL,
                    successor_location_digest TEXT NOT NULL,
                    successor_snapshot_digest TEXT NOT NULL,
                    before_snapshot_digest TEXT NOT NULL, after_snapshot_digest TEXT NOT NULL,
                    event_digest TEXT NOT NULL UNIQUE, finalized_at TEXT NOT NULL,
                    key_id TEXT NOT NULL, row_hmac TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence)
                );
                CREATE TABLE permit_consumptions (
                    permit_digest TEXT PRIMARY KEY,
                    consumption_nonce_digest TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    resource_digest TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    revocation_epoch INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                );
                CREATE TABLE issued_permits (
                    permit_digest TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL UNIQUE,
                    snapshot_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    revocation_epoch INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    raw_material BLOB NOT NULL,
                    key_id TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                );
                CREATE TABLE recovery_evidence (
                    event_id TEXT PRIMARY KEY REFERENCES emergency_events(event_id),
                    request_digest TEXT NOT NULL UNIQUE,
                    permit_digest TEXT NOT NULL UNIQUE,
                    evidence_digest TEXT NOT NULL UNIQUE,
                    raw_material BLOB NOT NULL,
                    key_id TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                );
                CREATE TABLE authority_lineage (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    predecessor_store_id TEXT NOT NULL,
                    predecessor_snapshot_digest TEXT NOT NULL,
                    rotation_id TEXT NOT NULL UNIQUE,
                    rotation_envelope_digest TEXT NOT NULL UNIQUE,
                    rotation_commitment_digest TEXT NOT NULL UNIQUE,
                    successor_location_digest TEXT NOT NULL,
                    raw_rotation BLOB NOT NULL,
                    old_anchor_json BLOB NOT NULL,
                    new_anchor_json BLOB NOT NULL,
                    inherited_revocation_epoch INTEGER NOT NULL,
                    inherited_revocation_head_digest TEXT NOT NULL,
                    inherited_revocation_set_digest TEXT NOT NULL,
                    before_snapshot_digest TEXT NOT NULL,
                    after_snapshot_digest TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                );
                CREATE TABLE inherited_revocations (
                    source_revocation_id TEXT PRIMARY KEY,
                    subject_kind TEXT NOT NULL, subject_id TEXT NOT NULL,
                    subject_digest TEXT NOT NULL, reason_code TEXT NOT NULL,
                    source_revocation_digest TEXT NOT NULL UNIQUE,
                    key_id TEXT NOT NULL, row_hmac TEXT NOT NULL,
                    UNIQUE(subject_kind,subject_id)
                );
                CREATE TABLE generation_finalizations (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    rotation_commitment_digest TEXT NOT NULL UNIQUE,
                    successor_location_digest TEXT NOT NULL,
                    active_policy_digest TEXT NOT NULL,
                    before_snapshot_digest TEXT NOT NULL,
                    after_snapshot_digest TEXT NOT NULL,
                    finalized_at TEXT NOT NULL, key_id TEXT NOT NULL,
                    row_hmac TEXT NOT NULL
                );
                CREATE TRIGGER policy_activations_immutable_update BEFORE UPDATE ON policy_activations
                    BEGIN SELECT RAISE(ABORT,'immutable policy activation'); END;
                CREATE TRIGGER policy_activations_immutable_delete BEFORE DELETE ON policy_activations
                    BEGIN SELECT RAISE(ABORT,'immutable policy activation'); END;
                CREATE TRIGGER revocations_immutable_update BEFORE UPDATE ON revocations
                    BEGIN SELECT RAISE(ABORT,'immutable revocation'); END;
                CREATE TRIGGER revocations_immutable_delete BEFORE DELETE ON revocations
                    BEGIN SELECT RAISE(ABORT,'immutable revocation'); END;
                CREATE TRIGGER emergency_events_immutable_update BEFORE UPDATE ON emergency_events
                    BEGIN SELECT RAISE(ABORT,'immutable emergency event'); END;
                CREATE TRIGGER emergency_events_immutable_delete BEFORE DELETE ON emergency_events
                    BEGIN SELECT RAISE(ABORT,'immutable emergency event'); END;
                CREATE TRIGGER recovery_evidence_immutable_update BEFORE UPDATE ON recovery_evidence
                    BEGIN SELECT RAISE(ABORT,'immutable recovery evidence'); END;
                CREATE TRIGGER recovery_evidence_immutable_delete BEFORE DELETE ON recovery_evidence
                    BEGIN SELECT RAISE(ABORT,'immutable recovery evidence'); END;
                CREATE TRIGGER authority_lineage_immutable_update BEFORE UPDATE ON authority_lineage
                    BEGIN SELECT RAISE(ABORT,'immutable authority lineage'); END;
                CREATE TRIGGER authority_lineage_immutable_delete BEFORE DELETE ON authority_lineage
                    BEGIN SELECT RAISE(ABORT,'immutable authority lineage'); END;
                CREATE TRIGGER inherited_revocations_immutable_update BEFORE UPDATE ON inherited_revocations
                    BEGIN SELECT RAISE(ABORT,'immutable inherited revocation'); END;
                CREATE TRIGGER inherited_revocations_immutable_delete BEFORE DELETE ON inherited_revocations
                    BEGIN SELECT RAISE(ABORT,'immutable inherited revocation'); END;
                CREATE TRIGGER rotation_reservations_immutable_update BEFORE UPDATE ON rotation_reservations
                    BEGIN SELECT RAISE(ABORT,'immutable rotation reservation'); END;
                CREATE TRIGGER rotation_reservations_immutable_delete BEFORE DELETE ON rotation_reservations
                    BEGIN SELECT RAISE(ABORT,'immutable rotation reservation'); END;
                CREATE TRIGGER rotation_finalizations_immutable_update BEFORE UPDATE ON rotation_finalizations
                    BEGIN SELECT RAISE(ABORT,'immutable rotation finalization'); END;
                CREATE TRIGGER rotation_finalizations_immutable_delete BEFORE DELETE ON rotation_finalizations
                    BEGIN SELECT RAISE(ABORT,'immutable rotation finalization'); END;
                CREATE TRIGGER generation_finalizations_immutable_update BEFORE UPDATE ON generation_finalizations
                    BEGIN SELECT RAISE(ABORT,'immutable generation finalization'); END;
                CREATE TRIGGER generation_finalizations_immutable_delete BEFORE DELETE ON generation_finalizations
                    BEGIN SELECT RAISE(ABORT,'immutable generation finalization'); END;
                CREATE TRIGGER audit_entries_immutable_update BEFORE UPDATE ON audit_entries
                    BEGIN SELECT RAISE(ABORT,'immutable audit entry'); END;
                CREATE TRIGGER audit_entries_immutable_delete BEFORE DELETE ON audit_entries
                    BEGIN SELECT RAISE(ABORT,'immutable audit entry'); END;
                PRAGMA application_id={TEAM_AUTHORITY_APPLICATION_ID};
                PRAGMA user_version={TEAM_AUTHORITY_SCHEMA_VERSION};
                COMMIT;
                """
            )
            meta = {
                "store_id": store_id,
                "application_id": TEAM_AUTHORITY_APPLICATION_ID,
                "schema_version": TEAM_AUTHORITY_SCHEMA_VERSION,
                "team_id": self._anchor.team_id,
                "project_id": self._project_id,
                "trust_anchor_digest": self._anchor_digest,
                "audit_key_id": self._key_id,
                "generation_profile": self._requested_generation_profile,
                "created_at": now,
            }
            meta_hmac = self._sign(self._meta_payload(meta))
            # The generated identity is part of the genesis snapshot itself.
            self._store_id = store_id
            self._generation_profile = self._requested_generation_profile
            state = self._genesis_state(now)
            state["state_hmac"] = self._state_hmac(state)
            with self._transaction():
                self._connection.execute(
                    "INSERT INTO store_meta VALUES (1,?,?,?,?,?,?,?,?,?,?)",
                    (
                        store_id,
                        TEAM_AUTHORITY_APPLICATION_ID,
                        TEAM_AUTHORITY_SCHEMA_VERSION,
                        self._anchor.team_id,
                        self._project_id,
                        self._anchor_digest,
                        self._key_id,
                        self._requested_generation_profile,
                        now,
                        meta_hmac,
                    ),
                )
                self._insert_heads(state)
        meta = self._connection.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
        if meta is None:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        verification_key = self._audit_keys.get(meta["audit_key_id"])
        if verification_key is None or meta["audit_key_id"] != self._key_id:
            raise _error("ECO_TEAM_AUTHORITY_KEY_MISMATCH")
        expected = hmac.new(
            verification_key,
            canonical_json(self._meta_payload(meta)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if (
            meta["application_id"] != TEAM_AUTHORITY_APPLICATION_ID
            or meta["schema_version"] != TEAM_AUTHORITY_SCHEMA_VERSION
            or meta["team_id"] != self._anchor.team_id
            or meta["project_id"] != self._project_id
            or meta["trust_anchor_digest"] != self._anchor_digest
            or meta["generation_profile"] not in _GENERATION_PROFILES
            or not hmac.compare_digest(meta["meta_hmac"], expected)
            or (self._requested_store_id is not None and meta["store_id"] != self._requested_store_id)
        ):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        self._store_id = meta["store_id"]
        self._generation_profile = meta["generation_profile"]

    def _genesis_state(self, now_text: str) -> dict[str, Any]:
        state = {
            "state_revision": 0,
            "policy_epoch": 0,
            "identity_epoch": 0,
            "revocation_epoch": 0,
            "emergency_epoch": 0,
            "active_policy_id": None,
            "active_policy_revision": 0,
            "active_policy_digest": GENESIS_DIGEST,
            "identity_catalog_digest": GENESIS_DIGEST,
            "revocation_head_digest": GENESIS_DIGEST,
            "emergency_deny": 0,
            "emergency_head_digest": GENESIS_DIGEST,
            "generation_status": (
                "pending-successor"
                if self._generation_profile == "successor"
                else "active"
            ),
            "rotation_commitment_digest": GENESIS_DIGEST,
            # Store creation is not an authority command and must not prevent an
            # operator from activating a still-valid envelope whose explicit
            # observation time predates the filesystem initialization instant.
            "last_observed_epoch_us": 0,
            "updated_at": now_text,
        }
        state["snapshot_digest"] = self._snapshot_digest(state)
        return state

    def _snapshot_digest(self, state: Mapping[str, Any]) -> str:
        return semantic_digest(
            {
                "domain": "eco-team-authority-snapshot-v1",
                "storeId": getattr(self, "_store_id", self._requested_store_id),
                "teamId": self._anchor.team_id,
                "projectId": self._project_id,
                "trustAnchorDigest": self._anchor_digest,
                "stateRevision": state["state_revision"],
                "epochs": {
                    "policy": state["policy_epoch"],
                    "identity": state["identity_epoch"],
                    "revocation": state["revocation_epoch"],
                    "emergency": state["emergency_epoch"],
                },
                "activePolicy": {
                    "id": state["active_policy_id"],
                    "revision": state["active_policy_revision"],
                    "digest": state["active_policy_digest"],
                },
                "identityCatalogDigest": state["identity_catalog_digest"],
                "revocationHeadDigest": state["revocation_head_digest"],
                "emergencyDeny": bool(state["emergency_deny"]),
                "emergencyHeadDigest": state["emergency_head_digest"],
                "generationStatus": state["generation_status"],
                "rotationCommitmentDigest": state[
                    "rotation_commitment_digest"
                ],
            }
        )

    @staticmethod
    def _state_payload(state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: state[key]
            for key in (
                "state_revision",
                "policy_epoch",
                "identity_epoch",
                "revocation_epoch",
                "emergency_epoch",
                "active_policy_id",
                "active_policy_revision",
                "active_policy_digest",
                "identity_catalog_digest",
                "revocation_head_digest",
                "emergency_deny",
                "emergency_head_digest",
                "snapshot_digest",
                "generation_status",
                "rotation_commitment_digest",
                "last_observed_epoch_us",
                "updated_at",
            )
        }

    def _state_hmac(self, state: Mapping[str, Any]) -> str:
        return self._sign(
            {
                "domain": "eco-team-authority-heads-v1",
                "storeId": getattr(self, "_store_id", self._requested_store_id),
                "state": self._state_payload(state),
            }
        )

    def _insert_heads(self, state: Mapping[str, Any]) -> None:
        self._connection.execute(
            "INSERT INTO authority_heads VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(self._state_payload(state).values()) + (state["state_hmac"],),
        )

    def _write_heads(self, state: dict[str, Any]) -> None:
        state["snapshot_digest"] = self._snapshot_digest(state)
        state["state_hmac"] = self._state_hmac(state)
        values = tuple(self._state_payload(state).values()) + (state["state_hmac"],)
        self._connection.execute(
            """UPDATE authority_heads SET state_revision=?,policy_epoch=?,identity_epoch=?,
            revocation_epoch=?,emergency_epoch=?,active_policy_id=?,active_policy_revision=?,
            active_policy_digest=?,identity_catalog_digest=?,revocation_head_digest=?,
            emergency_deny=?,emergency_head_digest=?,snapshot_digest=?,generation_status=?,
            rotation_commitment_digest=?,last_observed_epoch_us=?,
            updated_at=?,state_hmac=? WHERE singleton=1""",
            values,
        )

    @staticmethod
    def _revocation_set_digest(records: Sequence[Mapping[str, Any]]) -> str:
        normalized = sorted(
            (dict(record) for record in records),
            key=lambda item: (item["subjectKind"], item["subjectId"]),
        )
        return semantic_digest(
            {
                "domain": "eco-team-revocation-set-v1",
                "records": normalized,
            }
        )

    def _revocation_export_locked(self) -> tuple[dict[str, Any], ...]:
        records: list[dict[str, Any]] = []
        for row in self._connection.execute(
            "SELECT * FROM inherited_revocations ORDER BY subject_kind,subject_id"
        ):
            records.append(
                {
                    "revocationId": row["source_revocation_id"],
                    "subjectKind": row["subject_kind"],
                    "subjectId": row["subject_id"],
                    "subjectDigest": row["subject_digest"],
                    "reasonCode": row["reason_code"],
                    "revocationDigest": row["source_revocation_digest"],
                }
            )
        for row in self._connection.execute(
            "SELECT * FROM revocations ORDER BY subject_kind,subject_id"
        ):
            records.append(
                {
                    "revocationId": row["revocation_id"],
                    "subjectKind": row["subject_kind"],
                    "subjectId": row["subject_id"],
                    "subjectDigest": row["subject_digest"],
                    "reasonCode": row["reason_code"],
                    "revocationDigest": row["revocation_digest"],
                }
            )
        return tuple(
            sorted(records, key=lambda item: (item["subjectKind"], item["subjectId"]))
        )

    def _verify_revocations_locked(self, state: Mapping[str, Any]) -> None:
        base_epoch = 0
        base_head = GENESIS_DIGEST
        inherited: list[dict[str, Any]] = []
        lineage = self._connection.execute(
            "SELECT * FROM authority_lineage WHERE singleton=1"
        ).fetchone()
        if lineage is not None:
            lineage_values = dict(lineage)
            lineage_values.pop("singleton")
            lineage_tag = lineage_values.pop("row_hmac")
            if (
                self._generation_profile != "successor"
                or not hmac.compare_digest(
                    lineage_tag,
                    self._sign(
                        self._lineage_payload(lineage_values),
                        key_id=lineage_values["key_id"],
                    ),
                )
            ):
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            base_epoch = lineage_values["inherited_revocation_epoch"]
            base_head = lineage_values["inherited_revocation_head_digest"]
            for row in self._connection.execute(
                "SELECT * FROM inherited_revocations ORDER BY subject_kind,subject_id"
            ):
                values = dict(row)
                tag = values.pop("row_hmac")
                if not hmac.compare_digest(
                    tag,
                    self._sign(
                        self._inherited_revocation_payload(values),
                        key_id=values["key_id"],
                    ),
                ):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                inherited.append(
                    {
                        "revocationId": values["source_revocation_id"],
                        "subjectKind": values["subject_kind"],
                        "subjectId": values["subject_id"],
                        "subjectDigest": values["subject_digest"],
                        "reasonCode": values["reason_code"],
                        "revocationDigest": values["source_revocation_digest"],
                    }
                )
            if (
                len(inherited) != base_epoch
                or self._revocation_set_digest(inherited)
                != lineage_values["inherited_revocation_set_digest"]
            ):
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        elif self._connection.execute(
            "SELECT 1 FROM inherited_revocations LIMIT 1"
        ).fetchone() is not None:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

        seen = {(item["subjectKind"], item["subjectId"]) for item in inherited}
        head = base_head
        local_count = 0
        for row in self._connection.execute(
            "SELECT * FROM revocations ORDER BY audit_sequence"
        ):
            key = (row["subject_kind"], row["subject_id"])
            revocation_digest = semantic_digest(
                {
                    "domain": "eco-team-revocation-v1",
                    "revocationId": row["revocation_id"],
                    "subject": {
                        "kind": row["subject_kind"],
                        "id": row["subject_id"],
                        "digest": row["subject_digest"],
                    },
                    "reasonCode": row["reason_code"],
                    "previousHeadDigest": row["previous_head_digest"],
                    "authoritySnapshotDigest": row["before_snapshot_digest"],
                    "revokedAt": row["revoked_at"],
                }
            )
            if (
                key in seen
                or row["previous_head_digest"] != head
                or row["revocation_digest"] != revocation_digest
            ):
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            seen.add(key)
            head = semantic_digest(
                {
                    "domain": "eco-team-revocation-chain-v1",
                    "previous": head,
                    "record": revocation_digest,
                }
            )
            local_count += 1
        if (
            state["revocation_epoch"] != base_epoch + local_count
            or state["revocation_head_digest"] != head
        ):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

    def _verify_generation_locked(self, state: Mapping[str, Any]) -> None:
        reservation = self._connection.execute(
            "SELECT * FROM rotation_reservations"
        ).fetchall()
        finalizations = self._connection.execute(
            "SELECT * FROM rotation_finalizations"
        ).fetchall()
        if state["generation_status"] in {"rotation-pending", "retired"}:
            if len(reservation) != 1:
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            values = dict(reservation[0])
            tag = values.pop("row_hmac")
            values.pop("audit_sequence")
            if (
                values["commitment_digest"]
                != state["rotation_commitment_digest"]
                or not hmac.compare_digest(
                    tag,
                    self._sign(
                        self._rotation_reservation_payload(values),
                        key_id=values["key_id"],
                    ),
                )
            ):
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            if state["generation_status"] == "retired":
                if len(finalizations) != 1:
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                values = dict(finalizations[0])
                tag = values.pop("row_hmac")
                values.pop("audit_sequence")
                if not hmac.compare_digest(
                    tag,
                    self._sign(
                        self._rotation_finalization_payload(values),
                        key_id=values["key_id"],
                    ),
                ):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            elif finalizations:
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        elif reservation or finalizations:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

        successor_finalization = self._connection.execute(
            "SELECT * FROM generation_finalizations"
        ).fetchall()
        if self._generation_profile == "successor" and state[
            "generation_status"
        ] == "active":
            if len(successor_finalization) != 1:
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
            values = dict(successor_finalization[0])
            values.pop("singleton")
            tag = values.pop("row_hmac")
            lineage = self._connection.execute(
                "SELECT successor_location_digest FROM authority_lineage "
                "WHERE singleton=1"
            ).fetchone()
            if (
                lineage is None
                or lineage["successor_location_digest"]
                != values["successor_location_digest"]
                or not hmac.compare_digest(
                    tag,
                    self._sign(
                        self._generation_finalization_payload(values),
                        key_id=values["key_id"],
                    ),
                )
            ):
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        elif successor_finalization:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

    def _heads(self) -> dict[str, Any]:
        row = self._connection.execute("SELECT * FROM authority_heads WHERE singleton=1").fetchone()
        if row is None:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        result = dict(row)
        result.pop("singleton", None)
        if not hmac.compare_digest(result["state_hmac"], self._state_hmac(result)):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        self._verify_revocations_locked(result)
        self._verify_generation_locked(result)
        return result

    def _observe_clock(self, state: Mapping[str, Any], now: datetime) -> tuple[str, int]:
        text = _time_text(now)
        epoch = _epoch_us(now)
        if epoch < state["last_observed_epoch_us"]:
            raise _error("ECO_TEAM_AUTHORITY_CLOCK_ROLLBACK")
        return text, epoch

    def _append_audit(
        self,
        *,
        transaction_id: str,
        entity_type: str,
        entity_id: str,
        action: str,
        payload_digest: str,
        occurred_at: str,
    ) -> int:
        previous = self._connection.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else GENESIS_DIGEST
        sequence = self._connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM audit_entries"
        ).fetchone()[0]
        payload = {
            "domain": "eco-team-authority-audit-v1",
            "storeId": self._store_id,
            "sequence": sequence,
            "transactionId": transaction_id,
            "entityType": entity_type,
            "entityId": entity_id,
            "action": action,
            "payloadDigest": payload_digest,
            "previousEntryHash": previous_hash,
            "occurredAt": occurred_at,
        }
        entry_hash = semantic_digest(payload)
        tag = hmac.new(
            self._hmac_key, bytes.fromhex(entry_hash), hashlib.sha256
        ).hexdigest()
        self._connection.execute(
            "INSERT INTO audit_entries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence,
                transaction_id,
                entity_type,
                entity_id,
                action,
                payload_digest,
                previous_hash,
                entry_hash,
                tag,
                self._key_id,
                occurred_at,
            ),
        )
        return int(sequence)

    @staticmethod
    def _document(raw: bytes) -> dict[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _error("ECO_TEAM_AUTHORITY_POLICY_INVALID") from exc
        if not isinstance(value, dict) or not isinstance(value.get("bundle"), dict):
            raise _error("ECO_TEAM_AUTHORITY_POLICY_INVALID")
        return value

    @staticmethod
    def _document_like(raw: bytes) -> dict[str, Any]:
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
        if not isinstance(value, dict):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        return value

    @staticmethod
    def _identity_digest(document: Mapping[str, Any]) -> str:
        documents = document["bundle"]["spec"]["documents"]
        return semantic_digest(
            {
                "domain": "eco-team-authority-identity-catalog-v1",
                "documents": {
                    name: documents[name]
                    for name in ("teams", "principals", "memberships", "keys")
                },
            }
        )

    @staticmethod
    def _active_records(document: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        records: list[dict[str, Any]] = []
        for catalog in document["bundle"]["spec"]["documents"].values():
            for record in catalog:
                if record["spec"].get("status") == "active":
                    records.append(record)
        return tuple(records)

    def _active_document_locked(self) -> tuple[sqlite3.Row, dict[str, Any]]:
        row = self._connection.execute(
            "SELECT * FROM policy_activations ORDER BY bundle_revision DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise _error("ECO_TEAM_AUTHORITY_POLICY_MISSING")
        raw = bytes(row["raw_envelope"])
        if _raw_sha256(raw) != row["raw_sha256"]:
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        return row, self._document(raw)

    @staticmethod
    def _access_policy(document: Mapping[str, Any]) -> dict[str, Any]:
        policies = document["bundle"]["spec"]["documents"].get(
            "accessPolicies", []
        )
        if len(policies) != 1:
            raise _error("ECO_TEAM_AUTHORITY_ACCESS_POLICY_MISSING")
        return policies[0]

    @classmethod
    def _approval_policy_binding(
        cls, document: Mapping[str, Any], *, revocation_epoch: int
    ) -> dict[str, Any]:
        bundle = document["bundle"]
        access_policy = cls._access_policy(document)
        return {
            "id": access_policy["metadata"]["id"],
            "revision": access_policy["metadata"]["revision"],
            "digest": approval_policy_context_digest(
                bundle_id=bundle["metadata"]["id"],
                bundle_revision=bundle["metadata"]["revision"],
                team=bundle["spec"]["team"],
                target_project_ids=bundle["spec"]["targetProjectIds"],
                access_policy_id=access_policy["metadata"]["id"],
                access_policy_revision=access_policy["metadata"]["revision"],
            ),
            "revocationEpoch": revocation_epoch,
        }

    def _is_revoked_locked(self, *, subject_kind: str, subject_id: str) -> bool:
        local = self._connection.execute(
            "SELECT 1 FROM revocations WHERE subject_kind=? AND subject_id=?",
            (subject_kind, subject_id),
        ).fetchone()
        inherited = self._connection.execute(
            "SELECT 1 FROM inherited_revocations WHERE subject_kind=? AND subject_id=?",
            (subject_kind, subject_id),
        ).fetchone()
        return local is not None or inherited is not None

    def _assert_verifiable_locked(
        self,
        state: Mapping[str, Any],
        *,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        now_utc = _utc(now)
        if state["snapshot_digest"] != expected_snapshot_digest:
            raise _error("ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT")
        if state["active_policy_revision"] == 0:
            raise _error("ECO_TEAM_AUTHORITY_POLICY_MISSING")
        row, document = self._active_document_locked()
        previous = (row["previous_revision"], row["previous_digest"])
        try:
            verified = self._verifier.verify(
                bytes(row["raw_envelope"]),
                expected_project_id=self._project_id,
                now=now_utc,
                expected_previous=None if previous[0] == 0 else previous,
            )
        except RuntimePolicyError as exc:
            raise _error("ECO_TEAM_AUTHORITY_POLICY_INVALID") from exc
        if (
            verified.bundle_id != state["active_policy_id"]
            or verified.revision != state["active_policy_revision"]
            or verified.bundle_digest != state["active_policy_digest"]
            or verified.bundle_digest != row["bundle_digest"]
            or verified.envelope_digest != row["envelope_digest"]
        ):
            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
        if self._is_revoked_locked(
            subject_kind="TeamIdentity", subject_id=self._anchor.team_id
        ) or self._is_revoked_locked(
            subject_kind="IdentityKey", subject_id=self._anchor.key_id
        ):
            raise _error("ECO_TEAM_AUTHORITY_CRITICAL_REVOCATION")
        return document

    def _assert_live_locked(
        self,
        state: Mapping[str, Any],
        *,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        document = self._assert_verifiable_locked(
            state,
            expected_snapshot_digest=expected_snapshot_digest,
            now=now,
        )
        if state["generation_status"] != "active":
            raise _error("ECO_TEAM_AUTHORITY_GENERATION_INACTIVE")
        if state["emergency_deny"]:
            raise _error("ECO_TEAM_AUTHORITY_EMERGENCY_DENY")
        return document

    @staticmethod
    def _active_at(record: Mapping[str, Any], at: datetime) -> bool:
        validity = record["spec"].get("validity")
        return bool(
            record["spec"].get("status") == "active"
            and isinstance(validity, dict)
            and _parse_time(validity["notBefore"]) <= at < _parse_time(
                validity["notAfter"]
            )
        )

    def active_access_context(
        self,
        *,
        principal_id: str,
        membership_id: str,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Resolve caller identity only from the current signed catalog."""

        _require_id(principal_id)
        _require_id(membership_id)
        _require_digest(expected_snapshot_digest)
        observed = _utc(now)
        with self._lock:
            state = self._heads()
            document = self._assert_live_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=observed,
            )
            documents = document["bundle"]["spec"]["documents"]
            principal = next(
                (
                    item
                    for item in documents["principals"]
                    if item["metadata"]["id"] == principal_id
                ),
                None,
            )
            membership = next(
                (
                    item
                    for item in documents["memberships"]
                    if item["metadata"]["id"] == membership_id
                ),
                None,
            )
            if (
                principal is None
                or membership is None
                or not self._active_at(principal, observed)
                or not self._active_at(membership, observed)
                or membership["spec"]["principal"]
                != {
                    "kind": "PrincipalIdentity",
                    "id": principal_id,
                    "digest": principal["metadata"]["recordDigest"],
                }
                or membership["spec"]["team"]
                != document["bundle"]["spec"]["team"]
                or self._is_revoked_locked(
                    subject_kind="PrincipalIdentity", subject_id=principal_id
                )
                or self._is_revoked_locked(
                    subject_kind="MembershipBinding", subject_id=membership_id
                )
            ):
                raise _error("ECO_TEAM_AUTHORITY_ACTOR_INACTIVE")
            return {
                "accessPolicy": json.loads(canonical_json(self._access_policy(document))),
                "approvalProfiles": json.loads(
                    canonical_json(
                        documents.get("approvalProfiles", [])
                    )
                ),
                "principal": {
                    "kind": "PrincipalIdentity",
                    "id": principal_id,
                    "digest": principal["metadata"]["recordDigest"],
                },
                "membership": {
                    "kind": "MembershipBinding",
                    "id": membership_id,
                    "digest": membership["metadata"]["recordDigest"],
                },
                "authoritySnapshotDigest": state["snapshot_digest"],
                "activeBundleDigest": state["active_policy_digest"],
                "revocationEpoch": state["revocation_epoch"],
            }

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
    ) -> AuthenticatedActorAssertion:
        """Authenticate one exact actor operation using current signed identity state.

        Emergency recovery deliberately verifies identity without treating the
        emergency deny bit as an authentication failure.  Every runtime-effect
        assertion remains behind the ordinary live/emergency gate.
        """

        _require_digest(expected_snapshot_digest)
        _require_digest(expected_operation_digest)
        if expected_audience not in {"runtime-effect", "emergency-recovery"}:
            raise _error("ECO_TEAM_ACTOR_ASSERTION_INVALID")
        try:
            record = validate_actor_assertion(assertion)
        except RuntimePolicyError as exc:
            raise _error(exc.code, "Team actor authentication failed closed") from exc
        observed = _utc(now)
        spec = record["spec"]
        issued_at = _parse_time(spec["issuedAt"])
        expires_at = _parse_time(spec["expiresAt"])
        with self._lock:
            state = self._heads()
            assert_state = (
                self._assert_verifiable_locked
                if expected_audience == "emergency-recovery"
                else self._assert_live_locked
            )
            document = assert_state(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=observed,
            )
            documents = document["bundle"]["spec"]["documents"]
            principal = next(
                (
                    item
                    for item in documents["principals"]
                    if item["metadata"]["id"] == spec["principal"]["id"]
                ),
                None,
            )
            membership = next(
                (
                    item
                    for item in documents["memberships"]
                    if item["metadata"]["id"] == spec["membership"]["id"]
                ),
                None,
            )
            key = next(
                (
                    item
                    for item in documents["keys"]
                    if item["metadata"]["id"] == spec["keyId"]
                ),
                None,
            )
            principal_binding = (
                {
                    "kind": "PrincipalIdentity",
                    "id": principal["metadata"]["id"],
                    "digest": principal["metadata"]["recordDigest"],
                }
                if principal is not None
                else None
            )
            membership_binding = (
                {
                    "kind": "MembershipBinding",
                    "id": membership["metadata"]["id"],
                    "digest": membership["metadata"]["recordDigest"],
                }
                if membership is not None
                else None
            )
            team_binding = document["bundle"]["spec"]["team"]
            valid = (
                principal is not None
                and membership is not None
                and key is not None
                and dict(expected_principal) == principal_binding == spec["principal"]
                and dict(expected_membership) == membership_binding == spec["membership"]
                and spec["team"] == team_binding
                and spec["projectId"] == self._project_id
                and spec["authoritySnapshotDigest"] == expected_snapshot_digest
                and spec["audience"] == expected_audience
                and spec["operationDigest"] == expected_operation_digest
                and membership["spec"]["principal"] == principal_binding
                and membership["spec"]["team"] == team_binding
                and key["spec"]["subject"] == principal_binding
                and key["spec"]["purpose"] == "workload-authentication"
                and self._active_at(principal, observed)
                and self._active_at(membership, observed)
                and self._active_at(key, observed)
                and not self._is_revoked_locked(
                    subject_kind="PrincipalIdentity",
                    subject_id=principal["metadata"]["id"],
                )
                and not self._is_revoked_locked(
                    subject_kind="MembershipBinding",
                    subject_id=membership["metadata"]["id"],
                )
                and not self._is_revoked_locked(
                    subject_kind="IdentityKey", subject_id=key["metadata"]["id"]
                )
                and issued_at
                <= observed + timedelta(seconds=60)
                and observed < expires_at
                and expires_at - issued_at <= timedelta(minutes=5)
                and _parse_time(principal["spec"]["validity"]["notBefore"])
                <= issued_at
                and expires_at
                <= _parse_time(principal["spec"]["validity"]["notAfter"])
                and _parse_time(membership["spec"]["validity"]["notBefore"])
                <= issued_at
                and expires_at
                <= _parse_time(membership["spec"]["validity"]["notAfter"])
                and _parse_time(key["spec"]["validity"]["notBefore"])
                <= issued_at
                and expires_at <= _parse_time(key["spec"]["validity"]["notAfter"])
            )
            if not valid:
                raise _error("ECO_TEAM_ACTOR_ASSERTION_UNTRUSTED")
            try:
                public_key = decode_base64url(
                    key["spec"]["publicKey"]["value"], expected_bytes=32
                )
                signature = decode_base64url(
                    spec["signature"]["value"], expected_bytes=64
                )
                Ed25519PublicKey.from_public_bytes(public_key).verify(
                    signature, actor_assertion_message(record)
                )
            except (InvalidSignature, ValueError, RuntimePolicyError) as exc:
                raise _error("ECO_TEAM_ACTOR_ASSERTION_SIGNATURE_INVALID") from exc
            return authenticated_actor_assertion(
                record, issued_at=issued_at, expires_at=expires_at
            )

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
    ) -> ResolvedApprovalKey | None:
        """Implement the approval verifier's active-key resolver protocol."""

        try:
            observed = _utc(at)
            with self._lock:
                state = self._heads()
                document = self._assert_verifiable_locked(
                    state,
                    expected_snapshot_digest=state["snapshot_digest"],
                    now=observed,
                )
                documents = document["bundle"]["spec"]["documents"]
                access_policy = self._access_policy(document)
                approval_policy = self._approval_policy_binding(
                    document, revocation_epoch=state["revocation_epoch"]
                )
                profiles = documents.get("approvalProfiles", [])
                profile = next(
                    (
                        item
                        for item in profiles
                        if item["metadata"]["id"] == profile_id
                        and item["metadata"]["recordDigest"] == profile_digest
                    ),
                    None,
                )
                if (
                    team_id != self._anchor.team_id
                    or profile is None
                    or profile["spec"]["requiredApproverRole"] != required_role
                    or profile["spec"]["quorum"] != quorum
                    or policy_digest != approval_policy["digest"]
                    or revocation_epoch != state["revocation_epoch"]
                    or profile["spec"]["policy"]
                    != approval_policy
                    or not (
                        _parse_time(profile["spec"]["validity"]["notBefore"])
                        <= observed
                        < _parse_time(profile["spec"]["validity"]["notAfter"])
                    )
                ):
                    return None
                principal = next(
                    (
                        item
                        for item in documents["principals"]
                        if item["metadata"]["id"] == principal_id
                    ),
                    None,
                )
                if (
                    principal is None
                    or principal["spec"]["type"] != "human"
                    or principal["spec"]["controller"] is not None
                    or not self._active_at(principal, observed)
                ):
                    return None
                principal_binding = {
                    "kind": "PrincipalIdentity",
                    "id": principal_id,
                    "digest": principal["metadata"]["recordDigest"],
                }
                memberships = {
                    item["metadata"]["recordDigest"]: item
                    for item in documents["memberships"]
                    if item["spec"]["principal"] == principal_binding
                    and item["spec"]["team"] == document["bundle"]["spec"]["team"]
                    and self._active_at(item, observed)
                    and not self._is_revoked_locked(
                        subject_kind="MembershipBinding",
                        subject_id=item["metadata"]["id"],
                    )
                }
                roles = tuple(
                    sorted(
                        {
                            binding["roleId"]
                            for binding in access_policy["spec"]["bindings"]
                            if binding["principal"] == principal_binding
                            and binding["membership"]["digest"] in memberships
                        }
                    )
                )
                key = next(
                    (
                        item
                        for item in documents["keys"]
                        if item["metadata"]["id"] == key_id
                        and item["spec"]["subject"] == principal_binding
                        and item["spec"]["purpose"] == "approval-signing"
                        and self._active_at(item, observed)
                    ),
                    None,
                )
                if (
                    required_role not in roles
                    or len(memberships) != 1
                    or key is None
                    or self._is_revoked_locked(
                        subject_kind="PrincipalIdentity", subject_id=principal_id
                    )
                    or self._is_revoked_locked(
                        subject_kind="IdentityKey", subject_id=key_id
                    )
                ):
                    return None
                public_key = decode_base64url(
                    key["spec"]["publicKey"]["value"], expected_bytes=32
                )
                membership_digest = next(iter(memberships))
                return ResolvedApprovalKey(
                    team_id=team_id,
                    principal_id=principal_id,
                    key_id=key_id,
                    membership_digest=membership_digest,
                    roles=roles,
                    policy_digest=policy_digest,
                    revocation_epoch=revocation_epoch,
                    not_before=max(
                        _parse_time(principal["spec"]["validity"]["notBefore"]),
                        _parse_time(key["spec"]["validity"]["notBefore"]),
                    ),
                    not_after=min(
                        _parse_time(principal["spec"]["validity"]["notAfter"]),
                        _parse_time(key["spec"]["validity"]["notAfter"]),
                    ),
                    public_key=public_key,
                )
        except (RuntimeStoreError, RuntimePolicyError, ValueError, KeyError, TypeError):
            return None

    def _permit_consumption_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-permit-consumption-v1",
            "storeId": self._store_id,
            "permitDigest": values["permit_digest"],
            "consumptionNonceDigest": values["consumption_nonce_digest"],
            "requestDigest": values["request_digest"],
            "actionDigest": values["action_digest"],
            "resourceDigest": values["resource_digest"],
            "snapshotDigest": values["snapshot_digest"],
            "policyDigest": values["policy_digest"],
            "revocationEpoch": values["revocation_epoch"],
            "expiresAt": values["expires_at"],
            "consumedAt": values["consumed_at"],
            "receiptDigest": values["receipt_digest"],
            "keyId": values["key_id"],
        }

    def _issued_permit_payload(self, values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": "eco-team-issued-permit-v1",
            "storeId": self._store_id,
            "permitDigest": values["permit_digest"],
            "requestDigest": values["request_digest"],
            "snapshotDigest": values["snapshot_digest"],
            "policyDigest": values["policy_digest"],
            "revocationEpoch": values["revocation_epoch"],
            "expiresAt": values["expires_at"],
            "rawMaterialSha256": hashlib.sha256(
                bytes(values["raw_material"])
            ).hexdigest(),
            "keyId": values["key_id"],
        }

    def _recovery_evidence_payload(
        self, values: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            "domain": "eco-team-recovery-evidence-v1",
            "storeId": self._store_id,
            "eventId": values["event_id"],
            "requestDigest": values["request_digest"],
            "permitDigest": values["permit_digest"],
            "evidenceDigest": values["evidence_digest"],
            "rawMaterialSha256": hashlib.sha256(
                bytes(values["raw_material"])
            ).hexdigest(),
            "keyId": values["key_id"],
        }

    def issue_team_action_permit(
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
        """Verify and persist one quorum-derived A2 permit from signed policy state."""

        _require_id(permit_id)
        observed = _utc(now)
        with self._transaction():
            state = self._heads()
            document = self._assert_live_locked(
                state,
                expected_snapshot_digest=request.get("spec", {})
                .get("snapshot", {})
                .get("digest", ""),
                now=observed,
            )
            documents = document["bundle"]["spec"]["documents"]
            access_policy = self._access_policy(document)
            approval_policy = self._approval_policy_binding(
                document, revocation_epoch=state["revocation_epoch"]
            )
            signed_profile = next(
                (
                    item
                    for item in documents.get("approvalProfiles", [])
                    if item.get("metadata", {}).get("id")
                    == profile.get("metadata", {}).get("id")
                    and item.get("metadata", {}).get("recordDigest")
                    == profile.get("metadata", {}).get("recordDigest")
                ),
                None,
            )
            request_spec = request.get("spec", {})
            if (
                signed_profile is None
                or canonical_json(signed_profile) != canonical_json(profile)
                or signed_profile["spec"]["purpose"] != "runtime-action"
                or request_spec.get("action", {}).get("actionClass") != "A2"
                or request_spec.get("snapshot")
                != {
                    "kind": "AuthoritySnapshot",
                    "id": self._store_id,
                    "digest": state["snapshot_digest"],
                }
                or request_spec.get("policy") != approval_policy
            ):
                raise _error("ECO_TEAM_AUTHORITY_APPROVAL_BINDING_INVALID")
            permit = TeamApprovalVerifier(self).build_action_permit(
                signed_profile,
                request,
                votes,
                permit_id=permit_id,
                consumption_nonce=consumption_nonce,
                expected_requester_principal_id=expected_requester_principal_id,
                expected_requester_membership_digest=expected_requester_membership_digest,
                now=observed,
            )
            record = permit.as_dict()
            raw_material = canonical_json(
                {
                    "profile": signed_profile,
                    "request": request,
                    "votes": list(votes),
                    "permit": record,
                }
            ).encode("utf-8")
            values = {
                "permit_digest": permit.permit_digest,
                "request_digest": record["spec"]["request"]["digest"],
                "snapshot_digest": record["spec"]["snapshot"]["digest"],
                "policy_digest": record["spec"]["policy"]["digest"],
                "revocation_epoch": record["spec"]["policy"]["revocationEpoch"],
                "expires_at": record["spec"]["expiresAt"],
                "raw_material": raw_material,
                "key_id": self._key_id,
            }
            tag = self._sign(self._issued_permit_payload(values))
            try:
                self._connection.execute(
                    "INSERT INTO issued_permits VALUES (?,?,?,?,?,?,?,?,?)",
                    tuple(values.values()) + (tag,),
                )
            except sqlite3.IntegrityError as exc:
                raise _error("ECO_TEAM_AUTHORITY_APPROVAL_REPLAY") from exc
            return permit

    def assert_issued_action_permit(
        self,
        permit: VerifiedActionPermit,
        *,
        expected_snapshot_digest: str,
        expected_requester_principal_id: str,
        expected_requester_membership_digest: str,
        now: datetime,
    ) -> None:
        if not isinstance(permit, VerifiedActionPermit):
            raise _error("ECO_TEAM_AUTHORITY_PERMIT_INVALID")
        _require_digest(expected_snapshot_digest)
        observed = _utc(now)
        with self._lock:
            state = self._heads()
            self._assert_live_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=observed,
            )
            row = self._connection.execute(
                "SELECT * FROM issued_permits WHERE permit_digest=?",
                (permit.permit_digest,),
            ).fetchone()
            if row is None:
                raise _error("ECO_TEAM_AUTHORITY_PERMIT_UNISSUED")
            values = dict(row)
            tag = values.pop("row_hmac")
            material = self._document_like(bytes(values["raw_material"]))
            expected_requester = {
                "principalId": expected_requester_principal_id,
                "membershipDigest": expected_requester_membership_digest,
            }
            if (
                canonical_json(material.get("permit"))
                != canonical_json(permit.as_dict())
                or material.get("request", {}).get("spec", {}).get("requester")
                != expected_requester
                or values["snapshot_digest"] != expected_snapshot_digest
                or values["revocation_epoch"] != state["revocation_epoch"]
                or observed >= _parse_time(values["expires_at"])
                or not hmac.compare_digest(
                    tag,
                    self._sign(
                        self._issued_permit_payload(values),
                        key_id=values["key_id"],
                    ),
                )
            ):
                raise _error("ECO_TEAM_AUTHORITY_PERMIT_INVALID")

    def effect_guard(
        self,
        *,
        expected_snapshot_digest: str,
        principal_id: str,
        membership_id: str,
        now: datetime,
        operation: Callable[[], _T],
    ) -> _T:
        """Linearize the final live check with one bounded local effect callback."""

        if not callable(operation):
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        with self._transaction():
            state = self._heads()
            self._assert_live_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=now,
            )
            self.active_access_context(
                principal_id=principal_id,
                membership_id=membership_id,
                expected_snapshot_digest=expected_snapshot_digest,
                now=now,
            )
            return operation()

    def backup_to(
        self,
        destination: str | os.PathLike[str],
        *,
        expected_snapshot_digest: str,
        now: datetime,
        forbidden_root: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Create and verify one coherent private SQLite backup at an external path."""

        target = Path(destination).expanduser()
        if not target.is_absolute() or target.exists() or target.is_symlink():
            raise _error("ECO_TEAM_AUTHORITY_BACKUP_PATH_INVALID")
        target = target.resolve()
        if forbidden_root is not None:
            try:
                target.relative_to(Path(forbidden_root).resolve())
            except ValueError:
                pass
            else:
                raise _error("ECO_TEAM_AUTHORITY_LOCATION_DENIED")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            parent = target.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise _error("ECO_TEAM_AUTHORITY_PERMISSIONS")
        _require_digest(expected_snapshot_digest)
        staging = _private_staging_path(target)
        staging_identity: tuple[int, int] | None = None
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            descriptor = os.open(staging, flags, 0o600)
            os.close(descriptor)
            staging_identity = _path_identity(staging)
            if staging_identity is None:
                raise _error("ECO_TEAM_AUTHORITY_STAGING_UNSAFE")
            with self._lock:
                state = self._heads()
                self._assert_verifiable_locked(
                    state,
                    expected_snapshot_digest=expected_snapshot_digest,
                    now=now,
                )
                destination_connection = sqlite3.connect(staging)
                try:
                    self._connection.backup(destination_connection)
                finally:
                    destination_connection.close()
            if os.name == "posix":
                os.chmod(staging, 0o600)
            with SQLiteTeamAuthority(
                staging,
                hmac_key=self._hmac_key,
                key_id=self._key_id,
                trust_anchor=self._anchor,
                project_id=self._project_id,
                store_id=self._store_id,
                historical_hmac_keys=self._audit_keys,
            ) as restored:
                restored.verify()
                if (
                    restored.snapshot()["authoritySnapshotDigest"]
                    != expected_snapshot_digest
                ):
                    raise _error("ECO_TEAM_AUTHORITY_BACKUP_INVALID")
            digest = hashlib.sha256(staging.read_bytes()).hexdigest()
            _publish_no_replace(
                staging,
                target,
                staging_identity,
                conflict_code="ECO_TEAM_AUTHORITY_BACKUP_PATH_INVALID",
            )
            staging_identity = None
            return {
                "storeId": self._store_id,
                "authoritySnapshotDigest": expected_snapshot_digest,
                "databaseSha256": digest,
                "verified": True,
            }
        except Exception:
            _unlink_owned(staging, staging_identity)
            raise

    def reserve_rotation(
        self,
        *,
        raw_rotation: bytes,
        new_anchor: PolicyTrustAnchor,
        successor_store_id: str,
        successor_location_digest: str,
        successor_policy_digest: str,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Reserve one exact successor and fence every ordinary predecessor use."""

        _require_id(successor_store_id)
        _require_digest(successor_location_digest)
        _require_digest(successor_policy_digest)
        _require_digest(expected_snapshot_digest)
        raw = bytes(raw_rotation) if isinstance(raw_rotation, bytes) else b""
        observed = _utc(now)
        try:
            verified = TeamKeyRotationVerifier(self._anchor, new_anchor).verify(
                raw, expected_project_id=self._project_id, now=observed
            )
        except RuntimePolicyError as exc:
            raise _error(exc.code, "Team authority rotation failed closed") from exc
        with self._transaction():
            state = self._heads()
            records = self._revocation_export_locked()
            set_digest = self._revocation_set_digest(records)
            commitment = semantic_digest(
                {
                    "domain": "eco-team-rotation-successor-commitment-v1",
                    "rotationId": verified.rotation_id,
                    "rotationEnvelopeDigest": verified.envelope_digest,
                    "predecessorStoreId": self._store_id,
                    "predecessorSnapshotDigest": expected_snapshot_digest,
                    "successorStoreId": successor_store_id,
                    "successorLocationDigest": successor_location_digest,
                    "successorAnchorDigest": policy_trust_anchor_digest(new_anchor),
                    "successorPolicyDigest": successor_policy_digest,
                    "inheritedRevocationEpoch": state["revocation_epoch"],
                    "inheritedRevocationHeadDigest": state[
                        "revocation_head_digest"
                    ],
                    "inheritedRevocationSetDigest": set_digest,
                }
            )
            existing = self._connection.execute(
                "SELECT * FROM rotation_reservations WHERE rotation_id=?",
                (verified.rotation_id,),
            ).fetchone()
            if existing is not None:
                values = dict(existing)
                tag = values.pop("row_hmac")
                values.pop("audit_sequence")
                if (
                    values["commitment_digest"] != commitment
                    or values["rotation_envelope_digest"]
                    != verified.envelope_digest
                    or values["predecessor_snapshot_digest"]
                    != expected_snapshot_digest
                    or not hmac.compare_digest(
                        tag,
                        self._sign(
                            self._rotation_reservation_payload(values),
                            key_id=values["key_id"],
                        ),
                    )
                    or state["rotation_commitment_digest"] != commitment
                    or state["generation_status"]
                    not in {"rotation-pending", "retired"}
                ):
                    raise _error("ECO_TEAM_ROTATION_RESERVATION_CONFLICT")
                return {
                    "rotationId": verified.rotation_id,
                    "rotationCommitmentDigest": commitment,
                    "successorLocationDigest": successor_location_digest,
                    "reservationSnapshotDigest": values[
                        "after_snapshot_digest"
                    ],
                    "predecessorStatus": state["generation_status"],
                    "revocationEpoch": state["revocation_epoch"],
                    "revocationHeadDigest": state["revocation_head_digest"],
                    "revocationSetDigest": set_digest,
                    "revocations": list(records),
                    "replayed": True,
                }
            self._assert_live_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=observed,
            )
            before = state["snapshot_digest"]
            now_text, now_epoch = self._observe_clock(state, observed)
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "generation_status": "rotation-pending",
                    "rotation_commitment_digest": commitment,
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            event_digest = _event_digest(
                kind="rotation-reservation",
                identifier=verified.rotation_id,
                object_digest=commitment,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="rotation-reservation",
                entity_id=verified.rotation_id,
                action="reserve",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            values = {
                "rotation_id": verified.rotation_id,
                "commitment_digest": commitment,
                "rotation_envelope_digest": verified.envelope_digest,
                "successor_store_id": successor_store_id,
                "successor_location_digest": successor_location_digest,
                "successor_anchor_digest": policy_trust_anchor_digest(new_anchor),
                "successor_policy_digest": successor_policy_digest,
                "predecessor_snapshot_digest": expected_snapshot_digest,
                "inherited_revocation_epoch": state["revocation_epoch"],
                "inherited_revocation_head_digest": state[
                    "revocation_head_digest"
                ],
                "inherited_revocation_set_digest": set_digest,
                "raw_rotation": raw,
                "new_anchor_json": self._anchor_json(new_anchor),
                "before_snapshot_digest": before,
                "after_snapshot_digest": after,
                "event_digest": event_digest,
                "reserved_at": now_text,
                "key_id": self._key_id,
            }
            tag = self._sign(self._rotation_reservation_payload(values))
            self._connection.execute(
                "INSERT INTO rotation_reservations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(values.values()) + (tag, sequence),
            )
            self._write_heads(next_state)
        return {
            "rotationId": verified.rotation_id,
            "rotationCommitmentDigest": commitment,
            "successorLocationDigest": successor_location_digest,
            "reservationSnapshotDigest": after,
            "predecessorStatus": "rotation-pending",
            "revocationEpoch": state["revocation_epoch"],
            "revocationHeadDigest": state["revocation_head_digest"],
            "revocationSetDigest": set_digest,
            "revocations": list(records),
            "replayed": False,
        }

    def finalize_rotation(
        self,
        *,
        rotation_id: str,
        rotation_commitment_digest: str,
        successor_store_id: str,
        successor_location_digest: str,
        successor_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Retire the predecessor only after the exact successor is published live."""

        _require_id(rotation_id)
        _require_digest(rotation_commitment_digest)
        _require_id(successor_store_id)
        _require_digest(successor_location_digest)
        _require_digest(successor_snapshot_digest)
        observed = _utc(now)
        with self._transaction():
            state = self._heads()
            existing = self._connection.execute(
                "SELECT * FROM rotation_finalizations WHERE rotation_id=?",
                (rotation_id,),
            ).fetchone()
            if existing is not None:
                values = dict(existing)
                tag = values.pop("row_hmac")
                values.pop("audit_sequence")
                if (
                    values["commitment_digest"] != rotation_commitment_digest
                    or values["successor_store_id"] != successor_store_id
                    or values["successor_location_digest"]
                    != successor_location_digest
                    or values["successor_snapshot_digest"]
                    != successor_snapshot_digest
                    or state["generation_status"] != "retired"
                    or not hmac.compare_digest(
                        tag,
                        self._sign(
                            self._rotation_finalization_payload(values),
                            key_id=values["key_id"],
                        ),
                    )
                ):
                    raise _error("ECO_TEAM_ROTATION_FINALIZATION_CONFLICT")
                return {**self.snapshot(), "replayed": True}
            reservation = self._connection.execute(
                "SELECT * FROM rotation_reservations WHERE rotation_id=?",
                (rotation_id,),
            ).fetchone()
            if (
                reservation is None
                or reservation["commitment_digest"]
                != rotation_commitment_digest
                or reservation["successor_store_id"] != successor_store_id
                or reservation["successor_location_digest"]
                != successor_location_digest
                or state["generation_status"] != "rotation-pending"
                or state["rotation_commitment_digest"]
                != rotation_commitment_digest
            ):
                raise _error("ECO_TEAM_ROTATION_FINALIZATION_CONFLICT")
            before = state["snapshot_digest"]
            now_text, now_epoch = self._observe_clock(state, observed)
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "generation_status": "retired",
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            event_digest = _event_digest(
                kind="rotation-finalization",
                identifier=rotation_id,
                object_digest=successor_snapshot_digest,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="rotation-finalization",
                entity_id=rotation_id,
                action="retire",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            values = {
                "rotation_id": rotation_id,
                "commitment_digest": rotation_commitment_digest,
                "successor_store_id": successor_store_id,
                "successor_location_digest": successor_location_digest,
                "successor_snapshot_digest": successor_snapshot_digest,
                "before_snapshot_digest": before,
                "after_snapshot_digest": after,
                "event_digest": event_digest,
                "finalized_at": now_text,
                "key_id": self._key_id,
            }
            tag = self._sign(self._rotation_finalization_payload(values))
            self._connection.execute(
                "INSERT INTO rotation_finalizations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(values.values()) + (tag, sequence),
            )
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def record_rotated_predecessor(
        self,
        *,
        raw_rotation: bytes,
        predecessor_anchor: PolicyTrustAnchor,
        predecessor_store_id: str,
        predecessor_snapshot_digest: str,
        rotation_commitment_digest: str,
        successor_location_digest: str,
        inherited_revocation_epoch: int,
        inherited_revocation_head_digest: str,
        inherited_revocation_set_digest: str,
        inherited_revocations: Sequence[Mapping[str, Any]],
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Bind this new authority generation to a dual-signed predecessor."""

        _require_id(predecessor_store_id)
        _require_digest(predecessor_snapshot_digest)
        _require_digest(rotation_commitment_digest)
        _require_digest(successor_location_digest)
        _require_digest(inherited_revocation_head_digest)
        _require_digest(inherited_revocation_set_digest)
        _require_digest(expected_snapshot_digest)
        if type(inherited_revocation_epoch) is not int or inherited_revocation_epoch < 0:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        normalized = [dict(item) for item in inherited_revocations]
        required = {
            "revocationId",
            "subjectKind",
            "subjectId",
            "subjectDigest",
            "reasonCode",
            "revocationDigest",
        }
        for item in normalized:
            if set(item) != required or item["subjectKind"] not in _REVOCABLE:
                raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
            _require_id(item["revocationId"])
            _require_id(item["subjectId"], key=item["subjectKind"] == "IdentityKey")
            _require_digest(item["subjectDigest"])
            _require_digest(item["revocationDigest"])
            if not isinstance(item["reasonCode"], str) or _REASON.fullmatch(
                item["reasonCode"]
            ) is None:
                raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        if (
            len(normalized) != inherited_revocation_epoch
            or self._revocation_set_digest(normalized)
            != inherited_revocation_set_digest
        ):
            raise _error("ECO_TEAM_AUTHORITY_REVOCATION_CARRY_INVALID")
        raw = bytes(raw_rotation) if isinstance(raw_rotation, bytes) else b""
        observed = _utc(now)
        try:
            verified = TeamKeyRotationVerifier(
                predecessor_anchor, self._anchor
            ).verify(raw, expected_project_id=self._project_id, now=observed)
        except RuntimePolicyError as exc:
            raise _error(exc.code, "Team authority rotation failed closed") from exc
        with self._transaction():
            state = self._heads()
            if (
                self._generation_profile != "successor"
                or state["generation_status"] != "pending-successor"
                or state["snapshot_digest"] != expected_snapshot_digest
                or state["active_policy_revision"] != 0
                or state["revocation_epoch"] != 0
                or self._connection.execute(
                "SELECT 1 FROM authority_lineage WHERE singleton=1"
                ).fetchone()
                is not None
            ):
                raise _error("ECO_TEAM_AUTHORITY_LINEAGE_EXISTS")
            before = state["snapshot_digest"]
            now_text, now_epoch = self._observe_clock(state, observed)
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "revocation_epoch": inherited_revocation_epoch,
                    "revocation_head_digest": inherited_revocation_head_digest,
                    "rotation_commitment_digest": rotation_commitment_digest,
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            values = {
                "predecessor_store_id": predecessor_store_id,
                "predecessor_snapshot_digest": predecessor_snapshot_digest,
                "rotation_id": verified.rotation_id,
                "rotation_envelope_digest": verified.envelope_digest,
                "rotation_commitment_digest": rotation_commitment_digest,
                "successor_location_digest": successor_location_digest,
                "raw_rotation": raw,
                "old_anchor_json": self._anchor_json(predecessor_anchor),
                "new_anchor_json": self._anchor_json(self._anchor),
                "inherited_revocation_epoch": inherited_revocation_epoch,
                "inherited_revocation_head_digest": inherited_revocation_head_digest,
                "inherited_revocation_set_digest": inherited_revocation_set_digest,
                "before_snapshot_digest": before,
                "after_snapshot_digest": after,
                "recorded_at": now_text,
                "key_id": self._key_id,
            }
            tag = self._sign(self._lineage_payload(values))
            self._connection.execute(
                "INSERT INTO authority_lineage VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(values.values()) + (tag,),
            )
            for item in normalized:
                inherited_values = {
                    "source_revocation_id": item["revocationId"],
                    "subject_kind": item["subjectKind"],
                    "subject_id": item["subjectId"],
                    "subject_digest": item["subjectDigest"],
                    "reason_code": item["reasonCode"],
                    "source_revocation_digest": item["revocationDigest"],
                    "key_id": self._key_id,
                }
                inherited_tag = self._sign(
                    self._inherited_revocation_payload(inherited_values)
                )
                self._connection.execute(
                    "INSERT INTO inherited_revocations VALUES (?,?,?,?,?,?,?,?)",
                    tuple(inherited_values.values()) + (inherited_tag,),
                )
            self._write_heads(next_state)
        return {
            "predecessorStoreId": predecessor_store_id,
            "predecessorSnapshotDigest": predecessor_snapshot_digest,
            "successorStoreId": self._store_id,
            "successorSnapshotDigest": self.snapshot()[
                "authoritySnapshotDigest"
            ],
            "rotationId": verified.rotation_id,
            "rotationEnvelopeDigest": verified.envelope_digest,
            "rotationCommitmentDigest": rotation_commitment_digest,
            "successorLocationDigest": successor_location_digest,
            "verified": True,
        }

    def finalize_successor_generation(
        self,
        *,
        rotation_commitment_digest: str,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Make a published pending successor live exactly once."""

        _require_digest(rotation_commitment_digest)
        _require_digest(expected_snapshot_digest)
        successor_location_digest = _successor_location_digest(self._path)
        observed = _utc(now)
        with self._transaction():
            state = self._heads()
            existing = self._connection.execute(
                "SELECT * FROM generation_finalizations WHERE singleton=1"
            ).fetchone()
            if existing is not None:
                values = dict(existing)
                values.pop("singleton")
                tag = values.pop("row_hmac")
                if (
                    values["rotation_commitment_digest"]
                    != rotation_commitment_digest
                    or values["successor_location_digest"]
                    != successor_location_digest
                    or state["generation_status"] != "active"
                    or not hmac.compare_digest(
                        tag,
                        self._sign(
                            self._generation_finalization_payload(values),
                            key_id=values["key_id"],
                        ),
                    )
                ):
                    raise _error("ECO_TEAM_ROTATION_FINALIZATION_CONFLICT")
                return {**self.snapshot(), "replayed": True}
            lineage = self._connection.execute(
                "SELECT rotation_commitment_digest,successor_location_digest "
                "FROM authority_lineage WHERE singleton=1"
            ).fetchone()
            if (
                self._generation_profile != "successor"
                or lineage is None
                or lineage["rotation_commitment_digest"]
                != rotation_commitment_digest
                or lineage["successor_location_digest"]
                != successor_location_digest
                or state["rotation_commitment_digest"]
                != rotation_commitment_digest
                or state["generation_status"] != "pending-successor"
                or state["snapshot_digest"] != expected_snapshot_digest
                or state["active_policy_revision"] != 1
            ):
                raise _error("ECO_TEAM_ROTATION_FINALIZATION_CONFLICT")
            before = state["snapshot_digest"]
            now_text, now_epoch = self._observe_clock(state, observed)
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "generation_status": "active",
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            values = {
                "rotation_commitment_digest": rotation_commitment_digest,
                "successor_location_digest": successor_location_digest,
                "active_policy_digest": state["active_policy_digest"],
                "before_snapshot_digest": before,
                "after_snapshot_digest": after,
                "finalized_at": now_text,
                "key_id": self._key_id,
            }
            tag = self._sign(self._generation_finalization_payload(values))
            self._connection.execute(
                "INSERT INTO generation_finalizations VALUES (1,?,?,?,?,?,?,?,?)",
                tuple(values.values()) + (tag,),
            )
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def consume_team_action_permit(
        self, intent: PermitConsumptionIntent
    ) -> str | None:
        """Durably consume one exact A2 permit under the live authority fence."""

        if not isinstance(intent, PermitConsumptionIntent):
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        for value in (
            intent.permit_digest,
            intent.request_digest,
            intent.action_digest,
            intent.resource_digest,
            intent.snapshot_digest,
            intent.policy_digest,
            intent.consumption_nonce_digest,
        ):
            _require_digest(value)
        consumed_at = _utc(intent.consumed_at)
        expires_at = _utc(intent.expires_at)
        if consumed_at >= expires_at:
            raise _error("ECO_TEAM_AUTHORITY_PERMIT_EXPIRED")
        with self._transaction():
            state = self._heads()
            document = self._assert_live_locked(
                state,
                expected_snapshot_digest=intent.snapshot_digest,
                now=consumed_at,
            )
            access_policy = self._access_policy(document)
            approval_policy = self._approval_policy_binding(
                document, revocation_epoch=state["revocation_epoch"]
            )
            if (
                intent.policy_digest != approval_policy["digest"]
                or intent.revocation_epoch != state["revocation_epoch"]
            ):
                raise _error("ECO_TEAM_AUTHORITY_PERMIT_STALE")
            issued = self._connection.execute(
                "SELECT * FROM issued_permits WHERE permit_digest=?",
                (intent.permit_digest,),
            ).fetchone()
            if issued is None:
                raise _error("ECO_TEAM_AUTHORITY_PERMIT_UNISSUED")
            material = self._document_like(bytes(issued["raw_material"]))
            permit_spec = material["permit"]["spec"]
            if (
                issued["request_digest"] != intent.request_digest
                or issued["snapshot_digest"] != intent.snapshot_digest
                or issued["policy_digest"] != intent.policy_digest
                or issued["revocation_epoch"] != intent.revocation_epoch
                or permit_spec["action"]["digest"] != intent.action_digest
                or permit_spec["resource"]["digest"] != intent.resource_digest
                or permit_spec["constraints"]["consumptionNonceDigest"]
                != intent.consumption_nonce_digest
                or _parse_time(issued["expires_at"]) != expires_at
            ):
                raise _error("ECO_TEAM_AUTHORITY_PERMIT_INVALID")
            existing = self._connection.execute(
                "SELECT 1 FROM permit_consumptions WHERE permit_digest=? OR consumption_nonce_digest=?",
                (intent.permit_digest, intent.consumption_nonce_digest),
            ).fetchone()
            if existing is not None:
                return None
            receipt = semantic_digest(
                {
                    "domain": "eco-team-permit-consumption-receipt-v1",
                    "storeId": self._store_id,
                    "permitDigest": intent.permit_digest,
                    "snapshotDigest": intent.snapshot_digest,
                    "consumedAt": _time_text(consumed_at),
                }
            )
            values = {
                "permit_digest": intent.permit_digest,
                "consumption_nonce_digest": intent.consumption_nonce_digest,
                "request_digest": intent.request_digest,
                "action_digest": intent.action_digest,
                "resource_digest": intent.resource_digest,
                "snapshot_digest": intent.snapshot_digest,
                "policy_digest": intent.policy_digest,
                "revocation_epoch": intent.revocation_epoch,
                "expires_at": _time_text(expires_at),
                "consumed_at": _time_text(consumed_at),
                "receipt_digest": receipt,
                "key_id": self._key_id,
            }
            tag = self._sign(self._permit_consumption_payload(values))
            self._connection.execute(
                "INSERT INTO permit_consumptions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(values.values()) + (tag,),
            )
            return receipt

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            state = self._heads()
        return {
            "storeId": self._store_id,
            "teamId": self._anchor.team_id,
            "projectId": self._project_id,
            "trustAnchorDigest": self._anchor_digest,
            "stateRevision": state["state_revision"],
            "epochs": {
                "policy": state["policy_epoch"],
                "identity": state["identity_epoch"],
                "revocation": state["revocation_epoch"],
                "emergency": state["emergency_epoch"],
            },
            "activePolicy": {
                "id": state["active_policy_id"],
                "revision": state["active_policy_revision"],
                "digest": state["active_policy_digest"],
            },
            "identityCatalogDigest": state["identity_catalog_digest"],
            "revocationHeadDigest": state["revocation_head_digest"],
            "emergencyDeny": bool(state["emergency_deny"]),
            "emergencyHeadDigest": state["emergency_head_digest"],
            "generationStatus": state["generation_status"],
            "rotationCommitmentDigest": state[
                "rotation_commitment_digest"
            ],
            "authoritySnapshotDigest": state["snapshot_digest"],
        }

    def activate_policy(
        self,
        raw_envelope: bytes,
        *,
        activation_id: str,
        expected_previous: tuple[int, str],
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        _require_id(activation_id)
        if (
            not isinstance(expected_previous, tuple)
            or len(expected_previous) != 2
            or type(expected_previous[0]) is not int
            or expected_previous[0] < 0
        ):
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        _require_digest(expected_previous[1])
        _require_digest(expected_snapshot_digest)
        raw = bytes(raw_envelope) if isinstance(raw_envelope, bytes) else b""
        expected_for_verifier = None if expected_previous[0] == 0 else expected_previous
        try:
            verified = self._verifier.verify(
                raw,
                expected_project_id=self._project_id,
                now=now,
                expected_previous=expected_for_verifier,
            )
        except RuntimePolicyError as exc:
            raise _error(exc.code, "Team policy activation failed closed") from exc
        document = self._document(raw)
        identity_digest = self._identity_digest(document)
        raw_digest = _raw_sha256(raw)

        with self._transaction():
            state = self._heads()
            if state["generation_status"] not in {
                "active",
                "pending-successor",
            }:
                raise _error("ECO_TEAM_AUTHORITY_GENERATION_INACTIVE")
            if state["generation_status"] == "pending-successor" and self._connection.execute(
                "SELECT 1 FROM authority_lineage WHERE singleton=1"
            ).fetchone() is None:
                raise _error("ECO_TEAM_AUTHORITY_LINEAGE_REQUIRED")
            now_text, now_epoch = self._observe_clock(state, now)
            existing = self._connection.execute(
                "SELECT * FROM policy_activations WHERE activation_id=?", (activation_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["envelope_digest"] != verified.envelope_digest
                    or existing["raw_sha256"] != raw_digest
                ):
                    raise _error("ECO_TEAM_AUTHORITY_IDEMPOTENCY_CONFLICT")
                return {**self.snapshot(), "replayed": True}
            if state["snapshot_digest"] != expected_snapshot_digest:
                raise _error("ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT")
            replay = self._connection.execute(
                "SELECT activation_id FROM policy_activations WHERE envelope_digest=? OR raw_sha256=?",
                (verified.envelope_digest, raw_digest),
            ).fetchone()
            if replay is not None:
                raise _error("ECO_TEAM_AUTHORITY_REPLAY")
            current = (state["active_policy_revision"], state["active_policy_digest"])
            if current != expected_previous:
                raise _error("ECO_TEAM_AUTHORITY_REVISION_CONFLICT")
            if verified.revision != state["active_policy_revision"] + 1:
                raise _error("ECO_TEAM_AUTHORITY_REVISION_CONFLICT")
            if any(
                self._is_revoked_locked(
                    subject_kind=record["kind"],
                    subject_id=record["metadata"]["id"],
                )
                for record in self._active_records(document)
            ):
                raise _error("ECO_TEAM_AUTHORITY_REVOKED_SUBJECT")

            before = state["snapshot_digest"]
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "policy_epoch": state["policy_epoch"] + 1,
                    "identity_epoch": state["identity_epoch"]
                    + (identity_digest != state["identity_catalog_digest"]),
                    "active_policy_id": verified.bundle_id,
                    "active_policy_revision": verified.revision,
                    "active_policy_digest": verified.bundle_digest,
                    "identity_catalog_digest": identity_digest,
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            object_digest = semantic_digest(
                {
                    "domain": "eco-team-policy-activation-v1",
                    "activationId": activation_id,
                    "envelopeId": verified.envelope_id,
                    "envelopeDigest": verified.envelope_digest,
                    "bundleId": verified.bundle_id,
                    "bundleRevision": verified.revision,
                    "bundleDigest": verified.bundle_digest,
                    "previous": {
                        "revision": expected_previous[0],
                        "digest": expected_previous[1],
                    },
                    "identityCatalogDigest": identity_digest,
                    "rawSha256": raw_digest,
                    "activatedAt": now_text,
                }
            )
            event_digest = _event_digest(
                kind="policy-activation",
                identifier=activation_id,
                object_digest=object_digest,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="policy-activation",
                entity_id=activation_id,
                action="activate",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            try:
                self._connection.execute(
                    "INSERT INTO policy_activations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        activation_id,
                        verified.envelope_id,
                        verified.envelope_digest,
                        verified.bundle_id,
                        verified.revision,
                        verified.bundle_digest,
                        expected_previous[0],
                        expected_previous[1],
                        identity_digest,
                        raw_digest,
                        raw,
                        before,
                        after,
                        event_digest,
                        now_text,
                        sequence,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise _error("ECO_TEAM_AUTHORITY_REVISION_CONFLICT") from exc
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def _active_subject(self, kind: str, identifier: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT raw_envelope FROM policy_activations ORDER BY bundle_revision DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        document = self._document(bytes(row["raw_envelope"]))
        return next(
            (
                record
                for record in self._active_records(document)
                if record["kind"] == kind and record["metadata"]["id"] == identifier
            ),
            None,
        )

    def revoke(
        self,
        *,
        revocation_id: str,
        subject_kind: str,
        subject_id: str,
        subject_digest: str,
        reason_code: str,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        _require_id(revocation_id)
        if subject_kind not in _REVOCABLE:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        _require_id(subject_id, key=subject_kind == "IdentityKey")
        _require_digest(subject_digest)
        _require_digest(expected_snapshot_digest)
        if not isinstance(reason_code, str) or _REASON.fullmatch(reason_code) is None:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        with self._transaction():
            state = self._heads()
            if state["generation_status"] != "active":
                raise _error("ECO_TEAM_AUTHORITY_GENERATION_INACTIVE")
            now_text, now_epoch = self._observe_clock(state, now)
            existing = self._connection.execute(
                "SELECT * FROM revocations WHERE revocation_id=?", (revocation_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["subject_kind"] != subject_kind
                    or existing["subject_id"] != subject_id
                    or existing["subject_digest"] != subject_digest
                    or existing["reason_code"] != reason_code
                ):
                    raise _error("ECO_TEAM_AUTHORITY_IDEMPOTENCY_CONFLICT")
                return {**self.snapshot(), "replayed": True}
            if state["snapshot_digest"] != expected_snapshot_digest:
                raise _error("ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT")
            subject = self._active_subject(subject_kind, subject_id)
            if subject is None or subject["metadata"]["recordDigest"] != subject_digest:
                raise _error("ECO_TEAM_AUTHORITY_SUBJECT_MISMATCH")
            if self._is_revoked_locked(
                subject_kind=subject_kind, subject_id=subject_id
            ):
                raise _error("ECO_TEAM_AUTHORITY_ALREADY_REVOKED")
            before = state["snapshot_digest"]
            revocation_digest = semantic_digest(
                {
                    "domain": "eco-team-revocation-v1",
                    "revocationId": revocation_id,
                    "subject": {
                        "kind": subject_kind,
                        "id": subject_id,
                        "digest": subject_digest,
                    },
                    "reasonCode": reason_code,
                    "previousHeadDigest": state["revocation_head_digest"],
                    "authoritySnapshotDigest": before,
                    "revokedAt": now_text,
                }
            )
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "revocation_epoch": state["revocation_epoch"] + 1,
                    "revocation_head_digest": semantic_digest(
                        {
                            "domain": "eco-team-revocation-chain-v1",
                            "previous": state["revocation_head_digest"],
                            "record": revocation_digest,
                        }
                    ),
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            event_digest = _event_digest(
                kind="revocation",
                identifier=revocation_id,
                object_digest=revocation_digest,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="revocation",
                entity_id=revocation_id,
                action="revoke",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            try:
                self._connection.execute(
                    "INSERT INTO revocations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        revocation_id,
                        subject_kind,
                        subject_id,
                        subject_digest,
                        reason_code,
                        state["revocation_head_digest"],
                        revocation_digest,
                        before,
                        after,
                        event_digest,
                        now_text,
                        sequence,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise _error("ECO_TEAM_AUTHORITY_ALREADY_REVOKED") from exc
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def set_emergency_deny(
        self,
        *,
        event_id: str,
        enabled: bool,
        reason_code: str,
        expected_snapshot_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        _require_id(event_id)
        if type(enabled) is not bool:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        if not enabled:
            raise _error("ECO_TEAM_AUTHORITY_RECOVERY_APPROVAL_REQUIRED")
        if not isinstance(reason_code, str) or _REASON.fullmatch(reason_code) is None:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        _require_digest(expected_snapshot_digest)
        with self._transaction():
            state = self._heads()
            if state["generation_status"] != "active":
                raise _error("ECO_TEAM_AUTHORITY_GENERATION_INACTIVE")
            now_text, now_epoch = self._observe_clock(state, now)
            existing = self._connection.execute(
                "SELECT * FROM emergency_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if existing is not None:
                if bool(existing["enabled"]) != enabled or existing["reason_code"] != reason_code:
                    raise _error("ECO_TEAM_AUTHORITY_IDEMPOTENCY_CONFLICT")
                return {**self.snapshot(), "replayed": True}
            if state["snapshot_digest"] != expected_snapshot_digest:
                raise _error("ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT")
            if bool(state["emergency_deny"]) == enabled:
                raise _error("ECO_TEAM_AUTHORITY_EMERGENCY_STATE_CONFLICT")
            before = state["snapshot_digest"]
            emergency_digest = semantic_digest(
                {
                    "domain": "eco-team-emergency-deny-v1",
                    "eventId": event_id,
                    "enabled": enabled,
                    "reasonCode": reason_code,
                    "previousHeadDigest": state["emergency_head_digest"],
                    "authoritySnapshotDigest": before,
                    "occurredAt": now_text,
                }
            )
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "emergency_epoch": state["emergency_epoch"] + 1,
                    "emergency_deny": int(enabled),
                    "emergency_head_digest": semantic_digest(
                        {
                            "domain": "eco-team-emergency-chain-v1",
                            "previous": state["emergency_head_digest"],
                            "record": emergency_digest,
                        }
                    ),
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            event_digest = _event_digest(
                kind="emergency",
                identifier=event_id,
                object_digest=emergency_digest,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="emergency",
                entity_id=event_id,
                action="enable" if enabled else "disable",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            self._connection.execute(
                "INSERT INTO emergency_events VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    int(enabled),
                    reason_code,
                    state["emergency_head_digest"],
                    emergency_digest,
                    before,
                    after,
                    event_digest,
                    now_text,
                    sequence,
                ),
            )
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def disable_emergency_deny(
        self,
        *,
        event_id: str,
        reason_code: str,
        expected_snapshot_digest: str,
        profile: dict[str, Any],
        request: dict[str, Any],
        requester_assertion: Mapping[str, Any],
        votes: Sequence[dict[str, Any]],
        consumption_nonce: bytes,
        expected_requester_principal_id: str,
        expected_requester_membership_digest: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Disable lockdown only from a signed, independent recovery quorum."""

        _require_id(event_id)
        _require_digest(expected_snapshot_digest)
        if not isinstance(reason_code, str) or _REASON.fullmatch(reason_code) is None:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        observed = _utc(now)
        with self._transaction():
            state = self._heads()
            if state["generation_status"] != "active":
                raise _error("ECO_TEAM_AUTHORITY_GENERATION_INACTIVE")
            if not state["emergency_deny"]:
                raise _error("ECO_TEAM_AUTHORITY_EMERGENCY_STATE_CONFLICT")
            now_text, now_epoch = self._observe_clock(state, observed)
            document = self._assert_verifiable_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=observed,
            )
            if self._connection.execute(
                "SELECT 1 FROM emergency_events WHERE event_id=?", (event_id,)
            ).fetchone() is not None:
                raise _error("ECO_TEAM_AUTHORITY_RECOVERY_REPLAY")
            documents = document["bundle"]["spec"]["documents"]
            signed_profile = next(
                (
                    item
                    for item in documents.get("approvalProfiles", [])
                    if item.get("metadata", {}).get("id")
                    == profile.get("metadata", {}).get("id")
                    and item.get("metadata", {}).get("recordDigest")
                    == profile.get("metadata", {}).get("recordDigest")
                ),
                None,
            )
            approval_policy = self._approval_policy_binding(
                document, revocation_epoch=state["revocation_epoch"]
            )
            expected_action = {
                "capability": "authority.emergency",
                "actionClass": "A2",
                "operation": "emergency.disable",
                "digest": emergency_recovery_action_digest(
                    store_id=self._store_id,
                    authority_snapshot_digest=state["snapshot_digest"],
                ),
            }
            expected_resource = {
                "kind": "AuthorityEmergencyState",
                "id": self._store_id,
                "digest": emergency_recovery_resource_digest(
                    store_id=self._store_id,
                    emergency_head_digest=state["emergency_head_digest"],
                    emergency_epoch=state["emergency_epoch"],
                ),
            }
            request_spec = request.get("spec", {})
            if (
                signed_profile is None
                or canonical_json(signed_profile) != canonical_json(profile)
                or signed_profile["spec"]["purpose"] != "emergency-recovery"
                or request_spec.get("profile")
                != {
                    "kind": "ApprovalProfile",
                    "id": signed_profile["metadata"]["id"],
                    "digest": signed_profile["metadata"]["recordDigest"],
                }
                or request_spec.get("action") != expected_action
                or request_spec.get("resource") != expected_resource
                or request_spec.get("snapshot")
                != {
                    "kind": "AuthoritySnapshot",
                    "id": self._store_id,
                    "digest": state["snapshot_digest"],
                }
                or request_spec.get("policy") != approval_policy
            ):
                raise _error("ECO_TEAM_AUTHORITY_RECOVERY_BINDING_INVALID")
            requester_principal = next(
                (
                    item
                    for item in documents["principals"]
                    if item["metadata"]["id"]
                    == expected_requester_principal_id
                ),
                None,
            )
            requester_membership = next(
                (
                    item
                    for item in documents["memberships"]
                    if item["metadata"]["recordDigest"]
                    == expected_requester_membership_digest
                ),
                None,
            )
            if requester_principal is None or requester_membership is None:
                raise _error("ECO_TEAM_AUTHORITY_RECOVERY_REQUESTER_UNTRUSTED")
            try:
                self.verify_actor_assertion(
                    requester_assertion,
                    expected_principal={
                        "kind": "PrincipalIdentity",
                        "id": requester_principal["metadata"]["id"],
                        "digest": requester_principal["metadata"]["recordDigest"],
                    },
                    expected_membership={
                        "kind": "MembershipBinding",
                        "id": requester_membership["metadata"]["id"],
                        "digest": requester_membership["metadata"]["recordDigest"],
                    },
                    expected_snapshot_digest=state["snapshot_digest"],
                    expected_audience="emergency-recovery",
                    expected_operation_digest=recovery_actor_operation_digest(
                        request["metadata"]["recordDigest"]
                    ),
                    now=observed,
                )
            except (RuntimePolicyError, RuntimeStoreError) as exc:
                raise _error(
                    "ECO_TEAM_AUTHORITY_RECOVERY_REQUESTER_UNTRUSTED"
                ) from exc
            permit = TeamApprovalVerifier(self).build_action_permit(
                signed_profile,
                request,
                votes,
                permit_id=f"recovery:{request['metadata']['recordDigest']}",
                consumption_nonce=consumption_nonce,
                expected_requester_principal_id=expected_requester_principal_id,
                expected_requester_membership_digest=expected_requester_membership_digest,
                now=observed,
            )
            permit_record = permit.as_dict()
            raw_material = canonical_json(
                {
                    "profile": signed_profile,
                    "request": request,
                    "votes": list(votes),
                    "permit": permit_record,
                }
            ).encode("utf-8")
            evidence_digest = semantic_digest(
                {
                    "domain": "eco-team-emergency-recovery-evidence-v1",
                    "eventId": event_id,
                    "requestDigest": request["metadata"]["recordDigest"],
                    "permitDigest": permit.permit_digest,
                    "rawMaterialSha256": hashlib.sha256(raw_material).hexdigest(),
                }
            )
            before = state["snapshot_digest"]
            emergency_digest = semantic_digest(
                {
                    "domain": "eco-team-emergency-deny-v1",
                    "eventId": event_id,
                    "enabled": False,
                    "reasonCode": reason_code,
                    "previousHeadDigest": state["emergency_head_digest"],
                    "authoritySnapshotDigest": before,
                    "recoveryEvidenceDigest": evidence_digest,
                    "occurredAt": now_text,
                }
            )
            next_state = dict(state)
            next_state.update(
                {
                    "state_revision": state["state_revision"] + 1,
                    "emergency_epoch": state["emergency_epoch"] + 1,
                    "emergency_deny": 0,
                    "emergency_head_digest": semantic_digest(
                        {
                            "domain": "eco-team-emergency-chain-v1",
                            "previous": state["emergency_head_digest"],
                            "record": emergency_digest,
                        }
                    ),
                    "last_observed_epoch_us": now_epoch,
                    "updated_at": now_text,
                }
            )
            after = self._snapshot_digest(next_state)
            next_state["snapshot_digest"] = after
            event_digest = _event_digest(
                kind="emergency",
                identifier=event_id,
                object_digest=emergency_digest,
                before=before,
                after=after,
            )
            sequence = self._append_audit(
                transaction_id=secrets.token_hex(16),
                entity_type="emergency",
                entity_id=event_id,
                action="disable",
                payload_digest=event_digest,
                occurred_at=now_text,
            )
            recovery_values = {
                "event_id": event_id,
                "request_digest": request["metadata"]["recordDigest"],
                "permit_digest": permit.permit_digest,
                "evidence_digest": evidence_digest,
                "raw_material": raw_material,
                "key_id": self._key_id,
            }
            recovery_tag = self._sign(
                self._recovery_evidence_payload(recovery_values)
            )
            try:
                self._connection.execute(
                    "INSERT INTO emergency_events VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        event_id,
                        0,
                        reason_code,
                        state["emergency_head_digest"],
                        emergency_digest,
                        before,
                        after,
                        event_digest,
                        now_text,
                        sequence,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO recovery_evidence VALUES (?,?,?,?,?,?,?)",
                    tuple(recovery_values.values()) + (recovery_tag,),
                )
            except sqlite3.IntegrityError as exc:
                raise _error("ECO_TEAM_AUTHORITY_RECOVERY_REPLAY") from exc
            self._write_heads(next_state)
        return {**self.snapshot(), "replayed": False}

    def is_revoked(self, *, subject_kind: str, subject_id: str) -> bool:
        if subject_kind not in _REVOCABLE:
            raise _error("ECO_TEAM_AUTHORITY_INPUT_INVALID")
        _require_id(subject_id, key=subject_kind == "IdentityKey")
        with self._lock:
            self._heads()
            return self._is_revoked_locked(
                subject_kind=subject_kind, subject_id=subject_id
            )

    def assert_live(self, *, expected_snapshot_digest: str, now: datetime) -> None:
        _require_digest(expected_snapshot_digest)
        with self._lock:
            state = self._heads()
            self._assert_live_locked(
                state,
                expected_snapshot_digest=expected_snapshot_digest,
                now=now,
            )

    def verify(self) -> None:
        """Verify one coherent snapshot, event replay, signatures and HMAC chain."""

        with self._lock:
            try:
                self._connection.execute("BEGIN")
                if self._connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                meta = self._connection.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
                heads = self._heads()
                if meta is None:
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                key = self._audit_keys.get(meta["audit_key_id"])
                if key is None:
                    raise _error("ECO_TEAM_AUTHORITY_KEY_UNKNOWN")
                expected_meta = hmac.new(
                    key,
                    canonical_json(self._meta_payload(meta)).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(meta["meta_hmac"], expected_meta):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                if heads["snapshot_digest"] != self._snapshot_digest(heads):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                expected_state_hmac = self._state_hmac(heads)
                if not hmac.compare_digest(heads["state_hmac"], expected_state_hmac):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

                audit: dict[int, sqlite3.Row] = {}
                previous_hash = GENESIS_DIGEST
                for row in self._connection.execute("SELECT * FROM audit_entries ORDER BY sequence"):
                    payload = {
                        "domain": "eco-team-authority-audit-v1",
                        "storeId": self._store_id,
                        "sequence": row["sequence"],
                        "transactionId": row["transaction_id"],
                        "entityType": row["entity_type"],
                        "entityId": row["entity_id"],
                        "action": row["action"],
                        "payloadDigest": row["payload_digest"],
                        "previousEntryHash": row["previous_entry_hash"],
                        "occurredAt": row["occurred_at"],
                    }
                    entry_hash = semantic_digest(payload)
                    audit_key = self._audit_keys.get(row["key_id"])
                    expected_tag = (
                        hmac.new(audit_key, bytes.fromhex(entry_hash), hashlib.sha256).hexdigest()
                        if audit_key is not None
                        else ""
                    )
                    if (
                        row["previous_entry_hash"] != previous_hash
                        or row["entry_hash"] != entry_hash
                        or not hmac.compare_digest(row["hmac_tag"], expected_tag)
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                    audit[row["sequence"]] = row
                    previous_hash = entry_hash

                replay = self._genesis_state(meta["created_at"])
                lineage = self._connection.execute(
                    "SELECT * FROM authority_lineage WHERE singleton=1"
                ).fetchone()
                if lineage is not None:
                    lineage_values = dict(lineage)
                    lineage_values.pop("singleton")
                    lineage_tag = lineage_values.pop("row_hmac")
                    old_anchor = self._anchor_from_json(
                        bytes(lineage_values["old_anchor_json"])
                    )
                    new_anchor = self._anchor_from_json(
                        bytes(lineage_values["new_anchor_json"])
                    )
                    try:
                        rotation = TeamKeyRotationVerifier(
                            old_anchor, new_anchor
                        ).verify(
                            bytes(lineage_values["raw_rotation"]),
                            expected_project_id=self._project_id,
                            now=_parse_time(lineage_values["recorded_at"]),
                        )
                    except RuntimePolicyError as exc:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
                    if (
                        self._generation_profile != "successor"
                        or replay["generation_status"] != "pending-successor"
                        or lineage_values["before_snapshot_digest"]
                        != replay["snapshot_digest"]
                        or new_anchor != self._anchor
                        or rotation.rotation_id != lineage_values["rotation_id"]
                        or rotation.envelope_digest
                        != lineage_values["rotation_envelope_digest"]
                        or not hmac.compare_digest(
                            lineage_tag,
                            self._sign(
                                self._lineage_payload(lineage_values),
                                key_id=lineage_values["key_id"],
                            ),
                        )
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                    replay.update(
                        {
                            "state_revision": replay["state_revision"] + 1,
                            "revocation_epoch": lineage_values[
                                "inherited_revocation_epoch"
                            ],
                            "revocation_head_digest": lineage_values[
                                "inherited_revocation_head_digest"
                            ],
                            "rotation_commitment_digest": lineage_values[
                                "rotation_commitment_digest"
                            ],
                            "last_observed_epoch_us": _epoch_us(
                                _parse_time(lineage_values["recorded_at"])
                            ),
                            "updated_at": lineage_values["recorded_at"],
                        }
                    )
                    replay["snapshot_digest"] = self._snapshot_digest(replay)
                    if (
                        lineage_values["after_snapshot_digest"]
                        != replay["snapshot_digest"]
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                semantic_rows: dict[int, tuple[str, sqlite3.Row]] = {}
                for table, kind in (
                    ("policy_activations", "policy-activation"),
                    ("revocations", "revocation"),
                    ("emergency_events", "emergency"),
                    ("rotation_reservations", "rotation-reservation"),
                    ("rotation_finalizations", "rotation-finalization"),
                ):
                    for row in self._connection.execute(f"SELECT * FROM {table}"):
                        if row["audit_sequence"] in semantic_rows:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        semantic_rows[row["audit_sequence"]] = (kind, row)

                for sequence in sorted(semantic_rows):
                    kind, row = semantic_rows[sequence]
                    audited = audit.get(sequence)
                    if audited is None or audited["entity_type"] != kind or audited["payload_digest"] != row["event_digest"]:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                    if row["before_snapshot_digest"] != replay["snapshot_digest"]:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                    if kind == "policy-activation":
                        raw = bytes(row["raw_envelope"])
                        if _raw_sha256(raw) != row["raw_sha256"]:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        previous = (row["previous_revision"], row["previous_digest"])
                        try:
                            verified = self._verifier.verify(
                                raw,
                                expected_project_id=self._project_id,
                                now=_parse_time(row["activated_at"]),
                                expected_previous=None if previous[0] == 0 else previous,
                            )
                        except RuntimePolicyError as exc:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
                        document = self._document(raw)
                        identity_digest = self._identity_digest(document)
                        if (
                            previous != (replay["active_policy_revision"], replay["active_policy_digest"])
                            or verified.envelope_id != row["envelope_id"]
                            or verified.envelope_digest != row["envelope_digest"]
                            or verified.bundle_id != row["bundle_id"]
                            or verified.revision != row["bundle_revision"]
                            or verified.bundle_digest != row["bundle_digest"]
                            or identity_digest != row["identity_catalog_digest"]
                        ):
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        replay.update(
                            {
                                "state_revision": replay["state_revision"] + 1,
                                "policy_epoch": replay["policy_epoch"] + 1,
                                "identity_epoch": replay["identity_epoch"]
                                + (identity_digest != replay["identity_catalog_digest"]),
                                "active_policy_id": verified.bundle_id,
                                "active_policy_revision": verified.revision,
                                "active_policy_digest": verified.bundle_digest,
                                "identity_catalog_digest": identity_digest,
                            }
                        )
                        object_digest = semantic_digest(
                            {
                                "domain": "eco-team-policy-activation-v1",
                                "activationId": row["activation_id"],
                                "envelopeId": row["envelope_id"],
                                "envelopeDigest": row["envelope_digest"],
                                "bundleId": row["bundle_id"],
                                "bundleRevision": row["bundle_revision"],
                                "bundleDigest": row["bundle_digest"],
                                "previous": {"revision": previous[0], "digest": previous[1]},
                                "identityCatalogDigest": identity_digest,
                                "rawSha256": row["raw_sha256"],
                                "activatedAt": row["activated_at"],
                            }
                        )
                    elif kind == "revocation":
                        revocation_digest = semantic_digest(
                            {
                                "domain": "eco-team-revocation-v1",
                                "revocationId": row["revocation_id"],
                                "subject": {"kind": row["subject_kind"], "id": row["subject_id"], "digest": row["subject_digest"]},
                                "reasonCode": row["reason_code"],
                                "previousHeadDigest": row["previous_head_digest"],
                                "authoritySnapshotDigest": row["before_snapshot_digest"],
                                "revokedAt": row["revoked_at"],
                            }
                        )
                        if revocation_digest != row["revocation_digest"] or row["previous_head_digest"] != replay["revocation_head_digest"]:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        replay.update(
                            {
                                "state_revision": replay["state_revision"] + 1,
                                "revocation_epoch": replay["revocation_epoch"] + 1,
                                "revocation_head_digest": semantic_digest(
                                    {"domain": "eco-team-revocation-chain-v1", "previous": replay["revocation_head_digest"], "record": revocation_digest}
                                ),
                            }
                        )
                        object_digest = revocation_digest
                    elif kind == "emergency":
                        recovery = self._connection.execute(
                            "SELECT * FROM recovery_evidence WHERE event_id=?",
                            (row["event_id"],),
                        ).fetchone()
                        emergency_payload = {
                            "domain": "eco-team-emergency-deny-v1",
                            "eventId": row["event_id"],
                            "enabled": bool(row["enabled"]),
                            "reasonCode": row["reason_code"],
                            "previousHeadDigest": row["previous_head_digest"],
                            "authoritySnapshotDigest": row["before_snapshot_digest"],
                            "occurredAt": row["occurred_at"],
                        }
                        if row["enabled"]:
                            if recovery is not None:
                                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        else:
                            if recovery is None:
                                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                            recovery_values = dict(recovery)
                            recovery_tag = recovery_values.pop("row_hmac")
                            material = self._document_like(
                                bytes(recovery_values["raw_material"])
                            )
                            expected_evidence = semantic_digest(
                                {
                                    "domain": "eco-team-emergency-recovery-evidence-v1",
                                    "eventId": recovery_values["event_id"],
                                    "requestDigest": recovery_values["request_digest"],
                                    "permitDigest": recovery_values["permit_digest"],
                                    "rawMaterialSha256": hashlib.sha256(
                                        bytes(recovery_values["raw_material"])
                                    ).hexdigest(),
                                }
                            )
                            if (
                                material.get("request", {})
                                .get("metadata", {})
                                .get("recordDigest")
                                != recovery_values["request_digest"]
                                or material.get("permit", {})
                                .get("metadata", {})
                                .get("recordDigest")
                                != recovery_values["permit_digest"]
                                or recovery_values["evidence_digest"]
                                != expected_evidence
                                or not hmac.compare_digest(
                                    recovery_tag,
                                    self._sign(
                                        self._recovery_evidence_payload(
                                            recovery_values
                                        ),
                                        key_id=recovery_values["key_id"],
                                    ),
                                )
                            ):
                                raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                            emergency_payload["recoveryEvidenceDigest"] = (
                                recovery_values["evidence_digest"]
                            )
                        emergency_digest = semantic_digest(emergency_payload)
                        if emergency_digest != row["emergency_digest"] or row["previous_head_digest"] != replay["emergency_head_digest"]:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        replay.update(
                            {
                                "state_revision": replay["state_revision"] + 1,
                                "emergency_epoch": replay["emergency_epoch"] + 1,
                                "emergency_deny": row["enabled"],
                                "emergency_head_digest": semantic_digest(
                                    {"domain": "eco-team-emergency-chain-v1", "previous": replay["emergency_head_digest"], "record": emergency_digest}
                                ),
                            }
                        )
                        object_digest = emergency_digest
                    elif kind == "rotation-reservation":
                        values = dict(row)
                        tag = values.pop("row_hmac")
                        values.pop("audit_sequence")
                        new_anchor = self._anchor_from_json(
                            bytes(values["new_anchor_json"])
                        )
                        try:
                            rotation = TeamKeyRotationVerifier(
                                self._anchor, new_anchor
                            ).verify(
                                bytes(values["raw_rotation"]),
                                expected_project_id=self._project_id,
                                now=_parse_time(values["reserved_at"]),
                            )
                        except RuntimePolicyError as exc:
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
                        if (
                            replay["generation_status"] != "active"
                            or rotation.rotation_id != values["rotation_id"]
                            or rotation.envelope_digest
                            != values["rotation_envelope_digest"]
                            or values["predecessor_snapshot_digest"]
                            != replay["snapshot_digest"]
                            or not hmac.compare_digest(
                                tag,
                                self._sign(
                                    self._rotation_reservation_payload(values),
                                    key_id=values["key_id"],
                                ),
                            )
                        ):
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        replay.update(
                            {
                                "state_revision": replay["state_revision"] + 1,
                                "generation_status": "rotation-pending",
                                "rotation_commitment_digest": values[
                                    "commitment_digest"
                                ],
                            }
                        )
                        object_digest = values["commitment_digest"]
                    else:
                        values = dict(row)
                        tag = values.pop("row_hmac")
                        values.pop("audit_sequence")
                        if (
                            replay["generation_status"] != "rotation-pending"
                            or replay["rotation_commitment_digest"]
                            != values["commitment_digest"]
                            or not hmac.compare_digest(
                                tag,
                                self._sign(
                                    self._rotation_finalization_payload(values),
                                    key_id=values["key_id"],
                                ),
                            )
                        ):
                            raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                        replay.update(
                            {
                                "state_revision": replay["state_revision"] + 1,
                                "generation_status": "retired",
                            }
                        )
                        object_digest = values["successor_snapshot_digest"]
                    replay["last_observed_epoch_us"] = _epoch_us(_parse_time(audited["occurred_at"]))
                    replay["updated_at"] = audited["occurred_at"]
                    replay["snapshot_digest"] = self._snapshot_digest(replay)
                    expected_event = _event_digest(
                        kind=kind,
                        identifier=audited["entity_id"],
                        object_digest=object_digest,
                        before=row["before_snapshot_digest"],
                        after=replay["snapshot_digest"],
                    )
                    if row["after_snapshot_digest"] != replay["snapshot_digest"] or row["event_digest"] != expected_event:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")

                if set(audit) != set(semantic_rows):
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                disabled_events = self._connection.execute(
                    "SELECT COUNT(*) FROM emergency_events WHERE enabled=0"
                ).fetchone()[0]
                recovery_rows = self._connection.execute(
                    "SELECT COUNT(*) FROM recovery_evidence"
                ).fetchone()[0]
                if disabled_events != recovery_rows:
                    raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                finalization = self._connection.execute(
                    "SELECT * FROM generation_finalizations WHERE singleton=1"
                ).fetchone()
                if finalization is not None:
                    values = dict(finalization)
                    values.pop("singleton")
                    tag = values.pop("row_hmac")
                    if (
                        lineage is None
                        or replay["generation_status"] != "pending-successor"
                        or replay["active_policy_revision"] != 1
                        or replay["rotation_commitment_digest"]
                        != values["rotation_commitment_digest"]
                        or lineage["successor_location_digest"]
                        != values["successor_location_digest"]
                        or replay["active_policy_digest"]
                        != values["active_policy_digest"]
                        or values["before_snapshot_digest"]
                        != replay["snapshot_digest"]
                        or not hmac.compare_digest(
                            tag,
                            self._sign(
                                self._generation_finalization_payload(values),
                                key_id=values["key_id"],
                            ),
                        )
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                    replay.update(
                        {
                            "state_revision": replay["state_revision"] + 1,
                            "generation_status": "active",
                            "last_observed_epoch_us": _epoch_us(
                                _parse_time(values["finalized_at"])
                            ),
                            "updated_at": values["finalized_at"],
                        }
                    )
                    replay["snapshot_digest"] = self._snapshot_digest(replay)
                    if values["after_snapshot_digest"] != replay["snapshot_digest"]:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                for row in self._connection.execute(
                    "SELECT * FROM issued_permits ORDER BY permit_digest"
                ):
                    values = dict(row)
                    tag = values.pop("row_hmac")
                    material = self._document_like(bytes(values["raw_material"]))
                    permit = material.get("permit", {})
                    if (
                        permit.get("metadata", {}).get("recordDigest")
                        != values["permit_digest"]
                        or permit.get("spec", {}).get("request", {}).get("digest")
                        != values["request_digest"]
                        or permit.get("spec", {}).get("snapshot", {}).get("digest")
                        != values["snapshot_digest"]
                        or permit.get("spec", {}).get("policy", {}).get("digest")
                        != values["policy_digest"]
                        or permit.get("spec", {}).get("policy", {}).get(
                            "revocationEpoch"
                        )
                        != values["revocation_epoch"]
                        or not hmac.compare_digest(
                            tag,
                            self._sign(
                                self._issued_permit_payload(values),
                                key_id=values["key_id"],
                            ),
                        )
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                for row in self._connection.execute(
                    "SELECT * FROM permit_consumptions ORDER BY permit_digest"
                ):
                    values = dict(row)
                    tag = values.pop("row_hmac")
                    if (
                        values["receipt_digest"]
                        != semantic_digest(
                            {
                                "domain": "eco-team-permit-consumption-receipt-v1",
                                "storeId": self._store_id,
                                "permitDigest": values["permit_digest"],
                                "snapshotDigest": values["snapshot_digest"],
                                "consumedAt": values["consumed_at"],
                            }
                        )
                        or not hmac.compare_digest(
                            tag,
                            self._sign(
                                self._permit_consumption_payload(values),
                                key_id=values["key_id"],
                            ),
                        )
                    ):
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                for key in self._state_payload(replay):
                    if replay[key] != heads[key]:
                        raise _error("ECO_TEAM_AUTHORITY_CORRUPT")
                self._connection.execute("COMMIT")
            except (RuntimeStoreError, RuntimePolicyError):
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            except (sqlite3.Error, KeyError, IndexError, TypeError, ValueError) as exc:
                if self._connection.in_transaction:
                    try:
                        self._connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise _error("ECO_TEAM_AUTHORITY_CORRUPT") from exc
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
