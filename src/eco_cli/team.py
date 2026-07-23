from __future__ import annotations

"""Safe CLI composition helpers for the embedded M5 team authority.

The helpers in this module deliberately do not parse or expose private signing
keys.  The local SQLite journal key is supplied through one explicitly named
environment variable, while the public policy trust anchor and the journal
remain external to the governed repository.
"""

import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from eco_runtime.team_authority import SQLiteTeamAuthority

from .authority import load_trust_anchor, read_regular_file
from .errors import EcoError


_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_HEX_32_BYTES = re.compile(r"[0-9A-Fa-f]{64}\Z")


def _input_error(code: str) -> EcoError:
    # Error text is intentionally only a stable code.  In particular, do not
    # add the environment variable name, a path, or supplied content here.
    return EcoError(code)


def load_hmac_key_from_env(
    variable_name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> bytes:
    """Load one exact 32-byte HMAC journal key encoded as hexadecimal.

    The value and variable name are never included in failures or reports.
    Accepting a mapping makes the boundary testable without copying a secret to
    process-global state; production callers normally omit ``environ``.
    """

    if not isinstance(variable_name, str) or _ENVIRONMENT_NAME.fullmatch(
        variable_name
    ) is None:
        raise _input_error("ECO_TEAM_HMAC_ENV_NAME_INVALID")
    source = os.environ if environ is None else environ
    try:
        encoded = source.get(variable_name)
    except Exception as exc:
        raise _input_error("ECO_TEAM_HMAC_UNAVAILABLE") from exc
    if encoded is None:
        raise _input_error("ECO_TEAM_HMAC_MISSING")
    if not isinstance(encoded, str) or _HEX_32_BYTES.fullmatch(encoded) is None:
        raise _input_error("ECO_TEAM_HMAC_INVALID")
    try:
        return bytes.fromhex(encoded)
    except ValueError as exc:  # Defensive: the exact regex already excludes it.
        raise _input_error("ECO_TEAM_HMAC_INVALID") from exc


def _absolute_forbidden_root(root: Path) -> Path:
    if not isinstance(root, Path) or not root.is_absolute():
        raise _input_error("ECO_TEAM_PROJECT_ROOT_NOT_ABSOLUTE")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _input_error("ECO_TEAM_PROJECT_ROOT_INVALID") from exc
    if not resolved.is_dir() or resolved != root:
        raise _input_error("ECO_TEAM_PROJECT_ROOT_INVALID")
    return resolved


def _validate_database_path(
    path: Path,
    *,
    forbidden_root: Path,
    require_existing: bool,
) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise _input_error("ECO_TEAM_DATABASE_PATH_NOT_ABSOLUTE")
    root = _absolute_forbidden_root(forbidden_root)
    try:
        if path.exists() or path.is_symlink():
            details = path.lstat()
            resolved = path.resolve(strict=True)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or resolved != path
                or getattr(details, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise _input_error("ECO_TEAM_DATABASE_FILE_UNSAFE")
        else:
            if require_existing:
                raise _input_error("ECO_TEAM_DATABASE_MISSING")
            resolved_parent = path.parent.resolve(strict=True)
            if not resolved_parent.is_dir() or resolved_parent / path.name != path:
                raise _input_error("ECO_TEAM_DATABASE_FILE_UNSAFE")
            resolved = path
        if resolved.is_relative_to(root):
            raise _input_error("ECO_TEAM_AUTHORITY_PROJECT_CONTROLLED")
        return resolved
    except EcoError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _input_error("ECO_TEAM_DATABASE_FILE_UNSAFE") from exc


def open_team_authority(
    *,
    database_path: Path,
    trust_anchor_path: Path,
    forbidden_root: Path,
    project_id: str,
    audit_key_id: str,
    hmac_env: str,
    environ: Mapping[str, str] | None = None,
    store_id: str | None = None,
    require_existing: bool = False,
) -> SQLiteTeamAuthority:
    """Open an externally anchored authority without trusting project files.

    ``forbidden_root`` is the governed repository/project root.  Both the
    database and public trust anchor must resolve outside it.  The returned
    store owns no asymmetric signing key and callers must close it.
    """

    root = _absolute_forbidden_root(forbidden_root)
    database = _validate_database_path(
        database_path,
        forbidden_root=root,
        require_existing=require_existing,
    )
    anchor_raw = read_regular_file(trust_anchor_path, forbidden_root=root)
    anchor = load_trust_anchor(anchor_raw)
    hmac_key = load_hmac_key_from_env(hmac_env, environ=environ)
    return SQLiteTeamAuthority(
        database,
        hmac_key=hmac_key,
        key_id=audit_key_id,
        trust_anchor=anchor,
        project_id=project_id,
        forbidden_root=root,
        store_id=store_id,
    )


def _sanitized_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Copy the fixed public snapshot projection, dropping all other fields."""

    active = snapshot["activePolicy"]
    epochs = snapshot["epochs"]
    return {
        "storeId": snapshot["storeId"],
        "teamId": snapshot["teamId"],
        "projectId": snapshot["projectId"],
        "trustAnchorDigest": snapshot["trustAnchorDigest"],
        "stateRevision": snapshot["stateRevision"],
        "epochs": {
            "policy": epochs["policy"],
            "identity": epochs["identity"],
            "revocation": epochs["revocation"],
            "emergency": epochs["emergency"],
        },
        "activePolicy": {
            "id": active["id"],
            "revision": active["revision"],
            "digest": active["digest"],
        },
        "identityCatalogDigest": snapshot["identityCatalogDigest"],
        "revocationHeadDigest": snapshot["revocationHeadDigest"],
        "emergencyDeny": bool(snapshot["emergencyDeny"]),
        "emergencyHeadDigest": snapshot["emergencyHeadDigest"],
        "authoritySnapshotDigest": snapshot["authoritySnapshotDigest"],
    }


def doctor_team_authority(
    *,
    database_path: Path,
    trust_anchor_path: Path,
    forbidden_root: Path,
    project_id: str,
    audit_key_id: str,
    hmac_env: str,
    environ: Mapping[str, str] | None = None,
    store_id: str | None = None,
) -> dict[str, Any]:
    """Verify an existing authority and return only its public state summary."""

    with open_team_authority(
        database_path=database_path,
        trust_anchor_path=trust_anchor_path,
        forbidden_root=forbidden_root,
        project_id=project_id,
        audit_key_id=audit_key_id,
        hmac_env=hmac_env,
        environ=environ,
        store_id=store_id,
        require_existing=True,
    ) as authority:
        authority.verify()
        snapshot = _sanitized_snapshot(authority.snapshot())
    return {
        "available": True,
        "operation": "team-doctor",
        "status": "verified",
        "trustBasis": "externally-pinned-anchor",
        **snapshot,
        "safety": {
            "secretExposed": False,
            "pathExposed": False,
            "rawEnvelopeExposed": False,
            "repositoryMutation": False,
            "networkAccessed": False,
        },
    }


def activate_team_policy(
    authority: SQLiteTeamAuthority,
    raw_envelope: bytes,
    *,
    activation_id: str,
    expected_previous: tuple[int, str],
    expected_snapshot_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Activate exact signed bytes under predecessor and authority-snapshot CAS."""

    if not isinstance(authority, SQLiteTeamAuthority):
        raise _input_error("ECO_TEAM_AUTHORITY_HANDLE_INVALID")
    if not isinstance(raw_envelope, bytes) or not raw_envelope:
        raise _input_error("ECO_TEAM_POLICY_ENVELOPE_INVALID")
    observed = datetime.now(timezone.utc) if now is None else now
    activated = authority.activate_policy(
        raw_envelope,
        activation_id=activation_id,
        expected_previous=expected_previous,
        expected_snapshot_digest=expected_snapshot_digest,
        now=observed,
    )
    snapshot = _sanitized_snapshot(activated)
    return {
        "available": True,
        "operation": "team-policy-activate",
        "status": "replayed" if activated["replayed"] else "activated",
        "replayed": bool(activated["replayed"]),
        **snapshot,
        "safety": {
            "secretExposed": False,
            "pathExposed": False,
            "rawEnvelopeExposed": False,
            "repositoryMutation": False,
            "networkAccessed": False,
        },
    }


def activate_team_policy_file(
    *,
    database_path: Path,
    trust_anchor_path: Path,
    forbidden_root: Path,
    project_id: str,
    audit_key_id: str,
    hmac_env: str,
    envelope_path: Path,
    activation_id: str,
    expected_previous: tuple[int, str],
    expected_snapshot_digest: str,
    environ: Mapping[str, str] | None = None,
    store_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Open an existing authority and activate one exact signed envelope file."""

    raw_envelope = read_regular_file(envelope_path)
    with open_team_authority(
        database_path=database_path,
        trust_anchor_path=trust_anchor_path,
        forbidden_root=forbidden_root,
        project_id=project_id,
        audit_key_id=audit_key_id,
        hmac_env=hmac_env,
        environ=environ,
        store_id=store_id,
        require_existing=True,
    ) as authority:
        return activate_team_policy(
            authority,
            raw_envelope,
            activation_id=activation_id,
            expected_previous=expected_previous,
            expected_snapshot_digest=expected_snapshot_digest,
            now=now,
        )


__all__ = [
    "activate_team_policy",
    "activate_team_policy_file",
    "doctor_team_authority",
    "load_hmac_key_from_env",
    "open_team_authority",
]
