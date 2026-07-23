from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .contracts import tool_argument_errors, validate_record
from .digests import semantic_digest
from .errors import ContractValidationError, RuntimePolicyError


_PROTECTED_SEGMENTS = frozenset(
    {".git", ".hg", ".svn", ".ssh", ".aws", ".docker", ".kube", "secrets"}
)
_PROTECTED_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials",
        "credentials.json",
        "service-account.json",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
    }
)
_PROTECTED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
_TRUST_ORDER = {f"P{level}": level for level in range(5)}


def protected_repository_path(path: str) -> bool:
    segments = path.split("/")
    lowered = [segment.casefold() for segment in segments]
    name = lowered[-1]
    return (
        any(segment in _PROTECTED_SEGMENTS for segment in lowered)
        or name.startswith(".env.")
        or name in _PROTECTED_NAMES
        or name.endswith(_PROTECTED_SUFFIXES)
    )


def root_identity_from_stat(root_stat: os.stat_result) -> str:
    return semantic_digest(
        {
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
            "mode": root_stat.st_mode,
        }
    )


def repository_root_identity(root: str | os.PathLike[str]) -> str:
    trusted_root = Path(root).resolve(strict=True)
    return root_identity_from_stat(trusted_root.stat())


def repository_snapshot_entries(
    snapshot: dict[str, Any],
    *,
    project_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    try:
        validate_record(snapshot)
    except ContractValidationError as exc:
        raise RuntimePolicyError(
            "ECO_REPOSITORY_SNAPSHOT_INVALID",
            "Repository snapshot contract is invalid",
        ) from exc
    if project_id is not None and snapshot["metadata"]["projectId"] != project_id:
        raise RuntimePolicyError(
            "ECO_REPOSITORY_SNAPSHOT_INVALID",
            "Repository snapshot belongs to another project",
        )
    snapshot_trust = snapshot["spec"]["trust"]
    entries: dict[str, dict[str, Any]] = {}
    for entry in snapshot["spec"]["entries"]:
        path = entry["path"]
        if (
            path in entries
            or tool_argument_errors("repository.read", {"path": path})
            or _TRUST_ORDER[entry["trust"]] > _TRUST_ORDER[snapshot_trust]
        ):
            raise RuntimePolicyError(
                "ECO_REPOSITORY_SNAPSHOT_INVALID",
                "Repository snapshot contains an invalid entry",
            )
        entries[path] = entry
    return entries
