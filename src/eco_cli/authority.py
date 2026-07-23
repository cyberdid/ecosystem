from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eco_runtime.digests import canonical_json
from eco_runtime.policy_bundle import PolicyTrustAnchor
from eco_runtime.team_identity import decode_base64url

from .errors import EcoError

MAX_AUTHORITY_FILE_BYTES = 2 * 1024 * 1024
TRUST_ANCHOR_PROFILE = "eco-team-policy-trust-anchor-v1"


def _input_error(code: str = "ECO_AUTHORITY_INPUT_INVALID") -> EcoError:
    return EcoError(code)


def read_regular_file(path: Path, *, forbidden_root: Path | None = None) -> bytes:
    """Read one exact, bounded, non-linked file without exposing path details."""

    if not path.is_absolute():
        raise _input_error("ECO_AUTHORITY_PATH_NOT_ABSOLUTE")
    descriptor = -1
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        if forbidden_root is not None and resolved.is_relative_to(
            forbidden_root.resolve(strict=True)
        ):
            raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_PROJECT_CONTROLLED")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_AUTHORITY_FILE_BYTES
            or resolved != path
            or getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise _input_error()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        if any(getattr(before, field) != getattr(opened, field) for field in fields):
            raise _input_error()
        blocks: list[bytes] = []
        observed = 0
        while observed <= MAX_AUTHORITY_FILE_BYTES:
            block = os.read(descriptor, min(65_536, MAX_AUTHORITY_FILE_BYTES + 1 - observed))
            if not block:
                break
            blocks.append(block)
            observed += len(block)
        after = os.fstat(descriptor)
        if observed != after.st_size or any(
            getattr(opened, field) != getattr(after, field) for field in fields
        ):
            raise _input_error()
        return b"".join(blocks)
    except EcoError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _input_error() from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def parse_canonical_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _input_error("ECO_AUTHORITY_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except EcoError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _input_error() from exc
    if not isinstance(document, dict):
        raise _input_error()
    try:
        canonical = canonical_json(document).encode("utf-8")
    except Exception as exc:
        raise _input_error() from exc
    if canonical != raw:
        raise _input_error("ECO_AUTHORITY_INPUT_NONCANONICAL")
    return document


def _parse_anchor_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or "." in value:
        raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_INVALID")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_INVALID") from exc


def load_trust_anchor(raw: bytes) -> PolicyTrustAnchor:
    document = parse_canonical_json(raw)
    if frozenset(document) != frozenset(
        {"profile", "teamId", "keyId", "publicKey", "allowedProjectIds", "validity"}
    ) or document.get("profile") != TRUST_ANCHOR_PROFILE:
        raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_INVALID")
    public_key = document.get("publicKey")
    validity = document.get("validity")
    if (
        not isinstance(public_key, dict)
        or frozenset(public_key) != frozenset({"encoding", "value"})
        or public_key.get("encoding") != "raw-base64url"
        or not isinstance(validity, dict)
        or frozenset(validity) != frozenset({"notBefore", "notAfter"})
        or not isinstance(document.get("allowedProjectIds"), list)
    ):
        raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_INVALID")
    try:
        key_bytes = decode_base64url(public_key["value"], expected_bytes=32)
        return PolicyTrustAnchor(
            team_id=document["teamId"],
            key_id=document["keyId"],
            public_key=key_bytes,
            allowed_project_ids=tuple(document["allowedProjectIds"]),
            not_before=_parse_anchor_time(validity["notBefore"]),
            not_after=_parse_anchor_time(validity["notAfter"]),
        )
    except Exception as exc:
        if isinstance(exc, EcoError):
            raise
        raise _input_error("ECO_AUTHORITY_TRUST_ANCHOR_INVALID") from exc


def observed_at() -> datetime:
    return datetime.now(timezone.utc)
