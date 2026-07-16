#!/usr/bin/env python3
"""Stdlib-only offline verifier for an ecosystem wheelhouse.

This script verifies integrity, not publisher identity, and performs no install.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import unicodedata
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
from typing import Any


MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_WHEEL_ENTRIES = 4096
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9._+-]{0,32})?$")
WHEEL_VERSION_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9._+!]{0,32})?$"
)
MANIFEST_ID_RE = re.compile(
    r"^ai-ecosystem-harness-[0-9][A-Za-z0-9._+-]{4,63}$"
)
REVISION_RE = re.compile(r"^[a-f0-9]{7,64}$")
WHEEL_RE = re.compile(
    r"^(?P<distribution>[A-Za-z0-9](?:[A-Za-z0-9_.]*[A-Za-z0-9])?)-"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.!+]*)(?:-[0-9][A-Za-z0-9_]*)?-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*\.whl$"
)
SCHEMA_PATH_RE = re.compile(
    r"^eco_(?:cli|runtime)/schemas/[A-Za-z0-9._/-]{1,200}\.json$"
)
REQUIRED_ENTRIES = {
    "eco_cli/__init__.py",
    "eco_cli/authority.py",
    "eco_cli/cli.py",
    "eco_cli/distribution.py",
    "eco_cli/platform_profiles.py",
    "eco_cli/team.py",
    "eco_runtime/__init__.py",
    "eco_runtime/policy_bundle.py",
    "eco_runtime/team_access.py",
    "eco_runtime/team_actor.py",
    "eco_runtime/team_approval.py",
    "eco_runtime/team_authority.py",
    "eco_runtime/team_identity.py",
    "eco_runtime/team_migration.py",
    "eco_runtime/team_rotation.py",
    "eco_runtime/team_runtime.py",
    "eco_cli/schemas/distribution-manifest.schema.json",
    "eco_cli/schemas/platform-profile.schema.json",
    "eco_cli/schemas/adapter-capability-profile.schema.json",
    "eco_runtime/schemas/identity-key.schema.json",
    "eco_runtime/schemas/membership-binding.schema.json",
    "eco_runtime/schemas/principal-identity.schema.json",
    "eco_runtime/schemas/team-access-policy.schema.json",
    "eco_runtime/schemas/team-approval.schema.json",
    "eco_runtime/schemas/team-identity.schema.json",
    "eco_runtime/schemas/team-key-rotation.schema.json",
    "eco_runtime/schemas/team-policy-bundle.schema.json",
}
SAFETY = {
    "authorityCreated": False,
    "installationPerformed": False,
    "projectMutation": False,
    "networkAccessed": False,
}


class VerificationError(ValueError):
    pass


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
        result[key] = value
    return result


def read_regular(path: Path, maximum: int, code: str) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum
            or getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise VerificationError(code)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(code) from exc
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or any(getattr(before, field) != getattr(opened, field) for field in fields)
        ):
            raise VerificationError(code)
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise VerificationError(code)
        after = os.fstat(descriptor)
        if total != after.st_size or any(
            getattr(opened, field) != getattr(after, field) for field in fields
        ):
            raise VerificationError("ECO_DISTRIBUTION_ARTIFACT_CHANGED")
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def require_keys(value: object, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise VerificationError(code)
    return value


def validate_artifact(value: object) -> dict[str, Any]:
    item = require_keys(value, {"filename", "sha256", "size"}, "ECO_DISTRIBUTION_MANIFEST_INVALID")
    name, digest, size = item["filename"], item["sha256"], item["size"]
    if (
        not isinstance(name, str)
        or WHEEL_RE.fullmatch(name) is None
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or type(size) is not int
        or not 1 <= size <= MAX_WHEEL_BYTES
    ):
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    return item


def wheel_filename_identity(name: str) -> tuple[str, str]:
    match = WHEEL_RE.fullmatch(name)
    if match is None:
        raise VerificationError("ECO_DISTRIBUTION_ARTIFACT_NAME_INVALID")
    distribution = re.sub(r"[-_.]+", "-", match.group("distribution")).lower()
    return distribution, match.group("version")


def validate_manifest(document: object) -> dict[str, Any]:
    manifest = require_keys(document, {"apiVersion", "kind", "metadata", "spec"}, "ECO_DISTRIBUTION_MANIFEST_INVALID")
    if manifest["apiVersion"] != "distribution.ai.ecosystem/v1alpha1" or manifest["kind"] != "DistributionManifest":
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    metadata = require_keys(manifest["metadata"], {"id", "version", "manifestDigest"}, "ECO_DISTRIBUTION_MANIFEST_INVALID")
    spec = require_keys(
        manifest["spec"],
        {
            "package", "mainArtifact", "dependencyArtifacts", "lockDigest",
            "sourceRevision", "schemaEntries", "installers", "support",
            "provenance", "safety",
        },
        "ECO_DISTRIBUTION_MANIFEST_INVALID",
    )
    package = require_keys(spec["package"], {"name", "version", "entryPoint", "pythonRequires", "format"}, "ECO_DISTRIBUTION_MANIFEST_INVALID")
    if (
        package != {
            "name": "ai-ecosystem-harness",
            "version": metadata["version"],
            "entryPoint": "eco",
            "pythonRequires": ">=3.11",
            "format": "wheel",
        }
        or spec["installers"] != ["pipx", "uv-tool", "venv-pip"]
        or spec["safety"] != SAFETY
        or any(type(spec["safety"].get(key)) is not bool for key in SAFETY)
        or not isinstance(spec["dependencyArtifacts"], list)
        or len(spec["dependencyArtifacts"]) > 128
        or not isinstance(spec["schemaEntries"], list)
        or not 1 <= len(spec["schemaEntries"]) <= 256
        or not isinstance(metadata.get("id"), str)
        or MANIFEST_ID_RE.fullmatch(metadata["id"]) is None
        or metadata.get("id") != f"ai-ecosystem-harness-{metadata.get('version')}"
        or metadata.get("version") != package.get("version")
        or spec["support"] != {
            "operatingSystems": ["linux", "macos", "windows", "wsl"],
            "architecture": "python-wheel-dependent",
            "offlineWheelhouse": True,
            "zipapp": False,
            "standaloneBinary": False,
        }
        or any(
            type(spec["support"].get(key)) is not bool
            for key in ("offlineWheelhouse", "zipapp", "standaloneBinary")
        )
        or spec["provenance"] != {
            "artifactIntegrity": "sha256",
            "originAuthentication": "not-attested",
            "sbom": "not-included",
        }
        or not isinstance(metadata.get("version"), str)
        or VERSION_RE.fullmatch(metadata["version"]) is None
        or not isinstance(metadata.get("manifestDigest"), str)
        or len(metadata["manifestDigest"]) != 64
        or any(character not in "0123456789abcdef" for character in metadata["manifestDigest"])
        or not isinstance(spec["lockDigest"], str)
        or len(spec["lockDigest"]) != 64
        or any(character not in "0123456789abcdef" for character in spec["lockDigest"])
        or not isinstance(spec["sourceRevision"], str)
        or REVISION_RE.fullmatch(spec["sourceRevision"]) is None
    ):
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    artifacts = [validate_artifact(spec["mainArtifact"])] + [
        validate_artifact(item) for item in spec["dependencyArtifacts"]
    ]
    names = [item["filename"] for item in artifacts]
    if len(names) != len(set(names)) or names[1:] != sorted(names[1:]):
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    schema_paths: list[str] = []
    for item in spec["schemaEntries"]:
        entry = require_keys(item, {"path", "sha256", "size"}, "ECO_DISTRIBUTION_MANIFEST_INVALID")
        if (
            not isinstance(entry["path"], str)
            or SCHEMA_PATH_RE.fullmatch(entry["path"]) is None
            or not safe_zip_name(entry["path"])
            or not isinstance(entry["sha256"], str)
            or len(entry["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in entry["sha256"])
            or type(entry["size"]) is not int
            or not 1 <= entry["size"] <= MAX_ENTRY_BYTES
        ):
            raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
        schema_paths.append(entry["path"])
    if not schema_paths or schema_paths != sorted(schema_paths) or len(schema_paths) != len(set(schema_paths)):
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    body = copy.deepcopy(manifest)
    body["metadata"].pop("manifestDigest")
    if metadata["manifestDigest"] != semantic_digest(body):
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    return manifest


def safe_zip_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not name.startswith("/")
        and "\\" not in name
        and not any(part in {"", ".", ".."} for part in path.parts)
        and not any(ord(character) < 32 or ord(character) == 127 for character in name)
    )


def inspect_wheel(
    encoded: bytes,
    manifest: dict[str, Any],
    *,
    filename: str,
    require_main_package: bool,
) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            normalized = [unicodedata.normalize("NFC", item).casefold() for item in names]
            if (
                not infos
                or len(infos) > MAX_WHEEL_ENTRIES
                or len(names) != len(set(names))
                or len(normalized) != len(set(normalized))
                or sum(item.file_size for item in infos) > MAX_WHEEL_BYTES
                or any(
                    not safe_zip_name(name)
                    or info.flag_bits & 1
                    or info.file_size > MAX_ENTRY_BYTES
                    for name, info in zip(names, infos)
                )
            ):
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
            for info in infos:
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_IFMT(mode) and not stat.S_ISREG(mode) and not (
                    stat.S_ISDIR(mode) and info.filename.endswith("/")
                ):
                    raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
            metadata_infos = [
                item for item in infos if item.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_infos) != 1 or metadata_infos[0].file_size > 1024 * 1024:
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
            metadata_name = metadata_infos[0].filename
            dist_info = metadata_name[: -len("METADATA")]
            if not {
                f"{dist_info}METADATA",
                f"{dist_info}WHEEL",
                f"{dist_info}RECORD",
            } <= set(names):
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")
            metadata = BytesParser(policy=email_policy).parsebytes(
                archive.read(metadata_infos[0])
            )
            filename_package, filename_version = wheel_filename_identity(filename)
            metadata_package = re.sub(
                r"[-_.]+", "-", str(metadata.get("Name", ""))
            ).lower()
            if (
                not str(metadata.get("Name", ""))
                or WHEEL_VERSION_RE.fullmatch(str(metadata.get("Version", ""))) is None
                or filename_package != metadata_package
                or filename_version != str(metadata.get("Version", ""))
            ):
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")
            record_info = archive.getinfo(f"{dist_info}RECORD")
            if record_info.file_size > MAX_ENTRY_BYTES:
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
            rows = list(csv.reader(io.StringIO(archive.read(record_info).decode("utf-8"))))
            record_names = [row[0] for row in rows if len(row) == 3]
            if (
                len(rows) != len(record_names)
                or len(record_names) != len(set(record_names))
                or set(record_names) != {name for name in names if not name.endswith("/")}
            ):
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
            if require_main_package:
                entry_points = f"{dist_info}entry_points.txt"
                if (
                    str(metadata.get("Name", "")).lower().replace("_", "-")
                    != "ai-ecosystem-harness"
                    or str(metadata.get("Version", ""))
                    != manifest["metadata"]["version"]
                    or metadata.get("Requires-Python") != ">=3.11"
                    or not REQUIRED_ENTRIES <= set(names)
                    or entry_points not in names
                ):
                    raise VerificationError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")
                entry_info = archive.getinfo(entry_points)
                if entry_info.file_size > 64 * 1024:
                    raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID")
                entry_text = archive.read(entry_info).decode("utf-8")
                if (
                    "[console_scripts]" not in entry_text
                    or "eco=eco_cli.cli:main" not in "".join(entry_text.split())
                ):
                    raise VerificationError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")
            actual: list[dict[str, Any]] = []
            for info in sorted(infos, key=lambda item: item.filename):
                if not (
                    info.filename.startswith("eco_cli/schemas/")
                    or info.filename.startswith("eco_runtime/schemas/")
                ) or not info.filename.endswith(".json"):
                    continue
                content = archive.read(info)
                actual.append({"path": info.filename, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
            if require_main_package and actual != manifest["spec"]["schemaEntries"]:
                raise VerificationError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")
    except VerificationError:
        raise
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        raise VerificationError("ECO_DISTRIBUTION_WHEEL_INVALID") from exc


def verify(manifest_path: Path, bundle_root: Path) -> dict[str, Any]:
    if not manifest_path.is_absolute() or not bundle_root.is_absolute():
        raise VerificationError("ECO_DISTRIBUTION_PATH_INVALID")
    manifest_bytes = read_regular(manifest_path, MAX_MANIFEST_BYTES, "ECO_DISTRIBUTION_MANIFEST_UNREADABLE")
    try:
        document = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=no_duplicate_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("ECO_DISTRIBUTION_MANIFEST_INVALID") from exc
    manifest = validate_manifest(document)
    try:
        root_status = bundle_root.lstat()
    except OSError as exc:
        raise VerificationError("ECO_DISTRIBUTION_BUNDLE_UNSAFE") from exc
    if not stat.S_ISDIR(root_status.st_mode) or getattr(root_status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
        raise VerificationError("ECO_DISTRIBUTION_BUNDLE_UNSAFE")
    artifacts = [manifest["spec"]["mainArtifact"], *manifest["spec"]["dependencyArtifacts"]]
    expected = {item["filename"] for item in artifacts}
    entries = list(bundle_root.iterdir())
    actual = {item.name for item in entries if item.name.endswith(".whl")}
    if actual != expected:
        raise VerificationError("ECO_DISTRIBUTION_BUNDLE_INCOMPLETE")
    if {item.name for item in entries} != {*expected, "uv.lock"}:
        raise VerificationError("ECO_DISTRIBUTION_BUNDLE_INCOMPLETE")
    lock = read_regular(
        bundle_root / "uv.lock", MAX_LOCK_BYTES, "ECO_DISTRIBUTION_LOCK_UNSAFE"
    )
    if hashlib.sha256(lock).hexdigest() != manifest["spec"]["lockDigest"]:
        raise VerificationError("ECO_DISTRIBUTION_LOCK_MISMATCH")
    verified: list[dict[str, Any]] = []
    for index, artifact in enumerate(artifacts):
        content = read_regular(bundle_root / artifact["filename"], MAX_WHEEL_BYTES, "ECO_DISTRIBUTION_ARTIFACT_UNSAFE")
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != artifact["size"] or digest != artifact["sha256"]:
            raise VerificationError("ECO_DISTRIBUTION_ARTIFACT_MISMATCH")
        inspect_wheel(
            content,
            manifest,
            filename=artifact["filename"],
            require_main_package=index == 0,
        )
        verified.append({"filename": artifact["filename"], "sha256": digest, "size": len(content)})
    body = {
        "available": True,
        "mode": "distribution-verification-only",
        "status": "pass",
        "code": "ECO_DISTRIBUTION_VERIFIED",
        "manifestDigest": manifest["metadata"]["manifestDigest"],
        "bundleDigest": semantic_digest(verified),
        "artifactCount": len(verified),
        "safety": SAFETY,
    }
    return {**body, "reportDigest": semantic_digest(body)}


def failure(code: str) -> dict[str, Any]:
    body = {
        "available": False,
        "mode": "distribution-verification-only",
        "status": "blocked",
        "code": code,
        "manifestDigest": None,
        "bundleDigest": None,
        "artifactCount": 0,
        "safety": SAFETY,
    }
    return {**body, "reportDigest": semantic_digest(body)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_distribution.py")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--bundle-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.manifest, args.bundle_root)
    except VerificationError as exc:
        result = failure(str(exc) if str(exc).startswith("ECO_DISTRIBUTION_") else "ECO_DISTRIBUTION_VERIFICATION_FAILED")
    except Exception:
        result = failure("ECO_DISTRIBUTION_VERIFICATION_FAILED")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["available"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
