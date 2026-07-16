from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import os
import re
import stat
import unicodedata
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator


DISTRIBUTION_API_VERSION = "distribution.ai.ecosystem/v1alpha1"
PACKAGE_NAME = "ai-ecosystem-harness"
PYTHON_REQUIRES = ">=3.11"
INSTALLER_ADAPTERS = ("pipx", "uv-tool", "venv-pip")
INSTALLER_OPERATIONS = ("install", "upgrade", "uninstall")
MAX_WHEEL_BYTES = 512 * 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_WHEEL_ENTRIES = 4096
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024

_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_REVISION_RE = re.compile(r"^[a-f0-9]{7,64}$")
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9._+-]{0,32})?$")
_WHEEL_VERSION_RE = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9._+!]{0,32})?$"
)
_WHEEL_RE = re.compile(
    r"^(?P<distribution>[A-Za-z0-9](?:[A-Za-z0-9_.]*[A-Za-z0-9])?)-"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.!+]*)(?:-[0-9][A-Za-z0-9_]*)?-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*-"
    r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*\.whl$"
)
_REQUIRED_PACKAGE_ENTRIES = frozenset(
    {
        "eco_cli/cli.py",
        "eco_cli/__init__.py",
        "eco_cli/authority.py",
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
)


class _DistributionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DistributionError("ECO_DISTRIBUTION_MANIFEST_INVALID")
        result[key] = value
    return result


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def distribution_manifest_digest(document: Mapping[str, Any]) -> str:
    body = copy.deepcopy(dict(document))
    metadata = body.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("manifestDigest", None)
    return _semantic_digest(body)


def installer_plan_digest(document: Mapping[str, Any]) -> str:
    body = copy.deepcopy(dict(document))
    metadata = body.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("planDigest", None)
    return _semantic_digest(body)


def _schema() -> dict[str, Any]:
    source = resources.files("eco_cli").joinpath(
        "schemas", "distribution-manifest.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def distribution_manifest_errors(document: Any) -> list[str]:
    validator = Draft202012Validator(_schema())
    errors = sorted(
        validator.iter_errors(document),
        key=lambda item: (list(item.absolute_path), str(item.validator)),
    )
    sanitized: list[str] = []
    for error in errors:
        location = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        sanitized.append(f"{location}: {error.validator or 'invalid'}")
    if errors or not isinstance(document, dict):
        return sanitized

    metadata = document.get("metadata")
    spec = document.get("spec")
    if isinstance(metadata, dict) and metadata.get("manifestDigest") != distribution_manifest_digest(document):
        sanitized.append("$.metadata.manifestDigest: digest")
    if not isinstance(spec, dict):
        return sanitized

    package = spec.get("package")
    if isinstance(metadata, dict) and isinstance(package, dict):
        version = package.get("version")
        if metadata.get("id") != f"{PACKAGE_NAME}-{version}":
            sanitized.append("$.metadata.id: identity")
        if metadata.get("version") != version:
            sanitized.append("$.metadata.version: identity")

    artifacts = [spec.get("mainArtifact"), *spec.get("dependencyArtifacts", [])]
    for index, item in enumerate(artifacts):
        if isinstance(item, dict) and type(item.get("size")) is not int:
            sanitized.append(f"$.spec.artifacts[{index}].size: strict-integer")
    filenames = [item.get("filename") for item in artifacts if isinstance(item, dict)]
    if filenames and filenames[1:] != sorted(filenames[1:]):
        sanitized.append("$.spec.dependencyArtifacts: order")
    if len(filenames) != len(set(filenames)):
        sanitized.append("$.spec.artifacts: duplicate")
    schemas = spec.get("schemaEntries")
    if isinstance(schemas, list):
        for index, item in enumerate(schemas):
            if isinstance(item, dict) and type(item.get("size")) is not int:
                sanitized.append(
                    f"$.spec.schemaEntries[{index}].size: strict-integer"
                )
        paths = [item.get("path") for item in schemas if isinstance(item, dict)]
        if paths != sorted(paths):
            sanitized.append("$.spec.schemaEntries: order")
        if len(paths) != len(set(paths)):
            sanitized.append("$.spec.schemaEntries: duplicate")
    installers = spec.get("installers")
    if installers != list(INSTALLER_ADAPTERS):
        sanitized.append("$.spec.installers: exact-inventory")
    return sanitized


def validate_distribution_manifest(document: Any) -> dict[str, Any]:
    errors = distribution_manifest_errors(document)
    if errors:
        raise _DistributionError("ECO_DISTRIBUTION_MANIFEST_INVALID")
    return document


def load_distribution_manifest(path: Path) -> dict[str, Any]:
    """Load one bounded, regular manifest without following aliases."""

    source = Path(path)
    if not source.is_absolute():
        raise _DistributionError("ECO_DISTRIBUTION_PATH_INVALID")
    try:
        raw = _read_regular_file(source, maximum_size=MAX_MANIFEST_BYTES)
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
        )
    except _DistributionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _DistributionError("ECO_DISTRIBUTION_MANIFEST_INVALID") from exc
    return validate_distribution_manifest(document)


def _safe_wheel_name(path: Path) -> str:
    name = path.name
    if path.parent == path or _WHEEL_RE.fullmatch(name) is None:
        raise _DistributionError("ECO_DISTRIBUTION_ARTIFACT_NAME_INVALID")
    return name


def _wheel_filename_identity(name: str) -> tuple[str, str]:
    match = _WHEEL_RE.fullmatch(name)
    if match is None:
        raise _DistributionError("ECO_DISTRIBUTION_ARTIFACT_NAME_INVALID")
    distribution = re.sub(r"[-_.]+", "-", match.group("distribution")).lower()
    return distribution, match.group("version")


def _safe_zip_path(name: str) -> bool:
    path = PurePosixPath(name)
    return not (
        not name
        or "\\" in name
        or name.startswith("/")
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    )


def _wheel_inventory_bytes(
    encoded: bytes, *, require_main_package: bool
) -> tuple[str, str, list[dict[str, Any]]]:
    try:
        with zipfile.ZipFile(io.BytesIO(encoded)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_WHEEL_ENTRIES:
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")
            names = [item.filename for item in infos]
            normalized_names = [unicodedata.normalize("NFC", item).casefold() for item in names]
            if (
                len(names) != len(set(names))
                or len(normalized_names) != len(set(normalized_names))
                or any(not _safe_zip_path(name) for name in names)
                or sum(item.file_size for item in infos) > MAX_WHEEL_BYTES
            ):
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")
            for info in infos:
                mode = (info.external_attr >> 16) & 0xFFFF
                type_bits = stat.S_IFMT(mode)
                valid_type = type_bits == 0 or stat.S_ISREG(mode) or (
                    stat.S_ISDIR(mode) and info.filename.endswith("/")
                )
                if (
                    info.flag_bits & 0x1
                    or info.file_size > MAX_ENTRY_BYTES
                    or not valid_type
                ):
                    raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")

            metadata_infos = [
                item for item in infos if item.filename.endswith(".dist-info/METADATA")
            ]
            if len(metadata_infos) != 1 or metadata_infos[0].file_size > 1024 * 1024:
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")
            metadata_name = metadata_infos[0].filename
            dist_info = metadata_name[: -len("METADATA")]
            required_dist_info = {
                f"{dist_info}METADATA",
                f"{dist_info}WHEEL",
                f"{dist_info}RECORD",
            }
            if not required_dist_info <= set(names):
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")

            metadata = BytesParser(policy=email_policy).parsebytes(
                archive.read(metadata_infos[0])
            )
            package_name = re.sub(
                r"[-_.]+", "-", str(metadata.get("Name", ""))
            ).lower()
            version = str(metadata.get("Version", ""))
            if not package_name or _WHEEL_VERSION_RE.fullmatch(version) is None:
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")

            record_info = archive.getinfo(f"{dist_info}RECORD")
            if record_info.file_size > MAX_ENTRY_BYTES:
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")
            record_rows = list(
                csv.reader(io.StringIO(archive.read(record_info).decode("utf-8")))
            )
            record_names = [row[0] for row in record_rows if len(row) == 3]
            if (
                len(record_rows) != len(record_names)
                or len(record_names) != len(set(record_names))
                or set(record_names) != {name for name in names if not name.endswith("/")}
            ):
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")

            if require_main_package:
                entry_points = f"{dist_info}entry_points.txt"
                if (
                    package_name != PACKAGE_NAME
                    or metadata.get("Requires-Python") != PYTHON_REQUIRES
                    or not _REQUIRED_PACKAGE_ENTRIES <= set(names)
                    or entry_points not in names
                ):
                    raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")
                entry_info = archive.getinfo(entry_points)
                if entry_info.file_size > 64 * 1024:
                    raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID")
                entry_text = archive.read(entry_info).decode("utf-8")
                normalized = "".join(entry_text.split())
                if "[console_scripts]" not in entry_text or "eco=eco_cli.cli:main" not in normalized:
                    raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")

            schema_entries: list[dict[str, Any]] = []
            for info in sorted(infos, key=lambda item: item.filename):
                if not (
                    info.filename.startswith("eco_cli/schemas/")
                    or info.filename.startswith("eco_runtime/schemas/")
                ) or not info.filename.endswith(".json"):
                    continue
                content = archive.read(info)
                schema_entries.append(
                    {
                        "path": info.filename,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size": len(content),
                    }
                )
            if require_main_package and not schema_entries:
                raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INCOMPLETE")
            return package_name, version, schema_entries
    except _DistributionError:
        raise
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        raise _DistributionError("ECO_DISTRIBUTION_WHEEL_INVALID") from exc


def _inspect_wheel_artifact(
    path: Path, *, require_main_package: bool
) -> tuple[dict[str, Any], str, str, list[dict[str, Any]]]:
    name = _safe_wheel_name(path)
    encoded = _read_regular_file(path, maximum_size=MAX_WHEEL_BYTES)
    package_name, version, schemas = _wheel_inventory_bytes(
        encoded, require_main_package=require_main_package
    )
    filename_package, filename_version = _wheel_filename_identity(name)
    if filename_package != package_name or filename_version != version:
        raise _DistributionError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")
    return (
        {"filename": name, "sha256": hashlib.sha256(encoded).hexdigest(), "size": len(encoded)},
        package_name,
        version,
        schemas,
    )


def _read_regular_file(path: Path, *, maximum_size: int) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum_size
            or getattr(before, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise _DistributionError("ECO_DISTRIBUTION_FILE_UNSAFE")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or any(
                getattr(before, field) != getattr(opened, field)
                for field in identity_fields
            )
        ):
            raise _DistributionError("ECO_DISTRIBUTION_FILE_UNSAFE")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum_size + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum_size:
                raise _DistributionError("ECO_DISTRIBUTION_FILE_UNSAFE")
        after = os.fstat(descriptor)
        if total != after.st_size or any(
            getattr(opened, field) != getattr(after, field)
            for field in identity_fields
        ):
            raise _DistributionError("ECO_DISTRIBUTION_ARTIFACT_CHANGED")
        return b"".join(chunks)
    except _DistributionError:
        raise
    except OSError as exc:
        raise _DistributionError("ECO_DISTRIBUTION_FILE_UNREADABLE") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def distribution_file_digest(path: Path, *, maximum_size: int) -> str:
    """Digest one bounded regular non-alias file for release tooling."""

    return hashlib.sha256(
        _read_regular_file(Path(path), maximum_size=maximum_size)
    ).hexdigest()


def build_distribution_manifest(
    main_wheel: Path,
    *,
    dependency_wheels: Sequence[Path],
    version: str,
    lock_digest: str,
    source_revision: str,
) -> dict[str, Any]:
    """Build deterministic integrity metadata; this does not attest artifact origin."""

    if _VERSION_RE.fullmatch(version) is None:
        raise _DistributionError("ECO_DISTRIBUTION_VERSION_INVALID")
    if _DIGEST_RE.fullmatch(lock_digest) is None or _REVISION_RE.fullmatch(source_revision) is None:
        raise _DistributionError("ECO_DISTRIBUTION_BINDING_INVALID")
    if not isinstance(dependency_wheels, Sequence) or isinstance(dependency_wheels, (str, bytes)):
        raise _DistributionError("ECO_DISTRIBUTION_DEPENDENCIES_INVALID")
    if len(dependency_wheels) > 128:
        raise _DistributionError("ECO_DISTRIBUTION_DEPENDENCIES_INVALID")
    main_path = Path(main_wheel)
    main_artifact, package_name, wheel_version, schema_entries = _inspect_wheel_artifact(
        main_path, require_main_package=True
    )
    if wheel_version != version:
        raise _DistributionError("ECO_DISTRIBUTION_VERSION_MISMATCH")
    dependencies = sorted(
        (
            _inspect_wheel_artifact(Path(path), require_main_package=False)[0]
            for path in dependency_wheels
        ),
        key=lambda item: item["filename"],
    )
    names = [main_artifact["filename"], *(item["filename"] for item in dependencies)]
    if len(names) != len(set(names)):
        raise _DistributionError("ECO_DISTRIBUTION_DEPENDENCIES_INVALID")

    document: dict[str, Any] = {
        "apiVersion": DISTRIBUTION_API_VERSION,
        "kind": "DistributionManifest",
        "metadata": {
            "id": f"{PACKAGE_NAME}-{version}",
            "version": version,
            "manifestDigest": "0" * 64,
        },
        "spec": {
            "package": {
                "name": package_name,
                "version": version,
                "entryPoint": "eco",
                "pythonRequires": PYTHON_REQUIRES,
                "format": "wheel",
            },
            "mainArtifact": main_artifact,
            "dependencyArtifacts": dependencies,
            "lockDigest": lock_digest,
            "sourceRevision": source_revision,
            "schemaEntries": schema_entries,
            "installers": list(INSTALLER_ADAPTERS),
            "support": {
                "operatingSystems": ["linux", "macos", "windows", "wsl"],
                "architecture": "python-wheel-dependent",
                "offlineWheelhouse": True,
                "zipapp": False,
                "standaloneBinary": False,
            },
            "provenance": {
                "artifactIntegrity": "sha256",
                "originAuthentication": "not-attested",
                "sbom": "not-included",
            },
            "safety": {
                "authorityCreated": False,
                "installationPerformed": False,
                "projectMutation": False,
                "networkAccessed": False,
            },
        },
    }
    document["metadata"]["manifestDigest"] = distribution_manifest_digest(document)
    validate_distribution_manifest(document)
    return document


def _blocked_report(code: str) -> dict[str, Any]:
    body = {
        "available": False,
        "mode": "distribution-verification-only",
        "status": "blocked",
        "code": code,
        "manifestDigest": None,
        "bundleDigest": None,
        "artifactCount": 0,
        "safety": {
            "authorityCreated": False,
            "installationPerformed": False,
            "projectMutation": False,
            "networkAccessed": False,
        },
    }
    return {**body, "reportDigest": _semantic_digest(body)}


def verify_distribution(manifest: dict[str, Any], bundle_root: Path) -> dict[str, Any]:
    """Verify a complete local wheelhouse without executing or installing it."""

    try:
        validate_distribution_manifest(copy.deepcopy(manifest))
        root = Path(bundle_root)
        root_status = root.lstat()
        if not stat.S_ISDIR(root_status.st_mode):
            raise _DistributionError("ECO_DISTRIBUTION_BUNDLE_UNSAFE")
        if getattr(root_status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise _DistributionError("ECO_DISTRIBUTION_BUNDLE_UNSAFE")
        spec = manifest["spec"]
        artifacts = [spec["mainArtifact"], *spec["dependencyArtifacts"]]
        expected_names = {item["filename"] for item in artifacts}
        actual_entries = list(root.iterdir())
        actual_wheels = {
            item.name for item in actual_entries if item.name.endswith(".whl")
        }
        if actual_wheels != expected_names:
            raise _DistributionError("ECO_DISTRIBUTION_BUNDLE_INCOMPLETE")
        if {item.name for item in actual_entries} != {*expected_names, "uv.lock"}:
            raise _DistributionError("ECO_DISTRIBUTION_BUNDLE_INCOMPLETE")

        lock_bytes = _read_regular_file(
            root / "uv.lock", maximum_size=MAX_LOCK_BYTES
        )
        lock_digest = hashlib.sha256(lock_bytes).hexdigest()
        if lock_digest != spec["lockDigest"]:
            raise _DistributionError("ECO_DISTRIBUTION_LOCK_MISMATCH")
        verified: list[dict[str, Any]] = []
        main_identity: tuple[str, str, list[dict[str, Any]]] | None = None
        for index, artifact in enumerate(artifacts):
            inspected, package_name, version, schema_entries = _inspect_wheel_artifact(
                root / artifact["filename"], require_main_package=index == 0
            )
            if inspected != artifact:
                raise _DistributionError("ECO_DISTRIBUTION_ARTIFACT_MISMATCH")
            verified.append(inspected)
            if index == 0:
                main_identity = (package_name, version, schema_entries)

        if main_identity is None:
            raise _DistributionError("ECO_DISTRIBUTION_BUNDLE_INCOMPLETE")
        package_name, version, schema_entries = main_identity
        if (
            package_name != spec["package"]["name"]
            or version != spec["package"]["version"]
            or schema_entries != spec["schemaEntries"]
        ):
            raise _DistributionError("ECO_DISTRIBUTION_WHEEL_IDENTITY_INVALID")

        bundle_digest = _semantic_digest(verified)
        body = {
            "available": True,
            "mode": "distribution-verification-only",
            "status": "pass",
            "code": "ECO_DISTRIBUTION_VERIFIED",
            "manifestDigest": manifest["metadata"]["manifestDigest"],
            "bundleDigest": bundle_digest,
            "artifactCount": len(verified),
            "safety": {
                "authorityCreated": False,
                "installationPerformed": False,
                "projectMutation": False,
                "networkAccessed": False,
            },
        }
        return {**body, "reportDigest": _semantic_digest(body)}
    except _DistributionError as exc:
        return _blocked_report(exc.code)
    except Exception:
        return _blocked_report("ECO_DISTRIBUTION_VERIFICATION_FAILED")


def installer_plan(
    manifest: dict[str, Any], adapter: str, operation: str = "install"
) -> dict[str, Any]:
    """Return a descriptive tokenized package-manager plan; never execute it."""

    validate_distribution_manifest(copy.deepcopy(manifest))
    if adapter not in INSTALLER_ADAPTERS or operation not in INSTALLER_OPERATIONS:
        raise _DistributionError("ECO_INSTALLER_PLAN_INVALID")
    package = f"{PACKAGE_NAME}=={manifest['metadata']['version']}"
    commands = {
        ("pipx", "install"): ["pipx", "install", "--pip-args=--no-index --find-links <verified-bundle>", package],
        ("pipx", "upgrade"): ["pipx", "install", "--force", "--pip-args=--no-index --find-links <verified-bundle>", package],
        ("pipx", "uninstall"): ["pipx", "uninstall", PACKAGE_NAME],
        ("uv-tool", "install"): ["uv", "tool", "install", "--offline", "--find-links", "<verified-bundle>", package],
        ("uv-tool", "upgrade"): ["uv", "tool", "install", "--force", "--offline", "--find-links", "<verified-bundle>", package],
        ("uv-tool", "uninstall"): ["uv", "tool", "uninstall", PACKAGE_NAME],
        ("venv-pip", "install"): ["<venv-python>", "-m", "pip", "install", "--no-index", "--find-links", "<verified-bundle>", package],
        ("venv-pip", "upgrade"): ["<venv-python>", "-m", "pip", "install", "--upgrade", "--no-index", "--find-links", "<verified-bundle>", package],
        ("venv-pip", "uninstall"): ["<venv-python>", "-m", "pip", "uninstall", "--yes", PACKAGE_NAME],
    }
    document: dict[str, Any] = {
        "apiVersion": DISTRIBUTION_API_VERSION,
        "kind": "InstallerPlan",
        "metadata": {"id": f"{adapter}-{operation}-{manifest['metadata']['version']}", "planDigest": "0" * 64},
        "spec": {
            "manifestDigest": manifest["metadata"]["manifestDigest"],
            "adapter": adapter,
            "operation": operation,
            "argv": commands[(adapter, operation)],
            "preconditions": {
                "verifiedBundleRequired": True,
                "isolatedUserEnvironmentRequired": True,
                "administratorRequired": False,
                "projectAdoptionSeparate": True,
            },
            "safety": {
                "executionReady": False,
                "authorityCreated": False,
                "installationPerformed": False,
                "projectMutation": False,
                "networkAccessed": False,
            },
        },
    }
    document["metadata"]["planDigest"] = installer_plan_digest(document)
    return document


__all__ = [
    "DISTRIBUTION_API_VERSION",
    "INSTALLER_ADAPTERS",
    "INSTALLER_OPERATIONS",
    "build_distribution_manifest",
    "distribution_manifest_digest",
    "distribution_manifest_errors",
    "distribution_file_digest",
    "installer_plan",
    "installer_plan_digest",
    "load_distribution_manifest",
    "validate_distribution_manifest",
    "verify_distribution",
]
