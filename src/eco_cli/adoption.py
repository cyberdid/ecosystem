from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from . import VERSION
from .audit import audit_repository
from .compiler import (
    ProjectionPlan,
    _backup_path,
    _managed_span,
    _projection_state,
    _verified_backup,
    apply_projections,
    plan_projections,
)
from .config import (
    atomic_write,
    config_directory,
    dump_yaml,
    sha256_file,
    sha256_bytes,
    sha256_text,
    stable_json,
    validate_bundle,
    validate_repository,
)
from .constants import CONFIG_FILES
from .errors import EcoError
from .templates import starter_bundle


ADOPTION_API_VERSION = "adoption.ai.ecosystem/v1alpha1"
ADOPTION_RECEIPT = "adoption.json"
_STATE_IGNORE = "*\n!.gitignore\n"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class _AdoptionContext:
    plan: dict[str, Any]
    bundle: dict[str, dict[str, Any]] | None
    config_paths: dict[str, Path]
    config_content: dict[Path, str]
    projections: tuple[ProjectionPlan, ...]
    lock_path: Path | None
    lock_content: str | None
    prior_receipt: dict[str, Any] | None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _file_digest(path: Path) -> str | None:
    return sha256_file(path) if path.is_file() else None


def _relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise EcoError("ECO_ADOPTION_PATH_INVALID")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise EcoError("ECO_ADOPTION_PATH_INVALID")
    return path


def _repository_path(repo: Path, relative: str) -> Path:
    path = _relative_path(relative)
    candidate = repo.joinpath(*path.parts)
    try:
        candidate.relative_to(repo)
    except ValueError as exc:
        raise EcoError("ECO_ADOPTION_PATH_INVALID") from exc
    return candidate


def _safe_target(repo: Path, relative: str, *, allow_directory: bool = False) -> bool:
    """Reject aliases and special files without resolving through them."""

    try:
        pure = _relative_path(relative)
    except EcoError:
        return False
    current = repo
    for index, part in enumerate(pure.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        final = index == len(pure.parts) - 1
        if stat.S_ISLNK(metadata.st_mode):
            return False
        if final:
            if not stat.S_ISREG(metadata.st_mode) and not (
                allow_directory and stat.S_ISDIR(metadata.st_mode)
            ):
                return False
            if stat.S_ISREG(metadata.st_mode) and os.name == "posix" and metadata.st_nlink != 1:
                return False
        elif not stat.S_ISDIR(metadata.st_mode):
            return False
    return True


def _projection_topology_unsafe(
    repo: Path, bundle: dict[str, dict[str, Any]]
) -> bool:
    projections = bundle.get("instructions", {}).get("projections", {})
    if not isinstance(projections, dict):
        return False
    for relative in projections.values():
        if not isinstance(relative, str) or not _safe_target(repo, relative):
            return True
    return False


def _operation(
    repo: Path,
    path: Path,
    *,
    action: str,
    ownership: str,
    after_digest: str | None,
) -> dict[str, Any]:
    relative = path.relative_to(repo).as_posix()
    before_digest = _file_digest(path)
    if path.exists() and path.is_dir():
        before_state = "directory"
    elif before_digest is not None:
        before_state = "file"
    else:
        before_state = "absent"
    return {
        "path": relative,
        "action": action,
        "ownership": ownership,
        "beforeState": before_state,
        "beforeDigest": before_digest,
        "afterDigest": after_digest,
    }


def _validate_receipt(value: Any) -> dict[str, Any]:
    schema = json.loads(
        resources.files("eco_cli")
        .joinpath("schemas", "adoption-receipt.schema.json")
        .read_text(encoding="utf-8")
    )
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors or not isinstance(value, dict):
        raise EcoError("ECO_ADOPTION_RECEIPT_INVALID")
    paths: set[str] = set()
    for item in value["spec"]["files"]:
        path = item["path"]
        if path in paths:
            raise EcoError("ECO_ADOPTION_RECEIPT_INVALID")
        paths.add(path)
        role, ownership = item["role"], item["ownership"]
        created, block = item["createdDigest"], item["managedBlockDigest"]
        if role == "canonical" and (
            ownership not in {"created", "preexisting"}
            or (ownership == "created" and created is None)
            or block is not None
        ):
            raise EcoError("ECO_ADOPTION_RECEIPT_INVALID")
        if role == "projection" and (
            ownership not in {"created", "managed-block"} or block is None
        ):
            raise EcoError("ECO_ADOPTION_RECEIPT_INVALID")
        if role == "generated" and (
            ownership != "generated" or created is None or block is not None
        ):
            raise EcoError("ECO_ADOPTION_RECEIPT_INVALID")
    return value


def _validate_plan(value: Any) -> dict[str, Any]:
    schema = json.loads(
        resources.files("eco_cli")
        .joinpath("schemas", "adoption-plan.schema.json")
        .read_text(encoding="utf-8")
    )
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors or not isinstance(value, dict):
        raise EcoError("ECO_ADOPTION_PLAN_INVALID")
    body = {key: item for key, item in value.items() if key != "planDigest"}
    if value["planDigest"] != _digest(body):
        raise EcoError("ECO_ADOPTION_PLAN_INVALID")
    paths: set[str] = set()
    for operation in value["spec"]["operations"]:
        path = operation["path"]
        _relative_path(path)
        if path in paths:
            raise EcoError("ECO_ADOPTION_PLAN_INVALID")
        paths.add(path)
    return value


def _read_receipt(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EcoError("ECO_ADOPTION_RECEIPT_INVALID") from exc
    return _validate_receipt(value)


def _fresh_bundle(name: str, discovery: dict[str, Any]) -> dict[str, dict[str, Any]]:
    bundle = starter_bundle(name)
    bundle["project"]["project"]["languages"] = list(discovery.get("languages", []))
    bundle["project"]["project"]["build"] = list(discovery.get("buildFiles", []))
    bundle["project"]["project"]["test"] = []
    # Project commands are suggestions until they have an explicit acceptance contract.
    bundle["instructions"]["commands"] = {"validate": "eco validate"}
    return bundle


def _fresh_projections(
    repo: Path,
    bundle: dict[str, dict[str, Any]],
    instruction_content: str,
) -> tuple[ProjectionPlan, ...]:
    source_digest = sha256_text(instruction_content)
    return tuple(
        plan_projections(
            repo,
            repo / ".ai",
            bundle,
            None,
            adopt=True,
            source_digest=source_digest,
            instruction_source=".ai/instructions.yaml",
        )
    )


def _projection_ownership_is_valid(
    repo: Path,
    directory: Path,
    projections: tuple[ProjectionPlan, ...],
) -> bool:
    try:
        _, state = _projection_state(directory)
        if not state:
            return False
        outputs = {item["path"]: item for item in state["outputs"]}
        expected_paths = {
            projection.path.relative_to(repo).as_posix() for projection in projections
        }
        if set(outputs) != expected_paths:
            return False
        for projection in projections:
            relative = projection.path.relative_to(repo).as_posix()
            output = outputs[relative]
            if output["digest"] != sha256_bytes(projection.current_bytes):
                return False
            if output["backup"] is not None:
                _verified_backup(
                    directory,
                    output["backup"],
                    output["backupDigest"],
                    output["backupSize"],
                )
    except (EcoError, OSError, UnicodeDecodeError, KeyError, ValueError):
        return False
    return True


def _lock_document(
    directory: Path,
    bundle: dict[str, dict[str, Any]],
    config_paths: dict[str, Path],
    config_content: dict[Path, str],
) -> str:
    inputs: dict[str, dict[str, str]] = {}
    for key, path in sorted(config_paths.items()):
        digest = sha256_text(config_content[path]) if path in config_content else sha256_file(path)
        inputs[key] = {"path": path.relative_to(directory).as_posix(), "sha256": digest}
    deployments = [
        {
            "id": item["id"],
            "provider": item["provider"],
            "adapter": item["adapter"],
            "model": item["model"],
            "enabled": item["enabled"],
        }
        for item in bundle["deployments"].get("deployments", [])
    ]
    return stable_json(
        {
            "apiVersion": bundle["project"]["apiVersion"],
            "inputs": inputs,
            "deployments": deployments,
        }
    )


def _blocked_plan(
    *,
    project_name: str,
    mode: str,
    discovery: dict[str, Any],
    blockers: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    body = {
        "apiVersion": ADOPTION_API_VERSION,
        "kind": "ProjectAdoptionPlan",
        "metadata": {
            "toolVersion": VERSION,
            "projectName": project_name if _NAME_RE.fullmatch(project_name) else "unresolved",
            "configRoot": ".ai",
        },
        "spec": {
            "mode": mode,
            "discovery": discovery,
            "operations": [],
        },
        "status": {
            "state": "blocked",
            "blockers": sorted(set(blockers)),
            "warnings": sorted(set(warnings)),
        },
    }
    return _validate_plan({**body, "planDigest": _digest(body)})


def _build_context(
    repo: Path,
    config_root: str,
    name: str | None,
    adopt_existing_config: bool,
) -> _AdoptionContext:
    repo = repo.expanduser().resolve()
    raw_name = name or repo.name.lower().replace(" ", "-")
    try:
        audit = audit_repository(repo, config_root)
    except (OSError, EcoError):
        audit = {
            "git": {"available": False, "dirty": None},
            "languages": [],
            "buildFiles": [],
            "instructionSurfaces": [],
            "potentialSecretLocations": [],
        }
    discovery = {
        "gitAvailable": bool(audit.get("git", {}).get("available")),
        "gitDirty": audit.get("git", {}).get("dirty"),
        "languageCount": len(audit.get("languages", [])),
        "buildFileCount": len(audit.get("buildFiles", [])),
        "instructionSurfaceCount": len(audit.get("instructionSurfaces", [])),
        "potentialSecretLocationCount": len(audit.get("potentialSecretLocations", [])),
    }
    warnings: list[str] = []
    if discovery["gitDirty"]:
        warnings.append("ECO_ADOPTION_DIRTY_WORKTREE")
    if discovery["potentialSecretLocationCount"]:
        warnings.append("ECO_ADOPTION_SECRET_LOCATIONS_PRESENT")
    if not discovery["gitAvailable"]:
        warnings.append("ECO_ADOPTION_GIT_UNAVAILABLE")

    if config_root != ".ai":
        plan = _blocked_plan(
            project_name=raw_name,
            mode="fresh",
            discovery=discovery,
            blockers=["ECO_ADOPTION_CONFIG_ROOT_UNSUPPORTED"],
            warnings=warnings,
        )
        return _AdoptionContext(plan, None, {}, {}, (), None, None, None)
    if not repo.is_dir():
        plan = _blocked_plan(
            project_name=raw_name,
            mode="fresh",
            discovery=discovery,
            blockers=["ECO_ADOPTION_REPOSITORY_INVALID"],
            warnings=warnings,
        )
        return _AdoptionContext(plan, None, {}, {}, (), None, None, None)
    if not _NAME_RE.fullmatch(raw_name):
        plan = _blocked_plan(
            project_name=raw_name,
            mode="fresh",
            discovery=discovery,
            blockers=["ECO_ADOPTION_NAME_INVALID"],
            warnings=warnings,
        )
        return _AdoptionContext(plan, None, {}, {}, (), None, None, None)

    directory = repo / ".ai"
    receipt_path = directory / ADOPTION_RECEIPT
    blockers: list[str] = []
    if not _safe_target(repo, ".ai", allow_directory=True) or not _safe_target(
        repo, ".ai/adoption.json"
    ):
        blockers.append("ECO_ADOPTION_PATH_UNSAFE")

    prior_receipt: dict[str, Any] | None = None
    if not blockers:
        try:
            prior_receipt = _read_receipt(receipt_path)
        except EcoError:
            blockers.append("ECO_ADOPTION_RECEIPT_INVALID")

    config_content: dict[Path, str] = {}
    config_paths: dict[str, Path] = {}
    bundle: dict[str, dict[str, Any]] | None = None
    projections: tuple[ProjectionPlan, ...] = ()
    lock_path: Path | None = None
    lock_content: str | None = None
    mode = "fresh"
    operations: list[dict[str, Any]] = []

    if directory.exists():
        mode = "reinstall" if prior_receipt is not None else "existing-config"
        if prior_receipt is None and not adopt_existing_config:
            blockers.append("ECO_ADOPTION_CONFIG_EXISTS")
        else:
            try:
                errors, bundle, config_paths = validate_repository(repo, config_root)
                topology_unsafe = _projection_topology_unsafe(repo, bundle)
                if topology_unsafe:
                    blockers.append("ECO_ADOPTION_PATH_UNSAFE")
                elif errors:
                    blockers.append("ECO_ADOPTION_CONFIG_INVALID")
                if bundle is not None:
                    raw_name = bundle["project"]["metadata"]["name"]
                for path in config_paths.values():
                    relative = path.relative_to(repo).as_posix()
                    if not _safe_target(repo, relative):
                        blockers.append("ECO_ADOPTION_PATH_UNSAFE")
                if not blockers and bundle is not None:
                    projections = tuple(
                        plan_projections(
                            repo,
                            directory,
                            bundle,
                            config_paths["instructions"],
                            adopt=True,
                        )
                    )
            except (EcoError, OSError, UnicodeDecodeError, KeyError):
                blockers.append("ECO_ADOPTION_CONFIG_INVALID")
    else:
        bundle = _fresh_bundle(raw_name, audit)
        config_paths = {
            key: directory / filename for key, filename in CONFIG_FILES.items()
        }
        config_content = {
            config_paths[key]: dump_yaml(bundle[key]) for key in sorted(bundle)
        }
        errors = validate_bundle(repo, directory, bundle)
        topology_unsafe = _projection_topology_unsafe(repo, bundle)
        if topology_unsafe:
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")
        elif errors:
            blockers.append("ECO_ADOPTION_CONFIG_INVALID")
        for path in config_paths.values():
            if not _safe_target(repo, path.relative_to(repo).as_posix()):
                blockers.append("ECO_ADOPTION_PATH_UNSAFE")
        try:
            projections = _fresh_projections(
                repo, bundle, config_content[config_paths["instructions"]]
            )
        except (EcoError, OSError, UnicodeDecodeError):
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")

    if bundle is not None and not blockers:
        marker_present = any(_managed_span(item.current) is not None for item in projections)
        state_exists = (directory / ".state" / "render.json").exists()
        if mode == "fresh" and marker_present:
            blockers.append("ECO_ADOPTION_OWNERSHIP_AMBIGUOUS")
        elif mode == "reinstall" or (
            mode == "existing-config" and (marker_present or state_exists)
        ):
            if not _projection_ownership_is_valid(repo, directory, projections):
                blockers.append("ECO_ADOPTION_OWNERSHIP_AMBIGUOUS")

    if bundle is not None and not blockers:
        for key, path in sorted(config_paths.items()):
            if mode == "fresh":
                desired = config_content[path]
                operations.append(
                    _operation(
                        repo,
                        path,
                        action="create-canonical",
                        ownership="created",
                        after_digest=sha256_text(desired),
                    )
                )

        for projection in projections:
            relative = projection.path.relative_to(repo).as_posix()
            if not _safe_target(repo, relative):
                blockers.append("ECO_ADOPTION_PATH_UNSAFE")
                continue
            if projection.current == projection.desired:
                continue
            action = {
                "created": "create-managed-surface",
                "adopted": "append-managed-block",
                "updated": "update-managed-block",
            }.get(projection.mode, "update-managed-block")
            prior_entry = next(
                (
                    item
                    for item in (prior_receipt or {}).get("spec", {}).get("files", [])
                    if item.get("path") == relative
                ),
                None,
            )
            ownership = (
                prior_entry.get("ownership")
                if prior_entry is not None
                else ("created" if projection.mode == "created" else "managed-block")
            )
            operations.append(
                _operation(
                    repo,
                    projection.path,
                    action=action,
                    ownership=ownership,
                    after_digest=sha256_text(projection.desired),
                )
            )

        lock_path = directory / "locks" / "ecosystem.lock.json"
        lock_content = _lock_document(directory, bundle, config_paths, config_content)
        if not _safe_target(repo, lock_path.relative_to(repo).as_posix()):
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")
        elif not lock_path.is_file() or lock_path.read_text(encoding="utf-8") != lock_content:
            operations.append(
                _operation(
                    repo,
                    lock_path,
                    action="write-lock",
                    ownership="generated",
                    after_digest=sha256_text(lock_content),
                )
            )

        state_ignore_path = directory / ".state" / ".gitignore"
        if not _safe_target(repo, state_ignore_path.relative_to(repo).as_posix()):
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")
        elif (
            not state_ignore_path.is_file()
            or state_ignore_path.read_text(encoding="utf-8") != _STATE_IGNORE
        ):
            operations.append(
                _operation(
                    repo,
                    state_ignore_path,
                    action="write-state-ignore",
                    ownership="generated",
                    after_digest=sha256_text(_STATE_IGNORE),
                )
            )

        if mode != "reinstall" or operations:
            operations.append(
                _operation(
                    repo,
                    receipt_path,
                    action="write-adoption-receipt",
                    ownership="generated",
                    after_digest=None,
                )
            )

    if blockers:
        plan = _blocked_plan(
            project_name=raw_name,
            mode=mode,
            discovery=discovery,
            blockers=blockers,
            warnings=warnings,
        )
        return _AdoptionContext(plan, bundle, config_paths, config_content, projections, lock_path, lock_content, prior_receipt)

    body = {
        "apiVersion": ADOPTION_API_VERSION,
        "kind": "ProjectAdoptionPlan",
        "metadata": {
            "toolVersion": VERSION,
            "projectName": raw_name,
            "configRoot": ".ai",
        },
        "spec": {
            "mode": mode,
            "discovery": discovery,
            "operations": operations,
        },
        "status": {
            "state": "ready" if operations else "clean",
            "blockers": [],
            "warnings": sorted(set(warnings)),
        },
    }
    plan = _validate_plan({**body, "planDigest": _digest(body)})
    return _AdoptionContext(
        plan,
        bundle,
        config_paths,
        config_content,
        projections,
        lock_path,
        lock_content,
        prior_receipt,
    )


def plan_adoption(
    repo: Path,
    config_root: str = ".ai",
    name: str | None = None,
    adopt_existing_config: bool = False,
) -> dict[str, Any]:
    """Return a deterministic, content-free adoption plan.

    The plan contains repository-relative paths and digests only.  Its digest is
    a stale-preview guard, not an authorization token.
    """

    return _validate_plan(
        _build_context(repo, config_root, name, adopt_existing_config).plan
    )


def _managed_block_digest(content: str) -> str | None:
    span = _managed_span(content)
    if span is None:
        return None
    start, end = span
    return sha256_text(content[start:end])


def _build_receipt(context: _AdoptionContext) -> dict[str, Any]:
    assert context.bundle is not None
    repo_files: dict[str, dict[str, Any]] = {
        item["path"]: dict(item)
        for item in (context.prior_receipt or {}).get("spec", {}).get("files", [])
    }
    mode = context.plan["spec"]["mode"]
    repo = next(iter(context.config_paths.values())).parents[1]
    for path in context.config_paths.values():
        relative = path.relative_to(repo).as_posix()
        if relative in repo_files:
            continue
        digest = sha256_file(path)
        repo_files[relative] = {
            "path": relative,
            "role": "canonical",
            "ownership": "created" if mode == "fresh" else "preexisting",
            "createdDigest": digest if mode == "fresh" else None,
            "managedBlockDigest": None,
        }
    for projection in context.projections:
        relative = projection.path.relative_to(repo).as_posix()
        existing = repo_files.get(relative)
        ownership = (
            existing["ownership"]
            if existing is not None
            else ("created" if projection.mode == "created" else "managed-block")
        )
        repo_files[relative] = {
            "path": relative,
            "role": "projection",
            "ownership": ownership,
            "createdDigest": (
                existing.get("createdDigest")
                if existing is not None
                else (sha256_file(projection.path) if ownership == "created" else None)
            ),
            "managedBlockDigest": _managed_block_digest(
                projection.path.read_text(encoding="utf-8")
            ),
        }
    if context.lock_path is not None:
        relative = context.lock_path.relative_to(repo).as_posix()
        repo_files[relative] = {
            "path": relative,
            "role": "generated",
            "ownership": "generated",
            "createdDigest": sha256_file(context.lock_path),
            "managedBlockDigest": None,
        }
    state_ignore_path = repo / ".ai" / ".state" / ".gitignore"
    if state_ignore_path.is_file():
        relative = state_ignore_path.relative_to(repo).as_posix()
        repo_files[relative] = {
            "path": relative,
            "role": "generated",
            "ownership": "generated",
            "createdDigest": sha256_file(state_ignore_path),
            "managedBlockDigest": None,
        }
    return {
        "apiVersion": ADOPTION_API_VERSION,
        "kind": "ProjectAdoptionReceipt",
        "metadata": {
            "ecosystemVersion": VERSION,
            "projectName": context.plan["metadata"]["projectName"],
        },
        "spec": {
            "configRoot": ".ai",
            "templateVersion": "starter-v1",
            "appliedPlanDigest": context.plan["planDigest"],
            "files": [repo_files[path] for path in sorted(repo_files)],
        },
    }


def _snapshot(path: Path) -> tuple[bytes | None, int | None]:
    if not path.exists():
        return None, None
    metadata = path.stat()
    return path.read_bytes(), stat.S_IMODE(metadata.st_mode)


def _restore(path: Path, snapshot: tuple[bytes | None, int | None]) -> None:
    content, mode = snapshot
    if content is None:
        if path.exists() and path.is_file():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def _exclusive_adoption_lock(repo: Path):
    """Serialize apply outside the governed repository without persisting paths."""

    identity = (
        f"uid:{os.getuid()}" if hasattr(os, "getuid") else f"home:{Path.home()}"
    )
    identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    lock_root = Path(tempfile.gettempdir()) / f"eco-adoption-locks-{identity_digest}"
    try:
        root_metadata = lock_root.lstat()
    except FileNotFoundError:
        try:
            lock_root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        root_metadata = lock_root.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or bool(getattr(root_metadata, "st_file_attributes", 0) & reparse_flag)
        or (
            os.name == "posix"
            and (
                root_metadata.st_uid != os.getuid()
                or stat.S_IMODE(root_metadata.st_mode) & 0o077
            )
        )
    ):
        raise EcoError("ECO_ADOPTION_LOCK_UNSAFE")
    name = hashlib.sha256(str(repo).encode("utf-8")).hexdigest()
    lock_path = lock_root / f"{name}.lock"
    try:
        existing_lock = lock_path.lstat()
    except FileNotFoundError:
        existing_lock = None
    except OSError as exc:
        raise EcoError("ECO_ADOPTION_LOCK_UNSAFE") from exc
    if existing_lock is not None and (
        stat.S_ISLNK(existing_lock.st_mode)
        or not stat.S_ISREG(existing_lock.st_mode)
        or existing_lock.st_nlink != 1
        or bool(getattr(existing_lock, "st_file_attributes", 0) & reparse_flag)
        or (
            os.name == "posix"
            and (
                existing_lock.st_uid != os.getuid()
                or stat.S_IMODE(existing_lock.st_mode) & 0o077
            )
        )
    ):
        raise EcoError("ECO_ADOPTION_LOCK_UNSAFE")
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise EcoError("ECO_ADOPTION_LOCK_UNSAFE") from exc
    try:
        lock_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or (
                os.name == "posix"
                and (
                    lock_metadata.st_uid != os.getuid()
                    or stat.S_IMODE(lock_metadata.st_mode) & 0o077
                )
            )
        ):
            raise EcoError("ECO_ADOPTION_LOCK_UNSAFE")
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise EcoError("ECO_ADOPTION_BUSY") from exc
        elif os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise EcoError("ECO_ADOPTION_BUSY") from exc
        yield
    finally:
        if os.name == "posix":
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif os.name == "nt":
            import msvcrt

            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        os.close(descriptor)


def apply_adoption(
    repo: Path,
    *,
    expected_plan_digest: str,
    config_root: str = ".ai",
    name: str | None = None,
    adopt_existing_config: bool = False,
) -> dict[str, Any]:
    resolved = repo.expanduser().resolve()
    with _exclusive_adoption_lock(resolved):
        return _apply_adoption_locked(
            resolved,
            expected_plan_digest=expected_plan_digest,
            config_root=config_root,
            name=name,
            adopt_existing_config=adopt_existing_config,
        )


def _apply_adoption_locked(
    repo: Path,
    *,
    expected_plan_digest: str,
    config_root: str = ".ai",
    name: str | None = None,
    adopt_existing_config: bool = False,
) -> dict[str, Any]:
    """Apply exactly the recomputed plan and return a content-free result."""

    if not _DIGEST_RE.fullmatch(expected_plan_digest):
        raise EcoError("ECO_ADOPTION_PLAN_DIGEST_INVALID")
    repo = repo.expanduser().resolve()
    context = _build_context(repo, config_root, name, adopt_existing_config)
    plan = context.plan
    if plan["status"]["state"] == "blocked":
        raise EcoError(plan["status"]["blockers"][0])
    if plan["planDigest"] != expected_plan_digest:
        raise EcoError("ECO_ADOPTION_PLAN_CHANGED")
    if plan["status"]["state"] == "clean":
        return {
            "applied": False,
            "status": "already-adopted",
            "planDigest": plan["planDigest"],
            "operationCount": 0,
        }
    if context.bundle is None:
        raise EcoError("ECO_ADOPTION_CONFIG_INVALID")

    directory = config_directory(repo, config_root)
    receipt_path = directory / ADOPTION_RECEIPT
    state_path = directory / ".state" / "render.json"
    state_ignore_path = directory / ".state" / ".gitignore"
    affected = {
        *context.config_content,
        *(projection.path for projection in context.projections),
        *(
            _backup_path(directory, repo, projection)
            for projection in context.projections
            if projection.mode in {"adopted", "replaced"}
            and projection.current_bytes
        ),
        *(
            path
            for path in (context.lock_path, receipt_path, state_path, state_ignore_path)
            if path is not None
        ),
    }
    snapshots = {path: _snapshot(path) for path in affected}
    expected_after: dict[Path, bytes] = {
        path: content.encode("utf-8") for path, content in context.config_content.items()
    }
    expected_after[state_ignore_path] = _STATE_IGNORE.encode("utf-8")
    for projection in context.projections:
        if projection.current != projection.desired:
            expected_after[projection.path] = projection.desired.encode("utf-8")
        if projection.mode in {"adopted", "replaced"} and projection.current_bytes:
            expected_after[
                _backup_path(directory, repo, projection)
            ] = projection.current_bytes
    if context.lock_path is not None and context.lock_content is not None:
        expected_after[context.lock_path] = context.lock_content.encode("utf-8")
    try:
        for path, content in sorted(
            context.config_content.items(), key=lambda item: item[0].as_posix()
        ):
            if path.exists():
                raise EcoError("ECO_ADOPTION_PLAN_CHANGED")
            atomic_write(path, content)

        if not state_ignore_path.is_file() or state_ignore_path.read_text(
            encoding="utf-8"
        ) != _STATE_IGNORE:
            atomic_write(state_ignore_path, _STATE_IGNORE)

        if any(item.current != item.desired for item in context.projections):
            apply_projections(repo, directory, list(context.projections))
            expected_after[state_path] = state_path.read_bytes()

        if context.lock_path is not None and context.lock_content is not None:
            current = (
                context.lock_path.read_text(encoding="utf-8")
                if context.lock_path.is_file()
                else None
            )
            if current != context.lock_content:
                atomic_write(context.lock_path, context.lock_content)

        errors, _, _ = validate_repository(repo, config_root)
        if errors:
            raise EcoError("ECO_ADOPTION_CONFIG_INVALID")

        receipt = _build_receipt(context)
        _validate_receipt(receipt)
        atomic_write(receipt_path, stable_json(receipt))
    except BaseException as error:
        rollback_conflicts: list[Path] = []
        for path in sorted(snapshots, key=lambda item: len(item.parts), reverse=True):
            expected = expected_after.get(path)
            if expected is None:
                continue
            try:
                live = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            except OSError:
                live = None
            before = snapshots[path][0]
            if live != expected:
                if live != before:
                    rollback_conflicts.append(path)
                continue
            _restore(path, snapshots[path])
        for parent in sorted(
            {
                parent
                for path in affected
                for parent in path.parents
                if parent != repo and parent.is_relative_to(repo)
            },
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            try:
                parent.rmdir()
            except OSError:
                pass
        if rollback_conflicts:
            raise EcoError("ECO_ADOPTION_ROLLBACK_CONFLICT") from error
        raise

    return {
        "applied": True,
        "status": "adopted",
        "planDigest": plan["planDigest"],
        "operationCount": len(plan["spec"]["operations"]),
    }


def remove_owned_adoption_config(
    repo: Path,
    config_root: str = ".ai",
    *,
    dry_run: bool = False,
    allow_projection_state: bool = False,
) -> dict[str, Any]:
    """Remove only exact receipt-owned config after a complete read-only preflight."""

    repo = repo.expanduser().resolve()
    if config_root != ".ai":
        return {
            "removed": False,
            "status": "blocked",
            "blockers": ["ECO_ADOPTION_CONFIG_ROOT_UNSUPPORTED"],
            "removedCount": 0,
        }
    directory = repo / ".ai"
    receipt_path = directory / ADOPTION_RECEIPT
    if not _safe_target(repo, ".ai", allow_directory=True) or not _safe_target(
        repo, ".ai/adoption.json"
    ):
        return {
            "removed": False,
            "status": "blocked",
            "blockers": ["ECO_ADOPTION_PATH_UNSAFE"],
            "removedCount": 0,
        }
    try:
        receipt = _read_receipt(receipt_path)
    except EcoError:
        receipt = None
    if receipt is None:
        return {
            "removed": False,
            "status": "blocked",
            "blockers": ["ECO_ADOPTION_RECEIPT_REQUIRED"],
            "removedCount": 0,
        }

    blockers: list[str] = []
    removable: set[Path] = {receipt_path}
    expected_digests: dict[Path, str] = {receipt_path: sha256_file(receipt_path)}
    known_inside: set[Path] = {receipt_path}
    for item in receipt["spec"]["files"]:
        try:
            path = _repository_path(repo, item["path"])
        except EcoError:
            blockers.append("ECO_ADOPTION_RECEIPT_INVALID")
            continue
        try:
            path.relative_to(directory)
        except ValueError:
            continue
        known_inside.add(path)
        if item["role"] == "projection":
            if path.exists() or path.is_symlink():
                blockers.append("ECO_ADOPTION_PROJECTION_CLEANUP_REQUIRED")
            continue
        if item["ownership"] == "preexisting":
            blockers.append("ECO_ADOPTION_PREEXISTING_CONFIG")
            continue
        expected = item.get("createdDigest")
        if not path.is_file() or not isinstance(expected, str) or sha256_file(path) != expected:
            blockers.append("ECO_ADOPTION_CONFIG_DRIFT")
            continue
        if not _safe_target(repo, item["path"]):
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")
            continue
        removable.add(path)
        expected_digests[path] = expected

    local_state = {
        directory / ".state" / "render.json",
        directory / ".state" / ".gitignore",
    }
    known_inside.update(local_state)
    if allow_projection_state:
        try:
            _, state = _projection_state(directory)
            if not state:
                raise EcoError("ECO_ADOPTION_PROJECTION_STATE_INVALID")
            for output in state["outputs"]:
                backup_relative = output["backup"]
                if not backup_relative:
                    continue
                backup, _ = _verified_backup(
                    directory,
                    backup_relative,
                    output["backupDigest"],
                    output["backupSize"],
                )
                known_inside.add(backup)
        except (OSError, UnicodeDecodeError, ValueError, EcoError, KeyError):
            blockers.append("ECO_ADOPTION_PROJECTION_STATE_INVALID")

    known_directories: set[Path] = {
        directory,
        directory / ".state",
        directory / ".state" / "backups",
        directory / "locks",
    }
    for path in known_inside:
        for parent in path.parents:
            if parent == directory:
                known_directories.add(parent)
                break
            if parent.is_relative_to(directory):
                known_directories.add(parent)
    if directory.exists():
        try:
            for path in directory.rglob("*"):
                if path.is_symlink() or path.is_file():
                    unknown = path not in known_inside
                else:
                    unknown = not path.is_dir() or path not in known_directories
                if unknown:
                    blockers.append("ECO_ADOPTION_UNKNOWN_CONFIG_ENTRY")
        except OSError:
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")

    # Revalidate the deletion set and inventory after discovery. This catches
    # changes injected during preflight before any projection/config mutation.
    for path, expected in expected_digests.items():
        try:
            relative = path.relative_to(repo).as_posix()
            metadata = path.lstat()
        except (OSError, ValueError):
            blockers.append("ECO_ADOPTION_CONFIG_DRIFT")
            continue
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not _safe_target(repo, relative)
            or sha256_file(path) != expected
        ):
            blockers.append("ECO_ADOPTION_CONFIG_DRIFT")
    if directory.exists():
        try:
            for path in directory.rglob("*"):
                if path.is_symlink() or path.is_file():
                    unknown = path not in known_inside
                else:
                    unknown = not path.is_dir() or path not in known_directories
                if unknown:
                    blockers.append("ECO_ADOPTION_UNKNOWN_CONFIG_ENTRY")
        except OSError:
            blockers.append("ECO_ADOPTION_PATH_UNSAFE")

    if blockers:
        return {
            "removed": False,
            "status": "blocked",
            "blockers": sorted(set(blockers)),
            "removedCount": 0,
        }

    if dry_run:
        return {
            "removed": False,
            "status": "ready",
            "blockers": [],
            "removedCount": 0,
        }

    count = 0
    for path in sorted(removable, key=lambda item: len(item.parts), reverse=True):
        expected = expected_digests[path]
        try:
            metadata = path.lstat()
            relative = path.relative_to(repo).as_posix()
        except (OSError, ValueError) as exc:
            raise EcoError("ECO_ADOPTION_CONFIG_DRIFT") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not _safe_target(repo, relative)
            or sha256_file(path) != expected
        ):
            raise EcoError("ECO_ADOPTION_CONFIG_DRIFT")
        path.unlink()
        count += 1
    for path in sorted(
        [item for item in directory.rglob("*") if item.is_dir()] + [directory],
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            path.rmdir()
        except OSError:
            pass
    return {
        "removed": True,
        "status": "removed",
        "blockers": [],
        "removedCount": count,
    }
