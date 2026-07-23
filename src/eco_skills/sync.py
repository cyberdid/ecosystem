from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from eco_cli.config import atomic_write_bytes, stable_json
from eco_cli.errors import EcoError


DEFAULT_SURFACES = ("codex", "claude", "gemini", "portable", "copilot", "cursor")
LOCK_PATH = ".ai/skills/eco-skills.lock.json"
MAX_LOCK_BYTES = 1024 * 1024
MARKER_PREFIX = "<!-- eco-skills:managed "
IDENTIFIER_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SkillSyncError(EcoError):
    """A stable, content-free skills synchronization failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Skill:
    record: dict[str, Any]
    content: bytes

    @property
    def identifier(self) -> str:
        return self.record["id"]


@dataclass(frozen=True)
class Registry:
    document: dict[str, Any]
    digest: str
    skills: tuple[Skill, ...]


@dataclass(frozen=True)
class Projection:
    path: str
    surface: str
    skill_id: str | None
    content: bytes

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
        result[key] = value
    return result


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _schema() -> dict[str, Any]:
    source = resources.files("eco_skills").joinpath(
        "schemas", "skill-registry.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def _catalog_resource(path: str) -> bytes:
    source = resources.files("eco_skills").joinpath("catalog", *path.split("/"))
    return source.read_bytes()


def validate_registry(
    document: Any,
    *,
    resource_reader: Callable[[str], bytes] = _catalog_resource,
) -> Registry:
    """Validate metadata and packaged bytes without importing or executing a skill."""

    errors = list(Draft202012Validator(_schema()).iter_errors(document))
    if errors or not isinstance(document, dict):
        raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
    records = document["skills"]
    identifiers = [item["id"] for item in records]
    normalized = [unicodedata.normalize("NFC", item).casefold() for item in identifiers]
    if (
        identifiers != sorted(identifiers)
        or len(identifiers) != len(set(identifiers))
        or len(normalized) != len(set(normalized))
    ):
        raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")

    known = set(identifiers)
    loaded: list[Skill] = []
    for record in records:
        resource_name = record["resource"]
        parsed = PurePosixPath(resource_name)
        if (
            parsed.is_absolute()
            or "\\" in resource_name
            or unicodedata.normalize("NFC", resource_name) != resource_name
            or any(part in {"", ".", ".."} for part in parsed.parts)
            or resource_name != f"{record['id']}/SKILL.md"
        ):
            raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
        if any(dependency not in known for dependency in record["dependencies"]):
            raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
        try:
            content = resource_reader(resource_name)
        except (FileNotFoundError, OSError, TypeError) as exc:
            raise SkillSyncError("ECO_SKILL_RESOURCE_INVALID") from exc
        if not isinstance(content, bytes) or len(content) > 256 * 1024:
            raise SkillSyncError("ECO_SKILL_RESOURCE_INVALID")
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillSyncError("ECO_SKILL_RESOURCE_INVALID") from exc
        if "\x00" in decoded or hashlib.sha256(content).hexdigest() != record["contentDigest"]:
            raise SkillSyncError("ECO_SKILL_RESOURCE_INVALID")
        if record["revocation"]["revoked"] and not record["revocation"]["reason"]:
            raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
        if not record["revocation"]["revoked"] and record["revocation"]["reason"] is not None:
            raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID")
        for surface in ("copilot", "cursor"):
            support = record["compatibility"][surface]
            if support["mode"] != "instruction-only" or not support["limitations"]:
                raise SkillSyncError("ECO_SKILL_COMPATIBILITY_OVERCLAIM")
        loaded.append(Skill(record=copy.deepcopy(record), content=content))

    graph = {item["id"]: tuple(item["dependencies"]) for item in records}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise SkillSyncError("ECO_SKILL_DEPENDENCY_CYCLE")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in graph[identifier]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in identifiers:
        visit(identifier)
    return Registry(
        document=copy.deepcopy(document),
        digest=_semantic_digest(document),
        skills=tuple(loaded),
    )


def load_builtin_registry() -> Registry:
    source = resources.files("eco_skills").joinpath("catalog", "registry.json")
    try:
        document = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_duplicate_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SkillSyncError("ECO_SKILL_REGISTRY_INVALID") from exc
    return validate_registry(document)


def _marker(surface: str, registry_digest: str, skill_id: str | None = None) -> str:
    skill = f' skill="{skill_id}"' if skill_id is not None else ""
    return (
        f'{MARKER_PREFIX}surface="{surface}" registry="{registry_digest}"{skill} -->'
    )


def _native_content(skill: Skill, surface: str, registry_digest: str) -> bytes:
    text = skill.content.decode("utf-8")
    marker = _marker(surface, registry_digest, skill.identifier)
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end < 0:
            raise SkillSyncError("ECO_SKILL_RESOURCE_INVALID")
        split = end + len("\n---\n")
        return (text[:split] + marker + "\n\n" + text[split:]).encode("utf-8")
    return (marker + "\n\n" + text).encode("utf-8")


def _aggregate_content(registry: Registry, surface: str) -> bytes:
    marker = _marker(surface, registry.digest)
    if surface == "cursor":
        lines = ["---", "description: Eco managed portable skill guidance", "alwaysApply: false", "---", marker]
    else:
        lines = [marker]
    lines.extend(
        [
            "",
            "# Eco skill guidance",
            "",
            "> This is an instruction-only projection. Native skill discovery, invocation, dependency resolution, and semantic parity are not claimed.",
            "",
        ]
    )
    for skill in registry.skills:
        if skill.record["revocation"]["revoked"]:
            continue
        source = skill.content.decode("utf-8")
        body_start = source.find("\n---\n", 4)
        body = source[body_start + len("\n---\n") :] if body_start >= 0 else source
        lines.extend([f"## {skill.identifier} ({skill.record['version']})", "", body.strip(), ""])
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def _projections(registry: Registry) -> tuple[Projection, ...]:
    roots = {
        "codex": ".agents/skills",
        "claude": ".claude/skills",
        "gemini": ".gemini/skills",
        "portable": ".ai/skills/projected",
    }
    result: list[Projection] = []
    for surface, root in roots.items():
        for skill in registry.skills:
            if skill.record["revocation"]["revoked"]:
                continue
            result.append(
                Projection(
                    path=f"{root}/{skill.identifier}/SKILL.md",
                    surface=surface,
                    skill_id=skill.identifier,
                    content=_native_content(skill, surface, registry.digest),
                )
            )
    result.extend(
        [
            Projection(
                path=".github/instructions/eco-skills.instructions.md",
                surface="copilot",
                skill_id=None,
                content=_aggregate_content(registry, "copilot"),
            ),
            Projection(
                path=".cursor/rules/eco-skills.mdc",
                surface="cursor",
                skill_id=None,
                content=_aggregate_content(registry, "cursor"),
            ),
        ]
    )
    result.sort(key=lambda item: item.path)
    keys = [unicodedata.normalize("NFC", item.path).casefold() for item in result]
    if len(keys) != len(set(keys)):
        raise SkillSyncError("ECO_SKILL_TARGET_COLLISION")
    return tuple(result)


def _canonical_path(relative: str) -> PurePosixPath:
    parsed = PurePosixPath(relative)
    if (
        not relative
        or parsed.is_absolute()
        or "\\" in relative
        or "\x00" in relative
        or "//" in relative
        or relative.startswith("./")
        or relative.endswith("/")
        or unicodedata.normalize("NFC", relative) != relative
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in relative)
    ):
        raise SkillSyncError("ECO_SKILL_PATH_INVALID")
    return parsed


def _target(repo: Path, relative: str) -> Path:
    parsed = _canonical_path(relative)
    root = repo.resolve(strict=True)
    cursor = root
    for index, part in enumerate(parsed.parts):
        if cursor.is_dir():
            requested = unicodedata.normalize("NFC", part).casefold()
            aliases = [
                entry.name
                for entry in cursor.iterdir()
                if unicodedata.normalize("NFC", entry.name).casefold() == requested
            ]
            if any(alias != part for alias in aliases):
                raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
        cursor = cursor / part
        try:
            status = cursor.lstat()
        except FileNotFoundError:
            continue
        final = index == len(parsed.parts) - 1
        if stat.S_ISLNK(status.st_mode):
            raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
        if final:
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
        elif not stat.S_ISDIR(status.st_mode):
            raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
    return root.joinpath(*parsed.parts)


def _read_regular(path: Path, *, maximum: int = 512 * 1024) -> bytes:
    try:
        status = path.lstat()
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > maximum:
        raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
    raw = path.read_bytes()
    after = path.lstat()
    if (
        after.st_dev != status.st_dev
        or after.st_ino != status.st_ino
        or after.st_size != status.st_size
        or after.st_mtime_ns != status.st_mtime_ns
    ):
        raise SkillSyncError("ECO_SKILL_PATH_RACE")
    return raw


def _lock_document(registry: Registry, projections: tuple[Projection, ...]) -> dict[str, Any]:
    return {
        "apiVersion": "skills.ai.ecosystem/v1alpha1",
        "kind": "SkillProjectionLock",
        "metadata": {
            "owner": "eco-skills",
            "registryDigest": registry.digest,
            "registryVersion": registry.document["metadata"]["version"],
        },
        "files": [
            {
                "path": item.path,
                "surface": item.surface,
                "skillId": item.skill_id,
                "contentDigest": item.digest,
            }
            for item in projections
        ],
    }


def _load_lock(repo: Path) -> dict[str, Any] | None:
    path = _target(repo, LOCK_PATH)
    if not path.exists():
        return None
    raw = _read_regular(path, maximum=MAX_LOCK_BYTES)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SkillSyncError("ECO_SKILL_LOCK_INVALID") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"apiVersion", "kind", "metadata", "files"}
        or document.get("apiVersion") != "skills.ai.ecosystem/v1alpha1"
        or document.get("kind") != "SkillProjectionLock"
        or not isinstance(document.get("metadata"), dict)
        or set(document["metadata"])
        != {"owner", "registryDigest", "registryVersion"}
        or document["metadata"].get("owner") != "eco-skills"
        or not isinstance(document["metadata"].get("registryDigest"), str)
        or len(document["metadata"]["registryDigest"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in document["metadata"]["registryDigest"]
        )
        or not isinstance(document["metadata"].get("registryVersion"), str)
        or not isinstance(document.get("files"), list)
        or len(document["files"]) > 256
    ):
        raise SkillSyncError("ECO_SKILL_LOCK_INVALID")
    paths: list[str] = []
    for item in document["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "surface", "skillId", "contentDigest"}
            or item.get("surface") not in DEFAULT_SURFACES
            or not isinstance(item.get("path"), str)
            or not isinstance(item.get("contentDigest"), str)
            or len(item["contentDigest"]) != 64
            or any(character not in "0123456789abcdef" for character in item["contentDigest"])
        ):
            raise SkillSyncError("ECO_SKILL_LOCK_INVALID")
        _canonical_path(item["path"])
        skill_id = item["skillId"]
        native_roots = {
            "codex": ".agents/skills",
            "claude": ".claude/skills",
            "gemini": ".gemini/skills",
            "portable": ".ai/skills/projected",
        }
        if item["surface"] in native_roots:
            if (
                not isinstance(skill_id, str)
                or IDENTIFIER_RE.fullmatch(skill_id) is None
                or PurePosixPath(item["path"])
                != PurePosixPath(native_roots[item["surface"]], skill_id, "SKILL.md")
            ):
                raise SkillSyncError("ECO_SKILL_LOCK_INVALID")
        else:
            aggregate = {
                "copilot": ".github/instructions/eco-skills.instructions.md",
                "cursor": ".cursor/rules/eco-skills.mdc",
            }
            if skill_id is not None or item["path"] != aggregate[item["surface"]]:
                raise SkillSyncError("ECO_SKILL_LOCK_INVALID")
        paths.append(item["path"])
    normalized = [unicodedata.normalize("NFC", item).casefold() for item in paths]
    if paths != sorted(paths) or len(normalized) != len(set(normalized)):
        raise SkillSyncError("ECO_SKILL_LOCK_INVALID")
    return document


def _managed(
    raw: bytes,
    surface: str,
    registry_digest: str,
    skill_id: str | None,
) -> bool:
    try:
        head = raw[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return _marker(surface, registry_digest, skill_id) in head


def _assess(repo: Path, registry: Registry) -> tuple[tuple[Projection, ...], dict[str, Any] | None, list[dict[str, Any]]]:
    projections = _projections(registry)
    lock = _load_lock(repo)
    locked = {item["path"]: item for item in lock["files"]} if lock else {}
    statuses: list[dict[str, Any]] = []
    desired_paths = {item.path for item in projections}

    for item in projections:
        path = _target(repo, item.path)
        binding = locked.get(item.path)
        if not path.exists():
            status = "missing" if binding else "create"
        else:
            raw = _read_regular(path)
            current_digest = hashlib.sha256(raw).hexdigest()
            if raw == item.content:
                status = "current" if binding else "unowned-match"
            elif binding is None or lock is None or not _managed(
                raw,
                item.surface,
                lock["metadata"]["registryDigest"],
                item.skill_id,
            ):
                status = "conflict"
            elif current_digest != binding["contentDigest"]:
                status = "drift"
            else:
                status = "update"
        if binding is not None and (
            binding["surface"] != item.surface or binding["skillId"] != item.skill_id
        ):
            status = "drift"
        statuses.append(
            {
                "path": item.path,
                "surface": item.surface,
                "skillId": item.skill_id,
                "status": status,
                "desiredDigest": item.digest,
            }
        )

    for relative, binding in sorted(locked.items()):
        if relative in desired_paths:
            continue
        path = _target(repo, relative)
        status = "obsolete"
        if not path.exists():
            status = "drift"
        else:
            raw = _read_regular(path)
            if (
                hashlib.sha256(raw).hexdigest() != binding["contentDigest"]
                or lock is None
                or not _managed(
                    raw,
                    binding["surface"],
                    lock["metadata"]["registryDigest"],
                    binding["skillId"],
                )
            ):
                status = "drift"
        statuses.append(
            {
                "path": relative,
                "surface": binding["surface"],
                "skillId": binding["skillId"],
                "status": status,
                "desiredDigest": None,
            }
        )
    statuses.sort(key=lambda item: item["path"])
    return projections, lock, statuses


def _result(registry: Registry, statuses: list[dict[str, Any]], operation: str) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in statuses:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    blocked = any(item["status"] in {"conflict", "drift", "unowned-match"} for item in statuses)
    return {
        "available": not blocked,
        "operation": operation,
        "registryDigest": registry.digest,
        "registryVersion": registry.document["metadata"]["version"],
        "skillCount": len(registry.skills),
        "projectionCount": len(statuses),
        "counts": counts,
        "projections": statuses,
        "compatibility": {
            surface: registry.skills[0].record["compatibility"][surface]["mode"]
            for surface in DEFAULT_SURFACES
        },
        "safety": {
            "skillCodeExecuted": False,
            "networkAccessed": False,
            "unmanagedFilesOverwritten": False,
            "runtimeAuthorityCreated": False,
        },
    }


def plan_skills(repo: Path) -> dict[str, Any]:
    registry = load_builtin_registry()
    _, _, statuses = _assess(repo.resolve(strict=True), registry)
    return _result(registry, statuses, "plan")


def check_skills(repo: Path) -> dict[str, Any]:
    registry = load_builtin_registry()
    projections, lock, statuses = _assess(repo.resolve(strict=True), registry)
    expected = _lock_document(registry, projections)
    healthy = (
        lock == expected
        and len(statuses) == len(projections)
        and all(item["status"] == "current" for item in statuses)
    )
    result = _result(registry, statuses, "check")
    result["available"] = healthy
    result["status"] = "synchronized" if healthy else "drift"
    return result


def _atomic_write(path: Path, content: bytes) -> None:
    atomic_write_bytes(path, content)


def _remove(path: Path) -> None:
    path.unlink()


def _snapshot(paths: list[Path]) -> dict[Path, tuple[bytes, int] | None]:
    result: dict[Path, tuple[bytes, int] | None] = {}
    for path in paths:
        try:
            status = path.lstat()
        except FileNotFoundError:
            result[path] = None
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise SkillSyncError("ECO_SKILL_PATH_ALIAS")
        result[path] = (_read_regular(path, maximum=MAX_LOCK_BYTES), stat.S_IMODE(status.st_mode))
    return result


def _rollback(snapshot: Mapping[Path, tuple[bytes, int] | None]) -> None:
    failures = False
    for path, prior in reversed(tuple(snapshot.items())):
        try:
            if prior is None:
                if path.exists() or path.is_symlink():
                    status = path.lstat()
                    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                        failures = True
                        continue
                    path.unlink()
            else:
                content, mode = prior
                atomic_write_bytes(path, content)
                os.chmod(path, mode)
        except OSError:
            failures = True
    if failures:
        raise SkillSyncError("ECO_SKILL_ROLLBACK_INCOMPLETE")


def sync_skills(repo: Path) -> dict[str, Any]:
    root = repo.resolve(strict=True)
    registry = load_builtin_registry()
    projections, lock, statuses = _assess(root, registry)
    if any(item["status"] in {"conflict", "drift", "unowned-match", "missing"} for item in statuses):
        raise SkillSyncError("ECO_SKILL_SYNC_BLOCKED")
    desired = {item.path: item for item in projections}
    obsolete = [item for item in statuses if item["status"] == "obsolete"]
    target_paths = [_target(root, item.path) for item in projections]
    target_paths.extend(_target(root, item["path"]) for item in obsolete)
    lock_path = _target(root, LOCK_PATH)
    target_paths.append(lock_path)
    snapshot = _snapshot(list(dict.fromkeys(target_paths)))
    try:
        for item in projections:
            if next(status for status in statuses if status["path"] == item.path)["status"] != "current":
                _atomic_write(_target(root, item.path), item.content)
        for item in obsolete:
            _remove(_target(root, item["path"]))
        _atomic_write(lock_path, stable_json(_lock_document(registry, projections)).encode("utf-8"))
    except (OSError, SkillSyncError) as exc:
        try:
            _rollback(snapshot)
        except SkillSyncError:
            raise
        raise SkillSyncError("ECO_SKILL_SYNC_ROLLED_BACK") from exc
    result = check_skills(root)
    if not result["available"]:
        _rollback(snapshot)
        raise SkillSyncError("ECO_SKILL_SYNC_ROLLED_BACK")
    result["operation"] = "sync"
    result["changed"] = sum(
        1 for item in statuses if item["status"] in {"create", "update", "obsolete"}
    )
    return result


def uninstall_skills(repo: Path) -> dict[str, Any]:
    root = repo.resolve(strict=True)
    registry = load_builtin_registry()
    lock = _load_lock(root)
    if lock is None:
        return {
            "available": True,
            "operation": "uninstall",
            "removed": 0,
            "status": "absent",
            "safety": {"unmanagedFilesRemoved": False, "networkAccessed": False},
        }
    paths: list[Path] = []
    for item in lock["files"]:
        path = _target(root, item["path"])
        if not path.exists():
            raise SkillSyncError("ECO_SKILL_UNINSTALL_BLOCKED")
        raw = _read_regular(path)
        if (
            hashlib.sha256(raw).hexdigest() != item["contentDigest"]
            or not _managed(
                raw,
                item["surface"],
                lock["metadata"]["registryDigest"],
                item["skillId"],
            )
        ):
            raise SkillSyncError("ECO_SKILL_UNINSTALL_BLOCKED")
        paths.append(path)
    lock_path = _target(root, LOCK_PATH)
    paths.append(lock_path)
    snapshot = _snapshot(paths)
    try:
        for path in paths[:-1]:
            _remove(path)
        _remove(lock_path)
    except (OSError, SkillSyncError) as exc:
        try:
            _rollback(snapshot)
        except SkillSyncError:
            raise
        raise SkillSyncError("ECO_SKILL_UNINSTALL_ROLLED_BACK") from exc
    return {
        "available": True,
        "operation": "uninstall",
        "registryDigest": registry.digest,
        "removed": len(paths) - 1,
        "status": "removed",
        "safety": {"unmanagedFilesRemoved": False, "networkAccessed": False},
    }
