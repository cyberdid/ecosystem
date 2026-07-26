from __future__ import annotations

"""Offline inspection of skill-shaped content in one exact Git commit."""

import hashlib
import json
import os
import posixpath
import re
import subprocess
import unicodedata
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml
from jsonschema import Draft202012Validator

from eco_cli.errors import EcoError


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MAX_TREE_ENTRIES = 100_000
_MAX_SKILLS = 10_000
_MAX_SKILL_BYTES = 256 * 1024
_MAX_FRONTMATTER_CHARS = 16 * 1024
_MODE_REGULAR = {"100644", "100755"}
_MODE_SYMLINK = "120000"
_MODE_SUBMODULE = "160000"
_UNPINNED_RE = re.compile(
    rb"(?:@[Ll][Aa][Tt][Ee][Ss][Tt]\b|"
    rb"(?:docker\s+(?:run|pull)\s+)(?![^ \t\r\n]+@sha256:)[^ \t\r\n]+)"
)
_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("credential-reference", re.compile(rb"(?i)\b(?:api[_-]?key|token|password|secret)\b")),
    ("destructive-command", re.compile(rb"(?i)\b(?:rm\s+-rf|drop\s+table|delete\s+from)\b")),
    ("direct-network", re.compile(rb"(?i)\b(?:curl|wget|https?://)\b")),
    ("external-install", re.compile(rb"(?i)\b(?:npx\s+-y|pip\s+install|npm\s+install|uvx)\b")),
    ("telemetry-reference", re.compile(rb"(?i)\btelemetry\b")),
    ("unpinned-runtime", _UNPINNED_RE),
)


class UpstreamSkillImportError(EcoError):
    """A stable, content-free upstream inspection failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    kind: str
    oid: str
    path: str


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.YAMLError("unhashable key") from exc
        if duplicate:
            raise yaml.YAMLError("duplicate key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _schema() -> dict[str, Any]:
    source = resources.files("eco_skills").joinpath(
        "schemas", "upstream-import-plan.schema.json"
    )
    return json.loads(source.read_text(encoding="utf-8"))


def _normalize_source_uri(value: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SOURCE_INVALID")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SOURCE_INVALID") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path
    ):
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SOURCE_INVALID")
    host = parsed.hostname
    if host is None:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SOURCE_INVALID")
    netloc = host.lower()
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(("https", netloc, path, "", ""))


def _git(root: Path, *arguments: str) -> bytes:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-C",
        str(root),
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_GIT_UNAVAILABLE") from exc
    if completed.returncode != 0:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_GIT_REJECTED")
    return completed.stdout


def _canonical_path(raw: bytes) -> str:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_PATH_INVALID") from exc
    parsed = PurePosixPath(value)
    if (
        not value
        or len(value) > 2048
        or parsed.is_absolute()
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_PATH_INVALID")
    return value


def _tree(root: Path, commit: str) -> tuple[_TreeEntry, ...]:
    raw = _git(root, "ls-tree", "-rz", "--full-tree", commit)
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > _MAX_TREE_ENTRIES:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_TOO_LARGE")
    result: list[_TreeEntry] = []
    seen: set[str] = set()
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ", 2)
        except (ValueError, UnicodeDecodeError) as exc:
            raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID") from exc
        path = _canonical_path(raw_path)
        if path in seen or not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID")
        if (mode, kind) not in {
            ("100644", "blob"),
            ("100755", "blob"),
            ("120000", "blob"),
            ("160000", "commit"),
        }:
            raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID")
        seen.add(path)
        result.append(_TreeEntry(mode=mode, kind=kind, oid=oid, path=path))
    return tuple(sorted(result, key=lambda item: item.path))


def _blob(root: Path, oid: str, *, maximum: int) -> bytes:
    try:
        size = int(_git(root, "cat-file", "-s", oid).decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID") from exc
    if size < 0 or size > maximum:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_BLOB_TOO_LARGE")
    raw = _git(root, "cat-file", "blob", oid)
    if len(raw) != size:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID")
    return raw


def _parse_frontmatter(content: bytes) -> tuple[str | None, tuple[str, ...]]:
    reasons: list[str] = []
    if len(content) > _MAX_SKILL_BYTES:
        return None, ("skill-too-large",)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None, ("skill-not-utf8",)
    if "\x00" in text:
        return None, ("skill-contains-nul",)
    stripped = text.lstrip("\ufeff")
    if not stripped.startswith("---\n"):
        return None, ("frontmatter-missing",)
    end = stripped.find("\n---\n", 4)
    if end < 0 or end > _MAX_FRONTMATTER_CHARS:
        return None, ("frontmatter-invalid",)
    try:
        frontmatter = yaml.load(stripped[4:end], Loader=_UniqueKeyLoader)
    except yaml.YAMLError:
        return None, ("frontmatter-invalid",)
    if not isinstance(frontmatter, dict):
        return None, ("frontmatter-invalid",)
    name = frontmatter.get("name")
    description = frontmatter.get("description")
    if (
        not isinstance(name, str)
        or len(name) > 80
        or _IDENTIFIER_RE.fullmatch(name) is None
    ):
        reasons.append("name-invalid")
        name = None
    if not isinstance(description, str) or not description.strip():
        reasons.append("description-invalid")
    return name, tuple(sorted(reasons))


def _candidate_signals(content: bytes) -> tuple[str, ...]:
    return tuple(sorted(
        name for name, pattern in _SIGNAL_PATTERNS if pattern.search(content) is not None
    ))


def _resolve_alias(path: str, raw_target: bytes, known: set[str], directories: set[str]) -> dict[str, str]:
    try:
        target_text = raw_target.decode("utf-8")
    except UnicodeDecodeError:
        return {"path": path, "target": path, "status": "blocked"}
    if (
        not target_text
        or target_text.startswith("/")
        or "\\" in target_text
        or unicodedata.normalize("NFC", target_text) != target_text
    ):
        return {"path": path, "target": path, "status": "blocked"}
    target = posixpath.normpath(posixpath.join(posixpath.dirname(path), target_text))
    if target in {".", ".."} or target.startswith("../"):
        return {"path": path, "target": path, "status": "blocked"}
    if target in known or target in directories:
        return {"path": path, "target": target, "status": "resolved"}
    return {"path": path, "target": target, "status": "broken"}


def _tree_digest(entries: tuple[_TreeEntry, ...]) -> str:
    return _semantic_digest(
        [
            {"mode": item.mode, "kind": item.kind, "oid": item.oid, "path": item.path}
            for item in entries
        ]
    )


def inspect_upstream_skills(
    source_root: str | Path,
    *,
    source_uri: str,
    commit: str,
    selection: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return a deterministic, non-authorizing plan for one pinned Git tree."""

    root = Path(source_root).expanduser().resolve()
    if not root.is_dir():
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_ROOT_INVALID")
    normalized_uri = _normalize_source_uri(source_uri)
    if not isinstance(commit, str) or _COMMIT_RE.fullmatch(commit) is None:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_COMMIT_INVALID")
    normalized_selection = tuple(sorted(set(selection)))
    if any(
        not isinstance(item, str)
        or len(item) > 80
        or _IDENTIFIER_RE.fullmatch(item) is None
        for item in normalized_selection
    ):
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SELECTION_INVALID")

    resolved = _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}").decode(
        "ascii", errors="strict"
    ).strip()
    if resolved != commit:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_COMMIT_MISMATCH")
    entries = _tree(root, commit)
    if not entries:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_TREE_INVALID")

    known = {item.path for item in entries}
    directories: set[str] = set()
    for item in entries:
        parent = PurePosixPath(item.path).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent

    aliases: list[dict[str, str]] = []
    for item in entries:
        if item.mode != _MODE_SYMLINK:
            continue
        aliases.append(
            _resolve_alias(
                item.path,
                _blob(root, item.oid, maximum=4096),
                known,
                directories,
            )
        )
    aliases.sort(key=lambda item: item["path"])

    skill_entries = [
        item
        for item in entries
        if item.mode in _MODE_REGULAR and item.path.endswith("/SKILL.md")
    ]
    if len(skill_entries) > _MAX_SKILLS:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SKILLS_TOO_LARGE")

    raw_candidates: list[dict[str, Any]] = []
    name_paths: dict[str, list[str]] = {}
    unpinned_references = 0
    for item in skill_entries:
        content = _blob(root, item.oid, maximum=_MAX_SKILL_BYTES)
        name, reasons = _parse_frontmatter(content)
        signals = _candidate_signals(content)
        if "unpinned-runtime" in signals:
            unpinned_references += 1
        if name is not None:
            name_paths.setdefault(name, []).append(item.path)
        raw_candidates.append(
            {
                "path": item.path,
                "skillName": name,
                "contentDigest": hashlib.sha256(content).hexdigest(),
                "sizeBytes": len(content),
                "status": "blocked" if reasons else "review-required",
                "reasons": list(reasons),
                "signals": list(signals),
                "proposalEligible": False,
            }
        )

    duplicates = {name for name, paths in name_paths.items() if len(paths) > 1}
    candidates: list[dict[str, Any]] = []
    found_names: set[str] = set()
    for candidate in raw_candidates:
        name = candidate["skillName"]
        if name in duplicates:
            candidate["reasons"] = sorted(set(candidate["reasons"]) | {"duplicate-name"})
            candidate["status"] = "blocked"
        if name is not None:
            found_names.add(name)
        if normalized_selection and name not in normalized_selection:
            continue
        candidates.append(candidate)
    candidates.sort(key=lambda item: item["path"])

    if normalized_selection and set(normalized_selection) - found_names:
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_SELECTION_NOT_FOUND")

    mcp_configs = sum(
        PurePosixPath(item.path).name in {".mcp.json", "mcp.json"} for item in entries
    )
    hook_files = sum("hooks" in PurePosixPath(item.path).parts for item in entries)
    executable_files = sum(item.mode == "100755" for item in entries)
    submodules = sum(item.mode == _MODE_SUBMODULE for item in entries)
    broken_aliases = sum(item["status"] != "resolved" for item in aliases)
    blocked = sum(item["status"] == "blocked" for item in candidates)
    review_required = sum(item["status"] == "review-required" for item in candidates)

    document: dict[str, Any] = {
        "apiVersion": "skills.ai.ecosystem/v1alpha1",
        "kind": "UpstreamSkillImportPlan",
        "metadata": {"planDigest": "0" * 64},
        "source": {
            "uri": normalized_uri,
            "commit": commit,
            "commitVerified": True,
            "treeDigest": _tree_digest(entries),
            "authenticity": "not-established",
        },
        "selection": list(normalized_selection),
        "summary": {
            "trackedEntries": len(entries),
            "regularSkillFiles": len(skill_entries),
            "selectedCandidates": len(candidates),
            "blockedCandidates": blocked,
            "reviewRequiredCandidates": review_required,
            "trackedSymlinks": len(aliases),
            "brokenSymlinks": broken_aliases,
        },
        "repositorySignals": {
            "executableFiles": executable_files,
            "hookFiles": hook_files,
            "mcpConfigs": mcp_configs,
            "submodules": submodules,
            "unpinnedRuntimeReferences": unpinned_references,
        },
        "aliases": aliases,
        "candidates": candidates,
        "promotion": {
            "eligible": False,
            "requiredNextGate": "eco skills propose",
            "capabilitiesInferred": False,
            "ownerBound": False,
            "testsEstablished": False,
            "evidenceEstablished": False,
        },
        "safety": {
            "networkAccessed": False,
            "skillCodeExecuted": False,
            "hooksLoaded": False,
            "dependenciesInstalled": False,
            "filesWritten": False,
            "credentialsConsumed": False,
            "runtimeAuthorityCreated": False,
        },
    }
    digest_input = dict(document)
    digest_input["metadata"] = {}
    document["metadata"]["planDigest"] = _semantic_digest(digest_input)
    if list(Draft202012Validator(_schema()).iter_errors(document)):
        raise UpstreamSkillImportError("ECO_SKILL_IMPORT_PLAN_INVALID")
    return document


__all__ = ["UpstreamSkillImportError", "inspect_upstream_skills"]
