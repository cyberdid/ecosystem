from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .constants import MANAGED_START_PREFIX

LANGUAGE_MARKERS = {
    "python": ("pyproject.toml", "requirements.txt", "setup.py"),
    "javascript/typescript": ("package.json", "tsconfig.json"),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "dotnet": ("*.sln", "*.csproj"),
}

INSTRUCTION_SURFACES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".cursor/rules/eco.mdc",
    ".cursorrules",
)

BUILD_FILES = (
    "pyproject.toml",
    "package.json",
    "Makefile",
    "justfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "docker-compose.yml",
    "compose.yaml",
)

SENSITIVE_FILENAME_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\..+)?|.*(?:secret|credential|password|token|api[_-]?key).*)$",
    re.I,
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"^\s*[\"']?(?:password|passwd|secret|token|api[_-]?key|credential)[A-Za-z0-9_.-]*[\"']?\s*(?::|=)",
    re.I,
)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def _tracked_files(repo: Path) -> list[str]:
    result = _git(repo, "ls-files")
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line]


def _detect_languages(repo: Path) -> list[str]:
    detected: list[str] = []
    for language, markers in LANGUAGE_MARKERS.items():
        for marker in markers:
            if any(repo.glob(marker)):
                detected.append(language)
                break
    return detected


def _surface_record(repo: Path, relative: str) -> dict[str, Any] | None:
    path = repo / relative
    if not path.exists():
        return None
    if path.is_dir():
        return {"path": relative, "type": "directory", "managed": False}
    content = path.read_text(encoding="utf-8", errors="ignore")
    return {
        "path": relative,
        "type": "file",
        "managed": MANAGED_START_PREFIX in content,
    }


def _potential_secret_locations(repo: Path, tracked: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for relative in tracked:
        path = repo / relative
        if SENSITIVE_FILENAME_RE.search(relative):
            findings.append({"path": relative, "reason": "sensitive filename"})
        try:
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            if SECRET_ASSIGNMENT_RE.search(line):
                findings.append(
                    {
                        "path": relative,
                        "line": line_number,
                        "reason": "secret-like key; value intentionally not displayed",
                    }
                )
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for item in findings:
        key = (item.get("path"), item.get("line"), item.get("reason"))
        unique[key] = item
    return list(unique.values())


def audit_repository(repo: Path, config_root: str = ".ai") -> dict[str, Any]:
    repo = repo.resolve()
    tracked = _tracked_files(repo)
    git_status = _git(repo, "status", "--porcelain")
    git_head = _git(repo, "rev-parse", "HEAD")

    surfaces = [record for relative in INSTRUCTION_SURFACES if (record := _surface_record(repo, relative))]
    build_files = [relative for relative in BUILD_FILES if (repo / relative).exists()]
    config_directory = repo / config_root

    return {
        "repository": str(repo),
        "git": {
            "available": bool(tracked or git_head.returncode == 0),
            "head": git_head.stdout.strip() if git_head.returncode == 0 else None,
            "dirty": bool(git_status.stdout.strip()) if git_status.returncode == 0 else None,
        },
        "languages": _detect_languages(repo),
        "buildFiles": build_files,
        "instructionSurfaces": surfaces,
        "canonicalConfig": {
            "path": config_root,
            "exists": config_directory.is_dir(),
        },
        "trackedFileCount": len(tracked),
        "potentialSecretLocations": _potential_secret_locations(repo, tracked),
        "notes": [
            "Secret findings report keys and paths only; manually verify before rotation.",
            "Audit is read-only and does not prove runtime isolation or provider privacy.",
        ],
    }
