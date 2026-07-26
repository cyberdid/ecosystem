"""Deterministic, non-executing skill inspection and catalog synchronization."""

from .importer import UpstreamSkillImportError, inspect_upstream_skills

from .sync import (
    DEFAULT_SURFACES,
    SkillSyncError,
    check_skills,
    load_builtin_registry,
    plan_skills,
    sync_skills,
    uninstall_skills,
)

__all__ = [
    "DEFAULT_SURFACES",
    "UpstreamSkillImportError",
    "SkillSyncError",
    "check_skills",
    "load_builtin_registry",
    "inspect_upstream_skills",
    "plan_skills",
    "sync_skills",
    "uninstall_skills",
]
