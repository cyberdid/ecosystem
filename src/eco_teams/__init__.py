"""Bounded, embedded agent-team orchestration contracts and runtime."""

from .contracts import (
    API_VERSION,
    PROFILE,
    record_digest,
    schema_bundle_digest,
    validate_record,
)
from .runtime import (
    ExecutionAuthorization,
    LeaseClaim,
    M5AuthorityGuard,
    M5ExecutionAuthorizer,
    TaskEffectResult,
    TeamCoordinator,
    TeamRuntimeError,
)

__all__ = [
    "API_VERSION",
    "PROFILE",
    "ExecutionAuthorization",
    "LeaseClaim",
    "M5AuthorityGuard",
    "M5ExecutionAuthorizer",
    "TaskEffectResult",
    "TeamCoordinator",
    "TeamRuntimeError",
    "record_digest",
    "schema_bundle_digest",
    "validate_record",
]
