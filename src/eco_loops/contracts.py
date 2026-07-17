from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

from eco_runtime.digests import semantic_digest


_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_CODE = re.compile(r"^ECO_[A-Z0-9_]{1,95}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")

ACTIVE_STATES = frozenset({"ready", "running", "gating", "retry-wait"})
TERMINAL_STATES = frozenset({"succeeded", "failed", "exhausted", "cancelled"})
LOOP_STATES = frozenset({"new", *ACTIVE_STATES, *TERMINAL_STATES})
TRANSITIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "new": frozenset({"ready", "cancelled"}),
        "ready": frozenset({"running", "cancelled", "exhausted"}),
        "running": frozenset({"gating", "retry-wait", "failed", "cancelled", "exhausted"}),
        "gating": frozenset({"succeeded", "retry-wait", "failed", "cancelled", "exhausted"}),
        "retry-wait": frozenset({"running", "cancelled", "exhausted"}),
        "succeeded": frozenset(),
        "failed": frozenset(),
        "exhausted": frozenset(),
        "cancelled": frozenset(),
    }
)


class LoopContractError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _positive(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", f"{name} must be a positive integer")


def _non_negative(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", f"{name} must be a non-negative integer")


def _utc(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "deadline must be timezone-aware")
    if value.utcoffset() != timezone.utc.utcoffset(value):
        raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "deadline must use UTC")


@dataclass(frozen=True, slots=True)
class LoopBudget:
    max_attempts: int
    max_iterations: int
    deadline: datetime
    max_tokens: int
    max_cost_microusd: int
    max_storage_bytes: int
    reserve_tokens_per_attempt: int = 0
    reserve_cost_microusd_per_attempt: int = 0
    reserve_storage_bytes_per_attempt: int = 0

    def __post_init__(self) -> None:
        _positive("max_attempts", self.max_attempts)
        _positive("max_iterations", self.max_iterations)
        _utc(self.deadline)
        for name in (
            "max_tokens",
            "max_cost_microusd",
            "max_storage_bytes",
            "reserve_tokens_per_attempt",
            "reserve_cost_microusd_per_attempt",
            "reserve_storage_bytes_per_attempt",
        ):
            _non_negative(name, getattr(self, name))
        if self.reserve_tokens_per_attempt > self.max_tokens:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "token reservation exceeds total budget")
        if self.reserve_cost_microusd_per_attempt > self.max_cost_microusd:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "cost reservation exceeds total budget")
        if self.reserve_storage_bytes_per_attempt > self.max_storage_bytes:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "storage reservation exceeds total budget")

    def record(self) -> dict[str, object]:
        return {
            "maxAttempts": self.max_attempts,
            "maxIterations": self.max_iterations,
            "deadline": self.deadline.isoformat().replace("+00:00", "Z"),
            "maxTokens": self.max_tokens,
            "maxCostMicrousd": self.max_cost_microusd,
            "maxStorageBytes": self.max_storage_bytes,
            "reserveTokensPerAttempt": self.reserve_tokens_per_attempt,
            "reserveCostMicrousdPerAttempt": self.reserve_cost_microusd_per_attempt,
            "reserveStorageBytesPerAttempt": self.reserve_storage_bytes_per_attempt,
        }


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    allowed_reason_codes: frozenset[str] = field(default_factory=frozenset)
    max_stagnant_iterations: int = 2

    def __post_init__(self) -> None:
        _positive("max_stagnant_iterations", self.max_stagnant_iterations)
        if any(not isinstance(code, str) or not _CODE.fullmatch(code) for code in self.allowed_reason_codes):
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "retry reason codes must be safe ECO codes")

    def record(self) -> dict[str, object]:
        return {
            "allowedReasonCodes": sorted(self.allowed_reason_codes),
            "maxStagnantIterations": self.max_stagnant_iterations,
        }


@dataclass(frozen=True, slots=True)
class LoopDefinition:
    loop_id: str
    version: str
    objective_digest: str
    gate_digest: str
    profile: str
    side_effect_mode: str
    deterministic: bool
    executable: bool
    budget: LoopBudget
    retry: RetryPolicy
    state_outline: tuple[str, ...] = (
        "ready",
        "running",
        "gating",
        "retry-wait",
        "succeeded",
        "failed",
        "exhausted",
        "cancelled",
    )

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.loop_id):
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "loop id is invalid")
        if not isinstance(self.version, str) or not self.version or len(self.version) > 32:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "version is invalid")
        if not _DIGEST.fullmatch(self.objective_digest) or not _DIGEST.fullmatch(self.gate_digest):
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "objective and gate must be SHA-256 digests")
        if self.side_effect_mode not in {"no-effect", "report-only"}:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "M6.3 permits only no-effect/report-only loops")
        if not isinstance(self.deterministic, bool) or not isinstance(self.executable, bool):
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "profile flags must be booleans")
        if not isinstance(self.profile, str) or not self.profile or len(self.profile) > 128:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "profile is invalid")
        if tuple(dict.fromkeys(self.state_outline)) != self.state_outline:
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "state outline contains duplicates")
        if any(state not in LOOP_STATES for state in self.state_outline):
            raise LoopContractError("ECO_LOOP_DEFINITION_INVALID", "state outline is not closed")

    def record(self) -> dict[str, object]:
        return {
            "loopId": self.loop_id,
            "version": self.version,
            "objectiveDigest": self.objective_digest,
            "gateDigest": self.gate_digest,
            "profile": self.profile,
            "sideEffectMode": self.side_effect_mode,
            "deterministic": self.deterministic,
            "executable": self.executable,
            "budget": self.budget.record(),
            "retry": self.retry.record(),
            "stateOutline": list(self.state_outline),
        }

    @property
    def digest(self) -> str:
        return semantic_digest(self.record())


@dataclass(frozen=True, slots=True)
class AttemptResult:
    outcome: str
    reason_code: str
    candidate_digest: str
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.outcome not in {"candidate", "retryable-error", "fatal-error"}:
            raise LoopContractError("ECO_LOOP_OUTCOME_INVALID", "attempt result is invalid")
        if not _CODE.fullmatch(self.reason_code):
            raise LoopContractError("ECO_LOOP_OUTCOME_INVALID", "attempt reason code is unsafe")
        if not _DIGEST.fullmatch(self.candidate_digest) or not _DIGEST.fullmatch(self.evidence_digest):
            raise LoopContractError("ECO_LOOP_OUTCOME_INVALID", "attempt evidence must use SHA-256 digests")


@dataclass(frozen=True, slots=True)
class GateOutcome:
    outcome: str
    reason_code: str
    progress_digest: str
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.outcome not in {"pass", "fail"}:
            raise LoopContractError("ECO_LOOP_GATE_INVALID", "gate outcome is invalid")
        if not _CODE.fullmatch(self.reason_code):
            raise LoopContractError("ECO_LOOP_GATE_INVALID", "gate reason code is unsafe")
        if not _DIGEST.fullmatch(self.progress_digest) or not _DIGEST.fullmatch(self.evidence_digest):
            raise LoopContractError("ECO_LOOP_GATE_INVALID", "gate evidence must use SHA-256 digests")


@dataclass(frozen=True, slots=True)
class LoopUsage:
    attempts: int = 0
    iterations: int = 0
    tokens: int = 0
    cost_microusd: int = 0
    storage_bytes: int = 0

    def __post_init__(self) -> None:
        for name in ("attempts", "iterations", "tokens", "cost_microusd", "storage_bytes"):
            _non_negative(name, getattr(self, name))

    def record(self) -> dict[str, int]:
        return {
            "attempts": self.attempts,
            "iterations": self.iterations,
            "tokens": self.tokens,
            "costMicrousd": self.cost_microusd,
            "storageBytes": self.storage_bytes,
        }


@dataclass(frozen=True, slots=True)
class LoopCheckpoint:
    run_id: str
    definition_digest: str
    state: str
    sequence: int
    usage: LoopUsage
    last_progress_digest: str | None = None
    stagnant_iterations: int = 0
    terminal_reason: str | None = None
    head_digest: str | None = None

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.run_id):
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "run id is invalid")
        if not _DIGEST.fullmatch(self.definition_digest):
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "definition digest is invalid")
        if self.state not in LOOP_STATES:
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "state is invalid")
        _non_negative("sequence", self.sequence)
        _non_negative("stagnant_iterations", self.stagnant_iterations)
        if self.last_progress_digest is not None and not _DIGEST.fullmatch(self.last_progress_digest):
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "progress digest is invalid")
        if self.terminal_reason is not None and not _CODE.fullmatch(self.terminal_reason):
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "terminal reason is unsafe")
        if self.head_digest is not None and not _DIGEST.fullmatch(self.head_digest):
            raise LoopContractError("ECO_LOOP_CHECKPOINT_INVALID", "checkpoint head is invalid")


def transition_allowed(current: str, target: str) -> bool:
    return current in TRANSITIONS and target in TRANSITIONS[current]
