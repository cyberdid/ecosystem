from __future__ import annotations

import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol


@dataclass(frozen=True)
class UntrustedArtifact:
    """One inert artifact payload carried in an explicitly untrusted channel."""

    binding: Mapping[str, Any]
    content: bytes
    media_type: str
    source_entry_id: str | None = None
    trust: str = "P0"

    def __post_init__(self) -> None:
        if not isinstance(self.content, bytes):
            raise TypeError("content must be bytes")
        if not isinstance(self.binding, Mapping):
            raise TypeError("binding must be a mapping")
        if not isinstance(self.media_type, str) or not self.media_type:
            raise ValueError("media_type must be a non-empty string")
        if self.source_entry_id is not None and not isinstance(
            self.source_entry_id, str
        ):
            raise TypeError("source_entry_id must be a string or None")
        if self.trust != "P0":
            raise ValueError("source-review artifacts must remain P0")
        object.__setattr__(
            self, "binding", MappingProxyType(copy.deepcopy(dict(self.binding)))
        )


@dataclass(frozen=True)
class RoleInvocation:
    """Authority-separated input to one role executor.

    A provider adapter may map these channels to its native request shape, but
    the workflow never joins trusted instructions and untrusted bytes into one
    string. Runtime state is structured and contains no source payload.
    """

    role_id: str
    attempt: int
    trusted_instruction: str
    trusted_output_schema: Mapping[str, Any]
    runtime_state: Mapping[str, Any]
    untrusted_sources: tuple[UntrustedArtifact, ...]
    untrusted_artifacts: tuple[UntrustedArtifact, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.role_id, str) or not self.role_id:
            raise ValueError("role_id must be a non-empty string")
        if self.attempt not in {1, 2}:
            raise ValueError("attempt must be 1 or 2")
        if not isinstance(self.trusted_instruction, str) or not self.trusted_instruction:
            raise ValueError("trusted_instruction must be a non-empty string")
        object.__setattr__(
            self,
            "trusted_output_schema",
            MappingProxyType(copy.deepcopy(dict(self.trusted_output_schema))),
        )
        object.__setattr__(
            self,
            "runtime_state",
            MappingProxyType(copy.deepcopy(dict(self.runtime_state))),
        )
        object.__setattr__(self, "untrusted_sources", tuple(self.untrusted_sources))
        object.__setattr__(self, "untrusted_artifacts", tuple(self.untrusted_artifacts))


@dataclass(frozen=True)
class RoleUsage:
    duration_seconds: int
    input_bytes: int
    output_bytes: int
    total_tokens: int
    cost_microusd: int = 0

    def __post_init__(self) -> None:
        for name in (
            "duration_seconds",
            "input_bytes",
            "output_bytes",
            "total_tokens",
            "cost_microusd",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    def as_contract_usage(self) -> dict[str, int]:
        return {
            "durationSeconds": self.duration_seconds,
            "attempts": 1,
            "modelRequests": 1,
            "inputBytes": self.input_bytes,
            "outputBytes": self.output_bytes,
            "totalTokens": self.total_tokens,
            "costMicrousd": self.cost_microusd,
        }


@dataclass(frozen=True)
class RoleExecution:
    raw_output: bytes
    usage: RoleUsage

    def __post_init__(self) -> None:
        if not isinstance(self.raw_output, bytes):
            raise TypeError("raw_output must be bytes")
        if not isinstance(self.usage, RoleUsage):
            raise TypeError("usage must be RoleUsage")
        if self.usage.output_bytes != len(self.raw_output):
            raise ValueError("usage.output_bytes must equal the exact output length")


class RoleExecutorFailure(RuntimeError):
    """Sanitized terminal/ambiguous failure with trusted charged usage."""

    _CODES = {
        "adapter-failed",
        "budget-exceeded",
        "cancelled",
        "policy-denied",
        "provider-ambiguous",
        "provider-mismatch",
        "timeout",
    }

    def __init__(
        self,
        *,
        status: Literal["failed", "ambiguous"],
        error_code: str,
        usage: RoleUsage,
    ) -> None:
        if status not in {"failed", "ambiguous"}:
            raise ValueError("status must be failed or ambiguous")
        if error_code not in self._CODES:
            raise ValueError("error_code is not a safe role failure code")
        if not isinstance(usage, RoleUsage):
            raise TypeError("usage must be RoleUsage")
        super().__init__("Governed role execution did not produce output")
        self.status = status
        self.error_code = error_code
        self.usage = usage


class RoleExecutor(Protocol):
    """Injected execution boundary; the source-review core has no direct egress."""

    def execute(self, invocation: RoleInvocation) -> RoleExecution: ...
