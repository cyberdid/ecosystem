from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .errors import RuntimeStateError


class RunState(str, Enum):
    NEW = "NEW"
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    CANCELLED = "CANCELLED"
    EXHAUSTED = "EXHAUSTED"


TERMINAL_STATES = frozenset(
    {
        RunState.SUCCEEDED,
        RunState.FAILED,
        RunState.DENIED,
        RunState.CANCELLED,
        RunState.EXHAUSTED,
    }
)


@dataclass(frozen=True)
class RunProjection:
    """Content-free state required to deterministically reduce one run event."""

    state: RunState
    tool_states: tuple[tuple[str, str, str], ...] = ()
    adapter_completed: bool = False
    adapter_failed: bool = False
    budget_exhausted: bool = False

    @classmethod
    def initial(cls) -> RunProjection:
        return cls(state=RunState.NEW)

    @classmethod
    def from_parts(
        cls,
        *,
        state: RunState,
        tool_states: Mapping[str, tuple[str, str]],
        adapter_completed: bool,
        adapter_failed: bool,
        budget_exhausted: bool,
    ) -> RunProjection:
        return cls(
            state=state,
            tool_states=tuple(
                (subject_id, phase, subject_digest)
                for subject_id, (phase, subject_digest) in sorted(tool_states.items())
            ),
            adapter_completed=adapter_completed,
            adapter_failed=adapter_failed,
            budget_exhausted=budget_exhausted,
        )

    def tool_map(self) -> dict[str, tuple[str, str]]:
        return {
            subject_id: (phase, subject_digest)
            for subject_id, phase, subject_digest in self.tool_states
        }


def reduce_run_event(
    projection: RunProjection,
    event_type: str,
    spec: Mapping[str, Any],
) -> RunProjection:
    """Pure transition reducer shared by memory and durable replay paths."""

    tools = projection.tool_map()
    adapter_completed = projection.adapter_completed
    adapter_failed = projection.adapter_failed
    budget_exhausted = projection.budget_exhausted

    def result(state: RunState) -> RunProjection:
        return RunProjection.from_parts(
            state=state,
            tool_states=tools,
            adapter_completed=adapter_completed,
            adapter_failed=adapter_failed,
            budget_exhausted=budget_exhausted,
        )

    if projection.state == RunState.NEW and event_type == "run.received":
        return result(RunState.RECEIVED)
    if projection.state == RunState.RECEIVED and event_type == "run.validated":
        return result(RunState.VALIDATED)
    if projection.state == RunState.VALIDATED and event_type == "plan.created":
        return result(RunState.PLANNED)
    if projection.state == RunState.PLANNED:
        if event_type == "policy.allowed":
            return result(RunState.AUTHORIZED)
        if event_type == "policy.denied":
            return result(RunState.DENIED)
    if projection.state == RunState.AUTHORIZED and event_type == "adapter.started":
        return result(RunState.RUNNING)
    if projection.state == RunState.RUNNING:
        if event_type.startswith("tool."):
            subject_id = spec.get("subjectId")
            subject_digest = spec.get("subjectDigest")
            if not isinstance(subject_id, str) or not isinstance(subject_digest, str):
                raise RuntimeStateError(
                    "ECO_TOOL_EVENT_BINDING",
                    "Tool event requires a subject id and digest",
                )
            existing = tools.get(subject_id)
            if event_type == "tool.requested":
                if adapter_completed or adapter_failed or budget_exhausted or existing is not None:
                    raise RuntimeStateError("ECO_TOOL_EVENT_ORDER", "Tool request is not allowed now")
                tools[subject_id] = ("requested", subject_digest)
            else:
                if existing is None or existing[1] != subject_digest:
                    raise RuntimeStateError(
                        "ECO_TOOL_EVENT_BINDING", "Tool event subject does not match"
                    )
                current = existing[0]
                if event_type == "tool.allowed" and current == "requested":
                    tools[subject_id] = ("allowed", subject_digest)
                elif event_type == "tool.denied" and current == "requested":
                    tools[subject_id] = ("denied", subject_digest)
                elif event_type == "tool.cancelled" and current in {"requested", "allowed"}:
                    tools[subject_id] = ("cancelled", subject_digest)
                elif event_type in {"tool.completed", "tool.failed"} and current == "allowed":
                    if not isinstance(spec.get("resultDigest"), str):
                        raise RuntimeStateError(
                            "ECO_TOOL_EVENT_BINDING",
                            "Terminal tool event requires a result digest",
                        )
                    tools[subject_id] = (
                        "completed" if event_type == "tool.completed" else "failed",
                        subject_digest,
                    )
                else:
                    raise RuntimeStateError("ECO_TOOL_EVENT_ORDER", "Tool event is out of order")
            return result(RunState.RUNNING)
        if event_type == "adapter.completed":
            if adapter_completed or adapter_failed or budget_exhausted or any(
                state in {"requested", "allowed"} for state, _ in tools.values()
            ):
                raise RuntimeStateError("ECO_ADAPTER_EVENT_ORDER", "Adapter cannot complete now")
            adapter_completed = True
            return result(RunState.RUNNING)
        if event_type == "adapter.failed":
            if adapter_completed or adapter_failed:
                raise RuntimeStateError("ECO_ADAPTER_EVENT_ORDER", "Adapter failure is out of order")
            adapter_failed = True
            return result(RunState.RUNNING)
        if event_type == "artifact.recorded":
            if adapter_failed or budget_exhausted:
                raise RuntimeStateError("ECO_STATE_TRANSITION", "Artifact event is not allowed now")
            return result(RunState.RUNNING)
        if event_type == "budget.exhausted":
            if budget_exhausted or adapter_completed:
                raise RuntimeStateError("ECO_BUDGET_EVENT_ORDER", "Budget exhaustion is out of order")
            budget_exhausted = True
            return result(RunState.RUNNING)
        if event_type == "run.succeeded":
            if (
                not adapter_completed
                or adapter_failed
                or budget_exhausted
                or any(state in {"requested", "allowed"} for state, _ in tools.values())
            ):
                raise RuntimeStateError(
                    "ECO_RUN_SUCCESS_INVALID", "Run success preconditions are not met"
                )
            return result(RunState.SUCCEEDED)
        if event_type == "run.exhausted":
            if not budget_exhausted:
                raise RuntimeStateError(
                    "ECO_RUN_EXHAUSTION_INVALID", "Run is not budget exhausted"
                )
            if any(state in {"requested", "allowed"} for state, _ in tools.values()):
                raise RuntimeStateError(
                    "ECO_TOOL_EVENT_ORDER", "Open tool operations block termination"
                )
            return result(RunState.EXHAUSTED)
        if event_type == "run.failed":
            if any(state in {"requested", "allowed"} for state, _ in tools.values()):
                raise RuntimeStateError(
                    "ECO_TOOL_EVENT_ORDER", "Open tool operations block termination"
                )
            return result(RunState.FAILED)
        if event_type == "run.cancelled":
            if any(state in {"requested", "allowed"} for state, _ in tools.values()):
                raise RuntimeStateError(
                    "ECO_TOOL_EVENT_ORDER", "Open tool operations block termination"
                )
            return result(RunState.CANCELLED)

    if projection.state in {
        RunState.RECEIVED,
        RunState.VALIDATED,
        RunState.PLANNED,
        RunState.AUTHORIZED,
    }:
        if event_type == "run.failed":
            return result(RunState.FAILED)
        if event_type == "run.cancelled":
            return result(RunState.CANCELLED)

    raise RuntimeStateError(
        "ECO_STATE_TRANSITION",
        "Event is not allowed in the current run state",
    )
