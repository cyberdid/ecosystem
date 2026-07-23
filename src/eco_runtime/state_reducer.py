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
    no_model_authorized: bool = False
    no_model_started: bool = False
    no_model_plan_digest: str | None = None
    no_model_scope_entries: tuple[tuple[str, str], ...] = ()
    no_model_results: tuple[tuple[str, str, str], ...] = ()

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
        no_model_authorized: bool = False,
        no_model_started: bool = False,
        no_model_plan_digest: str | None = None,
        no_model_scope_entries: Mapping[str, str] | None = None,
        no_model_results: Mapping[str, tuple[str, str]] | None = None,
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
            no_model_authorized=no_model_authorized,
            no_model_started=no_model_started,
            no_model_plan_digest=no_model_plan_digest,
            no_model_scope_entries=tuple(sorted((no_model_scope_entries or {}).items())),
            no_model_results=tuple(
                (slot, content_digest, heading_check)
                for slot, (content_digest, heading_check) in sorted(
                    (no_model_results or {}).items()
                )
            ),
        )

    def tool_map(self) -> dict[str, tuple[str, str]]:
        return {
            subject_id: (phase, subject_digest)
            for subject_id, phase, subject_digest in self.tool_states
        }

    def no_model_result_map(self) -> dict[str, tuple[str, str]]:
        return {
            slot: (content_digest, heading_check)
            for slot, content_digest, heading_check in self.no_model_results
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
    no_model_authorized = projection.no_model_authorized
    no_model_started = projection.no_model_started
    no_model_plan_digest = projection.no_model_plan_digest
    no_model_scope_entries = dict(projection.no_model_scope_entries)
    no_model_results = projection.no_model_result_map()

    def result(state: RunState) -> RunProjection:
        return RunProjection.from_parts(
            state=state,
            tool_states=tools,
            adapter_completed=adapter_completed,
            adapter_failed=adapter_failed,
            budget_exhausted=budget_exhausted,
            no_model_authorized=no_model_authorized,
            no_model_started=no_model_started,
            no_model_plan_digest=no_model_plan_digest,
            no_model_scope_entries=no_model_scope_entries,
            no_model_results=no_model_results,
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
        if event_type == "no-model.policy.allowed":
            plan_digest = spec.get("subjectDigest")
            if not isinstance(plan_digest, str):
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model authorization requires a plan digest"
                )
            no_model_authorized = True
            no_model_plan_digest = plan_digest
            return result(RunState.AUTHORIZED)
        if event_type == "no-model.policy.denied":
            return result(RunState.DENIED)
    if projection.state == RunState.AUTHORIZED:
        if event_type == "adapter.started":
            if no_model_authorized:
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model authorization cannot start an adapter"
                )
            return result(RunState.RUNNING)
        if event_type == "no-model.workflow.started":
            if not no_model_authorized or spec.get("subjectDigest") != no_model_plan_digest:
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model workflow is not bound to its authorization"
                )
            entries = spec.get("scopeEntries")
            if not isinstance(entries, list) or len(entries) != 3:
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model workflow requires three scope entries"
                )
            scope_entries: dict[str, str] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise RuntimeStateError(
                        "ECO_NO_MODEL_LIFECYCLE", "No-model scope entry is invalid"
                    )
                slot, entry_digest = entry.get("slot"), entry.get("entryDigest")
                if (
                    slot not in {"slot-1", "slot-2", "slot-3"}
                    or not isinstance(entry_digest, str)
                    or slot in scope_entries
                ):
                    raise RuntimeStateError(
                        "ECO_NO_MODEL_LIFECYCLE", "No-model scope entries are not exact"
                    )
                scope_entries[slot] = entry_digest
            if (
                set(scope_entries) != {"slot-1", "slot-2", "slot-3"}
                or len(set(scope_entries.values())) != 3
            ):
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model scope entries are incomplete"
                )
            no_model_scope_entries = scope_entries
            no_model_started = True
            return result(RunState.RUNNING)
    if projection.state == RunState.RUNNING:
        if no_model_started:
            if event_type.startswith("adapter.") or event_type.startswith("tool.") or event_type in {
                "artifact.recorded",
                "budget.exhausted",
                "run.succeeded",
                "run.exhausted",
            }:
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model runs cannot enter adapter or tool lifecycles"
                )
            if event_type.startswith("no-model.read."):
                subject_id = spec.get("subjectId")
                subject_digest = spec.get("subjectDigest")
                scope_slot = spec.get("scopeSlot")
                entry_digest = spec.get("entryDigest")
                if not isinstance(subject_id, str) or not isinstance(subject_digest, str):
                    raise RuntimeStateError(
                        "ECO_TOOL_EVENT_BINDING", "No-model read event requires a subject id and digest"
                    )
                if (
                    not isinstance(scope_slot, str)
                    or no_model_scope_entries.get(scope_slot) != entry_digest
                ):
                    raise RuntimeStateError(
                        "ECO_NO_MODEL_LIFECYCLE", "No-model read is not bound to a scope entry"
                    )
                existing = tools.get(scope_slot)
                if event_type == "no-model.read.requested":
                    if existing is not None:
                        raise RuntimeStateError("ECO_TOOL_EVENT_ORDER", "No-model read is already recorded")
                    tools[scope_slot] = ("requested", subject_digest)
                else:
                    if existing is None or existing[1] != subject_digest:
                        raise RuntimeStateError(
                            "ECO_TOOL_EVENT_BINDING", "No-model read subject does not match"
                        )
                    current = existing[0]
                    if event_type == "no-model.read.allowed" and current == "requested":
                        tools[scope_slot] = ("allowed", subject_digest)
                    elif event_type == "no-model.read.started" and current == "allowed":
                        tools[scope_slot] = ("started", subject_digest)
                    elif event_type == "no-model.read.denied" and current in {"requested", "allowed"}:
                        tools[scope_slot] = ("denied", subject_digest)
                    elif event_type == "no-model.read.failed" and current in {"allowed", "started"}:
                        if not isinstance(spec.get("resultDigest"), str):
                            raise RuntimeStateError(
                                "ECO_TOOL_EVENT_BINDING", "No-model terminal read requires a result digest"
                            )
                        tools[scope_slot] = ("failed", subject_digest)
                    elif event_type == "no-model.read.completed" and current == "started":
                        if not isinstance(spec.get("resultDigest"), str):
                            raise RuntimeStateError(
                                "ECO_TOOL_EVENT_BINDING", "No-model terminal read requires a result digest"
                            )
                        tools[scope_slot] = ("completed", subject_digest)
                        content_digest = spec.get("contentDigest")
                        heading_check = spec.get("headingCheck")
                        if not isinstance(content_digest, str) or heading_check not in {"pass", "fail"}:
                            raise RuntimeStateError(
                                "ECO_TOOL_EVENT_BINDING",
                                "Completed no-model read requires sanitized check evidence",
                            )
                        no_model_results[scope_slot] = (content_digest, heading_check)
                    else:
                        raise RuntimeStateError("ECO_TOOL_EVENT_ORDER", "No-model read is out of order")
                return result(RunState.RUNNING)
            if event_type == "no-model.workflow.succeeded":
                # The only M4 no-model profile has exactly three fixed reads.
                # Policy binds their hidden path scope; the event chain binds
                # their exact request digests and cannot report success early.
                result_digests = {
                    content_digest for content_digest, _ in no_model_results.values()
                }
                if (
                    set(tools) != set(no_model_scope_entries)
                    or any(state != "completed" for state, _ in tools.values())
                    or set(no_model_results) != set(no_model_scope_entries)
                    or any(check != "pass" for _, check in no_model_results.values())
                    or len(result_digests) != 3
                ):
                    raise RuntimeStateError(
                        "ECO_RUN_SUCCESS_INVALID", "No-model workflow success preconditions are not met"
                    )
                return result(RunState.SUCCEEDED)
            if event_type == "run.succeeded":
                raise RuntimeStateError(
                    "ECO_NO_MODEL_LIFECYCLE", "No-model runs require no-model.workflow.succeeded"
                )
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
