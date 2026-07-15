from __future__ import annotations

import copy
import threading
from datetime import datetime
from typing import Any, Mapping

from .contracts import validate_record
from .digests import semantic_digest
from .errors import ContractValidationError, RuntimeStateError
from .state_reducer import RunProjection, RunState, TERMINAL_STATES, reduce_run_event

# Every event type has one exact outcome and one or more trusted producers.
EVENT_SEMANTICS: dict[str, tuple[str, frozenset[str]]] = {
    "run.received": ("pending", frozenset({"runtime"})),
    "run.validated": ("success", frozenset({"runtime"})),
    "plan.created": ("success", frozenset({"runtime"})),
    "policy.allowed": ("success", frozenset({"policy"})),
    "policy.denied": ("denied", frozenset({"policy"})),
    "adapter.started": ("pending", frozenset({"adapter"})),
    "adapter.completed": ("success", frozenset({"adapter"})),
    "adapter.failed": ("failed", frozenset({"adapter"})),
    "tool.requested": ("pending", frozenset({"runtime"})),
    "tool.allowed": ("success", frozenset({"policy"})),
    "tool.denied": ("denied", frozenset({"policy"})),
    "tool.cancelled": ("cancelled", frozenset({"runtime"})),
    "tool.completed": ("success", frozenset({"broker"})),
    "tool.failed": ("failed", frozenset({"broker"})),
    "artifact.recorded": ("success", frozenset({"runtime", "broker", "adapter"})),
    "budget.exhausted": ("exhausted", frozenset({"runtime"})),
    "run.succeeded": ("success", frozenset({"runtime"})),
    "run.failed": ("failed", frozenset({"runtime"})),
    "run.cancelled": ("cancelled", frozenset({"runtime"})),
    "run.exhausted": ("exhausted", frozenset({"runtime"})),
}

OPERATIONAL_EVENTS = frozenset(
    {
        "adapter.completed",
        "adapter.failed",
        "tool.requested",
        "tool.allowed",
        "tool.denied",
        "tool.cancelled",
        "tool.completed",
        "tool.failed",
        "artifact.recorded",
        "budget.exhausted",
    }
)

TERMINAL_EVENT_STATES = {
    "run.succeeded": RunState.SUCCEEDED,
    "run.failed": RunState.FAILED,
    "run.cancelled": RunState.CANCELLED,
    "run.exhausted": RunState.EXHAUSTED,
}


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


class RunEventChain:
    """Atomically validate and append one run's tamper-evident event chain.

    This is an in-process enforcement primitive. Durability and cross-process
    serialization belong to the M2 audit-store boundary and are not implied here.
    """

    def __init__(
        self,
        run_id: str,
        producer_capabilities: Mapping[str, tuple[str, object]],
    ):
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run_id must be a non-empty string")
        self._run_id = run_id
        required_producers = {"runtime", "policy", "broker", "adapter"}
        if set(producer_capabilities) != required_producers:
            raise ValueError("producer_capabilities must define every trusted producer")
        if any(
            not isinstance(issuer, str) or not issuer or token is None
            for issuer, token in producer_capabilities.values()
        ):
            raise ValueError("producer capabilities must have issuer ids and opaque tokens")
        tokens = [token for _, token in producer_capabilities.values()]
        if len({id(token) for token in tokens}) != len(tokens):
            raise ValueError("producer capability tokens must be distinct objects")
        self._producer_capabilities = dict(producer_capabilities)
        self._state = RunState.NEW
        self._events: list[dict[str, Any]] = []
        self._event_ids: set[str] = set()
        self._head_digest: str | None = None
        self._occurred_at: datetime | None = None
        self._tool_states: dict[str, tuple[str, str]] = {}
        self._adapter_completed = False
        self._adapter_failed = False
        self._budget_exhausted = False
        self._lock = threading.Lock()

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def state(self) -> RunState:
        with self._lock:
            return self._state

    @property
    def head_digest(self) -> str | None:
        with self._lock:
            return self._head_digest

    def events(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(copy.deepcopy(self._events))

    def append(self, event: dict[str, Any], producer_capability: object) -> RunState:
        """Validate and atomically append; leave the chain unchanged on failure."""

        try:
            validate_record(event)
        except ContractValidationError as exc:
            raise RuntimeStateError("ECO_EVENT_INVALID", "Run event contract is invalid") from exc

        candidate = copy.deepcopy(event)
        metadata = candidate["metadata"]
        spec = candidate["spec"]

        with self._lock:
            if self._state in TERMINAL_STATES:
                raise RuntimeStateError(
                    "ECO_RUN_TERMINAL",
                    "No event may be appended after a terminal run state",
                )
            if metadata["runId"] != self._run_id:
                raise RuntimeStateError("ECO_EVENT_RUN_MISMATCH", "Event belongs to another run")
            if metadata["id"] in self._event_ids:
                raise RuntimeStateError("ECO_EVENT_ID_REUSED", "Event identifier was already used")

            expected_sequence = len(self._events) + 1
            if metadata["sequence"] != expected_sequence:
                raise RuntimeStateError("ECO_EVENT_SEQUENCE", "Event sequence is not contiguous")
            if metadata["previousEventDigest"] != self._head_digest:
                raise RuntimeStateError(
                    "ECO_EVENT_CHAIN_MISMATCH",
                    "Event does not bind to the current event-chain head",
                )

            occurred_at = _timestamp(metadata["occurredAt"])
            if self._occurred_at is not None and occurred_at < self._occurred_at:
                raise RuntimeStateError("ECO_EVENT_TIME_REVERSED", "Event time moved backwards")

            event_type = spec["type"]
            expected_outcome, producers = EVENT_SEMANTICS[event_type]
            if spec["outcome"] != expected_outcome:
                raise RuntimeStateError("ECO_EVENT_OUTCOME", "Event outcome is invalid for its type")
            if metadata["producer"] not in producers:
                raise RuntimeStateError("ECO_EVENT_PRODUCER", "Producer cannot emit this event type")

            trusted_issuer, trusted_capability = self._producer_capabilities[metadata["producer"]]
            if (
                producer_capability is not trusted_capability
                or metadata["producerIssuer"] != trusted_issuer
            ):
                raise RuntimeStateError(
                    "ECO_EVENT_PRODUCER_UNTRUSTED",
                    "Event producer does not hold the configured runtime capability",
                )

            next_projection = reduce_run_event(
                RunProjection.from_parts(
                    state=self._state,
                    tool_states=self._tool_states,
                    adapter_completed=self._adapter_completed,
                    adapter_failed=self._adapter_failed,
                    budget_exhausted=self._budget_exhausted,
                ),
                event_type,
                spec,
            )
            event_digest = semantic_digest(candidate)
            self._events.append(candidate)
            self._event_ids.add(metadata["id"])
            self._head_digest = event_digest
            self._occurred_at = occurred_at
            self._state = next_projection.state
            self._tool_states = next_projection.tool_map()
            self._adapter_completed = next_projection.adapter_completed
            self._adapter_failed = next_projection.adapter_failed
            self._budget_exhausted = next_projection.budget_exhausted
            return next_projection.state
