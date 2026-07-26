from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterable

from eco_runtime.contracts import validate_record
from eco_runtime.digests import semantic_digest

from .contracts import (
    FLOW_API_VERSION,
    FLOW_CONTRACT_PROFILE,
    flow_projection_digest,
    validate_flow_projection,
)

_OUTCOME_STATUS = {
    "success": "succeeded",
    "denied": "denied",
    "failed": "failed",
    "exhausted": "exhausted",
    "cancelled": "cancelled",
}

_TERMINAL_EVENT_TYPES = {
    "policy.denied",
    "no-model.policy.denied",
    "no-model.workflow.succeeded",
    "run.succeeded",
    "run.failed",
    "run.cancelled",
    "run.exhausted",
}


@dataclass(frozen=True, slots=True)
class ObservedFlowEvent:
    event_type: str
    phase: str
    status: str
    subject_kind: str
    subject_id: str
    occurred_at: str | None = None
    reason_code: str | None = None
    subject_digest: str | None = None

    def record(self) -> dict[str, Any]:
        return {
            "eventType": self.event_type,
            "phase": self.phase,
            "status": self.status,
            "subject": {
                "kind": self.subject_kind,
                "id": self.subject_id,
                "digest": self.subject_digest,
            },
            "occurredAt": self.occurred_at,
            "reasonCode": self.reason_code,
        }


def _projection(
    *,
    project_id: str,
    run_id: str,
    source_kind: str,
    trust: str,
    boundary: str,
    head_digest: str | None,
    status: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes = []
    for sequence, event in enumerate(events, 1):
        nodes.append(
            {
                "id": f"node-{sequence:06d}",
                "sequence": sequence,
                **copy.deepcopy(event),
            }
        )
    edges = [
        {
            "id": f"edge-{sequence:06d}",
            "from": nodes[sequence - 1]["id"],
            "to": nodes[sequence]["id"],
            "type": "next",
        }
        for sequence in range(1, len(nodes))
    ]
    record: dict[str, Any] = {
        "apiVersion": FLOW_API_VERSION,
        "kind": "FlowProjection",
        "metadata": {
            "id": f"flow:{run_id}",
            "projectId": project_id,
            "runId": run_id,
            "recordDigest": "0" * 64,
        },
        "spec": {
            "profile": FLOW_CONTRACT_PROFILE,
            "source": {
                "kind": source_kind,
                "trust": trust,
                "boundary": boundary,
                "headDigest": head_digest,
            },
            "status": status,
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "nodeCount": len(nodes),
                "edgeCount": len(edges),
                "failedNodeCount": sum(node["status"] == "failed" for node in nodes),
                "deniedNodeCount": sum(node["status"] == "denied" for node in nodes),
            },
        },
    }
    record["metadata"]["recordDigest"] = flow_projection_digest(record)
    return validate_flow_projection(record)


def project_observed_flow(
    *,
    project_id: str,
    run_id: str,
    boundary: str,
    status: str,
    events: Iterable[ObservedFlowEvent],
) -> dict[str, Any]:
    """Project explicitly non-authoritative product observations."""

    return _projection(
        project_id=project_id,
        run_id=run_id,
        source_kind="product-observation",
        trust="observed",
        boundary=boundary,
        head_digest=None,
        status=status,
        events=[event.record() for event in events],
    )


def project_runtime_flow(
    *,
    project_id: str,
    events: Iterable[dict[str, Any]],
    authenticated: bool = False,
) -> dict[str, Any]:
    """Validate and project an ordered Runtime RunEvent chain.

    Validation proves record shape. ``authenticated=True`` is an explicit
    caller assertion that an external authority already authenticated the
    journal; this projector does not authenticate producers itself.
    """

    records = [copy.deepcopy(validate_record(event)) for event in events]
    if not records:
        raise ValueError("runtime event projection requires at least one event")
    run_id = records[0]["metadata"]["runId"]
    if any(event["metadata"]["runId"] != run_id for event in records):
        raise ValueError("runtime events must belong to one run")
    if [event["metadata"]["sequence"] for event in records] != list(
        range(1, len(records) + 1)
    ):
        raise ValueError("runtime event sequence must be contiguous")
    previous_digest: str | None = None
    for event in records:
        if event["metadata"]["previousEventDigest"] != previous_digest:
            raise ValueError("runtime event chain digest does not match")
        previous_digest = semantic_digest(event)

    projected: list[dict[str, Any]] = []
    for event in records:
        spec = event["spec"]
        event_type = spec["type"]
        suffix = event_type.rsplit(".", 1)[-1]
        if event_type.startswith(("policy.", "no-model.policy.")):
            phase = "policy"
        elif event_type.startswith(("tool.", "adapter.", "no-model.read.")):
            phase = "execute"
        elif event_type.startswith("no-model.workflow."):
            phase = "execute" if suffix == "started" else "terminal"
        elif event_type == "plan.created":
            phase = "plan"
        elif event_type in _TERMINAL_EVENT_TYPES:
            phase = "terminal"
        else:
            phase = "admission"
        outcome = spec["outcome"]
        status = (
            "running"
            if outcome == "pending" and suffix == "started"
            else "pending"
            if outcome == "pending"
            else _OUTCOME_STATUS[outcome]
        )
        subject_id = spec.get("subjectId")
        projected.append(
            {
                "eventType": event_type,
                "phase": phase,
                "status": status,
                "occurredAt": event["metadata"]["occurredAt"],
                "reasonCode": spec.get("reasonCode"),
                "subject": {
                    "kind": "RunEventSubject" if subject_id else "RunEvent",
                    "id": subject_id or event["metadata"]["id"],
                    "digest": spec.get("subjectDigest"),
                },
            }
        )
    last = records[-1]
    terminal_status = projected[-1]["status"]
    status = (
        terminal_status
        if last["spec"]["type"] in _TERMINAL_EVENT_TYPES
        else "running"
    )
    return _projection(
        project_id=project_id,
        run_id=run_id,
        source_kind="runtime-run-events",
        trust="authenticated" if authenticated else "validated",
        boundary=(
            "external-journal-authenticated"
            if authenticated
            else "schema-validated-not-authenticated"
        ),
        head_digest=semantic_digest(last),
        status=status,
        events=projected,
    )
