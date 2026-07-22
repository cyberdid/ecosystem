from __future__ import annotations

"""P3 vendor-neutral reference agent-team topologies.

Two runnable-shaped ``AgentTeamManifest`` references built only on M6.6
primitives, with no vendor SDK: evaluator-optimizer (a proposer plus an
independent evaluator that is never the author) and orchestrator-workers (a
planner that fans bounded work to narrower workers). They validate structurally
offline through the normal team contract; a live model PASS is deferred with the
same dependency as the M6 five-role run.
"""

from typing import Any, Callable

from .contracts import API_VERSION, seal_record

_DIGEST = "d" * 64
_CREATED = "2026-07-17T11:00:00Z"
_DEADLINE = "2026-07-17T13:00:00Z"
_NOT_AFTER = "2026-07-17T13:00:00Z"


def _binding(kind: str, identifier: str) -> dict[str, str]:
    return {"kind": kind, "id": identifier, "digest": _DIGEST}


def _role(
    role_id: str, *, actions: list[str], data: list[str], delegates: list[str], tokens: int, cost: int
) -> dict[str, Any]:
    return {
        "id": role_id,
        "principal": _binding("PrincipalIdentity", f"principal-{role_id}"),
        "membership": _binding("MembershipBinding", f"membership-{role_id}"),
        "actions": actions,
        "dataClasses": data,
        "toolIds": [],
        "zones": ["local"],
        "notAfter": _NOT_AFTER,
        "budget": {"maxTokens": tokens, "maxCostMicrousd": cost, "maxDurationSeconds": 60},
        "delegatesTo": delegates,
    }


def _manifest(manifest_id: str, roles: list[dict[str, Any]]) -> dict[str, Any]:
    return seal_record(
        {
            "apiVersion": API_VERSION,
            "kind": "AgentTeamManifest",
            "metadata": {
                "id": manifest_id,
                "projectId": "reference",
                "createdAt": _CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": "bounded-agent-team-v1",
                "authority": {
                    "teamId": f"{manifest_id}-team",
                    "storeId": "reference-store",
                    "authoritySnapshotDigest": "a" * 64,
                    "activeBundleDigest": "b" * 64,
                    "accessPolicyDigest": "c" * 64,
                },
                "roles": roles,
                "budget": {"maxTasks": 20, "maxTotalTokens": 100, "maxCostMicrousd": 100},
                "deadline": _DEADLINE,
                "safety": {
                    "signedAuthorityRequired": True,
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def evaluator_optimizer_manifest() -> dict[str, Any]:
    """Optimizer proposes and orchestrates; evaluator grades independently.

    The evaluator never delegates back to the optimizer, so the reviewer is
    never the author. The evaluator's authority is a strict subset.
    """

    roles = [
        _role("evaluator", actions=["evaluation.run"], data=["D0"], delegates=[], tokens=8, cost=8),
        _role(
            "optimizer",
            actions=["evaluation.run"],
            data=["D0", "D1"],
            delegates=["evaluator"],
            tokens=10,
            cost=10,
        ),
    ]
    return _manifest("reference-evaluator-optimizer", roles)


def orchestrator_workers_manifest() -> dict[str, Any]:
    """Orchestrator fans bounded work to two narrower workers."""

    roles = [
        _role(
            "orchestrator",
            actions=["evaluation.run"],
            data=["D0", "D1"],
            delegates=["worker-a", "worker-b"],
            tokens=10,
            cost=10,
        ),
        _role("worker-a", actions=["evaluation.run"], data=["D0"], delegates=[], tokens=8, cost=8),
        _role("worker-b", actions=["evaluation.run"], data=["D0"], delegates=[], tokens=8, cost=8),
    ]
    return _manifest("reference-orchestrator-workers", roles)


REFERENCE_MANIFESTS: dict[str, Callable[[], dict[str, Any]]] = {
    "evaluator-optimizer": evaluator_optimizer_manifest,
    "orchestrator-workers": orchestrator_workers_manifest,
}
