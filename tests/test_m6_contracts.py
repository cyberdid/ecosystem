from __future__ import annotations

import copy
import unittest

from eco_orchestration.contracts import (
    ORCHESTRATION_API_VERSION,
    ORCHESTRATION_CONTRACT_PROFILE,
    ORCHESTRATION_SCHEMA_BY_KIND,
    orchestration_contract_errors,
    orchestration_record_digest,
    orchestration_record_set_errors,
    orchestration_route_digest,
    orchestration_schema_bundle_digest,
    validate_orchestration_record,
    validate_orchestration_record_set,
)
from eco_runtime.contracts import schema_bundle_digest
from eco_runtime.errors import ContractValidationError

NOW = "2026-07-17T12:00:00Z"
LATER = "2026-07-17T13:00:00Z"
DIGEST = "a" * 64
ROLES = ("planner", "analyst", "verifier", "synthesizer", "reviewer")


def artifact(name: str, *, byte_length: int = 1) -> dict:
    return {
        "ref": f"artifact://private/{name}",
        "contentDigest": DIGEST,
        "byteLength": byte_length,
        "dataClass": "D1",
    }


def budget() -> dict:
    return {
        "maxDurationSeconds": 600,
        "maxAttempts": 2,
        "maxModelRequests": 2,
        "maxInputBytes": 1_000_000,
        "maxOutputBytes": 100_000,
        "maxTotalTokens": 50_000,
        "maxCostMicrousd": 0,
    }


def aggregate_budget() -> dict:
    value = budget()
    value.update(
        {
            "maxDurationSeconds": 3000,
            "maxAttempts": 10,
            "maxModelRequests": 10,
            "maxInputBytes": 5_000_000,
            "maxOutputBytes": 500_000,
            "maxTotalTokens": 250_000,
        }
    )
    return value


def usage() -> dict:
    return {
        "durationSeconds": 1,
        "attempts": 1,
        "modelRequests": 1,
        "inputBytes": 10,
        "outputBytes": 10,
        "totalTokens": 5,
        "costMicrousd": 0,
    }


def aggregate_usage() -> dict:
    return {
        "durationSeconds": 5,
        "attempts": 5,
        "modelRequests": 5,
        "inputBytes": 50,
        "outputBytes": 50,
        "totalTokens": 25,
        "costMicrousd": 0,
    }


def metadata(identifier: str, *, definition: bool = False) -> dict:
    value = {
        "id": identifier,
        "projectId": "ecosystem",
        "teamId": "research-team",
        "runId": "definition" if definition else "run-1",
        "createdAt": NOW,
        "recordDigest": "0" * 64,
    }
    if definition:
        value["revision"] = 1
    return value


def seal(record: dict) -> dict:
    record["metadata"]["recordDigest"] = orchestration_record_digest(record)
    return record


def binding(record: dict) -> dict:
    return {
        "kind": record["kind"],
        "id": record["metadata"]["id"],
        "digest": record["metadata"]["recordDigest"],
    }


def refresh_bindings_and_seals(graph: list[dict]) -> None:
    """Refresh digest-only dependencies after a focused fixture mutation."""

    def refresh(value: object, records: dict[tuple[str, str], dict]) -> None:
        if isinstance(value, dict):
            if set(value) == {"kind", "id", "digest"}:
                target = records.get((value["kind"], value["id"]))
                if target is not None:
                    value["digest"] = target["metadata"]["recordDigest"]
                return
            for child in value.values():
                refresh(child, records)
        elif isinstance(value, list):
            for child in value:
                refresh(child, records)

    for _ in range(len(graph) + 1):
        records = {
            (item["kind"], item["metadata"]["id"]): item for item in graph
        }
        changed = False
        for item in graph:
            before = item["metadata"]["recordDigest"]
            refresh(item, records)
            seal(item)
            changed = changed or item["metadata"]["recordDigest"] != before
        if not changed:
            return
    raise AssertionError("fixture binding refresh did not converge")


def record(kind: str, identifier: str, spec: dict, *, definition: bool = False) -> dict:
    return seal(
        {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": kind,
            "metadata": metadata(identifier, definition=definition),
            "spec": spec,
        }
    )


def positive_record_graph() -> list[dict]:
    profiles = []
    for role_id in ROLES:
        profiles.append(
            record(
                "RoleProfile",
                f"profile-{role_id}",
                {
                    "roleId": role_id,
                    "instruction": artifact(f"instruction-{role_id}"),
                    "outputSchema": artifact(f"output-schema-{role_id}"),
                    "inputKinds": ["source-bundle"],
                    "outputKinds": ["analysis"],
                    "allowedCapabilities": ["model.invoke"],
                    "allowedDataClasses": ["D0", "D1"],
                    "tools": [],
                    "modelRequirements": {
                        "capabilityIds": ["structured-output"],
                        "minimumContextTokens": 4096,
                        "maximumDataClass": "D1",
                    },
                },
                definition=True,
            )
        )
    team = record(
        "TeamManifest",
        "source-review-team",
        {
            "workflow": "source-review",
            "roles": [
                {"roleId": role, "profile": binding(profile)}
                for role, profile in zip(ROLES, profiles)
            ],
            "edges": [
                {"from": source, "to": target}
                for source, target in zip(ROLES, ROLES[1:])
            ],
            "maxRevisionCycles": 1,
            "gate": {
                "owner": "runtime",
                "rubric": artifact("review-rubric"),
                "acceptedVerdict": "accepted",
            },
        },
        definition=True,
    )
    loop = record(
        "LoopDefinition",
        "source-review-loop",
        {
            "workflow": "source-review",
            "teamManifest": binding(team),
            "trigger": "manual",
            "maxIterations": 2,
            "budget": aggregate_budget(),
            "gate": {
                "owner": "runtime",
                "reviewRole": "reviewer",
                "rubricDigest": DIGEST,
                "acceptedVerdict": "accepted",
            },
            "hardStops": [
                "budget-exhausted",
                "cancelled",
                "deadline",
                "policy-denied",
                "revision-exhausted",
                "verification-failed",
            ],
        },
        definition=True,
    )
    source = record(
        "SourceBundle",
        "source-bundle-1",
        {
            "ingestionPolicyDigest": DIGEST,
            "dataClass": "D1",
            "questionEntryId": "question",
            "totalByteLength": 2,
            "entries": [
                {
                    "id": "question",
                    "artifact": artifact("question"),
                    "mediaType": "text/plain",
                    "encoding": "utf-8",
                    "provenance": {
                        "kind": "local-file",
                        "provenanceDigest": DIGEST,
                        "remoteIdentityDigest": None,
                        "commitDigest": None,
                    },
                },
                {
                    "id": "source-1",
                    "artifact": artifact("source-1"),
                    "mediaType": "text/markdown",
                    "encoding": "utf-8",
                    "provenance": {
                        "kind": "local-file",
                        "provenanceDigest": DIGEST,
                        "remoteIdentityDigest": None,
                        "commitDigest": None,
                    },
                },
            ],
        },
    )
    request = record(
        "TeamRunRequest",
        "team-request-1",
        {
            "workflow": "source-review",
            "sourceBundle": binding(source),
            "teamManifest": binding(team),
            "loopDefinition": binding(loop),
            "requestedRoles": list(ROLES),
            "policySnapshotDigest": DIGEST,
            "budget": aggregate_budget(),
            "deadlineAt": LATER,
        },
    )

    route_slots = (
        ("planner", 1),
        ("analyst", 1),
        ("verifier", 1),
        ("synthesizer", 1),
        ("synthesizer", 2),
        ("reviewer", 1),
        ("reviewer", 2),
    )
    route_templates = []
    for role_id, attempt_number in route_slots:
        route = {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": "RouteDecision",
            "metadata": metadata(f"route-{role_id}-{attempt_number}"),
            "spec": {
                "planId": "team-plan-1",
                "planDigest": "0" * 64,
                "roleId": role_id,
                "attempt": attempt_number,
                "routeDigest": "0" * 64,
                "decision": "allowed",
                "reasonCode": "eligible",
                "deployment": {
                    "id": "scripted-offline",
                    "digest": DIGEST,
                    "endpointBindingDigest": DIGEST,
                    "capabilityEvidenceDigest": DIGEST,
                },
                "validUntil": LATER,
                "fallbackPolicy": "none",
            },
        }
        route["spec"]["routeDigest"] = orchestration_route_digest(route)
        route_templates.append(route)

    steps = []
    routes_by_role = {
        role_id: [
            route for route in route_templates if route["spec"]["roleId"] == role_id
        ]
        for role_id in ROLES
    }
    for index, (role_id, profile) in enumerate(zip(ROLES, profiles), start=1):
        steps.append(
            {
                "ordinal": index,
                "roleId": role_id,
                "profile": binding(profile),
                "predecessors": [] if index == 1 else [ROLES[index - 2]],
                "childPlanDigest": DIGEST,
                "routes": [
                    {
                        "attempt": route["spec"]["attempt"],
                        "decisionId": route["metadata"]["id"],
                        "routeDigest": route["spec"]["routeDigest"],
                    }
                    for route in routes_by_role[role_id]
                ],
                "budget": budget(),
            }
        )
    plan = record(
        "TeamRunPlan",
        "team-plan-1",
        {
            "request": binding(request),
            "sourceBundle": binding(source),
            "teamManifest": binding(team),
            "loopDefinition": binding(loop),
            "policySnapshotDigest": DIGEST,
            "deadlineAt": LATER,
            "aggregateBudget": aggregate_budget(),
            "steps": steps,
            "gate": {
                "owner": "runtime",
                "reviewRole": "reviewer",
                "rubricDigest": DIGEST,
                "maxRevisionCycles": 1,
            },
        },
    )
    routes = []
    for route in route_templates:
        route["spec"]["planDigest"] = plan["metadata"]["recordDigest"]
        routes.append(seal(route))
    route_by_slot = {
        (route["spec"]["roleId"], route["spec"]["attempt"]): route
        for route in routes
    }

    attempts = []
    for role_id in ROLES:
        route = route_by_slot[(role_id, 1)]
        attempts.append(
            record(
                "RoleAttemptResult",
                f"attempt-{role_id}",
                {
                    "planId": plan["metadata"]["id"],
                    "planDigest": plan["metadata"]["recordDigest"],
                    "roleId": role_id,
                    "attempt": 1,
                    "routeDecision": binding(route),
                    "status": "succeeded",
                    "startedAt": NOW,
                    "finishedAt": NOW,
                    "output": artifact(f"output-{role_id}"),
                    "errorCode": None,
                    "usage": usage(),
                },
            )
        )
    evidence = record(
        "EvidenceRecord",
        "evidence-1",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "sourceBundle": binding(source),
            "sourceEntryId": "source-1",
            "observation": artifact("observation-1"),
            "provenanceDigest": DIGEST,
            "trust": "P0",
            "relation": "supports",
            "claimIds": ["claim-1"],
        },
    )
    claim = record(
        "ClaimRecord",
        "claim-1",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "sourceBundle": binding(source),
            "producedByRole": "analyst",
            "statement": artifact("claim-statement-1"),
            "classification": "fact",
            "state": "proposed",
        },
    )
    verification = record(
        "VerificationRecord",
        "verification-1",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "claim": binding(claim),
            "verifiedByRole": "verifier",
            "rubricDigest": DIGEST,
            "evidence": [binding(evidence)],
            "status": "verified",
        },
    )
    handoffs = []
    for ordinal, (source_role, target_role, attempt) in enumerate(
        zip(ROLES, ROLES[1:], attempts), start=1
    ):
        handoffs.append(
            record(
                "HandoffRecord",
                f"handoff-{source_role}-{target_role}",
                {
                    "planId": plan["metadata"]["id"],
                    "planDigest": plan["metadata"]["recordDigest"],
                    "ordinal": ordinal,
                    "cycle": 0,
                    "fromRoleId": source_role,
                    "toRoleId": target_role,
                    "toAttempt": 1,
                    "roleAttemptResult": binding(attempt),
                    "status": "ready",
                    "artifacts": [artifact(f"handoff-{source_role}")],
                    "claims": [binding(claim)] if source_role == "analyst" else [],
                    "evidence": [binding(evidence)] if source_role == "analyst" else [],
                    "verifications": [binding(verification)] if source_role == "verifier" else [],
                    "uncertainty": "none",
                    "openQuestions": None,
                },
            )
        )
    review = record(
        "ReviewRecord",
        "review-1",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "subject": artifact("output-synthesizer"),
            "producerRole": "synthesizer",
            "reviewerRole": "reviewer",
            "reviewerAttempt": binding(attempts[-1]),
            "rubricDigest": DIGEST,
            "cycle": 0,
            "verdict": "accepted",
            "findings": None,
        },
    )
    event = record(
        "OrchestrationEvent",
        "event-1",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "sequence": 1,
            "occurredAt": NOW,
            "eventType": "run-succeeded",
            "subject": binding(plan),
            "previousEventDigest": None,
            "reasonCode": "accepted",
        },
    )
    result = record(
        "TeamRunResult",
        "result-1",
        {
            "plan": binding(plan),
            "request": binding(request),
            "sourceBundle": binding(source),
            "status": "succeeded",
            "reasonCode": "accepted",
            "finalReport": artifact("output-synthesizer"),
            "reviews": [binding(review)],
            "claims": [binding(claim)],
            "evidence": [binding(evidence)],
            "verifications": [binding(verification)],
            "routeDecisions": [binding(route_by_slot[(role_id, 1)]) for role_id in ROLES],
            "roleAttempts": [binding(item) for item in attempts],
            "handoffs": [binding(item) for item in handoffs],
            "usage": aggregate_usage(),
            "terminalEvent": binding(event),
        },
    )
    return [
        *profiles,
        team,
        loop,
        source,
        request,
        plan,
        *routes,
        *attempts,
        evidence,
        claim,
        verification,
        *handoffs,
        review,
        event,
        result,
    ]


def revision_record_graph(*, final_verdict: str = "accepted", same_report: bool = False) -> list[dict]:
    graph = positive_record_graph()
    plan = next(item for item in graph if item["kind"] == "TeamRunPlan")
    result = next(item for item in graph if item["kind"] == "TeamRunResult")
    event = next(item for item in graph if item["kind"] == "OrchestrationEvent")
    review_zero = next(item for item in graph if item["kind"] == "ReviewRecord")
    routes = {
        (item["spec"]["roleId"], item["spec"]["attempt"]): item
        for item in graph
        if item["kind"] == "RouteDecision"
    }
    attempts = {
        (item["spec"]["roleId"], item["spec"]["attempt"]): item
        for item in graph
        if item["kind"] == "RoleAttemptResult"
    }
    review_zero["spec"]["verdict"] = "revision-required"
    seal(review_zero)

    synthesis_output = (
        attempts[("synthesizer", 1)]["spec"]["output"]
        if same_report
        else artifact("output-synthesizer-2")
    )
    synthesizer_two = record(
        "RoleAttemptResult",
        "attempt-synthesizer-2",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "roleId": "synthesizer",
            "attempt": 2,
            "routeDecision": binding(routes[("synthesizer", 2)]),
            "status": "succeeded",
            "startedAt": NOW,
            "finishedAt": NOW,
            "output": synthesis_output,
            "errorCode": None,
            "usage": usage(),
        },
    )
    reviewer_two = record(
        "RoleAttemptResult",
        "attempt-reviewer-2",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "roleId": "reviewer",
            "attempt": 2,
            "routeDecision": binding(routes[("reviewer", 2)]),
            "status": "succeeded",
            "startedAt": NOW,
            "finishedAt": NOW,
            "output": artifact("output-reviewer-2"),
            "errorCode": None,
            "usage": usage(),
        },
    )
    handoff_five = record(
        "HandoffRecord",
        "handoff-reviewer-1-synthesizer-2",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "ordinal": 5,
            "cycle": 1,
            "fromRoleId": "reviewer",
            "toRoleId": "synthesizer",
            "toAttempt": 2,
            "roleAttemptResult": binding(attempts[("reviewer", 1)]),
            "status": "ready",
            "artifacts": [artifact("handoff-reviewer-1")],
            "claims": [],
            "evidence": [],
            "verifications": [],
            "uncertainty": "none",
            "openQuestions": None,
        },
    )
    handoff_six = record(
        "HandoffRecord",
        "handoff-synthesizer-2-reviewer-2",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "ordinal": 6,
            "cycle": 1,
            "fromRoleId": "synthesizer",
            "toRoleId": "reviewer",
            "toAttempt": 2,
            "roleAttemptResult": binding(synthesizer_two),
            "status": "ready",
            "artifacts": [artifact("handoff-synthesizer-2")],
            "claims": [],
            "evidence": [],
            "verifications": [],
            "uncertainty": "none",
            "openQuestions": None,
        },
    )
    review_one = record(
        "ReviewRecord",
        "review-2",
        {
            "planId": plan["metadata"]["id"],
            "planDigest": plan["metadata"]["recordDigest"],
            "subject": synthesis_output,
            "producerRole": "synthesizer",
            "reviewerRole": "reviewer",
            "reviewerAttempt": binding(reviewer_two),
            "rubricDigest": DIGEST,
            "cycle": 1,
            "verdict": final_verdict,
            "findings": None,
        },
    )
    graph.extend([synthesizer_two, reviewer_two, handoff_five, handoff_six, review_one])
    attempts.update({("synthesizer", 2): synthesizer_two, ("reviewer", 2): reviewer_two})
    execution_slots = (
        ("planner", 1), ("analyst", 1), ("verifier", 1),
        ("synthesizer", 1), ("reviewer", 1),
        ("synthesizer", 2), ("reviewer", 2),
    )
    handoffs = sorted(
        (item for item in graph if item["kind"] == "HandoffRecord"),
        key=lambda item: item["spec"]["ordinal"],
    )
    result["spec"].update(
        {
            "finalReport": synthesis_output,
            "reviews": [binding(review_zero), binding(review_one)],
            "routeDecisions": [binding(routes[slot]) for slot in execution_slots],
            "roleAttempts": [binding(attempts[slot]) for slot in execution_slots],
            "handoffs": [binding(item) for item in handoffs],
            "usage": {
                "durationSeconds": 7,
                "attempts": 7,
                "modelRequests": 7,
                "inputBytes": 70,
                "outputBytes": 70,
                "totalTokens": 35,
                "costMicrousd": 0,
            },
        }
    )
    if final_verdict == "accepted":
        result["spec"]["status"] = "succeeded"
        result["spec"]["reasonCode"] = "accepted"
    else:
        result["spec"]["status"] = "exhausted"
        result["spec"]["reasonCode"] = "no-progress" if same_report else "revision-exhausted"
        event["spec"]["eventType"] = "run-exhausted"
        event["spec"]["reasonCode"] = result["spec"]["reasonCode"]
        seal(event)
        result["spec"]["terminalEvent"] = binding(event)
    seal(result)
    return graph


class M6OrchestrationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.records = positive_record_graph()
        self.by_kind = {record["kind"]: record for record in self.records}

    def test_exact_additive_registry_and_profile(self) -> None:
        self.assertEqual(ORCHESTRATION_CONTRACT_PROFILE, "orchestration-contracts-v1alpha1")
        self.assertEqual(
            tuple(ORCHESTRATION_SCHEMA_BY_KIND),
            (
                "RoleProfile", "TeamManifest", "LoopDefinition", "SourceBundle",
                "TeamRunRequest", "TeamRunPlan", "RouteDecision", "RoleAttemptResult",
                "HandoffRecord", "ClaimRecord", "EvidenceRecord", "VerificationRecord",
                "ReviewRecord", "TeamRunResult", "OrchestrationEvent",
            ),
        )
        self.assertRegex(orchestration_schema_bundle_digest(), r"^[a-f0-9]{64}$")

    def test_all_positive_records_and_graph_validate(self) -> None:
        for record_value in self.records:
            with self.subTest(kind=record_value["kind"], identifier=record_value["metadata"]["id"]):
                self.assertIs(validate_orchestration_record(record_value), record_value)
        self.assertIs(validate_orchestration_record_set(self.records), self.records)

    def test_one_revision_and_bounded_exhaustion_graphs_validate(self) -> None:
        accepted = revision_record_graph()
        self.assertEqual(orchestration_record_set_errors(accepted), [])
        for same_report in (False, True):
            with self.subTest(same_report=same_report):
                exhausted = revision_record_graph(
                    final_verdict="revision-required", same_report=same_report
                )
                self.assertEqual(orchestration_record_set_errors(exhausted), [])

    def test_complete_graph_rejects_additional_roots(self) -> None:
        for root_kind in ("TeamRunPlan", "SourceBundle", "TeamRunResult"):
            graph = copy.deepcopy(self.records)
            extra = copy.deepcopy(next(item for item in graph if item["kind"] == root_kind))
            extra["metadata"]["id"] = f"extra-{root_kind.lower()}"
            seal(extra)
            graph.append(extra)
            with self.subTest(kind=root_kind):
                self.assertTrue(orchestration_record_set_errors(graph))

    def test_attempt_route_handoff_and_usage_history_are_exact(self) -> None:
        graph = revision_record_graph()
        attempt = next(
            item for item in graph
            if item["kind"] == "RoleAttemptResult" and item["spec"]["attempt"] == 2
        )
        attempt["spec"]["routeDecision"] = binding(
            next(
                item for item in graph
                if item["kind"] == "RouteDecision"
                and item["spec"]["roleId"] == attempt["spec"]["roleId"]
                and item["spec"]["attempt"] == 1
            )
        )
        seal(attempt)
        result = next(item for item in graph if item["kind"] == "TeamRunResult")
        for index, reference in enumerate(result["spec"]["roleAttempts"]):
            if reference["id"] == attempt["metadata"]["id"]:
                result["spec"]["roleAttempts"][index] = binding(attempt)
        seal(result)
        self.assertTrue(orchestration_record_set_errors(graph))

    def test_failed_prefix_is_truthful_and_skipped_slot_is_rejected(self) -> None:
        graph = positive_record_graph()
        result = next(item for item in graph if item["kind"] == "TeamRunResult")
        event = next(item for item in graph if item["kind"] == "OrchestrationEvent")
        attempts = [item for item in graph if item["kind"] == "RoleAttemptResult"]
        verifier = next(item for item in attempts if item["spec"]["roleId"] == "verifier")
        verifier["spec"].update(
            {"status": "failed", "output": None, "errorCode": "adapter-failed"}
        )
        seal(verifier)
        kept_attempts = [
            item for item in attempts
            if item["spec"]["roleId"] in {"planner", "analyst", "verifier"}
        ]
        kept_attempts.sort(key=lambda item: ROLES.index(item["spec"]["roleId"]))
        kept_handoffs = sorted(
            (
                item for item in graph
                if item["kind"] == "HandoffRecord" and item["spec"]["ordinal"] <= 2
            ),
            key=lambda item: item["spec"]["ordinal"],
        )
        graph[:] = [
            item for item in graph
            if not (
                (item["kind"] == "RoleAttemptResult" and item not in kept_attempts)
                or (item["kind"] == "HandoffRecord" and item not in kept_handoffs)
                or item["kind"] in {"ReviewRecord", "VerificationRecord"}
            )
        ]
        route_by_slot = {
            (item["spec"]["roleId"], item["spec"]["attempt"]): item
            for item in graph if item["kind"] == "RouteDecision"
        }
        result["spec"].update(
            {
                "status": "failed",
                "reasonCode": "role-failed",
                "finalReport": None,
                "reviews": [],
                "verifications": [],
                "routeDecisions": [
                    binding(route_by_slot[(role, 1)])
                    for role in ("planner", "analyst", "verifier")
                ],
                "roleAttempts": [binding(item) for item in kept_attempts],
                "handoffs": [binding(item) for item in kept_handoffs],
                "usage": {
                    "durationSeconds": 3,
                    "attempts": 3,
                    "modelRequests": 3,
                    "inputBytes": 30,
                    "outputBytes": 30,
                    "totalTokens": 15,
                    "costMicrousd": 0,
                },
            }
        )
        event["spec"].update({"eventType": "run-failed", "reasonCode": "role-failed"})
        seal(event)
        result["spec"]["terminalEvent"] = binding(event)
        seal(result)
        self.assertEqual(orchestration_record_set_errors(graph), [])

        result["spec"]["routeDecisions"][1] = binding(route_by_slot[("verifier", 1)])
        seal(result)
        self.assertTrue(orchestration_record_set_errors(graph))

        graph = positive_record_graph()
        result = next(item for item in graph if item["kind"] == "TeamRunResult")
        result["spec"]["usage"]["totalTokens"] += 1
        seal(result)
        self.assertTrue(orchestration_record_set_errors(graph))

    def test_runtime_registry_digest_is_unchanged(self) -> None:
        self.assertEqual(
            schema_bundle_digest(),
            "d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d",
        )
        self.assertNotEqual(orchestration_schema_bundle_digest(), schema_bundle_digest())

    def test_record_digest_is_domain_separated_and_binds_mutation(self) -> None:
        source = copy.deepcopy(self.by_kind["SourceBundle"])
        self.assertEqual(orchestration_record_digest(source), source["metadata"]["recordDigest"])
        source["spec"]["totalByteLength"] = 3
        self.assertNotEqual(orchestration_record_digest(source), source["metadata"]["recordDigest"])
        self.assertTrue(orchestration_contract_errors(source))

    def test_closed_schemas_and_errors_do_not_echo_untrusted_values(self) -> None:
        value = copy.deepcopy(self.by_kind["TeamRunRequest"])
        value["secret"] = "ECO_TEST_SECRET_DO_NOT_ECHO"
        first = orchestration_contract_errors(value)
        second = orchestration_contract_errors(value)
        self.assertEqual(first, second)
        self.assertTrue(first)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(first))
        with self.assertRaises(ContractValidationError):
            validate_orchestration_record(value)

    def test_fixed_role_graph_cannot_be_reordered_or_rewired(self) -> None:
        team = copy.deepcopy(self.by_kind["TeamManifest"])
        team["spec"]["roles"][0], team["spec"]["roles"][1] = (
            team["spec"]["roles"][1], team["spec"]["roles"][0]
        )
        seal(team)
        self.assertTrue(orchestration_contract_errors(team))
        plan = copy.deepcopy(self.by_kind["TeamRunPlan"])
        plan["spec"]["steps"][2]["predecessors"] = ["planner"]
        seal(plan)
        self.assertTrue(orchestration_contract_errors(plan))

    def test_source_bundle_totals_question_and_provenance_are_exact(self) -> None:
        for mutation in ("total", "question", "git"):
            source = copy.deepcopy(self.by_kind["SourceBundle"])
            if mutation == "total":
                source["spec"]["totalByteLength"] += 1
            elif mutation == "question":
                source["spec"]["questionEntryId"] = "missing"
            else:
                source["spec"]["entries"][1]["provenance"]["kind"] = "git"
            seal(source)
            with self.subTest(mutation=mutation):
                self.assertTrue(orchestration_contract_errors(source))

    def test_evidence_provenance_must_match_the_referenced_source_entry(self) -> None:
        graph = positive_record_graph()
        evidence = next(item for item in graph if item["kind"] == "EvidenceRecord")
        evidence["spec"]["provenanceDigest"] = "b" * 64
        refresh_bindings_and_seals(graph)

        self.assertIn(
            "EvidenceRecord$.spec: failed validation",
            orchestration_record_set_errors(graph),
        )

    def test_verified_claim_requires_support_and_exactly_one_verification(self) -> None:
        for relation in ("context", "contradicts"):
            graph = positive_record_graph()
            evidence = next(item for item in graph if item["kind"] == "EvidenceRecord")
            evidence["spec"]["relation"] = relation
            refresh_bindings_and_seals(graph)
            with self.subTest(relation=relation):
                self.assertIn(
                    "VerificationRecord$.spec.status: failed validation",
                    orchestration_record_set_errors(graph),
                )

        graph = positive_record_graph()
        verification = next(
            item for item in graph if item["kind"] == "VerificationRecord"
        )
        conflicting = copy.deepcopy(verification)
        conflicting["metadata"]["id"] = "verification-conflicting"
        conflicting["spec"]["status"] = "contradicted"
        seal(conflicting)
        graph.append(conflicting)
        result = next(item for item in graph if item["kind"] == "TeamRunResult")
        result["spec"]["verifications"].append(binding(conflicting))
        refresh_bindings_and_seals(graph)
        self.assertIn(
            "VerificationRecord$.spec.claim: failed validation",
            orchestration_record_set_errors(graph),
        )

        graph = positive_record_graph()
        graph[:] = [item for item in graph if item["kind"] != "VerificationRecord"]
        for item in graph:
            if item["kind"] == "HandoffRecord":
                item["spec"]["verifications"] = []
            elif item["kind"] == "TeamRunResult":
                item["spec"]["verifications"] = []
        refresh_bindings_and_seals(graph)
        self.assertIn(
            "TeamRunResult$.spec.status: failed validation",
            orchestration_record_set_errors(graph),
        )

    def test_verification_and_review_rubrics_must_match_the_plan_gate(self) -> None:
        for kind in ("VerificationRecord", "ReviewRecord"):
            graph = positive_record_graph()
            item = next(record for record in graph if record["kind"] == kind)
            item["spec"]["rubricDigest"] = "b" * 64
            refresh_bindings_and_seals(graph)
            errors = orchestration_record_set_errors(graph)
            with self.subTest(kind=kind):
                expected = (
                    "VerificationRecord$.spec.evidence: failed validation"
                    if kind == "VerificationRecord"
                    else "ReviewRecord$.spec: failed validation"
                )
                self.assertIn(expected, errors)

    def test_terminal_event_binds_reason_plan_and_attempt_completion_time(self) -> None:
        mutations = ("reason", "subject", "time", "attempt-finish")
        for mutation in mutations:
            graph = positive_record_graph()
            event = next(item for item in graph if item["kind"] == "OrchestrationEvent")
            if mutation == "reason":
                event["spec"]["reasonCode"] = "recorded"
            elif mutation == "subject":
                source = next(item for item in graph if item["kind"] == "SourceBundle")
                event["spec"]["subject"] = binding(source)
            elif mutation == "time":
                event["spec"]["occurredAt"] = "2026-07-17T11:59:59Z"
            else:
                attempt = next(
                    item for item in graph if item["kind"] == "RoleAttemptResult"
                )
                attempt["spec"]["finishedAt"] = "2026-07-17T12:30:00Z"
            refresh_bindings_and_seals(graph)
            with self.subTest(mutation=mutation):
                self.assertIn(
                    "TeamRunResult$.spec.terminalEvent: failed validation",
                    orchestration_record_set_errors(graph),
                )

    def test_route_snapshot_and_plan_budget_fail_closed(self) -> None:
        route = copy.deepcopy(self.by_kind["RouteDecision"])
        route["spec"]["deployment"]["digest"] = "b" * 64
        seal(route)
        self.assertIn("routeDigest", " ".join(orchestration_contract_errors(route)))
        plan = copy.deepcopy(self.by_kind["TeamRunPlan"])
        plan["spec"]["steps"][0]["budget"]["maxModelRequests"] = 11
        seal(plan)
        self.assertTrue(orchestration_contract_errors(plan))

    def test_claim_is_an_immutable_proposal_and_cannot_self_verify(self) -> None:
        claim = copy.deepcopy(self.by_kind["ClaimRecord"])
        claim["spec"]["state"] = "verified"
        seal(claim)
        self.assertTrue(orchestration_contract_errors(claim))

        claim = copy.deepcopy(self.by_kind["ClaimRecord"])
        claim["spec"]["verifications"] = []
        seal(claim)
        self.assertTrue(orchestration_contract_errors(claim))

    def test_artifact_references_reject_ambiguous_segments(self) -> None:
        claim = copy.deepcopy(self.by_kind["ClaimRecord"])
        claim["spec"]["statement"]["ref"] = "artifact://private/../secret"
        seal(claim)
        self.assertTrue(orchestration_contract_errors(claim))

    def test_cross_record_digest_and_namespace_substitution_fail(self) -> None:
        tampered = copy.deepcopy(self.records)
        result = next(item for item in tampered if item["kind"] == "TeamRunResult")
        result["spec"]["plan"]["digest"] = "b" * 64
        seal(result)
        self.assertTrue(orchestration_record_set_errors(tampered))

        foreign = copy.deepcopy(self.records)
        evidence = next(item for item in foreign if item["kind"] == "EvidenceRecord")
        evidence["metadata"]["projectId"] = "foreign-project"
        seal(evidence)
        self.assertTrue(orchestration_record_set_errors(foreign))

    def test_unsupported_kind_and_non_mapping_are_sanitized(self) -> None:
        self.assertEqual(
            orchestration_contract_errors({"kind": "FutureKind", "value": "secret"}),
            ["record$.kind: is not a supported orchestration record kind"],
        )
        self.assertEqual(orchestration_contract_errors("secret"), ["record$: has the wrong type"])


if __name__ == "__main__":
    unittest.main()
