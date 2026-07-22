from __future__ import annotations

import copy
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eco_runtime.digests import semantic_digest
from eco_runtime.team_runtime import _exact_runtime_subject_binding
from eco_routing.contracts import ROUTING_API_VERSION, seal_routing_record
from eco_teams.contracts import API_VERSION, seal_record, validate_record
from eco_teams.runtime import (
    TaskEffectResult,
    TeamCoordinator,
    TeamRuntimeError,
)

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
DIGEST = "d" * 64
OUTCOME = "e" * 64


def binding(kind: str, identifier: str, digest: str = DIGEST) -> dict:
    return {"kind": kind, "id": identifier, "digest": digest}


def worker(role: str) -> dict:
    return {
        "principal": binding("PrincipalIdentity", f"principal-{role}"),
        "membership": binding("MembershipBinding", f"membership-{role}"),
    }


def manifest(*, max_tokens: int = 100, max_cost: int = 100, model: bool = False) -> dict:
    action = "model.invoke" if model else "evaluation.run"
    resource_kind = "deployment" if model else "workflow"
    roles = []
    for identifier, delegates, data, tokens in (
        ("root", ["worker"], ["D0", "D1"], 10),
        ("worker", [], ["D0"], 8),
    ):
        identity = worker(identifier)
        roles.append(
            {
                "id": identifier,
                "principal": identity["principal"],
                "membership": identity["membership"],
                "actions": [action],
                "dataClasses": data,
                "toolIds": [],
                "zones": ["Z1" if model else "local"],
                "notAfter": "2026-07-17T13:00:00Z",
                "budget": {
                    "maxTokens": tokens,
                    "maxCostMicrousd": min(tokens, max_cost),
                    "maxDurationSeconds": 60,
                },
                "delegatesTo": delegates,
            }
        )
    return seal_record(
        {
            "apiVersion": API_VERSION,
            "kind": "AgentTeamManifest",
            "metadata": {
                "id": "manifest-1", "projectId": "project-1",
                "createdAt": "2026-07-17T11:00:00Z", "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": "bounded-agent-team-v1",
                "authority": {
                    "teamId": "team-1", "storeId": "store-1",
                    "authoritySnapshotDigest": "a" * 64,
                    "activeBundleDigest": "b" * 64,
                    "accessPolicyDigest": "c" * 64,
                },
                "roles": roles,
                "budget": {"maxTasks": 20, "maxTotalTokens": max_tokens, "maxCostMicrousd": max_cost},
                "deadline": "2026-07-17T13:00:00Z",
                "safety": {"signedAuthorityRequired": True, "permissionsGranted": False, "runtimeAuthorityCreated": False},
            },
        }
    )


def task(
    identifier: str,
    *,
    run_id: str = "run-1",
    role: str = "root",
    parent: str | None = None,
    dependencies: list[str] | None = None,
    tokens: int = 6,
    cost: int = 6,
    input_digest: str = DIGEST,
    model: bool = False,
    route_digest: str | None = None,
) -> dict:
    return seal_record(
        {
            "apiVersion": API_VERSION,
            "kind": "TeamTask",
            "metadata": {
                "id": identifier, "teamId": "team-1", "projectId": "project-1",
                "runId": run_id, "createdAt": "2026-07-17T11:30:00Z", "recordDigest": "0" * 64,
            },
            "spec": {
                "roleId": role, "parentTaskId": parent,
                "action": "model.invoke" if model else "evaluation.run",
                "dataClass": "D0", "toolId": None, "zone": "Z1" if model else "local", "environmentId": "development",
                "resource": binding("deployment" if model else "workflow", "resource-1"),
                "notAfter": "2026-07-17T12:30:00Z",
                "budget": {"maxTokens": tokens, "maxCostMicrousd": cost, "maxDurationSeconds": 30},
                "input": binding("ArtifactRecord", "input-1", input_digest),
                "dependencies": sorted(dependencies or []),
                "routeDecision": (
                    binding("ModelRouteDecision", "route-1", route_digest)
                    if route_digest is not None else None
                ),
                "safety": {"routerDecisionGrantsAuthority": False, "delegationExpandsAuthority": False},
            },
        }
    )


def routing_record(kind: str, identifier: str, spec: dict, *, created_at: str = "2026-07-17T12:00:00Z") -> dict:
    return seal_routing_record(
        {
            "apiVersion": ROUTING_API_VERSION,
            "kind": kind,
            "metadata": {"id": identifier, "createdAt": created_at},
            "spec": spec,
        }
    )


def valid_route_evidence(*, run_id: str = "run-1") -> tuple[dict, dict, dict]:
    request = routing_record(
        "ModelRouteRequest",
        "route-request-1",
        {
            "role": "eco-worker", "actionClass": "A0", "dataClass": "D0",
            "workloadClass": "review", "requiredCapabilities": ["model.text"],
            "requiredContextTokens": 32, "inputTokenCeiling": 100,
            "outputTokenCeiling": 100, "allowedZones": ["Z1"],
            "allowedRetentions": ["local-runtime-dependent"], "allowCloud": False,
            "maximumCostMicrousd": 6, "deadlineAt": "2026-07-17T12:30:00Z",
            "executionProfile": "standard", "policyDigest": "5" * 64,
            "contextDigest": "7" * 64,
        },
    )
    decision = routing_record(
        "ModelRouteDecision",
        "route-1",
        {
            "requestDigest": request["metadata"]["recordDigest"],
            "policyDigest": "5" * 64, "priceCatalogDigest": "6" * 64,
            "decision": "allowed", "reasonCode": "eligible", "routeAttempt": 1,
            "selected": {
                "deploymentId": "resource-1", "deploymentDigest": "8" * 64,
                "deploymentIdentityDigest": DIGEST, "observedEvidenceDigest": "9" * 64,
                "candidateDigest": "a" * 64, "reservedCostMicrousd": 3,
                "estimatedLatencyP95Millis": 10,
            },
            "validUntil": "2026-07-17T12:10:00Z", "fallbackFromDigest": None,
            "explainDigest": "b" * 64,
        },
    )
    subject = {
        "apiVersion": "runtime.ai.ecosystem/v1alpha1",
        "kind": "ModelRequest",
        "metadata": {"id": "model-request-1", "runId": run_id, "createdAt": "2026-07-17T12:00:00Z"},
        "spec": {
            "planDigest": "c" * 64, "deploymentId": "resource-1",
            "deploymentIdentityDigest": DIGEST, "endpointBindingDigest": "d" * 64,
            "input": {"artifactRecordDigest": DIGEST, "contentDigest": "e" * 64, "byteLength": 1, "dataClass": "D0", "trust": "P0"},
            "parameters": {"maxOutputTokens": 100, "maxOutputBytes": 1000, "temperatureMillis": 0},
            "timeoutMs": 1000, "fallbackPolicy": "none",
        },
    }
    return request, decision, subject


def route_execution_evidence(*, run_id: str = "run-1") -> dict:
    request, decision, subject = valid_route_evidence(run_id=run_id)
    return {"grant": True, "routeRequest": request, "routeDecision": decision, "runtimeSubject": subject}


class FakeAuthority:
    def __init__(self) -> None:
        self.code: str | None = None

    def _check(self) -> None:
        if self.code:
            raise TeamRuntimeError(self.code)

    def assert_manifest_current(self, manifest, *, now):
        self._check()

    def assert_claim_current(self, manifest, task, observed_worker, *, now):
        self._check()
        role = next(item for item in manifest["spec"]["roles"] if item["id"] == task["spec"]["roleId"])
        if observed_worker != {"principal": role["principal"], "membership": role["membership"]}:
            raise TeamRuntimeError("ECO_TEAM_WORKER_UNBOUND")
        return semantic_digest({"task": task["metadata"]["recordDigest"], "now": now.isoformat()})


class FakeExecution:
    def __init__(self) -> None:
        self.current = True

    def authorize(self, manifest, observed_task, observed_worker, evidence, *, now):
        if not isinstance(evidence, dict) or evidence.get("grant") is not True:
            raise TeamRuntimeError("ECO_TEAM_EXECUTION_DENIED")
        return {"effect": "allow", "taskDigest": observed_task["metadata"]["recordDigest"], "decision": "f" * 64}

    def assert_current(self, manifest, task, worker, evidence, authorization, *, now):
        if not self.current or dict(authorization) != dict(self.authorize(manifest, task, worker, evidence, now=now)):
            raise TeamRuntimeError("ECO_TEAM_EXECUTION_AUTHORITY_STALE")

    def execute_authorized(self, evidence, operation, *, now):
        if not isinstance(evidence, dict) or evidence.get("grant") is not True:
            raise TeamRuntimeError("ECO_TEAM_EXECUTION_DENIED")
        return operation()


class GeneralTeamRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        # Resolve the tempdir so the private-path guard sees the real location.
        # On macOS ``/var`` and ``/tmp`` are symlinks into ``/private``; a raw
        # ``TemporaryDirectory`` name therefore trips the runtime's legitimate
        # anti-symlink check. ``resolve()`` is a no-op on Linux CI.
        base = Path(self.temp.name).resolve()
        self.authority = FakeAuthority()
        self.execution = FakeExecution()
        self.clock_now = NOW
        self.repo = base / "repository"
        self.repo.mkdir()
        self.database = base / "teams.sqlite3"
        self.valid_route = route_execution_evidence()
        self.runtime = TeamCoordinator(
            self.database,
            authority_guard=self.authority,
            execution_authorizer=self.execution,
            hmac_key=b"t" * 32,
            key_id="teams-test-key",
            forbidden_root=self.repo,
            clock=lambda: self.clock_now,
            trusted_route_decision_digests=frozenset(
                {self.valid_route["routeDecision"]["metadata"]["recordDigest"]}
            ),
            trusted_route_policy_digests=frozenset({"5" * 64}),
            trusted_price_catalog_digests=frozenset({"6" * 64}),
        )

    def tearDown(self) -> None:
        self.runtime.close()
        self.temp.cleanup()

    def execute(self, claim, observed_worker, *, status="succeeded", tokens=1, cost=1):
        authorization = self.runtime.authorize_effect(claim, observed_worker, {"grant": True}, now=NOW)
        return self.runtime.execute_claimed(
            claim, authorization, observed_worker,
            lambda: TaskEffectResult(status, OUTCOME, tokens, cost), now=NOW,
        )

    def test_contract_rejects_expanding_delegation(self):
        record = manifest()
        record["spec"]["roles"][1]["actions"].append("repository.write")
        record = seal_record(record)
        with self.assertRaises(Exception):
            validate_record(record)

    def test_cross_project_team_and_run_are_rejected(self):
        for field, value in (("projectId", "project-2"), ("teamId", "team-2"), ("runId", "run-2")):
            candidate = task("task-1")
            candidate["metadata"][field] = value
            candidate = seal_record(candidate)
            with self.assertRaises(TeamRuntimeError):
                self.runtime.create_run(manifest(), "run-1", [candidate], now=NOW)

    def test_duplicate_concurrent_claim_has_one_winner(self):
        self.runtime.create_run(manifest(), "run-1", [task("task-1")], now=NOW)
        barrier = threading.Barrier(2)

        def attempt():
            barrier.wait()
            try:
                return self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW)
            except TeamRuntimeError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(not isinstance(item, str) for item in results), 1)
        self.assertIn("ECO_TEAM_TASK_NOT_CLAIMABLE", results)

    def test_expired_unstarted_lease_reclaims_but_started_becomes_ambiguous(self):
        self.runtime.create_run(manifest(), "run-1", [task("task-1")], now=NOW)
        first = self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW, lease_seconds=1)
        self.clock_now = NOW + timedelta(seconds=2)
        self.runtime.expire_leases("run-1", now=NOW + timedelta(seconds=2))
        second = self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW + timedelta(seconds=2), lease_seconds=1)
        auth = self.runtime.authorize_effect(second, worker("root"), {"grant": True}, now=NOW + timedelta(seconds=2))
        self.runtime.start_effect(second, auth, worker("root"), now=NOW + timedelta(seconds=2))
        self.clock_now = NOW + timedelta(seconds=4)
        self.assertEqual(self.runtime.expire_leases("run-1", now=NOW + timedelta(seconds=4)), 1)
        self.assertEqual(self.runtime.task_state("run-1", "task-1")["status"], "ambiguous")
        with self.assertRaises(TeamRuntimeError):
            self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW + timedelta(seconds=4))
        self.assertNotEqual(first.lease_token, second.lease_token)

    def test_aggregate_budget_reservation_prevents_race(self):
        self.runtime.create_run(
            manifest(max_tokens=10, max_cost=10), "run-1",
            [task("a", tokens=6, cost=6), task("b", tokens=6, cost=6)], now=NOW,
        )
        barrier = threading.Barrier(2)

        def reserve(identifier):
            barrier.wait()
            try:
                return self.runtime.claim_task("run-1", identifier, worker("root"), now=NOW)
            except TeamRuntimeError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, ("a", "b")))
        self.assertEqual(sum(not isinstance(item, str) for item in results), 1)
        self.assertIn("ECO_TEAM_AGGREGATE_BUDGET_EXCEEDED", results)

    def test_child_authority_cannot_expand(self):
        parent = task("parent", tokens=6)
        child = task("child", role="worker", parent="parent", tokens=7)
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.create_run(manifest(), "run-1", [parent, child], now=NOW)
        self.assertEqual(caught.exception.code, "ECO_TEAM_CHILD_AUTHORITY_EXPANSION")

    def test_typed_handoff_rejects_artifact_substitution(self):
        parent = task("parent")
        child = task("child", role="worker", parent="parent", dependencies=["parent"], input_digest="1" * 64)
        self.runtime.create_run(manifest(), "run-1", [parent, child], now=NOW)
        claim = self.runtime.claim_task("run-1", "parent", worker("root"), now=NOW)
        self.execute(claim, worker("root"))
        handoff = self.handoff("handoff-1", "2" * 64)
        with self.assertRaises(TeamRuntimeError):
            self.runtime.record_handoff(handoff)
        accepted = self.handoff("handoff-2", "1" * 64)
        self.runtime.record_handoff(accepted)
        self.runtime.claim_task("run-1", "child", worker("worker"), now=NOW)

    @staticmethod
    def handoff(identifier: str, artifact_digest: str) -> dict:
        return seal_record(
            {
                "apiVersion": API_VERSION, "kind": "TeamHandoff",
                "metadata": {"id": identifier, "teamId": "team-1", "projectId": "project-1", "runId": "run-1", "createdAt": "2026-07-17T12:00:00Z", "recordDigest": "0" * 64},
                "spec": {"fromTaskId": "parent", "fromRoleId": "root", "toTaskId": "child", "toRoleId": "worker", "artifact": binding("ArtifactRecord", "input-1", artifact_digest), "channel": "task-input"},
            }
        )

    def test_router_decision_alone_cannot_start_and_route_is_single_use(self):
        evidence = route_execution_evidence()
        route = evidence["routeDecision"]["metadata"]["recordDigest"]
        self.runtime.create_run(
            manifest(max_tokens=20, max_cost=20, model=True), "run-1",
            [task("a", model=True, route_digest=route), task("b", model=True, route_digest=route)], now=NOW,
        )
        first = self.runtime.claim_task("run-1", "a", worker("root"), now=NOW)
        with self.assertRaises(TeamRuntimeError):
            self.runtime.start_effect(first, object(), worker("root"), now=NOW)
        first_auth = self.runtime.authorize_effect(first, worker("root"), evidence, now=NOW)
        self.runtime.execute_claimed(
            first, first_auth, worker("root"),
            lambda: TaskEffectResult("succeeded", OUTCOME, 1, 1), now=NOW,
        )
        second = self.runtime.claim_task("run-1", "b", worker("root"), now=NOW)
        auth = self.runtime.authorize_effect(second, worker("root"), evidence, now=NOW)
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.start_effect(second, auth, worker("root"), now=NOW)
        self.assertEqual(caught.exception.code, "ECO_TEAM_ROUTE_ALREADY_CONSUMED")

    def test_stale_execution_authority_is_denied_before_effect(self):
        self.runtime.create_run(manifest(), "run-1", [task("task-1")], now=NOW)
        claim = self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW)
        auth = self.runtime.authorize_effect(claim, worker("root"), {"grant": True}, now=NOW)
        self.execution.current = False
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.start_effect(claim, auth, worker("root"), now=NOW)
        self.assertEqual(caught.exception.code, "ECO_TEAM_EXECUTION_AUTHORITY_STALE")
        self.assertEqual(self.runtime.task_state("run-1", "task-1")["status"], "leased")

    def test_route_rejects_forged_stale_denied_and_substituted_records(self):
        cases = []
        valid = route_execution_evidence()
        cases.append(("forged", copy.deepcopy(valid), "3" * 64))

        stale = copy.deepcopy(valid)
        stale["routeDecision"]["metadata"]["createdAt"] = "2026-07-17T11:00:00Z"
        stale["routeDecision"]["spec"]["validUntil"] = "2026-07-17T11:30:00Z"
        stale["routeDecision"] = seal_routing_record(stale["routeDecision"])
        cases.append(("stale", stale, stale["routeDecision"]["metadata"]["recordDigest"]))

        denied = copy.deepcopy(valid)
        denied["routeDecision"]["spec"].update(
            decision="denied", reasonCode="no-eligible-candidate", selected=None
        )
        denied["routeDecision"] = seal_routing_record(denied["routeDecision"])
        cases.append(("denied", denied, denied["routeDecision"]["metadata"]["recordDigest"]))

        substituted = copy.deepcopy(valid)
        substituted["routeDecision"]["spec"]["selected"]["deploymentIdentityDigest"] = "f" * 64
        substituted["routeDecision"] = seal_routing_record(substituted["routeDecision"])
        cases.append(("substituted", substituted, substituted["routeDecision"]["metadata"]["recordDigest"]))

        for index, (label, evidence, route_digest) in enumerate(cases):
            run_id = f"route-{index}"
            evidence["runtimeSubject"]["metadata"]["runId"] = run_id
            candidate = task("task", run_id=run_id, model=True, route_digest=route_digest)
            self.runtime.create_run(manifest(max_tokens=20, max_cost=20, model=True), run_id, [candidate], now=NOW)
            claim = self.runtime.claim_task(run_id, "task", worker("root"), now=NOW)
            with self.subTest(label=label), self.assertRaises(TeamRuntimeError):
                self.runtime.authorize_effect(claim, worker("root"), evidence, now=NOW)

    def test_stale_caller_time_cannot_revive_route_or_lease(self):
        evidence = route_execution_evidence()
        route = evidence["routeDecision"]["metadata"]["recordDigest"]
        self.runtime.create_run(
            manifest(max_tokens=20, max_cost=20, model=True), "run-1",
            [task("task", model=True, route_digest=route)], now=NOW,
        )
        claim = self.runtime.claim_task("run-1", "task", worker("root"), now=NOW, lease_seconds=60)
        self.clock_now = NOW + timedelta(minutes=20)
        with self.assertRaises(TeamRuntimeError):
            self.runtime.authorize_effect(claim, worker("root"), evidence, now=NOW)

        self.runtime.cancel_run("run-1", now=NOW)

    def test_stale_caller_time_cannot_revive_expired_lease(self):
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        claim = self.runtime.claim_task(
            "run-1", "task", worker("root"), now=NOW, lease_seconds=1
        )
        self.clock_now = NOW + timedelta(seconds=2)
        with self.assertRaises(TeamRuntimeError):
            self.runtime.authorize_effect(
                claim, worker("root"), {"grant": True}, now=NOW
            )

    def test_forward_caller_time_is_rejected_without_accounting_change(self):
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        before = self.runtime.task_state("run-1", "task")
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.claim_task(
                "run-1", "task", worker("root"), now=NOW + timedelta(seconds=1)
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_CLOCK_ASSERTION_AHEAD")
        self.assertEqual(before, self.runtime.task_state("run-1", "task"))

    def test_exception_after_effect_start_is_ambiguous_and_not_retried(self):
        self.runtime.create_run(manifest(), "run-1", [task("task-1", tokens=6, cost=6)], now=NOW)
        claim = self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW)
        auth = self.runtime.authorize_effect(claim, worker("root"), {"grant": True}, now=NOW)

        def uncertain():
            raise OSError("transport outcome is unknown")

        with self.assertRaises(OSError):
            self.runtime.execute_claimed(claim, auth, worker("root"), uncertain, now=NOW)
        state = self.runtime.task_state("run-1", "task-1")
        self.assertEqual(state["status"], "ambiguous")
        self.assertEqual((state["chargedTokens"], state["chargedCostMicrousd"]), (6, 6))
        with self.assertRaises(TeamRuntimeError):
            self.runtime.claim_task("run-1", "task-1", worker("root"), now=NOW)

    def test_stale_policy_identity_revocation_and_emergency_deny_fail_closed(self):
        for code in (
            "ECO_TEAM_AUTHORITY_STALE", "ECO_TEAM_WORKER_INACTIVE",
            "ECO_TEAM_IDENTITY_REVOKED", "ECO_TEAM_EMERGENCY_DENY",
        ):
            self.authority.code = None
            run_id = "run-" + code.lower().replace("eco_team_", "")
            self.runtime.create_run(manifest(), run_id, [task("task", run_id=run_id)], now=NOW)
            self.authority.code = code
            with self.assertRaises(TeamRuntimeError) as caught:
                self.runtime.claim_task(run_id, "task", worker("root"), now=NOW)
            self.assertEqual(caught.exception.code, code)

    def test_cancellation_propagates_and_result_is_truthful(self):
        self.runtime.create_run(manifest(), "run-1", [task("a"), task("b")], now=NOW)
        claim = self.runtime.claim_task("run-1", "a", worker("root"), now=NOW)
        auth = self.runtime.authorize_effect(claim, worker("root"), {"grant": True}, now=NOW)
        self.runtime.start_effect(claim, auth, worker("root"), now=NOW)
        self.runtime.cancel_run("run-1", now=NOW)
        self.assertTrue(self.runtime.cancellation_requested(claim))
        self.runtime.acknowledge_cancellation(claim, now=NOW)
        result = self.runtime.finalize_run("run-1", result_id="result-1", now=NOW)
        self.assertEqual(result["spec"]["status"], "cancelled")
        self.assertTrue(result["spec"]["cancellationRequested"])

    def test_partial_failure_and_exact_terminal_replay(self):
        self.runtime.create_run(manifest(), "run-1", [task("a"), task("b")], now=NOW)
        first = self.runtime.claim_task("run-1", "a", worker("root"), now=NOW)
        self.execute(first, worker("root"), status="succeeded")
        second = self.runtime.claim_task("run-1", "b", worker("root"), now=NOW)
        self.execute(second, worker("root"), status="failed")
        result = self.runtime.finalize_run("run-1", result_id="result-1", now=NOW)
        self.assertEqual(result["spec"]["status"], "partial-failure")
        self.clock_now = NOW + timedelta(seconds=1)
        self.assertEqual(result, self.runtime.finalize_run("run-1", result_id="result-1", now=NOW + timedelta(seconds=1)))

    def test_model_invoke_binds_request_subject_to_deployment_resource(self):
        subject = {
            "kind": "ModelRequest", "metadata": {"id": "model-1"},
            "spec": {"deploymentId": "deployment-1", "deploymentIdentityDigest": "4" * 64, "input": {"dataClass": "D1"}},
        }
        decision = {"spec": {"subject": {"kind": "ModelRequest", "id": "model-1", "digest": semantic_digest(subject)}}}
        request = {"action": "model.invoke", "resource": binding("deployment", "deployment-1", "4" * 64), "dataClass": "D1"}
        self.assertTrue(_exact_runtime_subject_binding(decision, subject, request))
        substituted = copy.deepcopy(request)
        substituted["resource"]["digest"] = semantic_digest(subject)
        self.assertFalse(_exact_runtime_subject_binding(decision, subject, substituted))

    def test_authenticated_state_detects_status_and_budget_tamper(self):
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        self.runtime.claim_task("run-1", "task", worker("root"), now=NOW)
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE tasks SET status='succeeded' WHERE run_id='run-1'")
        connection.commit()
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.verify()
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_AUTH_FAILED")
        connection.execute("UPDATE tasks SET status='leased' WHERE run_id='run-1'")
        connection.commit()
        self.runtime.verify()
        connection.execute("UPDATE tasks SET reserved_tokens=0 WHERE run_id='run-1'")
        connection.commit()
        connection.close()
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.verify()
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_AUTH_FAILED")

    def test_authenticated_state_detects_route_consumption_tamper(self):
        evidence = route_execution_evidence()
        route = evidence["routeDecision"]["metadata"]["recordDigest"]
        self.runtime.create_run(
            manifest(max_tokens=20, max_cost=20, model=True), "run-1",
            [task("task", model=True, route_digest=route)], now=NOW,
        )
        claim = self.runtime.claim_task("run-1", "task", worker("root"), now=NOW)
        authorization = self.runtime.authorize_effect(claim, worker("root"), evidence, now=NOW)
        self.runtime.start_effect(claim, authorization, worker("root"), now=NOW)
        connection = sqlite3.connect(self.database)
        connection.execute("DELETE FROM consumed_routes")
        connection.commit()
        connection.close()
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.verify()
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_AUTH_FAILED")

    def test_authenticated_state_detects_result_tamper(self):
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        claim = self.runtime.claim_task("run-1", "task", worker("root"), now=NOW)
        self.execute(claim, worker("root"))
        self.runtime.finalize_run("run-1", result_id="result", now=NOW)
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE runs SET result_document=? WHERE run_id='run-1'", (b"{}",))
        connection.commit()
        connection.close()
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.verify()
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_AUTH_FAILED")

    def test_authenticated_state_detects_lease_and_cancellation_tamper(self):
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        self.runtime.claim_task("run-1", "task", worker("root"), now=NOW)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE tasks SET lease_hash=?,cancellation_requested=1 WHERE run_id='run-1'",
            ("0" * 64,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(TeamRuntimeError) as caught:
            self.runtime.verify()
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_AUTH_FAILED")

    def test_store_path_inside_repository_is_denied_without_repo_write(self):
        before = sorted((path.relative_to(self.repo), path.stat().st_mode) for path in self.repo.rglob("*"))
        with self.assertRaises(TeamRuntimeError) as caught:
            TeamCoordinator(
                self.repo / "state" / "teams.sqlite3",
                authority_guard=self.authority, execution_authorizer=self.execution,
                hmac_key=b"x" * 32, key_id="denied", forbidden_root=self.repo,
                clock=lambda: NOW,
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_STORE_LOCATION_DENIED")
        after = sorted((path.relative_to(self.repo), path.stat().st_mode) for path in self.repo.rglob("*"))
        self.assertEqual(before, after)

    def test_external_coordinator_preserves_repository_identity(self):
        sentinel = self.repo / "sentinel.txt"
        sentinel.write_bytes(b"user-owned\n")

        def identity():
            return {
                path.relative_to(self.repo).as_posix(): (
                    hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode
                )
                for path in self.repo.rglob("*") if path.is_file()
            }

        before = identity()
        self.runtime.create_run(manifest(), "run-1", [task("task")], now=NOW)
        claim = self.runtime.claim_task("run-1", "task", worker("root"), now=NOW)
        self.execute(claim, worker("root"))
        self.runtime.finalize_run("run-1", result_id="result", now=NOW)
        self.assertEqual(before, identity())


if __name__ == "__main__":
    unittest.main()
