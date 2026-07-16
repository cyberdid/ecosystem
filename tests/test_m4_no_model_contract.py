from __future__ import annotations

import copy
import json
import unittest
from datetime import timedelta

from eco_cli.templates import starter_bundle
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimePolicyError, RuntimeStateError
from eco_runtime.evidence import EvidenceIssuerPolicy, HmacEvidenceSigner
from eco_runtime.policy import NO_MODEL_A1_PROFILE, PolicyEngine
from eco_runtime.state import RunEventChain, RunState
from tests.test_policy import DIGEST, NOW, TEST_EVIDENCE_KEY


def signed_snapshot() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RepositorySnapshot",
        "metadata": {
            "id": "m4-snapshot-1",
            "projectId": "sample",
            "createdAt": "2026-07-15T11:58:00Z",
            "issuer": {"type": "operator", "id": "operator-1"},
        },
        "spec": {
            "rootIdentityDigest": DIGEST,
            "trust": "P1",
            "entries": [
                {
                    "path": path,
                    "contentDigest": DIGEST,
                    "byteLength": 14,
                    "dataClass": "D0",
                    "trust": "P1",
                    "classificationAuthority": "policy",
                }
                for path in ("wiki/index.md", "wiki/architecture.md", "wiki/roadmap.md")
            ],
        },
    }


def no_model_engine(
    snapshot: dict | None = None,
    *,
    expires_at=None,
) -> PolicyEngine:
    bundle = starter_bundle("sample")
    record = snapshot or signed_snapshot()
    signer = HmacEvidenceSigner("operator-1", "m4-test-key", TEST_EVIDENCE_KEY)
    envelope = signer.sign(
        record,
        envelope_id="m4-snapshot-envelope-1",
        issued_at=NOW,
        expires_at=expires_at or NOW + timedelta(minutes=30),
    )
    return PolicyEngine(
        bundle,
        {},
        repository_snapshot=envelope,
        evidence_policies=(
            EvidenceIssuerPolicy(
                "operator-1",
                "m4-test-key",
                TEST_EVIDENCE_KEY,
                frozenset({"RepositorySnapshot"}),
                allowed_projects=frozenset({"sample"}),
            ),
        ),
        evidence_now=NOW,
        repository_root_identity_digest=DIGEST,
    )


def request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "NoModelRunRequest",
        "metadata": {
            "id": "m4-request-1",
            "createdAt": "2026-07-15T12:00:00Z",
            "actor": {"type": "human", "id": "operator-1"},
        },
        "spec": {"projectId": "sample", "workflow": "wiki-health-check"},
    }


def read_request(plan: dict, *, path: str = "wiki/index.md") -> dict:
    paths = ("wiki/index.md", "wiki/architecture.md", "wiki/roadmap.md")
    return {
        "apiVersion": API_VERSION,
        "kind": "NoModelReadRequest",
        "metadata": {
            "id": "m4-read-1",
            "runId": "m4-run-1",
            "createdAt": plan["metadata"]["createdAt"],
        },
        "spec": {
            "planDigest": semantic_digest(plan),
            "workflow": "wiki-health-check",
            "path": path,
            "scopeSlot": f"slot-{paths.index(path) + 1}" if path in paths else "slot-1",
        },
    }


class NoModelA1PolicyTests(unittest.TestCase):
    def plan(self, engine: PolicyEngine):
        return engine.plan_no_model_run(
            request(),
            run_id="m4-run-1",
            plan_id="m4-plan-1",
            decision_id="m4-plan-decision-1",
            now=NOW,
        )

    def test_exact_signed_snapshot_produces_route_free_zero_model_plan(self) -> None:
        result = self.plan(no_model_engine())
        self.assertEqual(result.decision["spec"]["effect"], "allow")
        self.assertIsNotNone(result.plan)
        plan = result.plan
        self.assertEqual(plan["spec"]["profile"], NO_MODEL_A1_PROFILE)
        self.assertEqual(plan["spec"]["effectivePolicy"]["modelRequests"], 0)
        self.assertEqual(plan["spec"]["effectivePolicy"]["workspaceWrites"], 0)
        self.assertNotIn("route", plan["spec"])
        self.assertNotIn("wiki/index.md", json.dumps(plan, sort_keys=True))
        self.assertEqual(plan["spec"]["workflow"]["entryCount"], 3)
        self.assertEqual(plan["spec"]["budget"]["maxDurationSeconds"], 30)
        self.assertEqual(plan["spec"]["budget"]["maxReadRequests"], 3)
        self.assertEqual(plan["spec"]["budget"]["maxModelRequests"], 0)
        self.assertEqual(plan["spec"]["budget"]["maxNetworkRequests"], 0)
        self.assertEqual(plan["spec"]["budget"]["maxWorkspaceWrites"], 0)

    def test_activation_consumes_exact_plan_decision_and_per_read_decision_is_bound(self) -> None:
        engine = no_model_engine()
        result = self.plan(engine)
        assert result.plan is not None
        engine.activate_no_model_plan(result.plan, result.decision, now=NOW)
        decision = engine.authorize_no_model_read(
            result.plan,
            read_request(result.plan),
            decision_id="m4-read-decision-1",
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(decision["spec"]["effect"], "allow")
        self.assertEqual(decision["spec"]["subject"]["kind"], "NoModelReadRequest")
        with self.assertRaises(RuntimePolicyError) as caught:
            engine.activate_no_model_plan(result.plan, result.decision, now=NOW)
        self.assertEqual(caught.exception.code, "ECO_DECISION_REPLAYED")

    def test_snapshot_scope_must_be_exact_d0_p1_policy_entries(self) -> None:
        snapshot = signed_snapshot()
        snapshot["spec"]["entries"][1]["dataClass"] = "D1"
        result = self.plan(no_model_engine(snapshot))
        self.assertIsNone(result.plan)
        self.assertEqual(result.decision["spec"]["reasonCodes"], ["ECO_WORKFLOW_SNAPSHOT_SCOPE_INVALID"])

        expanded = signed_snapshot()
        expanded["spec"]["entries"].append(
            {
                "path": "wiki/extra.md",
                "contentDigest": DIGEST,
                "byteLength": 14,
                "dataClass": "D0",
                "trust": "P1",
                "classificationAuthority": "policy",
            }
        )
        result = self.plan(no_model_engine(expanded))
        self.assertIsNone(result.plan)
        self.assertEqual(result.decision["spec"]["reasonCodes"], ["ECO_WORKFLOW_SNAPSHOT_SCOPE_INVALID"])

    def test_project_mismatch_is_a_typed_deny_without_a_plan(self) -> None:
        rejected = request()
        rejected["spec"]["projectId"] = "another-project"
        result = no_model_engine().plan_no_model_run(
            rejected,
            run_id="m4-run-1",
            plan_id="m4-plan-1",
            decision_id="m4-plan-decision-1",
            now=NOW,
        )
        self.assertIsNone(result.plan)
        self.assertEqual(result.decision["spec"]["reasonCodes"], ["ECO_PROJECT_MISMATCH"])

    def test_expired_snapshot_evidence_blocks_replanning(self) -> None:
        engine = no_model_engine(expires_at=NOW + timedelta(seconds=1))
        with self.assertRaises(RuntimePolicyError) as caught:
            engine.plan_no_model_run(
                request(),
                run_id="m4-run-1",
                plan_id="m4-plan-1",
                decision_id="m4-plan-decision-1",
                now=NOW + timedelta(seconds=2),
            )
        self.assertEqual(caught.exception.code, "ECO_EVIDENCE_EXPIRED")

    def test_forged_plan_and_config_drift_fail_closed(self) -> None:
        engine = no_model_engine()
        result = self.plan(engine)
        assert result.plan is not None
        forged = copy.deepcopy(result.plan)
        forged["spec"]["workflow"]["scopeDigest"] = "b" * 64
        with self.assertRaises(RuntimePolicyError) as caught:
            engine.activate_no_model_plan(forged, result.decision, now=NOW)
        self.assertEqual(caught.exception.code, "ECO_PLAN_UNTRUSTED")

        forged_budget = copy.deepcopy(result.plan)
        forged_budget["spec"]["budget"]["maxDurationSeconds"] = 31
        with self.assertRaises(ContractValidationError):
            engine.activate_no_model_plan(forged_budget, result.decision, now=NOW)

        engine.activate_no_model_plan(result.plan, result.decision, now=NOW)
        drifted = copy.deepcopy(result.plan)
        drifted["spec"]["project"]["semanticConfigDigest"] = "b" * 64
        with self.assertRaises(RuntimePolicyError) as caught:
            engine.authorize_no_model_read(
                drifted,
                read_request(drifted),
                decision_id="m4-drift-decision-1",
                now=NOW + timedelta(seconds=1),
            )
        self.assertEqual(caught.exception.code, "ECO_PLAN_UNTRUSTED")

    def test_read_cannot_escape_the_fixed_workflow_scope(self) -> None:
        engine = no_model_engine()
        result = self.plan(engine)
        assert result.plan is not None
        outside = read_request(result.plan, path="wiki/index.md")
        outside["spec"]["path"] = "wiki/private.md"
        with self.assertRaises(ContractValidationError):
            engine.authorize_no_model_read(
                result.plan,
                outside,
                decision_id="m4-outside-decision-1",
                now=NOW + timedelta(seconds=1),
            )

    def test_unissued_forged_plan_cannot_authorize_a_recovery_read(self) -> None:
        engine = no_model_engine()
        result = self.plan(engine)
        assert result.plan is not None
        forged = copy.deepcopy(result.plan)
        forged["metadata"]["id"] = "forged-plan"
        forged["metadata"]["runId"] = "forged-run"
        read = read_request(forged)
        read["metadata"]["runId"] = "forged-run"
        with self.assertRaises(RuntimePolicyError) as caught:
            engine.authorize_no_model_read(
                forged,
                read,
                decision_id="m4-forged-recovery-decision",
                now=NOW + timedelta(seconds=1),
            )
        self.assertEqual(caught.exception.code, "ECO_PLAN_UNTRUSTED")

    def test_read_time_and_scope_slot_are_bound_to_the_exact_plan(self) -> None:
        engine = no_model_engine()
        result = self.plan(engine)
        assert result.plan is not None
        engine.activate_no_model_plan(result.plan, result.decision, now=NOW)

        future = read_request(result.plan)
        future["metadata"]["createdAt"] = "2026-07-15T12:00:02Z"
        denied = engine.authorize_no_model_read(
            result.plan, future, decision_id="m4-read-time-deny", now=NOW + timedelta(seconds=1)
        )
        self.assertEqual(denied["spec"]["reasonCodes"], ["ECO_NO_MODEL_READ_TIME_INVALID"])

        wrong_slot = read_request(result.plan)
        wrong_slot["spec"]["scopeSlot"] = "slot-2"
        denied = engine.authorize_no_model_read(
            result.plan, wrong_slot, decision_id="m4-read-slot-deny", now=NOW + timedelta(seconds=1)
        )
        self.assertEqual(denied["spec"]["reasonCodes"], ["ECO_WORKFLOW_SNAPSHOT_SCOPE_INVALID"])


class NoModelA1StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.capabilities = {
            producer: (f"{producer}-issuer", object())
            for producer in ("runtime", "policy", "broker", "adapter")
        }
        self.chain = RunEventChain("m4-run-1", self.capabilities)

    def append(self, event_type: str, outcome: str, producer: str, **spec: object) -> RunState:
        event = {
            "apiVersion": API_VERSION,
            "kind": "RunEvent",
            "metadata": {
                "id": f"event-{len(self.chain.events()) + 1}",
                "runId": "m4-run-1",
                "sequence": len(self.chain.events()) + 1,
                "occurredAt": "2026-07-15T12:00:00Z",
                "producer": producer,
                "producerIssuer": self.capabilities[producer][0],
                "previousEventDigest": self.chain.head_digest,
            },
            "spec": {"type": event_type, "outcome": outcome, **spec},
        }
        return self.chain.append(event, self.capabilities[producer][1])

    @staticmethod
    def scope_entries() -> list[dict[str, str]]:
        return [
            {"slot": f"slot-{index}", "entryDigest": semantic_digest({"slot": index})}
            for index in range(1, 4)
        ]

    def authorize_and_start(self) -> None:
        self.append("run.received", "pending", "runtime")
        self.append("run.validated", "success", "runtime")
        self.append("plan.created", "success", "runtime")
        self.append(
            "no-model.policy.allowed", "success", "policy",
            subjectId="m4-plan-1", subjectDigest=DIGEST,
        )
        self.append(
            "no-model.workflow.started", "pending", "runtime",
            subjectDigest=DIGEST, scopeEntries=self.scope_entries(),
        )

    def test_no_model_lifecycle_cannot_start_adapter_and_requires_own_terminal_event(self) -> None:
        self.append("run.received", "pending", "runtime")
        self.append("run.validated", "success", "runtime")
        self.append("plan.created", "success", "runtime")
        self.append(
            "no-model.policy.allowed", "success", "policy",
            subjectId="m4-plan-1", subjectDigest=DIGEST,
        )
        with self.assertRaises(RuntimeStateError) as caught:
            self.append("adapter.started", "pending", "adapter")
        self.assertEqual(caught.exception.code, "ECO_NO_MODEL_LIFECYCLE")
        self.assertEqual(
            self.append(
                "no-model.workflow.started", "pending", "runtime",
                subjectDigest=DIGEST, scopeEntries=self.scope_entries(),
            ),
            RunState.RUNNING,
        )
        with self.assertRaises(RuntimeStateError) as caught:
            self.append("adapter.started", "pending", "adapter")
        self.assertEqual(caught.exception.code, "ECO_NO_MODEL_LIFECYCLE")
        for index in range(1, 4):
            subject_id = f"read-{index}"
            marker = self.scope_entries()[index - 1]
            request_digest = semantic_digest({"read": index})
            bindings = {
                "subjectId": subject_id,
                "subjectDigest": request_digest,
                "scopeSlot": marker["slot"],
                "entryDigest": marker["entryDigest"],
            }
            self.append("no-model.read.requested", "pending", "runtime", **bindings)
            self.append("no-model.read.allowed", "success", "policy", **bindings)
            self.append("no-model.read.started", "pending", "runtime", **bindings)
            self.append(
                "no-model.read.completed", "success", "broker",
                **bindings,
                resultDigest=DIGEST,
                contentDigest=semantic_digest({"content": index}),
                headingCheck="pass",
            )
        self.assertEqual(self.append("no-model.workflow.succeeded", "success", "runtime"), RunState.SUCCEEDED)

    def test_no_model_success_is_blocked_until_exact_three_completed_reads(self) -> None:
        self.authorize_and_start()
        with self.assertRaises(RuntimeStateError) as caught:
            self.append("no-model.workflow.succeeded", "success", "runtime")
        self.assertEqual(caught.exception.code, "ECO_RUN_SUCCESS_INVALID")
        with self.assertRaises(RuntimeStateError) as caught:
            self.append("run.succeeded", "success", "runtime")
        self.assertEqual(caught.exception.code, "ECO_NO_MODEL_LIFECYCLE")

    def test_no_model_scope_rejects_duplicate_slot_and_model_lifecycle_events(self) -> None:
        self.authorize_and_start()
        marker = self.scope_entries()[0]
        bindings = {
            "subjectId": "read-1", "subjectDigest": semantic_digest({"read": 1}),
            "scopeSlot": marker["slot"], "entryDigest": marker["entryDigest"],
        }
        self.append("no-model.read.requested", "pending", "runtime", **bindings)
        with self.assertRaises(RuntimeStateError):
            duplicate = {**bindings, "subjectId": "read-2", "subjectDigest": semantic_digest({"read": 2})}
            self.append("no-model.read.requested", "pending", "runtime", **duplicate)
        for event_type, outcome, producer in (
            ("artifact.recorded", "success", "runtime"),
            ("budget.exhausted", "exhausted", "runtime"),
            ("tool.requested", "pending", "runtime"),
        ):
            with self.assertRaises(RuntimeStateError) as caught:
                self.append(event_type, outcome, producer, subjectId="x", subjectDigest=DIGEST)
            self.assertEqual(caught.exception.code, "ECO_NO_MODEL_LIFECYCLE")


if __name__ == "__main__":
    unittest.main()
