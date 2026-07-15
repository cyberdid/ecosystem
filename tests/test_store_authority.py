from __future__ import annotations

import copy
import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

from eco_runtime.contracts import schema_bundle_digest
from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.store import SAFE_BROKER_ERROR_MESSAGES, SQLiteRuntimeStore
from tests.test_policy import NOW
from tests.test_runtime_contracts import (
    artifact_record,
    error_record,
    policy_decision,
    repository_read_receipt,
    repository_snapshot,
    run_request,
    run_plan,
    tool_execution_intent,
    tool_execution_outcome,
    tool_request,
)


KEY = b"a" * 32
POLICY_CAPABILITY = object()
BROKER_CAPABILITY = object()
RUNTIME_CAPABILITY = object()
ADAPTER_CAPABILITY = object()
PRODUCER_ISSUERS = {
    "runtime": "runtime-issuer-1",
    "policy": "policy-issuer-1",
    "broker": "broker-issuer-1",
    "adapter": "adapter-issuer-1",
}


class AuthoritativeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runtime.db"
        self.artifacts = ContentAddressedArtifactStore(
            Path(self.temp.name) / "artifacts",
            proof_key=b"p" * 32,
            key_id="artifact-test-key",
        )

    def tearDown(self) -> None:
        self.artifacts.close()
        self.temp.cleanup()

    def store(self) -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(
            self.path,
            hmac_key=KEY,
            key_id="authority-test-key",
            policy_capability=POLICY_CAPABILITY,
            broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY,
            adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
            artifact_store=self.artifacts,
        )

    @staticmethod
    def plan_decision(plan: dict, *, decision_id: str = "plan-decision-1") -> dict:
        decision = policy_decision()
        decision["metadata"]["id"] = decision_id
        decision["spec"]["policySnapshot"]["schemaBundleDigest"] = schema_bundle_digest()
        decision["spec"]["subject"] = {
            "kind": "RunPlan",
            "id": plan["metadata"]["id"],
            "digest": semantic_digest(plan),
        }
        return decision

    def context(
        self,
        store: SQLiteRuntimeStore,
        *,
        max_tool_requests: int = 5,
        max_duration_seconds: int = 600,
    ) -> dict:
        snapshot = repository_snapshot()
        snapshot["spec"]["entries"][0]["contentDigest"] = hashlib.sha256(b"x" * 42).hexdigest()
        snapshot["spec"]["entries"].append(
            {
                "path": "SECOND.md",
                "contentDigest": hashlib.sha256(b"x" * 17).hexdigest(),
                "byteLength": 17,
                "dataClass": "D1",
                "trust": "P1",
                "classificationAuthority": "operator",
            }
        )
        plan = run_plan()
        plan["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
        plan["spec"]["budget"]["maxToolRequests"] = max_tool_requests
        plan["spec"]["budget"]["maxDurationSeconds"] = max_duration_seconds
        plan["spec"]["repositorySnapshot"] = {
            "id": snapshot["metadata"]["id"],
            "digest": semantic_digest(snapshot),
            "rootIdentityDigest": snapshot["spec"]["rootIdentityDigest"],
            "trust": snapshot["spec"]["trust"],
            "evidence": run_plan()["spec"]["repositorySnapshot"]["evidence"],
        }
        plan_allow = self.plan_decision(plan)
        store.issue_plan(plan, plan_allow, policy_capability=POLICY_CAPABILITY)
        store.activate_plan(
            plan, plan_allow, nonce="plan-activation-1", now=NOW,
            policy_capability=POLICY_CAPABILITY,
        )
        store.start_adapter(
            plan["metadata"]["runId"], now=NOW, adapter_capability=ADAPTER_CAPABILITY
        )
        return {"snapshot": snapshot, "plan": plan}

    @staticmethod
    def operation(
        store: SQLiteRuntimeStore, context: dict, *, suffix: str, path: str
    ) -> tuple[dict, dict, dict]:
        plan = context["plan"]
        snapshot = context["snapshot"]
        request = tool_request()
        request["metadata"]["id"] = f"tool-request-{suffix}"
        request["spec"]["planDigest"] = semantic_digest(plan)
        request["spec"]["arguments"]["path"] = path
        decision = policy_decision()
        decision["metadata"]["id"] = f"tool-decision-{suffix}"
        decision["spec"]["policySnapshot"]["schemaBundleDigest"] = schema_bundle_digest()
        decision["spec"]["subject"] = {
            "kind": "ToolRequest",
            "id": request["metadata"]["id"],
            "digest": semantic_digest(request),
        }
        entry = next(item for item in snapshot["spec"]["entries"] if item["path"] == path)
        intent = tool_execution_intent()
        intent["metadata"]["id"] = f"operation-{suffix}"
        intent["spec"] = {
            "idempotencyKeyDigest": semantic_digest({"operationKey": suffix}),
            "planDigest": semantic_digest(plan),
            "toolRequest": {"id": request["metadata"]["id"], "digest": semantic_digest(request)},
            "allowDecision": {
                "id": decision["metadata"]["id"],
                "digest": semantic_digest(decision),
            },
            "toolCatalogDigest": plan["spec"]["tools"][0]["catalogDigest"],
            "reservation": {"toolRequests": 1, "inputBytes": entry["byteLength"]},
            "repositoryEntry": {
                "snapshotDigest": semantic_digest(snapshot),
                "pathDigest": store.path_reference_digest(path),
                "contentDigest": entry["contentDigest"],
                "byteLength": entry["byteLength"],
                "dataClass": entry["dataClass"],
                "trust": entry["trust"],
            },
        }
        return request, decision, intent

    def success_records(self, context: dict, request: dict, intent: dict) -> tuple[dict, dict, dict, object]:
        operation_id = intent["metadata"]["id"]
        entry = intent["spec"]["repositoryEntry"]
        receipt = repository_read_receipt()
        receipt["metadata"].update({"id": f"receipt-{operation_id}", "operationId": operation_id})
        receipt["spec"] = {
            "intentDigest": semantic_digest(intent),
            "toolRequestDigest": semantic_digest(request),
            "repositorySnapshotDigest": semantic_digest(context["snapshot"]),
            "contentDigest": entry["contentDigest"],
            "byteLength": entry["byteLength"],
            "dataClass": entry["dataClass"],
            "trust": entry["trust"],
        }
        artifact = artifact_record()
        artifact["metadata"]["id"] = f"artifact-{operation_id}"
        artifact["spec"].update(
            {
                "role": "output",
                "byteLength": entry["byteLength"],
                "sha256": entry["contentDigest"],
                "dataClass": entry["dataClass"],
                "trust": entry["trust"],
                "producer": {"type": "tool", "id": "repository.read"},
                "storageRef": f"artifact://runs/run-1/artifact-{operation_id}",
            }
        )
        outcome = tool_execution_outcome()
        outcome["metadata"].update({"id": f"outcome-{operation_id}", "operationId": operation_id})
        outcome["spec"] = {
            "intentDigest": semantic_digest(intent),
            "status": "succeeded",
            "receiptDigest": semantic_digest(receipt),
            "artifactRecordDigest": semantic_digest(artifact),
        }
        proof = self.artifacts.put(
            b"x" * entry["byteLength"],
            storage_ref=artifact["spec"]["storageRef"],
            expected_sha256=entry["contentDigest"],
            expected_byte_length=entry["byteLength"],
        )
        return receipt, artifact, outcome, proof

    @staticmethod
    def failure_records(intent: dict) -> tuple[dict, dict]:
        operation_id = intent["metadata"]["id"]
        error = error_record()
        error["metadata"] = {
            "id": f"error-{operation_id}",
            "runId": "run-1",
            "requestId": intent["spec"]["toolRequest"]["id"],
            "createdAt": error["metadata"]["createdAt"],
        }
        error["spec"].update(
            {
                "code": "ECO_FILE_NOT_FOUND",
                "category": "broker",
                "stage": "tool",
                "safeMessage": SAFE_BROKER_ERROR_MESSAGES["ECO_FILE_NOT_FOUND"],
            }
        )
        outcome = tool_execution_outcome()
        outcome["metadata"].update({"id": f"outcome-{operation_id}", "operationId": operation_id})
        outcome["spec"] = {
            "intentDigest": semantic_digest(intent),
            "status": "failed",
            "errorRecordDigest": semantic_digest(error),
        }
        return error, outcome

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_plan_activation_is_durable_idempotent_and_deadline_is_absolute(self) -> None:
        with self.store() as store:
            context = self.context(store)
            decision = self.plan_decision(context["plan"])
            first = store.activate_plan(
                context["plan"], decision, nonce="plan-activation-1", now=NOW,
                policy_capability=POLICY_CAPABILITY,
            )
            self.assertEqual(first["input_bytes"], 42)
            self.assertEqual(first["deadline_at"], "2026-07-15T12:10:00Z")
        with self.store() as reopened:
            status = reopened.budget_status("run-1")
            self.assertEqual(status["input_bytes"], 42)
            self.assertEqual(status["deadline_at"], "2026-07-15T12:10:00Z")
            reopened.verify()

    def test_durable_activation_rejects_evidence_capped_decision_after_expiry(self) -> None:
        with self.store() as store:
            plan_record = run_plan()
            plan_record["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
            decision = self.plan_decision(plan_record, decision_id="evidence-capped-decision")
            decision["spec"]["constraints"]["expiresAt"] = "2026-07-15T12:00:01Z"
            store.issue_plan(plan_record, decision, policy_capability=POLICY_CAPABILITY)
            self.assert_code(
                "ECO_DECISION_EXPIRED",
                lambda: store.activate_plan(
                    plan_record,
                    decision,
                    nonce="expired-evidence-plan-activation",
                    now=NOW + timedelta(seconds=2),
                    policy_capability=POLICY_CAPABILITY,
                ),
            )

    def test_durable_prepare_rejects_tool_allow_after_evidence_expiry(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, decision, intent = self.operation(
                store, context, suffix="expired-evidence", path="README.md"
            )
            decision["spec"]["constraints"]["expiresAt"] = "2026-07-15T12:00:01Z"
            intent["spec"]["allowDecision"]["digest"] = semantic_digest(decision)
            self.assert_code(
                "ECO_DECISION_EXPIRED",
                lambda: store.prepare_repository_read(
                    context["plan"],
                    context["snapshot"],
                    request,
                    decision,
                    intent,
                    owner_id="worker-expired-evidence",
                    now=NOW + timedelta(seconds=2),
                    policy_capability=POLICY_CAPABILITY,
                    broker_capability=BROKER_CAPABILITY,
                    runtime_capability=RUNTIME_CAPABILITY,
                ),
            )

    def test_native_run_history_replays_from_new_to_success(self) -> None:
        with self.store() as store:
            request = run_request()
            request_digest = store.start_run(
                "run-1", request, runtime_capability=RUNTIME_CAPABILITY
            )
            store.validate_run("run-1", now=NOW, runtime_capability=RUNTIME_CAPABILITY)
            snapshot = repository_snapshot()
            plan = run_plan()
            plan["spec"]["requestDigest"] = request_digest
            plan["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
            plan["spec"]["repositorySnapshot"] = {
                "id": snapshot["metadata"]["id"],
                "digest": semantic_digest(snapshot),
                "rootIdentityDigest": snapshot["spec"]["rootIdentityDigest"],
                "trust": snapshot["spec"]["trust"],
                "evidence": run_plan()["spec"]["repositorySnapshot"]["evidence"],
            }
            decision = self.plan_decision(plan)
            store.issue_plan(
                plan,
                decision,
                policy_capability=POLICY_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            store.activate_plan(
                plan, decision, nonce="native-plan-activation", now=NOW,
                policy_capability=POLICY_CAPABILITY,
            )
            store.start_adapter("run-1", now=NOW, adapter_capability=ADAPTER_CAPABILITY)
            store.complete_adapter("run-1", now=NOW, adapter_capability=ADAPTER_CAPABILITY)
            store.finish_run(
                "run-1", outcome="succeeded", now=NOW,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            checkpoint = store.create_terminal_checkpoint(
                "run-1", now=NOW, runtime_capability=RUNTIME_CAPABILITY
            )
            self.assertEqual(checkpoint["spec"]["projection"]["state"], "SUCCEEDED")
            self.assertTrue(checkpoint["spec"]["historyComplete"])
            self.assertEqual(store.run_status("run-1")["state"], "SUCCEEDED")
            self.assertTrue(store.run_status("run-1")["history_complete"])
            self.assertEqual(
                [event["spec"]["type"] for event in store.event_history("run-1")],
                [
                    "run.received", "run.validated", "plan.created", "policy.allowed",
                    "adapter.started", "adapter.completed", "run.succeeded",
                ],
            )
            store.verify()

    def test_native_plan_denial_is_terminal_and_event_bound(self) -> None:
        with self.store() as store:
            request = run_request()
            request_digest = store.start_run(
                "run-1", request, runtime_capability=RUNTIME_CAPABILITY
            )
            store.validate_run("run-1", now=NOW, runtime_capability=RUNTIME_CAPABILITY)
            snapshot = repository_snapshot()
            plan = run_plan()
            plan["spec"]["requestDigest"] = request_digest
            plan["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
            plan["spec"]["repositorySnapshot"]["digest"] = semantic_digest(snapshot)
            decision = self.plan_decision(plan)
            decision["spec"]["effect"] = "deny"
            decision["spec"]["reasonCodes"] = ["ECO_TEST_DENIAL"]
            store.issue_plan(
                plan, decision, policy_capability=POLICY_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            denied = store.deny_plan(
                plan, decision, nonce="plan-denial-1", now=NOW,
                policy_capability=POLICY_CAPABILITY,
            )
            self.assertEqual(denied["state"], "DENIED")
            self.assertEqual(store.event_history("run-1")[-1]["spec"]["type"], "policy.denied")
            store.verify()

    def test_competing_active_plan_is_rejected(self) -> None:
        with self.store() as store:
            context = self.context(store)
            second = copy.deepcopy(context["plan"])
            second["metadata"]["id"] = "plan-2"
            second["spec"]["route"]["identity"]["modelRevision"] = "revision-2"
            decision = self.plan_decision(second, decision_id="plan-decision-2")
            store.issue_plan(second, decision, policy_capability=POLICY_CAPABILITY)
            self.assert_code(
                "ECO_PLAN_CONFLICT",
                lambda: store.activate_plan(
                    second, decision, nonce="plan-activation-2", now=NOW,
                    policy_capability=POLICY_CAPABILITY,
                ),
            )

    def test_prepare_is_durable_and_raw_path_is_not_persisted(self) -> None:
        marker = "ECO_PRIVATE_PATH_MARKER.md"
        with self.store() as store:
            snapshot = repository_snapshot()
            snapshot["spec"]["entries"][0]["path"] = marker
            plan = run_plan()
            plan["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
            plan["spec"]["repositorySnapshot"]["digest"] = semantic_digest(snapshot)
            decision = self.plan_decision(plan)
            store.issue_plan(plan, decision, policy_capability=POLICY_CAPABILITY)
            store.activate_plan(
                plan, decision, nonce="plan-activation-1", now=NOW,
                policy_capability=POLICY_CAPABILITY,
            )
            store.start_adapter(
                plan["metadata"]["runId"], now=NOW,
                adapter_capability=ADAPTER_CAPABILITY,
            )
            context = {"snapshot": snapshot, "plan": plan}
            request, allow, intent = self.operation(store, context, suffix="private", path=marker)
            prepared = store.prepare_repository_read(
                plan, snapshot, request, allow, intent, owner_id="worker-1", now=NOW,
                policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            self.assertEqual(prepared["state"], "prepared")
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                self.assertNotIn(marker.encode(), candidate.read_bytes())
        with self.store() as reopened:
            self.assertEqual(reopened.operation_status("operation-private")["state"], "prepared")

    def test_concurrent_prepare_cannot_exceed_tool_budget(self) -> None:
        first = self.store()
        context = self.context(first, max_tool_requests=1)
        second = self.store()
        operations = [
            self.operation(first, context, suffix="a", path="README.md"),
            self.operation(second, context, suffix="b", path="SECOND.md"),
        ]
        barrier = threading.Barrier(2)
        results: list[str] = []

        def prepare(store: SQLiteRuntimeStore, values: tuple[dict, dict, dict]) -> None:
            barrier.wait()
            try:
                store.prepare_repository_read(
                    context["plan"],
                    context["snapshot"],
                    *values,
                    owner_id="worker",
                    now=NOW,
                    policy_capability=POLICY_CAPABILITY,
                    broker_capability=BROKER_CAPABILITY,
                    runtime_capability=RUNTIME_CAPABILITY,
                )
                results.append("prepared")
            except RuntimeStoreError as exc:
                results.append(exc.code)

        threads = [
            threading.Thread(target=prepare, args=(first, operations[0])),
            threading.Thread(target=prepare, args=(second, operations[1])),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        first.close()
        second.close()
        self.assertEqual(sorted(results), ["ECO_BUDGET_EXHAUSTED", "prepared"])
        with self.store() as reopened:
            self.assertEqual(reopened.budget_status("run-1")["tool_requests"], 1)
            reopened.verify()

    def test_concurrent_verify_and_writer_never_observe_mixed_snapshot(self) -> None:
        writer = self.store()
        context = self.context(writer)
        verifier = self.store()
        request, allow, intent = self.operation(
            writer, context, suffix="verify-race", path="README.md"
        )
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def mutate() -> None:
            try:
                barrier.wait()
                writer.prepare_repository_read(
                    context["plan"], context["snapshot"], request, allow, intent,
                    owner_id="race-writer", now=NOW,
                    policy_capability=POLICY_CAPABILITY,
                    broker_capability=BROKER_CAPABILITY,
                    runtime_capability=RUNTIME_CAPABILITY,
                )
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=mutate)
        thread.start()
        barrier.wait()
        for _ in range(20):
            verifier.verify()
        thread.join()
        writer.close()
        verifier.close()
        self.assertEqual(errors, [])
        with self.store() as reopened:
            reopened.verify()

    def test_success_commits_reserved_bytes_exactly_once(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(store, context, suffix="success", path="README.md")
            prepared = store.prepare_repository_read(
                context["plan"], context["snapshot"], request, allow, intent,
                owner_id="worker", now=NOW, policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            receipt, artifact, outcome, proof = self.success_records(context, request, intent)
            first = store.complete_repository_read(
                intent["metadata"]["id"], lease_token=prepared["leaseToken"],
                receipt=receipt, artifact=artifact, outcome=outcome,
                availability_proof=proof, now=NOW,
                broker_capability=BROKER_CAPABILITY,
            )
            second = store.complete_repository_read(
                intent["metadata"]["id"], lease_token="already-cleared",
                receipt=receipt, artifact=artifact, outcome=outcome,
                availability_proof=proof, now=NOW,
                broker_capability=BROKER_CAPABILITY,
            )
            self.assertEqual(first["state"], "succeeded")
            self.assertEqual(second["outcome_digest"], first["outcome_digest"])
            budget = store.budget_status("run-1")
            self.assertEqual(budget["input_bytes"], 84)
            self.assertEqual(budget["reserved_input_bytes"], 0)

    def test_failure_releases_bytes_but_keeps_tool_spent(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(store, context, suffix="failure", path="README.md")
            prepared = store.prepare_repository_read(
                context["plan"], context["snapshot"], request, allow, intent,
                owner_id="worker", now=NOW, policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            error, outcome = self.failure_records(intent)
            result = store.fail_repository_read(
                intent["metadata"]["id"], lease_token=prepared["leaseToken"],
                error=error, outcome=outcome, now=NOW,
                broker_capability=BROKER_CAPABILITY,
            )
            self.assertEqual(result["state"], "failed")
            budget = store.budget_status("run-1")
            self.assertEqual(budget["tool_requests"], 1)
            self.assertEqual(budget["input_bytes"], 42)
            self.assertEqual(budget["reserved_input_bytes"], 0)

    def test_expired_no_retry_lease_fails_closed_without_second_io(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(store, context, suffix="lease", path="README.md")
            first = store.prepare_repository_read(
                context["plan"], context["snapshot"], request, allow, intent,
                owner_id="worker-a", now=NOW, lease_seconds=1,
                policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            later = NOW + timedelta(seconds=2)
            self.assert_code(
                "ECO_OPERATION_NO_RETRY",
                lambda: store.claim_operation(
                    intent["metadata"]["id"], owner_id="worker-b", now=later,
                    lease_seconds=30, broker_capability=BROKER_CAPABILITY,
                ),
            )
            self.assert_code(
                "ECO_OPERATION_FENCED",
                lambda: store.resolve_unrecoverable_operation(
                    intent["metadata"]["id"], observed_lease_epoch=0, now=later,
                    broker_capability=BROKER_CAPABILITY,
                ),
            )
            result = store.resolve_unrecoverable_operation(
                intent["metadata"]["id"], observed_lease_epoch=first["leaseEpoch"], now=later,
                broker_capability=BROKER_CAPABILITY,
            )
            self.assertEqual(result["state"], "failed")
            budget = store.budget_status("run-1")
            self.assertEqual(budget["tool_requests"], 1)
            self.assertEqual(budget["reserved_input_bytes"], 0)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX process crash semantics")
    def test_process_exit_after_prepare_recovers_without_replaying_io(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(
                store, context, suffix="crash", path="README.md"
            )
        child = os.fork()
        if child == 0:
            try:
                with self.store() as child_store:
                    child_store.prepare_repository_read(
                        context["plan"], context["snapshot"], request, allow, intent,
                        owner_id="crash-worker", now=NOW, lease_seconds=1,
                        policy_capability=POLICY_CAPABILITY,
                        broker_capability=BROKER_CAPABILITY,
                        runtime_capability=RUNTIME_CAPABILITY,
                    )
                os._exit(73)
            except BaseException:
                os._exit(74)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73)
        with self.store() as reopened:
            recoverable = reopened.scan_recoverable_operations(
                now=NOW + timedelta(seconds=2), broker_capability=BROKER_CAPABILITY
            )
            self.assertEqual(recoverable[0]["recoveryMode"], "no_retry")
            result = reopened.resolve_unrecoverable_operation(
                intent["metadata"]["id"],
                observed_lease_epoch=recoverable[0]["leaseEpoch"],
                now=NOW + timedelta(seconds=2),
                broker_capability=BROKER_CAPABILITY,
            )
            self.assertEqual(result["state"], "failed")
            reopened.verify()

    def test_budget_projection_tampering_is_detected(self) -> None:
        with self.store() as store:
            self.context(store)
        connection = sqlite3.connect(self.path)
        connection.execute("UPDATE budgets SET input_bytes = input_bytes + 1 WHERE run_id = 'run-1'")
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_event_projection_tampering_is_detected_on_reopen(self) -> None:
        with self.store() as store:
            self.context(store)
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER run_events_immutable_update")
        connection.execute(
            "UPDATE run_events SET producer_issuer = 'forged-issuer' WHERE sequence = 1"
        )
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_event_baseline_tampering_is_detected_on_reopen(self) -> None:
        with self.store() as store:
            self.context(store)
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER run_event_baselines_immutable_update")
        connection.execute(
            "UPDATE run_event_baselines SET source = 'forged-source' WHERE run_id = 'run-1'"
        )
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_policy_capability_and_snapshot_provenance_are_required(self) -> None:
        with self.store() as store:
            snapshot = repository_snapshot()
            plan = run_plan()
            plan["spec"]["project"]["schemaBundleDigest"] = schema_bundle_digest()
            plan["spec"]["repositorySnapshot"]["digest"] = semantic_digest(snapshot)
            decision = self.plan_decision(plan)
            self.assert_code(
                "ECO_POLICY_ISSUER_UNTRUSTED",
                lambda: store.issue_plan(plan, decision, policy_capability=object()),
            )
            forged = copy.deepcopy(decision)
            forged["spec"]["policySnapshot"]["semanticConfigDigest"] = "b" * 64
            self.assert_code(
                "ECO_POLICY_PROVENANCE_MISMATCH",
                lambda: store.issue_plan(plan, forged, policy_capability=POLICY_CAPABILITY),
            )

    def test_lease_is_capped_by_deadline_and_late_success_is_rejected(self) -> None:
        with self.store() as store:
            context = self.context(store, max_duration_seconds=3)
            request, allow, intent = self.operation(
                store, context, suffix="deadline", path="README.md"
            )
            prepared = store.prepare_repository_read(
                context["plan"], context["snapshot"], request, allow, intent,
                owner_id="worker", now=NOW, lease_seconds=30,
                policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            self.assertEqual(prepared["leaseUntil"], "2026-07-15T12:00:03Z")
            receipt, artifact, outcome, proof = self.success_records(context, request, intent)
            self.assert_code(
                "ECO_DEADLINE_EXCEEDED",
                lambda: store.complete_repository_read(
                    intent["metadata"]["id"], lease_token=prepared["leaseToken"],
                    receipt=receipt, artifact=artifact, outcome=outcome,
                    availability_proof=proof,
                    now=NOW + timedelta(seconds=4),
                    broker_capability=BROKER_CAPABILITY,
                ),
            )
            recoverable = store.scan_recoverable_operations(
                now=NOW + timedelta(seconds=4), broker_capability=BROKER_CAPABILITY
            )
            self.assertEqual(recoverable[0]["reason"], "deadline_expired")
            aborted = store.abort_expired_operation(
                intent["metadata"]["id"], now=NOW + timedelta(seconds=4),
                broker_capability=BROKER_CAPABILITY,
            )
            self.assertEqual(aborted["state"], "failed")
            budget = store.budget_status("run-1")
            self.assertEqual(budget["tool_requests"], 1)
            self.assertEqual(budget["reserved_input_bytes"], 0)
            store.verify()

    def test_broker_capability_and_bounded_owner_are_required(self) -> None:
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(
                store, context, suffix="broker-cap", path="README.md"
            )
            self.assert_code(
                "ECO_BROKER_ISSUER_UNTRUSTED",
                lambda: store.prepare_repository_read(
                    context["plan"], context["snapshot"], request, allow, intent,
                    owner_id="worker", now=NOW,
                    policy_capability=POLICY_CAPABILITY, broker_capability=object(),
                    runtime_capability=RUNTIME_CAPABILITY,
                ),
            )
            with self.assertRaises(ValueError):
                store.prepare_repository_read(
                    context["plan"], context["snapshot"], request, allow, intent,
                    owner_id="secret/path/that/must/not/persist", now=NOW,
                    policy_capability=POLICY_CAPABILITY,
                    broker_capability=BROKER_CAPABILITY,
                    runtime_capability=RUNTIME_CAPABILITY,
                )

    def test_failure_rejects_untrusted_optional_fields_without_persisting_them(self) -> None:
        marker = "private-key-location-marker"
        with self.store() as store:
            context = self.context(store)
            request, allow, intent = self.operation(
                store, context, suffix="privacy", path="README.md"
            )
            prepared = store.prepare_repository_read(
                context["plan"], context["snapshot"], request, allow, intent,
                owner_id="worker", now=NOW, policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
            )
            error, outcome = self.failure_records(intent)
            error["spec"]["causeRef"] = f"internal://{marker}"
            outcome["spec"]["errorRecordDigest"] = semantic_digest(error)
            self.assert_code(
                "ECO_OPERATION_BINDING_INVALID",
                lambda: store.fail_repository_read(
                    intent["metadata"]["id"], lease_token=prepared["leaseToken"],
                    error=error, outcome=outcome, now=NOW,
                    broker_capability=BROKER_CAPABILITY,
                ),
            )
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                self.assertNotIn(marker.encode(), candidate.read_bytes())


if __name__ == "__main__":
    unittest.main()
