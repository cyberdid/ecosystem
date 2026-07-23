from __future__ import annotations

import copy
import hashlib
import hmac
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path

from eco_runtime.adapters import (
    OpenAICompatibleAdapter,
    PinnedOpenAICompatibleDeployment,
)
from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.contracts import API_VERSION, schema_bundle_digest
from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import RuntimePolicyError, RuntimeStoreError
from eco_runtime.model_orchestrator import GovernedModelOrchestrator
from eco_runtime.orchestrator import RuntimeCapabilities
from eco_runtime.store import SQLiteRuntimeStore
from tests.test_adapters import ADAPTER_VERSION, RecordingInvoker, deployment, response
from tests.test_policy import (
    DIGEST,
    NOW,
    artifact_registry,
    observation,
    policy_bundle,
    run_request,
    trusted_policy_engine,
)


KEY = b"m" * 32
CAPABILITIES = RuntimeCapabilities(object(), object(), object(), object())
PRODUCER_ISSUERS = {
    "runtime": "runtime-m6-test",
    "policy": "policy-m6-test",
    "broker": "broker-m6-test",
    "adapter": "adapter-m6-test",
}
INPUT = "review the exact governed input"


class GovernedModelExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "runtime.sqlite3"
        self.artifacts = ContentAddressedArtifactStore(
            self.root / "artifacts",
            proof_key=b"p" * 32,
            key_id="m6-artifact-key",
        )
        self.bundle, _ = policy_bundle()
        self.deployment = deployment(mode="local-loopback-http")
        self.bundle["deployments"]["deployments"] = [self.deployment]
        self.bundle["deployments"]["logicalRoles"]["code.read"]["candidates"] = [
            self.deployment["id"]
        ]
        observed = observation(self.deployment)
        observed["spec"]["adapterVersion"] = ADAPTER_VERSION
        self.observations = {self.deployment["id"]: observed}
        self.input_artifact = next(iter(artifact_registry().values()))
        encoded = INPUT.encode("utf-8")
        self.input_artifact["spec"].update(
            byteLength=len(encoded),
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
        self.artifact_map = {
            self.input_artifact["spec"]["storageRef"]: self.input_artifact
        }
        self.input_proof = self.artifacts.put(
            [encoded],
            storage_ref=self.input_artifact["spec"]["storageRef"],
            expected_sha256=self.input_artifact["spec"]["sha256"],
            expected_byte_length=self.input_artifact["spec"]["byteLength"],
        )
        self.engine = trusted_policy_engine(
            self.bundle,
            self.observations,
            self.artifact_map,
            trusted_suite_digests={DIGEST},
        )
        run = run_request()
        run["spec"]["deploymentPin"] = self.deployment["id"]
        run["spec"]["requestedTools"] = []
        run["spec"]["budget"].update(
            maxModelRequests=2,
            maxOutputBytes=4096,
            maxTotalTokens=10_000,
            maxCostMicrousd=0,
        )
        planned = self.engine.plan_run(
            run,
            run_id="run-1",
            plan_id="plan-1",
            decision_id="plan-decision-1",
            now=NOW,
        )
        self.plan = planned.plan
        self.plan_decision = planned.decision
        self.engine.activate_plan(self.plan, self.plan_decision, now=NOW)
        self.target = PinnedOpenAICompatibleDeployment(
            self.deployment,
            endpoint_url="http://127.0.0.1:8000/v1/chat/completions",
            transport_profile="local-loopback-http",
            resolved_at=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(minutes=10),
            maximum_timeout_ms=10_000,
        )
        self.endpoint = self.target.endpoint_binding()
        encoded = INPUT.encode("utf-8")
        self.request = {
            "apiVersion": API_VERSION,
            "kind": "ModelRequest",
            "metadata": {
                "id": "model-request-1",
                "runId": "run-1",
                "createdAt": "2026-07-15T12:00:00Z",
            },
            "spec": {
                "planDigest": semantic_digest(self.plan),
                "deploymentId": self.target.deployment_id,
                "deploymentIdentityDigest": self.target.identity_digest,
                "endpointBindingDigest": self.target.endpoint_binding_digest,
                "input": {
                    "artifactRecordDigest": semantic_digest(self.input_artifact),
                    "contentDigest": hashlib.sha256(encoded).hexdigest(),
                    "byteLength": len(encoded),
                    "dataClass": "D1",
                    "trust": "P1",
                },
                "parameters": {
                    "maxOutputTokens": 100,
                    "maxOutputBytes": 4096,
                    "temperatureMillis": 0,
                },
                "timeoutMs": 5_000,
                "fallbackPolicy": "none",
            },
        }
        self.model_decision = self.engine.authorize_model(
            self.plan,
            self.request,
            self.endpoint,
            self.input_artifact,
            decision_id="model-decision-1",
            now=NOW,
        )
        self.assertEqual(self.model_decision["spec"]["effect"], "allow")

    def tearDown(self) -> None:
        self.artifacts.close()
        self.temp.cleanup()

    def store(self) -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(
            self.database,
            hmac_key=KEY,
            key_id="m6-store-key",
            policy_capability=CAPABILITIES.policy,
            broker_capability=CAPABILITIES.broker,
            runtime_capability=CAPABILITIES.runtime,
            adapter_capability=CAPABILITIES.adapter,
            producer_issuers=PRODUCER_ISSUERS,
            artifact_store=self.artifacts,
        )

    def activate_store(self, store: SQLiteRuntimeStore) -> None:
        store.issue_plan(
            self.plan,
            self.plan_decision,
            policy_capability=CAPABILITIES.policy,
        )
        store.activate_plan(
            self.plan,
            self.plan_decision,
            nonce="store-plan-activation-1",
            now=NOW,
            policy_capability=CAPABILITIES.policy,
        )
        store.start_adapter(
            "run-1", now=NOW, adapter_capability=CAPABILITIES.adapter
        )

    def orchestrator(
        self,
        store: SQLiteRuntimeStore,
        invoker: RecordingInvoker,
        *,
        completion_time=NOW,
        clock=None,
    ) -> GovernedModelOrchestrator:
        return GovernedModelOrchestrator(
            store,
            self.artifacts,
            self.engine,
            OpenAICompatibleAdapter(self.target, invoker),
            capabilities=CAPABILITIES,
            clock=clock or (lambda: completion_time),
        )

    def execute(
        self,
        orchestrator: GovernedModelOrchestrator,
        *,
        cost: int = 0,
        now=NOW,
    ):
        return orchestrator.execute(
            self.plan,
            self.request,
            self.endpoint,
            self.input_artifact,
            self.model_decision,
            INPUT,
            idempotency_key="exact-model-key-1",
            cost_reservation_microusd=cost,
            now=now,
        )

    def test_success_is_prepared_once_cas_bound_and_terminal_replay_has_zero_calls(self) -> None:
        invoker = RecordingInvoker()
        with self.store() as store:
            self.activate_store(store)
            first = self.execute(self.orchestrator(store, invoker))
            self.assertEqual(first.state, "succeeded")
            self.assertEqual(first.untrusted_output, "review complete")
            self.assertEqual(len(invoker.calls), 1)
            budget = store.budget_status("run-1")
            self.assertEqual(budget["model_requests"], 1)
            self.assertEqual(budget["output_bytes"], len(b"review complete"))
            self.assertEqual(budget["total_tokens"], len(INPUT.encode()) + 100)
            self.assertEqual(budget["cost_microusd"], 0)
            replay = self.execute(self.orchestrator(store, invoker))
            self.assertTrue(replay.replayed)
            self.assertIsNone(replay.untrusted_output)
            self.assertEqual(len(invoker.calls), 1)
            with self.assertRaises(RuntimeStoreError) as cost_conflict:
                self.execute(self.orchestrator(store, invoker), cost=1)
            self.assertEqual(
                cost_conflict.exception.code, "ECO_PRICING_AUTHORITY_REQUIRED"
            )
            self.assertEqual(len(invoker.calls), 1)
            store.verify()
        database = self.database.read_bytes()
        self.assertNotIn(INPUT.encode(), database)
        self.assertNotIn(b"review complete", database)
        self.assertNotIn(b"provider-request-private-1", database)

    def test_transport_failure_is_sanitized_and_charges_reserved_ceiling(self) -> None:
        marker = "PRIVATE_PROVIDER_BODY_MUST_NOT_REACH_DB"
        invoker = RecordingInvoker(failure=OSError(marker))
        with self.store() as store:
            self.activate_store(store)
            failed = self.execute(self.orchestrator(store, invoker))
            self.assertEqual(failed.state, "failed")
            self.assertIsNotNone(failed.error_record_digest)
            budget = store.budget_status("run-1")
            self.assertEqual(budget["model_requests"], 1)
            self.assertEqual(budget["total_tokens"], len(INPUT.encode()) + 100)
            self.assertEqual(budget["cost_microusd"], 0)
            store.verify()
        self.assertNotIn(marker.encode(), self.database.read_bytes())

    def test_untranslated_adapter_exception_is_sanitized_and_settled(self) -> None:
        marker = "PRIVATE_UNTRANSLATED_PROVIDER_EXCEPTION"

        class ExplodingAdapter:
            def invoke(self, request, input_text, *, now):
                raise ValueError(marker)

        with self.store() as store:
            self.activate_store(store)
            orchestrator = GovernedModelOrchestrator(
                store,
                self.artifacts,
                self.engine,
                ExplodingAdapter(),
                capabilities=CAPABILITIES,
                clock=lambda: NOW,
            )
            failed = self.execute(orchestrator)
            self.assertEqual(failed.state, "failed")
            self.assertEqual(
                store.budget_status("run-1")["total_tokens"],
                len(INPUT.encode()) + 100,
            )
            store.verify()
        self.assertNotIn(marker.encode(), self.database.read_bytes())

    def test_missing_input_object_fails_before_prepare_or_egress(self) -> None:
        missing_artifacts = ContentAddressedArtifactStore(
            self.root / "missing-artifacts",
            proof_key=b"q" * 32,
            key_id="m6-missing-artifact-key",
        )
        missing_database = self.root / "missing-runtime.sqlite3"
        invoker = RecordingInvoker()
        try:
            with SQLiteRuntimeStore(
                missing_database,
                hmac_key=KEY,
                key_id="m6-missing-store-key",
                policy_capability=CAPABILITIES.policy,
                broker_capability=CAPABILITIES.broker,
                runtime_capability=CAPABILITIES.runtime,
                adapter_capability=CAPABILITIES.adapter,
                producer_issuers=PRODUCER_ISSUERS,
                artifact_store=missing_artifacts,
            ) as store:
                self.activate_store(store)
                orchestrator = GovernedModelOrchestrator(
                    store,
                    missing_artifacts,
                    self.engine,
                    OpenAICompatibleAdapter(self.target, invoker),
                    capabilities=CAPABILITIES,
                    clock=lambda: NOW,
                )
                with self.assertRaises(RuntimeStoreError):
                    self.execute(orchestrator)
                self.assertEqual(invoker.calls, [])
                self.assertEqual(
                    store.budget_status("run-1")["model_requests"], 0
                )
                with self.assertRaises(RuntimeStoreError) as missing_operation:
                    store.model_operation_status("model-request-1")
                self.assertEqual(
                    missing_operation.exception.code,
                    "ECO_MODEL_OPERATION_UNKNOWN",
                )
        finally:
            missing_artifacts.close()

    def test_restart_after_started_is_ambiguous_and_never_calls_adapter(self) -> None:
        with self.store() as store:
            self.activate_store(store)
            input_proof = self.artifacts.put(
                [INPUT.encode()],
                storage_ref=self.input_artifact["spec"]["storageRef"],
                expected_sha256=self.input_artifact["spec"]["sha256"],
                expected_byte_length=self.input_artifact["spec"]["byteLength"],
            )
            store.prepare_model_invocation(
                self.plan,
                self.request,
                self.endpoint,
                self.input_artifact,
                self.model_decision,
                input_availability_proof=input_proof,
                idempotency_key="exact-model-key-1",
                cost_reservation_microusd=0,
                now=NOW,
                policy_capability=CAPABILITIES.policy,
                runtime_capability=CAPABILITIES.runtime,
                adapter_capability=CAPABILITIES.adapter,
            )
            store.start_model_invocation(
                "model-request-1",
                now=NOW,
                adapter_capability=CAPABILITIES.adapter,
            )
        invoker = RecordingInvoker()
        with self.store() as reopened:
            reopened.verify()
            with self.assertRaises(RuntimeStoreError) as not_abortable:
                reopened.abort_prepared_model_invocation(
                    self.request,
                    reason="cancelled",
                    now=NOW + timedelta(seconds=1),
                    runtime_capability=CAPABILITIES.runtime,
                )
            self.assertEqual(
                not_abortable.exception.code, "ECO_MODEL_INVOCATION_AMBIGUOUS"
            )
            with self.assertRaises(RuntimeStoreError) as caught:
                self.execute(self.orchestrator(reopened, invoker))
            self.assertEqual(caught.exception.code, "ECO_MODEL_INVOCATION_AMBIGUOUS")
            self.assertEqual(invoker.calls, [])
            pending = reopened.scan_started_model_invocations(
                runtime_capability=CAPABILITIES.runtime
            )
            self.assertEqual(len(pending), 1)
            resolved = reopened.resolve_ambiguous_model_invocation(
                "model-request-1",
                observed_started_at=pending[0]["startedAt"],
                now=NOW + timedelta(seconds=1),
                runtime_capability=CAPABILITIES.runtime,
                adapter_capability=CAPABILITIES.adapter,
            )
            self.assertEqual(resolved["state"], "ambiguous")
            repeated = reopened.resolve_ambiguous_model_invocation(
                "model-request-1",
                observed_started_at=pending[0]["startedAt"],
                now=NOW + timedelta(seconds=1),
                runtime_capability=CAPABILITIES.runtime,
                adapter_capability=CAPABILITIES.adapter,
            )
            self.assertTrue(repeated["replayed"])
            reopened.finish_run(
                "run-1",
                outcome="failed",
                now=NOW + timedelta(seconds=2),
                runtime_capability=CAPABILITIES.runtime,
            )
            checkpoint = reopened.create_terminal_checkpoint(
                "run-1",
                now=NOW + timedelta(seconds=3),
                runtime_capability=CAPABILITIES.runtime,
            )
            self.assertEqual(checkpoint["spec"]["state"], "FAILED")
            reopened.verify()

    def test_route_and_input_tamper_fail_before_prepare_or_egress(self) -> None:
        invoker = RecordingInvoker()
        with self.store() as store:
            self.activate_store(store)
            before_objects = sorted(
                path.relative_to(self.root / "artifacts").as_posix()
                for path in (self.root / "artifacts" / "objects").rglob("*")
                if path.is_file()
            )
            with self.assertRaises(RuntimeStoreError) as priced:
                self.execute(self.orchestrator(store, invoker), cost=1)
            self.assertEqual(
                priced.exception.code, "ECO_PRICING_AUTHORITY_REQUIRED"
            )
            forged = copy.deepcopy(self.request)
            forged["spec"]["endpointBindingDigest"] = "b" * 64
            with self.assertRaises((RuntimePolicyError, RuntimeStoreError)):
                self.orchestrator(store, invoker).execute(
                    self.plan,
                    forged,
                    self.endpoint,
                    self.input_artifact,
                    self.model_decision,
                    INPUT,
                    idempotency_key="forged-key",
                    cost_reservation_microusd=0,
                    now=NOW,
                )
            self.assertEqual(invoker.calls, [])
            self.assertEqual(store.budget_status("run-1")["model_requests"], 0)
            with self.assertRaises(RuntimeStoreError) as missing_operation:
                store.model_operation_status("model-request-1")
            self.assertEqual(
                missing_operation.exception.code, "ECO_MODEL_OPERATION_UNKNOWN"
            )
            after_objects = sorted(
                path.relative_to(self.root / "artifacts").as_posix()
                for path in (self.root / "artifacts" / "objects").rglob("*")
                if path.is_file()
            )
            self.assertEqual(after_objects, before_objects)

    def test_prepared_restart_requires_fresh_authority_and_deadline(self) -> None:
        with self.store() as store:
            self.activate_store(store)
            proof = self.artifacts.put(
                [INPUT.encode()],
                storage_ref=self.input_artifact["spec"]["storageRef"],
                expected_sha256=self.input_artifact["spec"]["sha256"],
                expected_byte_length=self.input_artifact["spec"]["byteLength"],
            )
            store.prepare_model_invocation(
                self.plan,
                self.request,
                self.endpoint,
                self.input_artifact,
                self.model_decision,
                input_availability_proof=proof,
                idempotency_key="exact-model-key-1",
                cost_reservation_microusd=0,
                now=NOW,
                policy_capability=CAPABILITIES.policy,
                runtime_capability=CAPABILITIES.runtime,
                adapter_capability=CAPABILITIES.adapter,
            )
        invoker = RecordingInvoker()
        expired = NOW + timedelta(seconds=61)
        with self.store() as reopened:
            with self.assertRaises(RuntimeStoreError) as caught:
                self.execute(
                    self.orchestrator(
                        reopened, invoker, completion_time=expired
                    ),
                    now=expired,
                )
            self.assertEqual(caught.exception.code, "ECO_DEADLINE_EXCEEDED")
            self.assertEqual(invoker.calls, [])
            self.assertEqual(
                reopened.model_operation_status("model-request-1")["state"],
                "prepared",
            )
            aborted = reopened.abort_prepared_model_invocation(
                self.request,
                reason="deadline-expired",
                now=expired,
                runtime_capability=CAPABILITIES.runtime,
            )
            self.assertEqual(aborted["state"], "failed")
            self.assertFalse(aborted["replayed"])
            replay = reopened.abort_prepared_model_invocation(
                self.request,
                reason="deadline-expired",
                now=expired,
                runtime_capability=CAPABILITIES.runtime,
            )
            self.assertTrue(replay["replayed"])
            forged_request = copy.deepcopy(self.request)
            forged_request["spec"]["timeoutMs"] -= 1
            with self.assertRaises(RuntimeStoreError) as forged_abort:
                reopened.abort_prepared_model_invocation(
                    forged_request,
                    reason="deadline-expired",
                    now=expired,
                    runtime_capability=CAPABILITIES.runtime,
                )
            self.assertEqual(
                forged_abort.exception.code, "ECO_MODEL_BINDING_INVALID"
            )
            self.assertEqual(reopened.budget_status("run-1")["total_tokens"], 0)
            reopened.finish_run(
                "run-1",
                outcome="failed",
                now=expired + timedelta(seconds=1),
                runtime_capability=CAPABILITIES.runtime,
            )
            reopened.verify()

    def test_post_transport_deadline_is_failed_not_committed_as_success(self) -> None:
        invoker = RecordingInvoker()
        completed = NOW + timedelta(seconds=61)
        clock_values = iter((NOW, completed))
        with self.store() as store:
            self.activate_store(store)
            result = self.execute(
                self.orchestrator(store, invoker, clock=lambda: next(clock_values))
            )
            self.assertEqual(result.state, "failed")
            self.assertEqual(len(invoker.calls), 1)
            budget = store.budget_status("run-1")
            self.assertEqual(budget["total_tokens"], len(INPUT.encode()) + 100)
            store.verify()
        self.assertNotIn(b"review complete", self.database.read_bytes())

    def test_endpoint_expiring_during_transport_fails_current_policy_gate(self) -> None:
        target = PinnedOpenAICompatibleDeployment(
            self.deployment,
            endpoint_url="http://127.0.0.1:8000/v1/chat/completions",
            transport_profile="local-loopback-http",
            resolved_at=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(seconds=1),
            maximum_timeout_ms=10_000,
        )
        endpoint = target.endpoint_binding()
        request = copy.deepcopy(self.request)
        request["metadata"]["id"] = "model-request-expiring"
        request["spec"]["endpointBindingDigest"] = target.endpoint_binding_digest
        decision = self.engine.authorize_model(
            self.plan,
            request,
            endpoint,
            self.input_artifact,
            decision_id="model-decision-expiring",
            now=NOW,
        )
        invoker = RecordingInvoker()
        completed = NOW + timedelta(seconds=2)
        clock_values = iter((NOW, completed))
        with self.store() as store:
            self.activate_store(store)
            orchestrator = GovernedModelOrchestrator(
                store,
                self.artifacts,
                self.engine,
                OpenAICompatibleAdapter(target, invoker),
                capabilities=CAPABILITIES,
                clock=lambda: next(clock_values),
            )
            result = orchestrator.execute(
                self.plan,
                request,
                endpoint,
                self.input_artifact,
                decision,
                INPUT,
                idempotency_key="expiring-model-key",
                cost_reservation_microusd=0,
                now=NOW,
            )
            self.assertEqual(result.state, "failed")
            self.assertEqual(len(invoker.calls), 1)
            store.verify()
        database = self.database.read_bytes()
        self.assertNotIn(b"review complete", database)
        self.assertIn(b"ECO_MODEL_FINALIZATION_DENIED", database)

    def test_stale_caller_time_cannot_cross_owned_clock_deadline(self) -> None:
        invoker = RecordingInvoker()
        owned_now = NOW + timedelta(seconds=61)
        with self.store() as store:
            self.activate_store(store)
            with self.assertRaises((RuntimePolicyError, RuntimeStoreError)) as caught:
                self.execute(
                    self.orchestrator(store, invoker, completion_time=owned_now),
                    now=NOW,
                )
            self.assertIn(
                caught.exception.code,
                {"ECO_DECISION_EXPIRED", "ECO_DEADLINE_EXCEEDED"},
            )
            self.assertEqual(invoker.calls, [])
            with self.assertRaises(RuntimeStoreError) as unknown:
                store.model_operation_status("model-request-1")
            self.assertEqual(unknown.exception.code, "ECO_MODEL_OPERATION_UNKNOWN")

    def test_two_workers_cannot_cross_started_fence_twice(self) -> None:
        invoker = RecordingInvoker()
        results: list[object] = []

        def run(orchestrator: GovernedModelOrchestrator) -> None:
            try:
                results.append(self.execute(orchestrator))
            except Exception as exc:  # test captures the typed losing race
                results.append(exc)

        with self.store() as store:
            self.activate_store(store)
            workers = [
                threading.Thread(
                    target=run, args=(self.orchestrator(store, invoker),)
                )
                for _ in range(2)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(len(invoker.calls), 1)
            self.assertEqual(
                store.model_operation_status("model-request-1")["state"], "succeeded"
            )
            self.assertTrue(
                any(getattr(item, "state", None) == "succeeded" for item in results)
            )
            store.verify()

    @unittest.skipUnless(os.name == "posix", "permission and migration profile is POSIX")
    def test_runtime_schema_digest_is_unchanged_and_v3_store_reopens_via_v4_migration(self) -> None:
        expected_digest = schema_bundle_digest()
        with self.store():
            pass
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        meta = connection.execute("SELECT * FROM store_meta").fetchone()
        old_payload = {
            "domain": "eco-store-meta-v1",
            "storeId": meta["store_id"],
            "schemaVersion": 3,
            "digestProfile": meta["digest_profile"],
            "contractProfile": meta["contract_profile"],
            "schemaBundleDigest": meta["schema_bundle_digest"],
            "policyEngineVersion": meta["policy_engine_version"],
            "auditKeyId": meta["audit_key_id"],
            "producerIssuersDigest": meta["producer_issuers_digest"],
            "createdAt": meta["created_at"],
        }
        old_hmac = hmac.new(
            KEY, canonical_json(old_payload).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        connection.executescript(
            """DROP TABLE model_budget_reservations;
               DROP TABLE model_operations;
               PRAGMA user_version = 3;"""
        )
        connection.execute(
            "UPDATE store_meta SET schema_version = 3, meta_hmac = ?", (old_hmac,)
        )
        connection.commit()
        connection.close()
        with self.store() as migrated:
            migrated.verify()
        connection = sqlite3.connect(self.database)
        self.assertEqual(meta["schema_bundle_digest"], expected_digest)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertIsNotNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='model_operations'"
            ).fetchone()
        )
        connection.close()
