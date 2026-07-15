from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.broker import RepositoryReadBroker
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import BrokerError
from eco_runtime.orchestrator import (
    EmbeddedOrchestrator,
    RuntimeCapabilities,
)
from eco_runtime.policy import PolicyEngine
from eco_runtime.repository import repository_root_identity
from eco_runtime.store import SQLiteRuntimeStore
from tests.test_policy import (
    DIGEST,
    NOW,
    artifact_registry,
    plan,
    policy_bundle,
    trusted_policy_engine,
    repository_snapshot,
    tool_request_for,
)


KEY = b"o" * 32
POLICY_CAPABILITY = object()
BROKER_CAPABILITY = object()
RUNTIME_CAPABILITY = object()
ADAPTER_CAPABILITY = object()
CAPABILITIES = RuntimeCapabilities(
    policy=POLICY_CAPABILITY,
    broker=BROKER_CAPABILITY,
    runtime=RUNTIME_CAPABILITY,
    adapter=ADAPTER_CAPABILITY,
)
PRODUCER_ISSUERS = {
    "runtime": "runtime-issuer-1",
    "policy": "policy-issuer-1",
    "broker": "broker-issuer-1",
    "adapter": "adapter-issuer-1",
}


class FailingBroker:
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message

    def read(self, _path: str, *, maximum_bytes: int | None = None):
        raise BrokerError(self.code, self.message)


class EmbeddedOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "project"
        self.runtime_root = Path(self.temp.name) / "runtime"
        self.root.mkdir()
        self.runtime_root.mkdir(mode=0o700)
        self.artifact_root = Path(self.temp.name) / "artifacts"
        self.content = b"hello, orchestrator\n"
        (self.root / "README.md").write_bytes(self.content)
        self.snapshot = repository_snapshot(
            root_identity_digest=repository_root_identity(self.root),
            content_digest=hashlib.sha256(self.content).hexdigest(),
            byte_length=len(self.content),
        )
        bundle, observations = policy_bundle()
        self.policy = trusted_policy_engine(
            bundle,
            observations,
            artifact_registry(),
            repository_snapshot_record=self.snapshot,
            trusted_suite_digests={DIGEST},
        )
        planning = plan(self.policy)
        self.plan = planning.plan
        self.plan_decision = planning.decision
        self.artifacts = ContentAddressedArtifactStore(
            self.artifact_root,
            proof_key=b"artifact-proof-key-for-orchestrator!",
            key_id="orchestrator-artifact-key",
            forbidden_root=self.root,
        )
        self.store = SQLiteRuntimeStore(
            self.runtime_root / "runtime.db",
            hmac_key=KEY,
            key_id="orchestrator-test-key",
            policy_capability=POLICY_CAPABILITY,
            broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY,
            adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
            forbidden_root=self.root,
            artifact_store=self.artifacts,
        )
        self.broker = RepositoryReadBroker(self.root, self.snapshot)
        self.orchestrator = EmbeddedOrchestrator(
            self.store,
            self.broker,
            self.artifacts,
            self.policy,
            capabilities=CAPABILITIES,
            owner_id="worker-1",
        )
        self.orchestrator.activate_plan(
            self.plan,
            self.plan_decision,
            nonce="plan-activation-1",
            now=NOW,
        )
        self.execute_at = NOW + timedelta(seconds=2)

    def tearDown(self) -> None:
        self.broker.close()
        self.artifacts.close()
        self.store.close()
        self.temp.cleanup()

    def authorized_request(self, *, decision_id: str = "tool-decision-1") -> tuple[dict, dict]:
        request = tool_request_for(self.plan)
        decision = self.policy.authorize_tool(
            self.plan,
            request,
            decision_id=decision_id,
            now=self.execute_at,
            require_in_memory_activation=False,
        )
        self.assertEqual(decision["spec"]["effect"], "allow")
        return request, decision

    def test_success_is_durable_bound_and_budgeted_once(self) -> None:
        request, decision = self.authorized_request()
        result = self.orchestrator.execute_repository_read(
            self.plan,
            self.snapshot,
            request,
            decision,
            idempotency_key_digest=semantic_digest({"key": "read-1"}),
            now=self.execute_at,
        )

        self.assertEqual(result.state, "succeeded")
        self.assertEqual(result.untrusted_content, self.content.decode())
        self.assertEqual(result.content_digest, hashlib.sha256(self.content).hexdigest())
        self.assertFalse(result.replayed)
        object_digest = hashlib.sha256(self.content).hexdigest()
        object_path = (
            self.artifact_root
            / "objects"
            / object_digest[:2]
            / object_digest[2:4]
            / object_digest
        )
        self.assertTrue(object_path.is_file())
        operation = self.store.operation_status(result.operation_id)
        self.assertEqual(operation["outcome_digest"], result.outcome_digest)
        budget = self.store.budget_status("run-1")
        self.assertEqual(budget["tool_requests"], 1)
        self.assertEqual(budget["reserved_input_bytes"], 0)
        self.assertEqual(budget["input_bytes"], 32 + len(self.content))
        event_types = [event["spec"]["type"] for event in self.store.event_history("run-1")]
        self.assertEqual(
            event_types,
            [
                "policy.allowed",
                "adapter.started",
                "tool.requested",
                "tool.allowed",
                "tool.completed",
                "artifact.recorded",
            ],
        )
        self.store.verify()

    def test_same_key_replays_terminal_metadata_without_content_or_reaccounting(self) -> None:
        request, decision = self.authorized_request()
        key = semantic_digest({"key": "stable-read"})
        first = self.orchestrator.execute_repository_read(
            self.plan, self.snapshot, request, decision,
            idempotency_key_digest=key, now=self.execute_at,
        )
        before = self.store.budget_status("run-1")
        replay = self.orchestrator.execute_repository_read(
            self.plan, self.snapshot, request, decision,
            idempotency_key_digest=key, now=self.execute_at,
        )

        self.assertEqual(replay.operation_id, first.operation_id)
        self.assertEqual(replay.outcome_digest, first.outcome_digest)
        self.assertTrue(replay.replayed)
        self.assertIsNone(replay.untrusted_content)
        self.assertEqual(self.store.budget_status("run-1"), before)
        self.assertEqual(len(self.store.event_history("run-1")), 6)

    def test_broker_failure_is_sanitized_and_releases_only_byte_reservation(self) -> None:
        marker = "ECO_PRIVATE_BROKER_MESSAGE_MUST_NOT_PERSIST"
        request, decision = self.authorized_request()
        failing = EmbeddedOrchestrator(
            self.store,
            FailingBroker("ECO_FILE_NOT_FOUND", marker),
            self.artifacts,
            self.policy,
            capabilities=CAPABILITIES,
            owner_id="worker-2",
        )
        result = failing.execute_repository_read(
            self.plan,
            self.snapshot,
            request,
            decision,
            idempotency_key_digest=semantic_digest({"key": "missing-read"}),
            now=self.execute_at,
        )

        self.assertEqual(result.state, "failed")
        budget = self.store.budget_status("run-1")
        self.assertEqual(budget["tool_requests"], 1)
        self.assertEqual(budget["reserved_input_bytes"], 0)
        self.assertEqual(budget["input_bytes"], 32)
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.runtime_root / 'runtime.db'}{suffix}")
            if candidate.exists():
                self.assertNotIn(marker.encode(), candidate.read_bytes())
        self.store.verify()

if __name__ == "__main__":
    unittest.main()
