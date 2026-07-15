from __future__ import annotations

import copy
import hashlib
import tempfile
import threading
import time
import unittest
from datetime import timedelta
from pathlib import Path

from eco_runtime.approval import ApprovalKeyPolicy, ApprovalSigner, ApprovalTrustStore
from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.change_store import SQLiteChangeAuthority
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.repository import repository_root_identity
from eco_runtime.store import SQLiteRuntimeStore
from eco_runtime.write_broker import LinuxWorkspaceWriteBroker
from eco_runtime.write_orchestrator import ControlledWriteOrchestrator
from tests.test_policy import (
    DIGEST,
    NOW,
    artifact_registry,
    policy_bundle,
    repository_snapshot,
    run_request,
    trusted_policy_engine,
)


class ControlledWriteOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspace"
        self.runtime = Path(self.temp.name) / "runtime"
        self.root.mkdir()
        self.runtime.mkdir(mode=0o700)
        self.old = b"original workspace text\n"
        (self.root / "README.md").write_bytes(self.old)
        self.snapshot = repository_snapshot(
            root_identity_digest=repository_root_identity(self.root),
            content_digest=hashlib.sha256(self.old).hexdigest(),
            byte_length=len(self.old),
        )
        bundle, observations = policy_bundle()
        bundle["deployments"]["logicalRoles"]["code.read"]["maximumActionClass"] = "A2"
        next(item for item in bundle["tools"]["tools"] if item["id"] == "repository.write")[
            "enabled"
        ] = True
        self.policy = trusted_policy_engine(
            bundle,
            observations,
            artifact_registry(),
            repository_snapshot_record=self.snapshot,
            trusted_suite_digests={DIGEST},
        )
        request = run_request()
        request["spec"]["task"]["type"] = "repository.change"
        request["spec"]["requestedTools"] = ["repository.write"]
        request["spec"]["constraints"] = {
            "maximumActionClass": "A2",
            "sandbox": "workspace-change",
            "agentNetwork": "deny",
            "toolNetwork": "deny",
        }
        planned = self.policy.plan_run(
            request,
            run_id="run-1",
            plan_id="write-plan-1",
            decision_id="write-plan-decision-1",
            now=NOW,
        )
        self.assertIsNotNone(planned.plan)
        self.plan = planned.plan
        self.plan_decision = planned.decision
        self.artifacts = ContentAddressedArtifactStore(
            self.runtime / "artifacts",
            proof_key=b"orchestrator-artifact-proof-key!",
            key_id="artifact-key-1",
            forbidden_root=self.root,
        )
        self.runtime_capabilities = tuple(object() for _ in range(4))
        self.runtime_store = SQLiteRuntimeStore(
            self.runtime / "runtime-authority" / "runtime.db",
            hmac_key=b"runtime-authority-audit-key-test!",
            key_id="runtime-audit-key-1",
            policy_capability=self.runtime_capabilities[0],
            broker_capability=self.runtime_capabilities[1],
            runtime_capability=self.runtime_capabilities[2],
            adapter_capability=self.runtime_capabilities[3],
            producer_issuers={
                "policy": "write-policy-issuer",
                "broker": "write-broker-issuer",
                "runtime": "write-runtime-issuer",
                "adapter": "write-adapter-issuer",
            },
            forbidden_root=self.root,
            artifact_store=self.artifacts,
        )
        self.runtime_store.issue_plan(
            self.plan,
            self.plan_decision,
            policy_capability=self.runtime_capabilities[0],
            runtime_capability=self.runtime_capabilities[2],
        )
        self.runtime_store.activate_plan(
            self.plan,
            self.plan_decision,
            nonce="write-plan-activation-1",
            now=NOW,
            policy_capability=self.runtime_capabilities[0],
        )
        self.runtime_store.start_adapter(
            "run-1", now=NOW, adapter_capability=self.runtime_capabilities[3]
        )
        self.approval_policy = ApprovalKeyPolicy(
            key_id="human-key-1",
            human_id="operator-1",
            assurance="local-os-session",
            verification_key=b"human-approval-key-for-m3-tests!",
        )
        self.trust = ApprovalTrustStore({self.approval_policy.key_id: self.approval_policy})
        self.signer = ApprovalSigner(self.approval_policy)
        self.authority_path = self.runtime / "authority" / "changes.db"
        self.authority = SQLiteChangeAuthority(
            self.authority_path,
            hmac_key=b"change-authority-audit-key-test!",
            key_id="change-audit-key-1",
            approval_trust_store=self.trust,
            forbidden_root=self.root,
            store_id="change-store-1",
        )
        self.broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts)
        self.orchestrator = self.make_orchestrator(self.broker)
        self.tool_time = NOW + timedelta(seconds=2)

    def tearDown(self) -> None:
        self.broker.close()
        self.authority.close()
        self.runtime_store.close()
        self.artifacts.close()
        self.temp.cleanup()

    def make_orchestrator(self, broker: LinuxWorkspaceWriteBroker) -> ControlledWriteOrchestrator:
        return ControlledWriteOrchestrator(
            self.authority,
            broker,
            self.artifacts,
            self.policy,
            self.trust,
            self.runtime_store,
            path_hmac_key=b"opaque-path-reference-key-m3-test!",
            owner_id="write-worker-1",
        )

    def candidate(self, content: bytes, identifier: str) -> tuple[dict, object, dict]:
        digest = hashlib.sha256(content).hexdigest()
        proof = self.artifacts.put(
            [content],
            storage_ref=f"artifact://runs/run-1/{identifier}",
            expected_sha256=digest,
            expected_byte_length=len(content),
            max_bytes=len(content),
        )
        artifact = {
            "apiVersion": API_VERSION,
            "kind": "ArtifactRecord",
            "metadata": {
                "id": identifier,
                "runId": "run-1",
                "createdAt": "2026-07-15T12:00:01Z",
            },
            "spec": {
                "role": "output",
                "mediaType": "text/plain",
                "byteLength": len(content),
                "sha256": digest,
                "dataClass": "D1",
                "trust": "P1",
                "producer": {"type": "model", "id": "fixture-model"},
                "parentRefs": [],
                "storageRef": proof.storage_ref,
                "retention": "run",
            },
        }
        descriptor = {
            "artifactRecordDigest": semantic_digest(artifact),
            "contentDigest": digest,
            "byteLength": len(content),
            "dataClass": "D1",
            "trust": "P1",
            "availabilityProofDigest": semantic_digest(proof.as_dict()),
            "fileType": "regular",
            "encoding": "UTF-8",
            "mode": 0o644,
        }
        return artifact, proof, descriptor

    def proposal(
        self,
        *,
        path: str = "README.md",
        operation: str = "replace",
        content: bytes = b"approved replacement text\n",
        suffix: str = "1",
        orchestrator: ControlledWriteOrchestrator | None = None,
    ):
        artifact, proof, descriptor = self.candidate(content, f"candidate-{suffix}")
        before = (
            {"state": "absent"}
            if operation == "create"
            else {
                "state": "present",
                "fileType": "regular",
                "encoding": "UTF-8",
                "contentDigest": hashlib.sha256(self.old).hexdigest(),
                "byteLength": len(self.old),
                "mode": 0o644,
            }
        )
        request = {
            "apiVersion": API_VERSION,
            "kind": "ToolRequest",
            "metadata": {
                "id": f"write-request-{suffix}",
                "runId": "run-1",
                "createdAt": "2026-07-15T12:00:02Z",
                "source": "model",
            },
            "spec": {
                "planDigest": semantic_digest(self.plan),
                "toolId": "repository.write",
                "arguments": {
                    "path": path,
                    "operation": operation,
                    "expectedBefore": before,
                    "candidateArtifact": descriptor,
                },
            },
        }
        decision = self.policy.authorize_tool(
            self.plan,
            request,
            decision_id=f"write-decision-{suffix}",
            now=self.tool_time,
            require_in_memory_activation=False,
        )
        self.assertEqual(decision["spec"]["effect"], "allow")
        target = orchestrator or self.orchestrator
        return target.create_proposal(
            self.plan,
            self.snapshot,
            request,
            decision,
            artifact,
            proof,
            display_digest=semantic_digest({"display": suffix, "path": path}),
            now=self.tool_time,
        ), content

    def envelope(self, proposal, suffix: str) -> dict:
        return self.signer.sign(
            approval_id=f"approval-{suffix}",
            subject_digest=proposal.authority_subject_digest,
            challenge_nonce=f"challenge-{suffix}",
            issued_at=self.tool_time,
            expires_at=self.tool_time + timedelta(minutes=4),
        )

    def test_replace_runs_exact_approval_prepare_apply_and_commit(self) -> None:
        proposal, content = self.proposal(suffix="commit")
        result = self.orchestrator.execute(
            proposal,
            self.envelope(proposal, "commit"),
            idempotency_key="replace-commit-1",
            now=self.tool_time + timedelta(seconds=1),
        )
        self.assertEqual(result.state, "committed")
        self.assertEqual((self.root / "README.md").read_bytes(), content)
        self.assertEqual(self.authority.operation_status(result.operation_id)["state"], "committed")
        self.authority.verify()
        database = b"".join(
            candidate.read_bytes()
            for candidate in (
                self.authority_path,
                Path(f"{self.authority_path}-wal"),
                Path(f"{self.authority_path}-shm"),
            )
            if candidate.exists()
        )
        self.assertNotIn(b"README.md", database)
        self.assertNotIn(content, database)

    def test_post_apply_rejection_restores_exact_before_state(self) -> None:
        proposal, _ = self.proposal(suffix="rollback")
        result = self.orchestrator.execute(
            proposal,
            self.envelope(proposal, "rollback"),
            idempotency_key="replace-rollback-1",
            now=self.tool_time + timedelta(seconds=1),
            post_apply_validator=lambda _receipt: False,
        )
        self.assertEqual(result.state, "rolled_back")
        self.assertEqual((self.root / "README.md").read_bytes(), self.old)
        self.assertEqual(result.rollback_receipt["spec"]["status"], "rolled-back")

    def test_create_and_idempotent_terminal_replay_have_one_effect(self) -> None:
        proposal, content = self.proposal(
            path="NEW.md", operation="create", suffix="create"
        )
        envelope = self.envelope(proposal, "create")
        first = self.orchestrator.execute(
            proposal,
            envelope,
            idempotency_key="create-once-1",
            now=self.tool_time + timedelta(seconds=1),
        )
        replay = self.orchestrator.execute(
            proposal,
            envelope,
            idempotency_key="create-once-1",
            now=self.tool_time + timedelta(seconds=2),
        )
        self.assertEqual(first.state, "committed")
        self.assertEqual(replay.state, "committed")
        self.assertTrue(replay.replayed)
        self.assertEqual(first.operation_id, replay.operation_id)
        self.assertEqual((self.root / "NEW.md").read_bytes(), content)

    def test_terminal_replay_remains_available_after_authority_expiry(self) -> None:
        proposal, content = self.proposal(
            path="REPLAY.md", operation="create", suffix="expired-replay"
        )
        envelope = self.envelope(proposal, "expired-replay")
        first = self.orchestrator.execute(
            proposal,
            envelope,
            idempotency_key="expired-replay-1",
            now=self.tool_time + timedelta(seconds=1),
        )
        replay = self.orchestrator.execute(
            proposal,
            envelope,
            idempotency_key="expired-replay-1",
            now=self.tool_time + timedelta(hours=2),
        )
        self.assertEqual(first.state, "committed")
        self.assertEqual(replay.state, "committed")
        self.assertTrue(replay.replayed)
        self.assertEqual((self.root / "REPLAY.md").read_bytes(), content)

        alternate = self.signer.sign(
            approval_id=envelope["approvalId"],
            subject_digest=proposal.authority_subject_digest,
            challenge_nonce="challenge-expired-replay-alternate",
            issued_at=self.tool_time,
            expires_at=self.tool_time + timedelta(minutes=4),
        )
        with self.assertRaisesRegex(RuntimeStoreError, "another exact authority"):
            self.orchestrator.execute(
                proposal,
                alternate,
                idempotency_key="expired-replay-1",
                now=self.tool_time + timedelta(hours=2),
            )

    def test_approval_tamper_and_candidate_mismatch_fail_before_mutation(self) -> None:
        proposal, _ = self.proposal(suffix="tamper")
        envelope = self.envelope(proposal, "tamper")
        envelope["subjectDigest"] = "f" * 64
        with self.assertRaises(RuntimeStoreError):
            self.orchestrator.execute(
                proposal,
                envelope,
                idempotency_key="tampered-approval-1",
                now=self.tool_time + timedelta(seconds=1),
            )
        self.assertEqual((self.root / "README.md").read_bytes(), self.old)

        proposal.approval_request["spec"]["expiresAt"] = "2026-07-15T12:30:00Z"
        extended = self.signer.sign(
            approval_id="approval-extended",
            subject_digest=proposal.authority_subject_digest,
            challenge_nonce="challenge-extended",
            issued_at=self.tool_time,
            expires_at=self.tool_time + timedelta(minutes=20),
        )
        with self.assertRaises(RuntimeStoreError):
            self.orchestrator.execute(
                proposal,
                extended,
                idempotency_key="extended-window-1",
                now=self.tool_time + timedelta(seconds=1),
            )
        proposal.approval_request["spec"]["expiresAt"] = proposal.proposal["spec"][
            "approvalExpiresAt"
        ]

        artifact, proof, descriptor = self.candidate(b"candidate mismatch\n", "candidate-mismatch")
        descriptor["contentDigest"] = "e" * 64
        request = copy.deepcopy(proposal.tool_request)
        request["metadata"]["id"] = "write-request-mismatch"
        request["spec"]["arguments"]["candidateArtifact"] = descriptor
        decision = self.policy.authorize_tool(
            self.plan,
            request,
            decision_id="write-decision-mismatch",
            now=self.tool_time,
            require_in_memory_activation=False,
        )
        with self.assertRaises(RuntimeStoreError):
            self.orchestrator.create_proposal(
                self.plan,
                self.snapshot,
                request,
                decision,
                artifact,
                proof,
                display_digest=semantic_digest("mismatch"),
                now=self.tool_time,
            )
        self.assertEqual((self.root / "README.md").read_bytes(), self.old)

    def test_crash_after_atomic_commit_is_explicit_recovery_required(self) -> None:
        def fault(phase: str) -> None:
            if phase == "after_atomic_commit":
                from eco_runtime.errors import BrokerError

                raise BrokerError("ECO_FAULT_INJECTED", "test fault")

        fault_broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts, fault_hook=fault)
        try:
            orchestrator = self.make_orchestrator(fault_broker)
            proposal, content = self.proposal(
                path="FAULT.md",
                operation="create",
                content=b"durably ambiguous write\n",
                suffix="fault",
                orchestrator=orchestrator,
            )
            result = orchestrator.execute(
                proposal,
                self.envelope(proposal, "fault"),
                idempotency_key="fault-after-rename-1",
                now=self.tool_time + timedelta(seconds=1),
            )
            self.assertEqual(result.state, "recovery_required")
            self.assertEqual((self.root / "FAULT.md").read_bytes(), content)
            self.assertEqual(
                self.authority.operation_status(result.operation_id)["state"],
                "recovery_required",
            )
        finally:
            fault_broker.close()

    def test_restart_recovery_rolls_back_exact_after_state(self) -> None:
        def fault(phase: str) -> None:
            if phase == "after_atomic_commit":
                from eco_runtime.errors import BrokerError

                raise BrokerError("ECO_FAULT_INJECTED", "test process loss")

        fault_broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts, fault_hook=fault)
        try:
            crashing = self.make_orchestrator(fault_broker)
            proposal, content = self.proposal(
                path="RECOVER.md",
                operation="create",
                content=b"must be compensated after restart\n",
                suffix="restart-recovery",
                orchestrator=crashing,
            )
            result = crashing.execute(
                proposal,
                self.envelope(proposal, "restart-recovery"),
                idempotency_key="restart-recovery-1",
                now=self.tool_time + timedelta(seconds=1),
            )
            self.assertEqual(result.state, "recovery_required")
            self.assertEqual((self.root / "RECOVER.md").read_bytes(), content)
        finally:
            fault_broker.close()

        self.broker.close()
        self.authority.close()
        self.artifacts.close()
        self.artifacts = ContentAddressedArtifactStore(
            self.runtime / "artifacts",
            proof_key=b"orchestrator-artifact-proof-key!",
            key_id="artifact-key-1",
            forbidden_root=self.root,
        )
        self.authority = SQLiteChangeAuthority(
            self.authority_path,
            hmac_key=b"change-authority-audit-key-test!",
            key_id="change-audit-key-1",
            approval_trust_store=self.trust,
            forbidden_root=self.root,
            store_id="change-store-1",
        )
        self.broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts)
        restarted = self.make_orchestrator(self.broker)

        wrong_root = Path(self.temp.name) / "wrong-recovery-root"
        wrong_root.mkdir()
        (wrong_root / "RECOVER.md").write_bytes(content)
        wrong_broker = LinuxWorkspaceWriteBroker(wrong_root, self.artifacts)
        try:
            wrong_recovery = self.make_orchestrator(wrong_broker)
            with self.assertRaisesRegex(RuntimeStoreError, "approved workspace root"):
                wrong_recovery.recover(
                    result.operation_id,
                    now=self.tool_time + timedelta(seconds=32),
                )
            self.assertEqual((wrong_root / "RECOVER.md").read_bytes(), content)
            self.assertEqual(
                self.authority.operation_status(result.operation_id)["state"],
                "recovery_required",
            )
        finally:
            wrong_broker.close()

        recovered = restarted.recover(
            result.operation_id,
            now=self.tool_time + timedelta(seconds=32),
        )
        self.assertEqual(recovered.state, "rolled_back")
        self.assertFalse((self.root / "RECOVER.md").exists())
        self.assertEqual(
            self.authority.operation_status(result.operation_id)["state"], "rolled_back"
        )
        self.authority.verify()

    def test_recovery_conflict_is_durable_and_never_overwritten(self) -> None:
        def fault(phase: str) -> None:
            if phase == "after_atomic_commit":
                from eco_runtime.errors import BrokerError

                raise BrokerError("ECO_FAULT_INJECTED", "test conflict")

        fault_broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts, fault_hook=fault)
        try:
            crashing = self.make_orchestrator(fault_broker)
            proposal, _ = self.proposal(
                path="CONFLICT.md",
                operation="create",
                content=b"approved after state\n",
                suffix="recovery-conflict",
                orchestrator=crashing,
            )
            result = crashing.execute(
                proposal,
                self.envelope(proposal, "recovery-conflict"),
                idempotency_key="recovery-conflict-1",
                now=self.tool_time + timedelta(seconds=1),
            )
        finally:
            fault_broker.close()
        (self.root / "CONFLICT.md").write_bytes(b"unrelated third-party state\n")
        recovered = self.orchestrator.recover(
            result.operation_id,
            now=self.tool_time + timedelta(seconds=32),
        )
        self.assertEqual(recovered.state, "recovery_required")
        self.assertEqual(
            (self.root / "CONFLICT.md").read_bytes(), b"unrelated third-party state\n"
        )
        status = self.authority.operation_status(result.operation_id)
        self.assertIsNotNone(status["recovery_reason_digest"])
        self.authority.verify()

    def test_approved_authority_subject_cannot_be_substituted_for_other_target(self) -> None:
        approved, _ = self.proposal(suffix="approved-binding")
        substituted, _ = self.proposal(
            path="EVIL.md",
            operation="create",
            content=b"unapproved target and bytes\n",
            suffix="substituted-binding",
        )
        substituted.proposal["metadata"]["id"] = approved.proposal["metadata"]["id"]
        substituted.approval_request["spec"]["proposal"] = {
            "id": substituted.proposal["metadata"]["id"],
            "digest": semantic_digest(substituted.proposal),
        }
        substituted.approval_request["spec"]["subject"] = {
            "kind": "WorkspaceChangeProposal",
            "id": substituted.proposal["metadata"]["id"],
            "digest": semantic_digest(substituted.proposal),
        }
        object.__setattr__(
            substituted, "authority_subject_digest", approved.authority_subject_digest
        )
        substituted.approval_request["spec"][
            "authoritySubjectDigest"
        ] = approved.authority_subject_digest
        envelope = self.signer.sign(
            approval_id="approval-substitution",
            subject_digest=approved.authority_subject_digest,
            challenge_nonce="challenge-substitution",
            issued_at=self.tool_time,
            expires_at=self.tool_time + timedelta(minutes=4),
        )
        with self.assertRaises(RuntimeStoreError):
            self.orchestrator.execute(
                substituted,
                envelope,
                idempotency_key="substitution-1",
                now=self.tool_time + timedelta(seconds=1),
            )
        self.assertFalse((self.root / "EVIL.md").exists())

    def test_plan_snapshot_and_broker_root_must_be_identical(self) -> None:
        proposal, _ = self.proposal(suffix="root-binding")
        foreign = copy.deepcopy(self.snapshot)
        foreign["spec"]["rootIdentityDigest"] = "f" * 64
        with self.assertRaises(RuntimeStoreError):
            self.orchestrator.create_proposal(
                self.plan,
                foreign,
                proposal.tool_request,
                proposal.policy_decision,
                proposal.candidate_artifact,
                proposal.candidate_proof,
                display_digest=proposal.proposal["spec"]["displayDigest"],
                now=self.tool_time,
            )

        other = Path(self.temp.name) / "other-workspace"
        other.mkdir()
        wrong_broker = LinuxWorkspaceWriteBroker(other, self.artifacts)
        try:
            wrong = self.make_orchestrator(wrong_broker)
            with self.assertRaises(RuntimeStoreError):
                wrong.create_proposal(
                    self.plan,
                    self.snapshot,
                    proposal.tool_request,
                    proposal.policy_decision,
                    proposal.candidate_artifact,
                    proposal.candidate_proof,
                    display_digest=proposal.proposal["spec"]["displayDigest"],
                    now=self.tool_time,
                )
        finally:
            wrong_broker.close()

    def test_dedicated_write_plan_prevents_split_tool_budget(self) -> None:
        proposal, _ = self.proposal(suffix="write-budget-scope")
        mixed = copy.deepcopy(self.plan)
        read_tool = copy.deepcopy(mixed["spec"]["tools"][0])
        read_tool["id"] = "repository.read"
        mixed["spec"]["tools"].append(read_tool)
        with self.assertRaisesRegex(RuntimeStoreError, "dedicated write-only plan"):
            self.orchestrator.create_proposal(
                mixed,
                self.snapshot,
                proposal.tool_request,
                proposal.policy_decision,
                proposal.candidate_artifact,
                proposal.candidate_proof,
                display_digest=proposal.proposal["spec"]["displayDigest"],
                now=self.tool_time,
            )

    def test_active_plan_and_lease_are_rechecked_after_candidate_fsync(self) -> None:
        def stop_run(phase: str) -> None:
            if phase == "after_candidate_fsync":
                self.runtime_store.finish_run(
                    "run-1",
                    outcome="failed",
                    now=self.tool_time + timedelta(seconds=1),
                    runtime_capability=self.runtime_capabilities[2],
                )

        stopped_broker = LinuxWorkspaceWriteBroker(
            self.root, self.artifacts, fault_hook=stop_run
        )
        try:
            stopped = self.make_orchestrator(stopped_broker)
            proposal, _ = self.proposal(
                path="STOPPED.md",
                operation="create",
                suffix="stopped-before-commit",
                orchestrator=stopped,
            )
            with self.assertRaisesRegex(RuntimeStoreError, "exact active running plan"):
                stopped.execute(
                    proposal,
                    self.envelope(proposal, "stopped-before-commit"),
                    idempotency_key="stopped-before-commit-1",
                    now=self.tool_time + timedelta(seconds=1),
                )
            self.assertFalse((self.root / "STOPPED.md").exists())
        finally:
            stopped_broker.close()

    def test_expired_lease_cannot_reach_atomic_commit(self) -> None:
        slow_broker = LinuxWorkspaceWriteBroker(
            self.root,
            self.artifacts,
            fault_hook=lambda phase: time.sleep(1.05)
            if phase == "after_candidate_fsync"
            else None,
        )
        try:
            slow = ControlledWriteOrchestrator(
                self.authority,
                slow_broker,
                self.artifacts,
                self.policy,
                self.trust,
                self.runtime_store,
                path_hmac_key=b"opaque-path-reference-key-m3-test!",
                owner_id="write-worker-1",
                lease_seconds=1,
            )
            proposal, _ = self.proposal(
                path="STALE.md",
                operation="create",
                suffix="stale-before-commit",
                orchestrator=slow,
            )
            with self.assertRaisesRegex(RuntimeStoreError, "lease expired"):
                slow.execute(
                    proposal,
                    self.envelope(proposal, "stale-before-commit"),
                    idempotency_key="stale-before-commit-1",
                    now=self.tool_time + timedelta(seconds=1),
                )
            self.assertFalse((self.root / "STALE.md").exists())
        finally:
            slow_broker.close()

    def test_durable_commit_permit_recovers_if_lease_expires_inside_rename(self) -> None:
        permit_broker = LinuxWorkspaceWriteBroker(self.root, self.artifacts)
        original_rename = permit_broker._renameat2  # noqa: SLF001 - commit-window fixture
        delayed = False

        def delayed_once(*args):
            nonlocal delayed
            if not delayed:
                delayed = True
                time.sleep(1.05)
            return original_rename(*args)

        permit_broker._renameat2 = delayed_once  # type: ignore[method-assign]  # noqa: SLF001
        try:
            permit = ControlledWriteOrchestrator(
                self.authority,
                permit_broker,
                self.artifacts,
                self.policy,
                self.trust,
                self.runtime_store,
                path_hmac_key=b"opaque-path-reference-key-m3-test!",
                owner_id="write-worker-1",
                lease_seconds=1,
            )
            proposal, content = self.proposal(
                path="PERMIT.md",
                operation="create",
                suffix="durable-commit-permit",
                orchestrator=permit,
            )
            operation_id = permit._operation_id(  # noqa: SLF001 - exact recovery fixture
                "run-1", "durable-commit-permit-1"
            )
            with self.assertRaisesRegex(RuntimeStoreError, "lease expired"):
                permit.execute(
                    proposal,
                    self.envelope(proposal, "durable-commit-permit"),
                    idempotency_key="durable-commit-permit-1",
                    now=self.tool_time + timedelta(seconds=1),
                )
            self.assertEqual((self.root / "PERMIT.md").read_bytes(), content)
            self.assertEqual(
                self.authority.operation_status(operation_id)["state"], "commit_ready"
            )
            recovered = permit.recover(
                operation_id,
                now=self.tool_time + timedelta(seconds=3),
            )
            self.assertEqual(recovered.state, "rolled_back")
            self.assertFalse((self.root / "PERMIT.md").exists())
        finally:
            permit_broker.close()

    def test_active_plan_guard_serializes_run_stop_and_commit_permit(self) -> None:
        proposal, content = self.proposal(
            path="SERIALIZED.md", operation="create", suffix="serialized-permit"
        )
        competing_store = SQLiteRuntimeStore(
            self.runtime / "runtime-authority" / "runtime.db",
            hmac_key=b"runtime-authority-audit-key-test!",
            key_id="runtime-audit-key-1",
            policy_capability=self.runtime_capabilities[0],
            broker_capability=self.runtime_capabilities[1],
            runtime_capability=self.runtime_capabilities[2],
            adapter_capability=self.runtime_capabilities[3],
            producer_issuers={
                "policy": "write-policy-issuer",
                "broker": "write-broker-issuer",
                "runtime": "write-runtime-issuer",
                "adapter": "write-adapter-issuer",
            },
            forbidden_root=self.root,
            artifact_store=self.artifacts,
        )
        original_mark = self.authority.mark_commit_ready
        stop_started = threading.Event()
        stop_finished = threading.Event()
        stop_errors: list[BaseException] = []
        stop_thread: threading.Thread | None = None

        def stop_run() -> None:
            stop_started.set()
            try:
                competing_store.finish_run(
                    "run-1",
                    outcome="failed",
                    now=self.tool_time + timedelta(seconds=1),
                    runtime_capability=self.runtime_capabilities[2],
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                stop_errors.append(exc)
            finally:
                stop_finished.set()

        def mark_with_competing_stop(operation_id: str, **lease):
            nonlocal stop_thread
            stop_thread = threading.Thread(target=stop_run)
            stop_thread.start()
            self.assertTrue(stop_started.wait(1))
            time.sleep(0.05)
            self.assertFalse(stop_finished.is_set())
            return original_mark(operation_id, **lease)

        self.authority.mark_commit_ready = mark_with_competing_stop  # type: ignore[method-assign]
        try:
            result = self.orchestrator.execute(
                proposal,
                self.envelope(proposal, "serialized-permit"),
                idempotency_key="serialized-permit-1",
                now=self.tool_time + timedelta(seconds=1),
            )
        finally:
            self.authority.mark_commit_ready = original_mark  # type: ignore[method-assign]
            if stop_thread is not None:
                stop_thread.join(timeout=2)
            competing_store.close()
        self.assertEqual(stop_errors, [])
        self.assertTrue(stop_finished.is_set())
        self.assertEqual(self.runtime_store.run_status("run-1")["state"], "FAILED")
        self.assertEqual(result.state, "committed")
        self.assertEqual((self.root / "SERIALIZED.md").read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
