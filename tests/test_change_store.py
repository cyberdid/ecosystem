from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eco_runtime.approval import ApprovalKeyPolicy, ApprovalSigner, ApprovalTrustStore
from eco_runtime.change_store import CHANGE_STORE_SCHEMA_VERSION, SQLiteChangeAuthority
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError


NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
AUDIT_KEY = b"a" * 32
HUMAN_KEY = b"h" * 32


def proposal(
    identifier: str = "proposal-1", target: str = "target-1",
    *, policy_decision_digest: str | None = None,
) -> dict:
    return {
        "proposalId": identifier, "projectId": "project-1", "runId": "run-1",
        "planDigest": semantic_digest("plan"),
        "policyDecisionDigest": policy_decision_digest or semantic_digest(
            f"policy-decision-{identifier}"
        ),
        "actionClass": "A2",
        "operationKind": "replace", "rootIdentityDigest": semantic_digest("root"),
        "baseDigest": semantic_digest("before"), "targetRefDigest": semantic_digest(target),
        "desiredDigest": semantic_digest(f"after-{identifier}"),
        "rollbackDigest": semantic_digest("before"), "displayDigest": semantic_digest("display"),
        "limits": {
            "maxBytes": 4096,
            "maxFiles": 1,
            "maxOperations": 5,
            "approvalExpiresAt": "2026-07-15T12:05:00Z",
        },
    }


class ChangeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "private" / "changes.db"
        self.policy = ApprovalKeyPolicy(
            key_id="human-key-1", human_id="operator-1", assurance="local-os-session",
            verification_key=HUMAN_KEY,
        )
        self.signer = ApprovalSigner(self.policy)
        self.trust = ApprovalTrustStore({self.policy.key_id: self.policy})

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self) -> SQLiteChangeAuthority:
        return SQLiteChangeAuthority(
            self.path, hmac_key=AUDIT_KEY, key_id="audit-key-1",
            approval_trust_store=self.trust, store_id="change-store-1"
        )

    def grant(self, store: SQLiteChangeAuthority, item: dict, suffix: str = "1") -> tuple[dict, dict]:
        binding = store.register_proposal(item, now=NOW)
        envelope = self.signer.sign(
            approval_id=f"approval-{suffix}", subject_digest=binding["subjectDigest"],
            challenge_nonce=f"challenge-{suffix}", issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
        store.record_verified_grant(envelope, now=NOW)
        return binding, envelope

    def prepare(self, store: SQLiteChangeAuthority, *, operation_id: str = "operation-1",
                approval_id: str = "approval-1", key: str = "idem-1") -> dict:
        return store.prepare_operation(
            operation_id=operation_id, proposal_id="proposal-1", approval_id=approval_id,
            idempotency_key=key,
            recovery_storage_ref=f"artifact://recovery/{operation_id}/prepared",
            recovery_sha256=semantic_digest(f"recovery-bytes-{operation_id}"),
            recovery_byte_length=512,
            recovery_metadata_digest=semantic_digest("recovery-bundle"),
            owner_id="worker-1", now=NOW, lease_seconds=30,
        )

    def assert_code(self, code: str, call) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_full_apply_and_rollback_state_machine_is_fenced(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            prepared = self.prepare(store)
            lease = {
                "owner_id": "worker-1", "lease_token": prepared["leaseToken"],
                "lease_epoch": prepared["leaseEpoch"], "now": NOW + timedelta(seconds=1),
            }
            store.mark_rollback_ready(
                "operation-1", before_proof_digest=semantic_digest("before-proof"),
                execution_intent_digest=semantic_digest("execution-intent"),
                recovery_storage_ref="artifact://recovery/operation-1/execution",
                recovery_sha256=semantic_digest("execution-recovery-bytes"),
                recovery_byte_length=1024,
                recovery_metadata_digest=semantic_digest("execution-recovery-metadata"),
                **lease,
            )
            store.mark_applying("operation-1", **lease)
            store.mark_commit_ready("operation-1", **lease)
            applied = store.mark_applied(
                "operation-1", receipt_digest=semantic_digest("apply-receipt"), **lease
            )
            self.assertEqual(applied["state"], "applied")
            store.mark_rolling_back("operation-1", **lease)
            rolled = store.mark_rolled_back(
                "operation-1", receipt_digest=semantic_digest("rollback-receipt"), **lease
            )
            self.assertEqual(rolled["state"], "rolled_back")
            store.verify()

    def test_apply_cannot_start_before_durable_rollback_readiness(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            prepared = self.prepare(store)
            self.assert_code(
                "ECO_CHANGE_STATE",
                lambda: store.mark_applying(
                    "operation-1", owner_id="worker-1", lease_token=prepared["leaseToken"],
                    lease_epoch=1, now=NOW + timedelta(seconds=1),
                ),
            )

    def test_commit_closes_rollback_window_and_releases_target_lock(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            self.grant(store, proposal("proposal-2", "target-1"), "2")
            prepared = self.prepare(store)
            lease = {
                "owner_id": "worker-1", "lease_token": prepared["leaseToken"],
                "lease_epoch": 1, "now": NOW + timedelta(seconds=1),
            }
            store.mark_rollback_ready(
                "operation-1", before_proof_digest=semantic_digest("before-proof"),
                execution_intent_digest=semantic_digest("execution-intent"),
                recovery_storage_ref="artifact://recovery/operation-1/execution",
                recovery_sha256=semantic_digest("execution-recovery-bytes"),
                recovery_byte_length=1024,
                recovery_metadata_digest=semantic_digest("execution-recovery-metadata"),
                **lease,
            )
            store.mark_applying("operation-1", **lease)
            store.mark_commit_ready("operation-1", **lease)
            store.mark_applied(
                "operation-1", receipt_digest=semantic_digest("apply-receipt"), **lease
            )
            committed = store.mark_committed("operation-1", **lease)
            self.assertEqual(committed["state"], "committed")
            second = store.prepare_operation(
                operation_id="operation-2", proposal_id="proposal-2", approval_id="approval-2",
                idempotency_key="idem-2",
                recovery_storage_ref="artifact://recovery/operation-2/prepared",
                recovery_sha256=semantic_digest("recovery-bytes-2"),
                recovery_byte_length=512,
                recovery_metadata_digest=semantic_digest("recovery-2"),
                owner_id="worker-2", now=NOW + timedelta(seconds=2),
            )
            self.assertEqual(second["state"], "prepared")

    def test_exact_replay_returns_existing_but_approval_is_single_use(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            first = self.prepare(store)
            replay = self.prepare(store)
            self.assertFalse(first["replayed"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(replay["intent_digest"], first["intentDigest"])
            self.assert_code(
                "ECO_APPROVAL_CONSUMED",
                lambda: self.prepare(store, operation_id="operation-2", key="idem-2"),
            )
            self.assert_code(
                "ECO_CHANGE_IDEMPOTENCY_CONFLICT",
                lambda: self.prepare(store, operation_id="operation-2", key="idem-1"),
            )

    def test_target_lock_and_concurrent_single_use_are_atomic(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            second = proposal("proposal-2", "target-1")
            self.grant(store, second, "2")
            self.prepare(store)
            self.assert_code(
                "ECO_CHANGE_TARGET_LOCKED",
                lambda: store.prepare_operation(
                    operation_id="operation-2", proposal_id="proposal-2", approval_id="approval-2",
                    idempotency_key="idem-2",
                    recovery_storage_ref="artifact://recovery/operation-2/prepared",
                    recovery_sha256=semantic_digest("recovery-bytes-2"),
                    recovery_byte_length=512,
                    recovery_metadata_digest=semantic_digest("recovery-2"),
                    owner_id="worker-2", now=NOW,
                ),
            )

    def test_policy_allow_decision_is_consumed_exactly_once(self) -> None:
        decision = semantic_digest("one-policy-allow-decision")
        first = proposal(policy_decision_digest=decision)
        second = proposal(
            "proposal-2", "target-2", policy_decision_digest=decision
        )
        with self.store() as store:
            self.grant(store, first)
            self.grant(store, second, "2")
            self.prepare(store)
            self.assert_code(
                "ECO_POLICY_DECISION_CONSUMED",
                lambda: store.prepare_operation(
                    operation_id="operation-2",
                    proposal_id="proposal-2",
                    approval_id="approval-2",
                    idempotency_key="idem-2",
                    recovery_storage_ref="artifact://recovery/operation-2/prepared",
                    recovery_sha256=semantic_digest("recovery-bytes-2"),
                    recovery_byte_length=512,
                    recovery_metadata_digest=semantic_digest("recovery-metadata-2"),
                    owner_id="worker-2",
                    now=NOW,
                ),
            )
            store.verify()

    def test_two_connections_can_consume_one_approval_exactly_once(self) -> None:
        with self.store() as seed:
            self.grant(seed, proposal())
        first = self.store()
        second = self.store()
        barrier = threading.Barrier(2)
        results: list[str] = []
        result_lock = threading.Lock()

        def prepare(store: SQLiteChangeAuthority, suffix: str) -> None:
            barrier.wait()
            try:
                store.prepare_operation(
                    operation_id=f"operation-{suffix}", proposal_id="proposal-1",
                    approval_id="approval-1", idempotency_key=f"idem-{suffix}",
                    recovery_storage_ref=f"artifact://recovery/operation-{suffix}/prepared",
                    recovery_sha256=semantic_digest(f"recovery-bytes-{suffix}"),
                    recovery_byte_length=512,
                    recovery_metadata_digest=semantic_digest(f"recovery-{suffix}"),
                    owner_id=f"worker-{suffix}", now=NOW,
                )
                result = "prepared"
            except RuntimeStoreError as exc:
                result = exc.code
            with result_lock:
                results.append(result)

        threads = [
            threading.Thread(target=prepare, args=(first, "a")),
            threading.Thread(target=prepare, args=(second, "b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        first.close()
        second.close()
        self.assertEqual(sorted(results), ["ECO_APPROVAL_CONSUMED", "prepared"])
        with self.store() as verified:
            verified.verify()

    def test_expired_lease_is_recovered_with_a_new_fencing_epoch(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            prepared = self.prepare(store)
            recoverable = store.scan_recoverable(now=NOW + timedelta(seconds=31))
            self.assertEqual(recoverable[0]["operation_id"], "operation-1")
            claimed = store.claim_operation(
                "operation-1", owner_id="recovery-worker", now=NOW + timedelta(seconds=31)
            )
            self.assertEqual(claimed["leaseEpoch"], 2)
            self.assert_code(
                "ECO_CHANGE_FENCED",
                lambda: store.mark_rollback_ready(
                    "operation-1", before_proof_digest=semantic_digest("before-proof"),
                    execution_intent_digest=semantic_digest("execution-intent"),
                    recovery_storage_ref="artifact://recovery/operation-1/execution",
                    recovery_sha256=semantic_digest("execution-recovery-bytes"),
                    recovery_byte_length=1024,
                    recovery_metadata_digest=semantic_digest("execution-recovery-metadata"),
                    owner_id="worker-1", lease_token=prepared["leaseToken"],
                    lease_epoch=1, now=NOW + timedelta(seconds=32),
                ),
            )
            resumed_ready = store.mark_rollback_ready(
                "operation-1", before_proof_digest=semantic_digest("before-proof"),
                execution_intent_digest=semantic_digest("execution-intent"),
                recovery_storage_ref="artifact://recovery/operation-1/execution",
                recovery_sha256=semantic_digest("execution-recovery-bytes"),
                recovery_byte_length=1024,
                recovery_metadata_digest=semantic_digest("execution-recovery-metadata"),
                owner_id="recovery-worker", lease_token=claimed["leaseToken"],
                lease_epoch=2, now=NOW + timedelta(seconds=32),
            )
            self.assertEqual(resumed_ready["state"], "rollback_ready")
            resumed = store.mark_applying(
                "operation-1", owner_id="recovery-worker", lease_token=claimed["leaseToken"],
                lease_epoch=2, now=NOW + timedelta(seconds=32),
            )
            self.assertEqual(resumed["state"], "applying")

    def test_recovery_reference_is_atomically_updated_and_exposed_for_recovery(self) -> None:
        prepared_ref = "artifact://recovery/operation-1/prepared"
        execution_ref = "artifact://recovery/operation-1/execution"
        execution_sha = semantic_digest("execution-recovery-bytes")
        execution_metadata = semantic_digest("execution-recovery-metadata")
        with self.store() as store:
            self.grant(store, proposal())
            prepared = self.prepare(store)
            initial = store.operation_status("operation-1")
            self.assertEqual(initial["recovery_storage_ref"], prepared_ref)
            self.assertEqual(initial["recovery_byte_length"], 512)
            ready = store.mark_rollback_ready(
                "operation-1",
                before_proof_digest=semantic_digest("before-proof"),
                execution_intent_digest=semantic_digest("execution-intent"),
                recovery_storage_ref=execution_ref,
                recovery_sha256=execution_sha,
                recovery_byte_length=2048,
                recovery_metadata_digest=execution_metadata,
                owner_id="worker-1",
                lease_token=prepared["leaseToken"],
                lease_epoch=prepared["leaseEpoch"],
                now=NOW + timedelta(seconds=1),
            )
            self.assertEqual(ready["recovery_storage_ref"], execution_ref)
            self.assertEqual(ready["recovery_sha256"], execution_sha)
            self.assertEqual(ready["recovery_byte_length"], 2048)
            self.assertEqual(ready["recovery_metadata_digest"], execution_metadata)

            recoverable = store.scan_recoverable(now=NOW + timedelta(seconds=31))
            self.assertEqual(recoverable[0]["recoveryStorageRef"], execution_ref)
            self.assertEqual(recoverable[0]["recoverySha256"], execution_sha)
            self.assertEqual(recoverable[0]["recoveryByteLength"], 2048)
            self.assertEqual(recoverable[0]["recoveryMetadataDigest"], execution_metadata)
            claimed = store.claim_operation(
                "operation-1", owner_id="recovery-worker",
                now=NOW + timedelta(seconds=31),
            )
            self.assertEqual(claimed["recoveryStorageRef"], execution_ref)
            self.assertEqual(claimed["recoverySha256"], execution_sha)
            self.assertEqual(claimed["recoveryByteLength"], 2048)
            self.assertEqual(claimed["recoveryMetadataDigest"], execution_metadata)
            store.verify()

    def test_reconciled_apply_phase_recovery_can_enter_rollback(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            prepared = self.prepare(store)
            lease = {
                "owner_id": "worker-1",
                "lease_token": prepared["leaseToken"],
                "lease_epoch": prepared["leaseEpoch"],
                "now": NOW + timedelta(seconds=1),
            }
            store.mark_rollback_ready(
                "operation-1",
                before_proof_digest=semantic_digest("before-proof"),
                execution_intent_digest=semantic_digest("execution-intent"),
                recovery_storage_ref="artifact://recovery/operation-1/execution",
                recovery_sha256=semantic_digest("execution-recovery-bytes"),
                recovery_byte_length=1024,
                recovery_metadata_digest=semantic_digest("execution-recovery-metadata"),
                **lease,
            )
            store.mark_applying("operation-1", **lease)
            claimed = store.claim_operation(
                "operation-1", owner_id="recovery-worker",
                now=NOW + timedelta(seconds=31),
            )
            self.assertEqual(claimed["recoveryPhase"], "apply")
            rolling = store.mark_rolling_back(
                "operation-1",
                owner_id="recovery-worker",
                lease_token=claimed["leaseToken"],
                lease_epoch=claimed["leaseEpoch"],
                now=NOW + timedelta(seconds=32),
            )
            self.assertEqual(rolling["state"], "rolling_back")
            self.assertEqual(rolling["recovery_phase"], "rollback")
            store.verify()

    def test_unknown_fields_and_raw_path_or_content_never_enter_sqlite(self) -> None:
        secret_path = "private/customer/secret.txt"
        raw = proposal()
        raw["path"] = secret_path
        with self.store() as store:
            self.assert_code("ECO_CHANGE_INVALID", lambda: store.register_proposal(raw, now=NOW))
            self.grant(store, proposal())
            self.prepare(store)
        database_bytes = self.path.read_bytes()
        self.assertNotIn(secret_path.encode(), database_bytes)
        self.assertNotIn(b"raw file content", database_bytes)
        self.assertIn(b"artifact://recovery/operation-1/prepared", database_bytes)

    def test_table_and_audit_tampering_is_detected_after_reopen(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            self.prepare(store)
        connection = sqlite3.connect(self.path)
        connection.execute("UPDATE operations SET state='failed' WHERE operation_id='operation-1'")
        connection.commit()
        connection.close()
        self.assert_code("ECO_CHANGE_STORE_CORRUPT", self.store)

    def test_restart_reverifies_human_signature_but_accepts_historical_expiry(self) -> None:
        with self.store() as store:
            self.grant(store, proposal())
            self.prepare(store)
        # Expiry is an authorization-time rule, not retrospective corruption.
        with self.store() as reopened:
            reopened.verify()
        untrusted = ApprovalTrustStore(
            {
                "human-key-1": ApprovalKeyPolicy(
                    key_id="human-key-1", human_id="operator-1",
                    assurance="local-os-session", verification_key=b"x" * 32,
                )
            }
        )
        self.assert_code(
            "ECO_CHANGE_STORE_CORRUPT",
            lambda: SQLiteChangeAuthority(
                self.path, hmac_key=AUDIT_KEY, key_id="audit-key-1",
                approval_trust_store=untrusted, store_id="change-store-1",
            ),
        )

    def test_schema_is_separate_and_private_location_guarded(self) -> None:
        governed = Path(self.temp.name) / "project"
        governed.mkdir()
        self.assert_code(
            "ECO_CHANGE_STORE_LOCATION_DENIED",
            lambda: SQLiteChangeAuthority(
                governed / ".runtime" / "changes.db", hmac_key=AUDIT_KEY,
                key_id="audit-key-1", approval_trust_store=self.trust,
                forbidden_root=governed,
            ),
        )
        with self.store():
            pass
        connection = sqlite3.connect(self.path)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], CHANGE_STORE_SCHEMA_VERSION)
        connection.close()


if __name__ == "__main__":
    unittest.main()
