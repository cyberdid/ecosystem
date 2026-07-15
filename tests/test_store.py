from __future__ import annotations

import copy
import hashlib
import hmac
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from eco_runtime.errors import RuntimeStoreError
from eco_runtime.contracts import schema_bundle_digest
from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.store import SQLiteRuntimeStore
from eco_runtime.persistence import (
    HmacKeyring,
    MemoryAnchorSink,
    create_rotation_transition,
    restore_backup,
    verify_backup_bundle,
)
from tests.test_policy import NOW
from tests.test_runtime_contracts import (
    adapter_conformance_profile,
    policy_decision,
    run_checkpoint,
    tool_request,
)


KEY = b"k" * 32
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


class SQLiteRuntimeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "runtime.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self, *, key: bytes = KEY, key_id: str = "test-key-1") -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(
            self.path,
            hmac_key=key,
            key_id=key_id,
            policy_capability=POLICY_CAPABILITY,
            broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY,
            adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
        )

    @staticmethod
    def bound_decision(subject: dict) -> dict:
        decision = policy_decision()
        decision["spec"]["subject"]["digest"] = semantic_digest(subject)
        decision["spec"]["policySnapshot"]["schemaBundleDigest"] = schema_bundle_digest()
        return decision

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_safe_record_is_immutable_idempotent_and_hmac_verified(self) -> None:
        record = adapter_conformance_profile()
        with self.store() as store:
            first = store.put_record(record)
            self.assertEqual(store.put_record(copy.deepcopy(record)), first)
            store.verify()
            changed = copy.deepcopy(record)
            changed["spec"]["status"] = "fail"
            self.assert_code("ECO_STORE_ID_CONFLICT", lambda: store.put_record(changed))
        with self.store() as reopened:
            reopened.verify()

    def test_path_bearing_tool_request_is_never_written(self) -> None:
        marker = "ECO_TEST_SECRET_PATH_DO_NOT_PERSIST"
        request = tool_request()
        request["spec"]["arguments"]["path"] = marker
        with self.store() as store:
            self.assert_code("ECO_STORE_RECORD_UNSAFE", lambda: store.put_record(request))
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                self.assertNotIn(marker.encode(), candidate.read_bytes())

    def test_authority_managed_decision_cannot_bypass_issue_api(self) -> None:
        decision = self.bound_decision(tool_request())
        with self.store() as store:
            self.assert_code(
                "ECO_STORE_AUTHORITY_REQUIRED", lambda: store.put_record(decision)
            )
            self.assert_code(
                "ECO_STORE_AUTHORITY_REQUIRED", lambda: store.put_record(run_checkpoint())
            )
            store.verify()
        with self.store() as reopened:
            reopened.verify()

    def test_decision_issue_consume_and_nonce_idempotency_are_durable(self) -> None:
        subject = tool_request()
        decision = self.bound_decision(subject)
        with self.store() as store:
            store.issue_decision(
                decision, semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY
            )
            store.consume_decision(
                decision, subject, nonce="operation-1", now=NOW,
                semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
            )
            store.consume_decision(
                decision, subject, nonce="operation-1", now=NOW,
                semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
            )
            self.assert_code(
                "ECO_DECISION_REPLAYED",
                lambda: store.consume_decision(
                    decision, subject, nonce="operation-2", now=NOW,
                    semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
                ),
            )
        with self.store() as reopened:
            reopened.consume_decision(
                decision, subject, nonce="operation-1", now=NOW,
                semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
            )

    def test_concurrent_connections_consume_allow_once(self) -> None:
        first = self.store()
        second = self.store()
        subject = tool_request()
        decision = self.bound_decision(subject)
        first.issue_decision(
            decision, semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY
        )
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def consume(store: SQLiteRuntimeStore, nonce: str) -> None:
            barrier.wait()
            try:
                store.consume_decision(
                    decision, subject, nonce=nonce, now=NOW,
                    semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
                )
                outcomes.append("allowed")
            except RuntimeStoreError as exc:
                outcomes.append(exc.code)

        threads = [
            threading.Thread(target=consume, args=(first, "operation-a")),
            threading.Thread(target=consume, args=(second, "operation-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        first.close()
        second.close()
        self.assertEqual(sorted(outcomes), ["ECO_DECISION_REPLAYED", "allowed"])

    def test_wrong_key_and_audit_tampering_fail_closed(self) -> None:
        with self.store() as store:
            store.put_record(adapter_conformance_profile())
        self.assert_code(
            "ECO_JOURNAL_CORRUPT",
            lambda: self.store(key=b"x" * 32),
        )

        connection = sqlite3.connect(self.path)
        connection.execute("UPDATE audit_entries SET action = 'tampered' WHERE sequence = 1")
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_record_digest_rewrite_cannot_detach_record_from_audit(self) -> None:
        record = adapter_conformance_profile()
        with self.store() as store:
            store.put_record(record)
        changed = copy.deepcopy(record)
        changed["spec"]["status"] = "fail"
        from eco_runtime.digests import canonical_json, semantic_digest

        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER records_immutable_update")
        connection.execute(
            "UPDATE records SET canonical_json = ?, record_digest = ? WHERE record_id = ?",
            (canonical_json(changed).encode(), semantic_digest(changed), record["metadata"]["id"]),
        )
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_consumed_decision_cannot_be_reopened_by_row_edit(self) -> None:
        subject = tool_request()
        decision = self.bound_decision(subject)
        with self.store() as store:
            store.issue_decision(
                decision, semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY
            )
            store.consume_decision(
                decision, subject, nonce="operation-1", now=NOW,
                semantic_config_digest="a" * 64, policy_capability=POLICY_CAPABILITY,
            )
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE decisions SET consumed_at = NULL, consumed_nonce = NULL WHERE decision_id = ?",
            (decision["metadata"]["id"],),
        )
        connection.execute("DELETE FROM nonces WHERE nonce = 'operation-1'")
        connection.commit()
        connection.close()
        self.assert_code("ECO_JOURNAL_CORRUPT", self.store)

    def test_store_location_can_be_forbidden_and_permissions_are_private(self) -> None:
        governed = self.root / "project"
        governed.mkdir()
        self.assert_code(
            "ECO_STORE_LOCATION_DENIED",
            lambda: SQLiteRuntimeStore(
                governed / ".runtime" / "audit.db",
                hmac_key=KEY,
                key_id="test-key-1",
                policy_capability=POLICY_CAPABILITY,
                broker_capability=BROKER_CAPABILITY,
                runtime_capability=RUNTIME_CAPABILITY,
                adapter_capability=ADAPTER_CAPABILITY,
                producer_issuers=PRODUCER_ISSUERS,
                forbidden_root=governed,
            ),
        )
        with self.store():
            pass
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)

    def test_authenticated_empty_v2_store_migrates_atomically_to_v3(self) -> None:
        with self.store():
            pass
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        meta = connection.execute("SELECT * FROM store_meta").fetchone()
        old_payload = {
            "domain": "eco-store-meta-v1",
            "storeId": meta["store_id"],
            "schemaVersion": 2,
            "digestProfile": meta["digest_profile"],
            "contractProfile": meta["contract_profile"],
            "schemaBundleDigest": meta["schema_bundle_digest"],
            "policyEngineVersion": meta["policy_engine_version"],
            "auditKeyId": meta["audit_key_id"],
            "createdAt": meta["created_at"],
        }
        old_hmac = hmac.new(
            KEY, canonical_json(old_payload).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        connection.executescript(
            """
            DROP TRIGGER run_checkpoints_immutable_update;
            DROP TRIGGER run_checkpoints_immutable_delete;
            DROP TRIGGER key_rotations_immutable_update;
            DROP TRIGGER key_rotations_immutable_delete;
            DROP TRIGGER run_events_immutable_update;
            DROP TRIGGER run_events_immutable_delete;
            DROP TRIGGER run_event_baselines_immutable_update;
            DROP TRIGGER run_event_baselines_immutable_delete;
            DROP TABLE run_checkpoints;
            DROP TABLE key_rotations;
            DROP TABLE run_events;
            DROP TABLE run_event_baselines;
            ALTER TABLE operations DROP COLUMN recovery_mode;
            ALTER TABLE runs DROP COLUMN event_head_digest;
            ALTER TABLE runs DROP COLUMN next_event_sequence;
            ALTER TABLE store_meta DROP COLUMN producer_issuers_digest;
            PRAGMA user_version = 2;
            """
        )
        connection.execute(
            "UPDATE store_meta SET schema_version = 2, meta_hmac = ?", (old_hmac,)
        )
        connection.commit()
        connection.close()

        with self.store() as migrated:
            migrated.verify()
        connection = sqlite3.connect(self.path)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertIsNotNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_events'"
            ).fetchone()
        )
        connection.close()

    def test_dual_authenticated_rotation_keeps_history_and_path_digest_stable(self) -> None:
        new_key = b"n" * 32
        path_key = b"p" * 32
        keys = {"test-key-1": KEY, "test-key-2": new_key}
        with SQLiteRuntimeStore(
            self.path, hmac_key=KEY, key_id="test-key-1",
            historical_hmac_keys={"test-key-2": new_key}, path_hmac_key=path_key,
            policy_capability=POLICY_CAPABILITY, broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY, adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
        ) as store:
            before = store.path_reference_digest("README.md")
            transition = create_rotation_transition(
                HmacKeyring(keys, active_key_id="test-key-1"),
                store_id=store.store_id, new_key_id="test-key-2", now=NOW,
            )
            store.rotate_audit_key(transition, now=NOW)
            self.assertEqual(store.path_reference_digest("README.md"), before)
            store.put_record(adapter_conformance_profile())
            store.verify()

        with SQLiteRuntimeStore(
            self.path, hmac_key=new_key, key_id="test-key-2",
            historical_hmac_keys={"test-key-1": KEY}, path_hmac_key=path_key,
            policy_capability=POLICY_CAPABILITY, broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY, adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
        ) as reopened:
            reopened.verify()
            self.assertEqual(reopened.path_reference_digest("README.md"), before)

    def test_store_backup_and_restore_use_read_only_semantic_verification(self) -> None:
        backup = self.root / "backup" / "runtime.db"
        with self.store() as store:
            store.put_record(adapter_conformance_profile())
            bundle = store.create_backup(backup, now=NOW)
            keyring = HmacKeyring({"test-key-1": KEY}, active_key_id="test-key-1")
            verified = verify_backup_bundle(
                bundle.database_path, bundle.manifest_path,
                keyring=keyring, semantic_verifier=store.verify_snapshot_path,
            )
            self.assertEqual(verified["storeId"], store.store_id)
            restored = restore_backup(
                bundle.database_path, bundle.manifest_path,
                self.root / "restored" / "runtime.db",
                keyring=keyring, semantic_verifier=store.verify_snapshot_path,
            )
        with SQLiteRuntimeStore(
            restored, hmac_key=KEY, key_id="test-key-1",
            policy_capability=POLICY_CAPABILITY, broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY, adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
        ) as reopened:
            reopened.verify()

    def test_required_external_anchor_is_verified_on_startup(self) -> None:
        sink = MemoryAnchorSink()
        with self.store() as store:
            store.put_record(adapter_conformance_profile())
            publication = store.publish_external_anchor(sink, now=NOW)
        with SQLiteRuntimeStore(
            self.path, hmac_key=KEY, key_id="test-key-1",
            policy_capability=POLICY_CAPABILITY, broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY, adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
            required_anchor=publication.canonical_bytes,
        ) as anchored:
            anchored.verify()

if __name__ == "__main__":
    unittest.main()
