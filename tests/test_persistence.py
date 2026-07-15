from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eco_runtime.digests import canonical_json
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.persistence import (
    HmacKeyring,
    MemoryAnchorSink,
    apply_rotation_transition,
    create_online_backup,
    create_rotation_transition,
    export_external_anchor,
    restore_backup,
    verify_anchor_chain,
    verify_backup_bundle,
    verify_external_anchor,
)
from eco_runtime.store import STORE_APPLICATION_ID, STORE_SCHEMA_VERSION


NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
OLD_KEY = b"o" * 32
NEW_KEY = b"n" * 32


class PersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "runtime.db"
        self.connection = self.make_store(self.source)
        self.keyring = HmacKeyring({"old-key": OLD_KEY}, active_key_id="old-key")

    def tearDown(self) -> None:
        self.connection.close()
        self.temp.cleanup()

    @staticmethod
    def make_store(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(f"PRAGMA application_id = {STORE_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")
        connection.execute(
            "CREATE TABLE store_meta (singleton INTEGER PRIMARY KEY, store_id TEXT NOT NULL)"
        )
        connection.execute("INSERT INTO store_meta VALUES (1, 'store-test-1')")
        connection.execute(
            "CREATE TABLE audit_entries (sequence INTEGER PRIMARY KEY, entry_hash TEXT NOT NULL)"
        )
        connection.execute("CREATE TABLE payloads (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO payloads(value) VALUES ('first')")
        connection.execute("INSERT INTO audit_entries VALUES (1, ?)", ("a" * 64,))
        return connection

    @staticmethod
    def semantic_verifier(path: Path) -> None:
        uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        try:
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeStoreError("ECO_TEST_INVALID", "fixture is corrupt")
            if connection.execute("SELECT COUNT(*) FROM store_meta").fetchone()[0] != 1:
                raise RuntimeStoreError("ECO_TEST_INVALID", "fixture identity is missing")
        finally:
            connection.close()

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def backup(self):
        return create_online_backup(
            self.source,
            self.root / "backup.db",
            keyring=self.keyring,
            now=NOW,
            semantic_verifier=self.semantic_verifier,
        )

    def test_keyring_sign_verify_and_secret_safe_repr(self) -> None:
        with self.assertRaises(ValueError):
            HmacKeyring({"weak": b"x"}, active_key_id="weak")
        payload = {"protocol": "test", "value": 1}
        tag = self.keyring.sign(payload)
        self.keyring.verify(payload, key_id="old-key", tag=tag)
        self.assert_code(
            "ECO_AUTHENTICATION_FAILED",
            lambda: self.keyring.verify(
                {"protocol": "test", "value": 2}, key_id="old-key", tag=tag
            ),
        )
        self.assertNotIn(OLD_KEY.decode(), repr(self.keyring))

    def test_dual_authenticated_key_rotation_keeps_historical_key(self) -> None:
        keyring = HmacKeyring(
            {"old-key": OLD_KEY, "new-key": NEW_KEY}, active_key_id="old-key"
        )
        transition = create_rotation_transition(
            keyring, store_id="store-test-1", new_key_id="new-key", now=NOW
        )
        rotated = apply_rotation_transition(
            keyring, transition, store_id="store-test-1", now=NOW + timedelta(minutes=1)
        )
        self.assertEqual(rotated.active_key_id, "new-key")
        self.assertEqual(rotated.key_ids, ("new-key", "old-key"))
        old_tag = keyring.sign({"protocol": "historical"}, key_id="old-key")
        rotated.verify({"protocol": "historical"}, key_id="old-key", tag=old_tag)

        tampered = copy.deepcopy(transition)
        tampered["authentication"]["toTag"] = "0" * 64
        self.assert_code(
            "ECO_AUTHENTICATION_FAILED",
            lambda: apply_rotation_transition(
                keyring, tampered, store_id="store-test-1", now=NOW + timedelta(minutes=1)
            ),
        )
        self.assert_code(
            "ECO_ROTATION_EXPIRED",
            lambda: apply_rotation_transition(
                keyring, transition, store_id="store-test-1", now=NOW + timedelta(hours=2)
            ),
        )

    def test_online_backup_captures_wal_and_authenticates_exact_bytes(self) -> None:
        self.connection.execute("INSERT INTO payloads(value) VALUES ('wal-value')")
        bundle = self.backup()
        verified = verify_backup_bundle(
            bundle.database_path,
            bundle.manifest_path,
            keyring=self.keyring,
            semantic_verifier=self.semantic_verifier,
        )
        self.assertEqual(verified["storeId"], "store-test-1")
        backup = sqlite3.connect(bundle.database_path)
        try:
            values = [row[0] for row in backup.execute("SELECT value FROM payloads ORDER BY id")]
        finally:
            backup.close()
        self.assertEqual(values, ["first", "wal-value"])
        self.assertNotIn(str(self.source), bundle.manifest_path.read_text(encoding="utf-8"))
        self.assert_code(
            "ECO_PERSISTENCE_TARGET_EXISTS",
            lambda: self.backup(),
        )

        with bundle.database_path.open("ab") as stream:
            stream.write(b"tamper")
        self.assert_code(
            "ECO_BACKUP_AUTHENTICATION_FAILED",
            lambda: verify_backup_bundle(
                bundle.database_path,
                bundle.manifest_path,
                keyring=self.keyring,
                semantic_verifier=self.semantic_verifier,
            ),
        )

    def test_manifest_wrong_key_tamper_and_mutating_verifier_fail_closed(self) -> None:
        bundle = self.backup()
        wrong = HmacKeyring({"old-key": b"z" * 32}, active_key_id="old-key")
        self.assert_code(
            "ECO_AUTHENTICATION_FAILED",
            lambda: verify_backup_bundle(
                bundle.database_path,
                bundle.manifest_path,
                keyring=wrong,
                semantic_verifier=self.semantic_verifier,
            ),
        )
        manifest = json.loads(bundle.manifest_path.read_text(encoding="utf-8"))
        manifest["database"]["byteLength"] += 1
        bundle.manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
        self.assert_code(
            "ECO_AUTHENTICATION_FAILED",
            lambda: verify_backup_bundle(
                bundle.database_path,
                bundle.manifest_path,
                keyring=self.keyring,
                semantic_verifier=self.semantic_verifier,
            ),
        )

        second = create_online_backup(
            self.source,
            self.root / "second.db",
            keyring=self.keyring,
            now=NOW,
            semantic_verifier=self.semantic_verifier,
        )

        def mutating_verifier(path: Path) -> None:
            connection = sqlite3.connect(path)
            try:
                connection.execute("INSERT INTO payloads(value) VALUES ('forged')")
                connection.commit()
            finally:
                connection.close()

        self.assert_code(
            "ECO_BACKUP_VERIFIER_MUTATED",
            lambda: verify_backup_bundle(
                second.database_path,
                second.manifest_path,
                keyring=self.keyring,
                semantic_verifier=mutating_verifier,
            ),
        )

    def test_restore_verifies_and_never_overwrites(self) -> None:
        bundle = self.backup()
        target = self.root / "restored" / "runtime.db"
        restored = restore_backup(
            bundle.database_path,
            bundle.manifest_path,
            target,
            keyring=self.keyring,
            semantic_verifier=self.semantic_verifier,
        )
        self.assertEqual(restored, target.resolve())
        connection = sqlite3.connect(restored)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM payloads").fetchone()[0], 1)
        finally:
            connection.close()
        self.assert_code(
            "ECO_PERSISTENCE_TARGET_EXISTS",
            lambda: restore_backup(
                bundle.database_path,
                bundle.manifest_path,
                target,
                keyring=self.keyring,
                semantic_verifier=self.semantic_verifier,
            ),
        )

    def test_external_anchor_chain_detects_database_tail_rollback(self) -> None:
        sink = MemoryAnchorSink()
        first = export_external_anchor(
            self.source, keyring=self.keyring, sink=sink, now=NOW
        )
        verify_external_anchor(
            first.canonical_bytes, keyring=self.keyring, database=self.source, exact_head=True
        )
        tampered = json.loads(first.canonical_bytes.decode("utf-8"))
        tampered["auditEntryHash"] = "c" * 64
        self.assert_code(
            "ECO_AUTHENTICATION_FAILED",
            lambda: verify_external_anchor(
                canonical_json(tampered).encode("utf-8"), keyring=self.keyring
            ),
        )
        self.connection.execute("INSERT INTO audit_entries VALUES (2, ?)", ("b" * 64,))
        second = export_external_anchor(
            self.source,
            keyring=self.keyring,
            sink=sink,
            now=NOW + timedelta(minutes=1),
            previous_anchor=first.canonical_bytes,
        )
        chain = verify_anchor_chain(
            sink.items, keyring=self.keyring, database=self.source, exact_head=True
        )
        self.assertEqual([item["auditSequence"] for item in chain], [1, 2])
        verify_external_anchor(
            first.canonical_bytes, keyring=self.keyring, database=self.source
        )
        self.assert_code(
            "ECO_ANCHOR_DATABASE_MISMATCH",
            lambda: verify_external_anchor(
                first.canonical_bytes,
                keyring=self.keyring,
                database=self.source,
                exact_head=True,
            ),
        )

        self.connection.execute("DELETE FROM audit_entries WHERE sequence = 2")
        self.assert_code(
            "ECO_ANCHOR_DATABASE_MISMATCH",
            lambda: verify_external_anchor(
                second.canonical_bytes, keyring=self.keyring, database=self.source
            ),
        )


if __name__ == "__main__":
    unittest.main()
