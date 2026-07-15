from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.store import SQLiteRuntimeStore
from tests.test_runtime_contracts import policy_decision, tool_request


KEY = b"k" * 32
KEY_ID = "test-key-1"
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


class SQLiteRuntimeStoreIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runtime.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self) -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(
            self.path,
            hmac_key=KEY,
            key_id=KEY_ID,
            policy_capability=POLICY_CAPABILITY,
            broker_capability=BROKER_CAPABILITY,
            runtime_capability=RUNTIME_CAPABILITY,
            adapter_capability=ADAPTER_CAPABILITY,
            producer_issuers=PRODUCER_ISSUERS,
        )

    @staticmethod
    def bound_decision() -> tuple[dict, dict]:
        subject = tool_request()
        decision = policy_decision()
        decision["spec"]["subject"]["digest"] = semantic_digest(subject)
        decision["spec"]["policySnapshot"]["schemaBundleDigest"] = schema_bundle_digest()
        return decision, subject

    def assert_reopen_is_corrupt(self) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            self.store()
        self.assertEqual(caught.exception.code, "ECO_JOURNAL_CORRUPT")

    def test_orphan_nonce_is_detected_on_reopen(self) -> None:
        with self.store():
            pass

        connection = sqlite3.connect(self.path)
        connection.execute(
            "INSERT INTO nonces VALUES (?, ?, ?, ?, ?, ?)",
            (
                "orphan-nonce",
                "decision-consume",
                "run-orphan",
                "a" * 64,
                None,
                "2026-07-15T12:00:00Z",
            ),
        )
        connection.commit()
        connection.close()

        self.assert_reopen_is_corrupt()

    def test_consumed_at_without_consumed_nonce_is_detected_on_reopen(self) -> None:
        decision, _ = self.bound_decision()
        with self.store() as store:
            store.issue_decision(
                decision,
                semantic_config_digest="a" * 64,
                policy_capability=POLICY_CAPABILITY,
            )

        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE decisions SET consumed_at = ? WHERE decision_id = ?",
            ("2026-07-15T12:00:01Z", decision["metadata"]["id"]),
        )
        connection.commit()
        connection.close()

        self.assert_reopen_is_corrupt()

    def test_altered_decision_projection_is_detected_on_reopen(self) -> None:
        decision, _ = self.bound_decision()
        with self.store() as store:
            store.issue_decision(
                decision,
                semantic_config_digest="a" * 64,
                policy_capability=POLICY_CAPABILITY,
            )

        connection = sqlite3.connect(self.path)
        connection.execute(
            """
            UPDATE decisions
            SET run_id = ?, subject_digest = ?, effect = ?, expires_at = ?, expires_at_epoch_us = ?
            WHERE decision_id = ?
            """,
            (
                "run-forged",
                "b" * 64,
                "deny",
                "2099-01-01T00:00:00Z",
                4_070_908_800_000_000,
                decision["metadata"]["id"],
            ),
        )
        connection.commit()
        connection.close()

        self.assert_reopen_is_corrupt()


if __name__ == "__main__":
    unittest.main()
from eco_runtime.contracts import schema_bundle_digest
