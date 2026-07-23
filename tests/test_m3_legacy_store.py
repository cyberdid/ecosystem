from __future__ import annotations

import hashlib
import hmac
import sqlite3
import tempfile
import unittest
from pathlib import Path

from eco_runtime.digests import canonical_json
from eco_runtime.store import LEGACY_SCHEMA_BUNDLE_DIGESTS, SQLiteRuntimeStore


KEY = b"legacy-m2-journal-test-key-value!"
CAPABILITIES = tuple(object() for _ in range(4))
ISSUERS = {
    "policy": "legacy-policy",
    "broker": "legacy-broker",
    "runtime": "legacy-runtime",
    "adapter": "legacy-adapter",
}


class M3LegacyReadJournalTests(unittest.TestCase):
    def open_store(self, path: Path) -> SQLiteRuntimeStore:
        return SQLiteRuntimeStore(
            path,
            hmac_key=KEY,
            key_id="legacy-key",
            policy_capability=CAPABILITIES[0],
            broker_capability=CAPABILITIES[1],
            runtime_capability=CAPABILITIES[2],
            adapter_capability=CAPABILITIES[3],
            producer_issuers=ISSUERS,
        )

    def test_authenticated_m2_schema_bundle_remains_openable_after_additive_m3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authority"
            root.mkdir(mode=0o700)
            path = root / "runtime.db"
            self.open_store(path).close()

            legacy_digest = next(iter(LEGACY_SCHEMA_BUNDLE_DIGESTS))
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
            payload = {
                "domain": "eco-store-meta-v1",
                "storeId": row["store_id"],
                "schemaVersion": row["schema_version"],
                "digestProfile": row["digest_profile"],
                "contractProfile": row["contract_profile"],
                "schemaBundleDigest": legacy_digest,
                "policyEngineVersion": row["policy_engine_version"],
                "auditKeyId": row["audit_key_id"],
                "producerIssuersDigest": row["producer_issuers_digest"],
                "createdAt": row["created_at"],
            }
            tag = hmac.new(
                KEY, canonical_json(payload).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            connection.execute(
                "UPDATE store_meta SET schema_bundle_digest=?,meta_hmac=? WHERE singleton=1",
                (legacy_digest, tag),
            )
            connection.commit()
            connection.close()

            reopened = self.open_store(path)
            reopened.verify()
            reopened.close()


if __name__ == "__main__":
    unittest.main()
