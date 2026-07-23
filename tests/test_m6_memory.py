from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eco_memory import (
    ExplicitMemoryReadPolicy,
    MemoryQuery,
    PrivateMemoryStore,
    memory_contract_errors,
    retrieve_memory,
    seal_memory_record,
)
from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.errors import RuntimePolicyError


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
KEY = b"m" * 32
PROOF_KEY = b"p" * 32


class MemoryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.cas_root = root / "cas"
        self.database = root / "memory" / "memory.sqlite3"
        self.cas = ContentAddressedArtifactStore(
            self.cas_root,
            proof_key=PROOF_KEY,
            key_id="artifact-key-1",
        )
        self.store = PrivateMemoryStore(
            self.database,
            artifact_store=self.cas,
            hmac_key=KEY,
            key_id="memory-key-1",
        )
        self.ns = {"projectId": "project-a", "teamId": "team-a", "runId": "run-a"}
        self.source = self.cas.put(io.BytesIO(b"source evidence"))
        self.policy = ExplicitMemoryReadPolicy(
            allowed_data_classes=("D0", "D1", "D2", "D3"),
            allowed_privacy_levels=("P0", "P1", "P2", "P3"),
        )

    def tearDown(self) -> None:
        self.store.close()
        self.cas.close()
        self.temporary.cleanup()

    def put(
        self,
        record_id: str,
        content: bytes,
        *,
        namespace=None,
        memory_type="fact",
        data_class="D0",
        privacy_level="P0",
        created_at=NOW,
        ttl=None,
        links=None,
    ):
        return self.store.put_memory(
            record_id=record_id,
            namespace=namespace or self.ns,
            memory_type=memory_type,
            data_class=data_class,
            privacy_level=privacy_level,
            author="agent:researcher",
            created_at=created_at,
            content=content,
            source_artifacts=(self.source,),
            ttl=ttl,
            links=links,
        )

    def query(self, **overrides):
        values = {
            "namespace": self.ns,
            "data_classes": ("D0", "D1", "D2", "D3"),
            "privacy_levels": ("P0", "P1", "P2", "P3"),
            "max_items": 16,
            "max_bytes": 65536,
            "max_tokens": 16384,
        }
        values.update(overrides)
        return retrieve_memory(
            self.store,
            MemoryQuery(**values),
            policy=self.policy,
            now=NOW,
        )


class MemoryContractTests(MemoryFixture):
    def test_all_context_types_are_accepted_and_authority_fields_are_rejected(self) -> None:
        for index, memory_type in enumerate(
            ("fact", "claim", "decision", "constraint", "open-question", "failed-approach")
        ):
            record = self.put(f"r-{index}", memory_type.encode(), memory_type=memory_type)
            self.assertEqual(record["spec"]["memoryType"], memory_type)
        forged = json.loads(json.dumps(record))
        forged["spec"]["capabilities"] = ["network"]
        forged = seal_memory_record(forged)
        self.assertTrue(memory_contract_errors(forged))

    def test_provenance_digest_is_exact_and_content_free(self) -> None:
        secret = b"never persist this raw secret"
        record = self.put("fact-secret", secret)
        self.assertEqual(record["spec"]["sourceArtifacts"][0]["sha256"], self.source.sha256)
        self.assertNotIn("token", record["spec"]["sourceArtifacts"][0])
        self.store.close()
        database_bytes = self.database.read_bytes()
        self.assertNotIn(secret, database_bytes)
        self.store = PrivateMemoryStore(
            self.database,
            artifact_store=self.cas,
            hmac_key=KEY,
            key_id="memory-key-1",
        )

    def test_unjournaled_sealed_record_cannot_reissue_a_cas_proof(self) -> None:
        record = self.put("journaled", b"private bytes")
        forged = json.loads(json.dumps(record))
        forged["metadata"]["id"] = "not-journaled"
        forged = seal_memory_record(forged)
        with self.assertRaises(RuntimeStoreError):
            self.store.read_content(forged)

    def test_forged_and_cross_namespace_links_are_rejected(self) -> None:
        first = self.put("first", b"one")
        with self.assertRaisesRegex(RuntimeStoreError, "exact namespace"):
            self.put("forged", b"bad", links={"refutes": ["f" * 64]})
        other_ns = {"projectId": "project-b", "teamId": "team-a", "runId": "run-a"}
        with self.assertRaisesRegex(RuntimeStoreError, "exact namespace"):
            self.put(
                "cross",
                b"bad",
                namespace=other_ns,
                links={"conflicts": [first["metadata"]["recordDigest"]]},
            )


class MemoryRetrievalTests(MemoryFixture):
    def test_exact_namespace_prevents_cross_project_team_and_run_leakage(self) -> None:
        expected = self.put("expected", b"expected")
        variants = (
            {"projectId": "project-b", "teamId": "team-a", "runId": "run-a"},
            {"projectId": "project-a", "teamId": "team-b", "runId": "run-a"},
            {"projectId": "project-a", "teamId": "team-a", "runId": "run-b"},
        )
        for index, namespace in enumerate(variants):
            self.put(f"hidden-{index}", b"hidden", namespace=namespace)
        result = self.query()
        self.assertEqual([hit.record_digest for hit in result.hits], [expected["metadata"]["recordDigest"]])

    def test_ttl_data_class_privacy_and_policy_filters_fail_closed(self) -> None:
        visible = self.put("visible", b"visible", data_class="D0", privacy_level="P0")
        self.put("expired", b"expired", ttl=timedelta(seconds=1), created_at=NOW - timedelta(minutes=1))
        self.put("classified", b"classified", data_class="D2")
        self.put("private", b"private", privacy_level="P2")
        policy = ExplicitMemoryReadPolicy(
            allowed_data_classes=("D0",), allowed_privacy_levels=("P0",)
        )
        result = retrieve_memory(
            self.store,
            MemoryQuery(
                namespace=self.ns,
                data_classes=("D0", "D2"),
                privacy_levels=("P0", "P2"),
            ),
            policy=policy,
            now=NOW,
        )
        self.assertEqual([hit.record_digest for hit in result.hits], [visible["metadata"]["recordDigest"]])

    def test_conflict_component_is_atomic_under_item_budget(self) -> None:
        original = self.put("original", b"AAAA")
        rebuttal = self.put(
            "rebuttal",
            b"BBBB",
            links={"refutes": [original["metadata"]["recordDigest"]]},
            created_at=NOW + timedelta(seconds=1),
        )
        too_small = self.query(max_items=1)
        self.assertEqual(too_small.hits, ())
        self.assertTrue(too_small.truncated)
        complete = self.query(max_items=2, max_bytes=8, max_tokens=8)
        self.assertEqual({hit.record_digest for hit in complete.hits}, {
            original["metadata"]["recordDigest"], rebuttal["metadata"]["recordDigest"]
        })
        self.assertEqual(len(complete.relations), 1)
        self.assertEqual(complete.relations[0]["relation"], "refutes")

    def test_byte_and_token_boundaries_are_exact_and_order_is_deterministic(self) -> None:
        first = self.put("first", b"1234")
        second = self.put("second", b"5678")
        exact = self.query(max_items=2, max_bytes=8, max_tokens=8)
        expected = sorted(
            (first["metadata"]["recordDigest"], second["metadata"]["recordDigest"])
        )
        self.assertEqual([hit.record_digest for hit in exact.hits], expected)
        self.assertEqual(exact.used_bytes, 8)
        self.assertEqual(exact.estimated_tokens, 8)
        limited = self.query(max_items=2, max_bytes=7, max_tokens=8)
        self.assertEqual(len(limited.hits), 1)
        self.assertTrue(limited.truncated)
        self.assertEqual(
            [hit.record_digest for hit in self.query().hits],
            [hit.record_digest for hit in self.query().hits],
        )

    def test_public_result_has_bindings_but_never_raw_content(self) -> None:
        self.put("secret-result", b"private answer")
        result = self.query()
        public = result.as_public_dict()
        encoded = json.dumps(public)
        self.assertNotIn("private answer", encoded)
        self.assertIn("contentArtifact", public["hits"][0])
        self.assertEqual(result.hits[0].content, b"private answer")

    def test_policy_exception_and_non_boolean_decision_fail_closed(self) -> None:
        self.put("policy-record", b"value")

        class BrokenPolicy:
            def allows(self, record):
                raise ValueError("provider-controlled detail")

        class InvalidPolicy:
            def allows(self, record):
                return "yes"

        query = MemoryQuery(
            namespace=self.ns,
            data_classes=("D0",),
            privacy_levels=("P0",),
        )
        for policy in (BrokenPolicy(), InvalidPolicy()):
            with self.assertRaises(RuntimePolicyError) as caught:
                retrieve_memory(self.store, query, policy=policy, now=NOW)
            self.assertNotIn("provider-controlled detail", str(caught.exception))

    def test_filtered_conflict_propagates_to_the_complete_connected_component(self) -> None:
        first = self.put("chain-a", b"a")
        second = self.put(
            "chain-b",
            b"b",
            links={"conflicts": [first["metadata"]["recordDigest"]]},
            created_at=NOW + timedelta(seconds=1),
        )
        self.put(
            "chain-c",
            b"c",
            data_class="D2",
            links={"refutes": [second["metadata"]["recordDigest"]]},
            created_at=NOW + timedelta(seconds=2),
        )
        result = self.query(data_classes=("D0",))
        self.assertEqual(result.hits, ())
        self.assertTrue(result.truncated)


class MemoryCompactionTests(MemoryFixture):
    def test_compaction_cannot_outlive_earliest_source_or_explicit_ttl(self) -> None:
        expiring = self.put(
            "expiring-source",
            b"short lived",
            ttl=timedelta(minutes=30),
        )
        durable = self.put("durable-source", b"durable")
        summary = self.store.compact(
            record_id="clamped-summary",
            source_record_digests=(
                expiring["metadata"]["recordDigest"],
                durable["metadata"]["recordDigest"],
            ),
            summary_content=b"bounded summary",
            author="agent:synthesizer",
            created_at=NOW + timedelta(minutes=1),
            ttl=timedelta(hours=2),
        )
        self.assertEqual(
            summary["spec"]["expiresAt"],
            (NOW + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        visible = retrieve_memory(
            self.store,
            MemoryQuery(
                namespace=self.ns,
                data_classes=("D0",),
                privacy_levels=("P0",),
                memory_types=("summary",),
            ),
            policy=self.policy,
            now=NOW + timedelta(minutes=29),
        )
        self.assertEqual(
            [hit.record_digest for hit in visible.hits],
            [summary["metadata"]["recordDigest"]],
        )
        expired = retrieve_memory(
            self.store,
            MemoryQuery(
                namespace=self.ns,
                data_classes=("D0",),
                privacy_levels=("P0",),
                memory_types=("summary",),
            ),
            policy=self.policy,
            now=NOW + timedelta(minutes=31),
        )
        self.assertEqual(expired.hits, ())

    def test_nested_compaction_preserves_inherited_relations(self) -> None:
        claim = self.put("nested-claim", b"claim")
        refutation = self.put(
            "nested-refutation",
            b"refutation",
            links={"refutes": [claim["metadata"]["recordDigest"]]},
            created_at=NOW + timedelta(seconds=1),
        )
        inner = self.store.compact(
            record_id="inner-summary",
            source_record_digests=(
                claim["metadata"]["recordDigest"],
                refutation["metadata"]["recordDigest"],
            ),
            summary_content=b"inner",
            author="agent:synthesizer",
            created_at=NOW + timedelta(seconds=2),
        )
        outer = self.store.compact(
            record_id="outer-summary",
            source_record_digests=(inner["metadata"]["recordDigest"],),
            summary_content=b"outer",
            author="agent:synthesizer",
            created_at=NOW + timedelta(seconds=3),
        )
        self.assertEqual(
            outer["spec"]["compaction"]["preservedRelations"],
            [
                {
                    "from": refutation["metadata"]["recordDigest"],
                    "relation": "refutes",
                    "to": claim["metadata"]["recordDigest"],
                }
            ],
        )

    def test_compaction_roundtrip_preserves_sources_artifacts_and_refutation(self) -> None:
        first = self.put("claim", b"claim")
        second = self.put(
            "refutation",
            b"refutation",
            memory_type="claim",
            links={"refutes": [first["metadata"]["recordDigest"]]},
            created_at=NOW + timedelta(seconds=1),
        )
        summary = self.store.compact(
            record_id="summary",
            source_record_digests=(second["metadata"]["recordDigest"], first["metadata"]["recordDigest"]),
            summary_content=b"contested summary",
            author="agent:synthesizer",
            created_at=NOW + timedelta(seconds=2),
        )
        expanded = self.store.expand_summary(summary["metadata"]["recordDigest"])
        self.assertEqual(
            {item["metadata"]["recordDigest"] for item in expanded["sourceRecords"]},
            {first["metadata"]["recordDigest"], second["metadata"]["recordDigest"]},
        )
        self.assertEqual(expanded["preservedRelations"][0]["relation"], "refutes")
        result = self.query(memory_types=("summary",))
        self.assertEqual(len(result.hits), 1)
        self.assertEqual(result.relations[0]["preservedBy"], summary["metadata"]["recordDigest"])
        self.assertEqual(result.relations[0]["relation"], "refutes")

    def test_handcrafted_compaction_cannot_drop_preserved_relation(self) -> None:
        first = self.put("a", b"a")
        second = self.put(
            "b", b"b", links={"conflicts": [first["metadata"]["recordDigest"]]}
        )
        summary = self.store.compact(
            record_id="good-summary",
            source_record_digests=(first["metadata"]["recordDigest"], second["metadata"]["recordDigest"]),
            summary_content=b"summary",
            author="agent:synthesizer",
            created_at=NOW + timedelta(seconds=1),
        )
        forged = json.loads(json.dumps(summary))
        forged["metadata"]["id"] = "forged-summary"
        forged["spec"]["compaction"]["preservedRelations"] = []
        forged = seal_memory_record(forged)
        with self.assertRaisesRegex(RuntimeStoreError, "provenance is incomplete"):
            self.store.append(forged)


class MemoryIntegrityTests(MemoryFixture):
    def test_missing_or_tampered_cas_object_fails_closed_without_content_in_error(self) -> None:
        record = self.put("cas-record", b"sensitive payload")
        digest = record["spec"]["contentArtifact"]["sha256"]
        object_path = self.cas_root / "objects" / digest[:2] / digest[2:4] / digest
        object_path.unlink()
        with self.assertRaises(RuntimeStoreError) as caught:
            self.query()
        self.assertNotIn("sensitive payload", str(caught.exception))
        self.assertNotIn(digest, str(caught.exception))

    def test_modified_cas_object_fails_closed(self) -> None:
        record = self.put("tampered-record", b"original")
        digest = record["spec"]["contentArtifact"]["sha256"]
        object_path = self.cas_root / "objects" / digest[:2] / digest[2:4] / digest
        object_path.write_bytes(b"modified")
        with self.assertRaises(RuntimeStoreError) as caught:
            self.query()
        self.assertNotIn("original", str(caught.exception))

    def test_database_tamper_breaks_record_authentication(self) -> None:
        self.put("db-record", b"value")
        self.store.close()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("UPDATE records SET author = 'x'")
        except sqlite3.OperationalError:
            # There is deliberately no denormalized author column to tamper.
            connection.execute("UPDATE records SET record_json = replace(record_json, 'fact', 'claim')")
        connection.commit()
        connection.close()
        with self.assertRaises(RuntimeStoreError):
            PrivateMemoryStore(
                self.database,
                artifact_store=self.cas,
                hmac_key=KEY,
                key_id="memory-key-1",
            )

    def test_concurrent_exact_replay_writes_one_authenticated_entry(self) -> None:
        record = self.put("seed", b"seed")
        # Create a second exact record document using already-installed content;
        # all workers append the same sealed bytes.
        replay = json.loads(json.dumps(record))
        replay["metadata"]["id"] = "concurrent"
        replay = seal_memory_record(replay)
        barrier = threading.Barrier(8)
        second_store = PrivateMemoryStore(
            self.database,
            artifact_store=self.cas,
            hmac_key=KEY,
            key_id="memory-key-1",
        )

        def append_once(index):
            barrier.wait()
            selected = self.store if index % 2 == 0 else second_store
            return selected.append(replay)["metadata"]["recordDigest"]

        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                digests = list(executor.map(append_once, range(8)))
        finally:
            second_store.close()
        self.assertEqual(len(set(digests)), 1)
        status = self.store.verify()
        self.assertEqual(status["recordCount"], 2)

    def test_same_identifier_with_different_content_is_replay_conflict(self) -> None:
        self.put("same", b"one")
        with self.assertRaisesRegex(RuntimeStoreError, "already used"):
            self.put("same", b"two")


if __name__ == "__main__":
    unittest.main()
