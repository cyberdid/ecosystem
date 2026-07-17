from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from eco_runtime.artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from eco_runtime.digests import canonical_json
from eco_runtime.errors import ContractValidationError, RuntimeStoreError

from .contracts import (
    LINK_RELATIONS,
    MEMORY_API_VERSION,
    seal_memory_record,
    validate_memory_record,
)


MEMORY_STORE_APPLICATION_ID = 0x45434D36
MEMORY_STORE_SCHEMA_VERSION = 1
MEMORY_STORE_DOMAIN = "eco-private-memory-store-v1"
GENESIS_DIGEST = "0" * 64
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeStoreError("ECO_MEMORY_CLOCK_INVALID", "Memory clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _artifact_binding(proof: ArtifactAvailabilityProof) -> dict[str, Any]:
    return {
        "storageRef": proof.storage_ref,
        "sha256": proof.sha256,
        "byteLength": proof.byte_length,
    }


def _namespace_key(namespace: Mapping[str, Any]) -> str:
    return canonical_json(dict(namespace))


def _sorted_artifacts(artifacts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [dict(item) for item in artifacts]
    return sorted(normalized, key=lambda item: (item["sha256"], item["storageRef"]))


class PrivateMemoryStore:
    """Authenticated content-free memory journal backed by a private CAS.

    The SQLite database contains only sealed metadata, artifact bindings and an
    authenticated append chain. Memory bytes remain in the caller-owned CAS.
    Records are descriptive context and are never consulted as authorization.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        artifact_store: ContentAddressedArtifactStore,
        hmac_key: bytes,
        key_id: str,
    ) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key_id must be a bounded safe identifier")
        supplied = Path(path)
        if supplied.is_symlink():
            raise RuntimeStoreError("ECO_MEMORY_LOCATION_DENIED", "Memory database cannot be a symbolic link")
        self._path = supplied.resolve(strict=False)
        self._artifacts = artifact_store
        self._hmac_key = bytes(hmac_key)
        self._key_id = key_id
        self._lock = threading.RLock()
        self._closed = False
        self._prepare_location()
        try:
            self._connection = sqlite3.connect(
                self._path,
                isolation_level=None,
                timeout=10.0,
                check_same_thread=False,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode = DELETE")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 10000")
            if os.name == "posix":
                os.chmod(self._path, 0o600)
            self._initialize_or_verify()
        except sqlite3.Error as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._closed = True
            raise RuntimeStoreError(
                "ECO_MEMORY_STORE_UNAVAILABLE", "Memory store is unavailable"
            ) from exc
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            self._closed = True
            raise

    def _prepare_location(self) -> None:
        parent = self._path.parent
        existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeStoreError("ECO_MEMORY_LOCATION_DENIED", "Memory directory is not trusted")
        if os.name == "posix":
            if existed and info.st_mode & 0o077:
                raise RuntimeStoreError("ECO_MEMORY_PERMISSIONS", "Memory directory is not private")
            if not existed:
                os.chmod(parent, 0o700)
        if self._path.exists():
            info = self._path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeStoreError("ECO_MEMORY_LOCATION_DENIED", "Memory database is not a regular file")
            if os.name == "posix" and (info.st_mode & 0o077 or info.st_nlink != 1):
                raise RuntimeStoreError("ECO_MEMORY_PERMISSIONS", "Memory database is not private")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RuntimeStoreError("ECO_MEMORY_STORE_CLOSED", "Memory store is closed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield self._connection
                self._connection.execute("COMMIT")
            except sqlite3.Error as exc:
                try:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise RuntimeStoreError(
                    "ECO_MEMORY_STORE_UNAVAILABLE", "Memory store is unavailable"
                ) from exc
            except Exception:
                try:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise RuntimeStoreError(
                        "ECO_MEMORY_STORE_UNAVAILABLE", "Memory store is unavailable"
                    ) from exc
                raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> PrivateMemoryStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _meta_payload(self, *, store_id: str, head_sequence: int, head_hash: str) -> dict[str, Any]:
        return {
            "domain": MEMORY_STORE_DOMAIN,
            "schemaVersion": MEMORY_STORE_SCHEMA_VERSION,
            "storeId": store_id,
            "keyId": self._key_id,
            "headSequence": head_sequence,
            "headHash": head_hash,
        }

    def _sign(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(
            self._hmac_key,
            canonical_json(dict(payload)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _initialize_or_verify(self) -> None:
        with self._transaction() as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id == 0 and user_version == 0:
                for statement in (
                    """CREATE TABLE store_meta (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        store_id TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        key_id TEXT NOT NULL,
                        head_sequence INTEGER NOT NULL,
                        head_hash TEXT NOT NULL,
                        meta_hmac TEXT NOT NULL
                    )""",
                    """CREATE TABLE records (
                        record_id TEXT PRIMARY KEY,
                        record_digest TEXT NOT NULL UNIQUE,
                        namespace_key TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT,
                        data_class TEXT NOT NULL,
                        privacy_level TEXT NOT NULL,
                        memory_type TEXT NOT NULL,
                        record_json TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        record_hmac TEXT NOT NULL
                    )""",
                    """CREATE INDEX records_namespace_order
                        ON records(namespace_key, created_at DESC, record_digest ASC)""",
                    """CREATE TABLE journal (
                        sequence INTEGER PRIMARY KEY,
                        record_digest TEXT NOT NULL UNIQUE,
                        previous_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        entry_hmac TEXT NOT NULL,
                        FOREIGN KEY(record_digest) REFERENCES records(record_digest)
                    )""",
                ):
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id = {MEMORY_STORE_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {MEMORY_STORE_SCHEMA_VERSION}")
                store_id = secrets.token_hex(16)
                payload = self._meta_payload(store_id=store_id, head_sequence=0, head_hash=GENESIS_DIGEST)
                connection.execute(
                    "INSERT INTO store_meta VALUES (1, ?, ?, ?, 0, ?, ?)",
                    (store_id, MEMORY_STORE_SCHEMA_VERSION, self._key_id, GENESIS_DIGEST, self._sign(payload)),
                )
            elif application_id != MEMORY_STORE_APPLICATION_ID or user_version != MEMORY_STORE_SCHEMA_VERSION:
                raise RuntimeStoreError("ECO_MEMORY_PROFILE_MISMATCH", "Memory database profile is unsupported")
        self.verify(verify_artifacts=False)

    def _verified_meta(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM store_meta WHERE singleton = 1").fetchone()
        if row is None or row["schema_version"] != MEMORY_STORE_SCHEMA_VERSION or row["key_id"] != self._key_id:
            raise RuntimeStoreError("ECO_MEMORY_AUTHENTICATION_FAILED", "Memory store identity is invalid")
        payload = self._meta_payload(
            store_id=row["store_id"],
            head_sequence=row["head_sequence"],
            head_hash=row["head_hash"],
        )
        if not hmac.compare_digest(row["meta_hmac"], self._sign(payload)):
            raise RuntimeStoreError("ECO_MEMORY_AUTHENTICATION_FAILED", "Memory store authentication failed")
        return row

    @staticmethod
    def _decode_record(row: sqlite3.Row) -> dict[str, Any]:
        try:
            document = json.loads(row["record_json"])
            validate_memory_record(document)
        except (TypeError, json.JSONDecodeError, ContractValidationError) as exc:
            raise RuntimeStoreError("ECO_MEMORY_RECORD_INVALID", "Memory record is invalid") from exc
        return document

    def _verify_record_row(self, row: sqlite3.Row) -> dict[str, Any]:
        document = self._decode_record(row)
        payload = {
            "domain": MEMORY_STORE_DOMAIN,
            "recordDigest": row["record_digest"],
            "recordJson": row["record_json"],
        }
        if (
            row["record_digest"] != document["metadata"]["recordDigest"]
            or row["record_id"] != document["metadata"]["id"]
            or row["namespace_key"] != _namespace_key(document["spec"]["namespace"])
            or row["key_id"] != self._key_id
            or not hmac.compare_digest(row["record_hmac"], self._sign(payload))
        ):
            raise RuntimeStoreError("ECO_MEMORY_AUTHENTICATION_FAILED", "Memory record authentication failed")
        return document

    def _load_digest_locked(self, connection: sqlite3.Connection, digest: str) -> dict[str, Any] | None:
        row = connection.execute("SELECT * FROM records WHERE record_digest = ?", (digest,)).fetchone()
        return None if row is None else self._verify_record_row(row)

    def _require_related_locked(
        self,
        connection: sqlite3.Connection,
        document: Mapping[str, Any],
    ) -> None:
        namespace = _namespace_key(document["spec"]["namespace"])
        related = {
            digest
            for relation in LINK_RELATIONS
            for digest in document["spec"]["links"][relation]
        }
        compaction = document["spec"]["compaction"]
        if compaction is not None:
            related.update(compaction["sourceRecordDigests"])
        loaded: dict[str, dict[str, Any]] = {}
        for digest in sorted(related):
            record = self._load_digest_locked(connection, digest)
            if record is None or _namespace_key(record["spec"]["namespace"]) != namespace:
                raise RuntimeStoreError("ECO_MEMORY_LINK_INVALID", "Memory link is unavailable in the exact namespace")
            loaded[digest] = record
        if compaction is None:
            return
        sources = [loaded[digest] for digest in compaction["sourceRecordDigests"]]
        artifacts: dict[str, dict[str, Any]] = {}
        relations: set[tuple[str, str, str]] = set()
        for source in sources:
            binding = source["spec"]["contentArtifact"]
            artifacts[binding["sha256"]] = binding
            for binding in source["spec"]["sourceArtifacts"]:
                artifacts[binding["sha256"]] = binding
            source_digest = source["metadata"]["recordDigest"]
            for relation in LINK_RELATIONS:
                for target in source["spec"]["links"][relation]:
                    relations.add((source_digest, relation, target))
        expected_artifacts = _sorted_artifacts(list(artifacts.values()))
        expected_relations = [
            {"from": source, "relation": relation, "to": target}
            for source, relation, target in sorted(relations)
        ]
        if compaction["sourceArtifacts"] != expected_artifacts or compaction["preservedRelations"] != expected_relations:
            raise RuntimeStoreError("ECO_MEMORY_COMPACTION_INVALID", "Memory compaction provenance is incomplete")

    def _verify_artifact_bindings(self, document: Mapping[str, Any]) -> None:
        bindings = [document["spec"]["contentArtifact"], *document["spec"]["sourceArtifacts"]]
        compaction = document["spec"]["compaction"]
        if compaction is not None:
            bindings.extend(compaction["sourceArtifacts"])
        seen: set[str] = set()
        for binding in bindings:
            if binding["sha256"] in seen:
                continue
            seen.add(binding["sha256"])
            self._artifacts.verify_record(
                storage_ref=binding["storageRef"],
                sha256=binding["sha256"],
                byte_length=binding["byteLength"],
            )

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        document = validate_memory_record(dict(record))
        self._verify_artifact_bindings(document)
        encoded = canonical_json(document)
        digest = document["metadata"]["recordDigest"]
        record_id = document["metadata"]["id"]
        payload = {"domain": MEMORY_STORE_DOMAIN, "recordDigest": digest, "recordJson": encoded}
        with self._transaction() as connection:
            meta = self._verified_meta(connection)
            existing = connection.execute("SELECT * FROM records WHERE record_id = ?", (record_id,)).fetchone()
            if existing is not None:
                existing_document = self._verify_record_row(existing)
                if existing["record_digest"] == digest and existing["record_json"] == encoded:
                    return existing_document
                raise RuntimeStoreError("ECO_MEMORY_REPLAY_CONFLICT", "Memory record identifier was already used")
            self._require_related_locked(connection, document)
            spec = document["spec"]
            connection.execute(
                """INSERT INTO records
                   (record_id, record_digest, namespace_key, created_at, expires_at,
                    data_class, privacy_level, memory_type, record_json, key_id, record_hmac)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record_id,
                    digest,
                    _namespace_key(spec["namespace"]),
                    document["metadata"]["createdAt"],
                    spec["expiresAt"],
                    spec["dataClass"],
                    spec["privacyLevel"],
                    spec["memoryType"],
                    encoded,
                    self._key_id,
                    self._sign(payload),
                ),
            )
            sequence = int(meta["head_sequence"]) + 1
            previous = meta["head_hash"]
            entry_hash = hashlib.sha256(
                canonical_json(
                    {
                        "domain": MEMORY_STORE_DOMAIN,
                        "sequence": sequence,
                        "recordDigest": digest,
                        "previousHash": previous,
                    }
                ).encode("utf-8")
            ).hexdigest()
            connection.execute(
                "INSERT INTO journal VALUES (?, ?, ?, ?, ?, ?)",
                (sequence, digest, previous, entry_hash, self._key_id, self._sign({"entryHash": entry_hash})),
            )
            meta_payload = self._meta_payload(
                store_id=meta["store_id"], head_sequence=sequence, head_hash=entry_hash
            )
            connection.execute(
                "UPDATE store_meta SET head_sequence = ?, head_hash = ?, meta_hmac = ? WHERE singleton = 1",
                (sequence, entry_hash, self._sign(meta_payload)),
            )
        return document

    def put_memory(
        self,
        *,
        record_id: str,
        namespace: Mapping[str, Any],
        memory_type: str,
        data_class: str,
        privacy_level: str,
        author: str,
        created_at: datetime,
        content: bytes,
        source_artifacts: Sequence[ArtifactAvailabilityProof],
        ttl: timedelta | None = None,
        links: Mapping[str, Sequence[str]] | None = None,
        max_content_bytes: int = 1024 * 1024,
    ) -> dict[str, Any]:
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if not source_artifacts:
            raise RuntimeStoreError("ECO_MEMORY_PROVENANCE_REQUIRED", "Memory source provenance is required")
        content_proof = self._artifacts.put(io.BytesIO(content), max_bytes=max_content_bytes)
        for proof in source_artifacts:
            self._artifacts.verify_availability(proof)
        expires_at = None if ttl is None else _utc(created_at + ttl)
        relation_values = links or {}
        record = seal_memory_record(
            {
                "apiVersion": MEMORY_API_VERSION,
                "kind": "MemoryRecord",
                "metadata": {"id": record_id, "createdAt": _utc(created_at)},
                "spec": {
                    "namespace": dict(namespace),
                    "memoryType": memory_type,
                    "dataClass": data_class,
                    "privacyLevel": privacy_level,
                    "author": author,
                    "expiresAt": expires_at,
                    "contentArtifact": _artifact_binding(content_proof),
                    "sourceArtifacts": _sorted_artifacts([_artifact_binding(item) for item in source_artifacts]),
                    "links": {
                        relation: sorted(set(relation_values.get(relation, ())))
                        for relation in LINK_RELATIONS
                    },
                    "compaction": None,
                },
            }
        )
        return self.append(record)

    def get(self, digest: str, *, verify_artifacts: bool = True) -> dict[str, Any]:
        with self._transaction() as connection:
            self._verified_meta(connection)
            document = self._load_digest_locked(connection, digest)
        if document is None:
            raise RuntimeStoreError("ECO_MEMORY_NOT_FOUND", "Memory record is unavailable")
        if verify_artifacts:
            self._verify_artifact_bindings(document)
        return document

    def namespace_records(self, namespace: Mapping[str, Any]) -> list[dict[str, Any]]:
        with self._transaction() as connection:
            self._verified_meta(connection)
            rows = connection.execute(
                "SELECT * FROM records WHERE namespace_key = ? ORDER BY created_at DESC, record_digest ASC",
                (_namespace_key(namespace),),
            ).fetchall()
            return [self._verify_record_row(row) for row in rows]

    def read_content(self, record: Mapping[str, Any]) -> bytes:
        """Read one authenticated record's exact bytes without exposing a CAS path."""

        document = validate_memory_record(dict(record))
        authenticated = self.get(document["metadata"]["recordDigest"], verify_artifacts=False)
        if authenticated != document:
            raise RuntimeStoreError(
                "ECO_MEMORY_AUTHENTICATION_FAILED", "Memory record authentication failed"
            )
        binding = authenticated["spec"]["contentArtifact"]
        proof = self._artifacts.proof_for_record(
            storage_ref=binding["storageRef"],
            sha256=binding["sha256"],
            byte_length=binding["byteLength"],
        )
        with self._artifacts.open_verified(proof) as stream:
            return stream.read()

    def verify(self, *, verify_artifacts: bool = True) -> dict[str, Any]:
        with self._transaction() as connection:
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise RuntimeStoreError("ECO_MEMORY_STORE_CORRUPT", "Memory database integrity check failed")
            meta = self._verified_meta(connection)
            rows = connection.execute("SELECT * FROM records ORDER BY record_digest").fetchall()
            documents = {row["record_digest"]: self._verify_record_row(row) for row in rows}
            journal = connection.execute("SELECT * FROM journal ORDER BY sequence").fetchall()
            previous = GENESIS_DIGEST
            for expected_sequence, row in enumerate(journal, 1):
                expected_hash = hashlib.sha256(
                    canonical_json(
                        {
                            "domain": MEMORY_STORE_DOMAIN,
                            "sequence": expected_sequence,
                            "recordDigest": row["record_digest"],
                            "previousHash": previous,
                        }
                    ).encode("utf-8")
                ).hexdigest()
                if (
                    row["sequence"] != expected_sequence
                    or row["record_digest"] not in documents
                    or row["previous_hash"] != previous
                    or row["entry_hash"] != expected_hash
                    or row["key_id"] != self._key_id
                    or not hmac.compare_digest(row["entry_hmac"], self._sign({"entryHash": expected_hash}))
                ):
                    raise RuntimeStoreError("ECO_MEMORY_AUTHENTICATION_FAILED", "Memory journal authentication failed")
                previous = expected_hash
            if (
                len(journal) != len(documents)
                or meta["head_sequence"] != len(journal)
                or meta["head_hash"] != previous
            ):
                raise RuntimeStoreError("ECO_MEMORY_AUTHENTICATION_FAILED", "Memory journal head is invalid")
            for document in documents.values():
                self._require_related_locked(connection, document)
        if verify_artifacts:
            for document in documents.values():
                self._verify_artifact_bindings(document)
        return {
            "healthy": True,
            "schemaVersion": MEMORY_STORE_SCHEMA_VERSION,
            "recordCount": len(documents),
            "headHash": previous,
        }

    def compact(
        self,
        *,
        record_id: str,
        source_record_digests: Sequence[str],
        summary_content: bytes,
        author: str,
        created_at: datetime,
        ttl: timedelta | None = None,
        max_content_bytes: int = 1024 * 1024,
    ) -> dict[str, Any]:
        source_digests = sorted(set(source_record_digests))
        if not source_digests:
            raise RuntimeStoreError("ECO_MEMORY_COMPACTION_INVALID", "Compaction sources are required")
        sources = [self.get(digest) for digest in source_digests]
        namespace = sources[0]["spec"]["namespace"]
        if any(source["spec"]["namespace"] != namespace for source in sources):
            raise RuntimeStoreError("ECO_MEMORY_COMPACTION_INVALID", "Compaction cannot cross namespaces")
        artifacts: dict[str, dict[str, Any]] = {}
        relations: set[tuple[str, str, str]] = set()
        for source in sources:
            for binding in [source["spec"]["contentArtifact"], *source["spec"]["sourceArtifacts"]]:
                artifacts[binding["sha256"]] = binding
            digest = source["metadata"]["recordDigest"]
            for relation in LINK_RELATIONS:
                for target in source["spec"]["links"][relation]:
                    relations.add((digest, relation, target))
        summary_proof = self._artifacts.put(io.BytesIO(summary_content), max_bytes=max_content_bytes)
        expires_at = None if ttl is None else _utc(created_at + ttl)
        source_artifacts = _sorted_artifacts(list(artifacts.values()))
        source_classes = [source["spec"]["dataClass"] for source in sources]
        privacy_levels = [source["spec"]["privacyLevel"] for source in sources]
        record = seal_memory_record(
            {
                "apiVersion": MEMORY_API_VERSION,
                "kind": "MemoryRecord",
                "metadata": {"id": record_id, "createdAt": _utc(created_at)},
                "spec": {
                    "namespace": namespace,
                    "memoryType": "summary",
                    "dataClass": max(source_classes),
                    "privacyLevel": max(privacy_levels),
                    "author": author,
                    "expiresAt": expires_at,
                    "contentArtifact": _artifact_binding(summary_proof),
                    "sourceArtifacts": source_artifacts,
                    "links": {relation: [] for relation in LINK_RELATIONS},
                    "compaction": {
                        "sourceRecordDigests": source_digests,
                        "sourceArtifacts": source_artifacts,
                        "preservedRelations": [
                            {"from": source, "relation": relation, "to": target}
                            for source, relation, target in sorted(relations)
                        ],
                    },
                },
            }
        )
        return self.append(record)

    def expand_summary(self, digest: str) -> dict[str, Any]:
        summary = self.get(digest)
        compaction = summary["spec"]["compaction"]
        if compaction is None:
            raise RuntimeStoreError("ECO_MEMORY_NOT_SUMMARY", "Memory record is not a compaction summary")
        records = [self.get(source_digest) for source_digest in compaction["sourceRecordDigests"]]
        return {
            "summary": summary,
            "sourceRecords": records,
            "sourceArtifacts": list(compaction["sourceArtifacts"]),
            "preservedRelations": list(compaction["preservedRelations"]),
        }
