from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from .contracts import CONTRACT_PROFILE, schema_bundle_digest, validate_record
from .digests import DIGEST_PROFILE, canonical_json, semantic_digest
from .errors import ContractValidationError, RuntimeStateError, RuntimeStoreError
from .policy import POLICY_ENGINE_VERSION
from .state import EVENT_SEMANTICS
from .state_reducer import RunProjection, RunState, TERMINAL_STATES, reduce_run_event


STORE_SCHEMA_VERSION = 3
STORE_APPLICATION_ID = 0x45434F31
GENESIS_DIGEST = "0" * 64
SAFE_BROKER_ERROR_MESSAGES = {
    "ECO_BINARY_FILE": "Repository content is not approved text",
    "ECO_FILE_CHANGED": "Repository file changed during the approved read",
    "ECO_FILE_DENIED": "Repository file is not readable by the broker",
    "ECO_FILE_NOT_FOUND": "Repository file does not exist",
    "ECO_FILE_OPEN_FAILED": "Repository file could not be opened safely",
    "ECO_FILE_TOO_LARGE": "Repository file exceeds the approved read limit",
    "ECO_HARDLINK_DENIED": "Repository file has an unsupported link topology",
    "ECO_NOT_REGULAR_FILE": "Repository path is not a regular file",
    "ECO_PATH_ESCAPE": "Repository path is outside the approved root",
    "ECO_SNAPSHOT_CONTENT_MISMATCH": "Repository content differs from the approved snapshot",
    "ECO_TEXT_ENCODING": "Repository content is not valid approved text",
}
RECOVERY_EXPIRED_MESSAGE = "Prepared operation cannot be retried without a trusted recovery payload"
SAFE_JOURNAL_KINDS = frozenset(
    {
        "RunRequest",
        "RunPlan",
        "PolicyDecision",
        "RunEvent",
        "ArtifactRecord",
        "ErrorRecord",
        "AdapterConformanceProfile",
        "ToolExecutionIntent",
        "RepositoryReadReceipt",
        "ToolExecutionOutcome",
        "RunCheckpoint",
    }
)
AUTHORITY_MANAGED_KINDS = frozenset(
    {
        "RunPlan",
        "PolicyDecision",
        "ToolExecutionIntent",
        "RepositoryReadReceipt",
        "ToolExecutionOutcome",
        "RunEvent",
        "ArtifactRecord",
        "ErrorRecord",
        "RunCheckpoint",
    }
)


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Store clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RuntimeStoreError("ECO_TIME_INVALID", "Stored timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeStoreError("ECO_TIME_INVALID", "Stored timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


class SQLiteRuntimeStore:
    """Embedded durable journal for sanitized runtime records and decision nonces.

    The HMAC key and filesystem permissions are part of the trusted composition
    root. Raw model/tool content and path-bearing records are rejected.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        hmac_key: bytes,
        key_id: str,
        policy_capability: object,
        broker_capability: object,
        runtime_capability: object,
        adapter_capability: object,
        producer_issuers: Mapping[str, str],
        forbidden_root: str | os.PathLike[str] | None = None,
        read_only: bool = False,
        historical_hmac_keys: Mapping[str, bytes] | None = None,
        path_hmac_key: bytes | None = None,
        artifact_store: ContentAddressedArtifactStore | None = None,
        required_anchor: bytes | None = None,
    ) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        if policy_capability is None:
            raise ValueError("policy_capability must be an opaque non-null object")
        capabilities = {
            "policy": policy_capability,
            "broker": broker_capability,
            "runtime": runtime_capability,
            "adapter": adapter_capability,
        }
        if any(value is None for value in capabilities.values()) or len(
            {id(value) for value in capabilities.values()}
        ) != 4:
            raise ValueError("producer capabilities must be distinct opaque objects")
        if set(producer_issuers) != set(capabilities) or any(
            not isinstance(value, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
            for value in producer_issuers.values()
        ):
            raise ValueError("producer_issuers must define four bounded issuer ids")
        self._path = Path(path).resolve()
        self._read_only = read_only
        if forbidden_root is not None:
            root = Path(forbidden_root).resolve()
            try:
                self._path.relative_to(root)
            except ValueError:
                pass
            else:
                raise RuntimeStoreError(
                    "ECO_STORE_LOCATION_DENIED",
                    "Runtime store must be outside the governed repository",
                )
        parent_existed = self._path.parent.exists()
        if read_only and not self._path.is_file():
            raise RuntimeStoreError("ECO_STORE_MISSING", "Read-only runtime store is unavailable")
        if not read_only:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            parent_mode = self._path.parent.stat().st_mode & 0o777
            if parent_existed and parent_mode & 0o077:
                raise RuntimeStoreError(
                    "ECO_STORE_PERMISSIONS",
                    "Runtime store directory is accessible by another user or group",
                )
            if not parent_existed:
                os.chmod(self._path.parent, 0o700)
            if self._path.exists() and self._path.stat().st_mode & 0o077:
                raise RuntimeStoreError("ECO_STORE_PERMISSIONS", "Runtime store file permissions are unsafe")
            if not read_only and not self._path.exists():
                descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
        self._hmac_key = hmac_key
        self._key_id = key_id
        self._audit_keys = dict(historical_hmac_keys or {})
        if key_id in self._audit_keys and self._audit_keys[key_id] != hmac_key:
            raise ValueError("active HMAC key conflicts with historical keyring")
        self._audit_keys[key_id] = hmac_key
        if any(not isinstance(value, bytes) or len(value) < 32 for value in self._audit_keys.values()):
            raise ValueError("historical HMAC keys must contain at least 32 bytes")
        self._path_hmac_key = path_hmac_key or hmac_key
        if not isinstance(self._path_hmac_key, bytes) or len(self._path_hmac_key) < 32:
            raise ValueError("path_hmac_key must contain at least 32 bytes")
        self._artifact_store = artifact_store
        self._required_anchor = bytes(required_anchor) if required_anchor is not None else None
        self._policy_capability = policy_capability
        self._broker_capability = broker_capability
        self._runtime_capability = runtime_capability
        self._adapter_capability = adapter_capability
        self._producer_capabilities = capabilities
        self._producer_issuers = dict(producer_issuers)
        self._lock = threading.RLock()
        self._closed = False
        database = (
            f"{self._path.as_uri()}?mode=ro&immutable=1" if read_only else self._path
        )
        self._connection = sqlite3.connect(
            database,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
            uri=read_only,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure()
            self._migrate_or_verify()
            if os.name == "posix" and not read_only:
                os.chmod(self._path, 0o600)
            self.verify()
            if self._required_anchor is not None:
                from .persistence import HmacKeyring, verify_external_anchor

                verify_external_anchor(
                    self._required_anchor,
                    keyring=HmacKeyring(self._audit_keys, active_key_id=self._key_id),
                    database=self._path,
                )
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @property
    def store_id(self) -> str:
        return self._store_id

    def __enter__(self) -> SQLiteRuntimeStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def verify_snapshot_path(self, path: Path) -> None:
        """Semantically verify an immutable backup without changing its bytes."""

        with SQLiteRuntimeStore(
            path,
            hmac_key=self._hmac_key,
            key_id=self._key_id,
            policy_capability=self._policy_capability,
            broker_capability=self._broker_capability,
            runtime_capability=self._runtime_capability,
            adapter_capability=self._adapter_capability,
            producer_issuers=self._producer_issuers,
            historical_hmac_keys=self._audit_keys,
            path_hmac_key=self._path_hmac_key,
            artifact_store=self._artifact_store,
            read_only=True,
        ) as snapshot:
            snapshot.verify()

    def create_backup(self, target: str | os.PathLike[str], *, now: datetime):
        """Create an authenticated online backup through the operational protocol."""

        from .persistence import HmacKeyring, create_online_backup

        return create_online_backup(
            self._path,
            target,
            keyring=HmacKeyring(self._audit_keys, active_key_id=self._key_id),
            now=now,
            semantic_verifier=self.verify_snapshot_path,
        )

    def publish_external_anchor(
        self,
        sink: object,
        *,
        now: datetime,
        previous_anchor: bytes | None = None,
    ):
        """Publish the current audit head to a caller-owned independent sink."""

        from .persistence import HmacKeyring, export_external_anchor

        return export_external_anchor(
            self._path,
            keyring=HmacKeyring(self._audit_keys, active_key_id=self._key_id),
            sink=sink,
            now=now,
            previous_anchor=previous_anchor,
        )

    def rotate_audit_key(self, transition: Mapping[str, Any], *, now: datetime) -> str:
        """Atomically apply a dual-authenticated active audit-key transition."""

        if self._read_only:
            raise RuntimeStoreError("ECO_STORE_READ_ONLY", "Read-only store cannot rotate keys")
        from .persistence import HmacKeyring, apply_rotation_transition

        current = HmacKeyring(self._audit_keys, active_key_id=self._key_id)
        rotated = apply_rotation_transition(
            current, transition, store_id=self._store_id, now=now
        )
        new_key_id = rotated.active_key_id
        new_key = self._audit_keys[new_key_id]
        body = dict(transition)
        nonce = body.get("nonce")
        transition_digest = semantic_digest(body)
        now_text = _utc(now)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            if self._connection.execute(
                "SELECT 1 FROM key_rotations WHERE nonce = ?", (nonce,)
            ).fetchone() is not None:
                raise RuntimeStoreError("ECO_ROTATION_REPLAYED", "Rotation nonce was already used")
            self._connection.execute(
                "INSERT INTO key_rotations VALUES (?, ?, ?, ?, ?)",
                (nonce, transition_digest, self._key_id, new_key_id, now_text),
            )
            self._append_audit(
                transaction_id=transaction_id,
                record_type="HmacKeyRotation",
                record_id=nonce,
                action="key-rotation",
                payload_digest=transition_digest,
                occurred_at=now_text,
            )
            meta = self._connection.execute(
                "SELECT * FROM store_meta WHERE singleton = 1"
            ).fetchone()
            meta_payload = {
                "domain": "eco-store-meta-v1",
                "storeId": meta["store_id"],
                "schemaVersion": meta["schema_version"],
                "digestProfile": meta["digest_profile"],
                "contractProfile": meta["contract_profile"],
                "schemaBundleDigest": meta["schema_bundle_digest"],
                "policyEngineVersion": meta["policy_engine_version"],
                "auditKeyId": new_key_id,
                "producerIssuersDigest": meta["producer_issuers_digest"],
                "createdAt": meta["created_at"],
            }
            meta_hmac = hmac.new(
                new_key, canonical_json(meta_payload).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            self._connection.execute(
                "UPDATE store_meta SET audit_key_id = ?, meta_hmac = ? WHERE singleton = 1",
                (new_key_id, meta_hmac),
            )
        self._key_id = new_key_id
        self._hmac_key = new_key
        return transition_digest

    def _configure(self) -> None:
        statements = [
            "PRAGMA foreign_keys = ON",
            "PRAGMA busy_timeout = 5000",
            "PRAGMA trusted_schema = OFF",
            "PRAGMA temp_store = MEMORY",
        ]
        if self._read_only:
            statements.append("PRAGMA query_only = ON")
        else:
            statements.extend(
                [
                    "PRAGMA journal_mode = WAL",
                    "PRAGMA synchronous = FULL",
                    "PRAGMA wal_autocheckpoint = 1000",
                ]
            )
        for statement in statements:
            self._connection.execute(statement)

    def _require_policy_capability(self, capability: object) -> None:
        if capability is not self._policy_capability:
            raise RuntimeStoreError(
                "ECO_POLICY_ISSUER_UNTRUSTED", "Caller lacks the configured policy capability"
            )

    def _require_broker_capability(self, capability: object) -> None:
        if capability is not self._broker_capability:
            raise RuntimeStoreError(
                "ECO_BROKER_ISSUER_UNTRUSTED", "Caller lacks the configured broker capability"
            )

    def _require_runtime_capability(self, capability: object) -> None:
        if capability is not self._runtime_capability:
            raise RuntimeStoreError(
                "ECO_RUNTIME_ISSUER_UNTRUSTED", "Caller lacks the configured runtime capability"
            )

    def _require_adapter_capability(self, capability: object) -> None:
        if capability is not self._adapter_capability:
            raise RuntimeStoreError(
                "ECO_ADAPTER_ISSUER_UNTRUSTED", "Caller lacks the configured adapter capability"
            )

    @staticmethod
    def _require_owner_id(owner_id: str) -> None:
        if not isinstance(owner_id, str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", owner_id
        ) is None:
            raise ValueError("owner_id must be a bounded safe identifier")

    @staticmethod
    def _require_decision_profile(
        decision: dict[str, Any], *, semantic_config_digest: str
    ) -> None:
        snapshot = decision["spec"]["policySnapshot"]
        if snapshot != {
            "apiVersion": "ai.ecosystem/v1alpha1",
            "semanticConfigDigest": semantic_config_digest,
            "digestProfile": DIGEST_PROFILE,
            "contractProfile": CONTRACT_PROFILE,
            "schemaBundleDigest": schema_bundle_digest(),
            "policyEngineVersion": POLICY_ENGINE_VERSION,
        }:
            raise RuntimeStoreError(
                "ECO_POLICY_PROVENANCE_MISMATCH", "Decision policy snapshot is not trusted"
            )

    @staticmethod
    def _require_plan_profile(plan: dict[str, Any]) -> None:
        project = plan["spec"]["project"]
        if (
            project["digestProfile"] != DIGEST_PROFILE
            or project["contractProfile"] != CONTRACT_PROFILE
            or project["schemaBundleDigest"] != schema_bundle_digest()
            or project["policyEngineVersion"] != POLICY_ENGINE_VERSION
        ):
            raise RuntimeStoreError(
                "ECO_PLAN_PROFILE_MISMATCH", "Plan runtime profile is not trusted"
            )

    def _migrate_or_verify(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id not in {0, STORE_APPLICATION_ID} or user_version not in {0, 2, STORE_SCHEMA_VERSION}:
            raise RuntimeStoreError("ECO_STORE_PROFILE_MISMATCH", "Runtime store profile is unsupported")
        if self._read_only and user_version != STORE_SCHEMA_VERSION:
            raise RuntimeStoreError(
                "ECO_STORE_PROFILE_MISMATCH", "Read-only runtime store requires current schema"
            )
        if user_version == 2:
            self._migrate_v2_to_v3()
            user_version = STORE_SCHEMA_VERSION
        if user_version == 0:
            if self._read_only:
                raise RuntimeStoreError(
                    "ECO_STORE_PROFILE_MISMATCH", "Read-only runtime store is uninitialized"
                )
            self._connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE store_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    store_id TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    digest_profile TEXT NOT NULL,
                    contract_profile TEXT NOT NULL,
                    schema_bundle_digest TEXT NOT NULL,
                    policy_engine_version TEXT NOT NULL,
                    audit_key_id TEXT NOT NULL,
                    producer_issuers_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    meta_hmac TEXT NOT NULL
                );
                CREATE TABLE records (
                    record_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    kind TEXT NOT NULL,
                    record_digest TEXT NOT NULL UNIQUE,
                    canonical_json BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE decisions (
                    decision_id TEXT PRIMARY KEY REFERENCES records(record_id),
                    run_id TEXT NOT NULL,
                    decision_digest TEXT NOT NULL UNIQUE,
                    subject_digest TEXT NOT NULL,
                    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
                    expires_at TEXT NOT NULL,
                    expires_at_epoch_us INTEGER NOT NULL,
                    consumed_at TEXT,
                    consumed_nonce TEXT UNIQUE
                );
                CREATE TABLE nonces (
                    nonce TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    subject_digest TEXT NOT NULL,
                    result_digest TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE audit_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    previous_entry_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    hmac_tag TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN (
                        'NEW', 'RECEIVED', 'VALIDATED', 'PLANNED', 'AUTHORIZED', 'RUNNING',
                        'SUCCEEDED', 'FAILED', 'DENIED', 'CANCELLED', 'EXHAUSTED'
                    )),
                    active_plan_id TEXT,
                    active_plan_digest TEXT,
                    next_event_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_event_sequence >= 1),
                    event_head_digest TEXT,
                    started_at TEXT NOT NULL,
                    deadline_at TEXT,
                    deadline_epoch_us INTEGER,
                    terminal_at TEXT,
                    updated_at TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 0 CHECK (version >= 0)
                );
                CREATE TABLE plans (
                    plan_id TEXT PRIMARY KEY REFERENCES records(record_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    plan_digest TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK (status IN ('issued', 'active', 'terminal')),
                    activated_at TEXT
                );
                CREATE TABLE budgets (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                    plan_digest TEXT NOT NULL UNIQUE,
                    max_duration_seconds INTEGER NOT NULL CHECK (max_duration_seconds > 0),
                    max_model_requests INTEGER NOT NULL CHECK (max_model_requests >= 0),
                    max_tool_requests INTEGER NOT NULL CHECK (max_tool_requests >= 0),
                    max_input_bytes INTEGER NOT NULL CHECK (max_input_bytes >= 0),
                    max_output_bytes INTEGER NOT NULL CHECK (max_output_bytes >= 0),
                    max_total_tokens INTEGER NOT NULL CHECK (max_total_tokens >= 0),
                    max_cost_microusd INTEGER NOT NULL CHECK (max_cost_microusd >= 0),
                    deadline_at TEXT NOT NULL,
                    deadline_epoch_us INTEGER NOT NULL,
                    tool_requests INTEGER NOT NULL DEFAULT 0 CHECK (tool_requests >= 0),
                    input_bytes INTEGER NOT NULL CHECK (input_bytes >= 0),
                    reserved_input_bytes INTEGER NOT NULL DEFAULT 0 CHECK (reserved_input_bytes >= 0),
                    output_bytes INTEGER NOT NULL DEFAULT 0 CHECK (output_bytes >= 0),
                    model_requests INTEGER NOT NULL DEFAULT 0 CHECK (model_requests >= 0),
                    total_tokens INTEGER NOT NULL DEFAULT 0 CHECK (total_tokens >= 0),
                    cost_microusd INTEGER NOT NULL DEFAULT 0 CHECK (cost_microusd >= 0),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE operations (
                    operation_id TEXT PRIMARY KEY REFERENCES records(record_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    idempotency_key_digest TEXT NOT NULL,
                    intent_digest TEXT NOT NULL UNIQUE,
                    tool_request_digest TEXT NOT NULL,
                    allow_decision_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('prepared', 'succeeded', 'failed', 'aborted')),
                    recovery_mode TEXT NOT NULL CHECK (recovery_mode IN ('no_retry')),
                    lease_owner_id TEXT,
                    lease_epoch INTEGER NOT NULL DEFAULT 1 CHECK (lease_epoch >= 1),
                    lease_token_digest TEXT,
                    lease_until_epoch_us INTEGER,
                    receipt_digest TEXT,
                    artifact_record_digest TEXT,
                    error_record_digest TEXT,
                    outcome_digest TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(run_id, idempotency_key_digest),
                    UNIQUE(run_id, tool_request_digest)
                );
                CREATE TABLE budget_reservations (
                    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    plan_digest TEXT NOT NULL,
                    reserved_input_bytes INTEGER NOT NULL CHECK (reserved_input_bytes >= 0),
                    actual_input_bytes INTEGER CHECK (actual_input_bytes >= 0),
                    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'released', 'uncertain')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE run_event_baselines (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                    projection_json BLOB NOT NULL,
                    projection_digest TEXT NOT NULL,
                    next_sequence INTEGER NOT NULL CHECK (next_sequence = 1),
                    head_digest TEXT CHECK (head_digest IS NULL),
                    last_occurred_at TEXT NOT NULL,
                    history_complete INTEGER NOT NULL CHECK (history_complete IN (0, 1)),
                    source TEXT NOT NULL
                );
                CREATE TABLE run_events (
                    event_id TEXT PRIMARY KEY REFERENCES records(record_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    previous_event_digest TEXT,
                    event_digest TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    producer TEXT NOT NULL,
                    producer_issuer TEXT NOT NULL,
                    subject_id TEXT,
                    subject_digest TEXT,
                    result_digest TEXT,
                    occurred_at TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                );
                CREATE TABLE run_checkpoints (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                    checkpoint_id TEXT NOT NULL UNIQUE REFERENCES records(record_id),
                    checkpoint_digest TEXT NOT NULL UNIQUE,
                    run_version INTEGER NOT NULL CHECK (run_version >= 1)
                );
                CREATE TABLE key_rotations (
                    nonce TEXT PRIMARY KEY,
                    transition_digest TEXT NOT NULL UNIQUE,
                    from_key_id TEXT NOT NULL,
                    to_key_id TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE authority_revisions (
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    state_digest TEXT NOT NULL,
                    audit_sequence INTEGER NOT NULL UNIQUE REFERENCES audit_entries(sequence),
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY(entity_type, entity_id, revision)
                );
                CREATE TRIGGER records_immutable_update
                BEFORE UPDATE ON records BEGIN SELECT RAISE(ABORT, 'immutable record'); END;
                CREATE TRIGGER records_immutable_delete
                BEFORE DELETE ON records BEGIN SELECT RAISE(ABORT, 'immutable record'); END;
                CREATE TRIGGER run_event_baselines_immutable_update
                BEFORE UPDATE ON run_event_baselines BEGIN SELECT RAISE(ABORT, 'immutable baseline'); END;
                CREATE TRIGGER run_event_baselines_immutable_delete
                BEFORE DELETE ON run_event_baselines BEGIN SELECT RAISE(ABORT, 'immutable baseline'); END;
                CREATE TRIGGER run_events_immutable_update
                BEFORE UPDATE ON run_events BEGIN SELECT RAISE(ABORT, 'immutable event projection'); END;
                CREATE TRIGGER run_events_immutable_delete
                BEFORE DELETE ON run_events BEGIN SELECT RAISE(ABORT, 'immutable event projection'); END;
                CREATE TRIGGER run_checkpoints_immutable_update
                BEFORE UPDATE ON run_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable checkpoint'); END;
                CREATE TRIGGER run_checkpoints_immutable_delete
                BEFORE DELETE ON run_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable checkpoint'); END;
                CREATE TRIGGER key_rotations_immutable_update
                BEFORE UPDATE ON key_rotations BEGIN SELECT RAISE(ABORT, 'immutable key rotation'); END;
                CREATE TRIGGER key_rotations_immutable_delete
                BEFORE DELETE ON key_rotations BEGIN SELECT RAISE(ABORT, 'immutable key rotation'); END;
                PRAGMA application_id = 1162039089;
                PRAGMA user_version = 3;
                COMMIT;
                """
            )
            now = datetime.now(timezone.utc)
            store_id = secrets.token_hex(16)
            created_at = _utc(now)
            producer_issuers_digest = semantic_digest(
                {"domain": "eco-producer-issuers-v1", "issuers": self._producer_issuers}
            )
            meta_payload = {
                "domain": "eco-store-meta-v1",
                "storeId": store_id,
                "schemaVersion": STORE_SCHEMA_VERSION,
                "digestProfile": DIGEST_PROFILE,
                "contractProfile": CONTRACT_PROFILE,
                "schemaBundleDigest": schema_bundle_digest(),
                "policyEngineVersion": POLICY_ENGINE_VERSION,
                "auditKeyId": self._key_id,
                "producerIssuersDigest": producer_issuers_digest,
                "createdAt": created_at,
            }
            meta_hmac = hmac.new(
                self._hmac_key,
                canonical_json(meta_payload).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            with self._transaction():
                self._connection.execute(
                    """
                    INSERT INTO store_meta VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        store_id,
                        STORE_SCHEMA_VERSION,
                        DIGEST_PROFILE,
                        CONTRACT_PROFILE,
                        schema_bundle_digest(),
                        POLICY_ENGINE_VERSION,
                        self._key_id,
                        producer_issuers_digest,
                        created_at,
                        meta_hmac,
                    ),
                )
        meta = self._connection.execute("SELECT * FROM store_meta WHERE singleton = 1").fetchone()
        if meta is None or (
            meta["schema_version"] != STORE_SCHEMA_VERSION
            or meta["digest_profile"] != DIGEST_PROFILE
            or meta["contract_profile"] != CONTRACT_PROFILE
            or meta["schema_bundle_digest"] != schema_bundle_digest()
            or meta["policy_engine_version"] != POLICY_ENGINE_VERSION
            or meta["audit_key_id"] != self._key_id
            or meta["producer_issuers_digest"]
            != semantic_digest(
                {"domain": "eco-producer-issuers-v1", "issuers": self._producer_issuers}
            )
        ):
            raise RuntimeStoreError("ECO_STORE_PROFILE_MISMATCH", "Runtime store metadata is incompatible")
        meta_payload = {
            "domain": "eco-store-meta-v1",
            "storeId": meta["store_id"],
            "schemaVersion": meta["schema_version"],
            "digestProfile": meta["digest_profile"],
            "contractProfile": meta["contract_profile"],
            "schemaBundleDigest": meta["schema_bundle_digest"],
            "policyEngineVersion": meta["policy_engine_version"],
            "auditKeyId": meta["audit_key_id"],
            "producerIssuersDigest": meta["producer_issuers_digest"],
            "createdAt": meta["created_at"],
        }
        expected_meta_hmac = hmac.new(
            self._hmac_key,
            canonical_json(meta_payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(meta["meta_hmac"], expected_meta_hmac):
            raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Store metadata authentication failed")
        self._store_id = meta["store_id"]

    def _migrate_v2_to_v3(self) -> None:
        """Authenticate the v2 journal, then add event baselines without invented history."""

        if self._connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "SQLite integrity check failed")
        meta = self._connection.execute(
            "SELECT * FROM store_meta WHERE singleton = 1"
        ).fetchone()
        if meta is None or meta["schema_version"] != 2 or meta["audit_key_id"] != self._key_id:
            raise RuntimeStoreError(
                "ECO_STORE_PROFILE_MISMATCH", "Version-2 metadata is incompatible"
            )
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
        expected = hmac.new(
            self._hmac_key, canonical_json(old_payload).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(meta["meta_hmac"], expected):
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Version-2 metadata authentication failed"
            )
        previous = GENESIS_DIGEST
        expected_sequence = 1
        for row in self._connection.execute("SELECT * FROM audit_entries ORDER BY sequence"):
            payload = {
                "domain": "eco-audit-v1",
                "storeId": meta["store_id"],
                "sequence": row["sequence"],
                "transactionId": row["transaction_id"],
                "recordType": row["record_type"],
                "recordId": row["record_id"],
                "action": row["action"],
                "payloadDigest": row["payload_digest"],
                "previousEntryHash": row["previous_entry_hash"],
                "occurredAt": row["occurred_at"],
            }
            entry_hash = semantic_digest(payload)
            tag = hmac.new(self._hmac_key, bytes.fromhex(entry_hash), hashlib.sha256).hexdigest()
            if (
                row["sequence"] != expected_sequence
                or row["previous_entry_hash"] != previous
                or row["entry_hash"] != entry_hash
                or row["key_id"] != self._key_id
                or not hmac.compare_digest(row["hmac_tag"], tag)
            ):
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Version-2 audit authentication failed"
                )
            previous = entry_hash
            expected_sequence += 1
        for row in self._connection.execute("SELECT * FROM records"):
            try:
                record = json.loads(bytes(row["canonical_json"]).decode("utf-8"))
                validate_record(record)
            except (UnicodeDecodeError, json.JSONDecodeError, ContractValidationError) as exc:
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Version-2 record verification failed"
                ) from exc
            if (
                canonical_json(record).encode("utf-8") != bytes(row["canonical_json"])
                or semantic_digest(record) != row["record_digest"]
            ):
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Version-2 record digest differs"
                )
        existing_event_table = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_events'"
        ).fetchone()
        if existing_event_table and self._connection.execute(
            "SELECT 1 FROM run_events LIMIT 1"
        ).fetchone():
            raise RuntimeStoreError(
                "ECO_STORE_PROFILE_MISMATCH", "Version-2 store unexpectedly contains events"
            )

        self._store_id = meta["store_id"]
        issuer_digest = semantic_digest(
            {"domain": "eco-producer-issuers-v1", "issuers": self._producer_issuers}
        )
        with self._transaction():
            run_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(runs)")
            }
            if "next_event_sequence" not in run_columns:
                self._connection.execute(
                    "ALTER TABLE runs ADD COLUMN next_event_sequence INTEGER NOT NULL DEFAULT 1"
                )
            if "event_head_digest" not in run_columns:
                self._connection.execute("ALTER TABLE runs ADD COLUMN event_head_digest TEXT")
            operation_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(operations)")
            }
            if "recovery_mode" not in operation_columns:
                self._connection.execute(
                    "ALTER TABLE operations ADD COLUMN recovery_mode TEXT NOT NULL DEFAULT 'no_retry'"
                )
            meta_columns = {
                row["name"] for row in self._connection.execute("PRAGMA table_info(store_meta)")
            }
            if "producer_issuers_digest" not in meta_columns:
                self._connection.execute(
                    "ALTER TABLE store_meta ADD COLUMN producer_issuers_digest TEXT"
                )
            for statement in (
                """CREATE TABLE IF NOT EXISTS run_event_baselines (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                    projection_json BLOB NOT NULL,
                    projection_digest TEXT NOT NULL,
                    next_sequence INTEGER NOT NULL CHECK (next_sequence = 1),
                    head_digest TEXT CHECK (head_digest IS NULL),
                    last_occurred_at TEXT NOT NULL,
                    history_complete INTEGER NOT NULL CHECK (history_complete IN (0, 1)),
                    source TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS run_events (
                    event_id TEXT PRIMARY KEY REFERENCES records(record_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    sequence INTEGER NOT NULL CHECK (sequence >= 1),
                    previous_event_digest TEXT,
                    event_digest TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL, outcome TEXT NOT NULL,
                    producer TEXT NOT NULL, producer_issuer TEXT NOT NULL,
                    subject_id TEXT, subject_digest TEXT, result_digest TEXT,
                    occurred_at TEXT NOT NULL, UNIQUE(run_id, sequence)
                )""",
                """CREATE TABLE IF NOT EXISTS run_checkpoints (
                    run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
                    checkpoint_id TEXT NOT NULL UNIQUE REFERENCES records(record_id),
                    checkpoint_digest TEXT NOT NULL UNIQUE,
                    run_version INTEGER NOT NULL CHECK (run_version >= 1)
                )""",
                """CREATE TABLE IF NOT EXISTS key_rotations (
                    nonce TEXT PRIMARY KEY, transition_digest TEXT NOT NULL UNIQUE,
                    from_key_id TEXT NOT NULL, to_key_id TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )""",
                """CREATE TRIGGER IF NOT EXISTS run_event_baselines_immutable_update
                BEFORE UPDATE ON run_event_baselines BEGIN SELECT RAISE(ABORT, 'immutable baseline'); END""",
                """CREATE TRIGGER IF NOT EXISTS run_event_baselines_immutable_delete
                BEFORE DELETE ON run_event_baselines BEGIN SELECT RAISE(ABORT, 'immutable baseline'); END""",
                """CREATE TRIGGER IF NOT EXISTS run_events_immutable_update
                BEFORE UPDATE ON run_events BEGIN SELECT RAISE(ABORT, 'immutable event projection'); END""",
                """CREATE TRIGGER IF NOT EXISTS run_events_immutable_delete
                BEFORE DELETE ON run_events BEGIN SELECT RAISE(ABORT, 'immutable event projection'); END""",
                """CREATE TRIGGER IF NOT EXISTS run_checkpoints_immutable_update
                BEFORE UPDATE ON run_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable checkpoint'); END""",
                """CREATE TRIGGER IF NOT EXISTS run_checkpoints_immutable_delete
                BEFORE DELETE ON run_checkpoints BEGIN SELECT RAISE(ABORT, 'immutable checkpoint'); END""",
                """CREATE TRIGGER IF NOT EXISTS key_rotations_immutable_update
                BEFORE UPDATE ON key_rotations BEGIN SELECT RAISE(ABORT, 'immutable key rotation'); END""",
                """CREATE TRIGGER IF NOT EXISTS key_rotations_immutable_delete
                BEFORE DELETE ON key_rotations BEGIN SELECT RAISE(ABORT, 'immutable key rotation'); END""",
            ):
                self._connection.execute(statement)
            transaction_id = secrets.token_hex(16)
            for run in list(self._connection.execute("SELECT * FROM runs ORDER BY run_id")):
                tools: dict[str, tuple[str, str]] = {}
                for operation in self._connection.execute(
                    "SELECT * FROM operations WHERE run_id = ?", (run["run_id"],)
                ):
                    intent_row = self._connection.execute(
                        "SELECT canonical_json FROM records WHERE record_id = ?",
                        (operation["operation_id"],),
                    ).fetchone()
                    if intent_row is None:
                        raise RuntimeStoreError(
                            "ECO_JOURNAL_CORRUPT", "Migrated operation intent is missing"
                        )
                    intent = json.loads(bytes(intent_row["canonical_json"]).decode("utf-8"))
                    phase = {
                        "prepared": "allowed",
                        "succeeded": "completed",
                        "failed": "failed",
                        "aborted": "cancelled",
                    }[operation["state"]]
                    tools[intent["spec"]["toolRequest"]["id"]] = (
                        phase,
                        operation["tool_request_digest"],
                    )
                projection = RunProjection.from_parts(
                    state=RunState(run["state"]),
                    tool_states=tools,
                    adapter_completed=run["state"] == "SUCCEEDED",
                    adapter_failed=False,
                    budget_exhausted=run["state"] == "EXHAUSTED",
                )
                payload = self._projection_payload(projection)
                self._connection.execute(
                    "INSERT INTO run_event_baselines VALUES (?, ?, ?, 1, NULL, ?, 0, 'migration-v2')",
                    (
                        run["run_id"], canonical_json(payload).encode("utf-8"),
                        semantic_digest(payload), run["updated_at"],
                    ),
                )
                self._record_authority_revision(
                    entity_type="event-baseline", entity_id=run["run_id"],
                    table="run_event_baselines", id_column="run_id",
                    transaction_id=transaction_id, occurred_at=run["updated_at"],
                )
                self._record_authority_revision(
                    entity_type="run", entity_id=run["run_id"], table="runs",
                    id_column="run_id", transaction_id=transaction_id,
                    occurred_at=run["updated_at"],
                )
            for operation in self._connection.execute("SELECT * FROM operations"):
                self._record_authority_revision(
                    entity_type="operation", entity_id=operation["operation_id"],
                    table="operations", id_column="operation_id",
                    transaction_id=transaction_id, occurred_at=operation["updated_at"],
                )
            new_payload = dict(old_payload)
            new_payload["schemaVersion"] = STORE_SCHEMA_VERSION
            new_payload["producerIssuersDigest"] = issuer_digest
            new_hmac = hmac.new(
                self._hmac_key, canonical_json(new_payload).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            self._connection.execute(
                """UPDATE store_meta SET schema_version = ?, producer_issuers_digest = ?,
                   meta_hmac = ? WHERE singleton = 1""",
                (STORE_SCHEMA_VERSION, issuer_digest, new_hmac),
            )
            self._connection.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _record_identity(record: dict[str, Any]) -> tuple[str, str | None, str]:
        metadata = record["metadata"]
        record_id = metadata["id"]
        run_id = metadata.get("runId")
        created_at = metadata.get(
            "createdAt",
            metadata.get("testedAt", metadata.get("resolvedAt", metadata.get("occurredAt"))),
        )
        if not isinstance(created_at, str):
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Record has no safe timestamp")
        return record_id, run_id, created_at

    def _insert_record(self, record: dict[str, Any]) -> tuple[str, bool]:
        try:
            record = validate_record(record)
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Runtime record is invalid") from exc
        if record["kind"] not in SAFE_JOURNAL_KINDS:
            raise RuntimeStoreError("ECO_STORE_RECORD_UNSAFE", "Record kind may contain sensitive runtime data")
        record_id, run_id, created_at = self._record_identity(record)
        record_digest = semantic_digest(record)
        encoded = canonical_json(record).encode("utf-8")
        existing = self._connection.execute(
            "SELECT record_digest FROM records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if existing is not None:
            if existing["record_digest"] != record_digest:
                raise RuntimeStoreError("ECO_STORE_ID_CONFLICT", "Record id is bound to another digest")
            return record_digest, False
        self._connection.execute(
            "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)",
            (record_id, run_id, record["kind"], record_digest, encoded, created_at),
        )
        return record_digest, True

    def _append_audit(
        self,
        *,
        transaction_id: str,
        record_type: str,
        record_id: str,
        action: str,
        payload_digest: str,
        occurred_at: str,
    ) -> int:
        previous = self._connection.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else GENESIS_DIGEST
        next_sequence = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_entries"
        ).fetchone()[0]
        payload = {
            "domain": "eco-audit-v1",
            "storeId": self._store_id,
            "sequence": next_sequence,
            "transactionId": transaction_id,
            "recordType": record_type,
            "recordId": record_id,
            "action": action,
            "payloadDigest": payload_digest,
            "previousEntryHash": previous_hash,
            "occurredAt": occurred_at,
        }
        entry_hash = semantic_digest(payload)
        tag = hmac.new(self._hmac_key, bytes.fromhex(entry_hash), hashlib.sha256).hexdigest()
        self._connection.execute(
            """
            INSERT INTO audit_entries
            (transaction_id, record_type, record_id, action, payload_digest,
             previous_entry_hash, entry_hash, hmac_tag, key_id, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                transaction_id,
                record_type,
                record_id,
                action,
                payload_digest,
                previous_hash,
                entry_hash,
                tag,
                self._key_id,
                occurred_at,
            ),
        )
        return int(next_sequence)

    @staticmethod
    def _authority_state_digest(
        entity_type: str, entity_id: str, row: sqlite3.Row
    ) -> str:
        state = {
            key: (
                bytes(value).decode("utf-8")
                if isinstance(value, (bytes, bytearray, memoryview))
                else value
            )
            for key, value in dict(row).items()
        }
        return semantic_digest(
            {
                "domain": "eco-authority-state-v1",
                "entityType": entity_type,
                "entityId": entity_id,
                "state": state,
            }
        )

    def _record_authority_revision(
        self,
        *,
        entity_type: str,
        entity_id: str,
        table: str,
        id_column: str,
        transaction_id: str,
        occurred_at: str,
    ) -> str:
        if table not in {
            "runs",
            "plans",
            "budgets",
            "operations",
            "budget_reservations",
            "run_event_baselines",
            "run_checkpoints",
        }:
            raise RuntimeStoreError("ECO_STORE_INTERNAL", "Unsupported authority entity")
        row = self._connection.execute(
            f"SELECT * FROM {table} WHERE {id_column} = ?", (entity_id,)
        ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_STORE_INTERNAL", "Authority entity is missing")
        state_digest = self._authority_state_digest(entity_type, entity_id, row)
        revision = self._connection.execute(
            """
            SELECT COALESCE(MAX(revision), 0) + 1
            FROM authority_revisions WHERE entity_type = ? AND entity_id = ?
            """,
            (entity_type, entity_id),
        ).fetchone()[0]
        sequence = self._append_audit(
            transaction_id=transaction_id,
            record_type=entity_type,
            record_id=entity_id,
            action="authority-state",
            payload_digest=state_digest,
            occurred_at=occurred_at,
        )
        self._connection.execute(
            "INSERT INTO authority_revisions VALUES (?, ?, ?, ?, ?, ?)",
            (entity_type, entity_id, revision, state_digest, sequence, occurred_at),
        )
        return state_digest

    def put_record(self, record: dict[str, Any]) -> str:
        try:
            record = copy.deepcopy(validate_record(record))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Runtime record is invalid") from exc
        if record["kind"] in AUTHORITY_MANAGED_KINDS:
            raise RuntimeStoreError(
                "ECO_STORE_AUTHORITY_REQUIRED",
                "Record kind must be written through its authority transaction",
            )
        record_id, _, occurred_at = self._record_identity(record)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            digest, inserted = self._insert_record(record)
            if inserted:
                self._append_audit(
                    transaction_id=transaction_id,
                    record_type=record["kind"],
                    record_id=record_id,
                    action="recorded",
                    payload_digest=digest,
                    occurred_at=occurred_at,
                )
        return digest

    def start_run(
        self,
        run_id: str,
        request: dict[str, Any],
        *,
        runtime_capability: object,
    ) -> str:
        """Create a fresh complete-history run and durably record ``run.received``."""

        self._require_runtime_capability(runtime_capability)
        if not isinstance(run_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", run_id) is None:
            raise ValueError("run_id must be a bounded identifier")
        try:
            request = copy.deepcopy(validate_record(request))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Run request is invalid") from exc
        if request["kind"] != "RunRequest":
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Expected RunRequest")
        request_digest = semantic_digest(request)
        occurred_at = request["metadata"]["createdAt"]
        now = _parse(occurred_at)
        transaction_id = secrets.token_hex(16)
        initial = self._projection_payload(RunProjection.initial())
        with self._transaction():
            if self._connection.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone() is not None:
                raise RuntimeStoreError("ECO_RUN_CONFLICT", "Run identifier already exists")
            digest, inserted = self._insert_record(request)
            if not inserted:
                raise RuntimeStoreError(
                    "ECO_RUN_REQUEST_REUSED", "Run request is already bound elsewhere"
                )
            self._append_audit(
                transaction_id=transaction_id,
                record_type="RunRequest",
                record_id=request["metadata"]["id"],
                action="recorded",
                payload_digest=digest,
                occurred_at=occurred_at,
            )
            self._connection.execute(
                """
                INSERT INTO runs
                (run_id, request_digest, state, active_plan_id, active_plan_digest,
                 next_event_sequence, event_head_digest, started_at, deadline_at,
                 deadline_epoch_us, terminal_at, updated_at, version)
                VALUES (?, ?, 'NEW', NULL, NULL, 1, NULL, ?, NULL, NULL, NULL, ?, 1)
                """,
                (run_id, request_digest, occurred_at, occurred_at),
            )
            self._connection.execute(
                "INSERT INTO run_event_baselines VALUES (?, ?, ?, 1, NULL, ?, 1, 'native-v1')",
                (
                    run_id,
                    canonical_json(initial).encode("utf-8"),
                    semantic_digest(initial),
                    occurred_at,
                ),
            )
            self._record_authority_revision(
                entity_type="event-baseline",
                entity_id=run_id,
                table="run_event_baselines",
                id_column="run_id",
                transaction_id=transaction_id,
                occurred_at=occurred_at,
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="run.received",
                producer="runtime",
                producer_capability=runtime_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=request["metadata"]["id"],
                subject_digest=request_digest,
            )
        return request_digest

    def validate_run(
        self, run_id: str, *, now: datetime, runtime_capability: object
    ) -> dict[str, Any]:
        """Advance a received run after external contract/config validation."""

        self._require_runtime_capability(runtime_capability)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            run = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
            if run["state"] == "VALIDATED":
                return dict(run)
            if run["state"] != "RECEIVED":
                raise RuntimeStoreError("ECO_RUN_STATE", "Run is not awaiting validation")
            request_row = self._connection.execute(
                "SELECT * FROM records WHERE record_digest = ? AND kind = 'RunRequest'",
                (run["request_digest"],),
            ).fetchone()
            if request_row is None:
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Run request is missing")
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="run.validated",
                producer="runtime",
                producer_capability=runtime_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=request_row["record_id"],
                subject_digest=run["request_digest"],
            )
            return dict(
                self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            )

    def issue_plan(
        self,
        plan: dict[str, Any],
        decision: dict[str, Any],
        *,
        policy_capability: object,
        runtime_capability: object | None = None,
    ) -> str:
        """Durably bind a sanitized plan and its policy decision to one run."""

        self._require_policy_capability(policy_capability)
        try:
            plan = copy.deepcopy(validate_record(plan))
            decision = copy.deepcopy(validate_record(decision))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Plan or decision is invalid") from exc
        if plan["kind"] != "RunPlan" or decision["kind"] != "PolicyDecision":
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Expected RunPlan and PolicyDecision")
        plan_digest = semantic_digest(plan)
        self._require_plan_profile(plan)
        self._require_decision_profile(
            decision, semantic_config_digest=plan["spec"]["project"]["semanticConfigDigest"]
        )
        run_id = plan["metadata"]["runId"]
        subject = decision["spec"]["subject"]
        if (
            decision["metadata"]["runId"] != run_id
            or subject["kind"] != "RunPlan"
            or subject["id"] != plan["metadata"]["id"]
            or subject["digest"] != plan_digest
        ):
            raise RuntimeStoreError("ECO_DECISION_MISMATCH", "Plan decision binding is invalid")
        occurred_at = plan["metadata"]["createdAt"]
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            stored_digest, plan_record_inserted = self._insert_record(plan)
            if plan_record_inserted:
                self._append_audit(
                    transaction_id=transaction_id,
                    record_type="RunPlan",
                    record_id=plan["metadata"]["id"],
                    action="recorded",
                    payload_digest=stored_digest,
                    occurred_at=occurred_at,
                )
            run = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            run_inserted = run is None
            native_plan_event = run is not None and run["state"] == "VALIDATED"
            legacy_history = False
            if run is not None:
                baseline_row = self._connection.execute(
                    "SELECT history_complete FROM run_event_baselines WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                legacy_history = baseline_row is not None and not bool(
                    baseline_row["history_complete"]
                )
            baseline_inserted = False
            if run is None:
                self._connection.execute(
                    """
                    INSERT INTO runs
                    (run_id, request_digest, state, active_plan_id, active_plan_digest,
                     next_event_sequence, event_head_digest, started_at, deadline_at,
                     deadline_epoch_us, terminal_at, updated_at, version)
                    VALUES (?, ?, 'PLANNED', NULL, NULL, 1, NULL, ?, NULL, NULL, NULL, ?, 1)
                    """,
                    (run_id, plan["spec"]["requestDigest"], occurred_at, occurred_at),
                )
                self._connection.execute(
                    """
                    INSERT INTO run_event_baselines
                    VALUES (?, ?, ?, 1, NULL, ?, 0, 'issue-plan-bootstrap-v1')
                    """,
                    (
                        run_id,
                        canonical_json(
                            self._projection_payload(RunProjection(state=RunState.PLANNED))
                        ).encode("utf-8"),
                        semantic_digest(
                            self._projection_payload(RunProjection(state=RunState.PLANNED))
                        ),
                        occurred_at,
                    ),
                )
                baseline_inserted = True
            elif run["request_digest"] != plan["spec"]["requestDigest"]:
                raise RuntimeStoreError("ECO_RUN_CONFLICT", "Run is bound to another request")
            elif native_plan_event:
                self._require_runtime_capability(runtime_capability)
            elif run["state"] != "PLANNED" and not legacy_history:
                raise RuntimeStoreError("ECO_RUN_STATE", "Run is not awaiting a plan")
            existing_plan = self._connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan["metadata"]["id"],)
            ).fetchone()
            plan_inserted = existing_plan is None
            if existing_plan is None:
                self._connection.execute(
                    "INSERT INTO plans VALUES (?, ?, ?, 'issued', NULL)",
                    (plan["metadata"]["id"], run_id, plan_digest),
                )
            elif (
                existing_plan["run_id"] != run_id
                or existing_plan["plan_digest"] != plan_digest
            ):
                raise RuntimeStoreError("ECO_STORE_ID_CONFLICT", "Plan id has another binding")
            self._issue_decision_tx(decision, transaction_id=transaction_id)
            if native_plan_event:
                self._append_generated_event_tx(
                    run_id=run_id,
                    event_type="plan.created",
                    producer="runtime",
                    producer_capability=runtime_capability,
                    now=_parse(occurred_at),
                    transaction_id=transaction_id,
                    subject_id=plan["metadata"]["id"],
                    subject_digest=plan_digest,
                )
            if run_inserted:
                self._record_authority_revision(
                    entity_type="run",
                    entity_id=run_id,
                    table="runs",
                    id_column="run_id",
                    transaction_id=transaction_id,
                    occurred_at=occurred_at,
                )
            if baseline_inserted:
                self._record_authority_revision(
                    entity_type="event-baseline",
                    entity_id=run_id,
                    table="run_event_baselines",
                    id_column="run_id",
                    transaction_id=transaction_id,
                    occurred_at=occurred_at,
                )
            if plan_inserted:
                self._record_authority_revision(
                    entity_type="plan",
                    entity_id=plan["metadata"]["id"],
                    table="plans",
                    id_column="plan_id",
                    transaction_id=transaction_id,
                    occurred_at=occurred_at,
                )
        return plan_digest

    def activate_plan(
        self,
        plan: dict[str, Any],
        decision: dict[str, Any],
        *,
        nonce: str,
        now: datetime,
        policy_capability: object,
    ) -> dict[str, Any]:
        """Consume the plan allow once and initialize its absolute durable budget."""

        self._require_policy_capability(policy_capability)
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        try:
            plan = copy.deepcopy(validate_record(plan))
            decision = copy.deepcopy(validate_record(decision))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Plan or decision is invalid") from exc
        if plan["kind"] != "RunPlan" or decision["kind"] != "PolicyDecision":
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Expected RunPlan and PolicyDecision")
        run_id = plan["metadata"]["runId"]
        plan_id = plan["metadata"]["id"]
        plan_digest = semantic_digest(plan)
        self._require_plan_profile(plan)
        self._require_decision_profile(
            decision, semantic_config_digest=plan["spec"]["project"]["semanticConfigDigest"]
        )
        subject = decision["spec"]["subject"]
        if (
            decision["metadata"]["runId"] != run_id
            or decision["spec"]["effect"] != "allow"
            or subject != {"kind": "RunPlan", "id": plan_id, "digest": plan_digest}
        ):
            raise RuntimeStoreError("ECO_DECISION_MISMATCH", "Plan decision binding is invalid")
        now_text = _utc(now)
        budget = plan["spec"]["budget"]
        initial_input_bytes = sum(item["byteLength"] for item in plan["spec"]["inputs"])
        if initial_input_bytes > budget["maxInputBytes"]:
            raise RuntimeStoreError("ECO_BUDGET_EXHAUSTED", "Initial inputs exceed input budget")
        deadline = _parse(plan["metadata"]["createdAt"]) + timedelta(
            seconds=budget["maxDurationSeconds"]
        )
        if now.astimezone(timezone.utc) >= deadline:
            raise RuntimeStoreError("ECO_DEADLINE_EXCEEDED", "Plan deadline has elapsed")
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            plan_row = self._connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            run_row = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if (
                plan_row is None
                or run_row is None
                or plan_row["plan_digest"] != plan_digest
                or plan_row["run_id"] != run_id
            ):
                raise RuntimeStoreError("ECO_PLAN_UNTRUSTED", "Plan was not durably issued")
            if run_row["active_plan_id"] is not None:
                if (
                    run_row["active_plan_id"] != plan_id
                    or run_row["active_plan_digest"] != plan_digest
                ):
                    raise RuntimeStoreError("ECO_PLAN_CONFLICT", "Another plan is already active")
                self._consume_decision_tx(
                    decision,
                    subject_digest=plan_digest,
                    nonce=nonce,
                    now=now,
                    transaction_id=transaction_id,
                )
                return self._budget_status_tx(run_id)
            self._consume_decision_tx(
                decision,
                subject_digest=plan_digest,
                nonce=nonce,
                now=now,
                transaction_id=transaction_id,
            )
            deadline_text = _utc(deadline)
            deadline_epoch_us = int(deadline.timestamp() * 1_000_000)
            self._connection.execute(
                """
                UPDATE runs
                SET active_plan_id = ?, active_plan_digest = ?,
                    deadline_at = ?, deadline_epoch_us = ?, updated_at = ?
                WHERE run_id = ? AND active_plan_id IS NULL
                """,
                (plan_id, plan_digest, deadline_text, deadline_epoch_us, now_text, run_id),
            )
            self._connection.execute(
                "UPDATE plans SET status = 'active', activated_at = ? WHERE plan_id = ?",
                (now_text, plan_id),
            )
            self._connection.execute(
                """
                INSERT INTO budgets
                (run_id, plan_digest, max_duration_seconds, max_model_requests,
                 max_tool_requests, max_input_bytes, max_output_bytes, max_total_tokens,
                 max_cost_microusd, deadline_at, deadline_epoch_us, tool_requests,
                 input_bytes, reserved_input_bytes, output_bytes, model_requests,
                 total_tokens, cost_microusd, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, 0, 0, 0, 0, ?)
                """,
                (
                    run_id,
                    plan_digest,
                    budget["maxDurationSeconds"],
                    budget["maxModelRequests"],
                    budget["maxToolRequests"],
                    budget["maxInputBytes"],
                    budget["maxOutputBytes"],
                    budget["maxTotalTokens"],
                    budget["maxCostMicrousd"],
                    deadline_text,
                    deadline_epoch_us,
                    initial_input_bytes,
                    now_text,
                ),
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="policy.allowed",
                producer="policy",
                producer_capability=policy_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=plan_id,
                subject_digest=plan_digest,
                result_digest=semantic_digest(decision),
            )
            for entity_type, entity_id, table, id_column in (
                ("plan", plan_id, "plans", "plan_id"),
                ("budget", run_id, "budgets", "run_id"),
            ):
                self._record_authority_revision(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    table=table,
                    id_column=id_column,
                    transaction_id=transaction_id,
                    occurred_at=now_text,
                )
            return self._budget_status_tx(run_id)

    def deny_plan(
        self,
        plan: dict[str, Any],
        decision: dict[str, Any],
        *,
        nonce: str,
        now: datetime,
        policy_capability: object,
    ) -> dict[str, Any]:
        """Apply one durably issued deny decision and terminate the planned run."""

        self._require_policy_capability(policy_capability)
        plan = copy.deepcopy(validate_record(plan))
        decision = copy.deepcopy(validate_record(decision))
        plan_digest = semantic_digest(plan)
        decision_digest = semantic_digest(decision)
        run_id = plan["metadata"]["runId"]
        self._require_plan_profile(plan)
        self._require_decision_profile(
            decision, semantic_config_digest=plan["spec"]["project"]["semanticConfigDigest"]
        )
        if decision["spec"]["effect"] != "deny" or decision["spec"]["subject"] != {
            "kind": "RunPlan", "id": plan["metadata"]["id"], "digest": plan_digest,
        }:
            raise RuntimeStoreError("ECO_DECISION_MISMATCH", "Plan denial binding is invalid")
        transaction_id = secrets.token_hex(16)
        now_text = _utc(now)
        with self._transaction():
            plan_row = self._connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan["metadata"]["id"],)
            ).fetchone()
            run = self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if (
                plan_row is None or run is None or plan_row["plan_digest"] != plan_digest
                or run["state"] != "PLANNED"
            ):
                raise RuntimeStoreError("ECO_PLAN_UNTRUSTED", "Plan is not awaiting policy")
            self._issue_decision_tx(decision, transaction_id=transaction_id)
            self._consume_decision_tx(
                decision, subject_digest=plan_digest, nonce=nonce, now=now,
                transaction_id=transaction_id,
            )
            self._connection.execute(
                "UPDATE plans SET status = 'terminal' WHERE plan_id = ?",
                (plan["metadata"]["id"],),
            )
            self._append_generated_event_tx(
                run_id=run_id, event_type="policy.denied", producer="policy",
                producer_capability=policy_capability, now=now,
                transaction_id=transaction_id, subject_id=plan["metadata"]["id"],
                subject_digest=plan_digest, result_digest=decision_digest,
            )
            self._record_authority_revision(
                entity_type="plan", entity_id=plan["metadata"]["id"], table="plans",
                id_column="plan_id", transaction_id=transaction_id, occurred_at=now_text,
            )
            return dict(
                self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            )

    def _budget_status_tx(self, run_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT * FROM budgets WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_BUDGET_UNINITIALIZED", "Run budget is unavailable")
        return dict(row)

    def budget_status(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            return self._budget_status_tx(run_id)

    def run_status(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
            baseline = self._connection.execute(
                "SELECT history_complete, source FROM run_event_baselines WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            result = dict(row)
            result["history_complete"] = bool(baseline["history_complete"])
            result["history_source"] = baseline["source"]
            return result

    def event_history(self, run_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT r.canonical_json
                FROM run_events AS e JOIN records AS r ON r.record_id = e.event_id
                WHERE e.run_id = ? ORDER BY e.sequence
                """,
                (run_id,),
            ).fetchall()
            return tuple(json.loads(bytes(row["canonical_json"]).decode("utf-8")) for row in rows)

    @staticmethod
    def _projection_payload(projection: RunProjection) -> dict[str, Any]:
        return {
            "state": projection.state.value,
            "toolStates": [list(item) for item in projection.tool_states],
            "adapterCompleted": projection.adapter_completed,
            "adapterFailed": projection.adapter_failed,
            "budgetExhausted": projection.budget_exhausted,
        }

    @staticmethod
    def _projection_from_payload(payload: dict[str, Any]) -> RunProjection:
        try:
            tool_states = tuple(
                (str(subject_id), str(phase), str(subject_digest))
                for subject_id, phase, subject_digest in payload["toolStates"]
            )
            projection = RunProjection(
                state=RunState(payload["state"]),
                tool_states=tool_states,
                adapter_completed=payload["adapterCompleted"],
                adapter_failed=payload["adapterFailed"],
                budget_exhausted=payload["budgetExhausted"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run event baseline projection is invalid"
            ) from exc
        if SQLiteRuntimeStore._projection_payload(projection) != payload:
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run event baseline projection is non-canonical"
            )
        return projection

    def _replay_event_projection_tx(
        self, run_id: str
    ) -> tuple[RunProjection, int, str | None, datetime]:
        baseline = self._connection.execute(
            "SELECT * FROM run_event_baselines WHERE run_id = ?", (run_id,)
        ).fetchone()
        if baseline is None:
            raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Run event baseline is missing")
        try:
            projection_payload = json.loads(
                bytes(baseline["projection_json"]).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run event baseline projection is unreadable"
            ) from exc
        if (
            canonical_json(projection_payload).encode("utf-8")
            != bytes(baseline["projection_json"])
            or semantic_digest(projection_payload) != baseline["projection_digest"]
        ):
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run event baseline projection digest differs"
            )
        projection = self._projection_from_payload(projection_payload)
        expected_sequence = int(baseline["next_sequence"])
        head = baseline["head_digest"]
        occurred_at = _parse(baseline["last_occurred_at"])
        rows = self._connection.execute(
            """
            SELECT e.*, r.canonical_json
            FROM run_events AS e JOIN records AS r ON r.record_id = e.event_id
            WHERE e.run_id = ? ORDER BY e.sequence
            """,
            (run_id,),
        ).fetchall()
        for row in rows:
            event = json.loads(bytes(row["canonical_json"]).decode("utf-8"))
            metadata = event.get("metadata", {})
            spec = event.get("spec", {})
            event_time = _parse(event["metadata"]["occurredAt"])
            semantics = EVENT_SEMANTICS.get(spec.get("type"))
            if (
                event.get("kind") != "RunEvent"
                or row["sequence"] != expected_sequence
                or row["previous_event_digest"] != head
                or metadata.get("runId") != run_id
                or metadata.get("sequence") != expected_sequence
                or metadata.get("previousEventDigest") != head
                or metadata.get("producer") != row["producer"]
                or metadata.get("producerIssuer") != row["producer_issuer"]
                or metadata.get("occurredAt") != row["occurred_at"]
                or row["event_digest"] != semantic_digest(event)
                or row["event_type"] != spec.get("type")
                or row["outcome"] != spec.get("outcome")
                or row["subject_id"] != spec.get("subjectId")
                or row["subject_digest"] != spec.get("subjectDigest")
                or row["result_digest"] != spec.get("resultDigest")
                or semantics is None
                or spec.get("outcome") != semantics[0]
                or metadata.get("producer") not in semantics[1]
                or metadata.get("producerIssuer")
                != self._producer_issuers.get(metadata.get("producer"))
                or event_time < occurred_at
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Run event chain is inconsistent")
            try:
                projection = reduce_run_event(projection, spec["type"], spec)
            except RuntimeStateError as exc:
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Run event reducer replay failed"
                ) from exc
            head = semantic_digest(event)
            occurred_at = event_time
            expected_sequence += 1
        return projection, expected_sequence, head, occurred_at

    def _append_generated_event_tx(
        self,
        *,
        run_id: str,
        event_type: str,
        producer: str,
        producer_capability: object,
        now: datetime,
        transaction_id: str,
        subject_id: str | None = None,
        subject_digest: str | None = None,
        result_digest: str | None = None,
    ) -> str:
        semantics = EVENT_SEMANTICS.get(event_type)
        if semantics is None:
            raise RuntimeStoreError("ECO_EVENT_INVALID", "Event type is unsupported")
        expected_outcome, allowed_producers = semantics
        if producer not in allowed_producers or producer_capability is not self._producer_capabilities[producer]:
            raise RuntimeStoreError("ECO_EVENT_PRODUCER_UNTRUSTED", "Event producer is not trusted")
        run = self._connection.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
        projection, sequence, head, last_occurred_at = self._replay_event_projection_tx(run_id)
        if (
            projection.state.value != run["state"]
            or sequence != run["next_event_sequence"]
            or head != run["event_head_digest"]
        ):
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run cache differs from event replay"
            )
        if projection.state in TERMINAL_STATES:
            raise RuntimeStoreError("ECO_RUN_TERMINAL", "No event may follow a terminal state")
        now_text = _utc(now)
        if now.astimezone(timezone.utc) < last_occurred_at:
            raise RuntimeStoreError("ECO_EVENT_TIME_REVERSED", "Event time moved backwards")
        spec: dict[str, Any] = {"type": event_type, "outcome": expected_outcome}
        if subject_id is not None:
            spec["subjectId"] = subject_id
        if subject_digest is not None:
            spec["subjectDigest"] = subject_digest
        if result_digest is not None:
            spec["resultDigest"] = result_digest
        next_projection = reduce_run_event(projection, event_type, spec)
        event_id = f"evt-{semantic_digest({'runId': run_id})[:16]}-{sequence}"
        event = validate_record(
            {
                "apiVersion": "runtime.ai.ecosystem/v1alpha1",
                "kind": "RunEvent",
                "metadata": {
                    "id": event_id,
                    "runId": run_id,
                    "sequence": sequence,
                    "occurredAt": now_text,
                    "producer": producer,
                    "producerIssuer": self._producer_issuers[producer],
                    "previousEventDigest": head,
                },
                "spec": spec,
            }
        )
        event_digest, inserted = self._insert_record(event)
        if not inserted:
            raise RuntimeStoreError("ECO_EVENT_ID_REUSED", "Generated event id already exists")
        self._append_audit(
            transaction_id=transaction_id,
            record_type="RunEvent",
            record_id=event_id,
            action="recorded",
            payload_digest=event_digest,
            occurred_at=now_text,
        )
        self._connection.execute(
            """
            INSERT INTO run_events
            (event_id, run_id, sequence, previous_event_digest, event_digest,
             event_type, outcome, producer, producer_issuer, subject_id,
             subject_digest, result_digest, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                run_id,
                sequence,
                head,
                event_digest,
                event_type,
                expected_outcome,
                producer,
                self._producer_issuers[producer],
                subject_id,
                subject_digest,
                result_digest,
                now_text,
            ),
        )
        terminal_at = now_text if next_projection.state in TERMINAL_STATES else run["terminal_at"]
        self._connection.execute(
            """
            UPDATE runs
            SET state = ?, next_event_sequence = ?, event_head_digest = ?,
                terminal_at = ?, updated_at = ?, version = version + 1
            WHERE run_id = ?
            """,
            (
                next_projection.state.value,
                sequence + 1,
                event_digest,
                terminal_at,
                now_text,
                run_id,
            ),
        )
        self._record_authority_revision(
            entity_type="run",
            entity_id=run_id,
            table="runs",
            id_column="run_id",
            transaction_id=transaction_id,
            occurred_at=now_text,
        )
        return event_digest

    def start_adapter(
        self,
        run_id: str,
        *,
        now: datetime,
        adapter_capability: object,
    ) -> str:
        self._require_adapter_capability(adapter_capability)
        with self._transaction():
            return self._append_generated_event_tx(
                run_id=run_id,
                event_type="adapter.started",
                producer="adapter",
                producer_capability=adapter_capability,
                now=now,
                transaction_id=secrets.token_hex(16),
            )

    def complete_adapter(
        self, run_id: str, *, now: datetime, adapter_capability: object
    ) -> str:
        self._require_adapter_capability(adapter_capability)
        with self._transaction():
            return self._append_generated_event_tx(
                run_id=run_id,
                event_type="adapter.completed",
                producer="adapter",
                producer_capability=adapter_capability,
                now=now,
                transaction_id=secrets.token_hex(16),
            )

    def fail_adapter(
        self, run_id: str, *, now: datetime, adapter_capability: object
    ) -> str:
        self._require_adapter_capability(adapter_capability)
        with self._transaction():
            return self._append_generated_event_tx(
                run_id=run_id,
                event_type="adapter.failed",
                producer="adapter",
                producer_capability=adapter_capability,
                now=now,
                transaction_id=secrets.token_hex(16),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        outcome: str,
        now: datetime,
        runtime_capability: object,
    ) -> str:
        """Commit one explicit terminal run event after reducer preconditions pass."""

        self._require_runtime_capability(runtime_capability)
        event_types = {
            "succeeded": "run.succeeded",
            "failed": "run.failed",
            "cancelled": "run.cancelled",
            "exhausted": "run.exhausted",
        }
        try:
            event_type = event_types[outcome]
        except KeyError as exc:
            raise ValueError("outcome must be succeeded, failed, cancelled, or exhausted") from exc
        with self._transaction():
            return self._append_generated_event_tx(
                run_id=run_id,
                event_type=event_type,
                producer="runtime",
                producer_capability=runtime_capability,
                now=now,
                transaction_id=secrets.token_hex(16),
            )

    def create_terminal_checkpoint(
        self, run_id: str, *, now: datetime, runtime_capability: object
    ) -> dict[str, Any]:
        """Create the sole immutable checkpoint after a run becomes terminal."""

        self._require_runtime_capability(runtime_capability)
        now_text = _utc(now)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT checkpoint_id FROM run_checkpoints WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None:
                return self._load_record_tx(existing["checkpoint_id"])
            run = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
            projection, next_sequence, head_digest, last_occurred_at = (
                self._replay_event_projection_tx(run_id)
            )
            if projection.state not in TERMINAL_STATES:
                raise RuntimeStoreError(
                    "ECO_CHECKPOINT_NOT_TERMINAL", "Only terminal runs may be checkpointed"
                )
            if now.astimezone(timezone.utc) < last_occurred_at:
                raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Runtime clock moved backwards")
            budget = self._connection.execute(
                "SELECT * FROM budgets WHERE run_id = ?", (run_id,)
            ).fetchone()
            if budget is None or run["active_plan_id"] is None:
                raise RuntimeStoreError(
                    "ECO_CHECKPOINT_UNAVAILABLE", "Terminal run has no active budget"
                )
            plan = self._load_record_tx(run["active_plan_id"])
            baseline = self._connection.execute(
                "SELECT * FROM run_event_baselines WHERE run_id = ?", (run_id,)
            ).fetchone()
            open_operations = [
                row["operation_id"]
                for row in self._connection.execute(
                    "SELECT operation_id FROM operations WHERE run_id = ? AND state = 'prepared' ORDER BY operation_id",
                    (run_id,),
                )
            ]
            if open_operations:
                raise RuntimeStoreError(
                    "ECO_CHECKPOINT_OPEN_OPERATIONS", "Terminal checkpoint has open operations"
                )
            checkpoint_id = (
                f"checkpoint-{semantic_digest({'runId': run_id})[:16]}-{run['version']}"
            )
            checkpoint = validate_record(
                {
                    "apiVersion": "runtime.ai.ecosystem/v1alpha1",
                    "kind": "RunCheckpoint",
                    "metadata": {
                        "id": checkpoint_id,
                        "runId": run_id,
                        "revision": run["version"],
                        "createdAt": now_text,
                    },
                    "spec": {
                        "state": projection.state.value,
                        "projection": self._projection_payload(projection),
                        "historyComplete": bool(baseline["history_complete"]),
                        "historySource": baseline["source"],
                        "eventSequence": next_sequence - 1,
                        "eventHeadDigest": head_digest,
                        "activePlanDigest": run["active_plan_digest"],
                        "budget": {
                            "limitsDigest": semantic_digest(
                                {"domain": "eco-budget-limits-v1", "limits": plan["spec"]["budget"]}
                            ),
                            "toolRequests": budget["tool_requests"],
                            "inputBytes": budget["input_bytes"],
                            "reservedInputBytes": budget["reserved_input_bytes"],
                            "outputBytes": budget["output_bytes"],
                            "modelRequests": budget["model_requests"],
                            "totalTokens": budget["total_tokens"],
                            "costMicrousd": budget["cost_microusd"],
                        },
                        "openOperationIds": open_operations,
                        "startedAt": run["started_at"],
                        "deadlineAt": run["deadline_at"],
                    },
                }
            )
            checkpoint_digest, inserted = self._insert_record(checkpoint)
            if not inserted:
                raise RuntimeStoreError("ECO_CHECKPOINT_CONFLICT", "Checkpoint id already exists")
            self._append_audit(
                transaction_id=transaction_id,
                record_type="RunCheckpoint",
                record_id=checkpoint_id,
                action="recorded",
                payload_digest=checkpoint_digest,
                occurred_at=now_text,
            )
            self._connection.execute(
                "INSERT INTO run_checkpoints VALUES (?, ?, ?, ?)",
                (run_id, checkpoint_id, checkpoint_digest, run["version"]),
            )
            self._record_authority_revision(
                entity_type="checkpoint", entity_id=run_id,
                table="run_checkpoints", id_column="run_id",
                transaction_id=transaction_id, occurred_at=now_text,
            )
            return checkpoint

    def path_reference_digest(self, path: str) -> str:
        """Return a store-scoped opaque path reference, not a guessable plain hash."""

        if not isinstance(path, str) or not path:
            raise ValueError("path must be a non-empty string")
        payload = canonical_json({"domain": "eco-path-reference-v1", "path": path}).encode()
        return hmac.new(self._path_hmac_key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _lease_token_digest(token: str) -> str:
        return semantic_digest({"domain": "eco-operation-lease-v1", "token": token})

    def prepare_repository_read(
        self,
        plan: dict[str, Any],
        snapshot: dict[str, Any],
        tool_request: dict[str, Any],
        decision: dict[str, Any],
        intent: dict[str, Any],
        *,
        owner_id: str,
        now: datetime,
        policy_capability: object,
        broker_capability: object,
        runtime_capability: object,
        lease_seconds: int = 30,
    ) -> dict[str, Any]:
        """Atomically authorize, account, reserve, and lease a repository read."""

        self._require_policy_capability(policy_capability)
        self._require_broker_capability(broker_capability)
        self._require_runtime_capability(runtime_capability)
        self._require_owner_id(owner_id)
        if not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive integer")
        try:
            plan = copy.deepcopy(validate_record(plan))
            snapshot = copy.deepcopy(validate_record(snapshot))
            tool_request = copy.deepcopy(validate_record(tool_request))
            decision = copy.deepcopy(validate_record(decision))
            intent = copy.deepcopy(validate_record(intent))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Repository read input is invalid") from exc
        if (
            plan["kind"] != "RunPlan"
            or snapshot["kind"] != "RepositorySnapshot"
            or tool_request["kind"] != "ToolRequest"
            or decision["kind"] != "PolicyDecision"
            or intent["kind"] != "ToolExecutionIntent"
        ):
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Repository read record kinds are invalid")
        run_id = plan["metadata"]["runId"]
        plan_digest = semantic_digest(plan)
        self._require_plan_profile(plan)
        self._require_decision_profile(
            decision, semantic_config_digest=plan["spec"]["project"]["semanticConfigDigest"]
        )
        snapshot_digest = semantic_digest(snapshot)
        request_digest = semantic_digest(tool_request)
        decision_digest = semantic_digest(decision)
        intent_digest = semantic_digest(intent)
        operation_id = intent["metadata"]["id"]
        request_id = tool_request["metadata"]["id"]
        path = tool_request["spec"]["arguments"]["path"]
        now_text = _utc(now)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        plan_snapshot = plan["spec"]["repositorySnapshot"]
        if (
            snapshot["metadata"]["id"] != plan_snapshot["id"]
            or snapshot_digest != plan_snapshot["digest"]
            or snapshot["spec"]["rootIdentityDigest"] != plan_snapshot["rootIdentityDigest"]
            or snapshot["spec"]["trust"] != plan_snapshot["trust"]
        ):
            raise RuntimeStoreError("ECO_SNAPSHOT_MISMATCH", "Snapshot does not match active plan")
        entry = next(
            (candidate for candidate in snapshot["spec"]["entries"] if candidate["path"] == path),
            None,
        )
        if entry is None:
            raise RuntimeStoreError("ECO_PATH_NOT_IN_SNAPSHOT", "Requested path is not in snapshot")
        tool = next(
            (candidate for candidate in plan["spec"]["tools"] if candidate["id"] == "repository.read"),
            None,
        )
        intent_spec = intent["spec"]
        expected_entry = {
            "snapshotDigest": snapshot_digest,
            "pathDigest": self.path_reference_digest(path),
            "contentDigest": entry["contentDigest"],
            "byteLength": entry["byteLength"],
            "dataClass": entry["dataClass"],
            "trust": entry["trust"],
        }
        decision_subject = decision["spec"]["subject"]
        if (
            tool is None
            or plan["metadata"]["runId"] != tool_request["metadata"]["runId"]
            or plan["metadata"]["runId"] != decision["metadata"]["runId"]
            or plan["metadata"]["runId"] != intent["metadata"]["runId"]
            or tool_request["spec"]["planDigest"] != plan_digest
            or tool_request["spec"]["toolId"] != "repository.read"
            or decision["spec"]["effect"] != "allow"
            or decision_subject
            != {"kind": "ToolRequest", "id": request_id, "digest": request_digest}
            or intent_spec["planDigest"] != plan_digest
            or intent_spec["toolRequest"] != {"id": request_id, "digest": request_digest}
            or intent_spec["allowDecision"]
            != {"id": decision["metadata"]["id"], "digest": decision_digest}
            or intent_spec["toolCatalogDigest"] != tool["catalogDigest"]
            or intent_spec["reservation"]
            != {"toolRequests": 1, "inputBytes": entry["byteLength"]}
            or intent_spec["repositoryEntry"] != expected_entry
        ):
            raise RuntimeStoreError("ECO_OPERATION_BINDING_INVALID", "Repository read binding is invalid")

        transaction_id = secrets.token_hex(16)
        lease_token = secrets.token_hex(32)
        lease_until = now.astimezone(timezone.utc) + timedelta(seconds=lease_seconds)
        lease_until_epoch_us = int(lease_until.timestamp() * 1_000_000)
        with self._transaction():
            run_row = self._connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            plan_row = self._connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan["metadata"]["id"],)
            ).fetchone()
            if (
                run_row is None
                or plan_row is None
                or run_row["active_plan_digest"] != plan_digest
                or plan_row["plan_digest"] != plan_digest
                or run_row["state"] != "RUNNING"
            ):
                raise RuntimeStoreError("ECO_PLAN_UNTRUSTED", "Plan is not the active authority")
            if _parse(run_row["updated_at"]) > now.astimezone(timezone.utc):
                raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Runtime clock moved backwards")
            if run_row["deadline_epoch_us"] is None or run_row["deadline_epoch_us"] <= now_epoch_us:
                raise RuntimeStoreError("ECO_DEADLINE_EXCEEDED", "Run deadline has elapsed")
            lease_until_epoch_us = min(lease_until_epoch_us, run_row["deadline_epoch_us"])
            lease_until = datetime.fromtimestamp(
                lease_until_epoch_us / 1_000_000, tz=timezone.utc
            )
            existing = self._connection.execute(
                """
                SELECT * FROM operations
                WHERE run_id = ? AND idempotency_key_digest = ?
                """,
                (run_id, intent_spec["idempotencyKeyDigest"]),
            ).fetchone()
            if existing is not None:
                if existing["intent_digest"] != intent_digest:
                    raise RuntimeStoreError(
                        "ECO_IDEMPOTENCY_CONFLICT", "Idempotency key is bound to another intent"
                    )
                if existing["state"] == "prepared":
                    raise RuntimeStoreError("ECO_OPERATION_IN_PROGRESS", "Operation is already leased")
                return dict(existing)
            duplicate_subject = self._connection.execute(
                "SELECT operation_id FROM operations WHERE run_id = ? AND tool_request_digest = ?",
                (run_id, request_digest),
            ).fetchone()
            if duplicate_subject is not None:
                raise RuntimeStoreError(
                    "ECO_OPERATION_SUBJECT_CONFLICT", "Tool request already has an operation"
                )
            self._issue_decision_tx(decision, transaction_id=transaction_id)
            self._consume_decision_tx(
                decision,
                subject_digest=request_digest,
                nonce=operation_id,
                now=now,
                transaction_id=transaction_id,
            )
            updated_budget = self._connection.execute(
                """
                UPDATE budgets
                SET tool_requests = tool_requests + 1,
                    reserved_input_bytes = reserved_input_bytes + ?, updated_at = ?
                WHERE run_id = ? AND plan_digest = ? AND deadline_epoch_us > ?
                  AND tool_requests + 1 <= max_tool_requests
                  AND input_bytes + reserved_input_bytes + ? <= max_input_bytes
                """,
                (
                    entry["byteLength"],
                    now_text,
                    run_id,
                    plan_digest,
                    now_epoch_us,
                    entry["byteLength"],
                ),
            )
            if updated_budget.rowcount != 1:
                raise RuntimeStoreError("ECO_BUDGET_EXHAUSTED", "Tool or input budget is exhausted")
            _, intent_inserted = self._insert_record(intent)
            if not intent_inserted:
                raise RuntimeStoreError("ECO_OPERATION_CONFLICT", "Operation record already exists")
            self._append_audit(
                transaction_id=transaction_id,
                record_type="ToolExecutionIntent",
                record_id=operation_id,
                action="recorded",
                payload_digest=intent_digest,
                occurred_at=intent["metadata"]["createdAt"],
            )
            self._connection.execute(
                """
                INSERT INTO operations
                (operation_id, run_id, idempotency_key_digest, intent_digest,
                 tool_request_digest, allow_decision_digest, state, recovery_mode, lease_owner_id,
                 lease_epoch, lease_token_digest, lease_until_epoch_us, receipt_digest,
                 artifact_record_digest, error_record_digest, outcome_digest, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'prepared', 'no_retry', ?, 1, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    operation_id,
                    run_id,
                    intent_spec["idempotencyKeyDigest"],
                    intent_digest,
                    request_digest,
                    decision_digest,
                    owner_id,
                    self._lease_token_digest(lease_token),
                    lease_until_epoch_us,
                    now_text,
                    now_text,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO budget_reservations
                VALUES (?, ?, ?, ?, NULL, 'reserved', ?, ?)
                """,
                (operation_id, run_id, plan_digest, entry["byteLength"], now_text, now_text),
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="tool.requested",
                producer="runtime",
                producer_capability=runtime_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=request_id,
                subject_digest=request_digest,
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="tool.allowed",
                producer="policy",
                producer_capability=policy_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=request_id,
                subject_digest=request_digest,
                result_digest=decision_digest,
            )
            entities = [
                ("budget", run_id, "budgets", "run_id"),
                ("operation", operation_id, "operations", "operation_id"),
                ("reservation", operation_id, "budget_reservations", "operation_id"),
            ]
            for entity_type, entity_id, table, id_column in entities:
                self._record_authority_revision(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    table=table,
                    id_column=id_column,
                    transaction_id=transaction_id,
                    occurred_at=now_text,
                )
        return {
            "operationId": operation_id,
            "state": "prepared",
            "leaseToken": lease_token,
            "leaseEpoch": 1,
            "leaseUntil": _utc(lease_until),
            "intentDigest": intent_digest,
        }

    def operation_status(self, operation_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError("ECO_OPERATION_UNKNOWN", "Operation does not exist")
            return dict(row)

    def claim_operation(
        self,
        operation_id: str,
        *,
        owner_id: str,
        now: datetime,
        broker_capability: object,
        lease_seconds: int = 30,
    ) -> dict[str, Any]:
        """Reclaim an expired PREPARED operation and fence every older worker."""

        self._require_broker_capability(broker_capability)
        self._require_owner_id(owner_id)
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be valid")
        now_text = _utc(now)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        lease_until = now.astimezone(timezone.utc) + timedelta(seconds=lease_seconds)
        token = secrets.token_hex(32)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError("ECO_OPERATION_UNKNOWN", "Operation does not exist")
            if row["state"] != "prepared":
                return dict(row)
            if row["recovery_mode"] == "no_retry":
                raise RuntimeStoreError(
                    "ECO_OPERATION_NO_RETRY",
                    "Operation has no trusted durable recovery payload",
                )
            if row["lease_until_epoch_us"] is not None and row["lease_until_epoch_us"] > now_epoch_us:
                raise RuntimeStoreError("ECO_OPERATION_IN_PROGRESS", "Operation lease is still active")
            run = self._connection.execute(
                "SELECT deadline_epoch_us, updated_at FROM runs WHERE run_id = ?", (row["run_id"],)
            ).fetchone()
            if run is None or run["deadline_epoch_us"] <= now_epoch_us:
                raise RuntimeStoreError("ECO_DEADLINE_EXCEEDED", "Run deadline has elapsed")
            if _parse(run["updated_at"]) > now.astimezone(timezone.utc):
                raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Runtime clock moved backwards")
            lease_until_epoch_us = min(
                int(lease_until.timestamp() * 1_000_000), run["deadline_epoch_us"]
            )
            lease_until = datetime.fromtimestamp(
                lease_until_epoch_us / 1_000_000, tz=timezone.utc
            )
            self._connection.execute(
                """
                UPDATE operations
                SET lease_owner_id = ?, lease_epoch = lease_epoch + 1,
                    lease_token_digest = ?, lease_until_epoch_us = ?, updated_at = ?
                WHERE operation_id = ? AND state = 'prepared'
                """,
                (
                    owner_id,
                    self._lease_token_digest(token),
                    lease_until_epoch_us,
                    now_text,
                    operation_id,
                ),
            )
            self._record_authority_revision(
                entity_type="operation",
                entity_id=operation_id,
                table="operations",
                id_column="operation_id",
                transaction_id=transaction_id,
                occurred_at=now_text,
            )
            epoch = row["lease_epoch"] + 1
        return {
            "operationId": operation_id,
            "state": "prepared",
            "leaseToken": token,
            "leaseEpoch": epoch,
            "leaseUntil": _utc(lease_until),
        }

    def scan_recoverable_operations(
        self, *, now: datetime, broker_capability: object
    ) -> tuple[dict[str, Any], ...]:
        """List only safe metadata for PREPARED operations whose lease is no longer active."""

        self._require_broker_capability(broker_capability)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT o.operation_id, o.run_id, o.intent_digest, o.lease_epoch,
                       o.recovery_mode,
                       o.lease_until_epoch_us, r.deadline_epoch_us,
                       b.reserved_input_bytes
                FROM operations AS o
                JOIN runs AS r ON r.run_id = o.run_id
                JOIN budget_reservations AS b ON b.operation_id = o.operation_id
                WHERE o.state = 'prepared'
                  AND (o.lease_until_epoch_us IS NULL OR o.lease_until_epoch_us <= ?)
                ORDER BY o.operation_id
                """,
                (now_epoch_us,),
            ).fetchall()
            return tuple(
                {
                    "operationId": row["operation_id"],
                    "runId": row["run_id"],
                    "intentDigest": row["intent_digest"],
                    "leaseEpoch": row["lease_epoch"],
                    "reservedInputBytes": row["reserved_input_bytes"],
                    "recoveryMode": row["recovery_mode"],
                    "reason": (
                        "deadline_expired"
                        if row["deadline_epoch_us"] <= now_epoch_us
                        else "lease_expired"
                    ),
                }
                for row in rows
            )

    def abort_expired_operation(
        self,
        operation_id: str,
        *,
        now: datetime,
        broker_capability: object,
        observed_lease_epoch: int | None = None,
    ) -> dict[str, Any]:
        """Fail closed after lease expiry; ``no_retry`` never repeats broker I/O."""

        self._require_broker_capability(broker_capability)
        now_text = _utc(now)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            operation = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if operation is None:
                raise RuntimeStoreError("ECO_OPERATION_UNKNOWN", "Operation does not exist")
            if operation["state"] != "prepared":
                return dict(operation)
            if observed_lease_epoch is not None and operation["lease_epoch"] != observed_lease_epoch:
                raise RuntimeStoreError(
                    "ECO_OPERATION_FENCED", "Observed operation epoch is stale"
                )
            run = self._connection.execute(
                "SELECT deadline_epoch_us, updated_at FROM runs WHERE run_id = ?",
                (operation["run_id"],),
            ).fetchone()
            if run is None:
                raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
            if _parse(run["updated_at"]) > now.astimezone(timezone.utc):
                raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Runtime clock moved backwards")
            if (
                operation["lease_until_epoch_us"] is not None
                and operation["lease_until_epoch_us"] > now_epoch_us
            ):
                raise RuntimeStoreError(
                    "ECO_OPERATION_NOT_EXPIRED", "Operation lease has not elapsed"
                )
            reservation = self._connection.execute(
                "SELECT * FROM budget_reservations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if reservation is None or reservation["state"] != "reserved":
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Input reservation is invalid")
            intent = self._load_record_tx(operation_id)
            error = {
                "apiVersion": "runtime.ai.ecosystem/v1alpha1",
                "kind": "ErrorRecord",
                "metadata": {
                    "id": f"error-{operation_id}",
                    "runId": operation["run_id"],
                    "requestId": intent["spec"]["toolRequest"]["id"],
                    "createdAt": now_text,
                },
                "spec": {
                    "code": "ECO_OPERATION_RECOVERY_UNAVAILABLE",
                    "category": "internal",
                    "stage": "tool",
                    "retryable": False,
                    "safeMessage": RECOVERY_EXPIRED_MESSAGE,
                    "details": {"toolId": "repository.read"},
                },
            }
            error = validate_record(error)
            error_digest = semantic_digest(error)
            outcome = validate_record(
                {
                    "apiVersion": "runtime.ai.ecosystem/v1alpha1",
                    "kind": "ToolExecutionOutcome",
                    "metadata": {
                        "id": f"outcome-{operation_id}",
                        "runId": operation["run_id"],
                        "operationId": operation_id,
                        "createdAt": now_text,
                    },
                    "spec": {
                        "intentDigest": operation["intent_digest"],
                        "status": "failed",
                        "errorRecordDigest": error_digest,
                    },
                }
            )
            outcome_digest = semantic_digest(outcome)
            self._record_result_tx(error, transaction_id=transaction_id)
            self._record_result_tx(outcome, transaction_id=transaction_id)
            updated = self._connection.execute(
                """
                UPDATE budgets
                SET reserved_input_bytes = reserved_input_bytes - ?, updated_at = ?
                WHERE run_id = ? AND reserved_input_bytes >= ?
                """,
                (
                    reservation["reserved_input_bytes"],
                    now_text,
                    operation["run_id"],
                    reservation["reserved_input_bytes"],
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Budget reservation cannot release")
            self._connection.execute(
                "UPDATE budget_reservations SET state = 'released', updated_at = ? WHERE operation_id = ?",
                (now_text, operation_id),
            )
            self._connection.execute(
                """
                UPDATE operations
                SET state = 'failed', lease_owner_id = NULL, lease_token_digest = NULL,
                    lease_until_epoch_us = NULL, error_record_digest = ?, outcome_digest = ?,
                    updated_at = ? WHERE operation_id = ?
                """,
                (error_digest, outcome_digest, now_text, operation_id),
            )
            self._connection.execute(
                "UPDATE nonces SET result_digest = ? WHERE nonce = ?",
                (outcome_digest, operation_id),
            )
            self._append_generated_event_tx(
                run_id=operation["run_id"],
                event_type="tool.failed",
                producer="broker",
                producer_capability=broker_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=intent["spec"]["toolRequest"]["id"],
                subject_digest=operation["tool_request_digest"],
                result_digest=outcome_digest,
            )
            for entity_type, entity_id, table, id_column in (
                ("budget", operation["run_id"], "budgets", "run_id"),
                ("reservation", operation_id, "budget_reservations", "operation_id"),
                ("operation", operation_id, "operations", "operation_id"),
            ):
                self._record_authority_revision(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    table=table,
                    id_column=id_column,
                    transaction_id=transaction_id,
                    occurred_at=now_text,
                )
            return dict(
                self._connection.execute(
                    "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
                ).fetchone()
            )

    def resolve_unrecoverable_operation(
        self,
        operation_id: str,
        *,
        observed_lease_epoch: int,
        now: datetime,
        broker_capability: object,
    ) -> dict[str, Any]:
        """Resolve an expired explicit-no-retry PREPARE using an exact fencing epoch."""

        return self.abort_expired_operation(
            operation_id,
            observed_lease_epoch=observed_lease_epoch,
            now=now,
            broker_capability=broker_capability,
        )

    def _load_record_tx(self, record_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT canonical_json FROM records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_STORE_INTERNAL", "Immutable operation record is missing")
        return json.loads(bytes(row["canonical_json"]).decode("utf-8"))

    def _record_result_tx(
        self,
        record: dict[str, Any],
        *,
        transaction_id: str,
    ) -> str:
        digest, inserted = self._insert_record(record)
        if not inserted:
            raise RuntimeStoreError("ECO_OPERATION_CONFLICT", "Result record already exists")
        self._append_audit(
            transaction_id=transaction_id,
            record_type=record["kind"],
            record_id=record["metadata"]["id"],
            action="recorded",
            payload_digest=digest,
            occurred_at=record["metadata"]["createdAt"],
        )
        return digest

    def _require_live_lease(
        self, operation: sqlite3.Row, *, lease_token: str, now_epoch_us: int
    ) -> None:
        if operation["state"] != "prepared":
            raise RuntimeStoreError("ECO_OPERATION_TERMINAL", "Operation is already terminal")
        if (
            operation["lease_token_digest"] != self._lease_token_digest(lease_token)
            or operation["lease_until_epoch_us"] is None
            or operation["lease_until_epoch_us"] <= now_epoch_us
        ):
            raise RuntimeStoreError("ECO_OPERATION_FENCED", "Operation lease is invalid or expired")

    def _require_live_run_time_tx(
        self, run_id: str, *, now: datetime, now_epoch_us: int
    ) -> None:
        run = self._connection.execute(
            "SELECT deadline_epoch_us, updated_at FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if run is None:
            raise RuntimeStoreError("ECO_RUN_UNKNOWN", "Run does not exist")
        if _parse(run["updated_at"]) > now.astimezone(timezone.utc):
            raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Runtime clock moved backwards")
        if run["deadline_epoch_us"] is None or run["deadline_epoch_us"] <= now_epoch_us:
            raise RuntimeStoreError("ECO_DEADLINE_EXCEEDED", "Run deadline has elapsed")

    def complete_repository_read(
        self,
        operation_id: str,
        *,
        lease_token: str,
        receipt: dict[str, Any],
        artifact: dict[str, Any],
        outcome: dict[str, Any],
        availability_proof: ArtifactAvailabilityProof | None = None,
        now: datetime,
        broker_capability: object,
    ) -> dict[str, Any]:
        """Atomically commit a successful read and its exact budget/result bindings."""

        self._require_broker_capability(broker_capability)
        try:
            receipt = copy.deepcopy(validate_record(receipt))
            artifact = copy.deepcopy(validate_record(artifact))
            outcome = copy.deepcopy(validate_record(outcome))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Success result is invalid") from exc
        if (
            receipt["kind"] != "RepositoryReadReceipt"
            or artifact["kind"] != "ArtifactRecord"
            or outcome["kind"] != "ToolExecutionOutcome"
        ):
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Success result kinds are invalid")
        receipt_digest = semantic_digest(receipt)
        artifact_digest = semantic_digest(artifact)
        outcome_digest = semantic_digest(outcome)
        now_text = _utc(now)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            operation = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if operation is None:
                raise RuntimeStoreError("ECO_OPERATION_UNKNOWN", "Operation does not exist")
            if operation["state"] == "succeeded":
                if operation["outcome_digest"] != outcome_digest:
                    raise RuntimeStoreError("ECO_OPERATION_CONFLICT", "Operation has another outcome")
                return dict(operation)
            self._require_live_run_time_tx(
                operation["run_id"], now=now, now_epoch_us=now_epoch_us
            )
            self._require_live_lease(operation, lease_token=lease_token, now_epoch_us=now_epoch_us)
            intent = self._load_record_tx(operation_id)
            entry = intent["spec"]["repositoryEntry"]
            run_id = operation["run_id"]
            if (
                receipt["metadata"]
                != {
                    "id": f"receipt-{operation_id}",
                    "runId": run_id,
                    "operationId": operation_id,
                    "createdAt": receipt["metadata"]["createdAt"],
                }
                or receipt["spec"]
                != {
                    "intentDigest": operation["intent_digest"],
                    "toolRequestDigest": operation["tool_request_digest"],
                    "repositorySnapshotDigest": entry["snapshotDigest"],
                    "contentDigest": entry["contentDigest"],
                    "byteLength": entry["byteLength"],
                    "dataClass": entry["dataClass"],
                    "trust": entry["trust"],
                }
                or artifact["metadata"]["id"] != f"artifact-{operation_id}"
                or artifact["metadata"]["runId"] != run_id
                or artifact["spec"]["sha256"] != entry["contentDigest"]
                or artifact["spec"]["byteLength"] != entry["byteLength"]
                or artifact["spec"]["dataClass"] != entry["dataClass"]
                or artifact["spec"]["trust"] != entry["trust"]
                or artifact["spec"]["producer"] != {"type": "tool", "id": "repository.read"}
                or artifact["spec"]["storageRef"]
                != f"artifact://runs/{run_id}/artifact-{operation_id}"
                or outcome["metadata"]["id"] != f"outcome-{operation_id}"
                or outcome["metadata"]["runId"] != run_id
                or outcome["metadata"]["operationId"] != operation_id
                or outcome["spec"]
                != {
                    "intentDigest": operation["intent_digest"],
                    "status": "succeeded",
                    "receiptDigest": receipt_digest,
                    "artifactRecordDigest": artifact_digest,
                }
            ):
                raise RuntimeStoreError("ECO_OPERATION_BINDING_INVALID", "Success binding is invalid")
            if self._artifact_store is None or availability_proof is None:
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_PROOF_REQUIRED",
                    "Successful operation requires durable artifact availability proof",
                )
            if (
                availability_proof.storage_ref != artifact["spec"]["storageRef"]
                or availability_proof.sha256 != artifact["spec"]["sha256"]
                or availability_proof.byte_length != artifact["spec"]["byteLength"]
            ):
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_PROOF_INVALID", "Artifact proof binding differs"
                )
            self._artifact_store.verify_availability(availability_proof)
            reservation = self._connection.execute(
                "SELECT * FROM budget_reservations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if (
                reservation is None
                or reservation["state"] != "reserved"
                or reservation["reserved_input_bytes"] != entry["byteLength"]
            ):
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Input reservation is invalid")
            self._record_result_tx(receipt, transaction_id=transaction_id)
            self._record_result_tx(artifact, transaction_id=transaction_id)
            self._record_result_tx(outcome, transaction_id=transaction_id)
            budget_update = self._connection.execute(
                """
                UPDATE budgets
                SET reserved_input_bytes = reserved_input_bytes - ?,
                    input_bytes = input_bytes + ?, updated_at = ?
                WHERE run_id = ? AND reserved_input_bytes >= ?
                  AND input_bytes + ? <= max_input_bytes
                """,
                (
                    entry["byteLength"],
                    entry["byteLength"],
                    now_text,
                    run_id,
                    entry["byteLength"],
                    entry["byteLength"],
                ),
            )
            if budget_update.rowcount != 1:
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Budget reservation cannot commit")
            self._connection.execute(
                """
                UPDATE budget_reservations
                SET actual_input_bytes = reserved_input_bytes, state = 'committed', updated_at = ?
                WHERE operation_id = ?
                """,
                (now_text, operation_id),
            )
            self._connection.execute(
                """
                UPDATE operations
                SET state = 'succeeded', lease_owner_id = NULL, lease_token_digest = NULL,
                    lease_until_epoch_us = NULL, receipt_digest = ?, artifact_record_digest = ?,
                    outcome_digest = ?, updated_at = ?
                WHERE operation_id = ?
                """,
                (receipt_digest, artifact_digest, outcome_digest, now_text, operation_id),
            )
            self._connection.execute(
                "UPDATE nonces SET result_digest = ? WHERE nonce = ?",
                (outcome_digest, operation_id),
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="tool.completed",
                producer="broker",
                producer_capability=broker_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=intent["spec"]["toolRequest"]["id"],
                subject_digest=operation["tool_request_digest"],
                result_digest=outcome_digest,
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="artifact.recorded",
                producer="broker",
                producer_capability=broker_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=artifact["metadata"]["id"],
                subject_digest=artifact_digest,
                result_digest=artifact_digest,
            )
            for entity_type, entity_id, table, id_column in (
                ("budget", run_id, "budgets", "run_id"),
                ("reservation", operation_id, "budget_reservations", "operation_id"),
                ("operation", operation_id, "operations", "operation_id"),
            ):
                self._record_authority_revision(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    table=table,
                    id_column=id_column,
                    transaction_id=transaction_id,
                    occurred_at=now_text,
                )
            return dict(
                self._connection.execute(
                    "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
                ).fetchone()
            )

    def fail_repository_read(
        self,
        operation_id: str,
        *,
        lease_token: str,
        error: dict[str, Any],
        outcome: dict[str, Any],
        now: datetime,
        broker_capability: object,
    ) -> dict[str, Any]:
        """Atomically close a prepared read, release bytes, and preserve tool spend."""

        self._require_broker_capability(broker_capability)
        try:
            error = copy.deepcopy(validate_record(error))
            outcome = copy.deepcopy(validate_record(outcome))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Failure result is invalid") from exc
        if error["kind"] != "ErrorRecord" or outcome["kind"] != "ToolExecutionOutcome":
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Failure result kinds are invalid")
        error_digest = semantic_digest(error)
        outcome_digest = semantic_digest(outcome)
        now_text = _utc(now)
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            operation = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if operation is None:
                raise RuntimeStoreError("ECO_OPERATION_UNKNOWN", "Operation does not exist")
            if operation["state"] == "failed":
                if operation["outcome_digest"] != outcome_digest:
                    raise RuntimeStoreError("ECO_OPERATION_CONFLICT", "Operation has another outcome")
                return dict(operation)
            self._require_live_run_time_tx(
                operation["run_id"], now=now, now_epoch_us=now_epoch_us
            )
            self._require_live_lease(operation, lease_token=lease_token, now_epoch_us=now_epoch_us)
            intent = self._load_record_tx(operation_id)
            run_id = operation["run_id"]
            code = error["spec"]["code"]
            expected_message = SAFE_BROKER_ERROR_MESSAGES.get(code)
            expected_error_metadata = {
                "id": f"error-{operation_id}",
                "runId": run_id,
                "requestId": intent["spec"]["toolRequest"]["id"],
                "createdAt": error["metadata"]["createdAt"],
            }
            if (
                expected_message is None
                or error["metadata"] != expected_error_metadata
                or error["spec"]
                != {
                    "code": code,
                    "category": "broker",
                    "stage": "tool",
                    "retryable": False,
                    "safeMessage": expected_message,
                    "details": {"toolId": "repository.read"},
                }
                or outcome["metadata"]["id"] != f"outcome-{operation_id}"
                or outcome["metadata"]["runId"] != run_id
                or outcome["metadata"]["operationId"] != operation_id
                or outcome["spec"]
                != {
                    "intentDigest": operation["intent_digest"],
                    "status": "failed",
                    "errorRecordDigest": error_digest,
                }
            ):
                raise RuntimeStoreError("ECO_OPERATION_BINDING_INVALID", "Failure binding is invalid")
            reservation = self._connection.execute(
                "SELECT * FROM budget_reservations WHERE operation_id = ?", (operation_id,)
            ).fetchone()
            if reservation is None or reservation["state"] != "reserved":
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Input reservation is invalid")
            self._record_result_tx(error, transaction_id=transaction_id)
            self._record_result_tx(outcome, transaction_id=transaction_id)
            budget_update = self._connection.execute(
                """
                UPDATE budgets
                SET reserved_input_bytes = reserved_input_bytes - ?, updated_at = ?
                WHERE run_id = ? AND reserved_input_bytes >= ?
                """,
                (
                    reservation["reserved_input_bytes"],
                    now_text,
                    run_id,
                    reservation["reserved_input_bytes"],
                ),
            )
            if budget_update.rowcount != 1:
                raise RuntimeStoreError("ECO_RESERVATION_INVALID", "Budget reservation cannot release")
            self._connection.execute(
                """
                UPDATE budget_reservations
                SET state = 'released', updated_at = ? WHERE operation_id = ?
                """,
                (now_text, operation_id),
            )
            self._connection.execute(
                """
                UPDATE operations
                SET state = 'failed', lease_owner_id = NULL, lease_token_digest = NULL,
                    lease_until_epoch_us = NULL, error_record_digest = ?, outcome_digest = ?,
                    updated_at = ? WHERE operation_id = ?
                """,
                (error_digest, outcome_digest, now_text, operation_id),
            )
            self._connection.execute(
                "UPDATE nonces SET result_digest = ? WHERE nonce = ?",
                (outcome_digest, operation_id),
            )
            self._append_generated_event_tx(
                run_id=run_id,
                event_type="tool.failed",
                producer="broker",
                producer_capability=broker_capability,
                now=now,
                transaction_id=transaction_id,
                subject_id=intent["spec"]["toolRequest"]["id"],
                subject_digest=operation["tool_request_digest"],
                result_digest=outcome_digest,
            )
            for entity_type, entity_id, table, id_column in (
                ("budget", run_id, "budgets", "run_id"),
                ("reservation", operation_id, "budget_reservations", "operation_id"),
                ("operation", operation_id, "operations", "operation_id"),
            ):
                self._record_authority_revision(
                    entity_type=entity_type,
                    entity_id=entity_id,
                    table=table,
                    id_column=id_column,
                    transaction_id=transaction_id,
                    occurred_at=now_text,
                )
            return dict(
                self._connection.execute(
                    "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
                ).fetchone()
            )

    def issue_decision(
        self,
        decision: dict[str, Any],
        *,
        semantic_config_digest: str,
        policy_capability: object,
    ) -> str:
        self._require_policy_capability(policy_capability)
        try:
            decision = copy.deepcopy(validate_record(decision))
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Decision record is invalid") from exc
        if decision["kind"] != "PolicyDecision":
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Only PolicyDecision can be issued")
        self._require_decision_profile(
            decision, semantic_config_digest=semantic_config_digest
        )
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            return self._issue_decision_tx(decision, transaction_id=transaction_id)

    def _issue_decision_tx(self, decision: dict[str, Any], *, transaction_id: str) -> str:
        record_id, run_id, occurred_at = self._record_identity(decision)
        digest, inserted = self._insert_record(decision)
        spec = decision["spec"]
        existing = self._connection.execute(
            "SELECT decision_digest FROM decisions WHERE decision_id = ?", (record_id,)
        ).fetchone()
        if existing is not None and existing["decision_digest"] != digest:
            raise RuntimeStoreError("ECO_STORE_ID_CONFLICT", "Decision id has another digest")
        if existing is None:
            self._connection.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    record_id,
                    run_id,
                    digest,
                    spec["subject"]["digest"],
                    spec["effect"],
                    spec["constraints"]["expiresAt"],
                    int(_parse(spec["constraints"]["expiresAt"]).timestamp() * 1_000_000),
                ),
            )
        if inserted:
            self._append_audit(
                transaction_id=transaction_id,
                record_type="PolicyDecision",
                record_id=record_id,
                action="issued",
                payload_digest=digest,
                occurred_at=occurred_at,
            )
        return digest

    def consume_decision(
        self,
        decision: dict[str, Any],
        subject: dict[str, Any],
        *,
        nonce: str,
        now: datetime,
        semantic_config_digest: str,
        policy_capability: object,
    ) -> None:
        self._require_policy_capability(policy_capability)
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("nonce must be a non-empty string")
        try:
            validate_record(decision)
            validate_record(subject)
        except ContractValidationError as exc:
            raise RuntimeStoreError("ECO_STORE_RECORD_INVALID", "Decision or subject is invalid") from exc
        if decision["kind"] != "PolicyDecision" or decision["spec"]["effect"] != "allow":
            raise RuntimeStoreError("ECO_DECISION_DENIED", "Decision cannot authorize execution")
        self._require_decision_profile(
            decision, semantic_config_digest=semantic_config_digest
        )
        spec = decision["spec"]
        subject_digest = semantic_digest(subject)
        if (
            decision["metadata"]["runId"] != subject["metadata"].get("runId")
            or spec["subject"]["kind"] != subject["kind"]
            or spec["subject"]["id"] != subject["metadata"]["id"]
            or spec["subject"]["digest"] != subject_digest
        ):
            raise RuntimeStoreError("ECO_DECISION_MISMATCH", "Decision subject does not match")
        if _parse(spec["constraints"]["expiresAt"]) <= now.astimezone(timezone.utc):
            raise RuntimeStoreError("ECO_DECISION_EXPIRED", "Decision is expired")
        with self._transaction():
            self._consume_decision_tx(
                decision,
                subject_digest=subject_digest,
                nonce=nonce,
                now=now,
                transaction_id=secrets.token_hex(16),
            )

    def _consume_decision_tx(
        self,
        decision: dict[str, Any],
        *,
        subject_digest: str,
        nonce: str,
        now: datetime,
        transaction_id: str,
    ) -> bool:
        decision_id = decision["metadata"]["id"]
        decision_digest = semantic_digest(decision)
        now_text = _utc(now)
        row = self._connection.execute(
            "SELECT * FROM decisions WHERE decision_id = ?", (decision_id,)
        ).fetchone()
        if row is None or row["decision_digest"] != decision_digest:
            raise RuntimeStoreError("ECO_DECISION_UNTRUSTED", "Decision was not durably issued")
        now_epoch_us = int(now.astimezone(timezone.utc).timestamp() * 1_000_000)
        if row["expires_at_epoch_us"] <= now_epoch_us:
            raise RuntimeStoreError("ECO_DECISION_EXPIRED", "Decision is expired")
        existing_nonce = self._connection.execute(
            "SELECT * FROM nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        if existing_nonce is not None:
            if (
                existing_nonce["run_id"] == decision["metadata"]["runId"]
                and existing_nonce["subject_digest"] == subject_digest
                and row["consumed_nonce"] == nonce
            ):
                return False
            raise RuntimeStoreError("ECO_NONCE_CONFLICT", "Nonce is bound to another operation")
        updated = self._connection.execute(
            """
            UPDATE decisions SET consumed_at = ?, consumed_nonce = ?
            WHERE decision_id = ? AND decision_digest = ? AND consumed_at IS NULL AND expires_at_epoch_us > ?
            """,
            (now_text, nonce, decision_id, decision_digest, now_epoch_us),
        )
        if updated.rowcount != 1:
            raise RuntimeStoreError("ECO_DECISION_REPLAYED", "Decision was already consumed")
        self._connection.execute(
            "INSERT INTO nonces VALUES (?, 'decision-consume', ?, ?, NULL, ?)",
            (nonce, decision["metadata"]["runId"], subject_digest, now_text),
        )
        self._append_audit(
            transaction_id=transaction_id,
            record_type="PolicyDecision",
            record_id=decision_id,
            action="consumed",
            payload_digest=decision_digest,
            occurred_at=now_text,
        )
        return True

    def _verify_authority_semantics(
        self,
        record_objects: dict[str, dict[str, Any]],
        record_digests: dict[str, tuple[str, str]],
    ) -> None:
        records_by_digest = {
            digest: record_objects[record_id]
            for record_id, (_, digest) in record_digests.items()
        }
        plans = {
            row["plan_id"]: row for row in self._connection.execute("SELECT * FROM plans")
        }
        runs = {row["run_id"]: row for row in self._connection.execute("SELECT * FROM runs")}
        budgets = {
            row["run_id"]: row for row in self._connection.execute("SELECT * FROM budgets")
        }
        reservations = {
            row["operation_id"]: row
            for row in self._connection.execute("SELECT * FROM budget_reservations")
        }
        operations = {
            row["operation_id"]: row
            for row in self._connection.execute("SELECT * FROM operations")
        }
        decisions_by_digest = {
            row["decision_digest"]: row
            for row in self._connection.execute("SELECT * FROM decisions")
        }
        nonces = {row["nonce"]: row for row in self._connection.execute("SELECT * FROM nonces")}

        baselines = {
            row["run_id"]: row
            for row in self._connection.execute("SELECT * FROM run_event_baselines")
        }
        event_rows = list(self._connection.execute("SELECT * FROM run_events"))
        event_record_ids = {
            record_id
            for record_id, record in record_objects.items()
            if record["kind"] == "RunEvent"
        }
        if set(baselines) != set(runs) or {row["event_id"] for row in event_rows} != event_record_ids:
            raise RuntimeStoreError(
                "ECO_JOURNAL_CORRUPT", "Run event authority inventory differs"
            )
        for run_id, run in runs.items():
            projection, next_sequence, head_digest, _ = self._replay_event_projection_tx(run_id)
            if (
                projection.state.value != run["state"]
                or next_sequence != run["next_event_sequence"]
                or head_digest != run["event_head_digest"]
                or (run["terminal_at"] is None) != (projection.state not in TERMINAL_STATES)
            ):
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Run cache differs from authoritative event replay"
                )

        for event_row in event_rows:
            event = record_objects[event_row["event_id"]]
            spec = event["spec"]
            event_type = spec["type"]
            subject_id = spec.get("subjectId")
            subject_digest = spec.get("subjectDigest")
            result_digest = spec.get("resultDigest")
            if event_type in {"run.received", "run.validated"}:
                request = records_by_digest.get(subject_digest)
                if (
                    request is None
                    or request["kind"] != "RunRequest"
                    or request["metadata"]["id"] != subject_id
                    or runs[event_row["run_id"]]["request_digest"] != subject_digest
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Run lifecycle event request binding differs"
                    )
            elif event_type == "plan.created":
                plan = records_by_digest.get(subject_digest)
                if (
                    plan is None
                    or plan["kind"] != "RunPlan"
                    or plan["metadata"]["id"] != subject_id
                    or subject_id not in plans
                    or plans[subject_id]["run_id"] != event_row["run_id"]
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Plan event binding differs"
                    )
            elif event_type in {"policy.allowed", "policy.denied", "tool.allowed", "tool.denied"}:
                decision = decisions_by_digest.get(result_digest)
                if decision is None:
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Policy event result is not a decision"
                    )
                decision_record = record_objects[decision["decision_id"]]
                expected_kind = "RunPlan" if event_type.startswith("policy.") else "ToolRequest"
                if decision_record["spec"]["subject"] != {
                    "kind": expected_kind,
                    "id": subject_id,
                    "digest": subject_digest,
                }:
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Policy event subject binding differs"
                    )
                expected_effect = "deny" if event_type.endswith("denied") else "allow"
                if decision_record["spec"]["effect"] != expected_effect:
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Policy event effect differs"
                    )
            elif event_type == "tool.requested":
                if not any(
                    operation["tool_request_digest"] == subject_digest
                    and record_objects[operation_id]["spec"]["toolRequest"]["id"] == subject_id
                    for operation_id, operation in operations.items()
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Tool request event has no operation binding"
                    )
            elif event_type in {"tool.completed", "tool.failed"}:
                expected_state = "succeeded" if event_type == "tool.completed" else "failed"
                if not any(
                    operation["state"] == expected_state
                    and operation["tool_request_digest"] == subject_digest
                    and operation["outcome_digest"] == result_digest
                    and record_objects[operation_id]["spec"]["toolRequest"]["id"] == subject_id
                    for operation_id, operation in operations.items()
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Terminal tool event binding differs"
                    )
            elif event_type == "artifact.recorded":
                artifact = records_by_digest.get(subject_digest)
                if (
                    artifact is None
                    or artifact["kind"] != "ArtifactRecord"
                    or artifact["metadata"]["id"] != subject_id
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Artifact event binding differs"
                    )

        checkpoint_rows = {
            row["run_id"]: row for row in self._connection.execute("SELECT * FROM run_checkpoints")
        }
        checkpoint_record_ids = {
            record_id for record_id, record in record_objects.items()
            if record["kind"] == "RunCheckpoint"
        }
        if {row["checkpoint_id"] for row in checkpoint_rows.values()} != checkpoint_record_ids:
            raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Checkpoint inventory differs")
        for run_id, row in checkpoint_rows.items():
            run = runs.get(run_id)
            checkpoint = record_objects.get(row["checkpoint_id"])
            projection, next_sequence, head_digest, _ = self._replay_event_projection_tx(run_id)
            budget = budgets.get(run_id)
            plan = plans.get(run["active_plan_id"]) if run is not None else None
            plan_record = record_objects.get(run["active_plan_id"]) if run is not None else None
            baseline = baselines.get(run_id)
            if (
                run is None or checkpoint is None or budget is None or plan is None
                or plan_record is None or baseline is None
                or projection.state not in TERMINAL_STATES
                or row["checkpoint_digest"] != record_digests[row["checkpoint_id"]][1]
                or row["run_version"] != run["version"]
                or checkpoint["metadata"]["revision"] != run["version"]
                or checkpoint["spec"] != {
                    "state": projection.state.value,
                    "projection": self._projection_payload(projection),
                    "historyComplete": bool(baseline["history_complete"]),
                    "historySource": baseline["source"],
                    "eventSequence": next_sequence - 1,
                    "eventHeadDigest": head_digest,
                    "activePlanDigest": run["active_plan_digest"],
                    "budget": {
                        "limitsDigest": semantic_digest(
                            {"domain": "eco-budget-limits-v1", "limits": plan_record["spec"]["budget"]}
                        ),
                        "toolRequests": budget["tool_requests"],
                        "inputBytes": budget["input_bytes"],
                        "reservedInputBytes": budget["reserved_input_bytes"],
                        "outputBytes": budget["output_bytes"],
                        "modelRequests": budget["model_requests"],
                        "totalTokens": budget["total_tokens"],
                        "costMicrousd": budget["cost_microusd"],
                    },
                    "openOperationIds": [],
                    "startedAt": run["started_at"],
                    "deadlineAt": run["deadline_at"],
                }
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Checkpoint cache differs")

        for plan_id, row in plans.items():
            record = record_objects.get(plan_id)
            if (
                record is None
                or record["kind"] != "RunPlan"
                or record["metadata"]["runId"] != row["run_id"]
                or record_digests[plan_id][1] != row["plan_digest"]
                or row["run_id"] not in runs
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Plan projection is inconsistent")

        for run_id, run in runs.items():
            active_id = run["active_plan_id"]
            active_digest = run["active_plan_digest"]
            if (active_id is None) != (active_digest is None):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Active plan pointer is incomplete")
            if active_id is None:
                if run_id in budgets:
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Inactive run has a budget")
                continue
            plan = plans.get(active_id)
            if (
                plan is None
                or plan["run_id"] != run_id
                or plan["plan_digest"] != active_digest
                or plan["status"] != "active"
                or run_id not in budgets
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Active plan binding is inconsistent")

        for run_id, budget in budgets.items():
            run = runs.get(run_id)
            plan_row = next(
                (row for row in plans.values() if row["plan_digest"] == budget["plan_digest"]),
                None,
            )
            if (
                run is None
                or plan_row is None
                or run["active_plan_digest"] != budget["plan_digest"]
                or plan_row["run_id"] != run_id
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Budget plan binding is inconsistent")
            plan = record_objects[plan_row["plan_id"]]
            limits = plan["spec"]["budget"]
            expected_deadline = _parse(plan["metadata"]["createdAt"]) + timedelta(
                seconds=limits["maxDurationSeconds"]
            )
            expected_limits = {
                "max_duration_seconds": limits["maxDurationSeconds"],
                "max_model_requests": limits["maxModelRequests"],
                "max_tool_requests": limits["maxToolRequests"],
                "max_input_bytes": limits["maxInputBytes"],
                "max_output_bytes": limits["maxOutputBytes"],
                "max_total_tokens": limits["maxTotalTokens"],
                "max_cost_microusd": limits["maxCostMicrousd"],
            }
            if any(budget[column] != value for column, value in expected_limits.items()) or (
                budget["deadline_at"] != _utc(expected_deadline)
                or budget["deadline_epoch_us"] != int(expected_deadline.timestamp() * 1_000_000)
                or run["deadline_at"] != budget["deadline_at"]
                or run["deadline_epoch_us"] != budget["deadline_epoch_us"]
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Budget limits are inconsistent")
            run_reservations = [row for row in reservations.values() if row["run_id"] == run_id]
            expected_reserved = sum(
                row["reserved_input_bytes"]
                for row in run_reservations
                if row["state"] == "reserved"
            )
            expected_committed = sum(
                row["actual_input_bytes"]
                for row in run_reservations
                if row["state"] == "committed"
            )
            initial_input = sum(item["byteLength"] for item in plan["spec"]["inputs"])
            if (
                budget["tool_requests"] != len(run_reservations)
                or budget["reserved_input_bytes"] != expected_reserved
                or budget["input_bytes"] != initial_input + expected_committed
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Budget accounting is inconsistent")

        if set(reservations) != set(operations):
            raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Operation reservation inventory differs")
        for operation_id, operation in operations.items():
            intent = record_objects.get(operation_id)
            reservation = reservations[operation_id]
            decision = decisions_by_digest.get(operation["allow_decision_digest"])
            nonce = nonces.get(operation_id)
            if (
                intent is None
                or intent["kind"] != "ToolExecutionIntent"
                or record_digests[operation_id][1] != operation["intent_digest"]
                or intent["metadata"]["runId"] != operation["run_id"]
                or intent["spec"]["idempotencyKeyDigest"]
                != operation["idempotency_key_digest"]
                or intent["spec"]["toolRequest"]["digest"]
                != operation["tool_request_digest"]
                or intent["spec"]["allowDecision"]["digest"]
                != operation["allow_decision_digest"]
                or reservation["run_id"] != operation["run_id"]
                or reservation["plan_digest"] != intent["spec"]["planDigest"]
                or reservation["reserved_input_bytes"]
                != intent["spec"]["reservation"]["inputBytes"]
                or decision is None
                or decision["consumed_nonce"] != operation_id
                or nonce is None
                or operation["recovery_mode"] != "no_retry"
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Prepared operation binding is inconsistent")
            decision_record = record_objects[decision["decision_id"]]
            if (
                decision_record["spec"]["effect"] != "allow"
                or decision_record["spec"]["subject"]
                != {
                    "kind": "ToolRequest",
                    "id": intent["spec"]["toolRequest"]["id"],
                    "digest": operation["tool_request_digest"],
                }
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Operation decision is inconsistent")
            state = operation["state"]
            if state == "prepared":
                if (
                    reservation["state"] != "reserved"
                    or nonce["result_digest"] is not None
                    or any(
                        operation[column] is not None
                        for column in (
                            "receipt_digest",
                            "artifact_record_digest",
                            "error_record_digest",
                            "outcome_digest",
                        )
                    )
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Prepared operation shape is invalid")
                continue
            outcome = records_by_digest.get(operation["outcome_digest"])
            if (
                outcome is None
                or outcome["kind"] != "ToolExecutionOutcome"
                or outcome["metadata"]["runId"] != operation["run_id"]
                or outcome["metadata"]["operationId"] != operation_id
                or outcome["spec"]["intentDigest"] != operation["intent_digest"]
                or nonce["result_digest"] != operation["outcome_digest"]
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Operation outcome is inconsistent")
            entry = intent["spec"]["repositoryEntry"]
            if state == "succeeded":
                receipt = records_by_digest.get(operation["receipt_digest"])
                artifact = records_by_digest.get(operation["artifact_record_digest"])
                if (
                    reservation["state"] != "committed"
                    or reservation["actual_input_bytes"] != reservation["reserved_input_bytes"]
                    or operation["error_record_digest"] is not None
                    or receipt is None
                    or artifact is None
                    or receipt["kind"] != "RepositoryReadReceipt"
                    or artifact["kind"] != "ArtifactRecord"
                    or receipt["spec"]["intentDigest"] != operation["intent_digest"]
                    or receipt["spec"]["toolRequestDigest"] != operation["tool_request_digest"]
                    or receipt["spec"]["repositorySnapshotDigest"] != entry["snapshotDigest"]
                    or receipt["spec"]["contentDigest"] != entry["contentDigest"]
                    or receipt["spec"]["byteLength"] != entry["byteLength"]
                    or receipt["spec"]["dataClass"] != entry["dataClass"]
                    or receipt["spec"]["trust"] != entry["trust"]
                    or artifact["spec"]["sha256"] != entry["contentDigest"]
                    or artifact["spec"]["byteLength"] != entry["byteLength"]
                    or artifact["spec"]["dataClass"] != entry["dataClass"]
                    or artifact["spec"]["trust"] != entry["trust"]
                    or outcome["spec"]
                    != {
                        "intentDigest": operation["intent_digest"],
                        "status": "succeeded",
                        "receiptDigest": operation["receipt_digest"],
                        "artifactRecordDigest": operation["artifact_record_digest"],
                    }
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Successful operation is inconsistent")
                if self._artifact_store is None:
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_PROOF_REQUIRED",
                        "Artifact store is required to verify successful operations",
                    )
                self._artifact_store.verify_record(
                    storage_ref=artifact["spec"]["storageRef"],
                    sha256=artifact["spec"]["sha256"],
                    byte_length=artifact["spec"]["byteLength"],
                )
            elif state == "failed":
                error = records_by_digest.get(operation["error_record_digest"])
                if (
                    reservation["state"] != "released"
                    or reservation["actual_input_bytes"] is not None
                    or operation["receipt_digest"] is not None
                    or operation["artifact_record_digest"] is not None
                    or error is None
                    or error["kind"] != "ErrorRecord"
                    or error["metadata"]["runId"] != operation["run_id"]
                    or outcome["spec"]
                    != {
                        "intentDigest": operation["intent_digest"],
                        "status": "failed",
                        "errorRecordDigest": operation["error_record_digest"],
                    }
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Failed operation is inconsistent")
            else:
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Unsupported operation state")

    def verify(self) -> None:
        """Verify one coherent SQLite read snapshot, never a mix of writer commits."""

        with self._lock:
            if self._connection.in_transaction:
                raise RuntimeStoreError("ECO_STORE_INTERNAL", "Cannot verify inside a mutation")
            self._connection.execute("BEGIN")
            try:
                self._verify_snapshot()
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    def _verify_snapshot(self) -> None:
        with self._lock:
            check = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "SQLite integrity check failed")
            record_digests: dict[str, tuple[str, str]] = {}
            record_objects: dict[str, dict[str, Any]] = {}
            for row in self._connection.execute("SELECT * FROM records ORDER BY record_id"):
                try:
                    record = json.loads(bytes(row["canonical_json"]).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Stored record is unreadable") from exc
                try:
                    validate_record(record)
                except ContractValidationError as exc:
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Stored record contract is invalid") from exc
                if (
                    semantic_digest(record) != row["record_digest"]
                    or canonical_json(record).encode("utf-8") != bytes(row["canonical_json"])
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Stored record digest mismatch")
                record_digests[row["record_id"]] = (row["kind"], row["record_digest"])
                record_objects[row["record_id"]] = record
            previous = GENESIS_DIGEST
            expected_sequence = 1
            recorded_audit: dict[str, tuple[str, str]] = {}
            consumed_audit: dict[str, str] = {}
            authority_audit: dict[int, tuple[str, str, str]] = {}
            rotation_audit: dict[str, str] = {}
            for row in self._connection.execute("SELECT * FROM audit_entries ORDER BY sequence"):
                if row["sequence"] != expected_sequence or row["previous_entry_hash"] != previous:
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Audit chain sequence is broken")
                payload = {
                    "domain": "eco-audit-v1",
                    "storeId": self._store_id,
                    "sequence": row["sequence"],
                    "transactionId": row["transaction_id"],
                    "recordType": row["record_type"],
                    "recordId": row["record_id"],
                    "action": row["action"],
                    "payloadDigest": row["payload_digest"],
                    "previousEntryHash": row["previous_entry_hash"],
                    "occurredAt": row["occurred_at"],
                }
                entry_hash = semantic_digest(payload)
                verification_key = self._audit_keys.get(row["key_id"])
                expected_tag = (
                    hmac.new(
                        verification_key, bytes.fromhex(entry_hash), hashlib.sha256
                    ).hexdigest()
                    if verification_key is not None
                    else None
                )
                if (
                    row["entry_hash"] != entry_hash
                    or expected_tag is None
                    or not hmac.compare_digest(row["hmac_tag"], expected_tag)
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Audit chain authentication failed")
                previous = entry_hash
                expected_sequence += 1
                if row["action"] in {"recorded", "issued"}:
                    if row["record_id"] in recorded_audit:
                        raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Record has duplicate audit creation")
                    recorded_audit[row["record_id"]] = (row["record_type"], row["payload_digest"])
                elif row["action"] == "consumed":
                    if row["record_id"] in consumed_audit:
                        raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Decision has duplicate consume audit")
                    consumed_audit[row["record_id"]] = row["payload_digest"]
                elif row["action"] == "authority-state":
                    authority_audit[row["sequence"]] = (
                        row["record_type"],
                        row["record_id"],
                        row["payload_digest"],
                    )
                elif row["action"] == "key-rotation":
                    if row["record_type"] != "HmacKeyRotation" or row["record_id"] in rotation_audit:
                        raise RuntimeStoreError(
                            "ECO_JOURNAL_CORRUPT", "Key rotation audit is inconsistent"
                        )
                    rotation_audit[row["record_id"]] = row["payload_digest"]
                else:
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Audit action is unsupported")

            if set(record_digests) != set(recorded_audit):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Record and audit inventories differ")
            for record_id, (kind, digest) in record_digests.items():
                if recorded_audit[record_id] != (kind, digest):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Record is not bound to its audit entry")

            rotations = {
                row["nonce"]: row for row in self._connection.execute("SELECT * FROM key_rotations")
            }
            if set(rotations) != set(rotation_audit) or any(
                rotation_audit[nonce] != row["transition_digest"]
                or row["from_key_id"] not in self._audit_keys
                or row["to_key_id"] not in self._audit_keys
                for nonce, row in rotations.items()
            ):
                raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Key rotation inventory differs")

            decision_rows = {
                row["decision_id"]: row
                for row in self._connection.execute("SELECT * FROM decisions")
            }
            expected_decision_ids = {
                record_id
                for record_id, record in record_objects.items()
                if record["kind"] == "PolicyDecision"
            }
            if set(decision_rows) != expected_decision_ids:
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Decision and immutable record inventories differ"
                )

            referenced_nonces: set[str] = set()
            for decision_id, decision in decision_rows.items():
                record = record_objects[decision_id]
                spec = record["spec"]
                expected_expires_at = spec["constraints"]["expiresAt"]
                if (
                    decision["run_id"] != record["metadata"]["runId"]
                    or decision["decision_digest"] != record_digests[decision_id][1]
                    or decision["subject_digest"] != spec["subject"]["digest"]
                    or decision["effect"] != spec["effect"]
                    or decision["expires_at"] != expected_expires_at
                    or decision["expires_at_epoch_us"]
                    != int(_parse(expected_expires_at).timestamp() * 1_000_000)
                    or (decision["consumed_at"] is None) != (decision["consumed_nonce"] is None)
                ):
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Decision projection is inconsistent"
                    )
                nonce = decision["consumed_nonce"]
                if nonce is None:
                    if decision_id in consumed_audit:
                        raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Decision consumption state is inconsistent")
                    continue
                referenced_nonces.add(nonce)
                nonce_row = self._connection.execute(
                    "SELECT * FROM nonces WHERE nonce = ?", (nonce,)
                ).fetchone()
                if (
                    nonce_row is None
                    or nonce_row["purpose"] != "decision-consume"
                    or nonce_row["run_id"] != decision["run_id"]
                    or nonce_row["subject_digest"] != decision["subject_digest"]
                    or consumed_audit.get(decision_id) != decision["decision_digest"]
                ):
                    raise RuntimeStoreError("ECO_JOURNAL_CORRUPT", "Decision nonce or audit binding is inconsistent")
            nonce_inventory = {
                row["nonce"] for row in self._connection.execute("SELECT nonce FROM nonces")
            }
            if nonce_inventory != referenced_nonces:
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Nonce and consumed-decision inventories differ"
                )

            authority_rows = list(
                self._connection.execute(
                    "SELECT * FROM authority_revisions ORDER BY entity_type, entity_id, revision"
                )
            )
            if {row["audit_sequence"] for row in authority_rows} != set(authority_audit):
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Authority revision and audit inventories differ"
                )
            latest: dict[tuple[str, str], sqlite3.Row] = {}
            for row in authority_rows:
                expected = (row["entity_type"], row["entity_id"], row["state_digest"])
                if authority_audit.get(row["audit_sequence"]) != expected:
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Authority revision is not audit-bound"
                    )
                key = (row["entity_type"], row["entity_id"])
                previous_revision = latest[key]["revision"] if key in latest else 0
                if row["revision"] != previous_revision + 1:
                    raise RuntimeStoreError(
                        "ECO_JOURNAL_CORRUPT", "Authority revision sequence is broken"
                    )
                latest[key] = row

            authority_tables = {
                "run": ("runs", "run_id"),
                "plan": ("plans", "plan_id"),
                "budget": ("budgets", "run_id"),
                "operation": ("operations", "operation_id"),
                "reservation": ("budget_reservations", "operation_id"),
                "event-baseline": ("run_event_baselines", "run_id"),
                "checkpoint": ("run_checkpoints", "run_id"),
            }
            live_entities: set[tuple[str, str]] = set()
            for entity_type, (table, id_column) in authority_tables.items():
                for row in self._connection.execute(f"SELECT * FROM {table}"):
                    entity_id = row[id_column]
                    key = (entity_type, entity_id)
                    live_entities.add(key)
                    revision = latest.get(key)
                    if revision is None or revision["state_digest"] != self._authority_state_digest(
                        entity_type, entity_id, row
                    ):
                        raise RuntimeStoreError(
                            "ECO_JOURNAL_CORRUPT", "Mutable authority projection was altered"
                        )
            if set(latest) != live_entities:
                raise RuntimeStoreError(
                    "ECO_JOURNAL_CORRUPT", "Authority revision references a missing entity"
                )
            self._verify_authority_semantics(record_objects, record_digests)
