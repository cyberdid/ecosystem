from __future__ import annotations

"""Separate authenticated M3 authority for one-file controlled writes.

The journal contains only canonical metadata, digests, opaque identities, and
fencing tokens' digests.  Repository paths and file content belong to the
broker-owned recovery bundle and are intentionally outside this database.
"""

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

from .approval import ApprovalTrustStore, approval_subject_payload, parse_utc
from .digests import DIGEST_PROFILE, canonical_json, semantic_digest
from .errors import RuntimeStoreError


CHANGE_STORE_APPLICATION_ID = 1162039090
CHANGE_STORE_SCHEMA_VERSION = 1
GENESIS_DIGEST = "0" * 64
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_RECOVERY_REF = re.compile(
    r"artifact://(?!\.\.?(?:/|$))(?!.*?/\.\.?(?:/|$))(?!.*//)"
    r"(?!.*\\)(?!.*%2[fF]|.*%5[cC])[A-Za-z0-9][A-Za-z0-9._:/-]{0,4095}\Z"
)
_PROPOSAL_FIELDS = frozenset(
    {
        "proposalId", "projectId", "runId", "planDigest", "policyDecisionDigest", "actionClass",
        "operationKind", "rootIdentityDigest", "baseDigest", "targetRefDigest",
        "desiredDigest", "rollbackDigest", "displayDigest", "limits",
    }
)
_LIMIT_FIELDS = frozenset(
    {"maxBytes", "maxFiles", "maxOperations", "approvalExpiresAt"}
)
_NONTERMINAL = frozenset(
    {"prepared", "applying", "commit_ready", "rollback_ready", "rolling_back", "recovery_required"}
)


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("store timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _epoch_us(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("store timestamps must be timezone-aware")
    return int(value.astimezone(timezone.utc).timestamp() * 1_000_000)


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise RuntimeStoreError("ECO_CHANGE_INVALID", f"Change {field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise RuntimeStoreError("ECO_CHANGE_INVALID", f"Change {field} is invalid")
    return value


def _recovery_reference(value: Any) -> str:
    if not isinstance(value, str) or _RECOVERY_REF.fullmatch(value) is None:
        raise RuntimeStoreError(
            "ECO_CHANGE_INVALID", "Recovery storage reference is not an opaque artifact reference"
        )
    return value


def _recovery_length(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise RuntimeStoreError("ECO_CHANGE_INVALID", "Recovery artifact length is invalid")
    return value


class SQLiteChangeAuthority:
    """Authenticated, content-free authority for parameter-bound A2 writes."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        hmac_key: bytes,
        key_id: str,
        approval_trust_store: ApprovalTrustStore,
        forbidden_root: str | os.PathLike[str] | None = None,
        store_id: str | None = None,
    ) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        _id(key_id, "audit key id")
        self._path = Path(path).resolve()
        if forbidden_root is not None:
            root = Path(forbidden_root).resolve()
            try:
                self._path.relative_to(root)
            except ValueError:
                pass
            else:
                raise RuntimeStoreError(
                    "ECO_CHANGE_STORE_LOCATION_DENIED",
                    "Change authority must be outside the governed repository",
                )
        parent_existed = self._path.parent.exists()
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            if parent_existed and self._path.parent.stat().st_mode & 0o077:
                raise RuntimeStoreError(
                    "ECO_CHANGE_STORE_PERMISSIONS", "Change store directory is not private"
                )
            if not parent_existed:
                os.chmod(self._path.parent, 0o700)
            if self._path.exists() and self._path.stat().st_mode & 0o077:
                raise RuntimeStoreError(
                    "ECO_CHANGE_STORE_PERMISSIONS", "Change store file is not private"
                )
            if not self._path.exists():
                descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
        self._hmac_key = hmac_key
        self._key_id = key_id
        if not isinstance(approval_trust_store, ApprovalTrustStore):
            raise TypeError("approval_trust_store must be configured")
        self._approval_trust_store = approval_trust_store
        self._requested_store_id = store_id
        if store_id is not None:
            _id(store_id, "store id")
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self._path, timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._initialize_or_verify()
            if os.name == "posix":
                os.chmod(self._path, 0o600)
            self.verify()
        except Exception:
            self._connection.close()
            raise

    @property
    def store_id(self) -> str:
        return self._store_id

    def __enter__(self) -> "SQLiteChangeAuthority":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

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

    def _meta_payload(self, *, store_id: str, created_at: str) -> dict[str, Any]:
        return {
            "domain": "eco-change-store-meta-v1",
            "storeId": store_id,
            "applicationId": CHANGE_STORE_APPLICATION_ID,
            "schemaVersion": CHANGE_STORE_SCHEMA_VERSION,
            "digestProfile": DIGEST_PROFILE,
            "auditKeyId": self._key_id,
            "createdAt": created_at,
        }

    def _initialize_or_verify(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()[0]
        version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id not in {0, CHANGE_STORE_APPLICATION_ID} or version not in {
            0, CHANGE_STORE_SCHEMA_VERSION
        }:
            raise RuntimeStoreError("ECO_CHANGE_STORE_PROFILE", "Change store profile is unsupported")
        if version == 0:
            now = _utc(datetime.now(timezone.utc))
            store_id = self._requested_store_id or f"change-{secrets.token_hex(12)}"
            payload = self._meta_payload(store_id=store_id, created_at=now)
            tag = hmac.new(
                self._hmac_key, canonical_json(payload).encode("utf-8"), hashlib.sha256
            ).hexdigest()
            self._connection.executescript(
                f"""
                BEGIN IMMEDIATE;
                CREATE TABLE store_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL,
                    application_id INTEGER NOT NULL, schema_version INTEGER NOT NULL,
                    digest_profile TEXT NOT NULL, audit_key_id TEXT NOT NULL,
                    created_at TEXT NOT NULL, meta_hmac TEXT NOT NULL
                );
                CREATE TABLE proposals (
                    proposal_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, run_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL, proposal_digest TEXT NOT NULL UNIQUE,
                    subject_digest TEXT NOT NULL UNIQUE, target_ref_digest TEXT NOT NULL,
                    canonical_json BLOB NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE approvals (
                    approval_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
                    subject_digest TEXT NOT NULL, envelope_digest TEXT NOT NULL UNIQUE,
                    human_id TEXT NOT NULL, assurance TEXT NOT NULL, key_id TEXT NOT NULL,
                    challenge_nonce TEXT NOT NULL UNIQUE, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    expires_at_epoch_us INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('issued','consumed')),
                    consumed_at TEXT, consumed_operation_id TEXT UNIQUE, canonical_json BLOB NOT NULL
                );
                CREATE TABLE operations (
                    operation_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, proposal_id TEXT NOT NULL REFERENCES proposals(proposal_id),
                    approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(approval_id), idempotency_key_digest TEXT NOT NULL,
                    policy_decision_digest TEXT NOT NULL UNIQUE,
                    intent_digest TEXT NOT NULL UNIQUE,
                    recovery_storage_ref TEXT NOT NULL, recovery_sha256 TEXT NOT NULL,
                    recovery_byte_length INTEGER NOT NULL CHECK(recovery_byte_length>=0),
                    recovery_metadata_digest TEXT NOT NULL,
                    before_proof_digest TEXT,
                    execution_intent_digest TEXT,
                    target_ref_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN
                    ('prepared','applying','commit_ready','applied','committed','rollback_ready','rolling_back','rolled_back','failed','recovery_required')),
                    recovery_phase TEXT CHECK(recovery_phase IN ('apply','rollback')),
                    lease_owner_id TEXT, lease_epoch INTEGER NOT NULL CHECK(lease_epoch>=1),
                    lease_token_digest TEXT, lease_until_epoch_us INTEGER,
                    apply_receipt_digest TEXT, rollback_receipt_digest TEXT,
                    failure_digest TEXT, recovery_reason_digest TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(run_id,idempotency_key_digest)
                );
                CREATE TABLE target_locks (
                    target_ref_digest TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active','released')), updated_at TEXT NOT NULL
                );
                CREATE TABLE audit_entries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, transaction_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, action TEXT NOT NULL,
                    state_digest TEXT NOT NULL, previous_entry_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE, hmac_tag TEXT NOT NULL,
                    key_id TEXT NOT NULL, occurred_at TEXT NOT NULL
                );
                PRAGMA application_id = {CHANGE_STORE_APPLICATION_ID};
                PRAGMA user_version = {CHANGE_STORE_SCHEMA_VERSION};
                COMMIT;
                """
            )
            with self._transaction():
                self._connection.execute(
                    "INSERT INTO store_meta VALUES (1,?,?,?,?,?,?,?)",
                    (
                        store_id, CHANGE_STORE_APPLICATION_ID, CHANGE_STORE_SCHEMA_VERSION,
                        DIGEST_PROFILE, self._key_id, now, tag,
                    ),
                )
        meta = self._connection.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
        if meta is None:
            raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Change store metadata is absent")
        payload = self._meta_payload(store_id=meta["store_id"], created_at=meta["created_at"])
        expected = hmac.new(
            self._hmac_key, canonical_json(payload).encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if (
            meta["application_id"] != CHANGE_STORE_APPLICATION_ID
            or meta["schema_version"] != CHANGE_STORE_SCHEMA_VERSION
            or meta["digest_profile"] != DIGEST_PROFILE
            or meta["audit_key_id"] != self._key_id
            or not hmac.compare_digest(meta["meta_hmac"], expected)
            or (self._requested_store_id is not None and meta["store_id"] != self._requested_store_id)
        ):
            raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Change store metadata is untrusted")
        self._store_id = meta["store_id"]

    @staticmethod
    def _row_digest(row: sqlite3.Row | Mapping[str, Any]) -> str:
        payload: dict[str, Any] = {}
        for key in row.keys():
            value = row[key]
            payload[key] = bytes(value).decode("utf-8") if isinstance(value, bytes) else value
        return semantic_digest(payload)

    def _audit(
        self, *, transaction_id: str, entity_type: str, entity_id: str,
        action: str, state_digest: str, occurred_at: str,
    ) -> None:
        previous = self._connection.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["entry_hash"] if previous else GENESIS_DIGEST
        sequence = self._connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM audit_entries"
        ).fetchone()[0]
        payload = {
            "domain": "eco-change-audit-v1", "storeId": self._store_id,
            "sequence": sequence, "transactionId": transaction_id,
            "entityType": entity_type, "entityId": entity_id, "action": action,
            "stateDigest": state_digest, "previousEntryHash": previous_hash,
            "occurredAt": occurred_at,
        }
        entry_hash = semantic_digest(payload)
        tag = hmac.new(self._hmac_key, bytes.fromhex(entry_hash), hashlib.sha256).hexdigest()
        self._connection.execute(
            "INSERT INTO audit_entries VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence, transaction_id, entity_type, entity_id, action, state_digest,
                previous_hash, entry_hash, tag, self._key_id, occurred_at,
            ),
        )

    def _audit_row(
        self, table: str, id_column: str, entity_type: str, entity_id: str,
        *, transaction_id: str, action: str, occurred_at: str,
    ) -> None:
        row = self._connection.execute(
            f"SELECT * FROM {table} WHERE {id_column}=?", (entity_id,)
        ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Audited authority row is absent")
        self._audit(
            transaction_id=transaction_id, entity_type=entity_type, entity_id=entity_id,
            action=action, state_digest=self._row_digest(row), occurred_at=occurred_at,
        )

    @staticmethod
    def _validated_proposal(candidate: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(candidate, Mapping) or set(candidate) != _PROPOSAL_FIELDS:
            raise RuntimeStoreError("ECO_CHANGE_INVALID", "Change proposal shape is invalid")
        proposal = copy.deepcopy(dict(candidate))
        for field in ("proposalId", "projectId", "runId"):
            _id(proposal[field], field)
        for field in (
            "planDigest", "policyDecisionDigest", "rootIdentityDigest", "baseDigest", "targetRefDigest",
            "desiredDigest", "rollbackDigest", "displayDigest",
        ):
            _digest(proposal[field], field)
        if proposal["actionClass"] != "A2" or proposal["operationKind"] not in {"create", "replace"}:
            raise RuntimeStoreError("ECO_CHANGE_SCOPE", "Only one-file A2 create/replace is supported")
        limits = proposal["limits"]
        if not isinstance(limits, Mapping) or set(limits) != _LIMIT_FIELDS:
            raise RuntimeStoreError("ECO_CHANGE_INVALID", "Change limits shape is invalid")
        if (
            type(limits["maxBytes"]) is not int or not 0 <= limits["maxBytes"] <= 100_000_000
            or limits["maxFiles"] != 1
            or type(limits["maxOperations"]) is not int
            or not 1 <= limits["maxOperations"] <= 10_000
        ):
            raise RuntimeStoreError("ECO_CHANGE_SCOPE", "Single-file limits are invalid")
        parse_utc(limits["approvalExpiresAt"])
        return proposal

    def register_proposal(self, proposal: Mapping[str, Any], *, now: datetime) -> dict[str, str]:
        proposal = self._validated_proposal(proposal)
        now_text = _utc(now)
        body = {"domain": "eco-change-proposal-v1", **proposal}
        proposal_digest = semantic_digest(body)
        limits_digest = semantic_digest(proposal["limits"])
        subject_payload = approval_subject_payload(
            store_id=self._store_id, project_id=proposal["projectId"], run_id=proposal["runId"],
            plan_digest=proposal["planDigest"],
            policy_decision_digest=proposal["policyDecisionDigest"],
            proposal_digest=proposal_digest,
            action_class=proposal["actionClass"], operation_kind=proposal["operationKind"],
            root_identity_digest=proposal["rootIdentityDigest"], base_digest=proposal["baseDigest"],
            target_ref_digest=proposal["targetRefDigest"], desired_digest=proposal["desiredDigest"],
            rollback_digest=proposal["rollbackDigest"], display_digest=proposal["displayDigest"],
            limits_digest=limits_digest,
        )
        subject_digest = semantic_digest(subject_payload)
        stored = {**body, "proposalDigest": proposal_digest, "subjectDigest": subject_digest,
                  "limitsDigest": limits_digest}
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal["proposalId"],)
            ).fetchone()
            if existing is not None:
                if existing["proposal_digest"] != proposal_digest:
                    raise RuntimeStoreError("ECO_CHANGE_ID_CONFLICT", "Proposal id has another digest")
                return {"proposalDigest": proposal_digest, "subjectDigest": subject_digest}
            self._connection.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    proposal["proposalId"], proposal["projectId"], proposal["runId"],
                    proposal["planDigest"], proposal_digest, subject_digest,
                    proposal["targetRefDigest"], canonical_json(stored).encode("utf-8"), now_text,
                ),
            )
            self._audit_row(
                "proposals", "proposal_id", "proposal", proposal["proposalId"],
                transaction_id=transaction_id, action="registered", occurred_at=now_text,
            )
        return {"proposalDigest": proposal_digest, "subjectDigest": subject_digest}

    def proposal_status(self, proposal_id: str) -> dict[str, Any]:
        """Return the exact content-free authority proposal for trusted reconciliation."""

        _id(proposal_id, "proposal id")
        with self._lock:
            row = self._connection.execute(
                "SELECT canonical_json FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_CHANGE_UNKNOWN", "Change proposal does not exist")
        try:
            return json.loads(bytes(row["canonical_json"]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeStoreError(
                "ECO_CHANGE_STORE_CORRUPT", "Change proposal record is invalid"
            ) from exc

    def record_verified_grant(
        self, envelope: Mapping[str, Any], *, now: datetime
    ) -> dict[str, Any]:
        subject = envelope.get("subjectDigest") if isinstance(envelope, Mapping) else None
        if not isinstance(subject, str):
            raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval subject is absent")
        with self._lock:
            proposal = self._connection.execute(
                "SELECT * FROM proposals WHERE subject_digest=?", (subject,)
            ).fetchone()
        if proposal is None:
            raise RuntimeStoreError("ECO_APPROVAL_MISMATCH", "Approval proposal is unknown")
        verified = self._approval_trust_store.verify(
            envelope, expected_subject_digest=subject, now=now
        )
        body = verified.envelope
        now_text = _utc(now)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            existing = self._connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (body["approvalId"],)
            ).fetchone()
            if existing is not None:
                if existing["envelope_digest"] != verified.envelope_digest:
                    raise RuntimeStoreError("ECO_APPROVAL_ID_CONFLICT", "Approval id has another envelope")
                return dict(existing)
            try:
                self._connection.execute(
                    "INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,'issued',NULL,NULL,?)",
                    (
                        body["approvalId"], proposal["proposal_id"], subject,
                        verified.envelope_digest, body["humanId"], body["assurance"], body["keyId"],
                        body["challengeNonce"], body["issuedAt"], body["expiresAt"],
                        _epoch_us(parse_utc(body["expiresAt"])),
                        canonical_json(body).encode("utf-8"),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeStoreError("ECO_APPROVAL_REPLAY", "Approval challenge was already used") from exc
            self._audit_row(
                "approvals", "approval_id", "approval", body["approvalId"],
                transaction_id=transaction_id, action="issued", occurred_at=now_text,
            )
            return dict(self._connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (body["approvalId"],)
            ).fetchone())

    issue_grant = record_verified_grant

    @staticmethod
    def _lease_digest(token: str) -> str:
        return semantic_digest({"domain": "eco-change-lease-v1", "token": token})

    @staticmethod
    def _intent_digest(
        *, operation_id: str, proposal_id: str, approval_id: str,
        policy_decision_digest: str, idempotency_key_digest: str,
        recovery_storage_ref: str, recovery_sha256: str,
        recovery_byte_length: int, recovery_metadata_digest: str,
    ) -> str:
        return semantic_digest(
            {
                "domain": "eco-change-intent-v1",
                "operationId": operation_id,
                "proposalId": proposal_id,
                "approvalId": approval_id,
                "policyDecisionDigest": policy_decision_digest,
                "idempotencyKeyDigest": idempotency_key_digest,
                "recoveryStorageRef": recovery_storage_ref,
                "recoverySha256": recovery_sha256,
                "recoveryByteLength": recovery_byte_length,
                "recoveryMetadataDigest": recovery_metadata_digest,
            }
        )

    def prepare_operation(
        self, *, operation_id: str, proposal_id: str, approval_id: str,
        idempotency_key: str, recovery_storage_ref: str, recovery_sha256: str,
        recovery_byte_length: int, recovery_metadata_digest: str, owner_id: str,
        now: datetime, lease_seconds: int = 30,
    ) -> dict[str, Any]:
        for value, field in ((operation_id, "operation id"), (proposal_id, "proposal id"),
                             (approval_id, "approval id"), (owner_id, "owner id")):
            _id(value, field)
        _id(idempotency_key, "idempotency key")
        _recovery_reference(recovery_storage_ref)
        _digest(recovery_sha256, "recovery artifact digest")
        _recovery_length(recovery_byte_length)
        _digest(recovery_metadata_digest, "recovery metadata digest")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        now_text = _utc(now)
        now_epoch = _epoch_us(now)
        idem_digest = semantic_digest({"domain": "eco-change-idempotency-v1", "key": idempotency_key})
        lease_token = secrets.token_hex(32)
        lease_until = now.astimezone(timezone.utc) + timedelta(seconds=lease_seconds)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            proposal = self._connection.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            approval = self._connection.execute(
                "SELECT * FROM approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if proposal is None or approval is None or approval["proposal_id"] != proposal_id:
                raise RuntimeStoreError("ECO_CHANGE_AUTHORITY_MISMATCH", "Proposal or approval is not bound")
            try:
                proposal_record = json.loads(bytes(proposal["canonical_json"]).decode("utf-8"))
                policy_decision_digest = _digest(
                    proposal_record["policyDecisionDigest"], "policy decision digest"
                )
                maximum_operations = proposal_record["limits"]["maxOperations"]
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeStoreError(
                    "ECO_CHANGE_STORE_CORRUPT", "Proposal operation authority is invalid"
                ) from exc
            intent_digest = self._intent_digest(
                operation_id=operation_id,
                proposal_id=proposal_id,
                approval_id=approval_id,
                policy_decision_digest=policy_decision_digest,
                idempotency_key_digest=idem_digest,
                recovery_storage_ref=recovery_storage_ref,
                recovery_sha256=recovery_sha256,
                recovery_byte_length=recovery_byte_length,
                recovery_metadata_digest=recovery_metadata_digest,
            )
            existing = self._connection.execute(
                "SELECT * FROM operations WHERE run_id=? AND idempotency_key_digest=?",
                (proposal["run_id"], idem_digest),
            ).fetchone()
            if existing is not None:
                if existing["intent_digest"] != intent_digest:
                    raise RuntimeStoreError("ECO_CHANGE_IDEMPOTENCY_CONFLICT", "Key is bound to another intent")
                result = dict(existing)
                result["replayed"] = True
                return result
            operation_count = self._connection.execute(
                "SELECT COUNT(*) FROM operations WHERE run_id=?", (proposal["run_id"],)
            ).fetchone()[0]
            if operation_count >= maximum_operations:
                raise RuntimeStoreError(
                    "ECO_CHANGE_BUDGET_EXHAUSTED", "Plan write-operation budget is exhausted"
                )
            if approval["state"] != "issued" or approval["expires_at_epoch_us"] <= now_epoch:
                code = "ECO_APPROVAL_CONSUMED" if approval["state"] != "issued" else "ECO_APPROVAL_EXPIRED"
                raise RuntimeStoreError(code, "Approval is not available for PREPARE")
            consumed_decision = self._connection.execute(
                "SELECT operation_id FROM operations WHERE policy_decision_digest=?",
                (policy_decision_digest,),
            ).fetchone()
            if consumed_decision is not None:
                raise RuntimeStoreError(
                    "ECO_POLICY_DECISION_CONSUMED",
                    "Policy allow decision was already consumed by another operation",
                )
            lock = self._connection.execute(
                "SELECT * FROM target_locks WHERE target_ref_digest=?", (proposal["target_ref_digest"],)
            ).fetchone()
            if lock is not None and lock["state"] == "active":
                raise RuntimeStoreError("ECO_CHANGE_TARGET_LOCKED", "Change target is already locked")
            try:
                self._connection.execute(
                    """INSERT INTO operations (
                       operation_id,run_id,proposal_id,approval_id,idempotency_key_digest,
                       policy_decision_digest,intent_digest,recovery_storage_ref,recovery_sha256,
                       recovery_byte_length,recovery_metadata_digest,before_proof_digest,
                       execution_intent_digest,target_ref_digest,state,recovery_phase,
                       lease_owner_id,lease_epoch,lease_token_digest,lease_until_epoch_us,
                       apply_receipt_digest,rollback_receipt_digest,failure_digest,
                       recovery_reason_digest,created_at,updated_at
                       ) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,'prepared','apply',?,1,?,?,
                       NULL,NULL,NULL,NULL,?,?)""",
                    (
                        operation_id, proposal["run_id"], proposal_id, approval_id, idem_digest,
                        policy_decision_digest, intent_digest, recovery_storage_ref,
                        recovery_sha256, recovery_byte_length, recovery_metadata_digest,
                        proposal["target_ref_digest"], owner_id, self._lease_digest(lease_token),
                        _epoch_us(lease_until), now_text, now_text,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeStoreError("ECO_CHANGE_OPERATION_CONFLICT", "Operation identity is already bound") from exc
            updated = self._connection.execute(
                """UPDATE approvals SET state='consumed', consumed_at=?, consumed_operation_id=?
                   WHERE approval_id=? AND state='issued' AND expires_at_epoch_us>?""",
                (now_text, operation_id, approval_id, now_epoch),
            )
            if updated.rowcount != 1:
                raise RuntimeStoreError("ECO_APPROVAL_CONSUMED", "Approval was consumed concurrently")
            if lock is None:
                self._connection.execute(
                    "INSERT INTO target_locks VALUES (?,?,'active',?)",
                    (proposal["target_ref_digest"], operation_id, now_text),
                )
            else:
                self._connection.execute(
                    "UPDATE target_locks SET operation_id=?,state='active',updated_at=? WHERE target_ref_digest=?",
                    (operation_id, now_text, proposal["target_ref_digest"]),
                )
            for table, column, entity, entity_id, action in (
                ("approvals", "approval_id", "approval", approval_id, "consumed"),
                ("operations", "operation_id", "operation", operation_id, "prepared"),
                ("target_locks", "target_ref_digest", "target-lock", proposal["target_ref_digest"], "acquired"),
            ):
                self._audit_row(table, column, entity, entity_id, transaction_id=transaction_id,
                                action=action, occurred_at=now_text)
        return {
            "operationId": operation_id, "state": "prepared", "leaseToken": lease_token,
            "leaseEpoch": 1, "leaseUntil": _utc(lease_until), "intentDigest": intent_digest,
            "replayed": False,
        }

    def operation_status(self, operation_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_CHANGE_OPERATION_UNKNOWN", "Change operation does not exist")
        return dict(row)

    def approval_status(self, approval_id: str) -> dict[str, Any]:
        """Return content-free approval authority metadata for exact replay checks."""

        _id(approval_id, "approval id")
        with self._lock:
            row = self._connection.execute(
                """SELECT approval_id,proposal_id,subject_digest,envelope_digest,state,
                          consumed_operation_id FROM approvals WHERE approval_id=?""",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise RuntimeStoreError("ECO_APPROVAL_UNKNOWN", "Approval does not exist")
        return dict(row)

    def _require_lease(
        self, row: sqlite3.Row, *, owner_id: str, lease_token: str,
        lease_epoch: int, now: datetime,
    ) -> None:
        if (
            row["lease_owner_id"] != owner_id or row["lease_epoch"] != lease_epoch
            or row["lease_token_digest"] is None
            or not hmac.compare_digest(row["lease_token_digest"], self._lease_digest(lease_token))
        ):
            raise RuntimeStoreError("ECO_CHANGE_FENCED", "Change operation lease is stale")
        if row["lease_until_epoch_us"] is None or row["lease_until_epoch_us"] <= _epoch_us(now):
            raise RuntimeStoreError("ECO_CHANGE_LEASE_EXPIRED", "Change operation lease expired")

    def assert_operation_lease(
        self,
        operation_id: str,
        *,
        owner_id: str,
        lease_token: str,
        lease_epoch: int,
        now: datetime,
        required_state: str = "applying",
    ) -> None:
        """Recheck the fenced in-flight authority immediately before commit I/O."""

        _id(operation_id, "operation id")
        _id(owner_id, "owner id")
        if required_state not in {"rollback_ready", "applying", "rolling_back"}:
            raise ValueError("required_state is not an in-flight write state")
        _utc(now)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError(
                    "ECO_CHANGE_OPERATION_UNKNOWN", "Change operation does not exist"
                )
            if row["state"] != required_state:
                raise RuntimeStoreError(
                    "ECO_CHANGE_STATE", "Change operation is not authorized for commit I/O"
                )
            self._require_lease(
                row,
                owner_id=owner_id,
                lease_token=lease_token,
                lease_epoch=lease_epoch,
                now=now,
            )

    def _set_lock(self, row: sqlite3.Row, *, active: bool, now_text: str, transaction_id: str) -> None:
        lock = self._connection.execute(
            "SELECT * FROM target_locks WHERE target_ref_digest=?", (row["target_ref_digest"],)
        ).fetchone()
        if active:
            if lock is not None and lock["state"] == "active" and lock["operation_id"] != row["operation_id"]:
                raise RuntimeStoreError("ECO_CHANGE_TARGET_LOCKED", "Change target is already locked")
            if lock is None:
                self._connection.execute(
                    "INSERT INTO target_locks VALUES (?,?,'active',?)",
                    (row["target_ref_digest"], row["operation_id"], now_text),
                )
            else:
                self._connection.execute(
                    "UPDATE target_locks SET operation_id=?,state='active',updated_at=? WHERE target_ref_digest=?",
                    (row["operation_id"], now_text, row["target_ref_digest"]),
                )
        elif lock is not None and lock["operation_id"] == row["operation_id"]:
            self._connection.execute(
                "UPDATE target_locks SET state='released',updated_at=? WHERE target_ref_digest=?",
                (now_text, row["target_ref_digest"]),
            )
        self._audit_row(
            "target_locks", "target_ref_digest", "target-lock", row["target_ref_digest"],
            transaction_id=transaction_id, action="acquired" if active else "released",
            occurred_at=now_text,
        )

    def _transition(
        self, operation_id: str, *, allowed: set[str], target: str, owner_id: str,
        lease_token: str, lease_epoch: int, now: datetime,
        receipt_column: str | None = None, receipt_digest: str | None = None,
        reason_column: str | None = None, reason_digest: str | None = None,
        recovery_phase: str | None = None, lock_active: bool | None = None,
        recovery_source_phase: str | None = None,
        recovery_storage_ref: str | None = None,
        recovery_sha256: str | None = None,
        recovery_byte_length: int | None = None,
        recovery_metadata_digest: str | None = None,
    ) -> dict[str, Any]:
        _id(operation_id, "operation id")
        _id(owner_id, "owner id")
        if receipt_column is not None:
            _digest(receipt_digest, "receipt digest")
        if reason_column is not None:
            _digest(reason_digest, "reason digest")
        now_text = _utc(now)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError("ECO_CHANGE_OPERATION_UNKNOWN", "Change operation does not exist")
            if row["state"] == target:
                replay_mismatch = (
                    (receipt_column is not None and row[receipt_column] != receipt_digest)
                    or (reason_column is not None and row[reason_column] != reason_digest)
                    or (
                        recovery_storage_ref is not None
                        and (
                            row["recovery_storage_ref"] != recovery_storage_ref
                            or row["recovery_sha256"] != recovery_sha256
                            or row["recovery_byte_length"] != recovery_byte_length
                            or row["recovery_metadata_digest"] != recovery_metadata_digest
                        )
                    )
                )
                if replay_mismatch:
                    raise RuntimeStoreError(
                        "ECO_CHANGE_IDEMPOTENCY_CONFLICT",
                        "Repeated change transition has different authority bindings",
                    )
                return dict(row)
            if row["state"] not in allowed:
                raise RuntimeStoreError("ECO_CHANGE_STATE", "Change transition is not allowed")
            if (
                row["state"] == "recovery_required" and recovery_source_phase is not None
                and row["recovery_phase"] != recovery_source_phase
            ):
                raise RuntimeStoreError(
                    "ECO_CHANGE_RECOVERY_PHASE", "Recovery direction does not permit transition"
                )
            if target == "applying" and (
                row["before_proof_digest"] is None or row["execution_intent_digest"] is None
            ):
                raise RuntimeStoreError(
                    "ECO_CHANGE_ROLLBACK_UNREADY",
                    "Before proof and execution intent must be durable before apply",
                )
            self._require_lease(row, owner_id=owner_id, lease_token=lease_token,
                                lease_epoch=lease_epoch, now=now)
            assignments = ["state=?", "updated_at=?"]
            values: list[Any] = [target, now_text]
            if target == "recovery_required":
                recovery_phase = (
                    "rollback" if row["state"] in {"applied", "rolling_back"} else "apply"
                )
            if recovery_phase is not None:
                assignments.append("recovery_phase=?")
                values.append(recovery_phase)
            if receipt_column is not None:
                assignments.append(f"{receipt_column}=?")
                values.append(receipt_digest)
            if reason_column is not None:
                assignments.append(f"{reason_column}=?")
                values.append(reason_digest)
            if recovery_storage_ref is not None:
                assignments.extend(
                    [
                        "recovery_storage_ref=?", "recovery_sha256=?",
                        "recovery_byte_length=?", "recovery_metadata_digest=?",
                        "intent_digest=?",
                    ]
                )
                values.extend(
                    [
                        recovery_storage_ref, recovery_sha256, recovery_byte_length,
                        recovery_metadata_digest,
                        self._intent_digest(
                            operation_id=row["operation_id"], proposal_id=row["proposal_id"],
                            approval_id=row["approval_id"],
                            policy_decision_digest=row["policy_decision_digest"],
                            idempotency_key_digest=row["idempotency_key_digest"],
                            recovery_storage_ref=recovery_storage_ref,
                            recovery_sha256=recovery_sha256,
                            recovery_byte_length=recovery_byte_length,
                            recovery_metadata_digest=recovery_metadata_digest,
                        ),
                    ]
                )
            # APPLIED retains its fenced lease long enough to enter the exact
            # pre-authorized rollback path.  Final rollback/failure clears it.
            if target in {"committed", "rolled_back", "failed"}:
                assignments.extend(
                    ["lease_owner_id=NULL", "lease_token_digest=NULL", "lease_until_epoch_us=NULL"]
                )
            values.append(operation_id)
            self._connection.execute(
                f"UPDATE operations SET {','.join(assignments)} WHERE operation_id=?", values
            )
            updated = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if lock_active is not None:
                self._set_lock(updated, active=lock_active, now_text=now_text,
                               transaction_id=transaction_id)
            self._audit_row(
                "operations", "operation_id", "operation", operation_id,
                transaction_id=transaction_id, action=target, occurred_at=now_text,
            )
            return dict(updated)

    def mark_rollback_ready(
        self, operation_id: str, *, before_proof_digest: str,
        execution_intent_digest: str, recovery_storage_ref: str,
        recovery_sha256: str, recovery_byte_length: int,
        recovery_metadata_digest: str, **lease: Any
    ) -> dict[str, Any]:
        """Durably bind the exact before-state/absence proof before write I/O."""

        _recovery_reference(recovery_storage_ref)
        _digest(recovery_sha256, "recovery artifact digest")
        _recovery_length(recovery_byte_length)
        _digest(recovery_metadata_digest, "recovery metadata digest")

        return self._transition(
            operation_id, allowed={"prepared", "recovery_required"}, target="rollback_ready",
            reason_column="before_proof_digest", reason_digest=before_proof_digest,
            receipt_column="execution_intent_digest", receipt_digest=execution_intent_digest,
            recovery_phase="apply", recovery_source_phase="apply", lock_active=True, **lease,
            recovery_storage_ref=recovery_storage_ref, recovery_sha256=recovery_sha256,
            recovery_byte_length=recovery_byte_length,
            recovery_metadata_digest=recovery_metadata_digest,
        )

    def mark_applying(self, operation_id: str, **lease: Any) -> dict[str, Any]:
        return self._transition(operation_id, allowed={"rollback_ready"},
                                target="applying", recovery_phase="apply", lock_active=True, **lease)

    def mark_commit_ready(self, operation_id: str, **lease: Any) -> dict[str, Any]:
        """Durably issue the final one-shot filesystem commit permit."""

        return self._transition(
            operation_id,
            allowed={"applying"},
            target="commit_ready",
            recovery_phase="apply",
            lock_active=True,
            **lease,
        )

    def mark_applied(self, operation_id: str, *, receipt_digest: str, **lease: Any) -> dict[str, Any]:
        return self._transition(operation_id, allowed={"commit_ready"}, target="applied",
                                receipt_column="apply_receipt_digest", receipt_digest=receipt_digest,
                                lock_active=True, **lease)

    def mark_committed(self, operation_id: str, **lease: Any) -> dict[str, Any]:
        """Close the rollback window after postconditions succeed."""

        return self._transition(
            operation_id, allowed={"applied"}, target="committed", lock_active=False, **lease
        )

    def mark_rolling_back(self, operation_id: str, **lease: Any) -> dict[str, Any]:
        """Enter rollback after the caller reconciles the exact live file state.

        A fenced recovery worker may discover that an operation last recorded in
        the apply phase did in fact complete the atomic rename.  The durable
        execution recovery bundle plus broker CAS observation is the authority
        for that direction change, so ``recovery_required`` is accepted from
        either recorded phase.
        """

        return self._transition(operation_id, allowed={"applied", "recovery_required"},
                                target="rolling_back", recovery_phase="rollback",
                                lock_active=True, **lease)

    def mark_rolled_back(self, operation_id: str, *, receipt_digest: str, **lease: Any) -> dict[str, Any]:
        return self._transition(operation_id, allowed={"rolling_back"}, target="rolled_back",
                                receipt_column="rollback_receipt_digest", receipt_digest=receipt_digest,
                                lock_active=False, **lease)

    def mark_failed(self, operation_id: str, *, failure_digest: str, **lease: Any) -> dict[str, Any]:
        return self._transition(operation_id, allowed=set(_NONTERMINAL), target="failed",
                                reason_column="failure_digest", reason_digest=failure_digest,
                                lock_active=False, **lease)

    def mark_recovery_required(
        self, operation_id: str, *, reason_digest: str, **lease: Any
    ) -> dict[str, Any]:
        return self._transition(
            operation_id, allowed={"prepared", "rollback_ready", "applying", "commit_ready", "applied", "rolling_back"},
            target="recovery_required", reason_column="recovery_reason_digest",
            reason_digest=reason_digest, lock_active=True, **lease,
        )

    def record_recovery_conflict(
        self,
        operation_id: str,
        *,
        reason_digest: str,
        owner_id: str,
        lease_token: str,
        lease_epoch: int,
        now: datetime,
    ) -> dict[str, Any]:
        """Durably retain the exact reason an already-claimed recovery cannot proceed."""

        _digest(reason_digest, "recovery reason digest")
        now_text = _utc(now)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError(
                    "ECO_CHANGE_OPERATION_UNKNOWN", "Change operation does not exist"
                )
            if row["state"] != "recovery_required":
                raise RuntimeStoreError(
                    "ECO_CHANGE_STATE", "Operation is not awaiting recovery"
                )
            self._require_lease(
                row,
                owner_id=owner_id,
                lease_token=lease_token,
                lease_epoch=lease_epoch,
                now=now,
            )
            self._connection.execute(
                """UPDATE operations SET recovery_reason_digest=?,updated_at=?
                   WHERE operation_id=?""",
                (reason_digest, now_text, operation_id),
            )
            self._audit_row(
                "operations",
                "operation_id",
                "operation",
                operation_id,
                transaction_id=transaction_id,
                action="recovery_conflict",
                occurred_at=now_text,
            )
            return dict(
                self._connection.execute(
                    "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
                ).fetchone()
            )

    def claim_operation(
        self, operation_id: str, *, owner_id: str, now: datetime, lease_seconds: int = 30
    ) -> dict[str, Any]:
        _id(owner_id, "owner id")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        now_text = _utc(now)
        now_epoch = _epoch_us(now)
        token = secrets.token_hex(32)
        until = now.astimezone(timezone.utc) + timedelta(seconds=lease_seconds)
        transaction_id = secrets.token_hex(16)
        with self._transaction():
            row = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise RuntimeStoreError("ECO_CHANGE_OPERATION_UNKNOWN", "Change operation does not exist")
            if row["state"] not in _NONTERMINAL and row["state"] != "applied":
                return dict(row)
            if row["lease_until_epoch_us"] is not None and row["lease_until_epoch_us"] > now_epoch:
                raise RuntimeStoreError("ECO_CHANGE_IN_PROGRESS", "Change operation lease is active")
            phase = (
                "rollback" if row["state"] in {"applied", "rolling_back"}
                else row["recovery_phase"] or "apply"
            )
            self._connection.execute(
                """UPDATE operations SET state='recovery_required',recovery_phase=?,lease_owner_id=?,
                   lease_epoch=lease_epoch+1,lease_token_digest=?,lease_until_epoch_us=?,updated_at=?
                   WHERE operation_id=?""",
                (phase, owner_id, self._lease_digest(token), _epoch_us(until), now_text, operation_id),
            )
            self._audit_row(
                "operations", "operation_id", "operation", operation_id,
                transaction_id=transaction_id, action="recovery_required", occurred_at=now_text,
            )
            updated = self._connection.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            return {
                "operationId": operation_id, "state": "recovery_required",
                "recoveryPhase": phase, "leaseToken": token,
                "leaseEpoch": updated["lease_epoch"], "leaseUntil": _utc(until),
                "recoveryMetadataDigest": updated["recovery_metadata_digest"],
                "recoveryStorageRef": updated["recovery_storage_ref"],
                "recoverySha256": updated["recovery_sha256"],
                "recoveryByteLength": updated["recovery_byte_length"],
            }

    def scan_recoverable(self, *, now: datetime) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT operation_id,state,recovery_phase,lease_epoch,recovery_storage_ref,
                   recovery_sha256,recovery_byte_length,recovery_metadata_digest
                   FROM operations WHERE state IN ('prepared','applying','commit_ready','applied','rollback_ready','rolling_back','recovery_required')
                   AND (lease_until_epoch_us IS NULL OR lease_until_epoch_us<=?) ORDER BY operation_id""",
                (_epoch_us(now),),
            ).fetchall()
        return tuple(
            {
                **dict(row),
                "recoveryStorageRef": row["recovery_storage_ref"],
                "recoverySha256": row["recovery_sha256"],
                "recoveryByteLength": row["recovery_byte_length"],
                "recoveryMetadataDigest": row["recovery_metadata_digest"],
            }
            for row in rows
        )

    def verify(self) -> None:
        with self._lock:
            self._connection.execute("BEGIN")
            try:
                if self._connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "SQLite integrity check failed")
                meta = self._connection.execute(
                    "SELECT * FROM store_meta WHERE singleton=1"
                ).fetchone()
                if meta is None:
                    raise RuntimeStoreError(
                        "ECO_CHANGE_STORE_CORRUPT", "Change store metadata is absent"
                    )
                meta_payload = self._meta_payload(
                    store_id=meta["store_id"], created_at=meta["created_at"]
                )
                meta_tag = hmac.new(
                    self._hmac_key,
                    canonical_json(meta_payload).encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if (
                    self._connection.execute("PRAGMA application_id").fetchone()[0]
                    != CHANGE_STORE_APPLICATION_ID
                    or self._connection.execute("PRAGMA user_version").fetchone()[0]
                    != CHANGE_STORE_SCHEMA_VERSION
                    or meta["store_id"] != self._store_id
                    or meta["application_id"] != CHANGE_STORE_APPLICATION_ID
                    or meta["schema_version"] != CHANGE_STORE_SCHEMA_VERSION
                    or meta["digest_profile"] != DIGEST_PROFILE
                    or meta["audit_key_id"] != self._key_id
                    or not hmac.compare_digest(meta["meta_hmac"], meta_tag)
                ):
                    raise RuntimeStoreError(
                        "ECO_CHANGE_STORE_CORRUPT", "Change store metadata is untrusted"
                    )
                previous = GENESIS_DIGEST
                sequence = 1
                latest: dict[tuple[str, str], str] = {}
                for row in self._connection.execute("SELECT * FROM audit_entries ORDER BY sequence"):
                    payload = {
                        "domain": "eco-change-audit-v1", "storeId": self._store_id,
                        "sequence": row["sequence"], "transactionId": row["transaction_id"],
                        "entityType": row["entity_type"], "entityId": row["entity_id"],
                        "action": row["action"], "stateDigest": row["state_digest"],
                        "previousEntryHash": row["previous_entry_hash"], "occurredAt": row["occurred_at"],
                    }
                    entry_hash = semantic_digest(payload)
                    tag = hmac.new(self._hmac_key, bytes.fromhex(entry_hash), hashlib.sha256).hexdigest()
                    if (
                        row["sequence"] != sequence or row["previous_entry_hash"] != previous
                        or row["entry_hash"] != entry_hash or row["key_id"] != self._key_id
                        or not hmac.compare_digest(row["hmac_tag"], tag)
                    ):
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Audit authentication failed")
                    latest[(row["entity_type"], row["entity_id"])] = row["state_digest"]
                    previous, sequence = entry_hash, sequence + 1
                live: dict[tuple[str, str], str] = {}
                for table, column, entity in (
                    ("proposals", "proposal_id", "proposal"),
                    ("approvals", "approval_id", "approval"),
                    ("operations", "operation_id", "operation"),
                    ("target_locks", "target_ref_digest", "target-lock"),
                ):
                    for row in self._connection.execute(f"SELECT * FROM {table}"):
                        live[(entity, row[column])] = self._row_digest(row)
                if live != latest:
                    raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Authority and audit inventories differ")
                proposals: dict[str, sqlite3.Row] = {}
                for row in self._connection.execute("SELECT * FROM proposals"):
                    try:
                        record = json.loads(bytes(row["canonical_json"]).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Proposal record is invalid") from exc
                    raw = {name: record[name] for name in _PROPOSAL_FIELDS}
                    checked = self._validated_proposal(raw)
                    body = {"domain": "eco-change-proposal-v1", **checked}
                    proposal_digest = semantic_digest(body)
                    subject = approval_subject_payload(
                        store_id=self._store_id, project_id=checked["projectId"], run_id=checked["runId"],
                        plan_digest=checked["planDigest"],
                        policy_decision_digest=checked["policyDecisionDigest"],
                        proposal_digest=proposal_digest,
                        action_class=checked["actionClass"], operation_kind=checked["operationKind"],
                        root_identity_digest=checked["rootIdentityDigest"], base_digest=checked["baseDigest"],
                        target_ref_digest=checked["targetRefDigest"], desired_digest=checked["desiredDigest"],
                        rollback_digest=checked["rollbackDigest"], display_digest=checked["displayDigest"],
                        limits_digest=semantic_digest(checked["limits"]),
                    )
                    if (
                        canonical_json(record).encode("utf-8") != bytes(row["canonical_json"])
                        or row["proposal_digest"] != proposal_digest
                        or row["subject_digest"] != semantic_digest(subject)
                        or record["proposalDigest"] != proposal_digest
                        or record["subjectDigest"] != row["subject_digest"]
                    ):
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Proposal binding differs")
                    proposals[row["proposal_id"]] = row
                operations = {row["operation_id"]: row for row in self._connection.execute("SELECT * FROM operations")}
                for approval in self._connection.execute("SELECT * FROM approvals"):
                    proposal = proposals.get(approval["proposal_id"])
                    try:
                        envelope = json.loads(bytes(approval["canonical_json"]).decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Approval envelope is invalid") from exc
                    operation = operations.get(approval["consumed_operation_id"])
                    try:
                        verified = self._approval_trust_store.verify_historical(
                            envelope, expected_subject_digest=approval["subject_digest"]
                        )
                    except RuntimeStoreError as exc:
                        raise RuntimeStoreError(
                            "ECO_CHANGE_STORE_CORRUPT", "Stored human approval is untrusted"
                        ) from exc
                    if (
                        proposal is None or approval["subject_digest"] != proposal["subject_digest"]
                        or verified.envelope_digest != approval["envelope_digest"]
                        or envelope.get("approvalId") != approval["approval_id"]
                        or envelope.get("subjectDigest") != approval["subject_digest"]
                        or envelope.get("humanId") != approval["human_id"]
                        or envelope.get("assurance") != approval["assurance"]
                        or envelope.get("keyId") != approval["key_id"]
                        or envelope.get("challengeNonce") != approval["challenge_nonce"]
                        or envelope.get("issuedAt") != approval["issued_at"]
                        or envelope.get("expiresAt") != approval["expires_at"]
                        or approval["expires_at_epoch_us"] != _epoch_us(parse_utc(envelope["expiresAt"]))
                        or (approval["state"] == "issued" and (approval["consumed_at"] is not None or operation is not None))
                        or (approval["state"] == "consumed" and (approval["consumed_at"] is None or operation is None))
                    ):
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Approval binding differs")
                for operation in operations.values():
                    proposal = proposals.get(operation["proposal_id"])
                    approval = self._connection.execute(
                        "SELECT * FROM approvals WHERE approval_id=?", (operation["approval_id"],)
                    ).fetchone()
                    try:
                        proposal_record = json.loads(
                            bytes(proposal["canonical_json"]).decode("utf-8")
                        ) if proposal is not None else {}
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise RuntimeStoreError(
                            "ECO_CHANGE_STORE_CORRUPT", "Proposal record is invalid"
                        ) from exc
                    expected_policy_decision = proposal_record.get("policyDecisionDigest")
                    expected_intent = self._intent_digest(
                        operation_id=operation["operation_id"],
                        proposal_id=operation["proposal_id"],
                        approval_id=operation["approval_id"],
                        policy_decision_digest=operation["policy_decision_digest"],
                        idempotency_key_digest=operation["idempotency_key_digest"],
                        recovery_storage_ref=operation["recovery_storage_ref"],
                        recovery_sha256=operation["recovery_sha256"],
                        recovery_byte_length=operation["recovery_byte_length"],
                        recovery_metadata_digest=operation["recovery_metadata_digest"],
                    )
                    if (
                        proposal is None or approval is None
                        or approval["consumed_operation_id"] != operation["operation_id"]
                        or operation["run_id"] != proposal["run_id"]
                        or operation["target_ref_digest"] != proposal["target_ref_digest"]
                        or operation["policy_decision_digest"] != expected_policy_decision
                        or _RECOVERY_REF.fullmatch(operation["recovery_storage_ref"]) is None
                        or _HEX.fullmatch(operation["recovery_sha256"]) is None
                        or type(operation["recovery_byte_length"]) is not int
                        or operation["recovery_byte_length"] < 0
                        or _HEX.fullmatch(operation["recovery_metadata_digest"]) is None
                        or operation["intent_digest"] != expected_intent
                        or (operation["state"] in {"rollback_ready", "applying", "commit_ready", "applied", "committed", "rolling_back", "rolled_back"}
                            and (operation["before_proof_digest"] is None
                                 or operation["execution_intent_digest"] is None))
                        or (operation["state"] in {"applied", "committed"}
                            and operation["apply_receipt_digest"] is None)
                        or (operation["state"] == "rolled_back" and operation["rollback_receipt_digest"] is None)
                        or (operation["state"] == "failed" and operation["failure_digest"] is None)
                        or (operation["state"] == "recovery_required" and operation["recovery_reason_digest"] is None
                            and operation["lease_epoch"] == 1)
                    ):
                        raise RuntimeStoreError("ECO_CHANGE_STORE_CORRUPT", "Operation binding differs")
                locks = {
                    row["target_ref_digest"]: row
                    for row in self._connection.execute("SELECT * FROM target_locks")
                }
                lock_required = {
                    "prepared", "rollback_ready", "applying", "commit_ready", "applied",
                    "rolling_back", "recovery_required",
                }
                for operation in operations.values():
                    lock = locks.get(operation["target_ref_digest"])
                    if operation["state"] in lock_required and (
                        lock is None or lock["state"] != "active"
                        or lock["operation_id"] != operation["operation_id"]
                    ):
                        raise RuntimeStoreError(
                            "ECO_CHANGE_STORE_CORRUPT", "Operation target lock differs"
                        )
                for lock in locks.values():
                    operation = operations.get(lock["operation_id"])
                    if lock["state"] == "active" and (
                        operation is None or operation["target_ref_digest"] != lock["target_ref_digest"]
                        or operation["state"] not in lock_required
                    ):
                        raise RuntimeStoreError(
                            "ECO_CHANGE_STORE_CORRUPT", "Active target lock is orphaned"
                        )
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise


# Concise compatibility name for callers that prefer the journal terminology.
SQLiteChangeStore = SQLiteChangeAuthority
