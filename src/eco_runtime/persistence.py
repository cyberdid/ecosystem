from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .digests import canonical_json
from .errors import RuntimeStoreError
from .store import GENESIS_DIGEST, STORE_APPLICATION_ID, STORE_SCHEMA_VERSION


BACKUP_PROTOCOL = "eco-sqlite-backup-v1"
ANCHOR_PROTOCOL = "eco-external-audit-anchor-v1"
ROTATION_PROTOCOL = "eco-hmac-key-rotation-v1"
AUTHENTICATION_DOMAIN = "eco-persistence-authentication-v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ANCHOR_BYTES = 64 * 1024
MAX_ROTATION_SECONDS = 24 * 60 * 60
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HEX_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")

SnapshotVerifier = Callable[[Path], None]


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Persistence clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _authentication_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_json(
        {"domain": AUTHENTICATION_DOMAIN, "payload": dict(payload)}
    ).encode("utf-8")


class HmacKeyring:
    """In-memory verification keyring with one active signing key.

    Keys are deliberately not serializable. A caller-owned secret provider must
    reconstruct the keyring after restart and enforce access to its constructor.
    """

    def __init__(self, keys: Mapping[str, bytes], *, active_key_id: str) -> None:
        if not isinstance(keys, Mapping) or not keys:
            raise ValueError("keys must be a non-empty mapping")
        normalized: dict[str, bytes] = {}
        for key_id, key in keys.items():
            if not isinstance(key_id, str) or KEY_ID_RE.fullmatch(key_id) is None:
                raise ValueError("key ids must be bounded safe identifiers")
            if not isinstance(key, bytes) or len(key) < 32:
                raise ValueError("HMAC keys must contain at least 32 bytes")
            normalized[key_id] = bytes(key)
        if active_key_id not in normalized:
            raise ValueError("active_key_id must identify a configured key")
        self._keys = normalized
        self._active_key_id = active_key_id

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def __repr__(self) -> str:
        return f"HmacKeyring(active_key_id={self._active_key_id!r}, key_ids={self.key_ids!r})"

    def sign(self, payload: Mapping[str, Any], *, key_id: str | None = None) -> str:
        selected = key_id or self._active_key_id
        key = self._keys.get(selected)
        if key is None:
            raise RuntimeStoreError("ECO_HMAC_KEY_UNKNOWN", "HMAC key id is not configured")
        return hmac.new(key, _authentication_bytes(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: Mapping[str, Any], *, key_id: str, tag: str) -> None:
        if not isinstance(tag, str) or HEX_DIGEST_RE.fullmatch(tag) is None:
            raise RuntimeStoreError("ECO_AUTHENTICATION_FAILED", "Authentication tag is invalid")
        expected = self.sign(payload, key_id=key_id)
        if not hmac.compare_digest(tag, expected):
            raise RuntimeStoreError("ECO_AUTHENTICATION_FAILED", "Authentication tag does not match")

    def with_active_key(self, key_id: str) -> HmacKeyring:
        if key_id not in self._keys:
            raise RuntimeStoreError("ECO_HMAC_KEY_UNKNOWN", "HMAC key id is not configured")
        return HmacKeyring(self._keys, active_key_id=key_id)


@dataclass(frozen=True)
class BackupBundle:
    database_path: Path
    manifest_path: Path
    database_digest: str
    store_id: str


@dataclass(frozen=True)
class AnchorPublication:
    anchor: dict[str, Any]
    canonical_bytes: bytes
    sink_receipt: str


class AnchorSink(Protocol):
    """Caller-supplied external persistence boundary.

    Production implementations must provide independent durability and append-
    only or write-once semantics. A successful return is only a sink receipt;
    this module cannot prove the sink's durability.
    """

    def publish(self, anchor: bytes) -> str:
        ...


class MemoryAnchorSink:
    """Deterministic test sink. It is not durable and provides no immutability."""

    def __init__(self) -> None:
        self._items: list[bytes] = []

    @property
    def items(self) -> tuple[bytes, ...]:
        return tuple(self._items)

    def publish(self, anchor: bytes) -> str:
        payload = bytes(anchor)
        self._items.append(payload)
        return f"memory:{hashlib.sha256(payload).hexdigest()}"


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_IO", "Persistence file could not be read") from exc
    return digest.hexdigest(), size


def _ensure_private_parent(path: Path) -> None:
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        if parent_existed and path.parent.stat().st_mode & 0o077:
            raise RuntimeStoreError(
                "ECO_PERSISTENCE_PERMISSIONS",
                "Persistence directory is accessible by another user or group",
            )
        if not parent_existed:
            os.chmod(path.parent, 0o700)


def _temporary_path(target: Path) -> Path:
    return target.with_name(f".{target.name}.tmp-{secrets.token_hex(12)}")


def _fsync_file(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_IO", "Persistence file could not be synchronized") from exc


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_IO", "Persistence directory could not be synchronized") from exc


def _publish_noreplace(temporary: Path, target: Path) -> None:
    try:
        os.link(temporary, target)
    except FileExistsError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_TARGET_EXISTS", "Target already exists") from exc
    except OSError as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_IO", "Persistence file could not be published") from exc
    try:
        temporary.unlink(missing_ok=True)
    except OSError:
        # The target is already durably named and authenticatable. A stale hidden
        # temporary hardlink is cleanup debt, not an ambiguous publication.
        pass
    _fsync_directory(target.parent)


def _read_sqlite_identity(connection: sqlite3.Connection) -> tuple[str, int, int]:
    try:
        check = connection.execute("PRAGMA quick_check").fetchone()[0]
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        row = connection.execute("SELECT store_id FROM store_meta WHERE singleton = 1").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeStoreError("ECO_BACKUP_INVALID", "SQLite runtime profile is unavailable") from exc
    if check != "ok":
        raise RuntimeStoreError("ECO_BACKUP_INVALID", "SQLite integrity check failed")
    if application_id != STORE_APPLICATION_ID or schema_version != STORE_SCHEMA_VERSION:
        raise RuntimeStoreError("ECO_BACKUP_PROFILE_MISMATCH", "SQLite runtime profile is unsupported")
    if row is None or not isinstance(row[0], str) or not row[0]:
        raise RuntimeStoreError("ECO_BACKUP_INVALID", "Runtime store identity is unavailable")
    return row[0], application_id, schema_version


def _inspect_database(path: Path) -> tuple[str, int, int]:
    if not path.is_file():
        raise RuntimeStoreError("ECO_BACKUP_INVALID", "SQLite backup file is unavailable")
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    except sqlite3.Error as exc:
        raise RuntimeStoreError("ECO_BACKUP_INVALID", "SQLite backup could not be opened") from exc
    try:
        return _read_sqlite_identity(connection)
    finally:
        connection.close()


def _run_read_only_verifier(path: Path, verifier: SnapshotVerifier) -> None:
    before = _sha256_file(path)
    try:
        verifier(path)
    except RuntimeStoreError:
        raise
    except Exception as exc:
        raise RuntimeStoreError("ECO_BACKUP_SEMANTIC_INVALID", "Snapshot verifier rejected the database") from exc
    after = _sha256_file(path)
    if before != after:
        raise RuntimeStoreError(
            "ECO_BACKUP_VERIFIER_MUTATED",
            "Snapshot verifier must not mutate authenticated database bytes",
        )
    for suffix in ("-journal", "-wal"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() and sidecar.stat().st_size:
            raise RuntimeStoreError(
                "ECO_BACKUP_VERIFIER_MUTATED",
                "Snapshot verifier left mutable SQLite state outside the database",
            )


def _manifest_body(
    *,
    backup_id: str,
    store_id: str,
    created_at: str,
    database_digest: str,
    database_bytes: int,
    application_id: int,
    schema_version: int,
) -> dict[str, Any]:
    return {
        "protocol": BACKUP_PROTOCOL,
        "backupId": backup_id,
        "storeId": store_id,
        "createdAt": created_at,
        "database": {
            "sha256": database_digest,
            "byteLength": database_bytes,
            "applicationId": application_id,
            "schemaVersion": schema_version,
        },
    }


def _authenticated_record(body: Mapping[str, Any], keyring: HmacKeyring) -> dict[str, Any]:
    key_id = keyring.active_key_id
    return {
        **copy.deepcopy(dict(body)),
        "authentication": {
            "algorithm": "HMAC-SHA256",
            "keyId": key_id,
            "tag": keyring.sign(body, key_id=key_id),
        },
    }


def _decode_authenticated_record(
    raw: bytes,
    *,
    maximum_bytes: int,
    protocol: str,
    keyring: HmacKeyring,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(raw) > maximum_bytes:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Authenticated record is too large")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Authenticated record is unreadable") from exc
    if not isinstance(record, dict) or canonical_json(record).encode("utf-8") != raw:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Authenticated record is not canonical")
    authentication = record.get("authentication")
    body = {key: value for key, value in record.items() if key != "authentication"}
    if (
        body.get("protocol") != protocol
        or not isinstance(authentication, dict)
        or set(authentication) != {"algorithm", "keyId", "tag"}
        or authentication.get("algorithm") != "HMAC-SHA256"
        or not isinstance(authentication.get("keyId"), str)
    ):
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Authenticated record shape is invalid")
    keyring.verify(body, key_id=authentication["keyId"], tag=authentication.get("tag"))
    return record, body


def create_online_backup(
    source_database: str | os.PathLike[str],
    backup_database: str | os.PathLike[str],
    *,
    keyring: HmacKeyring,
    now: datetime,
    semantic_verifier: SnapshotVerifier,
    manifest_path: str | os.PathLike[str] | None = None,
) -> BackupBundle:
    """Create a consistent non-overwriting SQLite backup and authenticated manifest."""

    source = Path(source_database).resolve()
    backup = Path(backup_database).resolve()
    manifest = (
        Path(manifest_path).resolve()
        if manifest_path is not None
        else backup.with_name(f"{backup.name}.manifest.json")
    )
    if not callable(semantic_verifier):
        raise ValueError("semantic_verifier must be callable")
    if source == backup or backup == manifest or source == manifest:
        raise RuntimeStoreError("ECO_PERSISTENCE_PATH_CONFLICT", "Persistence paths must be distinct")
    if not source.is_file():
        raise RuntimeStoreError("ECO_BACKUP_SOURCE_MISSING", "Runtime database does not exist")
    _ensure_private_parent(backup)
    _ensure_private_parent(manifest)
    if backup.exists() or manifest.exists():
        raise RuntimeStoreError("ECO_PERSISTENCE_TARGET_EXISTS", "Backup target already exists")

    temporary_backup = _temporary_path(backup)
    temporary_manifest = _temporary_path(manifest)
    published_backup = False
    try:
        source_uri = f"{source.as_uri()}?mode=ro"
        source_connection = sqlite3.connect(source_uri, uri=True, timeout=5.0, isolation_level=None)
        destination_connection = sqlite3.connect(temporary_backup, timeout=5.0, isolation_level=None)
        try:
            source_connection.backup(destination_connection)
        except sqlite3.Error as exc:
            raise RuntimeStoreError("ECO_BACKUP_FAILED", "SQLite online backup failed") from exc
        finally:
            destination_connection.close()
            source_connection.close()
        if os.name == "posix":
            os.chmod(temporary_backup, 0o600)
        store_id, application_id, schema_version = _inspect_database(temporary_backup)
        _run_read_only_verifier(temporary_backup, semantic_verifier)
        if _inspect_database(temporary_backup) != (store_id, application_id, schema_version):
            raise RuntimeStoreError("ECO_BACKUP_INVALID", "Snapshot identity changed during verification")
        database_digest, database_bytes = _sha256_file(temporary_backup)
        body = _manifest_body(
            backup_id=secrets.token_hex(32),
            store_id=store_id,
            created_at=_utc(now),
            database_digest=database_digest,
            database_bytes=database_bytes,
            application_id=application_id,
            schema_version=schema_version,
        )
        manifest_record = _authenticated_record(body, keyring)
        manifest_bytes = canonical_json(manifest_record).encode("utf-8")
        descriptor = os.open(temporary_manifest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(manifest_bytes)
                stream.flush()
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_file(temporary_backup)
        _publish_noreplace(temporary_backup, backup)
        published_backup = True
        _publish_noreplace(temporary_manifest, manifest)
        return BackupBundle(backup, manifest, database_digest, store_id)
    except Exception:
        for temporary in (temporary_backup, temporary_manifest):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if published_backup and not manifest.exists():
            try:
                backup.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def verify_backup_bundle(
    backup_database: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    *,
    keyring: HmacKeyring,
    semantic_verifier: SnapshotVerifier,
) -> dict[str, Any]:
    backup = Path(backup_database).resolve()
    manifest = Path(manifest_path).resolve()
    try:
        raw = manifest.read_bytes()
    except OSError as exc:
        raise RuntimeStoreError("ECO_BACKUP_MANIFEST_MISSING", "Backup manifest is unavailable") from exc
    record, body = _decode_authenticated_record(
        raw, maximum_bytes=MAX_MANIFEST_BYTES, protocol=BACKUP_PROTOCOL, keyring=keyring
    )
    if set(body) != {"protocol", "backupId", "storeId", "createdAt", "database"}:
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Backup manifest shape is invalid")
    _parse_utc(body["createdAt"])
    database = body.get("database")
    if (
        not isinstance(body.get("backupId"), str)
        or HEX_DIGEST_RE.fullmatch(body["backupId"]) is None
        or not isinstance(body.get("storeId"), str)
        or not isinstance(database, dict)
        or set(database) != {"sha256", "byteLength", "applicationId", "schemaVersion"}
        or not isinstance(database.get("sha256"), str)
        or HEX_DIGEST_RE.fullmatch(database["sha256"]) is None
        or not isinstance(database.get("byteLength"), int)
        or database["byteLength"] < 0
    ):
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "Backup manifest values are invalid")
    digest, size = _sha256_file(backup)
    if digest != database["sha256"] or size != database["byteLength"]:
        raise RuntimeStoreError("ECO_BACKUP_AUTHENTICATION_FAILED", "Backup bytes do not match manifest")
    identity = _inspect_database(backup)
    if identity != (body["storeId"], database["applicationId"], database["schemaVersion"]):
        raise RuntimeStoreError("ECO_BACKUP_PROFILE_MISMATCH", "Backup identity does not match manifest")
    _run_read_only_verifier(backup, semantic_verifier)
    return copy.deepcopy(record)


def restore_backup(
    backup_database: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    target_database: str | os.PathLike[str],
    *,
    keyring: HmacKeyring,
    semantic_verifier: SnapshotVerifier,
) -> Path:
    """Verify and restore a self-contained backup without overwriting a target."""

    backup = Path(backup_database).resolve()
    manifest = Path(manifest_path).resolve()
    target = Path(target_database).resolve()
    if target in {backup, manifest}:
        raise RuntimeStoreError("ECO_PERSISTENCE_PATH_CONFLICT", "Restore paths must be distinct")
    _ensure_private_parent(target)
    if target.exists():
        raise RuntimeStoreError("ECO_PERSISTENCE_TARGET_EXISTS", "Restore target already exists")
    verified = verify_backup_bundle(
        backup, manifest, keyring=keyring, semantic_verifier=semantic_verifier
    )
    expected = verified["database"]
    temporary = _temporary_path(target)
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with backup.open("rb") as source:
                with os.fdopen(descriptor, "wb", closefd=False) as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                    destination.flush()
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        digest, size = _sha256_file(temporary)
        if digest != expected["sha256"] or size != expected["byteLength"]:
            raise RuntimeStoreError("ECO_RESTORE_COPY_FAILED", "Restored bytes differ from backup")
        _run_read_only_verifier(temporary, semantic_verifier)
        identity = _inspect_database(temporary)
        if identity != (
            verified["storeId"],
            expected["applicationId"],
            expected["schemaVersion"],
        ):
            raise RuntimeStoreError("ECO_RESTORE_COPY_FAILED", "Restored database identity changed")
        _publish_noreplace(temporary, target)
        return target
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def create_rotation_transition(
    keyring: HmacKeyring,
    *,
    store_id: str,
    new_key_id: str,
    now: datetime,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Create a short-lived transition authenticated by both old and new keys."""

    if not isinstance(store_id, str) or not store_id:
        raise ValueError("store_id must be a non-empty string")
    if new_key_id == keyring.active_key_id or new_key_id not in keyring.key_ids:
        raise RuntimeStoreError("ECO_ROTATION_KEY_INVALID", "Rotation target key is invalid")
    issued = now.astimezone(timezone.utc) if now.tzinfo is not None else None
    if issued is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Rotation clock must be timezone-aware")
    expiry = expires_at or (issued + timedelta(hours=1))
    if expiry.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Rotation expiry must be timezone-aware")
    expiry = expiry.astimezone(timezone.utc)
    if expiry <= issued or (expiry - issued).total_seconds() > MAX_ROTATION_SECONDS:
        raise RuntimeStoreError("ECO_ROTATION_WINDOW_INVALID", "Rotation validity window is invalid")
    body = {
        "protocol": ROTATION_PROTOCOL,
        "storeId": store_id,
        "fromKeyId": keyring.active_key_id,
        "toKeyId": new_key_id,
        "issuedAt": _utc(issued),
        "expiresAt": _utc(expiry),
        "nonce": secrets.token_hex(32),
    }
    return {
        **body,
        "authentication": {
            "algorithm": "HMAC-SHA256-DUAL",
            "fromTag": keyring.sign(body, key_id=keyring.active_key_id),
            "toTag": keyring.sign(body, key_id=new_key_id),
        },
    }


def apply_rotation_transition(
    keyring: HmacKeyring,
    transition: Mapping[str, Any],
    *,
    store_id: str,
    now: datetime,
) -> HmacKeyring:
    record = copy.deepcopy(dict(transition))
    authentication = record.pop("authentication", None)
    expected_keys = {
        "protocol", "storeId", "fromKeyId", "toKeyId", "issuedAt", "expiresAt", "nonce"
    }
    if (
        set(record) != expected_keys
        or record.get("protocol") != ROTATION_PROTOCOL
        or record.get("storeId") != store_id
        or record.get("fromKeyId") != keyring.active_key_id
        or record.get("toKeyId") not in keyring.key_ids
        or not isinstance(record.get("nonce"), str)
        or HEX_DIGEST_RE.fullmatch(record["nonce"]) is None
        or not isinstance(authentication, dict)
        or set(authentication) != {"algorithm", "fromTag", "toTag"}
        or authentication.get("algorithm") != "HMAC-SHA256-DUAL"
    ):
        raise RuntimeStoreError("ECO_ROTATION_INVALID", "Rotation transition shape is invalid")
    issued = _parse_utc(record["issuedAt"])
    expiry = _parse_utc(record["expiresAt"])
    current = now.astimezone(timezone.utc) if now.tzinfo is not None else None
    if (
        current is None
        or expiry <= issued
        or (expiry - issued).total_seconds() > MAX_ROTATION_SECONDS
        or current < issued
        or current >= expiry
    ):
        raise RuntimeStoreError("ECO_ROTATION_EXPIRED", "Rotation transition is outside its validity window")
    keyring.verify(record, key_id=record["fromKeyId"], tag=authentication.get("fromTag"))
    keyring.verify(record, key_id=record["toKeyId"], tag=authentication.get("toTag"))
    return keyring.with_active_key(record["toKeyId"])


def _read_anchor_head(database: Path) -> tuple[str, int, int, int, str]:
    uri = f"{database.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        store_id, application_id, schema_version = _read_sqlite_identity(connection)
        head = connection.execute(
            "SELECT sequence, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(head["sequence"]) if head is not None else 0
        entry_hash = head["entry_hash"] if head is not None else GENESIS_DIGEST
        connection.execute("COMMIT")
    except sqlite3.Error as exc:
        raise RuntimeStoreError("ECO_ANCHOR_SOURCE_INVALID", "Audit head is unavailable") from exc
    finally:
        if "connection" in locals():
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            connection.close()
    if not isinstance(entry_hash, str) or HEX_DIGEST_RE.fullmatch(entry_hash) is None:
        raise RuntimeStoreError("ECO_ANCHOR_SOURCE_INVALID", "Audit head digest is invalid")
    return store_id, application_id, schema_version, sequence, entry_hash


def export_external_anchor(
    database: str | os.PathLike[str],
    *,
    keyring: HmacKeyring,
    sink: AnchorSink,
    now: datetime,
    previous_anchor: bytes | None = None,
) -> AnchorPublication:
    """Authenticate the current audit head and publish it to a caller-owned sink."""

    store_id, application_id, schema_version, sequence, entry_hash = _read_anchor_head(
        Path(database)
    )
    previous_digest: str | None = None
    if previous_anchor is not None:
        previous_record = verify_external_anchor(previous_anchor, keyring=keyring)
        if previous_record["storeId"] != store_id or previous_record["auditSequence"] > sequence:
            raise RuntimeStoreError("ECO_ANCHOR_CHAIN_INVALID", "Previous anchor is incompatible")
        previous_digest = hashlib.sha256(previous_anchor).hexdigest()
    body = {
        "protocol": ANCHOR_PROTOCOL,
        "anchorId": secrets.token_hex(32),
        "storeId": store_id,
        "issuedAt": _utc(now),
        "applicationId": application_id,
        "schemaVersion": schema_version,
        "auditSequence": sequence,
        "auditEntryHash": entry_hash,
        "previousAnchorDigest": previous_digest,
    }
    anchor = _authenticated_record(body, keyring)
    encoded = canonical_json(anchor).encode("utf-8")
    try:
        receipt = sink.publish(encoded)
    except Exception as exc:
        raise RuntimeStoreError("ECO_ANCHOR_PUBLISH_FAILED", "External anchor sink rejected publication") from exc
    if not isinstance(receipt, str) or not receipt:
        raise RuntimeStoreError("ECO_ANCHOR_PUBLISH_FAILED", "External anchor sink returned no receipt")
    return AnchorPublication(copy.deepcopy(anchor), encoded, receipt)


def verify_external_anchor(
    anchor: bytes,
    *,
    keyring: HmacKeyring,
    database: str | os.PathLike[str] | None = None,
    exact_head: bool = False,
) -> dict[str, Any]:
    record, body = _decode_authenticated_record(
        bytes(anchor), maximum_bytes=MAX_ANCHOR_BYTES, protocol=ANCHOR_PROTOCOL, keyring=keyring
    )
    expected = {
        "protocol", "anchorId", "storeId", "issuedAt", "applicationId", "schemaVersion",
        "auditSequence", "auditEntryHash", "previousAnchorDigest",
    }
    if (
        set(body) != expected
        or not isinstance(body.get("anchorId"), str)
        or HEX_DIGEST_RE.fullmatch(body["anchorId"]) is None
        or not isinstance(body.get("storeId"), str)
        or not isinstance(body.get("auditSequence"), int)
        or body["auditSequence"] < 0
        or not isinstance(body.get("auditEntryHash"), str)
        or HEX_DIGEST_RE.fullmatch(body["auditEntryHash"]) is None
        or (
            body.get("previousAnchorDigest") is not None
            and (
                not isinstance(body["previousAnchorDigest"], str)
                or HEX_DIGEST_RE.fullmatch(body["previousAnchorDigest"]) is None
            )
        )
    ):
        raise RuntimeStoreError("ECO_PERSISTENCE_RECORD_INVALID", "External anchor shape is invalid")
    _parse_utc(body["issuedAt"])
    if database is not None:
        path = Path(database)
        uri = f"{path.resolve().as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            store_id, application_id, schema_version = _read_sqlite_identity(connection)
            head = connection.execute(
                "SELECT sequence, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            head_sequence = int(head["sequence"]) if head is not None else 0
            head_hash = head["entry_hash"] if head is not None else GENESIS_DIGEST
            if body["auditSequence"] == 0:
                anchored_hash = GENESIS_DIGEST
            elif body["auditSequence"] == head_sequence:
                anchored_hash = head_hash
            else:
                anchored = connection.execute(
                    "SELECT entry_hash FROM audit_entries WHERE sequence = ?",
                    (body["auditSequence"],),
                ).fetchone()
                anchored_hash = anchored["entry_hash"] if anchored is not None else None
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise RuntimeStoreError(
                "ECO_ANCHOR_DATABASE_MISMATCH", "Database audit history is unavailable"
            ) from exc
        finally:
            if "connection" in locals():
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
        if (
            body["storeId"] != store_id
            or body["applicationId"] != application_id
            or body["schemaVersion"] != schema_version
            or body["auditSequence"] > head_sequence
            or (exact_head and body["auditSequence"] != head_sequence)
        ):
            raise RuntimeStoreError("ECO_ANCHOR_DATABASE_MISMATCH", "Database does not contain anchored history")
        if anchored_hash != body["auditEntryHash"]:
            raise RuntimeStoreError("ECO_ANCHOR_DATABASE_MISMATCH", "Anchored audit entry is absent")
    return copy.deepcopy(record)


def verify_anchor_chain(
    anchors: Sequence[bytes],
    *,
    keyring: HmacKeyring,
    database: str | os.PathLike[str] | None = None,
    exact_head: bool = False,
) -> tuple[dict[str, Any], ...]:
    if not anchors:
        raise RuntimeStoreError("ECO_ANCHOR_CHAIN_INVALID", "Anchor chain is empty")
    verified: list[dict[str, Any]] = []
    previous_bytes: bytes | None = None
    previous_sequence = -1
    previous_time: datetime | None = None
    store_id: str | None = None
    for index, encoded in enumerate(anchors):
        record = verify_external_anchor(
            encoded,
            keyring=keyring,
            database=database if index == len(anchors) - 1 else None,
            exact_head=exact_head if index == len(anchors) - 1 else False,
        )
        expected_previous = (
            hashlib.sha256(previous_bytes).hexdigest() if previous_bytes is not None else None
        )
        issued = _parse_utc(record["issuedAt"])
        if (
            record["previousAnchorDigest"] != expected_previous
            or (store_id is not None and record["storeId"] != store_id)
            or record["auditSequence"] < previous_sequence
            or (previous_time is not None and issued < previous_time)
        ):
            raise RuntimeStoreError("ECO_ANCHOR_CHAIN_INVALID", "Anchor chain continuity is invalid")
        store_id = record["storeId"]
        previous_sequence = record["auditSequence"]
        previous_time = issued
        previous_bytes = bytes(encoded)
        verified.append(record)
    return tuple(verified)
