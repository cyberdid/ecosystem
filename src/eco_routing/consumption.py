"""Durable single-use consumption of M6.4 model route decisions.

A route decision is bookkeeping, never authority: consuming one records that a
specific caller bound one ``allowed`` decision to one exact governed effect so
the same decision (and its router-computed reservation) cannot be spent twice.
The exact model call must still cross the independent policy/store/model
bridge. The journal is a private HMAC-authenticated same-host SQLite file in
the same discipline as the other M6 planes; it stores digests and bindings,
never prompts, sources, endpoints or credentials.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from eco_runtime.digests import canonical_json

from .contracts import validate_routing_record
from .errors import RoutingError


ROUTE_JOURNAL_APPLICATION_ID = 0x45435236
ROUTE_JOURNAL_SCHEMA_VERSION = 1
ROUTE_JOURNAL_DOMAIN = "eco-route-consumption-journal-v1"
GENESIS_DIGEST = "0" * 64
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONSUMER_KIND_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RoutingError("ECO_ROUTE_CLOCK_INVALID", "Route consumption clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def verify_route_binding(
    decision: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    expected_deployment_id: str,
    expected_deployment_identity_digest: str,
    now: datetime,
    cost_reservation_microusd: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify one allowed decision against its request and an exact deployment.

    Pure and write-free: suitable for preflight. Raises a typed
    :class:`RoutingError`; returns the validated records on success.
    """

    current = _parse_time(_utc(now))
    try:
        decision_record = validate_routing_record(copy.deepcopy(dict(decision)))
        request_record = validate_routing_record(copy.deepcopy(dict(request)))
    except Exception as exc:
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence is invalid") from exc
    if (
        decision_record["kind"] != "ModelRouteDecision"
        or request_record["kind"] != "ModelRouteRequest"
    ):
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence kinds are invalid")
    decision_spec = decision_record["spec"]
    request_spec = request_record["spec"]
    selected = decision_spec["selected"]
    if decision_spec["decision"] != "allowed" or selected is None:
        raise RoutingError("ECO_ROUTE_NOT_ALLOWED", "Only an allowed route can be consumed")
    if (
        decision_spec["requestDigest"] != request_record["metadata"]["recordDigest"]
        or decision_spec["policyDigest"] != request_spec["policyDigest"]
    ):
        raise RoutingError("ECO_ROUTE_BINDING_MISMATCH", "Route evidence binding is inconsistent")
    if current >= _parse_time(decision_spec["validUntil"]) or current >= _parse_time(
        request_spec["deadlineAt"]
    ):
        raise RoutingError("ECO_ROUTE_EXPIRED", "Route decision is no longer valid")
    if (
        selected["deploymentId"] != expected_deployment_id
        or selected["deploymentIdentityDigest"] != expected_deployment_identity_digest
    ):
        raise RoutingError(
            "ECO_ROUTE_BINDING_MISMATCH", "Route selection does not match the governed deployment"
        )
    if selected["reservedCostMicrousd"] > request_spec["maximumCostMicrousd"]:
        raise RoutingError("ECO_ROUTE_BINDING_MISMATCH", "Route reservation exceeds its request")
    if (
        cost_reservation_microusd is not None
        and selected["reservedCostMicrousd"] != cost_reservation_microusd
    ):
        raise RoutingError(
            "ECO_ROUTE_BINDING_MISMATCH", "Route reservation does not match the prepared cost"
        )
    return decision_record, request_record


class DurableRouteConsumptionJournal:
    """Authenticated append-only journal of consumed model route decisions."""

    def __init__(self, path: str | os.PathLike[str], *, hmac_key: bytes, key_id: str) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ValueError("key_id must be a bounded safe identifier")
        self._path = Path(path)
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
            raise RoutingError(
                "ECO_ROUTE_JOURNAL_UNAVAILABLE", "Route consumption journal is unavailable"
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
            raise RoutingError("ECO_ROUTE_JOURNAL_LOCATION_DENIED", "Journal directory is not trusted")
        if os.name == "posix":
            if existed and info.st_mode & 0o077:
                raise RoutingError("ECO_ROUTE_JOURNAL_PERMISSIONS", "Journal directory is not private")
            if not existed:
                os.chmod(parent, 0o700)
        if self._path.exists():
            info = self._path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RoutingError(
                    "ECO_ROUTE_JOURNAL_LOCATION_DENIED", "Journal database is not a regular file"
                )
            if os.name == "posix" and (info.st_mode & 0o077 or info.st_nlink != 1):
                raise RoutingError("ECO_ROUTE_JOURNAL_PERMISSIONS", "Journal database is not private")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RoutingError("ECO_ROUTE_JOURNAL_CLOSED", "Route consumption journal is closed")
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
                raise RoutingError(
                    "ECO_ROUTE_JOURNAL_UNAVAILABLE", "Route consumption journal is unavailable"
                ) from exc
            except Exception:
                try:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise RoutingError(
                        "ECO_ROUTE_JOURNAL_UNAVAILABLE", "Route consumption journal is unavailable"
                    ) from exc
                raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "DurableRouteConsumptionJournal":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _meta_payload(self, *, journal_id: str, head_sequence: int, head_hash: str) -> dict[str, Any]:
        return {
            "domain": ROUTE_JOURNAL_DOMAIN,
            "schemaVersion": ROUTE_JOURNAL_SCHEMA_VERSION,
            "journalId": journal_id,
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
                    """CREATE TABLE journal_meta (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        journal_id TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        key_id TEXT NOT NULL,
                        head_sequence INTEGER NOT NULL,
                        head_hash TEXT NOT NULL,
                        meta_hmac TEXT NOT NULL
                    )""",
                    """CREATE TABLE consumed_routes (
                        route_digest TEXT PRIMARY KEY,
                        sequence INTEGER NOT NULL UNIQUE,
                        request_digest TEXT NOT NULL,
                        policy_digest TEXT NOT NULL,
                        price_catalog_digest TEXT NOT NULL,
                        deployment_id TEXT NOT NULL,
                        deployment_identity_digest TEXT NOT NULL,
                        reserved_cost_microusd INTEGER NOT NULL
                            CHECK (reserved_cost_microusd >= 0),
                        route_attempt INTEGER NOT NULL CHECK (route_attempt IN (1, 2)),
                        fallback_from_digest TEXT,
                        consumer_kind TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        consumer_digest TEXT NOT NULL,
                        consumed_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        entry_hmac TEXT NOT NULL
                    )""",
                    """CREATE TRIGGER consumed_routes_immutable_update
                        BEFORE UPDATE ON consumed_routes
                        BEGIN SELECT RAISE(ABORT, 'immutable consumption'); END""",
                    """CREATE TRIGGER consumed_routes_immutable_delete
                        BEFORE DELETE ON consumed_routes
                        BEGIN SELECT RAISE(ABORT, 'immutable consumption'); END""",
                ):
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id = {ROUTE_JOURNAL_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {ROUTE_JOURNAL_SCHEMA_VERSION}")
                journal_id = secrets.token_hex(16)
                payload = self._meta_payload(
                    journal_id=journal_id, head_sequence=0, head_hash=GENESIS_DIGEST
                )
                connection.execute(
                    "INSERT INTO journal_meta VALUES (1, ?, ?, ?, 0, ?, ?)",
                    (
                        journal_id,
                        ROUTE_JOURNAL_SCHEMA_VERSION,
                        self._key_id,
                        GENESIS_DIGEST,
                        self._sign(payload),
                    ),
                )
                return
            if (
                application_id != ROUTE_JOURNAL_APPLICATION_ID
                or user_version != ROUTE_JOURNAL_SCHEMA_VERSION
            ):
                raise RoutingError(
                    "ECO_ROUTE_JOURNAL_PROFILE_MISMATCH", "Journal schema is not supported"
                )
            self._verify_locked(connection)

    def _meta_row(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM journal_meta WHERE singleton = 1").fetchone()
        if row is None:
            raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal metadata is missing")
        payload = self._meta_payload(
            journal_id=row["journal_id"],
            head_sequence=row["head_sequence"],
            head_hash=row["head_hash"],
        )
        if row["key_id"] != self._key_id or not hmac.compare_digest(
            row["meta_hmac"], self._sign(payload)
        ):
            raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal metadata failed authentication")
        return row

    def _entry_payload(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": ROUTE_JOURNAL_DOMAIN,
            "entry": "consumed-route",
            "routeDigest": row["route_digest"],
            "sequence": row["sequence"],
            "requestDigest": row["request_digest"],
            "policyDigest": row["policy_digest"],
            "priceCatalogDigest": row["price_catalog_digest"],
            "deploymentId": row["deployment_id"],
            "deploymentIdentityDigest": row["deployment_identity_digest"],
            "reservedCostMicrousd": row["reserved_cost_microusd"],
            "routeAttempt": row["route_attempt"],
            "fallbackFromDigest": row["fallback_from_digest"],
            "consumerKind": row["consumer_kind"],
            "consumerId": row["consumer_id"],
            "consumerDigest": row["consumer_digest"],
            "consumedAt": row["consumed_at"],
            "previousHash": row["previous_hash"],
        }

    def _verify_locked(self, connection: sqlite3.Connection) -> dict[str, Any]:
        meta = self._meta_row(connection)
        previous = GENESIS_DIGEST
        count = 0
        for row in connection.execute("SELECT * FROM consumed_routes ORDER BY sequence"):
            count += 1
            if row["sequence"] != count or row["previous_hash"] != previous:
                raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal chain is broken")
            payload = self._entry_payload(row)
            expected_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            if row["entry_hash"] != expected_hash or row["key_id"] != self._key_id:
                raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal entry failed verification")
            if not hmac.compare_digest(row["entry_hmac"], self._sign(payload)):
                raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal entry failed authentication")
            previous = expected_hash
        if meta["head_sequence"] != count or meta["head_hash"] != previous:
            raise RoutingError("ECO_ROUTE_JOURNAL_TAMPERED", "Journal head does not match entries")
        return {"journalId": meta["journal_id"], "entries": count, "headHash": previous}

    def verify(self) -> dict[str, Any]:
        """Re-verify the complete authenticated consumption chain."""

        with self._transaction() as connection:
            return self._verify_locked(connection)

    def status(self, route_digest: str) -> dict[str, Any] | None:
        if not isinstance(route_digest, str) or _DIGEST_RE.fullmatch(route_digest) is None:
            raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route digest is invalid")
        with self._transaction() as connection:
            self._verify_locked(connection)
            row = connection.execute(
                "SELECT * FROM consumed_routes WHERE route_digest = ?", (route_digest,)
            ).fetchone()
        if row is None:
            return None
        return {
            "routeDigest": row["route_digest"],
            "consumerKind": row["consumer_kind"],
            "consumerId": row["consumer_id"],
            "consumerDigest": row["consumer_digest"],
            "consumedAt": row["consumed_at"],
        }

    def consume(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        expected_deployment_id: str,
        expected_deployment_identity_digest: str,
        consumer_kind: str,
        consumer_id: str,
        consumer_digest: str,
        now: datetime,
        cost_reservation_microusd: int | None = None,
    ) -> dict[str, Any]:
        """Bind one allowed decision to one consumer exactly once.

        Replaying the identical consumer binding is an idempotent no-op so a
        restarted workflow does not lose its already-consumed route; any other
        consumer receives a typed reuse failure.
        """

        if (
            not isinstance(consumer_kind, str)
            or _CONSUMER_KIND_RE.fullmatch(consumer_kind) is None
            or not isinstance(consumer_id, str)
            or _IDENTIFIER_RE.fullmatch(consumer_id) is None
            or not isinstance(consumer_digest, str)
            or _DIGEST_RE.fullmatch(consumer_digest) is None
        ):
            raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route consumer binding is invalid")
        current = _utc(now)
        decision_record, request_record = verify_route_binding(
            decision,
            request,
            expected_deployment_id=expected_deployment_id,
            expected_deployment_identity_digest=expected_deployment_identity_digest,
            now=now,
            cost_reservation_microusd=cost_reservation_microusd,
        )
        decision_spec = decision_record["spec"]
        selected = decision_spec["selected"]
        route_digest = decision_record["metadata"]["recordDigest"]
        with self._transaction() as connection:
            state = self._verify_locked(connection)
            existing = connection.execute(
                "SELECT * FROM consumed_routes WHERE route_digest = ?", (route_digest,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["consumer_kind"] == consumer_kind
                    and existing["consumer_id"] == consumer_id
                    and existing["consumer_digest"] == consumer_digest
                ):
                    return {
                        "routeDigest": route_digest,
                        "replayed": True,
                        "consumedAt": existing["consumed_at"],
                    }
                raise RoutingError(
                    "ECO_ROUTE_ALREADY_CONSUMED", "Route decision was consumed by another effect"
                )
            if decision_spec["routeAttempt"] == 2:
                predecessor = connection.execute(
                    "SELECT 1 FROM consumed_routes WHERE route_digest = ?",
                    (decision_spec["fallbackFromDigest"],),
                ).fetchone()
                if predecessor is None:
                    raise RoutingError(
                        "ECO_ROUTE_FALLBACK_PREDECESSOR_MISSING",
                        "Fallback route requires its consumed predecessor",
                    )
            sequence = state["entries"] + 1
            row = {
                "route_digest": route_digest,
                "sequence": sequence,
                "request_digest": request_record["metadata"]["recordDigest"],
                "policy_digest": decision_spec["policyDigest"],
                "price_catalog_digest": decision_spec["priceCatalogDigest"],
                "deployment_id": selected["deploymentId"],
                "deployment_identity_digest": selected["deploymentIdentityDigest"],
                "reserved_cost_microusd": selected["reservedCostMicrousd"],
                "route_attempt": decision_spec["routeAttempt"],
                "fallback_from_digest": decision_spec["fallbackFromDigest"],
                "consumer_kind": consumer_kind,
                "consumer_id": consumer_id,
                "consumer_digest": consumer_digest,
                "consumed_at": current,
                "previous_hash": state["headHash"],
            }
            payload = self._entry_payload(row)
            entry_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            connection.execute(
                """INSERT INTO consumed_routes VALUES (
                    :route_digest, :sequence, :request_digest, :policy_digest,
                    :price_catalog_digest, :deployment_id, :deployment_identity_digest,
                    :reserved_cost_microusd, :route_attempt, :fallback_from_digest,
                    :consumer_kind, :consumer_id, :consumer_digest, :consumed_at,
                    :previous_hash, :entry_hash, :key_id, :entry_hmac
                )""",
                {
                    **row,
                    "entry_hash": entry_hash,
                    "key_id": self._key_id,
                    "entry_hmac": self._sign(payload),
                },
            )
            meta_payload = self._meta_payload(
                journal_id=state["journalId"], head_sequence=sequence, head_hash=entry_hash
            )
            connection.execute(
                """UPDATE journal_meta
                    SET head_sequence = ?, head_hash = ?, meta_hmac = ?
                    WHERE singleton = 1""",
                (sequence, entry_hash, self._sign(meta_payload)),
            )
        return {"routeDigest": route_digest, "replayed": False, "consumedAt": current}
