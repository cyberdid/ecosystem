"""Durable authenticated aggregate usage for exact workflow-scoped routes.

This journal is accounting, not route authority.  A caller must first pass
``verify_exact_route_binding``/``consume_exact``.  Every new provider effect is
then reserved here, atomically, before egress.  Only digests, identifiers and
integer counters are persisted; prompts, responses, endpoints and credentials
are never stored.
"""

from __future__ import annotations

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

from .binding import RouteAggregateUsage, reserve_route_effect, route_consumer_digest
from .consumption import verify_route_binding
from .contracts import validate_routing_record
from .errors import RoutingError


ROUTE_USAGE_APPLICATION_ID = 0x45435536
ROUTE_USAGE_SCHEMA_VERSION = 1
ROUTE_USAGE_DOMAIN = "eco-route-aggregate-usage-journal-v1"
GENESIS_DIGEST = "0" * 64
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONSUMER_KIND_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RoutingError("ECO_ROUTE_CLOCK_INVALID", "Route usage clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class DurableRouteUsageJournal:
    """HMAC-authenticated, append-only aggregate route-usage journal."""

    def __init__(self, path: str | os.PathLike[str], *, hmac_key: bytes, key_id: str) -> None:
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or _IDENTIFIER_RE.fullmatch(key_id) is None:
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
                "ECO_ROUTE_USAGE_UNAVAILABLE", "Route usage journal is unavailable"
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
            raise RoutingError("ECO_ROUTE_USAGE_LOCATION_DENIED", "Usage directory is not trusted")
        if os.name == "posix":
            if existed and info.st_mode & 0o077:
                raise RoutingError("ECO_ROUTE_USAGE_PERMISSIONS", "Usage directory is not private")
            if not existed:
                os.chmod(parent, 0o700)
        if self._path.exists():
            info = self._path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RoutingError(
                    "ECO_ROUTE_USAGE_LOCATION_DENIED", "Usage journal is not a regular file"
                )
            if os.name == "posix" and (info.st_mode & 0o077 or info.st_nlink != 1):
                raise RoutingError("ECO_ROUTE_USAGE_PERMISSIONS", "Usage journal is not private")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RoutingError("ECO_ROUTE_USAGE_CLOSED", "Route usage journal is closed")
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
                    "ECO_ROUTE_USAGE_UNAVAILABLE", "Route usage journal is unavailable"
                ) from exc
            except Exception:
                try:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                except sqlite3.Error as exc:
                    raise RoutingError(
                        "ECO_ROUTE_USAGE_UNAVAILABLE", "Route usage journal is unavailable"
                    ) from exc
                raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> "DurableRouteUsageJournal":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _sign(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(
            self._hmac_key,
            canonical_json(dict(payload)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _authenticated(self, actual: object, payload: Mapping[str, Any]) -> bool:
        try:
            return isinstance(actual, str) and hmac.compare_digest(actual, self._sign(payload))
        except Exception:
            return False

    def _meta_payload(self, *, journal_id: str, head_sequence: int, head_hash: str) -> dict[str, Any]:
        return {
            "domain": ROUTE_USAGE_DOMAIN,
            "schemaVersion": ROUTE_USAGE_SCHEMA_VERSION,
            "journalId": journal_id,
            "keyId": self._key_id,
            "headSequence": head_sequence,
            "headHash": head_hash,
        }

    def _state_payload(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": ROUTE_USAGE_DOMAIN,
            "record": "aggregate-state",
            "consumerDigest": row["consumer_digest"],
            "requestDigest": row["request_digest"],
            "executionPlanDigest": row["execution_plan_digest"],
            "policyDigest": row["policy_digest"],
            "priceCatalogDigest": row["price_catalog_digest"],
            "consumerKind": row["consumer_kind"],
            "consumerId": row["consumer_id"],
            "calls": row["calls"],
            "inputTokens": row["input_tokens"],
            "outputTokens": row["output_tokens"],
            "costMicrousd": row["cost_microusd"],
            "updatedSequence": row["updated_sequence"],
        }

    def _entry_payload(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "domain": ROUTE_USAGE_DOMAIN,
            "record": "reserved-effect",
            "sequence": row["sequence"],
            "consumerDigest": row["consumer_digest"],
            "requestDigest": row["request_digest"],
            "executionPlanDigest": row["execution_plan_digest"],
            "policyDigest": row["policy_digest"],
            "priceCatalogDigest": row["price_catalog_digest"],
            "routeDigest": row["route_digest"],
            "deploymentId": row["deployment_id"],
            "deploymentIdentityDigest": row["deployment_identity_digest"],
            "consumerKind": row["consumer_kind"],
            "consumerId": row["consumer_id"],
            "effectId": row["effect_id"],
            "effectDigest": row["effect_digest"],
            "inputTokens": row["input_tokens"],
            "outputTokens": row["output_tokens"],
            "costMicrousd": row["cost_microusd"],
            "beforeCalls": row["before_calls"],
            "beforeInputTokens": row["before_input_tokens"],
            "beforeOutputTokens": row["before_output_tokens"],
            "beforeCostMicrousd": row["before_cost_microusd"],
            "afterCalls": row["after_calls"],
            "afterInputTokens": row["after_input_tokens"],
            "afterOutputTokens": row["after_output_tokens"],
            "afterCostMicrousd": row["after_cost_microusd"],
            "reservedAt": row["reserved_at"],
            "previousHash": row["previous_hash"],
        }

    def _initialize_or_verify(self) -> None:
        with self._transaction() as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id == 0 and user_version == 0:
                statements = (
                    """CREATE TABLE journal_meta (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        journal_id TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        key_id TEXT NOT NULL,
                        head_sequence INTEGER NOT NULL,
                        head_hash TEXT NOT NULL,
                        meta_hmac TEXT NOT NULL
                    )""",
                    """CREATE TABLE aggregate_usage (
                        consumer_digest TEXT PRIMARY KEY,
                        request_digest TEXT NOT NULL,
                        execution_plan_digest TEXT NOT NULL,
                        policy_digest TEXT NOT NULL,
                        price_catalog_digest TEXT NOT NULL,
                        consumer_kind TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        calls INTEGER NOT NULL CHECK (calls >= 0),
                        input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
                        output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
                        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
                        updated_sequence INTEGER NOT NULL CHECK (updated_sequence >= 0),
                        key_id TEXT NOT NULL,
                        state_hmac TEXT NOT NULL
                    )""",
                    """CREATE TABLE reserved_effects (
                        consumer_digest TEXT NOT NULL,
                        effect_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL UNIQUE,
                        request_digest TEXT NOT NULL,
                        execution_plan_digest TEXT NOT NULL,
                        policy_digest TEXT NOT NULL,
                        price_catalog_digest TEXT NOT NULL,
                        route_digest TEXT NOT NULL,
                        deployment_id TEXT NOT NULL,
                        deployment_identity_digest TEXT NOT NULL,
                        consumer_kind TEXT NOT NULL,
                        consumer_id TEXT NOT NULL,
                        effect_digest TEXT NOT NULL,
                        input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
                        output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
                        cost_microusd INTEGER NOT NULL CHECK (cost_microusd >= 0),
                        before_calls INTEGER NOT NULL,
                        before_input_tokens INTEGER NOT NULL,
                        before_output_tokens INTEGER NOT NULL,
                        before_cost_microusd INTEGER NOT NULL,
                        after_calls INTEGER NOT NULL,
                        after_input_tokens INTEGER NOT NULL,
                        after_output_tokens INTEGER NOT NULL,
                        after_cost_microusd INTEGER NOT NULL,
                        reserved_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        entry_hash TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        entry_hmac TEXT NOT NULL,
                        PRIMARY KEY (consumer_digest, effect_id),
                        FOREIGN KEY (consumer_digest) REFERENCES aggregate_usage(consumer_digest)
                    )""",
                    """CREATE TRIGGER reserved_effects_immutable_update
                        BEFORE UPDATE ON reserved_effects
                        BEGIN SELECT RAISE(ABORT, 'immutable route effect'); END""",
                    """CREATE TRIGGER reserved_effects_immutable_delete
                        BEFORE DELETE ON reserved_effects
                        BEGIN SELECT RAISE(ABORT, 'immutable route effect'); END""",
                    """CREATE TRIGGER aggregate_usage_immutable_delete
                        BEFORE DELETE ON aggregate_usage
                        BEGIN SELECT RAISE(ABORT, 'immutable route usage'); END""",
                )
                for statement in statements:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id = {ROUTE_USAGE_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {ROUTE_USAGE_SCHEMA_VERSION}")
                journal_id = secrets.token_hex(16)
                payload = self._meta_payload(
                    journal_id=journal_id,
                    head_sequence=0,
                    head_hash=GENESIS_DIGEST,
                )
                connection.execute(
                    "INSERT INTO journal_meta VALUES (1, ?, ?, ?, 0, ?, ?)",
                    (
                        journal_id,
                        ROUTE_USAGE_SCHEMA_VERSION,
                        self._key_id,
                        GENESIS_DIGEST,
                        self._sign(payload),
                    ),
                )
                return
            if (
                application_id != ROUTE_USAGE_APPLICATION_ID
                or user_version != ROUTE_USAGE_SCHEMA_VERSION
            ):
                raise RoutingError(
                    "ECO_ROUTE_USAGE_PROFILE_MISMATCH", "Route usage schema is not supported"
                )
            self._verify_locked(connection)

    def _meta_row(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM journal_meta WHERE singleton = 1").fetchone()
        if row is None:
            raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage metadata is missing")
        payload = self._meta_payload(
            journal_id=row["journal_id"],
            head_sequence=row["head_sequence"],
            head_hash=row["head_hash"],
        )
        if (
            row["schema_version"] != ROUTE_USAGE_SCHEMA_VERSION
            or row["key_id"] != self._key_id
            or not self._authenticated(row["meta_hmac"], payload)
        ):
            raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage metadata failed authentication")
        return row

    @staticmethod
    def _usage_from_row(row: Mapping[str, Any]) -> RouteAggregateUsage:
        return RouteAggregateUsage(
            calls=row["calls"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            cost_microusd=row["cost_microusd"],
        )

    def _verify_locked(self, connection: sqlite3.Connection) -> dict[str, Any]:
        meta = self._meta_row(connection)
        trigger_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger'"
            )
        }
        if not {
            "reserved_effects_immutable_update",
            "reserved_effects_immutable_delete",
            "aggregate_usage_immutable_delete",
        } <= trigger_names:
            raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage guards are missing")
        previous = GENESIS_DIGEST
        states: dict[str, dict[str, Any]] = {}
        count = 0
        for row in connection.execute("SELECT * FROM reserved_effects ORDER BY sequence"):
            count += 1
            if row["sequence"] != count or row["previous_hash"] != previous:
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage chain is broken")
            payload = self._entry_payload(row)
            try:
                expected_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            except Exception as exc:
                raise RoutingError(
                    "ECO_ROUTE_USAGE_TAMPERED", "Route usage entry is not canonical"
                ) from exc
            if (
                row["entry_hash"] != expected_hash
                or row["key_id"] != self._key_id
                or not self._authenticated(row["entry_hmac"], payload)
            ):
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage entry failed authentication")
            current = states.get(row["consumer_digest"])
            if current is None:
                current = {
                    "request_digest": row["request_digest"],
                    "execution_plan_digest": row["execution_plan_digest"],
                    "policy_digest": row["policy_digest"],
                    "price_catalog_digest": row["price_catalog_digest"],
                    "consumer_kind": row["consumer_kind"],
                    "consumer_id": row["consumer_id"],
                    "usage": RouteAggregateUsage(),
                    "updated_sequence": 0,
                }
            if any(
                current[field] != row[field]
                for field in (
                    "request_digest",
                    "execution_plan_digest",
                    "policy_digest",
                    "price_catalog_digest",
                    "consumer_kind",
                    "consumer_id",
                )
            ):
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage binding changed")
            before = current["usage"]
            if before != RouteAggregateUsage(
                row["before_calls"],
                row["before_input_tokens"],
                row["before_output_tokens"],
                row["before_cost_microusd"],
            ):
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage counters are discontinuous")
            after = RouteAggregateUsage(
                row["after_calls"],
                row["after_input_tokens"],
                row["after_output_tokens"],
                row["after_cost_microusd"],
            )
            if after != RouteAggregateUsage(
                before.calls + 1,
                before.input_tokens + row["input_tokens"],
                before.output_tokens + row["output_tokens"],
                before.cost_microusd + row["cost_microusd"],
            ):
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage counters are invalid")
            current["usage"] = after
            current["updated_sequence"] = row["sequence"]
            states[row["consumer_digest"]] = current
            previous = expected_hash
        if meta["head_sequence"] != count or meta["head_hash"] != previous:
            raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route usage head does not match entries")

        stored_rows = list(connection.execute("SELECT * FROM aggregate_usage ORDER BY consumer_digest"))
        if {row["consumer_digest"] for row in stored_rows} != set(states):
            raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route aggregate state is inconsistent")
        for row in stored_rows:
            expected = states[row["consumer_digest"]]
            if (
                row["key_id"] != self._key_id
                or not self._authenticated(row["state_hmac"], self._state_payload(row))
                or any(
                    row[field] != expected[field]
                    for field in (
                        "request_digest",
                        "execution_plan_digest",
                        "policy_digest",
                        "price_catalog_digest",
                        "consumer_kind",
                        "consumer_id",
                        "updated_sequence",
                    )
                )
                or self._usage_from_row(row) != expected["usage"]
            ):
                raise RoutingError("ECO_ROUTE_USAGE_TAMPERED", "Route aggregate state failed verification")
        return {
            "journalId": meta["journal_id"],
            "entries": count,
            "headHash": previous,
            "states": states,
        }

    def verify(self) -> dict[str, Any]:
        """Re-authenticate the full chain and every aggregate projection."""

        with self._transaction() as connection:
            state = self._verify_locked(connection)
        return {
            "journalId": state["journalId"],
            "entries": state["entries"],
            "consumers": len(state["states"]),
            "headHash": state["headHash"],
        }

    def status(self, consumer_digest: str) -> dict[str, Any] | None:
        if not isinstance(consumer_digest, str) or _DIGEST_RE.fullmatch(consumer_digest) is None:
            raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route consumer digest is invalid")
        with self._transaction() as connection:
            self._verify_locked(connection)
            row = connection.execute(
                "SELECT * FROM aggregate_usage WHERE consumer_digest = ?", (consumer_digest,)
            ).fetchone()
        if row is None:
            return None
        usage = self._usage_from_row(row)
        return {
            "consumerDigest": consumer_digest,
            "calls": usage.calls,
            "inputTokens": usage.input_tokens,
            "outputTokens": usage.output_tokens,
            "costMicrousd": usage.cost_microusd,
            "updatedSequence": row["updated_sequence"],
        }

    def reserve(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        consumer_kind: str,
        consumer_id: str,
        workflow_effect_digest: str,
        effect_id: str,
        effect_digest: str,
        input_tokens: int,
        output_tokens: int,
        cost_microusd: int,
        now: datetime,
    ) -> dict[str, Any]:
        """Atomically reserve one exact effect or return its idempotent replay."""

        if (
            not isinstance(consumer_kind, str)
            or _CONSUMER_KIND_RE.fullmatch(consumer_kind) is None
            or not isinstance(consumer_id, str)
            or _IDENTIFIER_RE.fullmatch(consumer_id) is None
            or not isinstance(effect_id, str)
            or _IDENTIFIER_RE.fullmatch(effect_id) is None
            or not isinstance(effect_digest, str)
            or _DIGEST_RE.fullmatch(effect_digest) is None
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (input_tokens, output_tokens, cost_microusd)
            )
        ):
            raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route effect binding is invalid")
        reserved_at = _utc(now)
        consumer_digest = route_consumer_digest(
            decision,
            request,
            consumer_kind=consumer_kind,
            consumer_id=consumer_id,
            effect_digest=workflow_effect_digest,
        )
        try:
            decision_record = validate_routing_record(dict(decision))
            request_record = validate_routing_record(dict(request))
        except Exception as exc:
            raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence is invalid") from exc
        decision_spec = decision_record["spec"]
        request_spec = request_record["spec"]
        selected = decision_spec["selected"]
        if selected is None:
            raise RoutingError("ECO_ROUTE_NOT_ALLOWED", "Only an allowed route can reserve usage")
        # A replay is authorization to proceed toward the provider effect, not
        # merely a historical read. Re-check current route validity before the
        # idempotent-return branch so a crash before provider STARTED cannot be
        # resumed under expired authority.
        verify_route_binding(
            decision_record,
            request_record,
            expected_deployment_id=selected["deploymentId"],
            expected_deployment_identity_digest=selected["deploymentIdentityDigest"],
            expected_policy_digest=decision_spec["policyDigest"],
            expected_price_catalog_digest=decision_spec["priceCatalogDigest"],
            expected_execution_plan_digest=request_spec["executionPlanDigest"],
            now=now,
        )
        bindings = {
            "request_digest": request_record["metadata"]["recordDigest"],
            "execution_plan_digest": request_spec["executionPlanDigest"],
            "policy_digest": decision_spec["policyDigest"],
            "price_catalog_digest": decision_spec["priceCatalogDigest"],
            "route_digest": decision_record["metadata"]["recordDigest"],
            "deployment_id": selected["deploymentId"],
            "deployment_identity_digest": selected["deploymentIdentityDigest"],
            "consumer_kind": consumer_kind,
            "consumer_id": consumer_id,
            "effect_digest": effect_digest,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_microusd": cost_microusd,
        }
        with self._transaction() as connection:
            journal = self._verify_locked(connection)
            existing = connection.execute(
                """SELECT * FROM reserved_effects
                    WHERE consumer_digest = ? AND effect_id = ?""",
                (consumer_digest, effect_id),
            ).fetchone()
            if existing is not None:
                if any(existing[field] != value for field, value in bindings.items()):
                    raise RoutingError(
                        "ECO_ROUTE_EFFECT_REPLAY_MISMATCH",
                        "Effect id was already reserved with another binding",
                    )
                return {
                    "consumerDigest": consumer_digest,
                    "effectId": effect_id,
                    "routeDigest": existing["route_digest"],
                    "sequence": existing["sequence"],
                    "entryHash": existing["entry_hash"],
                    "replayed": True,
                    "reservedAt": existing["reserved_at"],
                    "usage": {
                        "calls": existing["after_calls"],
                        "inputTokens": existing["after_input_tokens"],
                        "outputTokens": existing["after_output_tokens"],
                        "costMicrousd": existing["after_cost_microusd"],
                    },
                }
            current_state = journal["states"].get(consumer_digest)
            current = current_state["usage"] if current_state is not None else RouteAggregateUsage()
            if current_state is not None and any(
                current_state[field] != value
                for field, value in {
                    "request_digest": bindings["request_digest"],
                    "execution_plan_digest": bindings["execution_plan_digest"],
                    "policy_digest": bindings["policy_digest"],
                    "price_catalog_digest": bindings["price_catalog_digest"],
                    "consumer_kind": consumer_kind,
                    "consumer_id": consumer_id,
                }.items()
            ):
                raise RoutingError("ECO_ROUTE_USAGE_BINDING_MISMATCH", "Route usage binding changed")
            updated = reserve_route_effect(
                decision_record,
                request_record,
                current,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_microusd=cost_microusd,
            )
            sequence = journal["entries"] + 1
            row = {
                "consumer_digest": consumer_digest,
                "effect_id": effect_id,
                "sequence": sequence,
                **bindings,
                "before_calls": current.calls,
                "before_input_tokens": current.input_tokens,
                "before_output_tokens": current.output_tokens,
                "before_cost_microusd": current.cost_microusd,
                "after_calls": updated.calls,
                "after_input_tokens": updated.input_tokens,
                "after_output_tokens": updated.output_tokens,
                "after_cost_microusd": updated.cost_microusd,
                "reserved_at": reserved_at,
                "previous_hash": journal["headHash"],
            }
            entry_payload = self._entry_payload(row)
            entry_hash = hashlib.sha256(canonical_json(entry_payload).encode("utf-8")).hexdigest()
            state_row = {
                "consumer_digest": consumer_digest,
                "request_digest": bindings["request_digest"],
                "execution_plan_digest": bindings["execution_plan_digest"],
                "policy_digest": bindings["policy_digest"],
                "price_catalog_digest": bindings["price_catalog_digest"],
                "consumer_kind": consumer_kind,
                "consumer_id": consumer_id,
                "calls": updated.calls,
                "input_tokens": updated.input_tokens,
                "output_tokens": updated.output_tokens,
                "cost_microusd": updated.cost_microusd,
                "updated_sequence": sequence,
            }
            connection.execute(
                """INSERT INTO aggregate_usage VALUES (
                    :consumer_digest, :request_digest, :execution_plan_digest,
                    :policy_digest, :price_catalog_digest, :consumer_kind,
                    :consumer_id, :calls, :input_tokens, :output_tokens,
                    :cost_microusd, :updated_sequence, :key_id, :state_hmac
                ) ON CONFLICT(consumer_digest) DO UPDATE SET
                    calls=excluded.calls,
                    input_tokens=excluded.input_tokens,
                    output_tokens=excluded.output_tokens,
                    cost_microusd=excluded.cost_microusd,
                    updated_sequence=excluded.updated_sequence,
                    key_id=excluded.key_id,
                    state_hmac=excluded.state_hmac""",
                {
                    **state_row,
                    "key_id": self._key_id,
                    "state_hmac": self._sign(self._state_payload(state_row)),
                },
            )
            connection.execute(
                """INSERT INTO reserved_effects VALUES (
                    :consumer_digest, :effect_id, :sequence, :request_digest,
                    :execution_plan_digest, :policy_digest, :price_catalog_digest,
                    :route_digest, :deployment_id, :deployment_identity_digest,
                    :consumer_kind, :consumer_id, :effect_digest, :input_tokens,
                    :output_tokens, :cost_microusd, :before_calls,
                    :before_input_tokens, :before_output_tokens,
                    :before_cost_microusd, :after_calls, :after_input_tokens,
                    :after_output_tokens, :after_cost_microusd, :reserved_at,
                    :previous_hash, :entry_hash, :key_id, :entry_hmac
                )""",
                {
                    **row,
                    "entry_hash": entry_hash,
                    "key_id": self._key_id,
                    "entry_hmac": self._sign(entry_payload),
                },
            )
            meta_payload = self._meta_payload(
                journal_id=journal["journalId"],
                head_sequence=sequence,
                head_hash=entry_hash,
            )
            connection.execute(
                """UPDATE journal_meta
                    SET head_sequence = ?, head_hash = ?, meta_hmac = ?
                    WHERE singleton = 1""",
                (sequence, entry_hash, self._sign(meta_payload)),
            )
        return {
            "consumerDigest": consumer_digest,
            "effectId": effect_id,
            "routeDigest": bindings["route_digest"],
            "sequence": sequence,
            "entryHash": entry_hash,
            "replayed": False,
            "reservedAt": reserved_at,
            "usage": {
                "calls": updated.calls,
                "inputTokens": updated.input_tokens,
                "outputTokens": updated.output_tokens,
                "costMicrousd": updated.cost_microusd,
            },
        }
