from __future__ import annotations

"""Embedded, durable and fail-closed orchestration for bounded agent teams.

This scheduler coordinates work; it is not an authorization service.  Every
claim is narrowed by the current M5 authority and every effect requires a
separate, opaque authorization minted by a trusted runtime authorizer.
"""

import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TypeVar

from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.contracts import validate_record as validate_runtime_record
from eco_runtime.errors import ContractValidationError, RuntimePolicyError, RuntimeStoreError
from eco_runtime.team_access import evaluate_team_access
from eco_runtime.team_authority import SQLiteTeamAuthority
from eco_runtime.team_runtime import TeamAuthorizationGate
from eco_routing.contracts import validate_routing_record

from .contracts import API_VERSION, seal_record, validate_record

_T = TypeVar("_T")
_TERMINAL = frozenset({"succeeded", "failed", "cancelled", "ambiguous"})
_DATA_ORDER = {"D0": 0, "D1": 1, "D2": 2, "D3": 3}
_APPLICATION_ID = 0x45434F36
_SCHEMA_VERSION = 1


class TeamRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str = "Team orchestration failed closed") -> None:
        super().__init__(message)
        self.code = code


def _error(code: str) -> TeamRuntimeError:
    return TeamRuntimeError(code)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _error("ECO_TEAM_CLOCK_INVALID")
    return value.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise _error("ECO_TEAM_TIME_INVALID") from exc
    if result.tzinfo is None:
        raise _error("ECO_TEAM_TIME_INVALID")
    return result.astimezone(timezone.utc)


def _epoch(value: datetime) -> int:
    return int(_utc(value).timestamp() * 1_000_000)


def _binding_digest(value: Mapping[str, Any]) -> str:
    return semantic_digest({"profile": "eco-team-worker-binding-v1", "binding": dict(value)})


class AuthorityGuard(Protocol):
    def assert_manifest_current(self, manifest: Mapping[str, Any], *, now: datetime) -> None: ...

    def assert_claim_current(
        self,
        manifest: Mapping[str, Any],
        task: Mapping[str, Any],
        worker: Mapping[str, Any],
        *,
        now: datetime,
    ) -> str: ...


class ExecutionAuthorizer(Protocol):
    def authorize(
        self,
        manifest: Mapping[str, Any],
        task: Mapping[str, Any],
        worker: Mapping[str, Any],
        evidence: Any,
        *,
        now: datetime,
    ) -> Mapping[str, Any]: ...

    def assert_current(
        self,
        manifest: Mapping[str, Any],
        task: Mapping[str, Any],
        worker: Mapping[str, Any],
        evidence: Any,
        authorization: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None: ...

    def execute_authorized(
        self, evidence: Any, operation: Callable[[], _T], *, now: datetime
    ) -> _T: ...


class M5AuthorityGuard:
    """Exact manifest/worker binding to one current signed M5 authority.

    The guard only narrows scheduling eligibility.  Its allow is not runtime
    authority, which is why :class:`TeamCoordinator` separately requires an
    ``ExecutionAuthorizer`` before an effect may start.
    """

    __slots__ = ("_authority",)

    def __init__(self, authority: SQLiteTeamAuthority) -> None:
        if not isinstance(authority, SQLiteTeamAuthority):
            raise TypeError("authority must be SQLiteTeamAuthority")
        self._authority = authority

    def assert_manifest_current(self, manifest: Mapping[str, Any], *, now: datetime) -> None:
        candidate = validate_record(copy.deepcopy(dict(manifest)))
        if candidate["kind"] != "AgentTeamManifest":
            raise _error("ECO_TEAM_MANIFEST_INVALID")
        binding = candidate["spec"]["authority"]
        snapshot = self._authority.snapshot()
        expected = {
            "teamId": snapshot["teamId"],
            "storeId": snapshot["storeId"],
            "authoritySnapshotDigest": snapshot["authoritySnapshotDigest"],
            "activeBundleDigest": snapshot["activePolicy"]["digest"],
            "accessPolicyDigest": binding["accessPolicyDigest"],
        }
        if (
            binding != expected
            or candidate["metadata"]["projectId"] != snapshot["projectId"]
            or snapshot["emergencyDeny"]
            or snapshot["generationStatus"] != "active"
        ):
            raise _error("ECO_TEAM_AUTHORITY_STALE")
        try:
            self._authority.assert_live(
                expected_snapshot_digest=binding["authoritySnapshotDigest"], now=_utc(now)
            )
        except RuntimeStoreError as exc:
            raise _error("ECO_TEAM_AUTHORITY_STALE") from exc

    def assert_claim_current(
        self,
        manifest: Mapping[str, Any],
        task: Mapping[str, Any],
        worker: Mapping[str, Any],
        *,
        now: datetime,
    ) -> str:
        self.assert_manifest_current(manifest, now=now)
        roles = {role["id"]: role for role in manifest["spec"]["roles"]}
        role = roles.get(task["spec"]["roleId"])
        if role is None or set(worker) != {"principal", "membership"}:
            raise _error("ECO_TEAM_WORKER_UNBOUND")
        if worker["principal"] != role["principal"] or worker["membership"] != role["membership"]:
            raise _error("ECO_TEAM_WORKER_UNBOUND")
        snapshot = self._authority.snapshot()
        try:
            context = self._authority.active_access_context(
                principal_id=worker["principal"]["id"],
                membership_id=worker["membership"]["id"],
                expected_snapshot_digest=snapshot["authoritySnapshotDigest"],
                now=_utc(now),
            )
        except RuntimeStoreError as exc:
            raise _error("ECO_TEAM_WORKER_INACTIVE") from exc
        if (
            context["principal"] != worker["principal"]
            or context["membership"] != worker["membership"]
            or context["accessPolicy"]["metadata"]["recordDigest"]
            != manifest["spec"]["authority"]["accessPolicyDigest"]
        ):
            raise _error("ECO_TEAM_AUTHORITY_STALE")
        request = {
            "principal": worker["principal"],
            "membership": worker["membership"],
            "action": task["spec"]["action"],
            "actionClass": _action_class(task["spec"]["action"]),
            "resource": task["spec"]["resource"],
            "projectId": task["metadata"]["projectId"],
            "environmentId": task["spec"]["environmentId"],
            "dataClass": task["spec"]["dataClass"],
        }
        decision = evaluate_team_access(context["accessPolicy"], request, now=_utc(now))
        if decision.team_effect != "allow":
            raise _error(decision.code)
        return semantic_digest(
            {
                "domain": "eco-team-claim-narrowing-v1",
                "snapshot": snapshot["authoritySnapshotDigest"],
                "accessDecision": decision.as_dict(),
                "task": task["metadata"]["recordDigest"],
            }
        )


def _action_class(action: str) -> str:
    from eco_runtime.team_access import ACTION_PROFILE

    try:
        return ACTION_PROFILE[action][0]
    except KeyError as exc:
        raise _error("ECO_TEAM_ACTION_UNSUPPORTED") from exc


class M5ExecutionAuthorizer:
    """Trusted adapter that binds an exact M5/runtime gate to one team task."""

    __slots__ = ("_gate",)

    def __init__(self, gate: TeamAuthorizationGate) -> None:
        if not isinstance(gate, TeamAuthorizationGate):
            raise TypeError("gate must be TeamAuthorizationGate")
        self._gate = gate

    @staticmethod
    def _parts(task: Mapping[str, Any], worker: Mapping[str, Any], evidence: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], Any]:
        required = {"runtimeDecision", "runtimeSubject", "teamRequest", "actorAssertion", "permit"}
        if not isinstance(evidence, Mapping) or not required <= set(evidence):
            raise _error("ECO_TEAM_EXECUTION_EVIDENCE_INVALID")
        team_request = {
            "principal": worker["principal"],
            "membership": worker["membership"],
            "action": task["spec"]["action"],
            "actionClass": _action_class(task["spec"]["action"]),
            "resource": task["spec"]["resource"],
            "projectId": task["metadata"]["projectId"],
            "environmentId": task["spec"]["environmentId"],
            "dataClass": task["spec"]["dataClass"],
        }
        if evidence["teamRequest"] != team_request:
            raise _error("ECO_TEAM_EXECUTION_BINDING_MISMATCH")
        subject = copy.deepcopy(dict(evidence["runtimeSubject"]))
        if (
            subject.get("metadata", {}).get("runId") != task["metadata"]["runId"]
            or (task["spec"]["action"] == "model.invoke" and subject.get("kind") != "ModelRequest")
        ):
            raise _error("ECO_TEAM_EXECUTION_BINDING_MISMATCH")
        return (
            copy.deepcopy(dict(evidence["runtimeDecision"])),
            subject,
            team_request,
            copy.deepcopy(dict(evidence["actorAssertion"])),
            evidence["permit"],
        )

    def authorize(self, manifest: Mapping[str, Any], task: Mapping[str, Any], worker: Mapping[str, Any], evidence: Any, *, now: datetime) -> Mapping[str, Any]:
        decision, subject, request, assertion, permit = self._parts(task, worker, evidence)
        result = self._gate.authorize(
            decision, subject, request, now=_utc(now), actor_assertion=assertion, permit=permit
        )
        if result.effect != "allow" or not result.effective_authorization:
            raise _error(result.code)
        return {
            "effect": "allow",
            "taskDigest": task["metadata"]["recordDigest"],
            "runtimeDecisionDigest": result.runtime_decision_digest,
            "teamRequestDigest": result.team_request_digest,
            "authoritySnapshotDigest": result.authority_snapshot_digest,
        }

    def assert_current(self, manifest: Mapping[str, Any], task: Mapping[str, Any], worker: Mapping[str, Any], evidence: Any, authorization: Mapping[str, Any], *, now: datetime) -> None:
        if dict(authorization) != dict(self.authorize(manifest, task, worker, evidence, now=now)):
            raise _error("ECO_TEAM_EXECUTION_AUTHORITY_STALE")

    def execute_authorized(self, evidence: Any, operation: Callable[[], _T], *, now: datetime) -> _T:
        # The exact records have already been checked at authorization/start.
        # The caller must use this method immediately after start_effect; the
        # M5 gate consumes its single-use runtime decision around the effect.
        if not isinstance(evidence, Mapping):
            raise _error("ECO_TEAM_EXECUTION_EVIDENCE_INVALID")
        guarded = self._gate.execute_authorized(
            copy.deepcopy(dict(evidence["runtimeDecision"])),
            copy.deepcopy(dict(evidence["runtimeSubject"])),
            copy.deepcopy(dict(evidence["teamRequest"])),
            now=_utc(now),
            operation=operation,
            actor_assertion=copy.deepcopy(dict(evidence["actorAssertion"])),
            permit=evidence["permit"],
        )
        return guarded.result


@dataclass(frozen=True, slots=True)
class LeaseClaim:
    run_id: str
    task_id: str
    task_digest: str
    worker_digest: str
    lease_token: str
    lease_expires_at: datetime
    attempt: int


@dataclass(frozen=True, slots=True)
class ExecutionAuthorization:
    run_id: str
    task_id: str
    task_digest: str
    claim_digest: str
    authorization: Mapping[str, Any]
    evidence: Any
    expires_at: datetime
    _seal: object


@dataclass(frozen=True, slots=True)
class TaskEffectResult:
    status: str
    outcome_digest: str
    used_tokens: int
    used_cost_microusd: int

    def __post_init__(self) -> None:
        if self.status not in {"succeeded", "failed"}:
            raise ValueError("status must be succeeded or failed")
        if len(self.outcome_digest) != 64 or any(c not in "0123456789abcdef" for c in self.outcome_digest):
            raise ValueError("outcome_digest must be sha256")
        if self.used_tokens < 0 or self.used_cost_microusd < 0:
            raise ValueError("usage must not be negative")


class TeamCoordinator:
    """SQLite-backed scheduler with bounded leases and conservative settlement."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority_guard: AuthorityGuard,
        execution_authorizer: ExecutionAuthorizer,
        hmac_key: bytes,
        key_id: str,
        forbidden_root: str | Path,
        clock: Callable[[], datetime] | None = None,
        trusted_route_decision_digests: frozenset[str] = frozenset(),
        trusted_route_policy_digests: frozenset[str] = frozenset(),
        trusted_price_catalog_digests: frozenset[str] = frozenset(),
    ) -> None:
        if authority_guard is None or execution_authorizer is None:
            raise ValueError("both authority and execution gates are required")
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("hmac_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise ValueError("key_id is invalid")
        self._authority_guard = authority_guard
        self._execution_authorizer = execution_authorizer
        self._hmac_key = hmac_key
        self._key_id = key_id
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        initial_clock = _utc(self._clock())
        self._last_observed_time: datetime | None = initial_clock
        self._trusted_route_decision_digests = frozenset(trusted_route_decision_digests)
        self._trusted_route_policy_digests = frozenset(trusted_route_policy_digests)
        self._trusted_price_catalog_digests = frozenset(trusted_price_catalog_digests)
        self._seal = object()
        self._lock = threading.RLock()
        self._path = self._prepare_private_path(path, forbidden_root=forbidden_root)
        existed = self._path.exists()
        self._db = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS manifests(
              manifest_id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
              team_id TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, document BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs(
              run_id TEXT PRIMARY KEY, manifest_id TEXT NOT NULL REFERENCES manifests(manifest_id),
              team_id TEXT NOT NULL, project_id TEXT NOT NULL, status TEXT NOT NULL,
              cancellation_requested INTEGER NOT NULL DEFAULT 0,
              max_tokens INTEGER NOT NULL, max_cost INTEGER NOT NULL,
              result_document BLOB
            );
            CREATE TABLE IF NOT EXISTS tasks(
              run_id TEXT NOT NULL REFERENCES runs(run_id), task_id TEXT NOT NULL,
              digest TEXT NOT NULL UNIQUE, document BLOB NOT NULL, status TEXT NOT NULL,
              attempt INTEGER NOT NULL DEFAULT 0, worker_digest TEXT,
              lease_hash TEXT, lease_expires_us INTEGER,
              reserved_tokens INTEGER NOT NULL DEFAULT 0,
              reserved_cost INTEGER NOT NULL DEFAULT 0,
              charged_tokens INTEGER NOT NULL DEFAULT 0,
              charged_cost INTEGER NOT NULL DEFAULT 0,
              outcome_digest TEXT, cancellation_requested INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY(run_id, task_id)
            );
            CREATE TABLE IF NOT EXISTS handoffs(
              run_id TEXT NOT NULL, handoff_id TEXT NOT NULL, from_task_id TEXT NOT NULL,
              to_task_id TEXT NOT NULL, artifact_digest TEXT NOT NULL,
              digest TEXT NOT NULL UNIQUE, document BLOB NOT NULL,
              PRIMARY KEY(run_id, handoff_id),
              FOREIGN KEY(run_id, from_task_id) REFERENCES tasks(run_id, task_id),
              FOREIGN KEY(run_id, to_task_id) REFERENCES tasks(run_id, task_id)
            );
            CREATE TABLE IF NOT EXISTS consumed_routes(
              route_digest TEXT PRIMARY KEY, task_digest TEXT NOT NULL UNIQUE,
              consumed_at_us INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS task_status_idx ON tasks(run_id, status);
            CREATE TABLE IF NOT EXISTS store_meta(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL,
              schema_version INTEGER NOT NULL, key_id TEXT NOT NULL, created_at TEXT NOT NULL,
              last_observed_us INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_auth(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL,
              state_digest TEXT NOT NULL, mac TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_events(
              revision INTEGER PRIMARY KEY, state_digest TEXT NOT NULL,
              previous_event_digest TEXT NOT NULL, event_digest TEXT NOT NULL UNIQUE,
              mac TEXT NOT NULL
            );
            """
        )
        self._check_private_file(allow_repair=not existed)
        with self._lock:
            if not existed:
                self._db.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                self._db.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            application_id = int(self._db.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
            auth = self._db.execute("SELECT * FROM state_auth WHERE singleton=1").fetchone()
            if auth is None:
                populated = sum(
                    int(self._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                    for table in ("manifests", "runs", "tasks", "handoffs", "consumed_routes")
                )
                if existed or populated or application_id not in {0, _APPLICATION_ID} or user_version not in {0, _SCHEMA_VERSION}:
                    self._db.close()
                    raise _error("ECO_TEAM_STORE_UNAUTHENTICATED")
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute(
                        "INSERT INTO store_meta VALUES(1,?,?,?,?,?)",
                        (secrets.token_hex(16), _SCHEMA_VERSION, key_id, _time_text(initial_clock), _epoch(initial_clock)),
                    )
                    self._write_state_auth_locked(initial=True)
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    self._db.close()
                    raise
            else:
                if application_id != _APPLICATION_ID or user_version != _SCHEMA_VERSION:
                    self._db.close()
                    raise _error("ECO_TEAM_STORE_PROFILE_MISMATCH")
                try:
                    self._verify_state_locked()
                except Exception:
                    self._db.close()
                    raise
                meta = self._db.execute("SELECT last_observed_us FROM store_meta WHERE singleton=1").fetchone()
                persisted = datetime.fromtimestamp(meta["last_observed_us"] / 1_000_000, tz=timezone.utc)
                if initial_clock < persisted:
                    self._db.close()
                    raise _error("ECO_TEAM_CLOCK_ROLLBACK")
                self._last_observed_time = max(initial_clock, persisted)

    def _observed_time(self, asserted: datetime) -> datetime:
        assertion = _utc(asserted)
        trusted = _utc(self._clock())
        with self._lock:
            if self._last_observed_time is not None and trusted < self._last_observed_time:
                raise _error("ECO_TEAM_CLOCK_ROLLBACK")
            if trusted < assertion:
                raise _error("ECO_TEAM_CLOCK_ASSERTION_AHEAD")
            self._last_observed_time = trusted
        return trusted

    @staticmethod
    def _prepare_private_path(path: str | Path, *, forbidden_root: str | Path) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute() or candidate.is_symlink():
            raise _error("ECO_TEAM_STORE_PATH_UNSAFE")
        forbidden = Path(forbidden_root).expanduser()
        if not forbidden.is_absolute():
            raise _error("ECO_TEAM_STORE_PATH_UNSAFE")
        lexical = Path(os.path.abspath(candidate))
        forbidden_lexical = Path(os.path.abspath(forbidden))
        try:
            forbidden_resolved = forbidden.resolve()
        except OSError as exc:
            raise _error("ECO_TEAM_STORE_PATH_UNSAFE") from exc
        if lexical.is_relative_to(forbidden_lexical):
            raise _error("ECO_TEAM_STORE_LOCATION_DENIED")
        candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        resolved = candidate.resolve()
        if resolved != candidate.absolute():
            raise _error("ECO_TEAM_STORE_PATH_UNSAFE")
        if resolved.is_relative_to(forbidden_resolved):
            raise _error("ECO_TEAM_STORE_LOCATION_DENIED")
        if os.name == "posix":
            parent = resolved.parent.stat()
            if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise _error("ECO_TEAM_STORE_PERMISSIONS")
        return resolved

    def _check_private_file(self, *, allow_repair: bool = False) -> None:
        details = self._path.lstat()
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise _error("ECO_TEAM_STORE_PATH_UNSAFE")
        if os.name == "posix":
            if details.st_uid != os.getuid() or (details.st_mode & 0o077 and not allow_repair):
                raise _error("ECO_TEAM_STORE_PERMISSIONS")
            os.chmod(self._path, 0o600)

    @staticmethod
    def _blob_digest(value: object) -> str | None:
        if value is None:
            return None
        return hashlib.sha256(bytes(value)).hexdigest()

    def _state_payload_locked(self) -> dict[str, Any]:
        meta = self._db.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
        if meta is None:
            raise _error("ECO_TEAM_STORE_CORRUPT")
        manifests = [
            {
                "manifestId": row["manifest_id"], "projectId": row["project_id"],
                "teamId": row["team_id"], "digest": row["digest"],
                "documentSha256": self._blob_digest(row["document"]),
            }
            for row in self._db.execute("SELECT * FROM manifests ORDER BY manifest_id")
        ]
        runs = [
            {
                "runId": row["run_id"], "manifestId": row["manifest_id"],
                "teamId": row["team_id"], "projectId": row["project_id"],
                "status": row["status"],
                "cancellationRequested": int(row["cancellation_requested"]),
                "maxTokens": row["max_tokens"], "maxCost": row["max_cost"],
                "resultDocumentSha256": self._blob_digest(row["result_document"]),
            }
            for row in self._db.execute("SELECT * FROM runs ORDER BY run_id")
        ]
        tasks = [
            {
                "runId": row["run_id"], "taskId": row["task_id"],
                "digest": row["digest"], "documentSha256": self._blob_digest(row["document"]),
                "status": row["status"], "attempt": row["attempt"],
                "workerDigest": row["worker_digest"], "leaseHash": row["lease_hash"],
                "leaseExpiresUs": row["lease_expires_us"],
                "reservedTokens": row["reserved_tokens"], "reservedCost": row["reserved_cost"],
                "chargedTokens": row["charged_tokens"], "chargedCost": row["charged_cost"],
                "outcomeDigest": row["outcome_digest"],
                "cancellationRequested": int(row["cancellation_requested"]),
            }
            for row in self._db.execute("SELECT * FROM tasks ORDER BY run_id,task_id")
        ]
        handoffs = [
            {
                "runId": row["run_id"], "handoffId": row["handoff_id"],
                "fromTaskId": row["from_task_id"], "toTaskId": row["to_task_id"],
                "artifactDigest": row["artifact_digest"], "digest": row["digest"],
                "documentSha256": self._blob_digest(row["document"]),
            }
            for row in self._db.execute("SELECT * FROM handoffs ORDER BY run_id,handoff_id")
        ]
        routes = [
            {"routeDigest": row["route_digest"], "taskDigest": row["task_digest"], "consumedAtUs": row["consumed_at_us"]}
            for row in self._db.execute("SELECT * FROM consumed_routes ORDER BY route_digest")
        ]
        return {
            "domain": "eco-team-coordinator-state-v1",
            "meta": {
                "storeId": meta["store_id"], "schemaVersion": meta["schema_version"],
                "keyId": meta["key_id"], "createdAt": meta["created_at"],
                "lastObservedUs": meta["last_observed_us"],
            },
            "manifests": manifests, "runs": runs, "tasks": tasks,
            "handoffs": handoffs, "consumedRoutes": routes,
        }

    def _auth_mac(self, revision: int, state_digest: str) -> str:
        return hmac.new(
            self._hmac_key,
            canonical_json(
                {
                    "domain": "eco-team-coordinator-auth-v1",
                    "keyId": self._key_id,
                    "revision": revision,
                    "stateDigest": state_digest,
                }
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _event_mac(self, event_digest: str) -> str:
        return hmac.new(
            self._hmac_key,
            canonical_json(
                {"domain": "eco-team-coordinator-event-auth-v1", "keyId": self._key_id, "eventDigest": event_digest}
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _verify_event_chain_locked(self, head_revision: int, head_state_digest: str) -> None:
        previous = "0" * 64
        rows = self._db.execute("SELECT * FROM state_events ORDER BY revision").fetchall()
        if len(rows) != head_revision + 1:
            raise _error("ECO_TEAM_STORE_AUTH_FAILED")
        for expected_revision, row in enumerate(rows):
            event_digest = semantic_digest(
                {
                    "domain": "eco-team-coordinator-state-event-v1",
                    "revision": expected_revision,
                    "stateDigest": row["state_digest"],
                    "previousEventDigest": previous,
                }
            )
            if (
                row["revision"] != expected_revision
                or row["previous_event_digest"] != previous
                or row["event_digest"] != event_digest
                or not hmac.compare_digest(row["mac"], self._event_mac(event_digest))
            ):
                raise _error("ECO_TEAM_STORE_AUTH_FAILED")
            previous = event_digest
        if not rows or rows[-1]["state_digest"] != head_state_digest:
            raise _error("ECO_TEAM_STORE_AUTH_FAILED")

    def _verify_state_locked(self) -> None:
        auth = self._db.execute("SELECT * FROM state_auth WHERE singleton=1").fetchone()
        meta = self._db.execute("SELECT * FROM store_meta WHERE singleton=1").fetchone()
        if auth is None or meta is None or meta["key_id"] != self._key_id or meta["schema_version"] != _SCHEMA_VERSION:
            raise _error("ECO_TEAM_STORE_AUTH_FAILED")
        if (
            self._last_observed_time is not None
            and _epoch(self._last_observed_time) < meta["last_observed_us"]
        ):
            raise _error("ECO_TEAM_CLOCK_ROLLBACK")
        digest = semantic_digest(self._state_payload_locked())
        expected = self._auth_mac(int(auth["revision"]), digest)
        if digest != auth["state_digest"] or not hmac.compare_digest(expected, auth["mac"]):
            raise _error("ECO_TEAM_STORE_AUTH_FAILED")
        self._verify_event_chain_locked(int(auth["revision"]), digest)

    def _write_state_auth_locked(self, *, initial: bool = False) -> None:
        if self._last_observed_time is None:
            raise _error("ECO_TEAM_CLOCK_INVALID")
        self._db.execute(
            "UPDATE store_meta SET last_observed_us=? WHERE singleton=1 AND last_observed_us<=?",
            (_epoch(self._last_observed_time), _epoch(self._last_observed_time)),
        )
        current = self._db.execute("SELECT revision FROM state_auth WHERE singleton=1").fetchone()
        if initial:
            if current is not None:
                raise _error("ECO_TEAM_STORE_AUTH_FAILED")
            revision = 0
        else:
            if current is None:
                raise _error("ECO_TEAM_STORE_AUTH_FAILED")
            revision = int(current["revision"]) + 1
        digest = semantic_digest(self._state_payload_locked())
        mac = self._auth_mac(revision, digest)
        previous_row = self._db.execute(
            "SELECT event_digest FROM state_events ORDER BY revision DESC LIMIT 1"
        ).fetchone()
        previous = previous_row["event_digest"] if previous_row is not None else "0" * 64
        event_digest = semantic_digest(
            {
                "domain": "eco-team-coordinator-state-event-v1",
                "revision": revision,
                "stateDigest": digest,
                "previousEventDigest": previous,
            }
        )
        self._db.execute(
            "INSERT INTO state_events VALUES(?,?,?,?,?)",
            (revision, digest, previous, event_digest, self._event_mac(event_digest)),
        )
        self._db.execute(
            "INSERT OR REPLACE INTO state_auth(singleton,revision,state_digest,mac) VALUES(1,?,?,?)",
            (revision, digest, mac),
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "TeamCoordinator":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _role_map(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
        return {role["id"]: role for role in manifest["spec"]["roles"]}

    @staticmethod
    def _assert_task_role(task: Mapping[str, Any], role: Mapping[str, Any]) -> None:
        spec = task["spec"]
        budget = spec["budget"]
        if (
            spec["action"] not in role["actions"]
            or spec["dataClass"] not in role["dataClasses"]
            or (spec["toolId"] is not None and spec["toolId"] not in role["toolIds"])
            or spec["zone"] not in role["zones"]
            or _parse_time(spec["notAfter"]) > _parse_time(role["notAfter"])
            or budget["maxTokens"] > role["budget"]["maxTokens"]
            or budget["maxCostMicrousd"] > role["budget"]["maxCostMicrousd"]
            or budget["maxDurationSeconds"] > role["budget"]["maxDurationSeconds"]
        ):
            raise _error("ECO_TEAM_TASK_AUTHORITY_EXPANSION")

    @staticmethod
    def _assert_child_narrow(parent: Mapping[str, Any], child: Mapping[str, Any], roles: Mapping[str, Mapping[str, Any]]) -> None:
        parent_spec = parent["spec"]
        child_spec = child["spec"]
        parent_role = roles[parent_spec["roleId"]]
        if child_spec["roleId"] not in parent_role["delegatesTo"]:
            raise _error("ECO_TEAM_DELEGATION_DENIED")
        parent_budget = parent_spec["budget"]
        child_budget = child_spec["budget"]
        if (
            child_spec["action"] != parent_spec["action"]
            or _DATA_ORDER[child_spec["dataClass"]] > _DATA_ORDER[parent_spec["dataClass"]]
            or (parent_spec["toolId"] is None and child_spec["toolId"] is not None)
            or (parent_spec["toolId"] is not None and child_spec["toolId"] not in {None, parent_spec["toolId"]})
            or child_spec["zone"] != parent_spec["zone"]
            or child_spec["environmentId"] != parent_spec["environmentId"]
            or child_spec["resource"] != parent_spec["resource"]
            or _parse_time(child_spec["notAfter"]) > _parse_time(parent_spec["notAfter"])
            or child_budget["maxTokens"] > parent_budget["maxTokens"]
            or child_budget["maxCostMicrousd"] > parent_budget["maxCostMicrousd"]
            or child_budget["maxDurationSeconds"] > parent_budget["maxDurationSeconds"]
        ):
            raise _error("ECO_TEAM_CHILD_AUTHORITY_EXPANSION")

    @staticmethod
    def _assert_acyclic(tasks: Mapping[str, Mapping[str, Any]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise _error("ECO_TEAM_TASK_CYCLE")
            if task_id in visited:
                return
            visiting.add(task_id)
            task = tasks[task_id]
            parent = task["spec"]["parentTaskId"]
            edges = list(task["spec"]["dependencies"])
            if parent is not None:
                edges.append(parent)
            for edge in edges:
                if edge not in tasks:
                    raise _error("ECO_TEAM_TASK_REFERENCE_INVALID")
                visit(edge)
            visiting.remove(task_id)
            visited.add(task_id)

        for identifier in sorted(tasks):
            visit(identifier)

    def create_run(
        self,
        manifest: Mapping[str, Any],
        run_id: str,
        tasks: list[Mapping[str, Any]],
        *,
        now: datetime,
    ) -> str:
        observed = self._observed_time(now)
        candidate = validate_record(copy.deepcopy(dict(manifest)))
        if candidate["kind"] != "AgentTeamManifest":
            raise _error("ECO_TEAM_MANIFEST_INVALID")
        self._authority_guard.assert_manifest_current(candidate, now=observed)
        if not isinstance(run_id, str) or not run_id or len(tasks) < 1:
            raise _error("ECO_TEAM_RUN_INVALID")
        if len(tasks) > candidate["spec"]["budget"]["maxTasks"]:
            raise _error("ECO_TEAM_TASK_LIMIT")
        if (
            _parse_time(candidate["metadata"]["createdAt"]) > observed
            or observed >= _parse_time(candidate["spec"]["deadline"])
        ):
            raise _error("ECO_TEAM_RUN_EXPIRED")
        team_id = candidate["spec"]["authority"]["teamId"]
        project_id = candidate["metadata"]["projectId"]
        checked: dict[str, dict[str, Any]] = {}
        roles = self._role_map(candidate)
        for raw in tasks:
            task = validate_record(copy.deepcopy(dict(raw)))
            metadata = task["metadata"]
            if (
                task["kind"] != "TeamTask"
                or metadata["runId"] != run_id
                or metadata["teamId"] != team_id
                or metadata["projectId"] != project_id
                or metadata["id"] in checked
                or _parse_time(metadata["createdAt"]) > observed
                or _parse_time(task["spec"]["notAfter"]) > _parse_time(candidate["spec"]["deadline"])
            ):
                raise _error("ECO_TEAM_TASK_BINDING_MISMATCH")
            role = roles.get(task["spec"]["roleId"])
            if role is None:
                raise _error("ECO_TEAM_ROLE_UNKNOWN")
            self._assert_task_role(task, role)
            checked[metadata["id"]] = task
        self._assert_acyclic(checked)
        for task in checked.values():
            parent_id = task["spec"]["parentTaskId"]
            if parent_id is not None:
                self._assert_child_narrow(checked[parent_id], task, roles)
        manifest_raw = canonical_json(candidate).encode("utf-8")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                self._db.execute(
                    "INSERT OR IGNORE INTO manifests VALUES(?,?,?,?,?)",
                    (candidate["metadata"]["id"], project_id, team_id, candidate["metadata"]["recordDigest"], manifest_raw),
                )
                existing_manifest = self._db.execute(
                    "SELECT digest FROM manifests WHERE manifest_id=?", (candidate["metadata"]["id"],)
                ).fetchone()
                if existing_manifest is None or existing_manifest["digest"] != candidate["metadata"]["recordDigest"]:
                    raise _error("ECO_TEAM_MANIFEST_CONFLICT")
                self._db.execute(
                    "INSERT INTO runs(run_id,manifest_id,team_id,project_id,status,max_tokens,max_cost) VALUES(?,?,?,?,?,?,?)",
                    (run_id, candidate["metadata"]["id"], team_id, project_id, "active", candidate["spec"]["budget"]["maxTotalTokens"], candidate["spec"]["budget"]["maxCostMicrousd"]),
                )
                for task_id in sorted(checked):
                    task = checked[task_id]
                    self._db.execute(
                        "INSERT INTO tasks(run_id,task_id,digest,document,status) VALUES(?,?,?,?,?)",
                        (run_id, task_id, task["metadata"]["recordDigest"], canonical_json(task).encode("utf-8"), "pending"),
                    )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._db.execute("ROLLBACK")
                raise _error("ECO_TEAM_RUN_CONFLICT") from exc
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return semantic_digest(
            {"domain": "eco-team-run-v1", "manifest": candidate["metadata"]["recordDigest"], "runId": run_id, "tasks": sorted(task["metadata"]["recordDigest"] for task in checked.values())}
        )

    @staticmethod
    def _document(row: sqlite3.Row, field: str = "document") -> dict[str, Any]:
        try:
            value = json.loads(bytes(row[field]))
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise _error("ECO_TEAM_STORE_CORRUPT") from exc
        return validate_record(value)

    def _context_locked(self, run_id: str) -> tuple[sqlite3.Row, dict[str, Any]]:
        run = self._db.execute(
            "SELECT r.*,m.document manifest_document FROM runs r JOIN manifests m ON m.manifest_id=r.manifest_id WHERE r.run_id=?",
            (run_id,),
        ).fetchone()
        if run is None:
            raise _error("ECO_TEAM_RUN_UNKNOWN")
        try:
            manifest = validate_record(json.loads(bytes(run["manifest_document"])))
        except (TypeError, ValueError, UnicodeDecodeError, ContractValidationError) as exc:
            raise _error("ECO_TEAM_STORE_CORRUPT") from exc
        return run, manifest

    @staticmethod
    def _claim_hash(token: str) -> str:
        return hashlib.sha256(("eco-team-lease-v1\0" + token).encode("utf-8")).hexdigest()

    @staticmethod
    def _claim_digest(claim: LeaseClaim) -> str:
        return semantic_digest(
            {
                "domain": "eco-team-lease-claim-v1",
                "runId": claim.run_id,
                "taskId": claim.task_id,
                "taskDigest": claim.task_digest,
                "workerDigest": claim.worker_digest,
                "leaseTokenHash": TeamCoordinator._claim_hash(claim.lease_token),
                "leaseExpiresAt": _time_text(claim.lease_expires_at),
                "attempt": claim.attempt,
            }
        )

    def _assert_claim_locked(self, claim: LeaseClaim, *, allow_started: bool = True) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM tasks WHERE run_id=? AND task_id=?", (claim.run_id, claim.task_id)
        ).fetchone()
        if (
            row is None
            or row["digest"] != claim.task_digest
            or row["worker_digest"] != claim.worker_digest
            or row["lease_hash"] != self._claim_hash(claim.lease_token)
            or row["lease_expires_us"] != _epoch(claim.lease_expires_at)
            or row["attempt"] != claim.attempt
            or row["status"] not in ({"leased", "started"} if allow_started else {"leased"})
        ):
            raise _error("ECO_TEAM_CLAIM_INVALID")
        return row

    def _dependencies_ready_locked(self, task: Mapping[str, Any]) -> bool:
        run_id = task["metadata"]["runId"]
        task_id = task["metadata"]["id"]
        expected_artifact = task["spec"]["input"]["digest"]
        for dependency in task["spec"]["dependencies"]:
            row = self._db.execute(
                "SELECT status FROM tasks WHERE run_id=? AND task_id=?", (run_id, dependency)
            ).fetchone()
            if row is None or row["status"] != "succeeded":
                return False
            handoff = self._db.execute(
                "SELECT artifact_digest FROM handoffs WHERE run_id=? AND from_task_id=? AND to_task_id=?",
                (run_id, dependency, task_id),
            ).fetchone()
            if handoff is None or handoff["artifact_digest"] != expected_artifact:
                return False
        return True

    def _usage_locked(self, run_id: str) -> tuple[int, int]:
        row = self._db.execute(
            "SELECT COALESCE(SUM(reserved_tokens+charged_tokens),0) tokens, COALESCE(SUM(reserved_cost+charged_cost),0) cost FROM tasks WHERE run_id=?",
            (run_id,),
        ).fetchone()
        return int(row["tokens"]), int(row["cost"])

    def _expire_locked(self, run_id: str, *, now: datetime) -> int:
        now_us = _epoch(now)
        started = self._db.execute(
            "SELECT task_id FROM tasks WHERE run_id=? AND status='started' AND lease_expires_us<=?",
            (run_id, now_us),
        ).fetchall()
        for row in started:
            self._db.execute(
                "UPDATE tasks SET status='ambiguous',charged_tokens=reserved_tokens,charged_cost=reserved_cost,reserved_tokens=0,reserved_cost=0 WHERE run_id=? AND task_id=? AND status='started'",
                (run_id, row["task_id"]),
            )
        # A lease that never crossed the effect boundary is safe to reissue.
        self._db.execute(
            "UPDATE tasks SET status='pending',worker_digest=NULL,lease_hash=NULL,lease_expires_us=NULL,reserved_tokens=0,reserved_cost=0 WHERE run_id=? AND status='leased' AND lease_expires_us<=?",
            (run_id, now_us),
        )
        return len(started)

    def claim_task(
        self,
        run_id: str,
        task_id: str,
        worker: Mapping[str, Any],
        *,
        now: datetime,
        lease_seconds: int = 60,
    ) -> LeaseClaim:
        observed = self._observed_time(now)
        if not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 3600:
            raise _error("ECO_TEAM_LEASE_INVALID")
        worker_copy = copy.deepcopy(dict(worker)) if isinstance(worker, Mapping) else {}
        worker_digest = _binding_digest(worker_copy)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                run, manifest = self._context_locked(run_id)
                self._expire_locked(run_id, now=observed)
                if run["status"] != "active" or run["cancellation_requested"]:
                    raise _error("ECO_TEAM_RUN_NOT_ACTIVE")
                row = self._db.execute(
                    "SELECT * FROM tasks WHERE run_id=? AND task_id=?", (run_id, task_id)
                ).fetchone()
                if row is None:
                    raise _error("ECO_TEAM_TASK_UNKNOWN")
                if row["status"] != "pending":
                    raise _error("ECO_TEAM_TASK_NOT_CLAIMABLE")
                task = self._document(row)
                if observed >= _parse_time(task["spec"]["notAfter"]):
                    raise _error("ECO_TEAM_TASK_EXPIRED")
                if not self._dependencies_ready_locked(task):
                    raise _error("ECO_TEAM_DEPENDENCIES_INCOMPLETE")
                self._authority_guard.assert_claim_current(manifest, task, worker_copy, now=observed)
                tokens, cost = self._usage_locked(run_id)
                reserve_tokens = task["spec"]["budget"]["maxTokens"]
                reserve_cost = task["spec"]["budget"]["maxCostMicrousd"]
                if tokens + reserve_tokens > run["max_tokens"] or cost + reserve_cost > run["max_cost"]:
                    raise _error("ECO_TEAM_AGGREGATE_BUDGET_EXCEEDED")
                token = secrets.token_urlsafe(32)
                expires = min(
                    observed + timedelta(seconds=lease_seconds),
                    _parse_time(task["spec"]["notAfter"]),
                    _parse_time(manifest["spec"]["deadline"]),
                )
                attempt = int(row["attempt"]) + 1
                updated = self._db.execute(
                    "UPDATE tasks SET status='leased',attempt=?,worker_digest=?,lease_hash=?,lease_expires_us=?,reserved_tokens=?,reserved_cost=? WHERE run_id=? AND task_id=? AND status='pending'",
                    (attempt, worker_digest, self._claim_hash(token), _epoch(expires), reserve_tokens, reserve_cost, run_id, task_id),
                )
                if updated.rowcount != 1:
                    raise _error("ECO_TEAM_CLAIM_RACE")
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return LeaseClaim(
            run_id=run_id,
            task_id=task_id,
            task_digest=task["metadata"]["recordDigest"],
            worker_digest=worker_digest,
            lease_token=token,
            lease_expires_at=expires,
            attempt=attempt,
        )

    def claim_next(
        self,
        run_id: str,
        worker: Mapping[str, Any],
        *,
        now: datetime,
        lease_seconds: int = 60,
    ) -> LeaseClaim:
        with self._lock:
            self._verify_state_locked()
            identifiers = [
                row["task_id"]
                for row in self._db.execute(
                    "SELECT task_id FROM tasks WHERE run_id=? AND status='pending' ORDER BY task_id",
                    (run_id,),
                ).fetchall()
            ]
        last: TeamRuntimeError | None = None
        for identifier in identifiers:
            try:
                return self.claim_task(run_id, identifier, worker, now=now, lease_seconds=lease_seconds)
            except TeamRuntimeError as exc:
                last = exc
                if exc.code not in {"ECO_TEAM_WORKER_UNBOUND", "ECO_TEAM_DEPENDENCIES_INCOMPLETE", "ECO_TEAM_TASK_NOT_CLAIMABLE"}:
                    raise
        raise last or _error("ECO_TEAM_NO_CLAIMABLE_TASK")

    def _validate_route_locked(
        self, task: Mapping[str, Any], evidence: Any, *, now: datetime
    ) -> dict[str, Any] | None:
        route_binding = task["spec"]["routeDecision"]
        if route_binding is None:
            if task["spec"]["action"] == "model.invoke":
                raise _error("ECO_TEAM_ROUTE_REQUIRED")
            return None
        if task["spec"]["action"] != "model.invoke" or not isinstance(evidence, Mapping):
            raise _error("ECO_TEAM_ROUTE_INVALID")
        try:
            decision = validate_routing_record(copy.deepcopy(evidence["routeDecision"]))
            request = validate_routing_record(copy.deepcopy(evidence["routeRequest"]))
            subject = validate_runtime_record(copy.deepcopy(evidence["runtimeSubject"]))
        except (KeyError, TypeError, ContractValidationError) as exc:
            raise _error("ECO_TEAM_ROUTE_INVALID") from exc
        if decision["kind"] != "ModelRouteDecision" or request["kind"] != "ModelRouteRequest" or subject["kind"] != "ModelRequest":
            raise _error("ECO_TEAM_ROUTE_INVALID")
        selected = decision["spec"]["selected"]
        task_spec = task["spec"]
        request_spec = request["spec"]
        subject_spec = subject["spec"]
        if (
            route_binding != {
                "kind": "ModelRouteDecision",
                "id": decision["metadata"]["id"],
                "digest": decision["metadata"]["recordDigest"],
            }
            or decision["spec"]["decision"] != "allowed"
            or selected is None
            or decision["metadata"]["recordDigest"] not in self._trusted_route_decision_digests
            or decision["spec"]["requestDigest"] != request["metadata"]["recordDigest"]
            or decision["spec"]["policyDigest"] != request_spec["policyDigest"]
            or decision["spec"]["policyDigest"] not in self._trusted_route_policy_digests
            or decision["spec"]["priceCatalogDigest"] not in self._trusted_price_catalog_digests
            or now >= _parse_time(decision["spec"]["validUntil"])
            or now >= _parse_time(request_spec["deadlineAt"])
            or request_spec["deadlineAt"] != task_spec["notAfter"]
            or request_spec["actionClass"] != _action_class(task_spec["action"])
            or request_spec["dataClass"] != task_spec["dataClass"]
            or task_spec["zone"] not in request_spec["allowedZones"]
            or request_spec["maximumCostMicrousd"] != task_spec["budget"]["maxCostMicrousd"]
            or selected["reservedCostMicrousd"] > request_spec["maximumCostMicrousd"]
            or selected["deploymentId"] != task_spec["resource"]["id"]
            or selected["deploymentIdentityDigest"] != task_spec["resource"]["digest"]
            or subject["metadata"]["runId"] != task["metadata"]["runId"]
            or subject_spec["deploymentId"] != selected["deploymentId"]
            or subject_spec["deploymentIdentityDigest"] != selected["deploymentIdentityDigest"]
            or subject_spec["input"]["dataClass"] != task_spec["dataClass"]
            or subject_spec["input"]["artifactRecordDigest"] != task_spec["input"]["digest"]
            or subject_spec["parameters"]["maxOutputTokens"] > request_spec["outputTokenCeiling"]
        ):
            raise _error("ECO_TEAM_ROUTE_BINDING_MISMATCH")
        if decision["spec"]["routeAttempt"] == 2:
            previous = self._db.execute(
                "SELECT 1 FROM consumed_routes WHERE route_digest=?",
                (decision["spec"]["fallbackFromDigest"],),
            ).fetchone()
            if previous is None:
                raise _error("ECO_TEAM_FALLBACK_PREDECESSOR_MISSING")
        return decision

    def authorize_effect(
        self,
        claim: LeaseClaim,
        worker: Mapping[str, Any],
        evidence: Any,
        *,
        now: datetime,
    ) -> ExecutionAuthorization:
        observed = self._observed_time(now)
        worker_copy = copy.deepcopy(dict(worker)) if isinstance(worker, Mapping) else {}
        if _binding_digest(worker_copy) != claim.worker_digest or observed >= claim.lease_expires_at:
            raise _error("ECO_TEAM_CLAIM_INVALID")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._verify_state_locked()
                row = self._assert_claim_locked(claim, allow_started=False)
                _, manifest = self._context_locked(claim.run_id)
                task = self._document(row)
                self._validate_route_locked(task, evidence, now=observed)
                narrowing = self._authority_guard.assert_claim_current(
                    manifest, task, worker_copy, now=observed
                )
                authorization = copy.deepcopy(
                    dict(
                        self._execution_authorizer.authorize(
                            manifest, task, worker_copy, evidence, now=observed
                        )
                    )
                )
                if (
                    authorization.get("effect") != "allow"
                    or authorization.get("taskDigest") != claim.task_digest
                    or not isinstance(narrowing, str)
                ):
                    raise _error("ECO_TEAM_EXECUTION_AUTHORITY_INVALID")
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return ExecutionAuthorization(
            run_id=claim.run_id,
            task_id=claim.task_id,
            task_digest=claim.task_digest,
            claim_digest=self._claim_digest(claim),
            authorization=authorization,
            evidence=evidence,
            expires_at=claim.lease_expires_at,
            _seal=self._seal,
        )

    def start_effect(
        self,
        claim: LeaseClaim,
        authorization: ExecutionAuthorization,
        worker: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None:
        observed = self._observed_time(now)
        worker_copy = copy.deepcopy(dict(worker)) if isinstance(worker, Mapping) else {}
        if (
            not isinstance(authorization, ExecutionAuthorization)
            or authorization._seal is not self._seal
            or authorization.run_id != claim.run_id
            or authorization.task_id != claim.task_id
            or authorization.task_digest != claim.task_digest
            or authorization.claim_digest != self._claim_digest(claim)
            or authorization.expires_at != claim.lease_expires_at
            or _binding_digest(worker_copy) != claim.worker_digest
            or observed >= claim.lease_expires_at
        ):
            raise _error("ECO_TEAM_EXECUTION_AUTHORITY_INVALID")
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                row = self._assert_claim_locked(claim, allow_started=False)
                run, manifest = self._context_locked(claim.run_id)
                task = self._document(row)
                if run["cancellation_requested"] or row["cancellation_requested"]:
                    raise _error("ECO_TEAM_CANCELLED")
                self._authority_guard.assert_claim_current(manifest, task, worker_copy, now=observed)
                self._execution_authorizer.assert_current(
                    manifest,
                    task,
                    worker_copy,
                    authorization.evidence,
                    authorization.authorization,
                    now=observed,
                )
                route_decision = self._validate_route_locked(
                    task, authorization.evidence, now=observed
                )
                route = task["spec"]["routeDecision"]
                if route is not None:
                    if route_decision is None:
                        raise _error("ECO_TEAM_ROUTE_INVALID")
                    try:
                        self._db.execute(
                            "INSERT INTO consumed_routes(route_digest,task_digest,consumed_at_us) VALUES(?,?,?)",
                            (route["digest"], task["metadata"]["recordDigest"], _epoch(observed)),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise _error("ECO_TEAM_ROUTE_ALREADY_CONSUMED") from exc
                changed = self._db.execute(
                    "UPDATE tasks SET status='started' WHERE run_id=? AND task_id=? AND status='leased'",
                    (claim.run_id, claim.task_id),
                )
                if changed.rowcount != 1:
                    raise _error("ECO_TEAM_EFFECT_ALREADY_STARTED")
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def complete_effect(
        self,
        claim: LeaseClaim,
        result: TaskEffectResult,
        *,
        now: datetime,
    ) -> dict[str, Any]:
        observed = self._observed_time(now)
        if not isinstance(result, TaskEffectResult):
            raise _error("ECO_TEAM_EFFECT_RESULT_INVALID")
        # A completion received after the lease deadline cannot prove that no
        # competing recovery observer already treated the effect as uncertain.
        # Terminal replay remains readable, but a still-started row is first
        # conservatively fenced as ambiguous.
        if observed >= claim.lease_expires_at:
            self.expire_leases(claim.run_id, now=observed)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                row = self._db.execute(
                    "SELECT * FROM tasks WHERE run_id=? AND task_id=?", (claim.run_id, claim.task_id)
                ).fetchone()
                if row is None or row["digest"] != claim.task_digest:
                    raise _error("ECO_TEAM_CLAIM_INVALID")
                if row["status"] in {"succeeded", "failed"}:
                    if (
                        row["status"] == result.status
                        and row["outcome_digest"] == result.outcome_digest
                        and row["charged_tokens"] == result.used_tokens
                        and row["charged_cost"] == result.used_cost_microusd
                    ):
                        self._db.execute("COMMIT")
                        return self.task_state(claim.run_id, claim.task_id)
                    raise _error("ECO_TEAM_TERMINAL_CONFLICT")
                row = self._assert_claim_locked(claim)
                if row["status"] != "started":
                    raise _error("ECO_TEAM_EFFECT_NOT_STARTED")
                if result.used_tokens > row["reserved_tokens"] or result.used_cost_microusd > row["reserved_cost"]:
                    raise _error("ECO_TEAM_TASK_BUDGET_EXCEEDED")
                self._db.execute(
                    "UPDATE tasks SET status=?,outcome_digest=?,charged_tokens=?,charged_cost=?,reserved_tokens=0,reserved_cost=0 WHERE run_id=? AND task_id=? AND status='started'",
                    (result.status, result.outcome_digest, result.used_tokens, result.used_cost_microusd, claim.run_id, claim.task_id),
                )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.task_state(claim.run_id, claim.task_id)

    def mark_ambiguous(self, claim: LeaseClaim, *, now: datetime) -> dict[str, Any]:
        self._observed_time(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                row = self._assert_claim_locked(claim)
                if row["status"] != "started":
                    raise _error("ECO_TEAM_EFFECT_NOT_STARTED")
                self._db.execute(
                    "UPDATE tasks SET status='ambiguous',charged_tokens=reserved_tokens,charged_cost=reserved_cost,reserved_tokens=0,reserved_cost=0 WHERE run_id=? AND task_id=? AND status='started'",
                    (claim.run_id, claim.task_id),
                )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.task_state(claim.run_id, claim.task_id)

    def execute_claimed(
        self,
        claim: LeaseClaim,
        authorization: ExecutionAuthorization,
        worker: Mapping[str, Any],
        operation: Callable[[], TaskEffectResult],
        *,
        now: datetime,
    ) -> dict[str, Any]:
        self.start_effect(claim, authorization, worker, now=now)
        try:
            result = self._execution_authorizer.execute_authorized(
                authorization.evidence, operation, now=self._observed_time(now)
            )
            if not isinstance(result, TaskEffectResult):
                raise _error("ECO_TEAM_EFFECT_RESULT_INVALID")
        except BaseException:
            # Once the operation boundary was crossed, a thrown exception does
            # not prove the external effect did not happen.  Never auto-retry.
            self.mark_ambiguous(claim, now=now)
            raise
        return self.complete_effect(claim, result, now=now)

    def expire_leases(self, run_id: str, *, now: datetime) -> int:
        observed = self._observed_time(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                self._context_locked(run_id)
                count = self._expire_locked(run_id, now=observed)
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
                return count
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def cancel_run(self, run_id: str, *, now: datetime) -> None:
        self._observed_time(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                run, _ = self._context_locked(run_id)
                if run["status"] != "active":
                    raise _error("ECO_TEAM_RUN_NOT_ACTIVE")
                self._db.execute(
                    "UPDATE runs SET cancellation_requested=1,status='cancelling' WHERE run_id=?",
                    (run_id,),
                )
                self._db.execute(
                    "UPDATE tasks SET status='cancelled',reserved_tokens=0,reserved_cost=0,cancellation_requested=1 WHERE run_id=? AND status IN ('pending','leased')",
                    (run_id,),
                )
                self._db.execute(
                    "UPDATE tasks SET cancellation_requested=1 WHERE run_id=? AND status='started'",
                    (run_id,),
                )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def cancellation_requested(self, claim: LeaseClaim) -> bool:
        with self._lock:
            self._verify_state_locked()
            row = self._db.execute(
                "SELECT cancellation_requested FROM tasks WHERE run_id=? AND task_id=?",
                (claim.run_id, claim.task_id),
            ).fetchone()
            if row is None:
                raise _error("ECO_TEAM_TASK_UNKNOWN")
            return bool(row["cancellation_requested"])

    def acknowledge_cancellation(self, claim: LeaseClaim, *, now: datetime) -> None:
        self._observed_time(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                row = self._assert_claim_locked(claim)
                if row["status"] != "started" or not row["cancellation_requested"]:
                    raise _error("ECO_TEAM_CANCELLATION_NOT_PENDING")
                # Conservative: a started operation consumes its reservation
                # unless trusted usage is later settled by manual resolution.
                self._db.execute(
                    "UPDATE tasks SET status='cancelled',charged_tokens=reserved_tokens,charged_cost=reserved_cost,reserved_tokens=0,reserved_cost=0 WHERE run_id=? AND task_id=?",
                    (claim.run_id, claim.task_id),
                )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def record_handoff(self, handoff: Mapping[str, Any]) -> str:
        candidate = validate_record(copy.deepcopy(dict(handoff)))
        if candidate["kind"] != "TeamHandoff":
            raise _error("ECO_TEAM_HANDOFF_INVALID")
        metadata = candidate["metadata"]
        spec = candidate["spec"]
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                run, _ = self._context_locked(metadata["runId"])
                if metadata["teamId"] != run["team_id"] or metadata["projectId"] != run["project_id"]:
                    raise _error("ECO_TEAM_HANDOFF_BINDING_MISMATCH")
                source_row = self._db.execute(
                    "SELECT * FROM tasks WHERE run_id=? AND task_id=?",
                    (metadata["runId"], spec["fromTaskId"]),
                ).fetchone()
                target_row = self._db.execute(
                    "SELECT * FROM tasks WHERE run_id=? AND task_id=?",
                    (metadata["runId"], spec["toTaskId"]),
                ).fetchone()
                if source_row is None or target_row is None:
                    raise _error("ECO_TEAM_HANDOFF_TASK_UNKNOWN")
                source = self._document(source_row)
                target = self._document(target_row)
                if (
                    source_row["status"] != "succeeded"
                    or target_row["status"] != "pending"
                    or spec["fromRoleId"] != source["spec"]["roleId"]
                    or spec["toRoleId"] != target["spec"]["roleId"]
                    or spec["fromTaskId"] not in target["spec"]["dependencies"]
                    or spec["artifact"] != target["spec"]["input"]
                ):
                    raise _error("ECO_TEAM_HANDOFF_SUBSTITUTION")
                duplicate = self._db.execute(
                    "SELECT digest FROM handoffs WHERE run_id=? AND from_task_id=? AND to_task_id=?",
                    (metadata["runId"], spec["fromTaskId"], spec["toTaskId"]),
                ).fetchone()
                if duplicate is not None:
                    if duplicate["digest"] == metadata["recordDigest"]:
                        self._db.execute("COMMIT")
                        return metadata["recordDigest"]
                    raise _error("ECO_TEAM_HANDOFF_CONFLICT")
                self._db.execute(
                    "INSERT INTO handoffs VALUES(?,?,?,?,?,?,?)",
                    (
                        metadata["runId"], metadata["id"], spec["fromTaskId"],
                        spec["toTaskId"], spec["artifact"]["digest"],
                        metadata["recordDigest"], canonical_json(candidate).encode("utf-8"),
                    ),
                )
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
                return metadata["recordDigest"]
            except sqlite3.IntegrityError as exc:
                self._db.execute("ROLLBACK")
                raise _error("ECO_TEAM_HANDOFF_CONFLICT") from exc
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def task_state(self, run_id: str, task_id: str) -> dict[str, Any]:
        with self._lock:
            self._verify_state_locked()
            row = self._db.execute(
                "SELECT * FROM tasks WHERE run_id=? AND task_id=?", (run_id, task_id)
            ).fetchone()
            if row is None:
                raise _error("ECO_TEAM_TASK_UNKNOWN")
            return {
                "runId": run_id,
                "taskId": task_id,
                "taskDigest": row["digest"],
                "status": row["status"],
                "attempt": row["attempt"],
                "reservedTokens": row["reserved_tokens"],
                "reservedCostMicrousd": row["reserved_cost"],
                "chargedTokens": row["charged_tokens"],
                "chargedCostMicrousd": row["charged_cost"],
                "outcomeDigest": row["outcome_digest"],
                "cancellationRequested": bool(row["cancellation_requested"]),
            }

    def run_state(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            self._verify_state_locked()
            run, _ = self._context_locked(run_id)
            tasks = [
                self.task_state(run_id, row["task_id"])
                for row in self._db.execute(
                    "SELECT task_id FROM tasks WHERE run_id=? ORDER BY task_id", (run_id,)
                ).fetchall()
            ]
            return {
                "runId": run_id,
                "teamId": run["team_id"],
                "projectId": run["project_id"],
                "status": run["status"],
                "cancellationRequested": bool(run["cancellation_requested"]),
                "tasks": tasks,
            }

    def finalize_run(self, run_id: str, *, result_id: str, now: datetime) -> dict[str, Any]:
        observed = self._observed_time(now)
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._verify_state_locked()
                run, _ = self._context_locked(run_id)
                if run["result_document"] is not None:
                    result = validate_record(json.loads(bytes(run["result_document"])))
                    if result["metadata"]["id"] != result_id:
                        raise _error("ECO_TEAM_RESULT_CONFLICT")
                    self._db.execute("COMMIT")
                    return result
                rows = self._db.execute(
                    "SELECT task_id,status,outcome_digest,charged_tokens,charged_cost FROM tasks WHERE run_id=? ORDER BY task_id",
                    (run_id,),
                ).fetchall()
                if not rows or any(row["status"] not in _TERMINAL for row in rows):
                    raise _error("ECO_TEAM_RUN_INCOMPLETE")
                statuses = [row["status"] for row in rows]
                status = (
                    "ambiguous" if "ambiguous" in statuses else
                    "succeeded" if all(item == "succeeded" for item in statuses) else
                    "cancelled" if all(item == "cancelled" for item in statuses) else
                    "failed" if all(item == "failed" for item in statuses) else
                    "partial-failure"
                )
                tasks = [
                    {
                        "id": row["task_id"], "status": row["status"],
                        "outcomeDigest": row["outcome_digest"],
                        "chargedTokens": row["charged_tokens"],
                        "chargedCostMicrousd": row["charged_cost"],
                    }
                    for row in rows
                ]
                result = seal_record(
                    {
                        "apiVersion": API_VERSION,
                        "kind": "TeamRunResult",
                        "metadata": {
                            "id": result_id, "teamId": run["team_id"],
                            "projectId": run["project_id"], "runId": run_id,
                            "createdAt": _time_text(observed), "recordDigest": "0" * 64,
                        },
                        "spec": {
                            "status": status,
                            "cancellationRequested": bool(run["cancellation_requested"]),
                            "tasks": tasks,
                            "usage": {
                                "tokens": sum(row["charged_tokens"] for row in rows),
                                "costMicrousd": sum(row["charged_cost"] for row in rows),
                            },
                        },
                    }
                )
                validate_record(result)
                changed = self._db.execute(
                    "UPDATE runs SET status=?,result_document=? WHERE run_id=? AND result_document IS NULL",
                    (status, canonical_json(result).encode("utf-8"), run_id),
                )
                if changed.rowcount != 1:
                    raise _error("ECO_TEAM_RESULT_RACE")
                self._write_state_auth_locked()
                self._db.execute("COMMIT")
                return result
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def verify(self) -> None:
        with self._lock:
            if self._db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise _error("ECO_TEAM_STORE_CORRUPT")
            self._check_private_file()
            self._verify_state_locked()
            for row in self._db.execute("SELECT document,digest FROM manifests").fetchall():
                record = self._document(row)
                if record["metadata"]["recordDigest"] != row["digest"]:
                    raise _error("ECO_TEAM_STORE_CORRUPT")
            for row in self._db.execute("SELECT document,digest FROM tasks").fetchall():
                record = self._document(row)
                if record["metadata"]["recordDigest"] != row["digest"]:
                    raise _error("ECO_TEAM_STORE_CORRUPT")
            for row in self._db.execute("SELECT document,digest FROM handoffs").fetchall():
                record = self._document(row)
                if record["metadata"]["recordDigest"] != row["digest"]:
                    raise _error("ECO_TEAM_STORE_CORRUPT")
