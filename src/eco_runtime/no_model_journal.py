from __future__ import annotations

import json
import hmac
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import API_VERSION
from .digests import canonical_json, semantic_digest
from .errors import RuntimeStateError, RuntimeStoreError
from .state import RunEventChain
from .state_reducer import RunState


_OUTCOMES = {
    "run.received": "pending",
    "run.validated": "success",
    "plan.created": "success",
    "no-model.policy.allowed": "success",
    "no-model.workflow.started": "pending",
    "no-model.read.requested": "pending",
    "no-model.read.allowed": "success",
    "no-model.read.started": "pending",
    "no-model.read.denied": "denied",
    "no-model.read.completed": "success",
    "no-model.read.failed": "failed",
    "no-model.workflow.succeeded": "success",
    "run.failed": "failed",
}
_APPLICATION_ID = 0x45434F34
_SCHEMA_VERSION = 1


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class NoModelJournal:
    """Small, path- and content-free durable event journal for the M4 profile.

    The SQLite file is an audit/replay boundary, never a source of authority:
    every process reconstructs policy authority from fresh signed evidence before
    it can append an execution event.  It stores canonical RunEvents containing
    only opaque ids/digests, reason codes and byte counts.
    """

    def __init__(self, database: Path, *, integrity_key: bytes) -> None:
        self._database = database
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise RuntimeStoreError("ECO_NO_MODEL_STATE_KEY_UNAVAILABLE", "No-model state key is unavailable")
        self._integrity_key = integrity_key
        try:
            existed = database.exists()
            for candidate in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                if not candidate.exists() and not candidate.is_symlink():
                    continue
                status = candidate.lstat()
                if (
                    stat.S_ISLNK(status.st_mode)
                    or not stat.S_ISREG(status.st_mode)
                    or status.st_nlink != 1
                    or (os.name == "posix" and status.st_mode & 0o077)
                    or (
                        os.name == "posix"
                        and hasattr(os, "geteuid")
                        and status.st_uid != os.geteuid()
                    )
                ):
                    raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
            if existed:
                self._lock_descriptor = os.open(
                    database,
                    os.O_RDWR
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
            else:
                self._lock_descriptor = os.open(
                    database,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_RDWR
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
            locked = os.fstat(self._lock_descriptor)
            locked_path = database.lstat()
            if (
                not stat.S_ISREG(locked.st_mode)
                or locked.st_nlink != 1
                or (locked.st_dev, locked.st_ino) != (locked_path.st_dev, locked_path.st_ino)
            ):
                raise RuntimeStoreError(
                    "ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid"
                )
            if os.name == "posix":
                import fcntl

                try:
                    fcntl.flock(
                        self._lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
                except BlockingIOError as exc:
                    raise RuntimeStoreError(
                        "ECO_NO_MODEL_STATE_BUSY", "No-model state is already in use"
                    ) from exc
            self._connection = sqlite3.connect(database, isolation_level=None)
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            if existed:
                if (
                    self._connection.execute("PRAGMA application_id").fetchone()[0]
                    != _APPLICATION_ID
                    or self._connection.execute("PRAGMA user_version").fetchone()[0]
                    != _SCHEMA_VERSION
                ):
                    raise RuntimeStoreError(
                        "ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid"
                    )
            else:
                self._connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                self._connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS no_model_events ("
                "run_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_json TEXT NOT NULL, "
                "event_digest TEXT NOT NULL, event_mac TEXT NOT NULL, PRIMARY KEY (run_id, sequence))"
            )
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS no_model_runs ("
                "run_id TEXT PRIMARY KEY, plan_digest TEXT NOT NULL, plan_mac TEXT NOT NULL, "
                "head_digest TEXT, head_mac TEXT NOT NULL)"
            )
            expected_columns = {
                "no_model_events": (
                    "run_id", "sequence", "event_json", "event_digest", "event_mac"
                ),
                "no_model_runs": (
                    "run_id", "plan_digest", "plan_mac", "head_digest", "head_mac"
                ),
            }
            objects = self._connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            if set(objects) != {("table", name) for name in expected_columns}:
                raise RuntimeStoreError(
                    "ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid"
                )
            for table, columns in expected_columns.items():
                actual = tuple(
                    row[1] for row in self._connection.execute(f"PRAGMA table_info({table})")
                )
                if actual != columns:
                    raise RuntimeStoreError(
                        "ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid"
                    )
            opened = database.lstat()
            if (
                stat.S_ISLNK(opened.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (os.name == "posix" and opened.st_mode & 0o077)
                or (
                    os.name == "posix"
                    and hasattr(os, "geteuid")
                    and opened.st_uid != os.geteuid()
                )
            ):
                raise RuntimeStoreError(
                    "ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid"
                )
        except RuntimeStoreError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            lock_descriptor = getattr(self, "_lock_descriptor", None)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            raise
        except (sqlite3.Error, OSError) as exc:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            lock_descriptor = getattr(self, "_lock_descriptor", None)
            if lock_descriptor is not None:
                os.close(lock_descriptor)
            raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable") from exc
        self._tokens = {name: object() for name in ("runtime", "policy", "broker", "adapter")}
        self._producers = {
            "runtime": ("no-model-runtime", self._tokens["runtime"]),
            "policy": ("no-model-policy", self._tokens["policy"]),
            "broker": ("no-model-broker", self._tokens["broker"]),
            "adapter": ("no-model-adapter-disabled", self._tokens["adapter"]),
        }

    def close(self) -> None:
        self._connection.close()
        os.close(self._lock_descriptor)
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self._database}{suffix}")
            if candidate.exists() and os.name == "posix":
                os.chmod(candidate, 0o600)

    def __enter__(self) -> NoModelJournal:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _chain(self, run_id: str) -> RunEventChain:
        chain = RunEventChain(run_id, self._producers)
        rows = self._connection.execute(
            "SELECT event_json, event_digest, event_mac FROM no_model_events WHERE run_id = ? ORDER BY sequence", (run_id,)
        ).fetchall()
        for encoded, digest, event_mac in rows:
            try:
                event = json.loads(encoded)
            except (TypeError, ValueError) as exc:
                raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid") from exc
            if semantic_digest(event) != digest or not hmac.compare_digest(
                event_mac, self._mac("event", {"runId": run_id, "event": event})
            ):
                raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid")
            producer = event.get("metadata", {}).get("producer")
            if producer not in self._tokens:
                raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid")
            try:
                chain.append(event, self._tokens[producer])
            except RuntimeStateError as exc:
                raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid") from exc
        head = self._connection.execute(
            "SELECT head_digest, head_mac FROM no_model_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if head is None or not hmac.compare_digest(
            head[1], self._mac("head", {"runId": run_id, "headDigest": head[0]})
        ) or head[0] != chain.head_digest:
            raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid")
        return chain

    def begin(self, plan: dict[str, Any], *, now: datetime) -> tuple[RunEventChain, bool]:
        run_id = plan["metadata"]["runId"]
        plan_digest = semantic_digest(plan)
        existing = self._connection.execute(
            "SELECT plan_digest, plan_mac FROM no_model_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if existing is not None:
            if existing[0] != plan_digest:
                raise RuntimeStoreError("ECO_NO_MODEL_REPLAY_CONFLICT", "No-model run conflicts with prior state")
            if not hmac.compare_digest(
                existing[1], self._mac("plan", {"runId": run_id, "planDigest": plan_digest})
            ):
                raise RuntimeStoreError("ECO_NO_MODEL_STATE_INVALID", "No-model state is invalid")
            return self._chain(run_id), True
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "INSERT INTO no_model_runs(run_id, plan_digest, plan_mac, head_digest, head_mac) VALUES (?, ?, ?, ?, ?)",
                (
                    run_id, plan_digest, self._mac("plan", {"runId": run_id, "planDigest": plan_digest}),
                    None, self._mac("head", {"runId": run_id, "headDigest": None}),
                ),
            )
            chain = RunEventChain(run_id, self._producers)
            scope_entries = plan["spec"]["workflow"]["scopeSlots"]
            for event_type, producer, bindings in (
                ("run.received", "runtime", {}),
                ("run.validated", "runtime", {}),
                ("plan.created", "runtime", {}),
                (
                    "no-model.policy.allowed",
                    "policy",
                    {
                        "subject_id": plan["metadata"]["id"],
                        "subject_digest": plan_digest,
                    },
                ),
                (
                    "no-model.workflow.started",
                    "runtime",
                    {"subject_digest": plan_digest, "scope_entries": scope_entries},
                ),
            ):
                self._append(chain, event_type, producer, now=now, **bindings)
            self._connection.execute("COMMIT")
            return chain, False
        except (sqlite3.Error, RuntimeStateError) as exc:
            self._connection.execute("ROLLBACK")
            raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable") from exc

    def append(
        self,
        chain: RunEventChain,
        event_type: str,
        producer: str,
        *,
        now: datetime,
        subject_id: str | None = None,
        subject_digest: str | None = None,
        result_digest: str | None = None,
        reason_code: str | None = None,
        byte_count: int | None = None,
        scope_slot: str | None = None,
        entry_digest: str | None = None,
        scope_entries: list[dict[str, str]] | None = None,
        content_digest: str | None = None,
        heading_check: str | None = None,
    ) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._append(
                chain, event_type, producer, now=now, subject_id=subject_id,
                subject_digest=subject_digest, result_digest=result_digest,
                reason_code=reason_code, byte_count=byte_count,
                scope_slot=scope_slot, entry_digest=entry_digest,
                scope_entries=scope_entries,
                content_digest=content_digest, heading_check=heading_check,
            )
            self._connection.execute("COMMIT")
        except (sqlite3.Error, RuntimeStateError) as exc:
            self._connection.execute("ROLLBACK")
            raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable") from exc

    def _append(
        self,
        chain: RunEventChain,
        event_type: str,
        producer: str,
        *,
        now: datetime,
        subject_id: str | None = None,
        subject_digest: str | None = None,
        result_digest: str | None = None,
        reason_code: str | None = None,
        byte_count: int | None = None,
        scope_slot: str | None = None,
        entry_digest: str | None = None,
        scope_entries: list[dict[str, str]] | None = None,
        content_digest: str | None = None,
        heading_check: str | None = None,
    ) -> None:
        sequence = len(chain.events()) + 1
        spec: dict[str, Any] = {"type": event_type, "outcome": _OUTCOMES[event_type]}
        if subject_id is not None:
            spec["subjectId"] = subject_id
        if subject_digest is not None:
            spec["subjectDigest"] = subject_digest
        if result_digest is not None:
            spec["resultDigest"] = result_digest
        if reason_code is not None:
            spec["reasonCode"] = reason_code
        if byte_count is not None:
            spec["metrics"] = {"byteCount": byte_count}
        if scope_slot is not None:
            spec["scopeSlot"] = scope_slot
        if entry_digest is not None:
            spec["entryDigest"] = entry_digest
        if scope_entries is not None:
            spec["scopeEntries"] = scope_entries
        if content_digest is not None:
            spec["contentDigest"] = content_digest
        if heading_check is not None:
            spec["headingCheck"] = heading_check
        event = {
            "apiVersion": API_VERSION,
            "kind": "RunEvent",
            "metadata": {
                "id": f"nme-{semantic_digest({'run': chain.run_id, 'sequence': sequence})[:40]}",
                "runId": chain.run_id,
                "sequence": sequence,
                "occurredAt": _timestamp(now),
                "producer": producer,
                "producerIssuer": self._producers[producer][0],
                "previousEventDigest": chain.head_digest,
            },
            "spec": spec,
        }
        chain.append(event, self._tokens[producer])
        self._connection.execute(
            "INSERT INTO no_model_events(run_id, sequence, event_json, event_digest, event_mac) VALUES (?, ?, ?, ?, ?)",
            (
                chain.run_id, sequence, json.dumps(event, sort_keys=True, separators=(",", ":")),
                semantic_digest(event), self._mac("event", {"runId": chain.run_id, "event": event}),
            ),
        )
        self._connection.execute(
            "UPDATE no_model_runs SET head_digest = ?, head_mac = ? WHERE run_id = ?",
            (
                chain.head_digest,
                self._mac("head", {"runId": chain.run_id, "headDigest": chain.head_digest}),
                chain.run_id,
            ),
        )

    def _mac(self, domain: str, value: dict[str, Any]) -> str:
        return hmac.new(
            self._integrity_key,
            f"eco-no-model-journal-v1:{domain}:".encode("ascii") + canonical_json(value).encode("utf-8"),
            "sha256",
        ).hexdigest()

    @staticmethod
    def read_phase(chain: RunEventChain, request_id: str) -> str | None:
        phase: str | None = None
        mapping = {
            "no-model.read.requested": "requested",
            "no-model.read.allowed": "allowed",
            "no-model.read.started": "started",
            "no-model.read.denied": "denied",
            "no-model.read.completed": "completed",
            "no-model.read.failed": "failed",
        }
        for event in chain.events():
            if event["spec"].get("subjectId") == request_id:
                phase = mapping.get(event["spec"]["type"], phase)
        return phase

    @staticmethod
    def completed_summary(chain: RunEventChain) -> tuple[int, int]:
        completed = 0
        total_bytes = 0
        for event in chain.events():
            if event["spec"]["type"] == "no-model.read.completed":
                completed += 1
                total_bytes += event["spec"].get("metrics", {}).get("byteCount", 0)
        return completed, total_bytes

    @staticmethod
    def completed_observations(chain: RunEventChain) -> tuple[tuple[str, str], ...]:
        observations: list[tuple[str, str]] = []
        for event in chain.events():
            if event["spec"]["type"] == "no-model.read.completed":
                observations.append(
                    (event["spec"]["contentDigest"], event["spec"]["headingCheck"])
                )
        return tuple(observations)

    @staticmethod
    def state(chain: RunEventChain) -> RunState:
        return chain.state
