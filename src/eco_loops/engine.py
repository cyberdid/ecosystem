from __future__ import annotations

import copy
import json
import os
import sqlite3
import threading
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Protocol

from eco_runtime.digests import canonical_json, semantic_digest

from .contracts import (
    TERMINAL_STATES,
    AttemptResult,
    GateOutcome,
    LoopCheckpoint,
    LoopContractError,
    LoopDefinition,
    LoopUsage,
    transition_allowed,
)


class AttemptExecutor(Protocol):
    def __call__(self, checkpoint: LoopCheckpoint) -> AttemptResult: ...


class GateEvaluator(Protocol):
    def __call__(self, checkpoint: LoopCheckpoint, result: AttemptResult) -> GateOutcome: ...


class LoopEngineError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class InMemoryLoopJournal:
    """Content-free, process-local M6.3 checkpoint journal.

    This provides atomic replay and terminal compare-and-set semantics within one
    process. It deliberately makes no distributed durability claim.
    """

    def __init__(self) -> None:
        self._checkpoints: dict[str, LoopCheckpoint] = {}
        self._events: dict[str, list[dict[str, object]]] = {}
        self._cancelled: set[str] = set()
        self._kill_switch = False
        self._lock = threading.RLock()

    def create(self, run_id: str, definition: LoopDefinition) -> LoopCheckpoint:
        initial = LoopCheckpoint(
            run_id=run_id,
            definition_digest=definition.digest,
            state="new",
            sequence=0,
            usage=LoopUsage(),
        )
        with self._lock:
            existing = self._checkpoints.get(run_id)
            if existing is not None:
                if existing.definition_digest != definition.digest:
                    raise LoopEngineError("ECO_LOOP_DEFINITION_DRIFT", "run objective or gate changed")
                return copy.deepcopy(existing)
            self._checkpoints[run_id] = initial
            self._events[run_id] = []
            return copy.deepcopy(initial)

    def load(self, run_id: str) -> LoopCheckpoint:
        with self._lock:
            try:
                return copy.deepcopy(self._checkpoints[run_id])
            except KeyError as exc:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist") from exc

    def events(self, run_id: str) -> tuple[dict[str, object], ...]:
        with self._lock:
            if run_id not in self._events:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
            return tuple(copy.deepcopy(self._events[run_id]))

    def request_cancel(self, run_id: str) -> None:
        with self._lock:
            if run_id not in self._checkpoints:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
            self._cancelled.add(run_id)

    def set_kill_switch(self, enabled: bool = True) -> None:
        with self._lock:
            self._kill_switch = bool(enabled)

    def stop_reason(self, run_id: str) -> str | None:
        with self._lock:
            if self._kill_switch:
                return "ECO_LOOP_KILL_SWITCH"
            if run_id in self._cancelled:
                return "ECO_LOOP_CANCELLED"
            return None

    def transition(
        self,
        expected: LoopCheckpoint,
        target: str,
        *,
        usage: LoopUsage | None = None,
        progress_digest: str | None = None,
        stagnant_iterations: int | None = None,
        reason_code: str,
        evidence_digest: str | None = None,
    ) -> LoopCheckpoint:
        with self._lock:
            current = self._checkpoints.get(expected.run_id)
            if current is None:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
            if current != expected:
                if current.state in TERMINAL_STATES:
                    return copy.deepcopy(current)
                raise LoopEngineError("ECO_LOOP_CHECKPOINT_CONFLICT", "loop checkpoint changed concurrently")
            if not transition_allowed(current.state, target):
                raise LoopEngineError("ECO_LOOP_TRANSITION_DENIED", "loop state transition is closed")
            if target in TERMINAL_STATES and current.state in TERMINAL_STATES:
                return copy.deepcopy(current)

            if not isinstance(reason_code, str) or not reason_code.startswith("ECO_"):
                raise LoopEngineError("ECO_LOOP_EVENT_INVALID", "event reason code is unsafe")
            if evidence_digest is not None and (
                not isinstance(evidence_digest, str)
                or len(evidence_digest) != 64
                or any(character not in "0123456789abcdef" for character in evidence_digest)
            ):
                raise LoopEngineError("ECO_LOOP_EVENT_INVALID", "event evidence digest is invalid")
            candidate_usage = usage or current.usage
            before = current.usage.record()
            after = candidate_usage.record()
            if any(after[key] < before[key] for key in before):
                raise LoopEngineError("ECO_LOOP_USAGE_REVERSED", "loop usage cannot decrease")

            sequence = current.sequence + 1
            event = {
                "runId": current.run_id,
                "sequence": sequence,
                "from": current.state,
                "to": target,
                "definitionDigest": current.definition_digest,
                "reasonCode": reason_code,
                "evidenceDigest": evidence_digest,
                "previousEventDigest": current.head_digest,
                "usage": candidate_usage.record(),
                "progressDigest": (
                    progress_digest if progress_digest is not None else current.last_progress_digest
                ),
                "stagnantIterations": (
                    stagnant_iterations
                    if stagnant_iterations is not None
                    else current.stagnant_iterations
                ),
            }
            event_digest = semantic_digest(event)
            next_checkpoint = LoopCheckpoint(
                run_id=current.run_id,
                definition_digest=current.definition_digest,
                state=target,
                sequence=sequence,
                usage=candidate_usage,
                last_progress_digest=(
                    progress_digest if progress_digest is not None else current.last_progress_digest
                ),
                stagnant_iterations=(
                    stagnant_iterations
                    if stagnant_iterations is not None
                    else current.stagnant_iterations
                ),
                terminal_reason=reason_code if target in TERMINAL_STATES else None,
                head_digest=event_digest,
            )
            self._events[current.run_id].append(event)
            self._checkpoints[current.run_id] = next_checkpoint
            return copy.deepcopy(next_checkpoint)


class SQLiteLoopJournal:
    """Single-host durable content-free journal with atomic SQLite transitions.

    Hash-chain verification detects accidental drift but is not an authenticated
    trust anchor. Cross-host consensus and distributed execution are out of scope.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS loop_meta (
        key TEXT PRIMARY KEY,
        value INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS loop_runs (
        run_id TEXT PRIMARY KEY,
        definition_digest TEXT NOT NULL,
        state TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        attempts INTEGER NOT NULL,
        iterations INTEGER NOT NULL,
        tokens INTEGER NOT NULL,
        cost_microusd INTEGER NOT NULL,
        storage_bytes INTEGER NOT NULL,
        last_progress_digest TEXT,
        stagnant_iterations INTEGER NOT NULL,
        terminal_reason TEXT,
        head_digest TEXT,
        cancelled INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS loop_events (
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        PRIMARY KEY (run_id, sequence),
        FOREIGN KEY (run_id) REFERENCES loop_runs(run_id) ON DELETE CASCADE
    );
    """

    def __init__(self, database: str | os.PathLike[str]) -> None:
        self._database = os.fspath(database)
        parent = os.path.dirname(os.path.abspath(self._database))
        if not os.path.isdir(parent):
            raise LoopEngineError("ECO_LOOP_JOURNAL_UNAVAILABLE", "journal parent does not exist")
        connection = self._connect()
        try:
            connection.executescript(self._SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO loop_meta(key, value) VALUES ('kill_switch', 0)"
            )
            connection.commit()
        finally:
            connection.close()
        if os.name == "posix":
            os.chmod(self._database, 0o600)

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self._database, timeout=5.0, isolation_level=None)
        except sqlite3.Error as exc:
            raise LoopEngineError("ECO_LOOP_JOURNAL_UNAVAILABLE", "journal is unavailable") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _checkpoint(row: sqlite3.Row) -> LoopCheckpoint:
        return LoopCheckpoint(
            run_id=row["run_id"],
            definition_digest=row["definition_digest"],
            state=row["state"],
            sequence=row["sequence"],
            usage=LoopUsage(
                attempts=row["attempts"],
                iterations=row["iterations"],
                tokens=row["tokens"],
                cost_microusd=row["cost_microusd"],
                storage_bytes=row["storage_bytes"],
            ),
            last_progress_digest=row["last_progress_digest"],
            stagnant_iterations=row["stagnant_iterations"],
            terminal_reason=row["terminal_reason"],
            head_digest=row["head_digest"],
        )

    @staticmethod
    def _run_row(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM loop_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
        return row

    def _verify(self, connection: sqlite3.Connection, checkpoint: LoopCheckpoint) -> None:
        previous_digest: str | None = None
        previous_state = "new"
        rows = connection.execute(
            "SELECT sequence, event_json, event_digest FROM loop_events WHERE run_id = ? ORDER BY sequence",
            (checkpoint.run_id,),
        ).fetchall()
        if len(rows) != checkpoint.sequence:
            raise LoopEngineError("ECO_LOOP_JOURNAL_CORRUPT", "event count does not match checkpoint")
        last: dict[str, object] | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                event = json.loads(row["event_json"])
            except (json.JSONDecodeError, TypeError) as exc:
                raise LoopEngineError("ECO_LOOP_JOURNAL_CORRUPT", "event JSON is invalid") from exc
            if (
                not isinstance(event, dict)
                or not event_is_content_free(event)
                or row["sequence"] != expected_sequence
                or event["sequence"] != expected_sequence
                or event["runId"] != checkpoint.run_id
                or event["definitionDigest"] != checkpoint.definition_digest
                or event["previousEventDigest"] != previous_digest
                or event["from"] != previous_state
                or semantic_digest(event) != row["event_digest"]
            ):
                raise LoopEngineError("ECO_LOOP_JOURNAL_CORRUPT", "event chain verification failed")
            previous_digest = row["event_digest"]
            previous_state = event["to"]
            last = event
        if checkpoint.sequence == 0:
            if checkpoint.head_digest is not None or checkpoint.state != "new":
                raise LoopEngineError("ECO_LOOP_JOURNAL_CORRUPT", "empty checkpoint is inconsistent")
            return
        assert last is not None
        expected_usage = {
            "attempts": checkpoint.usage.attempts,
            "iterations": checkpoint.usage.iterations,
            "tokens": checkpoint.usage.tokens,
            "costMicrousd": checkpoint.usage.cost_microusd,
            "storageBytes": checkpoint.usage.storage_bytes,
        }
        if (
            checkpoint.head_digest != previous_digest
            or checkpoint.state != last["to"]
            or last["usage"] != expected_usage
            or last["progressDigest"] != checkpoint.last_progress_digest
            or last["stagnantIterations"] != checkpoint.stagnant_iterations
            or (checkpoint.terminal_reason if checkpoint.state in TERMINAL_STATES else None)
            != (last["reasonCode"] if checkpoint.state in TERMINAL_STATES else None)
        ):
            raise LoopEngineError("ECO_LOOP_JOURNAL_CORRUPT", "checkpoint does not match event head")

    def create(self, run_id: str, definition: LoopDefinition) -> LoopCheckpoint:
        initial = LoopCheckpoint(
            run_id=run_id,
            definition_digest=definition.digest,
            state="new",
            sequence=0,
            usage=LoopUsage(),
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM loop_runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO loop_runs(
                        run_id, definition_digest, state, sequence, attempts, iterations,
                        tokens, cost_microusd, storage_bytes, last_progress_digest,
                        stagnant_iterations, terminal_reason, head_digest, cancelled
                    ) VALUES (?, ?, 'new', 0, 0, 0, 0, 0, 0, NULL, 0, NULL, NULL, 0)""",
                    (run_id, definition.digest),
                )
                connection.commit()
                return initial
            existing = self._checkpoint(row)
            self._verify(connection, existing)
            if existing.definition_digest != definition.digest:
                raise LoopEngineError("ECO_LOOP_DEFINITION_DRIFT", "run objective or gate changed")
            connection.commit()
            return existing
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def load(self, run_id: str) -> LoopCheckpoint:
        connection = self._connect()
        try:
            checkpoint = self._checkpoint(self._run_row(connection, run_id))
            self._verify(connection, checkpoint)
            return checkpoint
        finally:
            connection.close()

    def events(self, run_id: str) -> tuple[dict[str, object], ...]:
        connection = self._connect()
        try:
            checkpoint = self._checkpoint(self._run_row(connection, run_id))
            self._verify(connection, checkpoint)
            rows = connection.execute(
                "SELECT event_json FROM loop_events WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
            return tuple(json.loads(row["event_json"]) for row in rows)
        finally:
            connection.close()

    def request_cancel(self, run_id: str) -> None:
        connection = self._connect()
        try:
            cursor = connection.execute(
                "UPDATE loop_runs SET cancelled = 1 WHERE run_id = ?", (run_id,)
            )
            if cursor.rowcount != 1:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
        finally:
            connection.close()

    def set_kill_switch(self, enabled: bool = True) -> None:
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE loop_meta SET value = ? WHERE key = 'kill_switch'",
                (1 if enabled else 0,),
            )
        finally:
            connection.close()

    def stop_reason(self, run_id: str) -> str | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT r.cancelled, m.value AS killed
                   FROM loop_runs r CROSS JOIN loop_meta m
                   WHERE r.run_id = ? AND m.key = 'kill_switch'""",
                (run_id,),
            ).fetchone()
            if row is None:
                raise LoopEngineError("ECO_LOOP_RUN_UNKNOWN", "loop run does not exist")
            if row["killed"]:
                return "ECO_LOOP_KILL_SWITCH"
            if row["cancelled"]:
                return "ECO_LOOP_CANCELLED"
            return None
        finally:
            connection.close()

    def transition(
        self,
        expected: LoopCheckpoint,
        target: str,
        *,
        usage: LoopUsage | None = None,
        progress_digest: str | None = None,
        stagnant_iterations: int | None = None,
        reason_code: str,
        evidence_digest: str | None = None,
    ) -> LoopCheckpoint:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = self._checkpoint(self._run_row(connection, expected.run_id))
            self._verify(connection, current)
            if current != expected:
                if current.state in TERMINAL_STATES:
                    connection.commit()
                    return current
                raise LoopEngineError("ECO_LOOP_CHECKPOINT_CONFLICT", "loop checkpoint changed concurrently")
            if not transition_allowed(current.state, target):
                raise LoopEngineError("ECO_LOOP_TRANSITION_DENIED", "loop state transition is closed")
            if not isinstance(reason_code, str) or not reason_code.startswith("ECO_"):
                raise LoopEngineError("ECO_LOOP_EVENT_INVALID", "event reason code is unsafe")
            if evidence_digest is not None and (
                not isinstance(evidence_digest, str)
                or len(evidence_digest) != 64
                or any(character not in "0123456789abcdef" for character in evidence_digest)
            ):
                raise LoopEngineError("ECO_LOOP_EVENT_INVALID", "event evidence digest is invalid")
            candidate_usage = usage or current.usage
            before = current.usage.record()
            after = candidate_usage.record()
            if any(after[key] < before[key] for key in before):
                raise LoopEngineError("ECO_LOOP_USAGE_REVERSED", "loop usage cannot decrease")
            next_progress = progress_digest if progress_digest is not None else current.last_progress_digest
            next_stagnant = (
                stagnant_iterations if stagnant_iterations is not None else current.stagnant_iterations
            )
            sequence = current.sequence + 1
            event: dict[str, object] = {
                "runId": current.run_id,
                "sequence": sequence,
                "from": current.state,
                "to": target,
                "definitionDigest": current.definition_digest,
                "reasonCode": reason_code,
                "evidenceDigest": evidence_digest,
                "previousEventDigest": current.head_digest,
                "usage": candidate_usage.record(),
                "progressDigest": next_progress,
                "stagnantIterations": next_stagnant,
            }
            event_digest = semantic_digest(event)
            terminal_reason = reason_code if target in TERMINAL_STATES else None
            connection.execute(
                "INSERT INTO loop_events(run_id, sequence, event_json, event_digest) VALUES (?, ?, ?, ?)",
                (current.run_id, sequence, canonical_json(event), event_digest),
            )
            connection.execute(
                """UPDATE loop_runs SET state = ?, sequence = ?, attempts = ?, iterations = ?,
                   tokens = ?, cost_microusd = ?, storage_bytes = ?, last_progress_digest = ?,
                   stagnant_iterations = ?, terminal_reason = ?, head_digest = ? WHERE run_id = ?""",
                (
                    target,
                    sequence,
                    candidate_usage.attempts,
                    candidate_usage.iterations,
                    candidate_usage.tokens,
                    candidate_usage.cost_microusd,
                    candidate_usage.storage_bytes,
                    next_progress,
                    next_stagnant,
                    terminal_reason,
                    event_digest,
                    current.run_id,
                ),
            )
            connection.commit()
            return self.load(current.run_id)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class BoundedLoopEngine:
    def __init__(
        self,
        definition: LoopDefinition,
        journal: InMemoryLoopJournal,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.definition = definition
        self.journal = journal
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise LoopEngineError("ECO_LOOP_CLOCK_INVALID", "loop clock must be timezone-aware")
        return value.astimezone(timezone.utc)

    def _terminal(self, checkpoint: LoopCheckpoint, state: str, reason: str) -> LoopCheckpoint:
        return self.journal.transition(checkpoint, state, reason_code=reason)

    def _stop_or_budget(self, checkpoint: LoopCheckpoint) -> LoopCheckpoint | None:
        stop = self.journal.stop_reason(checkpoint.run_id)
        if stop is not None:
            return self._terminal(checkpoint, "cancelled", stop)
        budget = self.definition.budget
        usage = checkpoint.usage
        if self._now() >= budget.deadline:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_DEADLINE_EXHAUSTED")
        if usage.attempts >= budget.max_attempts:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_ATTEMPTS_EXHAUSTED")
        if usage.iterations >= budget.max_iterations:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_ITERATIONS_EXHAUSTED")
        if usage.tokens + budget.reserve_tokens_per_attempt > budget.max_tokens:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_TOKENS_EXHAUSTED")
        if usage.cost_microusd + budget.reserve_cost_microusd_per_attempt > budget.max_cost_microusd:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_COST_EXHAUSTED")
        if usage.storage_bytes + budget.reserve_storage_bytes_per_attempt > budget.max_storage_bytes:
            return self._terminal(checkpoint, "exhausted", "ECO_LOOP_STORAGE_EXHAUSTED")
        return None

    def start(self, run_id: str) -> LoopCheckpoint:
        checkpoint = self.journal.create(run_id, self.definition)
        if checkpoint.state == "new":
            stop = self.journal.stop_reason(run_id)
            if stop is not None:
                return self._terminal(checkpoint, "cancelled", stop)
            checkpoint = self.journal.transition(
                checkpoint, "ready", reason_code="ECO_LOOP_READY"
            )
        return checkpoint

    def recover(self, run_id: str) -> LoopCheckpoint:
        """Recover a known checkpoint without repeating an ambiguous attempt."""

        checkpoint = self.journal.load(run_id)
        if checkpoint.definition_digest != self.definition.digest:
            raise LoopEngineError("ECO_LOOP_DEFINITION_DRIFT", "run objective or gate changed")
        if checkpoint.state == "new":
            return self.start(run_id)
        if checkpoint.state in {"ready", "retry-wait", *TERMINAL_STATES}:
            return checkpoint
        return self._terminal(checkpoint, "failed", "ECO_LOOP_RECOVERY_AMBIGUOUS")

    def run(
        self,
        run_id: str,
        executor: AttemptExecutor,
        gate: GateEvaluator,
    ) -> LoopCheckpoint:
        if not self.definition.executable:
            raise LoopEngineError("ECO_LOOP_PROFILE_NOT_EXECUTABLE", "loop profile is an outline only")
        if not self.definition.deterministic or self.definition.side_effect_mode not in {
            "no-effect",
            "report-only",
        }:
            raise LoopEngineError("ECO_LOOP_PROFILE_DENIED", "M6.3 runs deterministic no-effect profiles only")
        if executor is gate:
            raise LoopEngineError("ECO_LOOP_GATE_NOT_INDEPENDENT", "actor and gate must be separate callables")

        checkpoint = self.start(run_id)
        while checkpoint.state not in TERMINAL_STATES:
            if checkpoint.state not in {"ready", "retry-wait"}:
                raise LoopEngineError("ECO_LOOP_RECOVERY_AMBIGUOUS", "checkpoint cannot be automatically resumed")
            terminal = self._stop_or_budget(checkpoint)
            if terminal is not None:
                return terminal

            reserved = LoopUsage(
                attempts=checkpoint.usage.attempts + 1,
                iterations=checkpoint.usage.iterations,
                tokens=checkpoint.usage.tokens + self.definition.budget.reserve_tokens_per_attempt,
                cost_microusd=(
                    checkpoint.usage.cost_microusd
                    + self.definition.budget.reserve_cost_microusd_per_attempt
                ),
                storage_bytes=(
                    checkpoint.usage.storage_bytes
                    + self.definition.budget.reserve_storage_bytes_per_attempt
                ),
            )
            checkpoint = self.journal.transition(
                checkpoint,
                "running",
                usage=reserved,
                reason_code="ECO_LOOP_ATTEMPT_RESERVED",
            )
            try:
                attempt = executor(checkpoint)
            except LoopContractError:
                return self._terminal(checkpoint, "failed", "ECO_LOOP_OUTCOME_INVALID")
            except Exception:
                return self._terminal(checkpoint, "failed", "ECO_LOOP_EXECUTOR_FAILED")
            if not isinstance(attempt, AttemptResult):
                return self._terminal(checkpoint, "failed", "ECO_LOOP_OUTCOME_INVALID")

            stop = self.journal.stop_reason(run_id)
            if stop is not None:
                return self._terminal(checkpoint, "cancelled", stop)
            if self._now() >= self.definition.budget.deadline:
                return self._terminal(checkpoint, "exhausted", "ECO_LOOP_DEADLINE_EXHAUSTED")

            if attempt.outcome == "retryable-error":
                if attempt.reason_code not in self.definition.retry.allowed_reason_codes:
                    return self._terminal(checkpoint, "failed", "ECO_LOOP_RETRY_DENIED")
                checkpoint = self.journal.transition(
                    checkpoint,
                    "retry-wait",
                    reason_code=attempt.reason_code,
                    evidence_digest=attempt.evidence_digest,
                )
                continue
            if attempt.outcome == "fatal-error":
                return self._terminal(checkpoint, "failed", attempt.reason_code)

            gated_usage = replace(checkpoint.usage, iterations=checkpoint.usage.iterations + 1)
            checkpoint = self.journal.transition(
                checkpoint,
                "gating",
                usage=gated_usage,
                reason_code="ECO_LOOP_GATE_STARTED",
                evidence_digest=attempt.evidence_digest,
            )
            try:
                gate_outcome = gate(checkpoint, attempt)
            except LoopContractError:
                return self._terminal(checkpoint, "failed", "ECO_LOOP_GATE_INVALID")
            except Exception:
                return self._terminal(checkpoint, "failed", "ECO_LOOP_GATE_FAILED")
            if not isinstance(gate_outcome, GateOutcome):
                return self._terminal(checkpoint, "failed", "ECO_LOOP_GATE_INVALID")
            stop = self.journal.stop_reason(run_id)
            if stop is not None:
                return self._terminal(checkpoint, "cancelled", stop)
            if self._now() >= self.definition.budget.deadline:
                return self._terminal(checkpoint, "exhausted", "ECO_LOOP_DEADLINE_EXHAUSTED")
            stagnant = (
                checkpoint.stagnant_iterations + 1
                if checkpoint.last_progress_digest == gate_outcome.progress_digest
                else 0
            )
            # A gate decision is recorded as the next state transition. The
            # actor cannot write progress or acceptance into the checkpoint.
            if gate_outcome.outcome == "pass":
                return self.journal.transition(
                    checkpoint,
                    "succeeded",
                    progress_digest=gate_outcome.progress_digest,
                    stagnant_iterations=stagnant,
                    reason_code=gate_outcome.reason_code,
                    evidence_digest=gate_outcome.evidence_digest,
                )
            if gate_outcome.reason_code not in self.definition.retry.allowed_reason_codes:
                return self.journal.transition(
                    checkpoint,
                    "failed",
                    progress_digest=gate_outcome.progress_digest,
                    stagnant_iterations=stagnant,
                    reason_code="ECO_LOOP_RETRY_DENIED",
                    evidence_digest=gate_outcome.evidence_digest,
                )
            if stagnant >= self.definition.retry.max_stagnant_iterations:
                return self.journal.transition(
                    checkpoint,
                    "exhausted",
                    progress_digest=gate_outcome.progress_digest,
                    stagnant_iterations=stagnant,
                    reason_code="ECO_LOOP_NO_PROGRESS",
                    evidence_digest=gate_outcome.evidence_digest,
                )
            checkpoint = self.journal.transition(
                checkpoint,
                "retry-wait",
                progress_digest=gate_outcome.progress_digest,
                stagnant_iterations=stagnant,
                reason_code=gate_outcome.reason_code,
                evidence_digest=gate_outcome.evidence_digest,
            )
        return checkpoint


def event_is_content_free(event: dict[str, object]) -> bool:
    return set(event) == {
        "runId",
        "sequence",
        "from",
        "to",
        "definitionDigest",
        "reasonCode",
        "evidenceDigest",
        "previousEventDigest",
        "usage",
        "progressDigest",
        "stagnantIterations",
    }
