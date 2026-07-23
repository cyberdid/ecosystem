from __future__ import annotations

import dataclasses
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest import mock

from eco_loops import (
    LOOP_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    AttemptResult,
    BoundedLoopEngine,
    InMemoryLoopJournal,
    GateOutcome,
    LoopBudget,
    LoopContractError,
    LoopDefinition,
    LoopEngineError,
    LoopUsage,
    RetryPolicy,
    SQLiteLoopJournal,
    transition_allowed,
)
from eco_loops.compatibility import wiki_health_executor
from eco_loops.engine import event_is_content_free
from eco_loops.profiles import source_review_outline, validate_profile, wiki_health_compatibility
from eco_cli.cli import main
from eco_runtime.digests import semantic_digest


UTC = timezone.utc
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


class Clock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def definition(
    *,
    clock: Clock,
    max_attempts: int = 3,
    max_iterations: int = 3,
    max_tokens: int = 0,
    max_cost: int = 0,
    max_storage: int = 0,
    reserve_tokens: int = 0,
    reserve_cost: int = 0,
    reserve_storage: int = 0,
    retry_codes: frozenset[str] = frozenset({"ECO_TRANSIENT", "ECO_GATE_FAILED"}),
    stagnant: int = 2,
) -> LoopDefinition:
    return LoopDefinition(
        loop_id="test-loop",
        version="1",
        objective_digest=DIGEST_A,
        gate_digest=DIGEST_B,
        profile="test-loop/v1",
        side_effect_mode="no-effect",
        deterministic=True,
        executable=True,
        budget=LoopBudget(
            max_attempts=max_attempts,
            max_iterations=max_iterations,
            deadline=clock.value + timedelta(seconds=30),
            max_tokens=max_tokens,
            max_cost_microusd=max_cost,
            max_storage_bytes=max_storage,
            reserve_tokens_per_attempt=reserve_tokens,
            reserve_cost_microusd_per_attempt=reserve_cost,
            reserve_storage_bytes_per_attempt=reserve_storage,
        ),
        retry=RetryPolicy(retry_codes, stagnant),
    )


def attempt(
    kind: str = "candidate", *, code: str = "ECO_LOOP_CANDIDATE_READY", candidate: str = DIGEST_A
) -> AttemptResult:
    return AttemptResult(
        outcome=kind,
        reason_code=code,
        candidate_digest=candidate,
        evidence_digest=DIGEST_C,
    )


def gate_result(kind: str, *, code: str, progress: str = DIGEST_A) -> GateOutcome:
    return GateOutcome(kind, code, progress, DIGEST_C)


def pass_gate(_, __) -> GateOutcome:
    return gate_result("pass", code="ECO_GATE_PASSED")


def fail_gate(_, __) -> GateOutcome:
    return gate_result("fail", code="ECO_GATE_FAILED")


class ContractTests(unittest.TestCase):
    def test_transition_matrix_is_closed_and_terminals_have_no_exits(self) -> None:
        self.assertEqual(set(TRANSITIONS), set(LOOP_STATES))
        for current in LOOP_STATES:
            for target in LOOP_STATES:
                self.assertEqual(transition_allowed(current, target), target in TRANSITIONS[current])
        for terminal in TERMINAL_STATES:
            self.assertEqual(TRANSITIONS[terminal], frozenset())

    def test_definition_is_frozen_and_digest_binds_objective_gate_and_budget(self) -> None:
        clock = Clock(datetime(2026, 7, 17, tzinfo=UTC))
        item = definition(clock=clock)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            item.gate_digest = DIGEST_C  # type: ignore[misc]
        changed = dataclasses.replace(item, gate_digest=DIGEST_C)
        self.assertNotEqual(item.digest, changed.digest)

    def test_contract_rejects_bad_budget_digest_retry_and_effect_mode(self) -> None:
        now = datetime(2026, 7, 17, tzinfo=UTC)
        with self.assertRaises(LoopContractError):
            LoopBudget(0, 1, now, 0, 0, 0)
        with self.assertRaises(LoopContractError):
            RetryPolicy(frozenset({"provider said retry"}), 1)
        valid = definition(clock=Clock(now))
        with self.assertRaises(LoopContractError):
            dataclasses.replace(valid, objective_digest="bad")
        with self.assertRaises(LoopContractError):
            dataclasses.replace(valid, side_effect_mode="apply")
        with self.assertRaises(LoopContractError):
            LoopUsage(tokens=-1)


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock(datetime(2026, 7, 17, 10, 0, tzinfo=UTC))

    def test_success_has_one_terminal_and_content_free_hash_chain(self) -> None:
        journal = InMemoryLoopJournal()
        engine = BoundedLoopEngine(definition(clock=self.clock), journal, clock=self.clock)
        result = engine.run("run-success", lambda _: attempt(), pass_gate)

        self.assertEqual(result.state, "succeeded")
        self.assertEqual(result.usage, LoopUsage(attempts=1, iterations=1))
        events = journal.events("run-success")
        self.assertEqual(sum(event["to"] in TERMINAL_STATES for event in events), 1)
        self.assertTrue(all(event_is_content_free(event) for event in events))
        self.assertNotIn("content", repr(events).lower())
        for previous, current in zip(events, events[1:]):
            self.assertEqual(current["previousEventDigest"], semantic_digest(previous))

    def test_attempt_and_iteration_boundaries_are_exact(self) -> None:
        for budget_name, options, expected in (
            ("attempt", {"max_attempts": 1, "max_iterations": 3}, "ECO_LOOP_ATTEMPTS_EXHAUSTED"),
            ("iteration", {"max_attempts": 3, "max_iterations": 1}, "ECO_LOOP_ITERATIONS_EXHAUSTED"),
        ):
            with self.subTest(budget=budget_name):
                journal = InMemoryLoopJournal()
                engine = BoundedLoopEngine(
                    definition(clock=self.clock, **options), journal, clock=self.clock
                )
                result = engine.run(f"run-{budget_name}", lambda _: attempt(), fail_gate)
                self.assertEqual(result.state, "exhausted")
                self.assertEqual(result.terminal_reason, expected)
                self.assertEqual(result.usage.attempts, 1)
                self.assertEqual(result.usage.iterations, 1)

    def test_token_cost_and_storage_reservations_never_cross_budget(self) -> None:
        cases = (
            (
                "token",
                {"max_tokens": 2, "reserve_tokens": 2},
                "ECO_LOOP_TOKENS_EXHAUSTED",
                "tokens",
                2,
            ),
            (
                "cost",
                {"max_cost": 5, "reserve_cost": 5},
                "ECO_LOOP_COST_EXHAUSTED",
                "cost_microusd",
                5,
            ),
            (
                "storage",
                {"max_storage": 7, "reserve_storage": 7},
                "ECO_LOOP_STORAGE_EXHAUSTED",
                "storage_bytes",
                7,
            ),
        )
        for name, options, reason, field, value in cases:
            with self.subTest(budget=name):
                journal = InMemoryLoopJournal()
                engine = BoundedLoopEngine(
                    definition(clock=self.clock, max_attempts=2, max_iterations=2, **options),
                    journal,
                    clock=self.clock,
                )
                result = engine.run(
                    f"run-{name}",
                    lambda _: attempt(candidate=DIGEST_B),
                    lambda _, __: gate_result("fail", code="ECO_GATE_FAILED", progress=DIGEST_B),
                )
                self.assertEqual(result.terminal_reason, reason)
                self.assertEqual(getattr(result.usage, field), value)

    def test_retry_is_allowlisted_and_spends_an_attempt(self) -> None:
        calls = 0

        def execute(_):
            nonlocal calls
            calls += 1
            return (
                attempt("retryable-error", code="ECO_TRANSIENT")
                if calls == 1
                else attempt()
            )

        engine = BoundedLoopEngine(
            definition(clock=self.clock), InMemoryLoopJournal(), clock=self.clock
        )
        result = engine.run("run-retry", execute, pass_gate)
        self.assertEqual(result.state, "succeeded")
        self.assertEqual(result.usage, LoopUsage(attempts=2, iterations=1))

    def test_retryable_error_outside_allowlist_fails_closed(self) -> None:
        engine = BoundedLoopEngine(
            definition(clock=self.clock), InMemoryLoopJournal(), clock=self.clock
        )
        result = engine.run(
            "run-retry-denied",
            lambda _: attempt("retryable-error", code="ECO_NOT_ALLOWED"),
            pass_gate,
        )
        self.assertEqual(result.state, "failed")
        self.assertEqual(result.terminal_reason, "ECO_LOOP_RETRY_DENIED")

    def test_gate_failure_outside_retry_allowlist_fails_closed(self) -> None:
        engine = BoundedLoopEngine(
            definition(clock=self.clock, retry_codes=frozenset()),
            InMemoryLoopJournal(),
            clock=self.clock,
        )
        result = engine.run("run-gate-retry-denied", lambda _: attempt(), fail_gate)
        self.assertEqual(result.state, "failed")
        self.assertEqual(result.terminal_reason, "ECO_LOOP_RETRY_DENIED")

    def test_actor_cannot_be_its_own_gate(self) -> None:
        def same(*_):
            return attempt()

        engine = BoundedLoopEngine(
            definition(clock=self.clock), InMemoryLoopJournal(), clock=self.clock
        )
        with self.assertRaises(LoopEngineError) as caught:
            engine.run("run-self-gate", same, same)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "ECO_LOOP_GATE_NOT_INDEPENDENT")

    def test_repeated_progress_digest_hits_deterministic_no_progress_stop(self) -> None:
        engine = BoundedLoopEngine(
            definition(clock=self.clock, max_attempts=5, max_iterations=5, stagnant=2),
            InMemoryLoopJournal(),
            clock=self.clock,
        )
        result = engine.run("run-stagnant", lambda _: attempt(), fail_gate)
        self.assertEqual(result.state, "exhausted")
        self.assertEqual(result.terminal_reason, "ECO_LOOP_NO_PROGRESS")
        self.assertEqual(result.usage.iterations, 3)

    def test_deadline_is_checked_before_and_after_executor(self) -> None:
        item = definition(clock=self.clock)
        before_journal = InMemoryLoopJournal()
        before_engine = BoundedLoopEngine(item, before_journal, clock=self.clock)
        self.clock.value = item.budget.deadline
        result = before_engine.run(
            "run-deadline-before", lambda _: self.fail("must not execute"), pass_gate
        )
        self.assertEqual(result.terminal_reason, "ECO_LOOP_DEADLINE_EXHAUSTED")
        self.assertEqual(result.usage.attempts, 0)

        self.clock.value = datetime(2026, 7, 17, 10, 0, tzinfo=UTC)
        item = definition(clock=self.clock)

        def cross_deadline(_):
            self.clock.value = item.budget.deadline
            return attempt()

        result = BoundedLoopEngine(item, InMemoryLoopJournal(), clock=self.clock).run(
            "run-deadline-after", cross_deadline, pass_gate
        )
        self.assertEqual(result.state, "exhausted")
        self.assertEqual(result.usage.attempts, 1)

    def test_cancel_and_global_kill_switch_stop_before_or_after_attempt(self) -> None:
        journal = InMemoryLoopJournal()
        engine = BoundedLoopEngine(definition(clock=self.clock), journal, clock=self.clock)
        engine.start("run-cancel")
        journal.request_cancel("run-cancel")
        result = engine.run("run-cancel", lambda _: self.fail("must not execute"), pass_gate)
        self.assertEqual(result.terminal_reason, "ECO_LOOP_CANCELLED")

        journal = InMemoryLoopJournal()
        engine = BoundedLoopEngine(definition(clock=self.clock), journal, clock=self.clock)

        def kill(_):
            journal.set_kill_switch()
            return attempt()

        result = engine.run("run-kill", kill, pass_gate)
        self.assertEqual(result.state, "cancelled")
        self.assertEqual(result.terminal_reason, "ECO_LOOP_KILL_SWITCH")

    def test_crash_recovery_never_repeats_ambiguous_attempt_and_terminal_replays(self) -> None:
        item = definition(clock=self.clock)
        journal = InMemoryLoopJournal()
        engine = BoundedLoopEngine(item, journal, clock=self.clock)
        ready = engine.start("run-crash")
        running = journal.transition(
            ready,
            "running",
            usage=LoopUsage(attempts=1),
            reason_code="ECO_LOOP_ATTEMPT_RESERVED",
        )
        recovered = engine.recover("run-crash")
        self.assertEqual(recovered.state, "failed")
        self.assertEqual(recovered.terminal_reason, "ECO_LOOP_RECOVERY_AMBIGUOUS")
        event_count = len(journal.events("run-crash"))
        self.assertEqual(engine.recover("run-crash"), recovered)
        self.assertEqual(len(journal.events("run-crash")), event_count)
        self.assertEqual(running.usage.attempts, 1)

    def test_definition_drift_blocks_replay(self) -> None:
        item = definition(clock=self.clock)
        journal = InMemoryLoopJournal()
        BoundedLoopEngine(item, journal, clock=self.clock).start("run-drift")
        changed = dataclasses.replace(item, gate_digest=DIGEST_C)
        with self.assertRaisesRegex(LoopEngineError, "objective or gate changed"):
            BoundedLoopEngine(changed, journal, clock=self.clock).recover("run-drift")

    def test_concurrent_terminal_race_appends_exactly_one_terminal(self) -> None:
        item = definition(clock=self.clock)
        journal = InMemoryLoopJournal()
        ready = BoundedLoopEngine(item, journal, clock=self.clock).start("run-race")
        running = journal.transition(
            ready,
            "running",
            usage=LoopUsage(attempts=1),
            reason_code="ECO_LOOP_ATTEMPT_RESERVED",
        )
        gating = journal.transition(
            running,
            "gating",
            usage=LoopUsage(attempts=1, iterations=1),
            progress_digest=DIGEST_A,
            stagnant_iterations=0,
            reason_code="ECO_GATE_FAILED",
            evidence_digest=DIGEST_C,
        )
        results = []

        def terminate(state: str, reason: str) -> None:
            results.append(journal.transition(gating, state, reason_code=reason))

        threads = [
            threading.Thread(target=terminate, args=("succeeded", "ECO_GATE_PASSED")),
            threading.Thread(target=terminate, args=("failed", "ECO_GATE_FAILED")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        terminal_events = [event for event in journal.events("run-race") if event["to"] in TERMINAL_STATES]
        self.assertEqual(len(terminal_events), 1)
        self.assertEqual(len({result.state for result in results}), 1)

    def test_invalid_executor_result_fails_safely(self) -> None:
        engine = BoundedLoopEngine(
            definition(clock=self.clock), InMemoryLoopJournal(), clock=self.clock
        )
        result = engine.run(
            "run-invalid-result", lambda _: object(), pass_gate  # type: ignore[arg-type]
        )
        self.assertEqual(result.terminal_reason, "ECO_LOOP_OUTCOME_INVALID")

    def test_sqlite_reopen_replays_terminal_without_second_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = f"{temporary}/loops.sqlite3"
            item = definition(clock=self.clock)
            first = BoundedLoopEngine(item, SQLiteLoopJournal(database), clock=self.clock)
            completed = first.run("run-durable-success", lambda _: attempt(), pass_gate)
            second = BoundedLoopEngine(item, SQLiteLoopJournal(database), clock=self.clock)
            replayed = second.run(
                "run-durable-success",
                lambda _: self.fail("terminal replay must not execute"),
                pass_gate,
            )
            self.assertEqual(replayed, completed)

    def test_sqlite_crash_recovery_marks_started_attempt_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = f"{temporary}/loops.sqlite3"
            item = definition(clock=self.clock)
            journal = SQLiteLoopJournal(database)
            ready = BoundedLoopEngine(item, journal, clock=self.clock).start("run-durable-crash")
            journal.transition(
                ready,
                "running",
                usage=LoopUsage(attempts=1),
                reason_code="ECO_LOOP_ATTEMPT_RESERVED",
            )
            recovered = BoundedLoopEngine(
                item, SQLiteLoopJournal(database), clock=self.clock
            ).recover("run-durable-crash")
            self.assertEqual(recovered.state, "failed")
            self.assertEqual(recovered.terminal_reason, "ECO_LOOP_RECOVERY_AMBIGUOUS")

    def test_sqlite_detects_checkpoint_or_event_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = f"{temporary}/loops.sqlite3"
            item = definition(clock=self.clock)
            journal = SQLiteLoopJournal(database)
            BoundedLoopEngine(item, journal, clock=self.clock).run(
                "run-durable-tamper", lambda _: attempt(), pass_gate
            )
            connection = sqlite3.connect(database)
            connection.execute(
                "UPDATE loop_runs SET attempts = 0 WHERE run_id = 'run-durable-tamper'"
            )
            connection.commit()
            connection.close()
            with self.assertRaises(LoopEngineError) as caught:
                SQLiteLoopJournal(database).load("run-durable-tamper")
            self.assertEqual(caught.exception.code, "ECO_LOOP_JOURNAL_CORRUPT")

    def test_sqlite_concurrent_terminal_race_is_single_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = f"{temporary}/loops.sqlite3"
            item = definition(clock=self.clock)
            journal = SQLiteLoopJournal(database)
            ready = BoundedLoopEngine(item, journal, clock=self.clock).start("run-durable-race")
            running = journal.transition(
                ready,
                "running",
                usage=LoopUsage(attempts=1),
                reason_code="ECO_LOOP_ATTEMPT_RESERVED",
            )
            gating = journal.transition(
                running,
                "gating",
                usage=LoopUsage(attempts=1, iterations=1),
                progress_digest=DIGEST_A,
                stagnant_iterations=0,
                reason_code="ECO_GATE_FAILED",
                evidence_digest=DIGEST_C,
            )
            results = []

            def terminate(state: str, reason: str) -> None:
                results.append(
                    SQLiteLoopJournal(database).transition(gating, state, reason_code=reason)
                )

            threads = [
                threading.Thread(target=terminate, args=("succeeded", "ECO_GATE_PASSED")),
                threading.Thread(target=terminate, args=("failed", "ECO_GATE_FAILED")),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(results), 2)
            self.assertEqual(len({result.state for result in results}), 1)
            events = SQLiteLoopJournal(database).events("run-durable-race")
            self.assertEqual(sum(event["to"] in TERMINAL_STATES for event in events), 1)


class ProfileCompatibilityTests(unittest.TestCase):
    def test_source_review_is_outline_and_cannot_replace_fixed_runner(self) -> None:
        profile = source_review_outline(deadline=datetime(2026, 7, 18, tzinfo=UTC))
        report = validate_profile(profile)
        self.assertFalse(report["deterministic"])
        self.assertFalse(report["executable"])
        with self.assertRaises(LoopEngineError) as caught:
            BoundedLoopEngine(profile, InMemoryLoopJournal()).run(
                "run-source-outline", lambda _: attempt(), pass_gate
            )
        self.assertEqual(caught.exception.code, "ECO_LOOP_PROFILE_NOT_EXECUTABLE")

    def test_wiki_compatibility_delegates_existing_workflow_exactly_once(self) -> None:
        existing_result = {
            "available": True,
            "workflow": "wiki-health-check",
            "status": "succeeded",
            "code": "ECO_NO_MODEL_SUCCEEDED",
            "report": {"digest": DIGEST_A},
        }
        executor, gate, holder = wiki_health_executor("/repo", {})
        with mock.patch(
            "eco_runtime.no_model_execution.execute_wiki_health_check",
            return_value=existing_result,
        ) as existing:
            profile = wiki_health_compatibility(
                deadline=datetime.now(UTC) + timedelta(minutes=1)
            )
            result = BoundedLoopEngine(profile, InMemoryLoopJournal()).run(
                "run-wiki-compat", executor, gate
            )
        self.assertEqual(result.state, "succeeded")
        existing.assert_called_once_with("/repo", {})
        self.assertIs(holder["result"], existing_result)
        self.assertEqual(result.usage.tokens, 0)
        self.assertEqual(result.usage.cost_microusd, 0)
        self.assertEqual(result.usage.storage_bytes, 0)

    def test_cli_validate_exposes_only_deterministic_compatibility_profile(self) -> None:
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = main(["loops", "validate", "wiki-health-check", "--json"])
        self.assertEqual(code, 0)
        document = json.loads(stdout.getvalue())
        self.assertTrue(document["deterministic"])
        self.assertTrue(document["executable"])
        self.assertEqual(document["sideEffectMode"], "report-only")

        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as caught:
            main(["loops", "validate", "source-review", "--json"])
        self.assertEqual(caught.exception.code, 2)

    def test_cli_run_delegates_existing_workflow_once_and_emits_no_content(self) -> None:
        existing_result = {
            "available": True,
            "workflow": "wiki-health-check",
            "status": "succeeded",
            "code": "ECO_NO_MODEL_SUCCEEDED",
            "report": {"digest": DIGEST_A},
        }
        stdout = StringIO()
        with (
            mock.patch("eco_cli.cli._validate", return_value=([], {}, {})),
            mock.patch(
                "eco_runtime.no_model_execution.execute_wiki_health_check",
                return_value=existing_result,
            ) as existing,
            redirect_stdout(stdout),
        ):
            code = main(["--repo", ".", "loops", "run", "wiki-health-check", "--json"])
        self.assertEqual(code, 0)
        existing.assert_called_once()
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["state"], "succeeded")
        self.assertEqual(document["usage"]["attempts"], 1)
        self.assertEqual(document["evidence"]["delegatedReportDigest"], DIGEST_A)
        self.assertNotIn("raw", document)
        self.assertNotIn("content", document["evidence"])


if __name__ == "__main__":
    unittest.main()
