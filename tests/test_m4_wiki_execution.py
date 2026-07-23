from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import eco_runtime.no_model_execution as no_model_execution
from eco_cli.cli import main
from eco_cli.config import validate_repository
from eco_runtime.evidence import HmacEvidenceSigner
from eco_runtime.no_model_execution import execute_wiki_health_check
from eco_runtime.broker import RepositoryReadBroker
from eco_runtime.repository import repository_root_identity
from eco_runtime.wiki_health_evaluation import execute_wiki_health_evaluation
from eco_runtime.policy import PolicyEngine
from eco_runtime.no_model_journal import NoModelJournal
from eco_runtime.errors import RuntimeStoreError


NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
KEY = b"m4-wiki-execution-test-key-32bytes"


class WikiHealthExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        source = Path(__file__).resolve().parents[1]
        self.root = Path(self.temp.name) / "repository"
        shutil.copytree(source, self.root, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
        self.evidence_path = Path(self.temp.name) / "snapshot.envelope"
        self.state_root = Path(self.temp.name) / "runtime-state"
        self.state_root.mkdir(mode=0o700)
        errors, self.bundle, _ = validate_repository(self.root, ".ai")
        self.assertEqual(errors, [])
        self._write_snapshot()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_snapshot(
        self,
        *,
        envelope_id: str = "m4-wiki-envelope",
        expires_at: datetime | None = None,
    ) -> None:
        entries = []
        for entry in self.bundle["trust"]["repositorySnapshot"]["entries"]:
            path = entry["path"]
            contents = (self.root / path).read_bytes()
            entries.append(
                {
                    "path": path,
                    "contentDigest": hashlib.sha256(contents).hexdigest(),
                    "byteLength": len(contents),
                    "dataClass": entry["dataClass"],
                    "trust": entry["trust"],
                    "classificationAuthority": entry["classificationAuthority"],
                }
            )
        snapshot = {
            "apiVersion": "runtime.ai.ecosystem/v1alpha1",
            "kind": "RepositorySnapshot",
            "metadata": {
                "id": "m4-wiki-snapshot",
                "projectId": self.bundle["project"]["metadata"]["name"],
                "createdAt": "2026-07-16T11:59:00Z",
                "issuer": {"type": "operator", "id": "local-snapshot-authority"},
            },
            "spec": {
                "rootIdentityDigest": repository_root_identity(self.root),
                "trust": "P1",
                "entries": entries,
            },
        }
        encoded = HmacEvidenceSigner(
            "local-snapshot-authority", "local-snapshot-v1", KEY
        ).sign(
            snapshot,
            envelope_id=envelope_id,
            issued_at=NOW - timedelta(minutes=1),
            expires_at=expires_at or NOW + timedelta(minutes=5),
        )
        self.evidence_path.write_bytes(encoded)
        os.chmod(self.evidence_path, 0o600)

    def environment(self) -> dict[str, str]:
        return {
            "ECO_SNAPSHOT_EVIDENCE_KEY": KEY.decode("ascii"),
            "ECO_WIKI_SNAPSHOT_ENVELOPE_FILE": str(self.evidence_path),
            "ECO_RUNTIME_STATE_DIR": str(self.state_root),
            "ECO_RUNTIME_JOURNAL_HMAC_KEY": "m4-journal-integrity-key-at-least-32-bytes",
        }

    def test_executes_only_fixed_scope_and_replays_without_content_persistence(self) -> None:
        marker = "UNTRUSTED_WIKI_MARKER_MUST_NOT_ESCAPE"
        target = self.root / "wiki" / "index.md"
        target.write_text(target.read_text(encoding="utf-8") + marker, encoding="utf-8")
        self._write_snapshot()
        original_read = RepositoryReadBroker.read
        reads: list[str] = []

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
                replay = execute_wiki_health_check(self.root, self.bundle, now=NOW + timedelta(seconds=1))

        encoded = json.dumps(result, sort_keys=True)
        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["execution"]["readCount"], 3)
        self.assertFalse(result["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["execution"]["readCount"], result["execution"]["readCount"])
        self.assertEqual(replay["execution"]["totalBytes"], result["execution"]["totalBytes"])
        self.assertEqual(result["execution"]["brokerReadCount"], 3)
        self.assertEqual(replay["execution"]["brokerReadCount"], 0)
        self.assertEqual(replay["report"]["digest"], result["report"]["digest"])
        self.assertEqual(len(reads), 3)
        self.assertNotIn(marker, encoded)
        self.assertNotIn("wiki/index.md", encoded)
        self.assertEqual(result["safety"]["modelEgress"], "not-used")
        self.assertEqual(result["safety"]["repositoryMutation"], "denied")

        database = self.state_root / "no-model-a1.sqlite3"
        connection = sqlite3.connect(database)
        try:
            persisted = "".join(row[0] for row in connection.execute("SELECT event_json FROM no_model_events"))
        finally:
            connection.close()
        self.assertNotIn(marker, persisted)
        self.assertNotIn("wiki/index.md", persisted)
        self.assertNotIn("adapter.started", persisted)
        self.assertNotIn("tool.requested", persisted)

    def test_repository_tree_is_byte_identical_after_execution(self) -> None:
        def manifest() -> dict[str, str]:
            return {
                path.relative_to(self.root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.root.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

        before = manifest()
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertTrue(result["available"])
        self.assertEqual(manifest(), before)

    def test_authenticated_journal_rejects_rewritten_event_even_with_new_plain_digest(self) -> None:
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            self.assertTrue(execute_wiki_health_check(self.root, self.bundle, now=NOW)["available"])
            database = self.state_root / "no-model-a1.sqlite3"
            connection = sqlite3.connect(database)
            try:
                event_id, encoded = connection.execute(
                    "SELECT rowid, event_json FROM no_model_events ORDER BY sequence LIMIT 1"
                ).fetchone()
                changed = json.loads(encoded)
                changed["spec"]["outcome"] = "success"
                rewritten = json.dumps(changed, sort_keys=True, separators=(",", ":"))
                connection.execute(
                    "UPDATE no_model_events SET event_json = ?, event_digest = ? WHERE rowid = ?",
                    (rewritten, hashlib.sha256(rewritten.encode()).hexdigest(), event_id),
                )
                connection.commit()
            finally:
                connection.close()
            blocked = execute_wiki_health_check(self.root, self.bundle, now=NOW + timedelta(seconds=1))
        self.assertFalse(blocked["available"])
        self.assertEqual(blocked["code"], "ECO_NO_MODEL_STATE_INVALID")

    def test_preexisting_database_symlink_is_denied_without_touching_target(self) -> None:
        target = self.root / "must-not-be-created"
        (self.state_root / "no-model-a1.sqlite3").symlink_to(target)
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_STATE_LOCATION_DENIED")
        self.assertFalse(target.exists())

    def test_symlinked_state_directory_alias_is_denied(self) -> None:
        alias = Path(self.temp.name) / "runtime-state-alias"
        alias.symlink_to(self.state_root, target_is_directory=True)
        environment = {**self.environment(), "ECO_RUNTIME_STATE_DIR": str(alias)}
        with mock.patch.dict(os.environ, environment, clear=False):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_STATE_LOCATION_DENIED")

    def test_repository_resident_state_directory_is_denied_without_database_creation(self) -> None:
        resident = self.root / ".private-runtime-state"
        resident.mkdir(mode=0o700)
        environment = {**self.environment(), "ECO_RUNTIME_STATE_DIR": str(resident)}
        with mock.patch.dict(os.environ, environment, clear=False):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_STATE_LOCATION_DENIED")
        self.assertFalse((resident / "no-model-a1.sqlite3").exists())

    def test_preexisting_empty_or_hardlinked_database_is_denied(self) -> None:
        database = self.state_root / "no-model-a1.sqlite3"
        database.touch(mode=0o600)
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            malformed = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(malformed["available"])
        self.assertEqual(malformed["code"], "ECO_NO_MODEL_STATE_INVALID")

        database.unlink()
        target = Path(self.temp.name) / "linked-state"
        target.touch(mode=0o600)
        os.link(target, database)
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            linked = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(linked["available"])
        self.assertEqual(linked["code"], "ECO_NO_MODEL_STATE_LOCATION_DENIED")

    def test_concurrent_journal_owner_fails_closed_before_duplicate_io(self) -> None:
        database = self.state_root / "no-model-a1.sqlite3"
        key = self.environment()["ECO_RUNTIME_JOURNAL_HMAC_KEY"].encode("utf-8")
        with NoModelJournal(database, integrity_key=key):
            with self.assertRaises(RuntimeStoreError) as caught:
                NoModelJournal(database, integrity_key=key)
        self.assertEqual(caught.exception.code, "ECO_NO_MODEL_STATE_BUSY")

    def test_wrong_journal_key_fails_closed_and_resigned_snapshot_gets_new_run(self) -> None:
        environment = self.environment()
        with mock.patch.dict(os.environ, environment, clear=False):
            first = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertTrue(first["available"])

        wrong_key = {**environment, "ECO_RUNTIME_JOURNAL_HMAC_KEY": "different-journal-key-still-at-least-32-bytes"}
        with mock.patch.dict(os.environ, wrong_key, clear=False):
            blocked = execute_wiki_health_check(self.root, self.bundle, now=NOW + timedelta(seconds=1))
        self.assertFalse(blocked["available"])
        self.assertEqual(blocked["code"], "ECO_NO_MODEL_STATE_INVALID")

        self._write_snapshot(envelope_id="m4-wiki-envelope-resigned")
        with mock.patch.dict(os.environ, environment, clear=False):
            resigned = execute_wiki_health_check(self.root, self.bundle, now=NOW + timedelta(seconds=1))
        self.assertTrue(resigned["available"])
        self.assertFalse(resigned["replayed"])

    def test_recovery_from_allowed_read_reissues_and_consumes_fresh_policy_authority(self) -> None:
        original_append = NoModelJournal.append

        def interrupt_before_started(journal, chain, event_type, producer, **kwargs):
            if event_type == "no-model.read.started":
                raise KeyboardInterrupt
            return original_append(journal, chain, event_type, producer, **kwargs)

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(NoModelJournal, "append", new=interrupt_before_started):
                with self.assertRaises(KeyboardInterrupt):
                    execute_wiki_health_check(self.root, self.bundle, now=NOW)
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW + timedelta(seconds=1))
        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["execution"]["brokerReadCount"], 3)

    def test_partial_recovery_restores_completed_structural_evidence(self) -> None:
        original_append = NoModelJournal.append
        original_read = RepositoryReadBroker.read
        reads: list[str] = []
        interrupted = [False]

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        def interrupt_after_first_completion(journal, chain, event_type, producer, **kwargs):
            result = original_append(journal, chain, event_type, producer, **kwargs)
            if event_type == "no-model.read.completed" and not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                with mock.patch.object(
                    NoModelJournal, "append", new=interrupt_after_first_completion
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        execute_wiki_health_check(self.root, self.bundle, now=NOW)
                recovered = execute_wiki_health_check(
                    self.root, self.bundle, now=NOW + timedelta(seconds=1)
                )

        self.assertTrue(recovered["available"])
        self.assertEqual(recovered["execution"]["readCount"], 3)
        self.assertEqual(recovered["execution"]["brokerReadCount"], 2)
        self.assertEqual(recovered["report"]["checks"]["singleDocumentHeading"], "pass")
        self.assertEqual(recovered["report"]["checks"]["distinctDocuments"], "pass")
        self.assertEqual(len(reads), 3)

    def test_recovery_after_all_reads_completes_without_duplicate_io(self) -> None:
        original_append = NoModelJournal.append
        original_read = RepositoryReadBroker.read
        reads: list[str] = []

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        def interrupt_before_success(journal, chain, event_type, producer, **kwargs):
            if event_type == "no-model.workflow.succeeded":
                raise KeyboardInterrupt
            return original_append(journal, chain, event_type, producer, **kwargs)

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                with mock.patch.object(NoModelJournal, "append", new=interrupt_before_success):
                    with self.assertRaises(KeyboardInterrupt):
                        execute_wiki_health_check(self.root, self.bundle, now=NOW)
                recovered = execute_wiki_health_check(
                    self.root, self.bundle, now=NOW + timedelta(seconds=1)
                )

        self.assertTrue(recovered["available"])
        self.assertEqual(recovered["execution"]["brokerReadCount"], 0)
        self.assertEqual(recovered["execution"]["readCount"], 3)
        self.assertEqual(len(reads), 3)

    def test_ambiguous_post_read_crash_is_terminal_and_never_rereads(self) -> None:
        original_append = NoModelJournal.append
        original_read = RepositoryReadBroker.read
        reads: list[str] = []

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        def interrupt_before_completion(journal, chain, event_type, producer, **kwargs):
            if event_type == "no-model.read.completed":
                raise KeyboardInterrupt
            return original_append(journal, chain, event_type, producer, **kwargs)

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                with mock.patch.object(NoModelJournal, "append", new=interrupt_before_completion):
                    with self.assertRaises(KeyboardInterrupt):
                        execute_wiki_health_check(self.root, self.bundle, now=NOW)
                recovered = execute_wiki_health_check(
                    self.root, self.bundle, now=NOW + timedelta(seconds=1)
                )

        self.assertFalse(recovered["available"])
        self.assertEqual(recovered["code"], "ECO_NO_MODEL_READ_OUTCOME_AMBIGUOUS")
        self.assertEqual(recovered["execution"]["brokerReadCount"], 0)
        self.assertEqual(len(reads), 1)

    def test_parser_work_after_last_read_cannot_cross_deadline_and_succeed(self) -> None:
        clock = [0.0]
        parser_calls = [0]
        original_parser = no_model_execution._single_h1_outside_fences

        def delayed_parser(content):
            parser_calls[0] += 1
            result = original_parser(content)
            if parser_calls[0] == 3:
                clock[0] = 31.0
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch(
                "eco_runtime.no_model_execution.time.monotonic",
                side_effect=lambda: clock[0],
            ):
                with mock.patch(
                    "eco_runtime.no_model_execution._single_h1_outside_fences",
                    side_effect=delayed_parser,
                ):
                    result = execute_wiki_health_check(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_DEADLINE_EXCEEDED")
        self.assertEqual(result["execution"]["brokerReadCount"], 3)

    def test_initial_deadline_includes_work_before_journal_begin(self) -> None:
        clock = [0.0]
        original_state_directory = no_model_execution._private_state_directory
        original_begin = NoModelJournal.begin

        def delayed_state_directory(root):
            result = original_state_directory(root)
            clock[0] = 20.0
            return result

        def delayed_after_begin(journal, plan, *, now):
            result = original_begin(journal, plan, now=now)
            clock[0] = 40.0
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch(
                "eco_runtime.no_model_execution.time.monotonic",
                side_effect=lambda: clock[0],
            ):
                with mock.patch(
                    "eco_runtime.no_model_execution._private_state_directory",
                    side_effect=delayed_state_directory,
                ):
                    with mock.patch.object(
                        NoModelJournal, "begin", new=delayed_after_begin
                    ):
                        with mock.patch.object(RepositoryReadBroker, "read") as read:
                            result = execute_wiki_health_check(
                                self.root, self.bundle, now=NOW
                            )

        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_DEADLINE_EXCEEDED")
        self.assertEqual(result["execution"]["brokerReadCount"], 0)
        read.assert_not_called()

    def test_deadline_is_rechecked_after_final_authority_validation(self) -> None:
        clock = [0.0]
        validations = [0]
        original_assert_current = PolicyEngine.assert_no_model_plan_current

        def advance_after_final_validation(policy, plan, *, now):
            result = original_assert_current(policy, plan, now=now)
            validations[0] += 1
            if validations[0] == 4:
                clock[0] = 31.0
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch(
                "eco_runtime.no_model_execution.time.monotonic",
                side_effect=lambda: clock[0],
            ):
                with mock.patch.object(
                    PolicyEngine,
                    "assert_no_model_plan_current",
                    new=advance_after_final_validation,
                ):
                    result = execute_wiki_health_check(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_DEADLINE_EXCEEDED")
        self.assertEqual(result["execution"]["brokerReadCount"], 3)

    def test_expiring_evidence_blocks_later_reads_with_advancing_policy_time(self) -> None:
        self._write_snapshot(expires_at=NOW + timedelta(seconds=1))
        clock = [0.0]
        original_append = NoModelJournal.append
        original_read = RepositoryReadBroker.read
        reads: list[str] = []

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        def advance_after_first_completion(journal, chain, event_type, producer, **kwargs):
            result = original_append(journal, chain, event_type, producer, **kwargs)
            if event_type == "no-model.read.completed" and clock[0] == 0.0:
                clock[0] = 2.0
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch(
                "eco_runtime.no_model_execution.time.monotonic",
                side_effect=lambda: clock[0],
            ):
                with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                    with mock.patch.object(
                        NoModelJournal, "append", new=advance_after_first_completion
                    ):
                        result = execute_wiki_health_check(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(len(reads), 1)
        self.assertEqual(result["execution"]["brokerReadCount"], 1)

    def test_state_directory_is_mandatory_and_safe_failure_does_not_echo_location(self) -> None:
        marker = "PRIVATE_STATE_LOCATION_MUST_NOT_ESCAPE"
        with mock.patch.dict(
            os.environ,
            {
                "ECO_SNAPSHOT_EVIDENCE_KEY": KEY.decode("ascii"),
                "ECO_WIKI_SNAPSHOT_ENVELOPE_FILE": str(self.evidence_path),
                "ECO_RUNTIME_STATE_DIR": marker,
            },
            clear=True,
        ):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_STATE_LOCATION_DENIED")
        self.assertNotIn(marker, json.dumps(result))

    def test_fixed_wall_clock_budget_fails_before_broker_read(self) -> None:
        clock = [0.0]
        original_append = NoModelJournal.append

        def advance_after_allow(journal, chain, event_type, producer, **kwargs):
            result = original_append(journal, chain, event_type, producer, **kwargs)
            if event_type == "no-model.read.allowed":
                clock[0] = 31.0
            return result

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch(
                "eco_runtime.no_model_execution.time.monotonic",
                side_effect=lambda: clock[0],
            ):
                with mock.patch.object(NoModelJournal, "append", new=advance_after_allow):
                    with mock.patch.object(RepositoryReadBroker, "read") as read:
                        result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_NO_MODEL_DEADLINE_EXCEEDED")
        self.assertEqual(result["execution"]["brokerReadCount"], 0)
        read.assert_not_called()

    def test_policy_denial_records_denied_and_never_calls_broker(self) -> None:
        denial = {"spec": {"effect": "deny", "reasonCodes": ["ECO_TEST_READ_DENIED"]}}
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(PolicyEngine, "authorize_no_model_read", return_value=denial):
                with mock.patch.object(RepositoryReadBroker, "read") as read:
                    result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_TEST_READ_DENIED")
        read.assert_not_called()
        connection = sqlite3.connect(self.state_root / "no-model-a1.sqlite3")
        try:
            events = "".join(
                row[0] for row in connection.execute("SELECT event_json FROM no_model_events")
            )
        finally:
            connection.close()
        self.assertIn("no-model.read.denied", events)
        self.assertNotIn("no-model.read.failed", events)

    def test_structural_health_gate_rejects_missing_primary_heading_without_content_leak(self) -> None:
        marker = "PRIVATE_INVALID_HEADING_MARKER"
        target = self.root / "wiki" / "index.md"
        content = target.read_text(encoding="utf-8")
        target.write_text(content.replace("# Wiki Index — ecosystem", marker, 1), encoding="utf-8")
        self._write_snapshot()
        with mock.patch.dict(os.environ, self.environment(), clear=False):
            result = execute_wiki_health_check(self.root, self.bundle, now=NOW)
        self.assertFalse(result["available"])
        self.assertEqual(result["code"], "ECO_WIKI_HEALTH_STRUCTURE_INVALID")
        self.assertEqual(result["report"]["checks"]["singleDocumentHeading"], "fail")
        self.assertNotIn(marker, json.dumps(result, sort_keys=True))

    def test_cli_has_only_the_fixed_no_model_workflow_surface(self) -> None:
        with mock.patch("eco_runtime.no_model_execution.execute_wiki_health_check") as execute:
            execute.return_value = {
                "available": True,
                "workflow": "wiki-health-check",
                "status": "succeeded",
                "code": "ECO_NO_MODEL_WORKFLOW_SUCCEEDED",
                "safety": {},
            }
            with mock.patch("sys.stdout") as output:
                code = main(["--repo", str(self.root), "run", "wiki-health-check", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(output.write.called)

    def test_fixed_five_attempt_evaluation_promotes_only_to_l2_and_replays_without_reads(self) -> None:
        original_read = RepositoryReadBroker.read
        reads: list[str] = []

        def tracked_read(broker, path, **kwargs):
            reads.append(path)
            return original_read(broker, path, **kwargs)

        with mock.patch.dict(os.environ, self.environment(), clear=False):
            with mock.patch.object(RepositoryReadBroker, "read", new=tracked_read):
                first = execute_wiki_health_evaluation(self.root, self.bundle, now=NOW)
                self.assertEqual(len(reads), 15)
                second = execute_wiki_health_evaluation(
                    self.root, self.bundle, now=NOW + timedelta(seconds=1)
                )
        self.assertEqual(len(reads), 15)
        self.assertTrue(first["available"])
        self.assertEqual(first["evaluation"]["highestEligibleLevel"], "L2")
        self.assertTrue(first["evaluation"]["recoveryPassed"])
        self.assertFalse(
            first["promotionReport"]["spec"]["promotion"]["levels"]["L3"]["eligible"]
        )
        self.assertTrue(second["available"])
        self.assertEqual(second["evaluation"]["highestEligibleLevel"], "L2")
        self.assertEqual(
            len(list(self.state_root.glob("no-model-a1-evaluation-*.sqlite3"))), 5
        )

    def test_cli_exposes_only_the_fixed_wiki_evaluation(self) -> None:
        with mock.patch(
            "eco_runtime.wiki_health_evaluation.execute_wiki_health_evaluation"
        ) as evaluate:
            evaluate.return_value = {
                "available": True,
                "workflow": "wiki-health-check",
                "status": "succeeded",
                "code": "ECO_M4_PROMOTION_GATE_PASSED",
                "evaluation": {"highestEligibleLevel": "L2"},
            }
            with mock.patch("sys.stdout") as output:
                code = main(["--repo", str(self.root), "eval", "wiki-health-check", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(output.write.called)


if __name__ == "__main__":
    unittest.main()
