from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.errors import BrokerError
from eco_runtime.write_broker import FileState, LinuxWorkspaceWriteBroker


def file_state(path: Path) -> FileState:
    content = path.read_bytes()
    return FileState.present(
        hashlib.sha256(content).hexdigest(), len(content), stat.S_IMODE(path.stat().st_mode)
    )


class LinuxWorkspaceWriteBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository_temp = tempfile.TemporaryDirectory()
        self.store_temp = tempfile.TemporaryDirectory()
        self.outside_temp = tempfile.TemporaryDirectory()
        self.root = Path(self.repository_temp.name)
        self.outside = Path(self.outside_temp.name)
        self.store = ContentAddressedArtifactStore(
            self.store_temp.name,
            proof_key=b"w" * 32,
            key_id="write-tests-v1",
            forbidden_root=self.root,
        )
        (self.root / "existing.txt").write_bytes(b"before\n")
        os.chmod(self.root / "existing.txt", 0o640)
        (self.root / "subdir").mkdir()
        (self.root / ".git").mkdir()
        (self.root / ".env").write_bytes(b"SECRET=x\n")
        self.broker = LinuxWorkspaceWriteBroker(
            self.root, self.store, maximum_file_bytes=128
        )

    def tearDown(self) -> None:
        self.broker.close()
        self.store.close()
        self.repository_temp.cleanup()
        self.store_temp.cleanup()
        self.outside_temp.cleanup()

    def proof(self, content: bytes):
        return self.store.put(content)

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(BrokerError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def assert_no_temp(self, directory: Path | None = None) -> None:
        directory = directory or self.root
        self.assertEqual(
            [path.name for path in directory.iterdir() if path.name.startswith(".eco-write-")],
            [],
        )

    def test_create_returns_tombstone_rollback_and_rollback_is_idempotent(self) -> None:
        candidate = self.proof(b"created\n")
        receipt = self.broker.apply(
            "created.txt",
            operation="create",
            expected_before=FileState.absent(),
            candidate_proof=candidate,
            candidate_mode=0o644,
        )

        target = self.root / "created.txt"
        self.assertEqual(target.read_bytes(), b"created\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
        self.assertIsNone(receipt.rollback_proof)
        first = self.broker.rollback(receipt)
        second = self.broker.rollback(receipt)
        self.assertTrue(first.changed)
        self.assertFalse(second.changed)
        self.assertFalse(target.exists())
        self.assert_no_temp()

    def test_replace_captures_exact_before_bytes_and_mode_then_restores_them(self) -> None:
        target = self.root / "existing.txt"
        before = file_state(target)
        candidate = self.proof(b"after\n")

        receipt = self.broker.apply(
            "existing.txt",
            operation="replace",
            expected_before=before,
            candidate_proof=candidate,
            candidate_mode=0o600,
        )

        self.assertEqual(target.read_bytes(), b"after\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertIsNotNone(receipt.rollback_proof)
        assert receipt.rollback_proof is not None
        self.store.verify_availability(receipt.rollback_proof)
        restored = self.broker.rollback(receipt)
        repeated = self.broker.rollback(receipt)
        self.assertTrue(restored.changed)
        self.assertFalse(repeated.changed)
        self.assertEqual(target.read_bytes(), b"before\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assert_no_temp()

    def test_operation_must_match_exact_expected_before_state(self) -> None:
        proof = self.proof(b"value\n")
        self.assert_code(
            "ECO_WRITE_REQUEST_INVALID",
            lambda: self.broker.apply(
                "new.txt",
                operation="replace",
                expected_before=FileState.absent(),
                candidate_proof=proof,
            ),
        )
        self.assert_code(
            "ECO_EXPECTED_BEFORE_MISMATCH",
            lambda: self.broker.apply(
                "existing.txt",
                operation="create",
                expected_before=FileState.absent(),
                candidate_proof=proof,
            ),
        )

    def test_replace_rejects_digest_length_and_mode_drift(self) -> None:
        target = self.root / "existing.txt"
        correct = file_state(target)
        candidates = (
            replace(correct, sha256="0" * 64),
            replace(correct, byte_length=correct.byte_length + 1),  # type: ignore[operator]
            replace(correct, mode=0o600),
        )
        for expected in candidates:
            with self.subTest(expected=expected):
                self.assert_code(
                    "ECO_EXPECTED_BEFORE_MISMATCH",
                    lambda expected=expected: self.broker.apply(
                        "existing.txt",
                        operation="replace",
                        expected_before=expected,
                        candidate_proof=self.proof(b"after\n"),
                    ),
                )
        self.assertEqual(target.read_bytes(), b"before\n")

    def test_noncanonical_and_protected_paths_are_denied(self) -> None:
        proof = self.proof(b"value\n")
        for path in (
            "../outside.txt",
            "/absolute.txt",
            "./relative.txt",
            "double//slash.txt",
            "back\\slash.txt",
            "bad\x00name.txt",
        ):
            with self.subTest(path=path):
                self.assert_code(
                    "ECO_WRITE_REQUEST_INVALID",
                    lambda path=path: self.broker.apply(
                        path,
                        operation="create",
                        expected_before=FileState.absent(),
                        candidate_proof=proof,
                    ),
                )
        for path in (".git/config", ".env", "private.pem", "secrets/value.txt"):
            with self.subTest(path=path):
                self.assert_code(
                    "ECO_PROTECTED_PATH",
                    lambda path=path: self.broker.apply(
                        path,
                        operation="create",
                        expected_before=FileState.absent(),
                        candidate_proof=proof,
                    ),
                )

    def test_parent_must_exist_and_symlink_parents_cannot_escape(self) -> None:
        proof = self.proof(b"value\n")
        self.assert_code(
            "ECO_PARENT_NOT_FOUND",
            lambda: self.broker.apply(
                "missing/value.txt",
                operation="create",
                expected_before=FileState.absent(),
                candidate_proof=proof,
            ),
        )
        os.symlink(self.outside, self.root / "linked")
        self.assert_code(
            "ECO_PATH_ESCAPE",
            lambda: self.broker.apply(
                "linked/value.txt",
                operation="create",
                expected_before=FileState.absent(),
                candidate_proof=proof,
            ),
        )
        self.assertFalse((self.outside / "value.txt").exists())

    def test_final_symlink_and_hardlink_aliases_are_denied(self) -> None:
        outside_target = self.outside / "outside.txt"
        outside_target.write_bytes(b"outside\n")
        os.symlink(outside_target, self.root / "link.txt")
        os.link(outside_target, self.root / "hardlink.txt")
        proof = self.proof(b"replacement\n")
        outside_state = file_state(outside_target)
        self.assert_code(
            "ECO_PATH_ESCAPE",
            lambda: self.broker.apply(
                "link.txt",
                operation="replace",
                expected_before=outside_state,
                candidate_proof=proof,
            ),
        )
        self.assert_code(
            "ECO_HARDLINK_DENIED",
            lambda: self.broker.apply(
                "hardlink.txt",
                operation="replace",
                expected_before=outside_state,
                candidate_proof=proof,
            ),
        )
        self.assertEqual(outside_target.read_bytes(), b"outside\n")

    def test_directories_and_special_files_are_denied(self) -> None:
        os.mkfifo(self.root / "pipe")
        proof = self.proof(b"replacement\n")
        placeholder = FileState.present(hashlib.sha256(b"").hexdigest(), 0, 0o644)
        for path in ("subdir", "pipe"):
            with self.subTest(path=path):
                self.assert_code(
                    "ECO_NOT_REGULAR_FILE",
                    lambda path=path: self.broker.apply(
                        path,
                        operation="replace",
                        expected_before=placeholder,
                        candidate_proof=proof,
                    ),
                )

    def test_candidate_proof_binary_encoding_and_size_are_fail_closed(self) -> None:
        binary = self.proof(b"abc\x00def")
        invalid_utf8 = self.proof(b"\xff\xfe")
        oversized = self.proof(b"x" * 129)
        valid = self.proof(b"valid\n")
        tampered = replace(valid, token="0" * 64)
        expected_codes = (
            (binary, "ECO_BINARY_FILE"),
            (invalid_utf8, "ECO_TEXT_ENCODING"),
            (oversized, "ECO_FILE_TOO_LARGE"),
            (tampered, "ECO_CANDIDATE_UNAVAILABLE"),
        )
        for proof, code in expected_codes:
            with self.subTest(code=code):
                self.assert_code(
                    code,
                    lambda proof=proof: self.broker.apply(
                        "candidate.txt",
                        operation="create",
                        expected_before=FileState.absent(),
                        candidate_proof=proof,
                    ),
                )
                self.assertFalse((self.root / "candidate.txt").exists())
                self.assert_no_temp()

    def test_immediate_revalidation_detects_content_and_hardlink_races(self) -> None:
        target = self.root / "existing.txt"
        before = file_state(target)
        fired = False

        def change_content(phase: str) -> None:
            nonlocal fired
            if phase == "after_candidate_fsync" and not fired:
                fired = True
                target.write_bytes(b"raced\n")

        racing = LinuxWorkspaceWriteBroker(
            self.root, self.store, maximum_file_bytes=128, fault_hook=change_content
        )
        try:
            self.assert_code(
                "ECO_EXPECTED_BEFORE_MISMATCH",
                lambda: racing.apply(
                    "existing.txt",
                    operation="replace",
                    expected_before=before,
                    candidate_proof=self.proof(b"after\n"),
                ),
            )
        finally:
            racing.close()
        self.assertEqual(target.read_bytes(), b"raced\n")
        self.assert_no_temp()

        target.write_bytes(b"before\n")
        os.chmod(target, 0o640)
        before = file_state(target)
        alias = self.outside / "alias.txt"
        fired = False

        def add_hardlink(phase: str) -> None:
            nonlocal fired
            if phase == "after_candidate_fsync" and not fired:
                fired = True
                os.link(target, alias)

        racing = LinuxWorkspaceWriteBroker(
            self.root, self.store, maximum_file_bytes=128, fault_hook=add_hardlink
        )
        try:
            self.assert_code(
                "ECO_HARDLINK_DENIED",
                lambda: racing.apply(
                    "existing.txt",
                    operation="replace",
                    expected_before=before,
                    candidate_proof=self.proof(b"after\n"),
                ),
            )
        finally:
            racing.close()
        self.assertEqual(target.read_bytes(), b"before\n")
        self.assert_no_temp()

    def test_parent_symlink_swap_is_detected_without_outside_write(self) -> None:
        original_parent = self.root / "subdir"
        moved_parent = self.root / "subdir-original"
        fired = False

        def swap_parent(phase: str) -> None:
            nonlocal fired
            if phase == "after_candidate_fsync" and not fired:
                fired = True
                original_parent.rename(moved_parent)
                os.symlink(self.outside, original_parent)

        racing = LinuxWorkspaceWriteBroker(
            self.root, self.store, maximum_file_bytes=128, fault_hook=swap_parent
        )
        try:
            self.assert_code(
                "ECO_PATH_ESCAPE",
                lambda: racing.apply(
                    "subdir/new.txt",
                    operation="create",
                    expected_before=FileState.absent(),
                    candidate_proof=self.proof(b"candidate\n"),
                ),
            )
        finally:
            racing.close()
        self.assertFalse((self.outside / "new.txt").exists())
        self.assertFalse((moved_parent / "new.txt").exists())
        self.assert_no_temp(moved_parent)

    def test_fault_before_commit_leaves_target_and_temp_inventory_unchanged(self) -> None:
        class InjectedFault(Exception):
            pass

        def fail(phase: str) -> None:
            if phase == "before_atomic_commit":
                raise InjectedFault()

        faulting = LinuxWorkspaceWriteBroker(
            self.root, self.store, maximum_file_bytes=128, fault_hook=fail
        )
        try:
            with self.assertRaises(InjectedFault):
                faulting.apply(
                    "faulted.txt",
                    operation="create",
                    expected_before=FileState.absent(),
                    candidate_proof=self.proof(b"candidate\n"),
                )
        finally:
            faulting.close()
        self.assertFalse((self.root / "faulted.txt").exists())
        self.assert_no_temp()

    def test_process_kill_temp_is_removed_only_by_exact_recovery_name(self) -> None:
        candidate = self.proof(b"candidate survives process kill\n")
        temporary_name = self.broker.issue_temporary_name()
        process_id = os.fork()
        if process_id == 0:
            self.broker._fault_hook = (  # noqa: SLF001 - process-loss fault fixture
                lambda phase: os._exit(23) if phase == "after_candidate_fsync" else None
            )
            self.broker.apply(
                "killed.txt",
                operation="create",
                expected_before=FileState.absent(),
                candidate_proof=candidate,
                candidate_mode=0o644,
                temporary_name=temporary_name,
            )
            os._exit(0)
        _, status = os.waitpid(process_id, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 23)
        orphan = self.root / temporary_name
        self.assertTrue(orphan.exists())
        self.assertEqual(orphan.read_bytes(), b"candidate survives process kill\n")
        self.assertTrue(self.broker.cleanup_temporary("killed.txt", temporary_name))
        self.assertFalse(orphan.exists())
        self.assertFalse(self.broker.cleanup_temporary("killed.txt", temporary_name))
        self.assertFalse((self.root / "killed.txt").exists())

    def test_process_kill_during_rollback_uses_same_exact_cleanup_protocol(self) -> None:
        candidate = self.proof(b"created before rollback kill\n")
        receipt = self.broker.apply(
            "rollback-killed.txt",
            operation="create",
            expected_before=FileState.absent(),
            candidate_proof=candidate,
            candidate_mode=0o644,
        )
        temporary_name = self.broker.issue_temporary_name()
        process_id = os.fork()
        if process_id == 0:
            self.broker._fault_hook = (  # noqa: SLF001 - process-loss fault fixture
                lambda phase: os._exit(24)
                if phase == "after_rollback_atomic_commit"
                else None
            )
            self.broker.rollback(receipt, temporary_name=temporary_name)
            os._exit(0)
        _, status = os.waitpid(process_id, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 24)
        self.assertFalse((self.root / "rollback-killed.txt").exists())
        orphan = self.root / temporary_name
        self.assertEqual(orphan.read_bytes(), b"created before rollback kill\n")
        self.assertTrue(
            self.broker.cleanup_temporary("rollback-killed.txt", temporary_name)
        )
        self.assert_no_temp()

    def test_rollback_ready_hook_must_commit_before_any_workspace_mutation(self) -> None:
        target = self.root / "existing.txt"
        before = file_state(target)
        captured: list[tuple[FileState, object]] = []

        class DurableCommitFailed(Exception):
            pass

        def reject(state: FileState, proof: object) -> None:
            captured.append((state, proof))
            raise DurableCommitFailed()

        with self.assertRaises(DurableCommitFailed):
            self.broker.apply(
                "existing.txt",
                operation="replace",
                expected_before=before,
                candidate_proof=self.proof(b"after\n"),
                rollback_ready_hook=reject,
            )
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0][0], before)
        self.assertIsNotNone(captured[0][1])
        self.assertEqual(target.read_bytes(), b"before\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
        self.assert_no_temp()

    def test_observe_exposes_only_exact_content_free_reconciliation_state(self) -> None:
        self.assertEqual(self.broker.observe("missing.txt"), FileState.absent())
        self.assertEqual(self.broker.observe("existing.txt"), file_state(self.root / "existing.txt"))
        self.assert_code("ECO_PROTECTED_PATH", lambda: self.broker.observe(".env"))

    def test_two_brokers_competing_to_create_have_one_atomic_winner(self) -> None:
        first = LinuxWorkspaceWriteBroker(self.root, self.store, maximum_file_bytes=128)
        second = LinuxWorkspaceWriteBroker(self.root, self.store, maximum_file_bytes=128)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def create(broker: LinuxWorkspaceWriteBroker, content: bytes) -> None:
            barrier.wait()
            try:
                broker.apply(
                    "winner.txt",
                    operation="create",
                    expected_before=FileState.absent(),
                    candidate_proof=self.proof(content),
                )
                outcomes.append("success")
            except BrokerError as exc:
                outcomes.append(exc.code)

        threads = [
            threading.Thread(target=create, args=(first, b"first\n")),
            threading.Thread(target=create, args=(second, b"second\n")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        first.close()
        second.close()
        self.assertEqual(sorted(outcomes), ["ECO_EXPECTED_BEFORE_MISMATCH", "success"])
        self.assertIn((self.root / "winner.txt").read_bytes(), {b"first\n", b"second\n"})
        self.assert_no_temp()

    def test_rollback_refuses_content_mode_and_hardlink_drift(self) -> None:
        target = self.root / "existing.txt"
        before = file_state(target)
        receipt = self.broker.apply(
            "existing.txt",
            operation="replace",
            expected_before=before,
            candidate_proof=self.proof(b"after\n"),
            candidate_mode=0o600,
        )
        target.write_bytes(b"unrelated\n")
        self.assert_code("ECO_ROLLBACK_CONFLICT", lambda: self.broker.rollback(receipt))
        self.assertEqual(target.read_bytes(), b"unrelated\n")

        target.write_bytes(b"after\n")
        os.chmod(target, 0o644)
        self.assert_code("ECO_ROLLBACK_CONFLICT", lambda: self.broker.rollback(receipt))
        os.chmod(target, 0o600)
        alias = self.outside / "rollback-alias.txt"
        os.link(target, alias)
        self.assert_code("ECO_HARDLINK_DENIED", lambda: self.broker.rollback(receipt))
        self.assertEqual(target.read_bytes(), b"after\n")

    def test_tampered_rollback_proof_is_rejected_without_mutation(self) -> None:
        target = self.root / "existing.txt"
        receipt = self.broker.apply(
            "existing.txt",
            operation="replace",
            expected_before=file_state(target),
            candidate_proof=self.proof(b"after\n"),
        )
        assert receipt.rollback_proof is not None
        tampered = replace(
            receipt,
            rollback_proof=replace(receipt.rollback_proof, token="0" * 64),
        )
        self.assert_code("ECO_ROLLBACK_PROOF_INVALID", lambda: self.broker.rollback(tampered))
        self.assertEqual(target.read_bytes(), b"after\n")

    def test_close_is_idempotent_and_fails_closed(self) -> None:
        self.broker.close()
        self.broker.close()
        self.assert_code(
            "ECO_WRITE_BROKER_CLOSED",
            lambda: self.broker.apply(
                "new.txt",
                operation="create",
                expected_before=FileState.absent(),
                candidate_proof=self.proof(b"new\n"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
