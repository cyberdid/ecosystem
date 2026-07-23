from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path

from eco_runtime.broker import RepositoryReadBroker
from eco_runtime.errors import BrokerError
from eco_runtime.repository import repository_root_identity
from tests.test_policy import (
    repository_snapshot,
)


class RepositoryReadBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.outside = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        outside_root = Path(self.outside.name)

        files = {
            "README.md": b"hello, broker\n",
            "binary.bin": b"abc\x00def",
            "invalid.txt": b"\xff\xfe",
            "large.txt": b"x" * 129,
            "mutable.txt": b"original",
            "confidential.txt": b"confidential",
            "token.txt": b"token-value",
        }
        for path, content in files.items():
            (self.root / path).write_bytes(content)

        (self.root / "directory").mkdir()
        os.mkfifo(self.root / "pipe")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "config").write_bytes(b"token=x")
        (self.root / ".env").write_bytes(b"SECRET=x")
        (self.root / "private.pem").write_bytes(b"key")

        outside_file = outside_root / "outside.txt"
        outside_file.write_bytes(b"outside-secret")
        os.symlink(outside_file, self.root / "link.txt")
        os.symlink(outside_root, self.root / "linked-dir")
        os.link(outside_file, self.root / "innocent.md")

        snapshot = repository_snapshot(
            root_identity_digest=repository_root_identity(self.root),
            content_digest=hashlib.sha256(files["README.md"]).hexdigest(),
            byte_length=len(files["README.md"]),
        )
        entries = snapshot["spec"]["entries"]

        def add(path: str, content: bytes, *, data_class: str = "D1", byte_length: int | None = None) -> None:
            entries.append(
                {
                    "path": path,
                    "contentDigest": hashlib.sha256(content).hexdigest(),
                    "byteLength": len(content) if byte_length is None else byte_length,
                    "dataClass": data_class,
                    "trust": "P1",
                    "classificationAuthority": "operator",
                }
            )

        for path in ("binary.bin", "invalid.txt", "large.txt", "mutable.txt"):
            add(path, files[path])
        add("confidential.txt", files["confidential.txt"], data_class="D2")
        add("token.txt", files["token.txt"], data_class="D4")
        add("directory", b"", byte_length=0)
        add("pipe", b"", byte_length=0)
        add(".git/config", b"token=x")
        add(".env", b"SECRET=x")
        add("private.pem", b"key")
        add("link.txt", b"outside-secret")
        add("linked-dir/outside.txt", b"outside-secret")
        add("innocent.md", b"outside-secret")
        add("does-not-exist.txt", b"")
        self.snapshot = snapshot

        self.broker = RepositoryReadBroker(
            self.root,
            self.snapshot,
            maximum_file_bytes=128,
        )

    def tearDown(self) -> None:
        self.broker.close()
        self.temp.cleanup()
        self.outside.cleanup()

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(BrokerError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def execute(self, path: str):
        return self.broker.read(path)

    def test_reads_one_regular_utf8_file_and_returns_bound_untrusted_content(self) -> None:
        result = self.execute("README.md")
        expected = b"hello, broker\n"
        self.assertEqual(result.untrusted_content, expected.decode())
        self.assertEqual(result.byte_length, len(expected))
        self.assertEqual(result.sha256, hashlib.sha256(expected).hexdigest())
        self.assertEqual(result.data_class, "D1")

    def test_final_and_intermediate_symlinks_cannot_escape_or_alias(self) -> None:
        self.assert_code("ECO_PATH_ESCAPE", lambda: self.execute("link.txt"))
        self.assert_code("ECO_PATH_ESCAPE", lambda: self.execute("linked-dir/outside.txt"))

    def test_hardlink_alias_is_denied_even_under_safe_name(self) -> None:
        self.assert_code("ECO_HARDLINK_DENIED", lambda: self.execute("innocent.md"))

    def test_protected_paths_are_denied_by_filesystem_reader(self) -> None:
        for path in (".git/config", ".env", "private.pem"):
            with self.subTest(path=path):
                self.assert_code("ECO_PROTECTED_PATH", lambda path=path: self.execute(path))

    def test_unsnapshotted_path_is_denied(self) -> None:
        self.assert_code(
            "ECO_REPOSITORY_PATH_UNSNAPSHOTTED",
            lambda: self.execute("unknown.txt"),
        )

    def test_data_class_is_metadata_not_authority_in_filesystem_reader(self) -> None:
        result = self.execute("confidential.txt")
        self.assertEqual(result.data_class, "D2")

    def test_directories_and_special_files_are_not_regular_files(self) -> None:
        for path in ("directory", "pipe"):
            with self.subTest(path=path):
                self.assert_code("ECO_NOT_REGULAR_FILE", lambda path=path: self.execute(path))

    def test_binary_invalid_utf8_and_oversized_files_are_denied(self) -> None:
        expected = {
            "binary.bin": "ECO_BINARY_FILE",
            "invalid.txt": "ECO_TEXT_ENCODING",
            "large.txt": "ECO_FILE_TOO_LARGE",
        }
        for path, code in expected.items():
            with self.subTest(path=path):
                self.assert_code(code, lambda path=path: self.execute(path))

    def test_changed_content_is_rejected_against_snapshot(self) -> None:
        (self.root / "mutable.txt").write_bytes(b"modified")
        self.assert_code("ECO_SNAPSHOT_CONTENT_MISMATCH", lambda: self.execute("mutable.txt"))

    def test_missing_file_has_sanitized_error_and_no_content(self) -> None:
        self.assert_code("ECO_FILE_NOT_FOUND", lambda: self.execute("does-not-exist.txt"))

    def test_filesystem_reader_has_no_policy_or_budget_authority(self) -> None:
        self.assertFalse(hasattr(self.broker, "_policy"))
        self.assertFalse(hasattr(self.broker, "_budget"))

    def test_caller_limit_is_enforced_without_spending_budget(self) -> None:
        self.assert_code(
            "ECO_FILE_TOO_LARGE",
            lambda: self.broker.read("README.md", maximum_bytes=1),
        )

    def test_close_is_idempotent_and_serialized_with_open(self) -> None:
        errors: list[str] = []
        barrier = threading.Barrier(2)

        def close() -> None:
            barrier.wait()
            try:
                self.broker.close()
            except Exception as exc:  # pragma: no cover - regression guard
                errors.append(type(exc).__name__)

        threads = [threading.Thread(target=close) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assert_code("ECO_BROKER_CLOSED", lambda: self.execute("README.md"))


if __name__ == "__main__":
    unittest.main()
