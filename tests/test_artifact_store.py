from __future__ import annotations

import hashlib
import io
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from eco_runtime.artifact_store import (
    ArtifactAvailabilityProof,
    ContentAddressedArtifactStore,
)
from eco_runtime.errors import RuntimeStoreError


KEY = b"artifact-proof-key-for-tests-32bytes!"


class ArtifactStoreTests(unittest.TestCase):
    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def make_store(self, root: Path) -> ContentAddressedArtifactStore:
        return ContentAddressedArtifactStore(root, proof_key=KEY, key_id="test-key-1")

    def test_streams_installs_and_returns_content_free_proof(self) -> None:
        content = (b"durable artifact\n" * 100_000) + b"tail"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                proof = store.put(
                    io.BytesIO(content),
                    storage_ref="artifact://runs/run-1/artifact-1",
                    expected_sha256=hashlib.sha256(content).hexdigest(),
                    expected_byte_length=len(content),
                    chunk_size=997,
                )
                self.assertEqual(proof.sha256, hashlib.sha256(content).hexdigest())
                self.assertEqual(proof.byte_length, len(content))
                self.assertNotIn(str(root), repr(proof))
                self.assertNotIn("durable artifact", repr(proof))
                store.verify_availability(proof)
                with store.open_verified(proof) as stream:
                    self.assertEqual(stream.read(), content)

            object_path = root / "objects" / proof.sha256[:2] / proof.sha256[2:4] / proof.sha256
            self.assertTrue(object_path.is_file())
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(object_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)

    def test_reopen_authenticates_metadata_and_verifies_existing_object(self) -> None:
        content = b"reopen me"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                proof = store.put(content)
            with self.make_store(root) as reopened:
                reopened.verify()
                reopened.verify_availability(proof)
                self.assertEqual(proof.storage_ref, f"artifact://sha256/{proof.sha256}")

            self.assert_code(
                "ECO_ARTIFACT_STORE_CORRUPT",
                lambda: ContentAddressedArtifactStore(
                    root,
                    proof_key=b"different-proof-key-for-tests-32b!",
                    key_id="test-key-1",
                ),
            )

    def test_duplicate_content_is_idempotent_and_keeps_one_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                first = store.put([b"same", b" content"])
                second = store.put(b"same content")
                self.assertEqual(first.sha256, second.sha256)
                self.assertEqual(first.token, second.token)
                objects = [path for path in (root / "objects").rglob("*") if path.is_file()]
                self.assertEqual(len(objects), 1)

    def test_two_store_instances_serialize_duplicate_install(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            first_store = self.make_store(root)
            second_store = self.make_store(root)
            barrier = threading.Barrier(2)
            proofs: list[ArtifactAvailabilityProof] = []

            def install(store: ContentAddressedArtifactStore) -> None:
                barrier.wait()
                proofs.append(store.put([b"concurrent ", b"content"]))

            threads = [
                threading.Thread(target=install, args=(first_store,)),
                threading.Thread(target=install, args=(second_store,)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            first_store.close()
            second_store.close()

            self.assertEqual(len(proofs), 2)
            self.assertEqual(proofs[0], proofs[1])
            objects = [path for path in (root / "objects").rglob("*") if path.is_file()]
            self.assertEqual(len(objects), 1)

    def test_source_failure_cleans_temporary_file_without_install(self) -> None:
        def failing_source():
            yield b"partial"
            raise OSError("synthetic source failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                with self.assertRaises(OSError):
                    store.put(failing_source())
                self.assertEqual(list((root / "tmp").iterdir()), [])
                self.assertEqual(
                    [path for path in (root / "objects").rglob("*") if path.is_file()], []
                )

    def test_expected_digest_size_and_maximum_fail_without_installing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                self.assert_code(
                    "ECO_ARTIFACT_DIGEST_MISMATCH",
                    lambda: store.put(b"payload", expected_sha256="0" * 64),
                )
                self.assert_code(
                    "ECO_ARTIFACT_SIZE_MISMATCH",
                    lambda: store.put(b"payload", expected_byte_length=8),
                )
                self.assert_code(
                    "ECO_ARTIFACT_TOO_LARGE", lambda: store.put(b"payload", max_bytes=6)
                )
                self.assertEqual(
                    [path for path in (root / "objects").rglob("*") if path.is_file()], []
                )
                self.assertEqual(list((root / "tmp").iterdir()), [])

    def test_tampered_proof_or_object_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root) as store:
                proof = store.put(b"trusted")
                tampered = ArtifactAvailabilityProof(
                    proof.storage_ref,
                    proof.sha256,
                    proof.byte_length + 1,
                    proof.key_id,
                    proof.token,
                )
                self.assert_code(
                    "ECO_ARTIFACT_PROOF_INVALID", lambda: store.verify_availability(tampered)
                )
                object_path = (
                    root / "objects" / proof.sha256[:2] / proof.sha256[2:4] / proof.sha256
                )
                object_path.write_bytes(b"attacker")
                self.assert_code(
                    "ECO_ARTIFACT_STORE_CORRUPT", lambda: store.verify_availability(proof)
                )

    def test_forbidden_repository_overlap_is_denied_in_both_directions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repository = base / "repository"
            repository.mkdir()
            self.assert_code(
                "ECO_ARTIFACT_STORE_LOCATION_DENIED",
                lambda: ContentAddressedArtifactStore(
                    repository / ".runtime-artifacts",
                    proof_key=KEY,
                    key_id="test-key-1",
                    forbidden_root=repository,
                ),
            )
            self.assert_code(
                "ECO_ARTIFACT_STORE_LOCATION_DENIED",
                lambda: ContentAddressedArtifactStore(
                    base,
                    proof_key=KEY,
                    key_id="test-key-1",
                    forbidden_root=repository,
                ),
            )

    def test_reopen_collects_only_well_formed_crash_temporary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root):
                pass
            orphan = root / "tmp" / ("put-" + "a" * 32 + ".tmp")
            orphan.write_bytes(b"partial")
            if os.name == "posix":
                os.chmod(orphan, 0o600)
            with self.make_store(root):
                self.assertFalse(orphan.exists())

            unsafe = root / "tmp" / "unexpected"
            unsafe.write_bytes(b"do not delete blindly")
            self.assert_code(
                "ECO_ARTIFACT_STORE_CORRUPT", lambda: self.make_store(root)
            )
            self.assertTrue(unsafe.exists())

    def test_first_initialization_recovers_a_well_formed_crash_temp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            objects = root / "objects"
            temporary = root / "tmp"
            objects.mkdir(parents=True, mode=0o700)
            temporary.mkdir(mode=0o700)
            if os.name == "posix":
                os.chmod(root, 0o700)
                os.chmod(objects, 0o700)
                os.chmod(temporary, 0o700)
            orphan = temporary / ("put-" + "b" * 32 + ".tmp")
            orphan.write_bytes(b"partial store metadata")
            if os.name == "posix":
                os.chmod(orphan, 0o600)

            with self.make_store(root) as store:
                store.verify()
            self.assertFalse(orphan.exists())
            self.assertTrue((root / "store-meta.json").is_file())

    def test_metadata_tamper_and_unsafe_storage_reference_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "artifacts"
            with self.make_store(root):
                pass
            metadata = root / "store-meta.json"
            original = metadata.read_text(encoding="utf-8")
            metadata.write_text(original.replace("test-key-1", "test-key-2"), encoding="utf-8")
            self.assert_code(
                "ECO_ARTIFACT_STORE_CORRUPT", lambda: self.make_store(root)
            )

        with tempfile.TemporaryDirectory() as directory:
            with self.make_store(Path(directory) / "artifacts") as store:
                with self.assertRaises(ValueError):
                    store.put(b"data", storage_ref="artifact://runs/../secret")


if __name__ == "__main__":
    unittest.main()
