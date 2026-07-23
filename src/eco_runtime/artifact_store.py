from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Mapping

from .digests import canonical_json
from .errors import RuntimeStoreError


ARTIFACT_STORE_VERSION = 1
_META_NAME = "store-meta.json"
_LOCK_NAME = "store.lock"
_OBJECTS_NAME = "objects"
_TEMP_NAME = "tmp"
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_SHARD_RE = re.compile(r"^[a-f0-9]{2}$")
_TEMP_RE = re.compile(r"^put-[a-f0-9]{32}\.tmp$")
_ARTIFACT_REF_RE = re.compile(
    r"^artifact://(?!\.\.?(?:/|$))(?!.*?/\.\.?(?:/|$))(?!.*//)"
    r"(?!.*\\)(?!.*%2[fF]|.*%5[cC])[A-Za-z0-9][A-Za-z0-9._:/-]{0,4095}$"
)


@dataclass(frozen=True)
class ArtifactAvailabilityProof:
    """Content-free evidence that one exact object was installed by this store."""

    storage_ref: str
    sha256: str
    byte_length: int
    key_id: str
    token: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "storageRef": self.storage_ref,
            "sha256": self.sha256,
            "byteLength": self.byte_length,
            "keyId": self.key_id,
            "token": self.token,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ArtifactAvailabilityProof:
        try:
            return cls(
                storage_ref=value["storageRef"],
                sha256=value["sha256"],
                byte_length=value["byteLength"],
                key_id=value["keyId"],
                token=value["token"],
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact availability proof is invalid"
            ) from exc


class ContentAddressedArtifactStore:
    """Private, durable, content-addressed storage for runtime artifact bytes.

    The returned proof contains no filesystem location. The proof key, private
    root, and process boundary are part of the trusted composition root.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        proof_key: bytes,
        key_id: str,
        forbidden_root: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(proof_key, bytes) or len(proof_key) < 32:
            raise ValueError("proof_key must contain at least 32 bytes")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        supplied_root = Path(root)
        if supplied_root.is_symlink():
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_LOCATION_DENIED", "Artifact store root cannot be a symbolic link"
            )
        resolved_root = supplied_root.resolve(strict=False)
        if forbidden_root is not None:
            forbidden = Path(forbidden_root).resolve(strict=False)
            if self._contains(forbidden, resolved_root) or self._contains(resolved_root, forbidden):
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_STORE_LOCATION_DENIED",
                    "Artifact store and governed repository must not overlap",
                )

        self._root = resolved_root
        self._proof_key = proof_key
        self._key_id = key_id
        self._thread_lock = threading.RLock()
        self._closed = False
        self._create_private_directory(self._root)
        self._require_private_directory(self._root)
        self._objects = self._root / _OBJECTS_NAME
        self._temporary = self._root / _TEMP_NAME
        self._create_private_directory(self._objects)
        self._create_private_directory(self._temporary)
        self._require_private_directory(self._objects)
        self._require_private_directory(self._temporary)
        self._lock_path = self._root / _LOCK_NAME
        self._lock_fd = self._open_control_file(self._lock_path)

        try:
            with self._exclusive_lock():
                self._collect_orphaned_temporary_locked()
                self._load_or_create_metadata()
                self._verify_locked()
        except Exception:
            os.close(self._lock_fd)
            self._closed = True
            raise

    @staticmethod
    def _contains(parent: Path, child: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _create_private_directory(path: Path) -> None:
        existed = path.exists()
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix" and not existed:
            os.chmod(path, 0o700)

    @staticmethod
    def _require_private_directory(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_PERMISSIONS", "Artifact store directory is not trusted"
            )
        if os.name == "posix" and info.st_mode & 0o077:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_PERMISSIONS", "Artifact store directory is not private"
            )

    @staticmethod
    def _open_flags(*, writable: bool) -> int:
        flags = os.O_RDWR if writable else os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return flags

    def _open_control_file(self, path: Path) -> int:
        flags = self._open_flags(writable=True) | os.O_CREAT
        descriptor = os.open(path, flags, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or (
            os.name == "posix" and (info.st_mode & 0o077 or info.st_nlink != 1)
        ):
            os.close(descriptor)
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_PERMISSIONS", "Artifact store control file is not private"
            )
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        return descriptor

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            if self._closed:
                raise RuntimeStoreError("ECO_ARTIFACT_STORE_CLOSED", "Artifact store is closed")
            if os.name == "posix":
                import fcntl

                fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def close(self) -> None:
        with self._thread_lock:
            if not self._closed:
                os.close(self._lock_fd)
                self._closed = True

    def __enter__(self) -> ContentAddressedArtifactStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name != "posix":
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_WRITE_FAILED", "Artifact bytes could not be persisted"
                )
            view = view[written:]

    def _metadata_payload(self, store_id: str) -> dict[str, Any]:
        return {
            "domain": "eco-artifact-store-meta-v1",
            "version": ARTIFACT_STORE_VERSION,
            "storeId": store_id,
            "keyId": self._key_id,
        }

    def _metadata_hmac(self, payload: Mapping[str, Any]) -> str:
        return hmac.new(
            self._proof_key,
            canonical_json(dict(payload)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _load_or_create_metadata(self) -> None:
        path = self._root / _META_NAME
        if not path.exists():
            unexpected = set(os.listdir(self._root)) - {
                _LOCK_NAME,
                _OBJECTS_NAME,
                _TEMP_NAME,
            }
            if unexpected or any(self._objects.iterdir()) or any(self._temporary.iterdir()):
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_STORE_CORRUPT", "Artifact store identity is missing"
                )
            store_id = secrets.token_hex(16)
            payload = self._metadata_payload(store_id)
            encoded = canonical_json({**payload, "hmac": self._metadata_hmac(payload)}).encode("utf-8")
            temporary = self._temporary / f"put-{secrets.token_hex(16)}.tmp"
            descriptor = os.open(
                temporary,
                self._open_flags(writable=True) | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                self._write_all(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError:
                pass
            finally:
                temporary.unlink(missing_ok=True)
            self._fsync_directory(self._root)
            self._fsync_directory(self._temporary)

        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ValueError("not a regular file")
            if os.name == "posix" and (info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError("unsafe file metadata")
            encoded = path.read_bytes()
            metadata = json.loads(encoded.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_CORRUPT", "Artifact store identity is invalid"
            ) from exc
        required = {"domain", "version", "storeId", "keyId", "hmac"}
        if set(metadata) != required:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_CORRUPT", "Artifact store identity is invalid"
            )
        payload = {name: metadata[name] for name in required - {"hmac"}}
        if (
            payload.get("domain") != "eco-artifact-store-meta-v1"
            or payload.get("version") != ARTIFACT_STORE_VERSION
            or payload.get("keyId") != self._key_id
            or not isinstance(payload.get("storeId"), str)
            or re.fullmatch(r"[a-f0-9]{32}", payload["storeId"]) is None
            or not isinstance(metadata["hmac"], str)
            or not hmac.compare_digest(metadata["hmac"], self._metadata_hmac(payload))
            or encoded != canonical_json({**payload, "hmac": metadata["hmac"]}).encode("utf-8")
        ):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_CORRUPT", "Artifact store identity authentication failed"
            )
        self._store_id = payload["storeId"]

    def _object_path(self, digest: str) -> Path:
        if _DIGEST_RE.fullmatch(digest) is None:
            raise RuntimeStoreError("ECO_ARTIFACT_DIGEST_INVALID", "Artifact digest is invalid")
        return self._objects / digest[:2] / digest[2:4] / digest

    def _proof_payload(
        self, *, storage_ref: str, digest: str, byte_length: int
    ) -> dict[str, Any]:
        return {
            "domain": "eco-artifact-availability-v1",
            "version": ARTIFACT_STORE_VERSION,
            "storeId": self._store_id,
            "keyId": self._key_id,
            "storageRef": storage_ref,
            "sha256": digest,
            "byteLength": byte_length,
        }

    def _make_proof(
        self, *, storage_ref: str, digest: str, byte_length: int
    ) -> ArtifactAvailabilityProof:
        payload = self._proof_payload(
            storage_ref=storage_ref, digest=digest, byte_length=byte_length
        )
        token = hmac.new(
            self._proof_key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return ArtifactAvailabilityProof(storage_ref, digest, byte_length, self._key_id, token)

    @staticmethod
    def _iter_chunks(source: BinaryIO | Iterable[bytes], chunk_size: int) -> Iterator[bytes]:
        if isinstance(source, (bytes, bytearray, memoryview)):
            yield bytes(source)
            return
        reader = getattr(source, "read", None)
        if callable(reader):
            while True:
                chunk = reader(chunk_size)
                if chunk == b"":
                    return
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise TypeError("binary source read() must return bytes")
                yield bytes(chunk)
        else:
            for chunk in source:
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    raise TypeError("artifact chunks must contain bytes")
                yield bytes(chunk)

    def put(
        self,
        source: BinaryIO | Iterable[bytes],
        *,
        storage_ref: str | None = None,
        expected_sha256: str | None = None,
        expected_byte_length: int | None = None,
        max_bytes: int | None = None,
        chunk_size: int = 1024 * 1024,
    ) -> ArtifactAvailabilityProof:
        """Stream, fsync, and atomically install one object, then return opaque proof."""

        if expected_sha256 is not None and _DIGEST_RE.fullmatch(expected_sha256) is None:
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        if expected_byte_length is not None and (
            not isinstance(expected_byte_length, int) or expected_byte_length < 0
        ):
            raise ValueError("expected_byte_length must be a non-negative integer")
        if max_bytes is not None and (not isinstance(max_bytes, int) or max_bytes < 0):
            raise ValueError("max_bytes must be a non-negative integer")
        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")
        if storage_ref is not None and (
            not isinstance(storage_ref, str) or _ARTIFACT_REF_RE.fullmatch(storage_ref) is None
        ):
            raise ValueError("storage_ref must be a safe artifact reference")

        with self._exclusive_lock():
            temporary = self._temporary / f"put-{secrets.token_hex(16)}.tmp"
            descriptor = os.open(
                temporary,
                self._open_flags(writable=True) | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            digest = hashlib.sha256()
            byte_length = 0
            try:
                if os.name == "posix":
                    os.fchmod(descriptor, 0o600)
                for chunk in self._iter_chunks(source, chunk_size):
                    byte_length += len(chunk)
                    if max_bytes is not None and byte_length > max_bytes:
                        raise RuntimeStoreError(
                            "ECO_ARTIFACT_TOO_LARGE", "Artifact exceeds the approved byte limit"
                        )
                    digest.update(chunk)
                    self._write_all(descriptor, chunk)
                object_digest = digest.hexdigest()
                if expected_sha256 is not None and object_digest != expected_sha256:
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_DIGEST_MISMATCH", "Artifact content digest does not match"
                    )
                if expected_byte_length is not None and byte_length != expected_byte_length:
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_SIZE_MISMATCH", "Artifact byte length does not match"
                    )
                os.fsync(descriptor)
                final = self._object_path(object_digest)
                self._create_private_directory(final.parent.parent)
                self._create_private_directory(final.parent)
                self._require_private_directory(final.parent.parent)
                self._require_private_directory(final.parent)
                try:
                    os.link(temporary, final, follow_symlinks=False)
                except FileExistsError:
                    self._verify_object(final, object_digest, byte_length)
                else:
                    self._fsync_directory(final.parent)
                    self._fsync_directory(final.parent.parent)
                    self._fsync_directory(self._objects)
            finally:
                os.close(descriptor)
                temporary.unlink(missing_ok=True)
                self._fsync_directory(self._temporary)

            reference = storage_ref or f"artifact://sha256/{object_digest}"
            proof = self._make_proof(
                storage_ref=reference, digest=object_digest, byte_length=byte_length
            )
            self._verify_object(self._object_path(object_digest), object_digest, byte_length)
            return proof

    def _require_proof(self, proof: ArtifactAvailabilityProof) -> None:
        if not isinstance(proof, ArtifactAvailabilityProof):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact availability proof is invalid"
            )
        if (
            not isinstance(proof.storage_ref, str)
            or _ARTIFACT_REF_RE.fullmatch(proof.storage_ref) is None
            or not isinstance(proof.sha256, str)
            or _DIGEST_RE.fullmatch(proof.sha256) is None
            or not isinstance(proof.byte_length, int)
            or proof.byte_length < 0
            or not isinstance(proof.key_id, str)
            or proof.key_id != self._key_id
            or not isinstance(proof.token, str)
            or re.fullmatch(r"[a-f0-9]{64}", proof.token) is None
        ):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact availability proof is invalid"
            )
        payload = self._proof_payload(
            storage_ref=proof.storage_ref,
            digest=proof.sha256,
            byte_length=proof.byte_length,
        )
        expected = hmac.new(
            self._proof_key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, proof.token):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact availability proof authentication failed"
            )

    def _open_verified_descriptor(
        self, path: Path, expected_digest: str, expected_byte_length: int | None = None
    ) -> tuple[int, int]:
        try:
            descriptor = os.open(path, self._open_flags(writable=False))
        except OSError as exc:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_UNAVAILABLE", "Artifact object is unavailable"
            ) from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or (os.name == "posix" and (before.st_mode & 0o077 or before.st_nlink != 1))
            ):
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_STORE_CORRUPT", "Artifact object metadata is unsafe"
                )
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                length += len(chunk)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or digest.hexdigest() != expected_digest
                or length != before.st_size
                or (expected_byte_length is not None and length != expected_byte_length)
            ):
                raise RuntimeStoreError(
                    "ECO_ARTIFACT_STORE_CORRUPT", "Artifact object verification failed"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
            return descriptor, length
        except Exception:
            os.close(descriptor)
            raise

    def _verify_object(
        self, path: Path, expected_digest: str, expected_byte_length: int | None = None
    ) -> int:
        descriptor, length = self._open_verified_descriptor(
            path, expected_digest, expected_byte_length
        )
        os.close(descriptor)
        return length

    def verify_availability(self, proof: ArtifactAvailabilityProof) -> None:
        with self._exclusive_lock():
            self._require_proof(proof)
            self._verify_object(self._object_path(proof.sha256), proof.sha256, proof.byte_length)

    def verify_record(self, *, storage_ref: str, sha256: str, byte_length: int) -> None:
        """Verify bytes referenced by already-authenticated runtime metadata."""

        if not isinstance(storage_ref, str) or _ARTIFACT_REF_RE.fullmatch(storage_ref) is None:
            raise RuntimeStoreError("ECO_ARTIFACT_PROOF_INVALID", "Artifact reference is invalid")
        if not isinstance(byte_length, int) or byte_length < 0:
            raise RuntimeStoreError("ECO_ARTIFACT_PROOF_INVALID", "Artifact length is invalid")
        with self._exclusive_lock():
            self._verify_object(self._object_path(sha256), sha256, byte_length)

    def proof_for_record(
        self, *, storage_ref: str, sha256: str, byte_length: int
    ) -> ArtifactAvailabilityProof:
        """Reissue availability proof for authenticated runtime metadata.

        The caller is responsible for authenticating the record that supplies
        ``storage_ref``, ``sha256``, and ``byte_length``.  This store does not
        trust those claims on their own: it reopens the digest-addressed object,
        hashes every byte, verifies its exact length and stable file metadata,
        and only then signs a fresh availability proof.
        """

        if not isinstance(storage_ref, str) or _ARTIFACT_REF_RE.fullmatch(storage_ref) is None:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact reference is invalid"
            )
        if not isinstance(sha256, str) or _DIGEST_RE.fullmatch(sha256) is None:
            raise RuntimeStoreError("ECO_ARTIFACT_DIGEST_INVALID", "Artifact digest is invalid")
        if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_PROOF_INVALID", "Artifact length is invalid"
            )

        with self._exclusive_lock():
            self._verify_object(self._object_path(sha256), sha256, byte_length)
            return self._make_proof(
                storage_ref=storage_ref,
                digest=sha256,
                byte_length=byte_length,
            )

    @contextmanager
    def open_verified(self, proof: ArtifactAvailabilityProof) -> Iterator[BinaryIO]:
        """Open only after proof and full content verification; never expose the CAS path."""

        with self._exclusive_lock():
            self._require_proof(proof)
            path = self._object_path(proof.sha256)
            descriptor, _ = self._open_verified_descriptor(
                path, proof.sha256, proof.byte_length
            )
            stream = os.fdopen(descriptor, "rb", closefd=True)
            try:
                yield stream
            finally:
                stream.close()

    def _collect_orphaned_temporary_locked(self) -> int:
        removed = 0
        with os.scandir(self._temporary) as entries:
            for entry in entries:
                if _TEMP_RE.fullmatch(entry.name) is None or not entry.is_file(
                    follow_symlinks=False
                ):
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_STORE_CORRUPT", "Artifact temporary inventory is unsafe"
                    )
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or (
                    os.name == "posix" and info.st_nlink != 1
                ):
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_STORE_CORRUPT", "Artifact temporary object is unsafe"
                    )
                os.unlink(entry.path)
                removed += 1
        if removed:
            self._fsync_directory(self._temporary)
        return removed

    def collect_orphaned_temporary(self) -> int:
        """Remove only uninstalled temp files while holding the cross-process lock."""

        with self._exclusive_lock():
            return self._collect_orphaned_temporary_locked()

    def _verify_locked(self) -> None:
        expected_root = {_META_NAME, _LOCK_NAME, _OBJECTS_NAME, _TEMP_NAME}
        if set(os.listdir(self._root)) != expected_root:
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_CORRUPT", "Artifact store inventory is unexpected"
            )
        self._require_private_directory(self._root)
        self._require_private_directory(self._objects)
        self._require_private_directory(self._temporary)
        with os.scandir(self._objects) as level_ones:
            for level_one in level_ones:
                if _SHARD_RE.fullmatch(level_one.name) is None or not level_one.is_dir(
                    follow_symlinks=False
                ):
                    raise RuntimeStoreError(
                        "ECO_ARTIFACT_STORE_CORRUPT", "Artifact object inventory is malformed"
                    )
                self._require_private_directory(Path(level_one.path))
                with os.scandir(level_one.path) as level_twos:
                    for level_two in level_twos:
                        if _SHARD_RE.fullmatch(level_two.name) is None or not level_two.is_dir(
                            follow_symlinks=False
                        ):
                            raise RuntimeStoreError(
                                "ECO_ARTIFACT_STORE_CORRUPT",
                                "Artifact object inventory is malformed",
                            )
                        self._require_private_directory(Path(level_two.path))
                        with os.scandir(level_two.path) as items:
                            for item in items:
                                digest = item.name
                                if (
                                    _DIGEST_RE.fullmatch(digest) is None
                                    or digest[:2] != level_one.name
                                    or digest[2:4] != level_two.name
                                    or not item.is_file(follow_symlinks=False)
                                ):
                                    raise RuntimeStoreError(
                                        "ECO_ARTIFACT_STORE_CORRUPT",
                                        "Artifact object inventory is malformed",
                                    )
                                self._verify_object(Path(item.path), digest)

    def verify(self) -> None:
        """Re-hash every installed object and verify the private store layout."""

        with self._exclusive_lock():
            self._verify_locked()
