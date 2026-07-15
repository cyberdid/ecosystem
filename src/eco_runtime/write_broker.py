from __future__ import annotations

import codecs
import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
import sys
import threading
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Literal

from .artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from .errors import BrokerError, RuntimeStoreError
from .repository import protected_repository_path, root_identity_from_stat


_OPENAT2_SYSCALL = 437
_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_POLICY = (
    _RESOLVE_NO_XDEV | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS | _RESOLVE_BENEATH
)
_RENAME_NOREPLACE = 0x01
_RENAME_EXCHANGE = 0x02
_DIGEST_LENGTH = 64
_TEMP_PREFIX = ".eco-write-"
_TEMP_NAME = re.compile(r"\.eco-write-[0-9a-f]{64}\.tmp\Z")


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class FileState:
    """Content and mode expectation for one regular UTF-8 file, or absence."""

    state: Literal["absent", "present"]
    sha256: str | None = None
    byte_length: int | None = None
    mode: int | None = None

    @classmethod
    def absent(cls) -> FileState:
        return cls("absent")

    @classmethod
    def present(cls, sha256: str, byte_length: int, mode: int) -> FileState:
        return cls("present", sha256, byte_length, mode)


@dataclass(frozen=True)
class WorkspaceWriteResult:
    """A content-free receipt sufficient for an independently authorized rollback."""

    path: str
    operation: Literal["create", "replace"]
    before: FileState
    after: FileState
    candidate_proof: ArtifactAvailabilityProof
    rollback_proof: ArtifactAvailabilityProof | None


@dataclass(frozen=True)
class WorkspaceRollbackResult:
    path: str
    state: FileState
    changed: bool


@dataclass
class _ObservedFile:
    descriptor: int
    state: FileState
    stat_result: os.stat_result

    def close(self) -> None:
        os.close(self.descriptor)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino, left.st_mode) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
    )


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(left, field) == getattr(right, field) for field in fields)


class LinuxWorkspaceWriteBroker:
    """Descriptor-anchored Linux/WSL single-file create/replace broker.

    This object is deliberately not an authority boundary for policy, approval,
    budgets, or durable workflow state.  An orchestrator must perform those
    steps before calling :meth:`apply` or :meth:`rollback`.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        artifact_store: ContentAddressedArtifactStore,
        *,
        maximum_file_bytes: int = 1_048_576,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not sys.platform.startswith("linux"):
            raise BrokerError("ECO_WRITE_BROKER_UNSUPPORTED", "Linux openat2 backend is required")
        if os.uname().machine not in {"x86_64", "aarch64"}:
            raise BrokerError(
                "ECO_WRITE_BROKER_UNSUPPORTED", "Architecture lacks a tested openat2 profile"
            )
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be a ContentAddressedArtifactStore")
        if not isinstance(maximum_file_bytes, int) or maximum_file_bytes < 1:
            raise ValueError("maximum_file_bytes must be a positive integer")
        if fault_hook is not None and not callable(fault_hook):
            raise TypeError("fault_hook must be callable")

        supplied_root = Path(root)
        if supplied_root.is_symlink():
            raise BrokerError("ECO_ROOT_INVALID", "Broker root cannot be a symbolic link")
        trusted_root = supplied_root.resolve(strict=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            self._root_fd = os.open(trusted_root, flags)
        except OSError as exc:
            raise BrokerError("ECO_ROOT_INVALID", "Broker root is not a trusted directory") from exc
        root_info = os.fstat(self._root_fd)
        if not stat.S_ISDIR(root_info.st_mode):
            os.close(self._root_fd)
            raise BrokerError("ECO_ROOT_INVALID", "Broker root is not a directory")
        self._root_identity_digest = root_identity_from_stat(root_info)

        self._artifact_store = artifact_store
        self._maximum_file_bytes = maximum_file_bytes
        self._fault_hook = fault_hook
        self._lock = threading.RLock()
        self._closed = False
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long

    @property
    def root_identity_digest(self) -> str:
        return self._root_identity_digest

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                os.close(self._root_fd)
                self._closed = True

    def __enter__(self) -> LinuxWorkspaceWriteBroker:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _exclusive_operation(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise BrokerError("ECO_WRITE_BROKER_CLOSED", "Write broker is closed")
            import fcntl

            fcntl.flock(self._root_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self._root_fd, fcntl.LOCK_UN)

    def _phase(self, name: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(name)

    @staticmethod
    def _validate_path(path: str) -> str:
        invalid = (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or path == "."
            or path.startswith("./")
            or path.endswith("/")
            or "//" in path
            or "\\" in path
            or "://" in path
            or "%2f" in path.casefold()
            or "%5c" in path.casefold()
        )
        if not invalid:
            try:
                invalid = (
                    len(path.encode("utf-8")) > 4096
                    or any(segment in {"", ".", ".."} for segment in path.split("/"))
                    or any(ord(character) < 32 or ord(character) == 127 for character in path)
                    or unicodedata.normalize("NFC", path) != path
                )
            except UnicodeEncodeError:
                invalid = True
        if invalid:
            raise BrokerError(
                "ECO_WRITE_REQUEST_INVALID", "Write path is not canonical repository-relative"
            )
        if protected_repository_path(path):
            raise BrokerError("ECO_PROTECTED_PATH", "Protected repository path is not writable")
        return path

    @staticmethod
    def _validate_state(value: FileState, *, allow_absent: bool) -> FileState:
        if not isinstance(value, FileState):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "File expectation is invalid")
        if value.state == "absent":
            if not allow_absent or any(
                item is not None for item in (value.sha256, value.byte_length, value.mode)
            ):
                raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Absent expectation is invalid")
            return value
        if value.state != "present":
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "File expectation state is invalid")
        if (
            not isinstance(value.sha256, str)
            or len(value.sha256) != _DIGEST_LENGTH
            or any(character not in "0123456789abcdef" for character in value.sha256)
            or not isinstance(value.byte_length, int)
            or isinstance(value.byte_length, bool)
            or value.byte_length < 0
            or not isinstance(value.mode, int)
            or isinstance(value.mode, bool)
            or not 0 <= value.mode <= 0o777
        ):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Present expectation is invalid")
        return value

    @staticmethod
    def _validate_mode(mode: int) -> int:
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o777:
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Candidate file mode is invalid")
        return mode

    def _openat2(self, directory_fd: int, path: str, flags: int) -> int:
        how = _OpenHow(flags=flags, mode=0, resolve=_RESOLVE_POLICY)
        result = self._libc.syscall(
            ctypes.c_long(_OPENAT2_SYSCALL),
            ctypes.c_int(directory_fd),
            ctypes.c_char_p(path.encode("utf-8")),
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )
        if result >= 0:
            return int(result)
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            code = "ECO_WRITE_BROKER_UNSUPPORTED"
        elif error in {errno.EXDEV, errno.ELOOP}:
            code = "ECO_PATH_ESCAPE"
        elif error == errno.ENOENT:
            code = "ECO_FILE_NOT_FOUND"
        elif error in {errno.EACCES, errno.EPERM}:
            code = "ECO_FILE_DENIED"
        elif error in {errno.ENOTDIR, errno.EISDIR}:
            code = "ECO_NOT_REGULAR_FILE"
        else:
            code = "ECO_FILE_OPEN_FAILED"
        raise BrokerError(code, "Workspace path could not be opened safely")

    def _open_parent(self, parent_path: str) -> int:
        try:
            descriptor = self._openat2(
                self._root_fd,
                parent_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
        except BrokerError as exc:
            if exc.code == "ECO_FILE_NOT_FOUND":
                raise BrokerError("ECO_PARENT_NOT_FOUND", "Workspace parent does not exist") from exc
            raise
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise BrokerError("ECO_PARENT_INVALID", "Workspace parent is not a directory")
        return descriptor

    def _assert_parent_stable(
        self, parent_path: str, parent_descriptor: int, expected: os.stat_result
    ) -> None:
        current = os.fstat(parent_descriptor)
        if not _same_identity(expected, current):
            raise BrokerError("ECO_PARENT_CHANGED", "Workspace parent identity changed")
        reopened = self._open_parent(parent_path)
        try:
            if not _same_identity(expected, os.fstat(reopened)):
                raise BrokerError("ECO_PARENT_CHANGED", "Workspace parent identity changed")
        finally:
            os.close(reopened)

    def _read_file_state(self, descriptor: int) -> tuple[FileState, os.stat_result]:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BrokerError("ECO_NOT_REGULAR_FILE", "Workspace target is not a regular file")
        if before.st_nlink != 1:
            raise BrokerError("ECO_HARDLINK_DENIED", "Workspace target has multiple hard links")
        if before.st_size > self._maximum_file_bytes:
            raise BrokerError("ECO_FILE_TOO_LARGE", "Workspace file exceeds the write limit")
        digest = hashlib.sha256()
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        byte_length = 0
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            while True:
                chunk = os.read(descriptor, min(65_536, self._maximum_file_bytes + 1 - byte_length))
                if not chunk:
                    break
                byte_length += len(chunk)
                if byte_length > self._maximum_file_bytes:
                    raise BrokerError("ECO_FILE_TOO_LARGE", "Workspace file exceeds the write limit")
                if b"\x00" in chunk:
                    raise BrokerError("ECO_BINARY_FILE", "Workspace file contains binary content")
                decoder.decode(chunk, final=False)
                digest.update(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise BrokerError("ECO_TEXT_ENCODING", "Workspace file is not valid UTF-8") from exc
        after = os.fstat(descriptor)
        if not _same_stable_file(before, after) or byte_length != after.st_size:
            raise BrokerError("ECO_FILE_CHANGED", "Workspace file changed during verification")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return (
            FileState.present(digest.hexdigest(), byte_length, stat.S_IMODE(after.st_mode)),
            after,
        )

    def _observe(self, parent_descriptor: int, name: str) -> _ObservedFile | None:
        try:
            descriptor = self._openat2(
                parent_descriptor,
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
            )
        except BrokerError as exc:
            if exc.code == "ECO_FILE_NOT_FOUND":
                return None
            raise
        try:
            state, info = self._read_file_state(descriptor)
            return _ObservedFile(descriptor, state, info)
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _require_expected(actual: _ObservedFile | None, expected: FileState) -> None:
        if expected.state == "absent":
            if actual is not None:
                raise BrokerError("ECO_EXPECTED_BEFORE_MISMATCH", "Workspace target is not absent")
            return
        if actual is None or actual.state != expected:
            raise BrokerError(
                "ECO_EXPECTED_BEFORE_MISMATCH", "Workspace target differs from expected before state"
            )

    def _persist_before(self, observed: _ObservedFile) -> ArtifactAvailabilityProof:
        before = os.fstat(observed.descriptor)
        os.lseek(observed.descriptor, 0, os.SEEK_SET)
        stream = os.fdopen(os.dup(observed.descriptor), "rb", closefd=True)
        try:
            proof = self._artifact_store.put(
                stream,
                expected_sha256=observed.state.sha256,
                expected_byte_length=observed.state.byte_length,
                max_bytes=self._maximum_file_bytes,
            )
        except RuntimeStoreError as exc:
            raise BrokerError(
                "ECO_ROLLBACK_ARTIFACT_FAILED", "Rollback bytes could not be persisted"
            ) from exc
        finally:
            stream.close()
        after = os.fstat(observed.descriptor)
        if not _same_stable_file(before, after):
            raise BrokerError("ECO_FILE_CHANGED", "Workspace file changed during rollback capture")
        os.lseek(observed.descriptor, 0, os.SEEK_SET)
        return proof

    @staticmethod
    def _write_all(descriptor: int, chunk: bytes) -> None:
        view = memoryview(chunk)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BrokerError("ECO_WRITE_FAILED", "Candidate bytes could not be written")
            view = view[written:]

    def issue_temporary_name(self) -> str:
        """Issue an unguessable name that can be durably bound before creation."""

        with self._lock:
            if self._closed:
                raise BrokerError("ECO_WRITE_BROKER_CLOSED", "Write broker is closed")
            return f"{_TEMP_PREFIX}{secrets.token_hex(32)}.tmp"

    @staticmethod
    def _validate_temporary_name(name: str) -> str:
        if not isinstance(name, str) or _TEMP_NAME.fullmatch(name) is None:
            raise BrokerError(
                "ECO_WRITE_REQUEST_INVALID", "Recovery temporary name is invalid"
            )
        return name

    def _new_temp(self, parent_descriptor: int, reserved_name: str) -> tuple[str, int]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        name = self._validate_temporary_name(reserved_name)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
            return name, descriptor
        except FileExistsError as exc:
            raise BrokerError(
                "ECO_TEMP_CREATE_FAILED", "Authorized workspace temp name already exists"
            ) from exc
        except OSError as exc:
            raise BrokerError("ECO_TEMP_CREATE_FAILED", "Workspace temp file could not be created") from exc

    def _copy_candidate_to_temp(
        self,
        parent_descriptor: int,
        proof: ArtifactAvailabilityProof,
        mode: int,
        temporary_name: str,
    ) -> tuple[str, int, os.stat_result]:
        if (
            not isinstance(proof, ArtifactAvailabilityProof)
            or not isinstance(proof.byte_length, int)
            or isinstance(proof.byte_length, bool)
            or proof.byte_length < 0
        ):
            raise BrokerError("ECO_CANDIDATE_UNAVAILABLE", "Candidate proof is invalid")
        if proof.byte_length > self._maximum_file_bytes:
            raise BrokerError("ECO_FILE_TOO_LARGE", "Candidate exceeds the write limit")
        name, descriptor = self._new_temp(parent_descriptor, temporary_name)
        digest = hashlib.sha256()
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        byte_length = 0
        try:
            try:
                with self._artifact_store.open_verified(proof) as source:
                    while True:
                        chunk = source.read(65_536)
                        if not chunk:
                            break
                        byte_length += len(chunk)
                        if byte_length > self._maximum_file_bytes:
                            raise BrokerError("ECO_FILE_TOO_LARGE", "Candidate exceeds the write limit")
                        if b"\x00" in chunk:
                            raise BrokerError("ECO_BINARY_FILE", "Candidate contains binary content")
                        decoder.decode(chunk, final=False)
                        digest.update(chunk)
                        self._write_all(descriptor, chunk)
                    decoder.decode(b"", final=True)
            except RuntimeStoreError as exc:
                raise BrokerError("ECO_CANDIDATE_UNAVAILABLE", "Candidate proof is unavailable") from exc
            except UnicodeDecodeError as exc:
                raise BrokerError("ECO_TEXT_ENCODING", "Candidate is not valid UTF-8") from exc
            if byte_length != proof.byte_length or digest.hexdigest() != proof.sha256:
                raise BrokerError("ECO_CANDIDATE_MISMATCH", "Candidate content differs from proof")
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BrokerError("ECO_TEMP_CHANGED", "Workspace temp metadata is unsafe")
            self._phase("after_candidate_fsync")
            return name, descriptor, info
        except Exception:
            os.close(descriptor)
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except OSError:
                pass
            raise

    def _renameat2(
        self,
        old_directory: int,
        old_name: str,
        new_directory: int,
        new_name: str,
        flags: int,
    ) -> None:
        renameat2 = getattr(self._libc, "renameat2", None)
        if renameat2 is None:
            raise BrokerError(
                "ECO_WRITE_BROKER_UNSUPPORTED", "renameat2 backend is required"
            )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            ctypes.c_int(old_directory),
            ctypes.c_char_p(old_name.encode("utf-8")),
            ctypes.c_int(new_directory),
            ctypes.c_char_p(new_name.encode("utf-8")),
            ctypes.c_uint(flags),
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            code = "ECO_EXPECTED_BEFORE_MISMATCH"
        elif error == errno.ENOENT:
            code = "ECO_EXPECTED_BEFORE_MISMATCH"
        elif error in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EXDEV}:
            code = "ECO_WRITE_BROKER_UNSUPPORTED"
        else:
            code = "ECO_ATOMIC_WRITE_FAILED"
        raise BrokerError(code, "Atomic workspace update failed")

    @staticmethod
    def _fsync_directory(descriptor: int) -> None:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise BrokerError("ECO_DIRECTORY_FSYNC_FAILED", "Workspace directory was not persisted") from exc

    def _verify_owned_temp(
        self, parent_descriptor: int, name: str, expected: os.stat_result
    ) -> _ObservedFile:
        observed = self._observe(parent_descriptor, name)
        if observed is None or not _same_identity(observed.stat_result, expected):
            if observed is not None:
                observed.close()
            raise BrokerError("ECO_TEMP_CHANGED", "Workspace temp identity changed")
        return observed

    def apply(
        self,
        path: str,
        *,
        operation: Literal["create", "replace"],
        expected_before: FileState,
        candidate_proof: ArtifactAvailabilityProof,
        candidate_mode: int = 0o644,
        temporary_name: str | None = None,
        rollback_ready_hook: (
            Callable[[FileState, ArtifactAvailabilityProof | None], None] | None
        ) = None,
        commit_authority_hook: Callable[[], None] | None = None,
    ) -> WorkspaceWriteResult:
        """Atomically create or replace one exact file after fail-closed validation."""

        path = self._validate_path(path)
        if operation not in {"create", "replace"}:
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Write operation is invalid")
        expected_before = self._validate_state(expected_before, allow_absent=True)
        if (operation == "create") != (expected_before.state == "absent"):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Operation and before state disagree")
        candidate_mode = self._validate_mode(candidate_mode)
        temporary_name = (
            self.issue_temporary_name()
            if temporary_name is None
            else self._validate_temporary_name(temporary_name)
        )
        if not isinstance(candidate_proof, ArtifactAvailabilityProof):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Candidate proof is invalid")
        if rollback_ready_hook is not None and not callable(rollback_ready_hook):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Rollback-ready hook is invalid")
        if commit_authority_hook is not None and not callable(commit_authority_hook):
            raise BrokerError("ECO_WRITE_REQUEST_INVALID", "Commit-authority hook is invalid")
        if expected_before.byte_length is not None and expected_before.byte_length > self._maximum_file_bytes:
            raise BrokerError("ECO_FILE_TOO_LARGE", "Expected before file exceeds the write limit")

        parent_path, name = path.rsplit("/", 1) if "/" in path else (".", path)
        with self._exclusive_operation():
            parent = self._open_parent(parent_path)
            initial: _ObservedFile | None = None
            temp_name: str | None = None
            temp_descriptor: int | None = None
            committed = False
            try:
                parent_info = os.fstat(parent)
                initial = self._observe(parent, name)
                self._require_expected(initial, expected_before)
                self._phase("after_initial_validation")

                rollback_proof = self._persist_before(initial) if initial is not None else None
                if rollback_ready_hook is not None:
                    # The orchestrator durably records this content-free recovery
                    # descriptor before this broker creates a temp or mutates a name.
                    rollback_ready_hook(expected_before, rollback_proof)
                self._phase("after_rollback_persisted")
                temp_name, temp_descriptor, temp_info = self._copy_candidate_to_temp(
                    parent, candidate_proof, candidate_mode, temporary_name
                )
                self._assert_parent_stable(parent_path, parent, parent_info)
                owned_temp = self._verify_owned_temp(parent, temp_name, temp_info)
                owned_temp.close()
                current = self._observe(parent, name)
                try:
                    self._require_expected(current, expected_before)
                    if initial is None:
                        if current is not None:
                            raise BrokerError(
                                "ECO_EXPECTED_BEFORE_MISMATCH", "Workspace target appeared"
                            )
                    elif current is None or not _same_identity(
                        initial.stat_result, current.stat_result
                    ):
                        raise BrokerError("ECO_FILE_CHANGED", "Workspace target identity changed")
                finally:
                    if current is not None:
                        current.close()
                self._phase("before_atomic_commit")
                if commit_authority_hook is not None:
                    # Last cross-authority check before the atomic namespace
                    # mutation. Durable PREPARE remains the in-flight authority.
                    commit_authority_hook()

                if operation == "create":
                    self._renameat2(parent, temp_name, parent, name, _RENAME_NOREPLACE)
                else:
                    self._renameat2(parent, temp_name, parent, name, _RENAME_EXCHANGE)
                    exchanged_before = self._observe(parent, temp_name)
                    try:
                        if (
                            exchanged_before is None
                            or exchanged_before.state != expected_before
                            or initial is None
                            or not _same_identity(initial.stat_result, exchanged_before.stat_result)
                        ):
                            # Best-effort restoration is safe while the candidate is still exact.
                            self._renameat2(parent, temp_name, parent, name, _RENAME_EXCHANGE)
                            self._fsync_directory(parent)
                            raise BrokerError(
                                "ECO_FILE_CHANGED", "Workspace target raced the atomic replace"
                            )
                    finally:
                        if exchanged_before is not None:
                            exchanged_before.close()
                    os.unlink(temp_name, dir_fd=parent)
                committed = True
                self._fsync_directory(parent)
                self._phase("after_atomic_commit")

                applied = self._observe(parent, name)
                try:
                    after = FileState.present(
                        candidate_proof.sha256, candidate_proof.byte_length, candidate_mode
                    )
                    if (
                        applied is None
                        or applied.state != after
                        or not _same_identity(temp_info, applied.stat_result)
                    ):
                        raise BrokerError("ECO_WRITE_VERIFY_FAILED", "Applied file failed verification")
                finally:
                    if applied is not None:
                        applied.close()
                return WorkspaceWriteResult(
                    path=path,
                    operation=operation,
                    before=expected_before,
                    after=after,
                    candidate_proof=candidate_proof,
                    rollback_proof=rollback_proof,
                )
            finally:
                if temp_descriptor is not None:
                    os.close(temp_descriptor)
                if temp_name is not None and not committed:
                    try:
                        os.unlink(temp_name, dir_fd=parent)
                    except OSError:
                        pass
                if initial is not None:
                    initial.close()
                os.close(parent)

    def observe(self, path: str) -> FileState:
        """Return only the exact current state needed for crash reconciliation."""

        path = self._validate_path(path)
        parent_path, name = path.rsplit("/", 1) if "/" in path else (".", path)
        with self._exclusive_operation():
            parent = self._open_parent(parent_path)
            observed: _ObservedFile | None = None
            try:
                parent_info = os.fstat(parent)
                observed = self._observe(parent, name)
                self._assert_parent_stable(parent_path, parent, parent_info)
                return FileState.absent() if observed is None else observed.state
            finally:
                if observed is not None:
                    observed.close()
                os.close(parent)

    def cleanup_temporary(self, path: str, temporary_name: str) -> bool:
        """Remove one exact authority-bound orphan after process loss.

        The random name is persisted in the authenticated private recovery
        bundle before creation. No prefix scan or wildcard deletion occurs.
        """

        path = self._validate_path(path)
        temporary_name = self._validate_temporary_name(temporary_name)
        parent_path = path.rsplit("/", 1)[0] if "/" in path else "."
        with self._exclusive_operation():
            parent = self._open_parent(parent_path)
            try:
                parent_info = os.fstat(parent)
                try:
                    info = os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                except OSError as exc:
                    raise BrokerError(
                        "ECO_TEMP_CLEANUP_FAILED", "Recovery temp could not be inspected"
                    ) from exc
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise BrokerError("ECO_TEMP_CHANGED", "Recovery temp metadata is unsafe")
                self._assert_parent_stable(parent_path, parent, parent_info)
                try:
                    os.unlink(temporary_name, dir_fd=parent)
                except OSError as exc:
                    raise BrokerError(
                        "ECO_TEMP_CLEANUP_FAILED", "Recovery temp could not be removed"
                    ) from exc
                self._fsync_directory(parent)
                self._assert_parent_stable(parent_path, parent, parent_info)
                try:
                    os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    return True
                raise BrokerError(
                    "ECO_TEMP_CLEANUP_FAILED", "Recovery temp remains after removal"
                )
            finally:
                os.close(parent)

    @staticmethod
    def _validate_receipt(receipt: WorkspaceWriteResult) -> WorkspaceWriteResult:
        if not isinstance(receipt, WorkspaceWriteResult):
            raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Write receipt is invalid")
        if (
            not isinstance(receipt.before, FileState)
            or not isinstance(receipt.after, FileState)
            or not isinstance(receipt.candidate_proof, ArtifactAvailabilityProof)
        ):
            raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Write receipt is invalid")
        if receipt.operation == "create":
            if receipt.before.state != "absent" or receipt.rollback_proof is not None:
                raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Create receipt is invalid")
        elif receipt.operation == "replace":
            if receipt.before.state != "present" or receipt.rollback_proof is None:
                raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Replace receipt is invalid")
        else:
            raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Write receipt operation is invalid")
        return receipt

    def _verify_rollback_proof(self, receipt: WorkspaceWriteResult) -> None:
        if receipt.rollback_proof is None:
            return
        if (
            receipt.rollback_proof.sha256 != receipt.before.sha256
            or receipt.rollback_proof.byte_length != receipt.before.byte_length
        ):
            raise BrokerError("ECO_ROLLBACK_PROOF_INVALID", "Rollback proof does not match receipt")
        try:
            self._artifact_store.verify_availability(receipt.rollback_proof)
        except RuntimeStoreError as exc:
            raise BrokerError("ECO_ROLLBACK_PROOF_INVALID", "Rollback proof is unavailable") from exc

    def rollback(
        self,
        receipt: WorkspaceWriteResult,
        *,
        temporary_name: str | None = None,
        commit_authority_hook: Callable[[], None] | None = None,
    ) -> WorkspaceRollbackResult:
        """Restore captured before bytes only while the exact applied-after state remains."""

        receipt = self._validate_receipt(receipt)
        temporary_name = (
            self.issue_temporary_name()
            if temporary_name is None
            else self._validate_temporary_name(temporary_name)
        )
        if commit_authority_hook is not None and not callable(commit_authority_hook):
            raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Commit-authority hook is invalid")
        path = self._validate_path(receipt.path)
        before = self._validate_state(receipt.before, allow_absent=True)
        after = self._validate_state(receipt.after, allow_absent=False)
        if (
            receipt.candidate_proof.sha256 != after.sha256
            or receipt.candidate_proof.byte_length != after.byte_length
        ):
            raise BrokerError("ECO_ROLLBACK_REQUEST_INVALID", "Receipt candidate does not match after state")
        self._verify_rollback_proof(receipt)

        parent_path, name = path.rsplit("/", 1) if "/" in path else (".", path)
        with self._exclusive_operation():
            parent = self._open_parent(parent_path)
            current: _ObservedFile | None = None
            temp_name: str | None = None
            temp_descriptor: int | None = None
            committed = False
            try:
                parent_info = os.fstat(parent)
                current = self._observe(parent, name)
                if before.state == "absent" and current is None:
                    return WorkspaceRollbackResult(path, before, changed=False)
                if before.state == "present" and current is not None and current.state == before:
                    return WorkspaceRollbackResult(path, before, changed=False)
                if current is None or current.state != after:
                    raise BrokerError(
                        "ECO_ROLLBACK_CONFLICT", "Workspace target changed after the applied write"
                    )
                self._assert_parent_stable(parent_path, parent, parent_info)

                if before.state == "absent":
                    temp_name = temporary_name
                    if commit_authority_hook is not None:
                        commit_authority_hook()
                    self._renameat2(parent, name, parent, temp_name, _RENAME_NOREPLACE)
                    self._phase("after_rollback_atomic_commit")
                    moved = self._observe(parent, temp_name)
                    try:
                        if (
                            moved is None
                            or moved.state != after
                            or not _same_identity(current.stat_result, moved.stat_result)
                        ):
                            self._renameat2(parent, temp_name, parent, name, _RENAME_NOREPLACE)
                            self._fsync_directory(parent)
                            raise BrokerError(
                                "ECO_ROLLBACK_CONFLICT", "Workspace target raced rollback"
                            )
                    finally:
                        if moved is not None:
                            moved.close()
                    os.unlink(temp_name, dir_fd=parent)
                    committed = True
                else:
                    assert receipt.rollback_proof is not None
                    temp_name, temp_descriptor, temp_info = self._copy_candidate_to_temp(
                        parent,
                        receipt.rollback_proof,
                        before.mode,  # type: ignore[arg-type]
                        temporary_name,
                    )
                    self._assert_parent_stable(parent_path, parent, parent_info)
                    latest = self._observe(parent, name)
                    try:
                        if (
                            latest is None
                            or latest.state != after
                            or not _same_identity(current.stat_result, latest.stat_result)
                        ):
                            raise BrokerError(
                                "ECO_ROLLBACK_CONFLICT", "Workspace target raced rollback"
                            )
                    finally:
                        if latest is not None:
                            latest.close()
                    if commit_authority_hook is not None:
                        commit_authority_hook()
                    self._renameat2(parent, temp_name, parent, name, _RENAME_EXCHANGE)
                    self._phase("after_rollback_atomic_commit")
                    exchanged_after = self._observe(parent, temp_name)
                    try:
                        if (
                            exchanged_after is None
                            or exchanged_after.state != after
                            or not _same_identity(current.stat_result, exchanged_after.stat_result)
                        ):
                            self._renameat2(parent, temp_name, parent, name, _RENAME_EXCHANGE)
                            self._fsync_directory(parent)
                            raise BrokerError(
                                "ECO_ROLLBACK_CONFLICT", "Workspace target raced rollback"
                            )
                    finally:
                        if exchanged_after is not None:
                            exchanged_after.close()
                    os.unlink(temp_name, dir_fd=parent)
                    committed = True

                self._fsync_directory(parent)
                restored = self._observe(parent, name)
                try:
                    if before.state == "absent":
                        if restored is not None:
                            raise BrokerError(
                                "ECO_ROLLBACK_VERIFY_FAILED", "Created file was not removed"
                            )
                    elif restored is None or restored.state != before:
                        raise BrokerError(
                            "ECO_ROLLBACK_VERIFY_FAILED", "Before state was not restored"
                        )
                finally:
                    if restored is not None:
                        restored.close()
                return WorkspaceRollbackResult(path, before, changed=True)
            finally:
                if temp_descriptor is not None:
                    os.close(temp_descriptor)
                if temp_name is not None and not committed:
                    try:
                        os.unlink(temp_name, dir_fd=parent)
                    except OSError:
                        pass
                if current is not None:
                    current.close()
                os.close(parent)
