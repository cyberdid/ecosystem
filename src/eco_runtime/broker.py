from __future__ import annotations

import ctypes
import copy
import errno
import hashlib
import os
import stat
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import validate_record, validate_tool_arguments
from .digests import semantic_digest
from .errors import BrokerError, ContractValidationError
from .repository import (
    protected_repository_path,
    repository_snapshot_entries,
    root_identity_from_stat,
)


_OPENAT2_SYSCALL = 437
_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_POLICY = (
    _RESOLVE_NO_XDEV | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS | _RESOLVE_BENEATH
)


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class RepositoryReadResult:
    path: str
    untrusted_content: str
    byte_length: int
    sha256: str
    data_class: str
    trust: str
    repository_snapshot_digest: str


def _same_file_snapshot(before: os.stat_result, after: os.stat_result, byte_count: int) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, name) == getattr(after, name) for name in fields) and byte_count == after.st_size


class RepositoryReadBroker:
    """Linux/WSL filesystem-only reader anchored by a directory descriptor.

    Policy decisions, durable budget reservations, idempotency, and lifecycle
    transitions are deliberately outside this object.  The embedded
    orchestrator must complete those authority steps before calling ``read``.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        repository_snapshot: dict[str, Any],
        *,
        maximum_file_bytes: int = 1_048_576,
    ) -> None:
        if not sys.platform.startswith("linux"):
            raise BrokerError("ECO_BROKER_UNSUPPORTED", "Linux openat2 backend is required")
        if os.uname().machine not in {"x86_64", "aarch64"}:
            raise BrokerError("ECO_BROKER_UNSUPPORTED", "Architecture lacks a tested openat2 profile")
        if not isinstance(maximum_file_bytes, int) or maximum_file_bytes < 1:
            raise ValueError("maximum_file_bytes must be a positive integer")
        trusted_root = Path(root).resolve(strict=True)
        if not trusted_root.is_dir():
            raise BrokerError("ECO_ROOT_INVALID", "Broker root is not a directory")
        flags = os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_PATH", os.O_RDONLY)
        self._root_fd = os.open(trusted_root, flags)
        self._lifecycle_lock = threading.Lock()
        try:
            self._repository_snapshot = copy.deepcopy(validate_record(repository_snapshot))
        except ContractValidationError as exc:
            os.close(self._root_fd)
            self._closed = True
            raise BrokerError("ECO_SNAPSHOT_INVALID", "Repository snapshot is invalid") from exc
        if self._repository_snapshot["kind"] != "RepositorySnapshot":
            os.close(self._root_fd)
            self._closed = True
            raise BrokerError("ECO_SNAPSHOT_INVALID", "Repository snapshot kind is invalid")
        try:
            self._repository_entries = repository_snapshot_entries(self._repository_snapshot)
        except Exception:
            os.close(self._root_fd)
            self._closed = True
            raise
        self._repository_snapshot_digest = semantic_digest(self._repository_snapshot)
        actual_root_identity = root_identity_from_stat(os.fstat(self._root_fd))
        if self._repository_snapshot["spec"]["rootIdentityDigest"] != actual_root_identity:
            os.close(self._root_fd)
            self._closed = True
            raise BrokerError("ECO_ROOT_IDENTITY_MISMATCH", "Snapshot is bound to another repository root")
        self._maximum_file_bytes = maximum_file_bytes
        self._closed = False

    def close(self) -> None:
        with self._lifecycle_lock:
            if not self._closed:
                os.close(self._root_fd)
                self._closed = True

    def __enter__(self) -> RepositoryReadBroker:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open_beneath(self, path: str) -> int:
        with self._lifecycle_lock:
            if self._closed:
                raise BrokerError("ECO_BROKER_CLOSED", "Broker is closed")
            root_fd = os.dup(self._root_fd)
        how = _OpenHow(
            flags=getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC,
            mode=0,
            resolve=_RESOLVE_POLICY,
        )
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        try:
            result = libc.syscall(
                ctypes.c_long(_OPENAT2_SYSCALL),
                ctypes.c_int(root_fd),
                ctypes.c_char_p(path.encode("utf-8")),
                ctypes.byref(how),
                ctypes.c_size_t(ctypes.sizeof(how)),
            )
        finally:
            os.close(root_fd)
        if result >= 0:
            return int(result)
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            code = "ECO_BROKER_UNSUPPORTED"
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
        raise BrokerError(code, "Repository file could not be opened safely")

    def read(self, path: str, *, maximum_bytes: int | None = None) -> RepositoryReadResult:
        """Read one snapshotted UTF-8 regular file without granting authority."""

        try:
            arguments = validate_tool_arguments("repository.read", {"path": path})
        except ContractValidationError as exc:
            raise BrokerError("ECO_BROKER_REQUEST_INVALID", "Broker request is invalid") from exc
        path = arguments["path"]
        if protected_repository_path(path):
            raise BrokerError("ECO_PROTECTED_PATH", "Protected repository path is not readable")
        entry = self._repository_entries.get(path)
        if entry is None:
            raise BrokerError("ECO_REPOSITORY_PATH_UNSNAPSHOTTED", "Repository path is absent from the snapshot")
        if maximum_bytes is None:
            maximum_bytes = self._maximum_file_bytes
        if not isinstance(maximum_bytes, int) or maximum_bytes < 0:
            raise ValueError("maximum_bytes must be a non-negative integer")
        maximum_bytes = min(self._maximum_file_bytes, maximum_bytes)

        path_descriptor = self._open_beneath(path)
        try:
            path_stat = os.fstat(path_descriptor)
            if not stat.S_ISREG(path_stat.st_mode):
                raise BrokerError("ECO_NOT_REGULAR_FILE", "Repository path is not a regular file")
            if path_stat.st_nlink != 1:
                raise BrokerError("ECO_HARDLINK_DENIED", "Repository file has multiple hard links")
            if path_stat.st_size != entry["byteLength"]:
                raise BrokerError("ECO_SNAPSHOT_CONTENT_MISMATCH", "Repository file size differs from the snapshot")
            if path_stat.st_size > maximum_bytes:
                raise BrokerError("ECO_FILE_TOO_LARGE", "Repository file exceeds the read limit")
            descriptor = os.open(
                f"/proc/self/fd/{path_descriptor}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
            )
            before = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_mode) != (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_mode,
            ):
                os.close(descriptor)
                raise BrokerError("ECO_FILE_CHANGED", "Repository file identity changed before read")
        finally:
            os.close(path_descriptor)

        try:
            chunks: list[bytes] = []
            byte_count = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - byte_count))
                if not chunk:
                    break
                chunks.append(chunk)
                byte_count += len(chunk)
                if byte_count > maximum_bytes:
                    raise BrokerError("ECO_FILE_TOO_LARGE", "Repository file exceeds the read limit")
            after = os.fstat(descriptor)
            data = b"".join(chunks)
            if not _same_file_snapshot(before, after, len(data)):
                raise BrokerError("ECO_FILE_CHANGED", "Repository file changed during the read")

            if b"\x00" in data:
                raise BrokerError("ECO_BINARY_FILE", "Binary repository content is not readable")
            try:
                content = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise BrokerError("ECO_TEXT_ENCODING", "Repository content is not valid UTF-8") from exc
            content_digest = hashlib.sha256(data).hexdigest()
            if content_digest != entry["contentDigest"]:
                raise BrokerError("ECO_SNAPSHOT_CONTENT_MISMATCH", "Repository content differs from the snapshot")

            return RepositoryReadResult(
                path=path,
                untrusted_content=content,
                byte_length=len(data),
                sha256=content_digest,
                data_class=entry["dataClass"],
                trust=entry["trust"],
                repository_snapshot_digest=self._repository_snapshot_digest,
            )
        finally:
            os.close(descriptor)
