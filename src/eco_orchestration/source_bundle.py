from __future__ import annotations

import ctypes
import errno
import hashlib
import io
import json
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.digests import semantic_digest
from eco_runtime.repository import protected_repository_path, root_identity_from_stat

from .contracts import (
    ORCHESTRATION_API_VERSION,
    orchestration_record_digest,
    validate_orchestration_record,
)


FILESYSTEM_PROFILE = "linux-openat2-v1"
ALLOWED_MEDIA_TYPES = frozenset({"text/plain", "text/markdown", "application/json"})
ALLOWED_DATA_CLASSES = frozenset({"D0", "D1", "D2", "D3"})

_OPENAT2_SYSCALL = 437
_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_POLICY = (
    _RESOLVE_NO_XDEV | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS | _RESOLVE_BENEATH
)
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._:-]{0,126}[a-z0-9])?$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class SourceBundleError(RuntimeError):
    """Sanitized, stable failure raised before a SourceBundle is published."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SourceBundleLimits:
    maximum_file_bytes: int = 1_048_576
    maximum_source_count: int = 64
    maximum_total_bytes: int = 8_388_608
    maximum_manifest_bytes: int = 262_144
    maximum_json_depth: int = 64
    maximum_json_items: int = 20_000

    def __post_init__(self) -> None:
        for name in (
            "maximum_file_bytes",
            "maximum_source_count",
            "maximum_total_bytes",
            "maximum_manifest_bytes",
            "maximum_json_depth",
            "maximum_json_items",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.maximum_file_bytes > self.maximum_total_bytes:
            raise ValueError("maximum_file_bytes cannot exceed maximum_total_bytes")
        if self.maximum_source_count > 100:
            raise ValueError("maximum_source_count cannot exceed the SourceBundle contract limit")
        if self.maximum_total_bytes > 1_000_000_000:
            raise ValueError("maximum_total_bytes cannot exceed the SourceBundle contract limit")
        if self.maximum_json_depth > 256:
            raise ValueError("maximum_json_depth cannot exceed the SourceBundle contract limit")
        if self.maximum_json_items > 1_000_000:
            raise ValueError("maximum_json_items cannot exceed the SourceBundle contract limit")

    def policy_digest(self) -> str:
        """Digest the broker-owned ingestion behavior, never manifest assertions."""

        return semantic_digest(
            {
                "domain": "eco-source-bundle-ingestion-policy-v1",
                "filesystemProfile": FILESYSTEM_PROFILE,
                "allowedMediaTypes": sorted(ALLOWED_MEDIA_TYPES),
                "allowedDataClasses": sorted(ALLOWED_DATA_CLASSES),
                "maximumFileBytes": self.maximum_file_bytes,
                "maximumSourceCount": self.maximum_source_count,
                "maximumTotalBytes": self.maximum_total_bytes,
                "maximumManifestBytes": self.maximum_manifest_bytes,
                "maximumJsonDepth": self.maximum_json_depth,
                "maximumJsonItems": self.maximum_json_items,
                "pathProfile": "canonical-repository-relative-utf8-v1",
                "contentProfile": "utf8-no-nul-v1",
            }
        )


@dataclass(frozen=True)
class SourceManifestEntry:
    id: str
    path: str
    media_type: str
    data_class: str
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class SourceBundleManifest:
    bundle_id: str
    data_class: str
    question: SourceManifestEntry
    sources: tuple[SourceManifestEntry, ...]
    manifest_digest: str | None = None
    manifest_byte_length: int | None = None

    @property
    def entries(self) -> tuple[SourceManifestEntry, ...]:
        return (self.question, *self.sources)


@dataclass(frozen=True)
class _ReadSource:
    manifest: SourceManifestEntry
    content: bytes
    provenance_digest: str


def _fail(code: str, message: str) -> SourceBundleError:
    return SourceBundleError(code, message)


def _canonical_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise _fail("ECO_SOURCE_PATH_INVALID", "Source path is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _fail("ECO_SOURCE_PATH_INVALID", "Source path is invalid") from exc
    invalid = (
        len(encoded) > 4096
        or value.startswith("/")
        or value.startswith("./")
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or "%" in value
        or value == "."
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
        or any(unicodedata.category(character).startswith("C") for character in value)
        or unicodedata.normalize("NFC", value) != value
    )
    if invalid:
        raise _fail(
            "ECO_SOURCE_PATH_INVALID", "Source path is not canonical repository-relative UTF-8"
        )
    if protected_repository_path(value):
        raise _fail("ECO_SOURCE_PATH_PROTECTED", "Protected repository path is not ingestible")
    return value


def _identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise _fail("ECO_SOURCE_MANIFEST_INVALID", f"{field} is invalid")
    if unicodedata.normalize("NFC", value) != value:
        raise _fail("ECO_SOURCE_MANIFEST_INVALID", f"{field} is invalid")
    return value


def _exact_keys(value: Any, expected: frozenset[str], *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise _fail("ECO_SOURCE_MANIFEST_INVALID", f"{context} has invalid fields")
    return value


def _parse_entry(value: Any, *, bundle_data_class: str) -> SourceManifestEntry:
    item = _exact_keys(
        value,
        frozenset({"id", "path", "mediaType", "dataClass", "sha256", "byteLength"}),
        context="Source entry",
    )
    source_id = _identifier(item["id"], field="Source identifier")
    path = _canonical_path(item["path"])
    media_type = item["mediaType"]
    if not isinstance(media_type, str) or media_type not in ALLOWED_MEDIA_TYPES:
        raise _fail("ECO_SOURCE_MEDIA_TYPE_DENIED", "Source media type is not allowed")
    data_class = item["dataClass"]
    if data_class != bundle_data_class:
        raise _fail("ECO_SOURCE_DATA_CLASS_MISMATCH", "Source data class differs from bundle")
    digest = item["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise _fail("ECO_SOURCE_DIGEST_INVALID", "Source digest is invalid")
    byte_length = item["byteLength"]
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 1:
        raise _fail("ECO_SOURCE_LENGTH_INVALID", "Source byte length is invalid")
    return SourceManifestEntry(
        id=source_id,
        path=path,
        media_type=media_type,
        data_class=data_class,
        sha256=digest,
        byte_length=byte_length,
    )


def validate_source_bundle_manifest(
    value: Any, *, limits: SourceBundleLimits | None = None
) -> SourceBundleManifest:
    """Validate the strict path-bearing, pre-ingestion manifest.

    This is intentionally an internal input shape rather than a durable public
    contract. The returned durable record contains no source bytes or paths.
    """

    if limits is None:
        limits = SourceBundleLimits()
    elif not isinstance(limits, SourceBundleLimits):
        raise TypeError("limits must be SourceBundleLimits")
    document = _exact_keys(
        value,
        frozenset({"bundleId", "dataClass", "question", "sources"}),
        context="Source bundle manifest",
    )
    bundle_id = _identifier(document["bundleId"], field="Bundle identifier")
    data_class = document["dataClass"]
    if not isinstance(data_class, str) or data_class not in ALLOWED_DATA_CLASSES:
        raise _fail("ECO_SOURCE_DATA_CLASS_DENIED", "Bundle data class is not allowed")
    sources_value = document["sources"]
    if not isinstance(sources_value, list) or not sources_value:
        raise _fail("ECO_SOURCE_MANIFEST_INVALID", "Source list is invalid")
    if len(sources_value) + 1 > limits.maximum_source_count:
        raise _fail("ECO_SOURCE_COUNT_EXCEEDED", "Source bundle exceeds the source count limit")
    question = _parse_entry(document["question"], bundle_data_class=data_class)
    if question.media_type not in {"text/plain", "text/markdown"}:
        raise _fail("ECO_SOURCE_QUESTION_INVALID", "Question must be plain text or Markdown")
    sources = tuple(
        _parse_entry(item, bundle_data_class=data_class) for item in sources_value
    )
    entries = (question, *sources)
    identifiers = [item.id for item in entries]
    paths = [item.path for item in entries]
    if len(set(identifiers)) != len(identifiers):
        raise _fail("ECO_SOURCE_DUPLICATE_ID", "Source identifiers must be unique")
    if len(set(paths)) != len(paths):
        raise _fail("ECO_SOURCE_DUPLICATE_PATH", "Source paths must be unique")
    if any(item.byte_length > limits.maximum_file_bytes for item in entries):
        raise _fail("ECO_SOURCE_FILE_TOO_LARGE", "Source file exceeds the per-file limit")
    if sum(item.byte_length for item in entries) > limits.maximum_total_bytes:
        raise _fail("ECO_SOURCE_TOTAL_TOO_LARGE", "Source bundle exceeds the aggregate limit")
    return SourceBundleManifest(bundle_id, data_class, question, sources)


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("ECO_SOURCE_JSON_DUPLICATE_KEY", "JSON contains duplicate object keys")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _enforce_json_shape_limits(
    document: Any,
    *,
    maximum_depth: int,
    maximum_items: int,
    code: str,
) -> None:
    pending: list[tuple[Any, int]] = [(document, 1)]
    observed = 0
    while pending:
        value, depth = pending.pop()
        observed += 1
        if observed > maximum_items or depth > maximum_depth:
            raise _fail(code, "JSON exceeds the broker-owned structural limits")
        if isinstance(value, Mapping):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)


class _LinuxAnchoredSourceReader:
    """Linux/WSL executable proof; this makes no portability claim.

    Paths are resolved beneath a trusted repository descriptor with openat2.
    Other platforms must supply a separately tested conformance profile rather
    than silently falling back to path-string checks.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        fault_hook: Callable[[str, str], None] | None = None,
    ) -> None:
        if not sys.platform.startswith("linux"):
            raise _fail("ECO_SOURCE_BUNDLE_UNSUPPORTED", "Linux openat2 backend is required")
        if os.uname().machine not in {"x86_64", "aarch64"}:
            raise _fail(
                "ECO_SOURCE_BUNDLE_UNSUPPORTED", "Architecture lacks a tested openat2 profile"
            )
        try:
            trusted_root = Path(root).resolve(strict=True)
        except OSError as exc:
            raise _fail("ECO_SOURCE_ROOT_INVALID", "Source root is unavailable") from exc
        if not trusted_root.is_dir():
            raise _fail("ECO_SOURCE_ROOT_INVALID", "Source root is not a directory")
        flags = os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_PATH", os.O_RDONLY)
        root_fd = -1
        try:
            root_fd = os.open(trusted_root, flags)
            root_info = os.fstat(root_fd)
        except OSError as exc:
            if root_fd >= 0:
                try:
                    os.close(root_fd)
                except OSError:
                    pass
            raise _fail("ECO_SOURCE_ROOT_INVALID", "Source root is unavailable") from exc
        self._root_fd = root_fd
        self.root_identity_digest = root_identity_from_stat(root_info)
        self._fault_hook = fault_hook
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> _LinuxAnchoredSourceReader:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open_beneath(self, path: str) -> int:
        if self._closed:
            raise _fail("ECO_SOURCE_READER_CLOSED", "Source reader is closed")
        how = _OpenHow(
            flags=getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC,
            mode=0,
            resolve=_RESOLVE_POLICY,
        )
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        result = libc.syscall(
            ctypes.c_long(_OPENAT2_SYSCALL),
            ctypes.c_int(self._root_fd),
            ctypes.c_char_p(path.encode("utf-8")),
            ctypes.byref(how),
            ctypes.c_size_t(ctypes.sizeof(how)),
        )
        if result >= 0:
            return int(result)
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EINVAL}:
            code = "ECO_SOURCE_BUNDLE_UNSUPPORTED"
        elif error in {errno.EXDEV, errno.ELOOP}:
            code = "ECO_SOURCE_PATH_ESCAPE"
        elif error == errno.ENOENT:
            code = "ECO_SOURCE_NOT_FOUND"
        elif error in {errno.EACCES, errno.EPERM}:
            code = "ECO_SOURCE_DENIED"
        elif error in {errno.ENOTDIR, errno.EISDIR}:
            code = "ECO_SOURCE_NOT_REGULAR"
        else:
            code = "ECO_SOURCE_OPEN_FAILED"
        raise _fail(code, "Source file could not be opened safely")

    @staticmethod
    def _stable(before: os.stat_result, after: os.stat_result, length: int) -> bool:
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        return all(getattr(before, name) == getattr(after, name) for name in fields) and (
            length == after.st_size
        )

    @staticmethod
    def _fstat(descriptor: int) -> os.stat_result:
        try:
            return os.fstat(descriptor)
        except OSError as exc:
            raise _fail("ECO_SOURCE_STAT_FAILED", "Source metadata could not be read safely") from exc

    @staticmethod
    def _reopen(path_descriptor: int) -> int:
        try:
            return os.open(
                f"/proc/self/fd/{path_descriptor}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
            )
        except OSError as exc:
            raise _fail("ECO_SOURCE_REOPEN_FAILED", "Source file could not be reopened safely") from exc

    @staticmethod
    def _read_block(descriptor: int, maximum_bytes: int) -> bytes:
        try:
            return os.read(descriptor, maximum_bytes)
        except OSError as exc:
            raise _fail("ECO_SOURCE_READ_FAILED", "Source bytes could not be read safely") from exc

    def read(self, path: str, *, maximum_bytes: int) -> bytes:
        path = _canonical_path(path)
        path_descriptor = self._open_beneath(path)
        descriptor = -1
        try:
            path_info = self._fstat(path_descriptor)
            if not stat.S_ISREG(path_info.st_mode):
                raise _fail("ECO_SOURCE_NOT_REGULAR", "Source path is not a regular file")
            if path_info.st_nlink != 1:
                raise _fail("ECO_SOURCE_HARDLINK_DENIED", "Hardlinked source is denied")
            if path_info.st_size > maximum_bytes:
                raise _fail("ECO_SOURCE_FILE_TOO_LARGE", "Source file exceeds the read limit")
            descriptor = self._reopen(path_descriptor)
            before = self._fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
            ) != (
                path_info.st_dev,
                path_info.st_ino,
                path_info.st_mode,
                path_info.st_nlink,
            ):
                raise _fail("ECO_SOURCE_CHANGED", "Source identity changed before read")
        finally:
            os.close(path_descriptor)

        try:
            if self._fault_hook is not None:
                self._fault_hook("opened", path)
            chunks: list[bytes] = []
            observed = 0
            while True:
                block = self._read_block(
                    descriptor, min(65_536, maximum_bytes + 1 - observed)
                )
                if not block:
                    break
                chunks.append(block)
                observed += len(block)
                if observed > maximum_bytes:
                    raise _fail("ECO_SOURCE_FILE_TOO_LARGE", "Source file exceeds the read limit")
            if self._fault_hook is not None:
                self._fault_hook("read", path)
            after = self._fstat(descriptor)
            content = b"".join(chunks)
            if not self._stable(before, after, len(content)):
                raise _fail("ECO_SOURCE_CHANGED", "Source changed during read")
            return content
        finally:
            if descriptor >= 0:
                os.close(descriptor)


def load_source_bundle_manifest(
    root: str | os.PathLike[str],
    path: str,
    *,
    limits: SourceBundleLimits | None = None,
    fault_hook: Callable[[str, str], None] | None = None,
) -> SourceBundleManifest:
    """Descriptor-safely load one strict UTF-8 JSON manifest beneath ``root``."""

    if limits is None:
        limits = SourceBundleLimits()
    elif not isinstance(limits, SourceBundleLimits):
        raise TypeError("limits must be SourceBundleLimits")
    with _LinuxAnchoredSourceReader(root, fault_hook=fault_hook) as reader:
        encoded = reader.read(path, maximum_bytes=limits.maximum_manifest_bytes)
    if b"\x00" in encoded:
        raise _fail("ECO_SOURCE_MANIFEST_ENCODING", "Manifest contains a NUL byte")
    try:
        text = encoded.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_pairs,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise _fail("ECO_SOURCE_MANIFEST_ENCODING", "Manifest is not valid UTF-8") from exc
    except RecursionError as exc:
        raise _fail(
            "ECO_SOURCE_MANIFEST_JSON_LIMIT",
            "Manifest JSON exceeds the broker-owned structural limits",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise _fail("ECO_SOURCE_MANIFEST_JSON", "Manifest is not valid JSON") from exc
    _enforce_json_shape_limits(
        document,
        maximum_depth=limits.maximum_json_depth,
        maximum_items=limits.maximum_json_items,
        code="ECO_SOURCE_MANIFEST_JSON_LIMIT",
    )
    parsed = validate_source_bundle_manifest(document, limits=limits)
    return SourceBundleManifest(
        parsed.bundle_id,
        parsed.data_class,
        parsed.question,
        parsed.sources,
        hashlib.sha256(encoded).hexdigest(),
        len(encoded),
    )


def verify_source_bundle_files(
    root: str | os.PathLike[str],
    manifest: SourceBundleManifest,
    *,
    limits: SourceBundleLimits | None = None,
    fault_hook: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Read and validate every declared byte without publishing to the CAS."""

    if not isinstance(manifest, SourceBundleManifest):
        raise TypeError("manifest must be a SourceBundleManifest")
    if limits is None:
        limits = SourceBundleLimits()
    elif not isinstance(limits, SourceBundleLimits):
        raise TypeError("limits must be SourceBundleLimits")
    with _LinuxAnchoredSourceReader(root, fault_hook=fault_hook) as reader:
        read_sources = tuple(
            _read_declared_source(reader, entry, limits=limits)
            for entry in manifest.entries
        )
    observed_total = sum(len(item.content) for item in read_sources)
    if observed_total > limits.maximum_total_bytes:
        raise _fail("ECO_SOURCE_TOTAL_TOO_LARGE", "Source bundle exceeds the aggregate limit")
    return {
        "manifestDigest": manifest.manifest_digest,
        "manifestByteLength": manifest.manifest_byte_length,
        "sourceCount": len(manifest.sources),
        "totalByteLength": observed_total,
        "ingestionPolicyDigest": limits.policy_digest(),
    }


def _read_declared_source(
    reader: _LinuxAnchoredSourceReader,
    entry: SourceManifestEntry,
    *,
    limits: SourceBundleLimits,
) -> _ReadSource:
    content = reader.read(entry.path, maximum_bytes=limits.maximum_file_bytes)
    if b"\x00" in content:
        raise _fail("ECO_SOURCE_BINARY_DENIED", "Source contains a NUL byte")
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _fail("ECO_SOURCE_ENCODING_DENIED", "Source is not valid UTF-8") from exc
    if entry.media_type == "application/json":
        try:
            document = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_object_pairs,
                parse_constant=_reject_nonfinite_json_constant,
            )
        except RecursionError as exc:
            raise _fail(
                "ECO_SOURCE_JSON_LIMIT",
                "JSON source exceeds the broker-owned structural limits",
            ) from exc
        except (json.JSONDecodeError, ValueError) as exc:
            raise _fail("ECO_SOURCE_JSON_INVALID", "JSON source is invalid") from exc
        _enforce_json_shape_limits(
            document,
            maximum_depth=limits.maximum_json_depth,
            maximum_items=limits.maximum_json_items,
            code="ECO_SOURCE_JSON_LIMIT",
        )
    if len(content) != entry.byte_length:
        raise _fail("ECO_SOURCE_LENGTH_MISMATCH", "Source length differs from manifest")
    digest = hashlib.sha256(content).hexdigest()
    if digest != entry.sha256:
        raise _fail("ECO_SOURCE_DIGEST_MISMATCH", "Source digest differs from manifest")
    provenance_digest = semantic_digest(
        {
            "domain": "eco-source-local-file-provenance-v1",
            "rootIdentityDigest": reader.root_identity_digest,
            "path": entry.path,
            "contentDigest": digest,
            "byteLength": len(content),
        }
    )
    return _ReadSource(entry, content, provenance_digest)


def ingest_source_bundle(
    root: str | os.PathLike[str],
    manifest: SourceBundleManifest | Mapping[str, Any],
    artifact_store: ContentAddressedArtifactStore,
    *,
    project_id: str,
    team_id: str,
    run_id: str,
    created_at: str,
    limits: SourceBundleLimits | None = None,
    ingestion_policy_digest: str | None = None,
    fault_hook: Callable[[str, str], None] | None = None,
) -> dict[str, Any]:
    """Validate all bytes, then atomically publish a content-free SourceBundle.

    Publication is atomic at the record boundary: no SourceBundle is returned
    until every immutable object is installed and verified. A failed CAS write
    may leave an unreferenced content-addressed object, which is safe cleanup
    debt rather than a partially visible bundle. No source content is executed.
    """

    if not isinstance(artifact_store, ContentAddressedArtifactStore):
        raise TypeError("artifact_store must be a ContentAddressedArtifactStore")
    if limits is None:
        limits = SourceBundleLimits()
    elif not isinstance(limits, SourceBundleLimits):
        raise TypeError("limits must be SourceBundleLimits")
    if isinstance(manifest, SourceBundleManifest):
        manifest = {
            "bundleId": manifest.bundle_id,
            "dataClass": manifest.data_class,
            "question": {
                "id": manifest.question.id,
                "path": manifest.question.path,
                "mediaType": manifest.question.media_type,
                "dataClass": manifest.question.data_class,
                "sha256": manifest.question.sha256,
                "byteLength": manifest.question.byte_length,
            },
            "sources": [
                {
                    "id": item.id,
                    "path": item.path,
                    "mediaType": item.media_type,
                    "dataClass": item.data_class,
                    "sha256": item.sha256,
                    "byteLength": item.byte_length,
                }
                for item in manifest.sources
            ],
        }
    parsed = validate_source_bundle_manifest(manifest, limits=limits)
    project_id = _identifier(project_id, field="Project identifier")
    team_id = _identifier(team_id, field="Team identifier")
    run_id = _identifier(run_id, field="Run identifier")
    if not isinstance(created_at, str) or _TIMESTAMP_RE.fullmatch(created_at) is None:
        raise _fail("ECO_SOURCE_METADATA_INVALID", "Creation time is invalid")
    try:
        if datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ) != created_at:
            raise ValueError("timestamp is not canonical")
    except ValueError as exc:
        raise _fail("ECO_SOURCE_METADATA_INVALID", "Creation time is invalid") from exc
    expected_policy_digest = limits.policy_digest()
    if ingestion_policy_digest is not None:
        if (
            not isinstance(ingestion_policy_digest, str)
            or _SHA256_RE.fullmatch(ingestion_policy_digest) is None
        ):
            raise _fail("ECO_SOURCE_POLICY_INVALID", "Ingestion policy digest is invalid")
        if ingestion_policy_digest != expected_policy_digest:
            raise _fail(
                "ECO_SOURCE_POLICY_MISMATCH",
                "Ingestion policy digest does not match the enforced limits",
            )
    policy_digest = expected_policy_digest

    # Complete every untrusted filesystem read and exact manifest check before
    # the private CAS is mutated. Bytes remain inert in memory throughout.
    with _LinuxAnchoredSourceReader(root, fault_hook=fault_hook) as reader:
        read_sources = tuple(
            _read_declared_source(reader, entry, limits=limits) for entry in parsed.entries
        )
    observed_total = sum(len(item.content) for item in read_sources)
    if observed_total > limits.maximum_total_bytes:
        raise _fail("ECO_SOURCE_TOTAL_TOO_LARGE", "Source bundle exceeds the aggregate limit")

    entries: list[dict[str, Any]] = []
    for item in sorted(read_sources, key=lambda candidate: candidate.manifest.id):
        declared = item.manifest
        proof = artifact_store.put(
            io.BytesIO(item.content),
            storage_ref=f"artifact://sha256/{declared.sha256}",
            expected_sha256=declared.sha256,
            expected_byte_length=declared.byte_length,
            max_bytes=limits.maximum_file_bytes,
        )
        artifact_store.verify_availability(proof)
        entries.append(
            {
                "id": declared.id,
                "artifact": {
                    "ref": proof.storage_ref,
                    "contentDigest": proof.sha256,
                    "byteLength": proof.byte_length,
                    "dataClass": declared.data_class,
                },
                "mediaType": declared.media_type,
                "encoding": "utf-8",
                "provenance": {
                    "kind": "local-file",
                    "provenanceDigest": item.provenance_digest,
                    "remoteIdentityDigest": None,
                    "commitDigest": None,
                },
            }
        )

    record: dict[str, Any] = {
        "apiVersion": ORCHESTRATION_API_VERSION,
        "kind": "SourceBundle",
        "metadata": {
            "id": parsed.bundle_id,
            "projectId": project_id,
            "teamId": team_id,
            "runId": run_id,
            "createdAt": created_at,
            "recordDigest": "0" * 64,
        },
        "spec": {
            "ingestionPolicyDigest": policy_digest,
            "dataClass": parsed.data_class,
            "questionEntryId": parsed.question.id,
            "totalByteLength": observed_total,
            "entries": entries,
        },
    }
    record["metadata"]["recordDigest"] = orchestration_record_digest(record)
    return validate_orchestration_record(record)


def ingest_source_bundle_manifest_file(
    root: str | os.PathLike[str],
    manifest_path: str,
    artifact_store: ContentAddressedArtifactStore,
    **metadata: Any,
) -> dict[str, Any]:
    """CLI-facing composition for safe manifest load plus bounded ingestion."""

    expected_manifest_digest = metadata.pop("expected_manifest_digest", None)
    if expected_manifest_digest is not None and (
        not isinstance(expected_manifest_digest, str)
        or _SHA256_RE.fullmatch(expected_manifest_digest) is None
    ):
        raise _fail("ECO_SOURCE_MANIFEST_DIGEST_INVALID", "Manifest digest is invalid")
    limits = metadata.get("limits")
    if limits is not None and not isinstance(limits, SourceBundleLimits):
        raise TypeError("limits must be SourceBundleLimits")
    fault_hook = metadata.get("fault_hook")
    parsed = load_source_bundle_manifest(
        root,
        manifest_path,
        limits=limits,
        fault_hook=fault_hook,
    )
    if (
        expected_manifest_digest is not None
        and parsed.manifest_digest != expected_manifest_digest
    ):
        raise _fail("ECO_SOURCE_MANIFEST_CHANGED", "Manifest changed after preflight")
    return ingest_source_bundle(root, parsed, artifact_store, **metadata)
