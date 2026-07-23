from __future__ import annotations

import copy
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import threading
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .contracts import API_VERSION, tool_argument_errors, validate_record
from .digests import canonical_json, semantic_digest
from .errors import ContractValidationError, RuntimePolicyError
from .repository import protected_repository_path, repository_snapshot_entries, root_identity_from_stat


EVIDENCE_PROTOCOL = "eco-trusted-evidence-v1"
ATTESTED_EVIDENCE_PROTOCOL = "eco-trusted-evidence-v2"
EVIDENCE_AUTH_DOMAIN = "eco-trusted-evidence-authentication-v1"
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
ENDPOINT_REF_RE = re.compile(r"^env:[A-Z_][A-Z0-9_]{0,127}$")
DATA_CLASSES = frozenset(f"D{level}" for level in range(5))
TRUST_LEVELS = frozenset(f"P{level}" for level in range(1, 5))
TRUST_ORDER = {f"P{level}": level for level in range(5)}

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
class EvidenceProvenance:
    envelope_id: str
    envelope_digest: str
    issuer_id: str
    key_id: str
    issued_at: str
    expires_at: str

    def as_dict(self) -> dict[str, str]:
        return {
            "envelopeId": self.envelope_id,
            "envelopeDigest": self.envelope_digest,
            "issuerId": self.issuer_id,
            "keyId": self.key_id,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
        }


@dataclass(frozen=True)
class VerifiedEvidence:
    canonical_record: bytes = dataclass_field(repr=False)
    provenance: EvidenceProvenance

    def as_dict(self) -> dict[str, Any]:
        return json.loads(self.canonical_record.decode("utf-8"))


@dataclass(frozen=True)
class ObservationBindingExpectation:
    project_id: str
    endpoint_ref: str
    endpoint_reference_digest: str
    resolved_endpoint_digest: str
    model: str

    def __post_init__(self) -> None:
        _evidence_attestation(
            {
                "projectId": self.project_id,
                "endpointRef": self.endpoint_ref,
                "endpointReferenceDigest": self.endpoint_reference_digest,
                "resolvedEndpointDigest": self.resolved_endpoint_digest,
                "requestedModel": self.model,
                "reportedModels": [self.model],
            }
        )

    def ingestor_arguments(self) -> dict[str, str]:
        return {
            "expected_project_id": self.project_id,
            "expected_endpoint_ref": self.endpoint_ref,
            "expected_endpoint_reference_digest": self.endpoint_reference_digest,
            "expected_resolved_endpoint_digest": self.resolved_endpoint_digest,
            "expected_model": self.model,
        }


def _verified_evidence(
    record: dict[str, Any], body: dict[str, Any], encoded: bytes
) -> VerifiedEvidence:
    return VerifiedEvidence(
        canonical_json(record).encode("utf-8"),
        EvidenceProvenance(
            envelope_id=body["envelopeId"],
            envelope_digest=hashlib.sha256(encoded).hexdigest(),
            issuer_id=body["issuer"]["id"],
            key_id=body["issuer"]["keyId"],
            issued_at=body["issuedAt"],
            expires_at=body["expiresAt"],
        ),
    )


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimePolicyError("ECO_CLOCK_INVALID", "Evidence clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _auth_bytes(body: Mapping[str, Any]) -> bytes:
    return canonical_json(
        {"domain": EVIDENCE_AUTH_DOMAIN, "payload": dict(body)}
    ).encode("utf-8")


def _evidence_attestation(value: object) -> dict[str, Any]:
    required = {
        "projectId",
        "endpointRef",
        "endpointReferenceDigest",
        "resolvedEndpointDigest",
        "requestedModel",
        "reportedModels",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("evidence attestation shape is invalid")
    project_id = value["projectId"]
    endpoint_ref = value["endpointRef"]
    requested_model = value["requestedModel"]
    reported_models = value["reportedModels"]
    if (
        not isinstance(project_id, str)
        or len(project_id) > 128
        or PROJECT_RE.fullmatch(project_id) is None
        or not isinstance(endpoint_ref, str)
        or ENDPOINT_REF_RE.fullmatch(endpoint_ref) is None
        or not isinstance(value["endpointReferenceDigest"], str)
        or DIGEST_RE.fullmatch(value["endpointReferenceDigest"]) is None
        or value["endpointReferenceDigest"]
        != semantic_digest({"endpointRef": endpoint_ref})
        or not isinstance(value["resolvedEndpointDigest"], str)
        or DIGEST_RE.fullmatch(value["resolvedEndpointDigest"]) is None
        or not isinstance(requested_model, str)
        or not 1 <= len(requested_model) <= 512
        or not isinstance(reported_models, list)
        or not 1 <= len(reported_models) <= 16
        or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in reported_models)
        or reported_models != sorted(set(reported_models))
    ):
        raise ValueError("evidence attestation value is invalid")
    return copy.deepcopy(value)


@dataclass(frozen=True)
class EvidenceIssuerPolicy:
    issuer_id: str
    key_id: str
    verification_key: bytes
    allowed_kinds: frozenset[str]
    allowed_projects: frozenset[str] = frozenset()
    allowed_deployments: frozenset[str] = frozenset()
    allowed_suite_digests: frozenset[str] = frozenset()
    allowed_platform_profiles: frozenset[str] = frozenset()
    allowed_backend_instances: frozenset[str] = frozenset()
    allowed_runner_digests: frozenset[str] = frozenset()
    allowed_backend_implementation_digests: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if any(
            type(value) is not frozenset
            for value in (
                self.allowed_kinds,
                self.allowed_projects,
                self.allowed_deployments,
                self.allowed_suite_digests,
                self.allowed_platform_profiles,
                self.allowed_backend_instances,
                self.allowed_runner_digests,
                self.allowed_backend_implementation_digests,
            )
        ):
            raise ValueError("evidence issuer allowlists must be immutable frozensets")
        if ID_RE.fullmatch(self.issuer_id) is None or ID_RE.fullmatch(self.key_id) is None:
            raise ValueError("evidence issuer and key ids must be bounded safe identifiers")
        if not isinstance(self.verification_key, bytes) or len(self.verification_key) < 32:
            raise ValueError("evidence verification key must contain at least 32 bytes")
        if not self.allowed_kinds or not self.allowed_kinds <= {
            "RepositorySnapshot",
            "AdapterConformanceProfile",
            "PlatformBackendConformanceProfile",
        }:
            raise ValueError("evidence issuer kind allowlist is invalid")
        if any(PROJECT_RE.fullmatch(item) is None for item in self.allowed_projects):
            raise ValueError("evidence project allowlist is invalid")
        if any(ID_RE.fullmatch(item) is None for item in self.allowed_deployments):
            raise ValueError("evidence deployment allowlist is invalid")
        if any(DIGEST_RE.fullmatch(item) is None for item in self.allowed_suite_digests):
            raise ValueError("evidence suite allowlist is invalid")
        if any(ID_RE.fullmatch(item) is None for item in self.allowed_platform_profiles):
            raise ValueError("evidence platform profile allowlist is invalid")
        if any(DIGEST_RE.fullmatch(item) is None for item in self.allowed_backend_instances):
            raise ValueError("evidence backend instance allowlist is invalid")
        if any(DIGEST_RE.fullmatch(item) is None for item in self.allowed_runner_digests):
            raise ValueError("evidence runner digest allowlist is invalid")
        if any(
            DIGEST_RE.fullmatch(item) is None
            for item in self.allowed_backend_implementation_digests
        ):
            raise ValueError("evidence backend implementation allowlist is invalid")


class HmacEvidenceSigner:
    """Symmetric executable signer for embedded deployments.

    HMAC authenticates the issuer boundary but provides no third-party
    non-repudiation. A future asymmetric signer can preserve the same envelope.
    """

    def __init__(self, issuer_id: str, key_id: str, signing_key: bytes) -> None:
        if ID_RE.fullmatch(issuer_id) is None or ID_RE.fullmatch(key_id) is None:
            raise ValueError("evidence signer ids must be bounded safe identifiers")
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("evidence signing key must contain at least 32 bytes")
        self.issuer_id = issuer_id
        self.key_id = key_id
        self._key = bytes(signing_key)

    def sign(
        self,
        record: dict[str, Any],
        *,
        envelope_id: str,
        issued_at: datetime,
        expires_at: datetime,
        attestation: Mapping[str, Any] | None = None,
    ) -> bytes:
        if ID_RE.fullmatch(envelope_id) is None:
            raise ValueError("envelope_id must be a bounded safe identifier")
        try:
            record = copy.deepcopy(validate_record(record))
        except ContractValidationError as exc:
            raise RuntimePolicyError("ECO_EVIDENCE_RECORD_INVALID", "Evidence record is invalid") from exc
        issued = issued_at.astimezone(timezone.utc) if issued_at.tzinfo is not None else None
        expiry = expires_at.astimezone(timezone.utc) if expires_at.tzinfo is not None else None
        if issued is None or expiry is None:
            raise RuntimePolicyError("ECO_CLOCK_INVALID", "Evidence clock must be timezone-aware")
        if expiry <= issued:
            raise RuntimePolicyError("ECO_EVIDENCE_WINDOW_INVALID", "Evidence validity window is invalid")
        metadata = record["metadata"]
        record_id = metadata["id"]
        body = {
            "protocol": (
                ATTESTED_EVIDENCE_PROTOCOL
                if attestation is not None
                else EVIDENCE_PROTOCOL
            ),
            "envelopeId": envelope_id,
            "issuer": {"id": self.issuer_id, "keyId": self.key_id},
            "issuedAt": _timestamp(issued),
            "expiresAt": _timestamp(expiry),
            "subject": {
                "kind": record["kind"],
                "id": record_id,
                "digest": semantic_digest(record),
            },
            "record": record,
        }
        if attestation is not None:
            body["attestation"] = _evidence_attestation(dict(attestation))
        tag = hmac.new(self._key, _auth_bytes(body), hashlib.sha256).hexdigest()
        return canonical_json(
            {
                **body,
                "signature": {"algorithm": "HMAC-SHA256", "tag": tag},
            }
        ).encode("utf-8")


class EvidenceTrustStore:
    def __init__(self, policies: Iterable[EvidenceIssuerPolicy]) -> None:
        self._policies: dict[tuple[str, str], EvidenceIssuerPolicy] = {}
        for policy in policies:
            key = (policy.issuer_id, policy.key_id)
            if key in self._policies:
                raise ValueError("duplicate evidence issuer/key policy")
            self._policies[key] = policy
        if not self._policies:
            raise ValueError("at least one evidence issuer policy is required")

    def open(
        self,
        encoded: bytes,
        *,
        now: datetime,
        maximum_clock_skew_seconds: int = 300,
    ) -> tuple[dict[str, Any], EvidenceIssuerPolicy, dict[str, Any]]:
        if not isinstance(encoded, bytes) or len(encoded) > MAX_EVIDENCE_BYTES:
            raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence envelope size is invalid")
        try:
            envelope = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence envelope is unreadable") from exc
        if not isinstance(envelope, dict) or canonical_json(envelope).encode("utf-8") != encoded:
            raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence envelope is not canonical")
        signature = envelope.get("signature")
        body = {key: value for key, value in envelope.items() if key != "signature"}
        expected_body_keys = {
            "protocol",
            "envelopeId",
            "issuer",
            "issuedAt",
            "expiresAt",
            "subject",
            "record",
        }
        protocol = body.get("protocol")
        if "attestation" in body:
            expected_body_keys.add("attestation")
            try:
                _evidence_attestation(body["attestation"])
            except ValueError as exc:
                raise RuntimePolicyError(
                    "ECO_EVIDENCE_INVALID", "Evidence attestation is invalid"
                ) from exc
        issuer = body.get("issuer")
        subject = body.get("subject")
        if (
            set(body) != expected_body_keys
            or protocol not in {EVIDENCE_PROTOCOL, ATTESTED_EVIDENCE_PROTOCOL}
            or (protocol == EVIDENCE_PROTOCOL and "attestation" in body)
            or (protocol == ATTESTED_EVIDENCE_PROTOCOL and "attestation" not in body)
            or not isinstance(body.get("envelopeId"), str)
            or ID_RE.fullmatch(body["envelopeId"]) is None
            or not isinstance(issuer, dict)
            or set(issuer) != {"id", "keyId"}
            or not isinstance(issuer.get("id"), str)
            or not isinstance(issuer.get("keyId"), str)
            or not isinstance(subject, dict)
            or set(subject) != {"kind", "id", "digest"}
            or not isinstance(signature, dict)
            or set(signature) != {"algorithm", "tag"}
            or signature.get("algorithm") != "HMAC-SHA256"
            or not isinstance(signature.get("tag"), str)
            or DIGEST_RE.fullmatch(signature["tag"]) is None
        ):
            raise RuntimePolicyError("ECO_EVIDENCE_INVALID", "Evidence envelope shape is invalid")
        policy = self._policies.get((issuer["id"], issuer["keyId"]))
        if policy is None:
            raise RuntimePolicyError("ECO_EVIDENCE_ISSUER_UNTRUSTED", "Evidence issuer is not trusted")
        expected = hmac.new(policy.verification_key, _auth_bytes(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature["tag"], expected):
            raise RuntimePolicyError("ECO_EVIDENCE_SIGNATURE_INVALID", "Evidence signature is invalid")
        issued = _parse_timestamp(body["issuedAt"])
        expiry = _parse_timestamp(body["expiresAt"])
        current = now.astimezone(timezone.utc) if now.tzinfo is not None else None
        if current is None:
            raise RuntimePolicyError("ECO_CLOCK_INVALID", "Evidence clock must be timezone-aware")
        if expiry <= issued or issued > current + timedelta(seconds=maximum_clock_skew_seconds):
            raise RuntimePolicyError("ECO_EVIDENCE_WINDOW_INVALID", "Evidence validity window is invalid")
        if current >= expiry:
            raise RuntimePolicyError("ECO_EVIDENCE_EXPIRED", "Evidence envelope has expired")
        record = body.get("record")
        try:
            record = copy.deepcopy(validate_record(record))
        except ContractValidationError as exc:
            raise RuntimePolicyError("ECO_EVIDENCE_RECORD_INVALID", "Evidence record is invalid") from exc
        if (
            record["kind"] not in policy.allowed_kinds
            or subject
            != {
                "kind": record["kind"],
                "id": record["metadata"]["id"],
                "digest": semantic_digest(record),
            }
        ):
            raise RuntimePolicyError("ECO_EVIDENCE_BINDING_INVALID", "Evidence binding is invalid")
        return record, policy, copy.deepcopy(body)


class TrustedEvidenceIngestor:
    def __init__(
        self,
        trust_store: EvidenceTrustStore,
        *,
        maximum_snapshot_age_seconds: int = 3600,
        maximum_observation_age_seconds: int = 2_764_800,
        maximum_clock_skew_seconds: int = 300,
    ) -> None:
        if maximum_snapshot_age_seconds < 1 or maximum_observation_age_seconds < 1:
            raise ValueError("evidence age limits must be positive")
        if maximum_clock_skew_seconds < 0:
            raise ValueError("maximum_clock_skew_seconds must be non-negative")
        self._trust_store = trust_store
        self._snapshot_age = maximum_snapshot_age_seconds
        self._observation_age = maximum_observation_age_seconds
        self._clock_skew = maximum_clock_skew_seconds
        self._seen: dict[str, str] = {}
        self._seen_lock = threading.Lock()

    def _open(self, encoded: bytes, *, now: datetime) -> tuple[dict[str, Any], EvidenceIssuerPolicy, dict[str, Any]]:
        record, policy, body = self._trust_store.open(
            encoded, now=now, maximum_clock_skew_seconds=self._clock_skew
        )
        digest = hashlib.sha256(encoded).hexdigest()
        with self._seen_lock:
            previous = self._seen.get(body["envelopeId"])
            if previous is not None and previous != digest:
                raise RuntimePolicyError("ECO_EVIDENCE_ID_CONFLICT", "Evidence id has another digest")
            self._seen[body["envelopeId"]] = digest
        return record, policy, body

    def ingest_repository_snapshot(
        self,
        encoded: bytes,
        *,
        expected_project_id: str,
        expected_root_identity_digest: str,
        now: datetime,
    ) -> VerifiedEvidence:
        record, policy, body = self._open(encoded, now=now)
        if record["kind"] != "RepositorySnapshot":
            raise RuntimePolicyError("ECO_EVIDENCE_KIND_INVALID", "Evidence is not a repository snapshot")
        created = _parse_timestamp(record["metadata"]["createdAt"])
        current = now.astimezone(timezone.utc)
        issuer = record["metadata"]["issuer"]
        if (
            record["metadata"]["projectId"] != expected_project_id
            or (policy.allowed_projects and expected_project_id not in policy.allowed_projects)
            or record["spec"]["rootIdentityDigest"] != expected_root_identity_digest
            or issuer["id"] != body["issuer"]["id"]
            or created > current + timedelta(seconds=self._clock_skew)
            or current - created >= timedelta(seconds=self._snapshot_age)
        ):
            raise RuntimePolicyError("ECO_SNAPSHOT_EVIDENCE_MISMATCH", "Snapshot evidence does not match trust context")
        repository_snapshot_entries(record, project_id=expected_project_id)
        return _verified_evidence(record, body, encoded)

    def ingest_observed_capabilities(
        self,
        encoded: bytes,
        *,
        expected_deployment_id: str,
        expected_deployment_identity_digest: str,
        trusted_suite_digests: frozenset[str],
        now: datetime,
        expected_project_id: str | None = None,
        expected_endpoint_ref: str | None = None,
        expected_endpoint_reference_digest: str | None = None,
        expected_resolved_endpoint_digest: str | None = None,
        expected_model: str | None = None,
    ) -> VerifiedEvidence:
        record, policy, body = self._open(encoded, now=now)
        if record["kind"] != "AdapterConformanceProfile":
            raise RuntimePolicyError("ECO_EVIDENCE_KIND_INVALID", "Evidence is not an observation")
        tested = _parse_timestamp(record["metadata"]["testedAt"])
        valid_until = _parse_timestamp(record["metadata"]["validUntil"])
        current = now.astimezone(timezone.utc)
        suite_digest = record["spec"]["suite"]["digest"]
        binding = body.get("attestation")
        expected_binding = any(
            value is not None
            for value in (
                expected_project_id,
                expected_endpoint_ref,
                expected_endpoint_reference_digest,
                expected_resolved_endpoint_digest,
                expected_model,
            )
        )
        if (
            record["metadata"]["deploymentId"] != expected_deployment_id
            or (policy.allowed_deployments and expected_deployment_id not in policy.allowed_deployments)
            or record["spec"]["deploymentIdentityDigest"] != expected_deployment_identity_digest
            or suite_digest not in trusted_suite_digests
            or (policy.allowed_suite_digests and suite_digest not in policy.allowed_suite_digests)
            or valid_until <= tested
            or tested > current + timedelta(seconds=self._clock_skew)
            or current >= valid_until
            or current - tested > timedelta(seconds=self._observation_age)
            or valid_until - tested > timedelta(seconds=self._observation_age)
            or (expected_binding and not isinstance(binding, dict))
            or (
                expected_project_id is not None
                and binding.get("projectId") != expected_project_id
            )
            or (
                expected_project_id is not None
                and policy.allowed_projects
                and expected_project_id not in policy.allowed_projects
            )
            or (
                expected_endpoint_ref is not None
                and binding.get("endpointRef") != expected_endpoint_ref
            )
            or (
                expected_endpoint_reference_digest is not None
                and binding.get("endpointReferenceDigest")
                != expected_endpoint_reference_digest
            )
            or (
                expected_resolved_endpoint_digest is not None
                and binding.get("resolvedEndpointDigest")
                != expected_resolved_endpoint_digest
            )
            or (
                expected_model is not None
                and (
                    binding.get("requestedModel") != expected_model
                    or binding.get("reportedModels") != [expected_model]
                )
            )
        ):
            raise RuntimePolicyError("ECO_OBSERVATION_EVIDENCE_MISMATCH", "Observation evidence does not match trust context")
        return _verified_evidence(record, body, encoded)

    def ingest_platform_backend_conformance(
        self,
        encoded: bytes,
        *,
        expected_platform_profile_id: str,
        expected_platform_profile_digest: str,
        expected_backend_instance_digest: str,
        expected_backend_implementation_digest: str,
        expected_runner_digest: str,
        expected_distribution_manifest_digest: str,
        trusted_suite_digests: frozenset[str],
        now: datetime,
    ) -> VerifiedEvidence:
        """Authenticate exact-bound backend evidence without consuming it as authority."""

        record, policy, body = self._open(encoded, now=now)
        if record["kind"] != "PlatformBackendConformanceProfile":
            raise RuntimePolicyError(
                "ECO_EVIDENCE_KIND_INVALID", "Evidence is not backend conformance"
            )
        tested = _parse_timestamp(record["metadata"]["testedAt"])
        valid_until = _parse_timestamp(record["metadata"]["validUntil"])
        current = now.astimezone(timezone.utc)
        suite_digest = record["spec"]["suite"]["digest"]
        backend_instance = record["spec"]["backend"]["instanceDigest"]
        backend_implementation = record["spec"]["backend"]["implementationDigest"]
        runner_digest = record["spec"]["runnerDigest"]
        if (
            record["metadata"]["platformProfileId"]
            != expected_platform_profile_id
            or record["spec"]["platform"]["id"] != expected_platform_profile_id
            or record["spec"]["platformProfileDigest"]
            != expected_platform_profile_digest
            or backend_instance != expected_backend_instance_digest
            or backend_implementation != expected_backend_implementation_digest
            or runner_digest != expected_runner_digest
            or record["spec"]["distributionManifestDigest"]
            != expected_distribution_manifest_digest
            or suite_digest not in trusted_suite_digests
            or (
                policy.allowed_suite_digests
                and suite_digest not in policy.allowed_suite_digests
            )
            or (
                policy.allowed_platform_profiles
                and expected_platform_profile_id
                not in policy.allowed_platform_profiles
            )
            or (
                policy.allowed_backend_instances
                and backend_instance not in policy.allowed_backend_instances
            )
            or (
                policy.allowed_runner_digests
                and runner_digest not in policy.allowed_runner_digests
            )
            or (
                policy.allowed_backend_implementation_digests
                and backend_implementation
                not in policy.allowed_backend_implementation_digests
            )
            or valid_until <= tested
            or tested > current + timedelta(seconds=self._clock_skew)
            or current >= valid_until
            or current - tested > timedelta(seconds=self._observation_age)
            or valid_until - tested > timedelta(seconds=self._observation_age)
        ):
            raise RuntimePolicyError(
                "ECO_PLATFORM_CONFORMANCE_EVIDENCE_MISMATCH",
                "Backend conformance evidence does not match trust context",
            )
        return _verified_evidence(record, body, encoded)


@dataclass(frozen=True)
class SnapshotEntryClassification:
    data_class: str
    trust: str
    classification_authority: str

    def __post_init__(self) -> None:
        if self.data_class not in DATA_CLASSES:
            raise ValueError("snapshot data class is invalid")
        if self.trust not in TRUST_LEVELS:
            raise ValueError("snapshot trust is invalid")
        if self.classification_authority not in {"operator", "policy"}:
            raise ValueError("snapshot classification authority is invalid")


def _same_file(before: os.stat_result, after: os.stat_result, byte_count: int) -> bool:
    return byte_count == after.st_size and all(
        getattr(before, name) == getattr(after, name)
        for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


class LinuxRepositorySnapshotGenerator:
    """Linux/WSL executable proof for descriptor-anchored snapshot generation."""

    def __init__(self, root: str | os.PathLike[str], *, maximum_file_bytes: int = 16 * 1024 * 1024) -> None:
        if not sys.platform.startswith("linux") or os.uname().machine not in {"x86_64", "aarch64"}:
            raise RuntimePolicyError("ECO_SNAPSHOT_GENERATOR_UNSUPPORTED", "Linux openat2 is required")
        if not isinstance(maximum_file_bytes, int) or maximum_file_bytes < 1:
            raise ValueError("maximum_file_bytes must be positive")
        trusted_root = Path(root).resolve(strict=True)
        if not trusted_root.is_dir():
            raise RuntimePolicyError("ECO_SNAPSHOT_ROOT_INVALID", "Snapshot root is invalid")
        self._root = trusted_root
        self._root_fd = os.open(
            trusted_root,
            os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_PATH", os.O_RDONLY),
        )
        self._maximum_file_bytes = maximum_file_bytes
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._closed = True

    def __enter__(self) -> LinuxRepositorySnapshotGenerator:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _open(self, path: str) -> int:
        if self._closed:
            raise RuntimePolicyError("ECO_SNAPSHOT_GENERATOR_CLOSED", "Snapshot generator is closed")
        how = _OpenHow(
            flags=os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK,
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
        code = (
            "ECO_SNAPSHOT_GENERATOR_UNSUPPORTED"
            if error in {errno.ENOSYS, errno.EINVAL}
            else "ECO_SNAPSHOT_PATH_ESCAPE"
            if error in {errno.EXDEV, errno.ELOOP}
            else "ECO_SNAPSHOT_PATH_UNREADABLE"
        )
        raise RuntimePolicyError(code, "Snapshot path could not be opened safely")

    def _entry(self, path: str, classification: SnapshotEntryClassification) -> dict[str, Any]:
        if tool_argument_errors("repository.read", {"path": path}) or protected_repository_path(path):
            raise RuntimePolicyError("ECO_SNAPSHOT_PATH_DENIED", "Snapshot path is not allowed")
        descriptor = self._open(path)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise RuntimePolicyError("ECO_SNAPSHOT_FILE_UNSAFE", "Snapshot path is not a unique regular file")
            if before.st_size > self._maximum_file_bytes:
                raise RuntimePolicyError("ECO_SNAPSHOT_FILE_TOO_LARGE", "Snapshot file exceeds size limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, self._maximum_file_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self._maximum_file_bytes:
                    raise RuntimePolicyError("ECO_SNAPSHOT_FILE_TOO_LARGE", "Snapshot file exceeds size limit")
            after = os.fstat(descriptor)
            content = b"".join(chunks)
            if not _same_file(before, after, len(content)):
                raise RuntimePolicyError("ECO_SNAPSHOT_FILE_CHANGED", "Snapshot file changed during hashing")
            if b"\x00" in content:
                raise RuntimePolicyError("ECO_SNAPSHOT_BINARY_DENIED", "Snapshot file is not approved text")
            try:
                content.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RuntimePolicyError("ECO_SNAPSHOT_TEXT_INVALID", "Snapshot file is not valid UTF-8") from exc
            return {
                "path": path,
                "contentDigest": hashlib.sha256(content).hexdigest(),
                "byteLength": len(content),
                "dataClass": classification.data_class,
                "trust": classification.trust,
                "classificationAuthority": classification.classification_authority,
            }
        finally:
            os.close(descriptor)

    def generate(
        self,
        *,
        snapshot_id: str,
        project_id: str,
        issuer_type: str,
        issuer_id: str,
        snapshot_trust: str,
        classifications: Mapping[str, SnapshotEntryClassification],
        now: datetime,
        source_revision: str | None = None,
    ) -> dict[str, Any]:
        if ID_RE.fullmatch(snapshot_id) is None or ID_RE.fullmatch(issuer_id) is None:
            raise ValueError("snapshot and issuer ids must be bounded safe identifiers")
        if PROJECT_RE.fullmatch(project_id) is None or issuer_type not in {"operator", "runtime"}:
            raise ValueError("snapshot project or issuer type is invalid")
        if snapshot_trust not in TRUST_LEVELS or not classifications:
            raise ValueError("snapshot trust or classification map is invalid")
        if source_revision is not None and not 1 <= len(source_revision) <= 256:
            raise ValueError("source_revision is invalid")
        if any(not isinstance(path, str) for path in classifications):
            raise ValueError("snapshot paths must be strings")
        paths = sorted(classifications)
        if len(paths) != len(set(paths)):
            raise ValueError("snapshot paths must be unique")
        entries: list[dict[str, Any]] = []
        for path in paths:
            classification = classifications[path]
            if not isinstance(classification, SnapshotEntryClassification):
                raise ValueError("every snapshot path requires explicit classification")
            if TRUST_ORDER[classification.trust] > TRUST_ORDER[snapshot_trust]:
                raise RuntimePolicyError("ECO_SNAPSHOT_TRUST_INVALID", "Entry trust exceeds snapshot trust")
            entries.append(self._entry(path, classification))
        snapshot = {
            "apiVersion": API_VERSION,
            "kind": "RepositorySnapshot",
            "metadata": {
                "id": snapshot_id,
                "projectId": project_id,
                "createdAt": _timestamp(now),
                "issuer": {"type": issuer_type, "id": issuer_id},
            },
            "spec": {
                "rootIdentityDigest": root_identity_from_stat(os.fstat(self._root_fd)),
                "trust": snapshot_trust,
                **({"sourceRevision": source_revision} if source_revision is not None else {}),
                "entries": entries,
            },
        }
        try:
            validate_record(snapshot)
            repository_snapshot_entries(snapshot, project_id=project_id)
        except ContractValidationError as exc:
            raise RuntimePolicyError("ECO_SNAPSHOT_INVALID", "Generated snapshot is invalid") from exc
        return snapshot
