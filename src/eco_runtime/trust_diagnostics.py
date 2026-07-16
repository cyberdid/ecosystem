from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import (
    MAX_EVIDENCE_BYTES,
    EvidenceIssuerPolicy,
    EvidenceTrustStore,
    TrustedEvidenceIngestor,
)
from .errors import EcoRuntimeError, RuntimePolicyError
from .digests import deployment_identity_digest
from .repository import protected_repository_path, repository_root_identity


_ENV_REF = re.compile(r"^env:[A-Z][A-Z0-9_]{0,127}$")
_SAFE_CODE = re.compile(r"^ECO_[A-Z0-9_]{1,96}$")
_ALLOWED_PATH_PREFIXES = ("wiki/", "docs/")


class VerifiedTrustBootstrap:
    """Verified snapshot material for an embedded, no-model execution root.

    This object is intentionally process-local.  It contains canonical envelope
    bytes solely so ``PolicyEngine`` can independently verify them again when
    it issues each decision; callers must never serialize or display it.
    """

    def __init__(
        self,
        *,
        repository_snapshot: dict[str, Any],
        repository_snapshot_envelope: bytes,
        evidence_policies: tuple[EvidenceIssuerPolicy, ...],
        repository_root_identity_digest: str,
        maximum_file_bytes: int,
    ) -> None:
        self.repository_snapshot = repository_snapshot
        self.repository_snapshot_envelope = repository_snapshot_envelope
        self.evidence_policies = evidence_policies
        self.repository_root_identity_digest = repository_root_identity_digest
        self.maximum_file_bytes = maximum_file_bytes


def _ready(component: str, code: str) -> dict[str, str]:
    return {"component": component, "status": "ready", "code": code}


def _blocked(component: str, code: str) -> dict[str, str]:
    if _SAFE_CODE.fullmatch(code) is None:
        code = "ECO_RUNTIME_TRUST_PROBE_FAILED"
    return {"component": component, "status": "blocked", "code": code}


def _exception_code(exc: BaseException) -> str:
    if isinstance(exc, EcoRuntimeError):
        return getattr(exc, "code", "ECO_RUNTIME_TRUST_PROBE_FAILED")
    return "ECO_RUNTIME_TRUST_PROBE_FAILED"


def _env_bytes(reference: object) -> bytes:
    if not isinstance(reference, str) or _ENV_REF.fullmatch(reference) is None:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_REFERENCE_INVALID", "Trust reference is invalid")
    value = os.environ.get(reference[4:])
    if value is None or not value:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_KEY_UNAVAILABLE", "Trust key is unavailable")
    encoded = value.encode("utf-8")
    if len(encoded) < 32:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_KEY_INVALID", "Trust key is invalid")
    return encoded


def _external_evidence(reference: object, *, repository_root: Path) -> bytes:
    """Open one externally managed envelope without revealing its location.

    Evidence locations are deliberately environment references.  They must be
    absolute, non-symlink regular files owned by the runtime boundary; the
    project configuration never supplies a relative path to follow.
    """

    if not isinstance(reference, str) or _ENV_REF.fullmatch(reference) is None:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_REFERENCE_INVALID", "Evidence reference is invalid")
    supplied = os.environ.get(reference[4:])
    if not supplied:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_UNAVAILABLE", "Evidence is unavailable")
    path = Path(supplied)
    if not path.is_absolute():
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED", "Evidence location is invalid")
    try:
        path.resolve(strict=True).relative_to(repository_root)
    except ValueError:
        pass
    except OSError as exc:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_UNAVAILABLE", "Evidence is unavailable") from exc
    else:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED", "Evidence location is invalid")
    try:
        initial = path.lstat()
    except OSError as exc:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_UNAVAILABLE", "Evidence is unavailable") from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED", "Evidence location is invalid")
    if initial.st_size < 1 or initial.st_size > MAX_EVIDENCE_BYTES:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_INVALID", "Evidence size is invalid")
    if os.name == "posix" and (initial.st_mode & 0o077 or initial.st_nlink != 1):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED", "Evidence location is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_UNAVAILABLE", "Evidence is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != initial.st_size
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
            or (os.name == "posix" and (opened.st_mode & 0o077 or opened.st_nlink != 1))
        ):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED", "Evidence location is invalid")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_INVALID", "Evidence is incomplete")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.fstat(descriptor).st_size != opened.st_size:
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_EVIDENCE_INVALID", "Evidence changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _expected_entries(trust: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    snapshot = trust.get("repositorySnapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("entries"), list):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    expected: dict[str, tuple[str, str, str]] = {}
    for entry in snapshot["entries"]:
        if not isinstance(entry, dict):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or not path.startswith(_ALLOWED_PATH_PREFIXES)
            or protected_repository_path(path)
            or path in expected
        ):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_SCOPE_INVALID", "Trust scope is invalid")
        classification = (entry.get("dataClass"), entry.get("trust"), entry.get("classificationAuthority"))
        if not all(isinstance(item, str) for item in classification):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        expected[path] = classification
    if not expected:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_SCOPE_INVALID", "Trust scope is empty")
    return expected


def _issuer_policies(trust: dict[str, Any]) -> tuple[EvidenceIssuerPolicy, ...]:
    issuer_specs = trust.get("evidence", {}).get("issuers")
    if not isinstance(issuer_specs, list) or not issuer_specs:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    try:
        policies = tuple(
            EvidenceIssuerPolicy(
                issuer_id=issuer["id"],
                key_id=issuer["keyId"],
                verification_key=_env_bytes(issuer["verificationKeyRef"]),
                allowed_kinds=frozenset(issuer["allowedKinds"]),
                allowed_projects=frozenset(issuer["allowedProjects"]),
                allowed_deployments=frozenset(issuer["allowedDeployments"]),
                allowed_suite_digests=frozenset(issuer["allowedSuiteDigests"]),
            )
            for issuer in issuer_specs
        )
    except (KeyError, TypeError) as exc:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid") from exc
    if not policies:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    return policies


def verified_trust_bootstrap(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> VerifiedTrustBootstrap:
    """Verify and return only the signed snapshot material needed by M4.

    It performs no repository read, creates no durable state and returns no
    content.  The separate policy engine re-ingests the returned envelope when
    it grants execution authority, so this preliminary verification can never
    become an authorization bypass.
    """

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    root = Path(repository).resolve(strict=True)
    project = bundle.get("project", {})
    trust = bundle.get("trust")
    if not root.is_dir() or not isinstance(project, dict) or not isinstance(trust, dict):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    project_id = project.get("metadata", {}).get("name")
    if not isinstance(project_id, str):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    expected = _expected_entries(trust)
    policies = _issuer_policies(trust)
    snapshot_spec = trust.get("repositorySnapshot")
    if not isinstance(snapshot_spec, dict):
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    maximum_file_bytes = snapshot_spec.get("maximumFileBytes")
    if not isinstance(maximum_file_bytes, int) or maximum_file_bytes < 1:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
    envelope = _external_evidence(snapshot_spec.get("envelopeRef"), repository_root=root)
    ingestor = TrustedEvidenceIngestor(EvidenceTrustStore(policies))
    root_identity = repository_root_identity(root)
    verified = ingestor.ingest_repository_snapshot(
        envelope,
        expected_project_id=project_id,
        expected_root_identity_digest=root_identity,
        now=instant,
    )
    record = verified.as_dict()
    expected_issuer = snapshot_spec.get("issuer")
    if not isinstance(expected_issuer, dict) or record["metadata"]["issuer"] != {
        "type": expected_issuer.get("recordIssuerType"),
        "id": expected_issuer.get("id"),
    }:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_SNAPSHOT_ISSUER_MISMATCH", "Snapshot issuer is invalid")
    actual = {
        item["path"]: (item["dataClass"], item["trust"], item["classificationAuthority"])
        for item in record["spec"]["entries"]
    }
    if actual != expected:
        raise RuntimePolicyError("ECO_RUNTIME_TRUST_SNAPSHOT_SCOPE_INVALID", "Snapshot scope is invalid")
    return VerifiedTrustBootstrap(
        repository_snapshot=record,
        repository_snapshot_envelope=envelope,
        evidence_policies=policies,
        repository_root_identity_digest=root_identity,
        maximum_file_bytes=maximum_file_bytes,
    )


def _result(checks: list[dict[str, str]], *, checked_entries: int = 0) -> dict[str, Any]:
    available = all(item["status"] == "ready" for item in checks)
    return {
        "available": available,
        "executionReady": False,
        "mode": "embedded-trust-bootstrap-verification",
        "checks": checks,
        "evidence": {"verifiedSnapshotEntries": checked_entries if available else 0},
        "execution": {
            "status": "not-started",
            "code": "ECO_RUNTIME_TRUST_VERIFICATION_ONLY",
        },
        "safety": {
            "repositoryRead": "not-started",
            "repositoryMutation": "denied",
            "modelEgress": "not-used",
            "writeAuthority": "not-created",
            "runtimeState": "not-created",
        },
    }


def runtime_trust_diagnostics(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify only an externally signed read-only bootstrap.

    This intentionally stops before policy planning, store creation, broker
    construction, model routing, or a repository read.  The current RunPlan
    contract is model-routed; using it for a no-model health check would create
    a false adapter lifecycle.  A future explicit no-model A1 contract may use
    this verified bootstrap as its input.
    """

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    checks: list[dict[str, str]] = []
    try:
        root = Path(repository).resolve(strict=True)
        project = bundle.get("project", {})
        trust = bundle.get("trust")
        if not root.is_dir() or not isinstance(project, dict) or not isinstance(trust, dict):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        project_id = project.get("metadata", {}).get("name")
        if not isinstance(project_id, str):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        expected = _expected_entries(trust)
        issuer_specs = trust.get("evidence", {}).get("issuers")
        if not isinstance(issuer_specs, list) or not issuer_specs:
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        checks.append(_ready("trust-config", "ECO_RUNTIME_TRUST_CONFIG_READY"))
    except Exception as exc:
        checks.append(_blocked("trust-config", _exception_code(exc)))
        return _result(checks)

    try:
        policies = tuple(
            EvidenceIssuerPolicy(
                issuer_id=issuer["id"],
                key_id=issuer["keyId"],
                verification_key=_env_bytes(issuer["verificationKeyRef"]),
                allowed_kinds=frozenset(issuer["allowedKinds"]),
                allowed_projects=frozenset(issuer["allowedProjects"]),
                allowed_deployments=frozenset(issuer["allowedDeployments"]),
                allowed_suite_digests=frozenset(issuer["allowedSuiteDigests"]),
            )
            for issuer in issuer_specs
        )
        checks.append(_ready("evidence-key", "ECO_RUNTIME_TRUST_KEY_READY"))
    except Exception as exc:
        checks.append(_blocked("evidence-key", _exception_code(exc)))
        return _result(checks)

    try:
        snapshot_spec = trust["repositorySnapshot"]
        envelope = _external_evidence(snapshot_spec["envelopeRef"], repository_root=root)
        ingestor = TrustedEvidenceIngestor(EvidenceTrustStore(policies))
        verified = ingestor.ingest_repository_snapshot(
            envelope,
            expected_project_id=project_id,
            expected_root_identity_digest=repository_root_identity(root),
            now=instant,
        )
        record = verified.as_dict()
        expected_issuer = snapshot_spec["issuer"]
        if record["metadata"]["issuer"] != {
            "type": expected_issuer["recordIssuerType"],
            "id": expected_issuer["id"],
        }:
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_SNAPSHOT_ISSUER_MISMATCH", "Snapshot issuer is invalid")
        actual = {
            item["path"]: (item["dataClass"], item["trust"], item["classificationAuthority"])
            for item in record["spec"]["entries"]
        }
        if actual != expected:
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_SNAPSHOT_SCOPE_INVALID", "Snapshot scope is invalid")
        checks.append(_ready("repository-snapshot", "ECO_RUNTIME_TRUST_SNAPSHOT_VERIFIED"))
    except Exception as exc:
        checks.append(_blocked("repository-snapshot", _exception_code(exc)))
        return _result(checks)

    try:
        conformance = trust.get("conformance", {})
        suites = conformance.get("trustedSuites")
        requirements = conformance.get("requiredObservations")
        deployments = bundle.get("deployments", {}).get("deployments", [])
        if not isinstance(suites, list) or not isinstance(requirements, list) or not isinstance(deployments, list):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        trusted_suites = frozenset(
            suite["digest"] for suite in suites if isinstance(suite, dict) and isinstance(suite.get("digest"), str)
        )
        if len(trusted_suites) != len(suites):
            raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
        deployments_by_id = {
            deployment.get("id"): deployment
            for deployment in deployments
            if isinstance(deployment, dict) and isinstance(deployment.get("id"), str)
        }
        seen_deployments: set[str] = set()
        for requirement in requirements:
            if not isinstance(requirement, dict):
                raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
            deployment_id = requirement.get("deploymentId")
            suite_digest = requirement.get("suiteDigest")
            deployment = deployments_by_id.get(deployment_id)
            if (
                not isinstance(deployment_id, str)
                or not isinstance(suite_digest, str)
                or deployment_id in seen_deployments
                or deployment is None
                or suite_digest not in trusted_suites
            ):
                raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFIG_INVALID", "Trust configuration is invalid")
            seen_deployments.add(deployment_id)
            encoded = _external_evidence(requirement.get("envelopeRef"), repository_root=root)
            verified_observation = ingestor.ingest_observed_capabilities(
                encoded,
                expected_deployment_id=deployment_id,
                expected_deployment_identity_digest=deployment_identity_digest(deployment),
                trusted_suite_digests=trusted_suites,
                now=instant,
            ).as_dict()
            if verified_observation["spec"]["suite"]["digest"] != suite_digest:
                raise RuntimePolicyError("ECO_RUNTIME_TRUST_CONFORMANCE_MISMATCH", "Conformance evidence is invalid")
        checks.append(_ready("conformance", "ECO_RUNTIME_TRUST_CONFORMANCE_VERIFIED"))
    except Exception as exc:
        checks.append(_blocked("conformance", _exception_code(exc)))
        return _result(checks)
    return _result(checks, checked_entries=len(expected))
