from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .constants import CONFIG_FILES, SCHEMA_FILES
from .errors import EcoError

SECRET_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|credential|verification[_-]?key|signing[_-]?key|proof[_-]?key|audit[_-]?key|path[_-]?key)",
    re.I,
)
SAFE_REFERENCE_RE = re.compile(r"^(?:env:|config:|secret://|\$\{|<|placeholder$|none$)", re.I)
ARTIFACT_TRUST_ORDER = {f"P{level}": level for level in range(5)}


def ensure_within(root: Path, candidate: Path) -> Path:
    root = root.resolve()
    candidate = candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EcoError(f"Path escapes repository root: {candidate}") from exc
    return candidate


def config_directory(repo: Path, config_root: str) -> Path:
    root_path = Path(config_root)
    if root_path.is_absolute():
        raise EcoError("--config-root must be relative to the repository")
    return ensure_within(repo, repo / root_path)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise EcoError(f"Missing configuration file: {path}")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise EcoError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EcoError(f"Configuration root must be an object: {path}")
    return value


def dump_yaml(value: dict[str, Any]) -> str:
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False, width=100)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Atomically replace one regular file while preserving an existing mode.

    Callers that cross an ownership boundary must still validate path topology
    before calling this helper.  This function deliberately never follows a
    final symlink to write its target: ``os.replace`` replaces the directory
    entry itself.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode: int | None = None
    try:
        status = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISREG(status.st_mode):
            existing_mode = stat.S_IMODE(status.st_mode)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if existing_mode is not None:
            os.chmod(temporary, existing_mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_write(path: Path, content: str) -> None:
    atomic_write_bytes(path, content.encode("utf-8"))


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_bundle(repo: Path, config_root: str) -> tuple[Path, dict[str, dict[str, Any]], dict[str, Path]]:
    directory = config_directory(repo, config_root)
    project_path = directory / CONFIG_FILES["project"]
    project = load_yaml(project_path)

    references = project.get("references", {})
    paths: dict[str, Path] = {"project": project_path}
    bundle: dict[str, dict[str, Any]] = {"project": project}

    for key in ("instructions", "capabilities", "deployments", "tools", "trust"):
        relative = references.get(key, CONFIG_FILES[key])
        if not isinstance(relative, str):
            raise EcoError(f"project.references.{key} must be a relative path")
        path = ensure_within(directory, directory / relative)
        paths[key] = path
        bundle[key] = load_yaml(path)

    return directory, bundle, paths


def _load_schema(name: str) -> dict[str, Any]:
    schema = resources.files("eco_cli").joinpath("schemas", SCHEMA_FILES[name])
    return json.loads(schema.read_text(encoding="utf-8"))


def _json_path(parts: Any) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _schema_errors(name: str, document: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(_load_schema(name))
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    sanitized: list[str] = []
    for error in errors:
        parts = list(error.absolute_path)
        location = f"{name}{_json_path(parts)}"
        if parts and SECRET_KEY_RE.search(str(parts[-1])):
            sanitized.append(f"{location}: secret-like field does not contain an allowed reference")
        else:
            sanitized.append(f"{location}: {error.message}")
    return sanitized


def _duplicate_ids(items: list[dict[str, Any]], label: str) -> list[str]:
    seen: set[str] = set()
    errors: list[str] = []
    for item in items:
        identifier = item.get("id")
        if identifier in seen:
            errors.append(f"{label}: duplicate id {identifier!r}")
        if isinstance(identifier, str):
            seen.add(identifier)
    return errors


def _canonical_repository_path(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return not (
        len(value.encode("utf-8")) > 4096
        or value == "."
        or value.startswith("./")
        or value.endswith("/")
        or "//" in value
        or any(segment in {"", ".", ".."} for segment in value.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or unicodedata.normalize("NFC", value) != value
    )


def _trust_bootstrap_errors(bundle: dict[str, dict[str, Any]]) -> list[str]:
    """Validate cross-contract bindings without resolving keys or envelopes.

    Trust material is intentionally external. This validator checks only the
    bounded declarations that the runtime will later bind to canonical evidence.
    """

    trust = bundle.get("trust", {})
    project_id = bundle.get("project", {}).get("metadata", {}).get("name")
    deployments = bundle.get("deployments", {}).get("deployments", [])
    deployment_ids = {
        item.get("id") for item in deployments if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    errors: list[str] = []
    evidence = trust.get("evidence", {}) if isinstance(trust, dict) else {}
    issuers = evidence.get("issuers", []) if isinstance(evidence, dict) else []
    issuer_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for index, issuer in enumerate(issuers if isinstance(issuers, list) else []):
        if not isinstance(issuer, dict):
            continue
        issuer_id, key_id = issuer.get("id"), issuer.get("keyId")
        if isinstance(issuer_id, str) and isinstance(key_id, str):
            key = (issuer_id, key_id)
            if key in issuer_by_key:
                errors.append(f"trust.evidence.issuers[{index}]: duplicate issuer/key pair")
            issuer_by_key[key] = issuer
        for deployment_id in issuer.get("allowedDeployments", []):
            if deployment_id not in deployment_ids:
                errors.append(
                    f"trust.evidence.issuers[{index}].allowedDeployments: unknown deployment {deployment_id!r}"
                )

    snapshot = trust.get("repositorySnapshot", {}) if isinstance(trust, dict) else {}
    if isinstance(snapshot, dict):
        snapshot_issuer = snapshot.get("issuer", {})
        if isinstance(snapshot_issuer, dict):
            key = (snapshot_issuer.get("id"), snapshot_issuer.get("keyId"))
            issuer = issuer_by_key.get(key)
            if issuer is None:
                errors.append("trust.repositorySnapshot.issuer: not present in evidence issuer policies")
            else:
                if "RepositorySnapshot" not in issuer.get("allowedKinds", []):
                    errors.append("trust.repositorySnapshot.issuer: is not allowed to sign repository snapshots")
                if project_id not in issuer.get("allowedProjects", []):
                    errors.append("trust.repositorySnapshot.issuer: is not bound to this project")
        snapshot_trust = ARTIFACT_TRUST_ORDER.get(snapshot.get("trust"), -1)
        paths: set[str] = set()
        entries = snapshot.get("entries", [])
        for index, entry in enumerate(entries if isinstance(entries, list) else []):
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            if not _canonical_repository_path(path):
                errors.append(f"trust.repositorySnapshot.entries[{index}].path: is not a canonical repository-relative path")
            elif path in paths:
                errors.append(f"trust.repositorySnapshot.entries[{index}].path: duplicate snapshot path")
            else:
                paths.add(path)
            if ARTIFACT_TRUST_ORDER.get(entry.get("trust"), -1) > snapshot_trust:
                errors.append(f"trust.repositorySnapshot.entries[{index}].trust: exceeds snapshot trust")

    conformance = trust.get("conformance", {}) if isinstance(trust, dict) else {}
    suites = conformance.get("trustedSuites", []) if isinstance(conformance, dict) else []
    suite_digests: set[str] = set()
    for index, suite in enumerate(suites if isinstance(suites, list) else []):
        if not isinstance(suite, dict):
            continue
        digest = suite.get("digest")
        if isinstance(digest, str):
            if digest in suite_digests:
                errors.append(f"trust.conformance.trustedSuites[{index}].digest: duplicate suite digest")
            suite_digests.add(digest)

    observations = conformance.get("requiredObservations", []) if isinstance(conformance, dict) else []
    observed_deployments: set[str] = set()
    for index, observation in enumerate(observations if isinstance(observations, list) else []):
        if not isinstance(observation, dict):
            continue
        deployment_id = observation.get("deploymentId")
        suite_digest = observation.get("suiteDigest")
        if deployment_id not in deployment_ids:
            errors.append(f"trust.conformance.requiredObservations[{index}]: unknown deployment {deployment_id!r}")
        elif deployment_id in observed_deployments:
            errors.append(f"trust.conformance.requiredObservations[{index}]: duplicate deployment observation")
        else:
            observed_deployments.add(deployment_id)
        if suite_digest not in suite_digests:
            errors.append(f"trust.conformance.requiredObservations[{index}].suiteDigest: is not a trusted suite")
        supported = any(
            "AdapterConformanceProfile" in issuer.get("allowedKinds", [])
            and deployment_id in issuer.get("allowedDeployments", [])
            and suite_digest in issuer.get("allowedSuiteDigests", [])
            for issuer in issuer_by_key.values()
        )
        if not supported:
            errors.append(
                f"trust.conformance.requiredObservations[{index}]: no issuer is exactly allowlisted for its deployment and suite"
            )
    return errors


def _secret_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if SECRET_KEY_RE.search(str(key)) and isinstance(child, str):
                normalized = child.strip()
                if normalized and not SAFE_REFERENCE_RE.match(normalized):
                    errors.append(
                        f"{child_path}: secret-like fields must contain an env/config/secret reference, not a literal"
                    )
            errors.extend(_secret_errors(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_secret_errors(child, f"{path}[{index}]"))
    return errors


def validate_bundle(
    repo: Path,
    directory: Path,
    bundle: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for name, document in bundle.items():
        errors.extend(_schema_errors(name, document))
        errors.extend(_secret_errors(document, name))

    capabilities = bundle["capabilities"].get("capabilities", [])
    tools = bundle["tools"].get("tools", [])
    deployments = bundle["deployments"].get("deployments", [])
    roles = bundle["deployments"].get("logicalRoles", {})
    rules = bundle["instructions"].get("rules", [])

    errors.extend(_duplicate_ids(capabilities, "capabilities"))
    errors.extend(_duplicate_ids(tools, "tools"))
    errors.extend(_duplicate_ids(deployments, "deployments"))
    errors.extend(_duplicate_ids(rules, "instructions.rules"))

    capability_by_id = {item.get("id"): item for item in capabilities if isinstance(item, dict)}
    deployment_by_id = {item.get("id"): item for item in deployments if isinstance(item, dict)}

    for tool in tools:
        capability = tool.get("capability")
        if capability not in capability_by_id:
            errors.append(f"tools[{tool.get('id')}]: unknown capability {capability!r}")
            continue
        expected = capability_by_id[capability].get("actionClass")
        if tool.get("actionClass") != expected:
            errors.append(
                f"tools[{tool.get('id')}]: actionClass {tool.get('actionClass')} does not match "
                f"capability {capability} ({expected})"
            )

    for deployment in deployments:
        for capability in deployment.get("declaredCapabilities", []):
            if capability not in capability_by_id:
                errors.append(
                    f"deployments[{deployment.get('id')}]: unknown declared capability {capability!r}"
                )

    for role_name, role in roles.items():
        required = set(role.get("requiredCapabilities", []))
        unknown = required - set(capability_by_id)
        for capability in sorted(unknown):
            errors.append(f"logicalRoles.{role_name}: unknown capability {capability!r}")
        for candidate in role.get("candidates", []):
            deployment = deployment_by_id.get(candidate)
            if deployment is None:
                errors.append(f"logicalRoles.{role_name}: unknown deployment {candidate!r}")
                continue
            missing = required - set(deployment.get("declaredCapabilities", []))
            if missing:
                errors.append(
                    f"logicalRoles.{role_name}: deployment {candidate!r} lacks declared capabilities "
                    f"{', '.join(sorted(missing))}"
                )
            if deployment.get("zone") not in role.get("allowedZones", []):
                errors.append(
                    f"logicalRoles.{role_name}: deployment {candidate!r} zone "
                    f"{deployment.get('zone')!r} is not allowed"
                )
            shared_data_classes = set(role.get("allowedDataClasses", [])) & set(
                deployment.get("allowedDataClasses", [])
            )
            if not shared_data_classes:
                errors.append(
                    f"logicalRoles.{role_name}: deployment {candidate!r} has no allowed data-class intersection"
                )
            minimum_trust = ARTIFACT_TRUST_ORDER.get(role.get("minimumArtifactTrust"), -1)
            deployment_trust = ARTIFACT_TRUST_ORDER.get(deployment.get("artifactTrust"), -1)
            if deployment_trust < minimum_trust:
                errors.append(
                    f"logicalRoles.{role_name}: deployment {candidate!r} artifact trust "
                    f"{deployment.get('artifactTrust')!r} is below {role.get('minimumArtifactTrust')!r}"
                )

    for deployment in deployments:
        if not deployment.get("enabled"):
            continue
        observed_ref = deployment.get("observedCapabilitiesRef")
        if not isinstance(observed_ref, str):
            continue
        try:
            observed_path = ensure_within(directory, directory / observed_ref)
        except EcoError as exc:
            errors.append(f"deployments[{deployment.get('id')}].observedCapabilitiesRef: {exc}")
            continue
        if not observed_path.is_file():
            errors.append(
                f"deployments[{deployment.get('id')}]: observed capability record does not exist"
            )

    errors.extend(_trust_bootstrap_errors(bundle))

    projections = bundle["instructions"].get("projections", {})
    for client, relative in projections.items():
        if not isinstance(relative, str):
            continue
        try:
            ensure_within(repo, repo / relative)
        except EcoError as exc:
            errors.append(f"instructions.projections.{client}: {exc}")

    for name in ("instructions", "capabilities", "deployments", "tools", "trust"):
        if bundle[name].get("apiVersion") != bundle["project"].get("apiVersion"):
            errors.append(f"{name}: apiVersion differs from project")

    return sorted(set(errors))


def validate_repository(repo: Path, config_root: str) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Path]]:
    directory, bundle, paths = load_bundle(repo, config_root)
    return validate_bundle(repo, directory, bundle), bundle, paths
