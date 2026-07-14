from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .constants import CONFIG_FILES, SCHEMA_FILES
from .errors import EcoError

SECRET_KEY_RE = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|credential)", re.I)
SAFE_REFERENCE_RE = re.compile(r"^(?:env:|config:|secret://|\$\{|<|placeholder$|none$)", re.I)


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


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


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

    for key in ("instructions", "capabilities", "deployments", "tools"):
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

    projections = bundle["instructions"].get("projections", {})
    for client, relative in projections.items():
        if not isinstance(relative, str):
            continue
        try:
            ensure_within(repo, repo / relative)
        except EcoError as exc:
            errors.append(f"instructions.projections.{client}: {exc}")

    for name in ("instructions", "capabilities", "deployments", "tools"):
        if bundle[name].get("apiVersion") != bundle["project"].get("apiVersion"):
            errors.append(f"{name}: apiVersion differs from project")

    return sorted(set(errors))


def validate_repository(repo: Path, config_root: str) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Path]]:
    directory, bundle, paths = load_bundle(repo, config_root)
    return validate_bundle(repo, directory, bundle), bundle, paths
