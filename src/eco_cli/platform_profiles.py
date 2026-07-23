from __future__ import annotations

import copy
import hashlib
import json
import os
import platform as host_platform
import re
import shutil
import stat
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator


PLATFORM_API_VERSION = "platform.ai.ecosystem/v1alpha1"
ADAPTER_API_VERSION = PLATFORM_API_VERSION
PLATFORM_PROBE_VERSION = 1

PLATFORM_IDS = (
    "container",
    "hosted-ci",
    "linux-native",
    "macos",
    "windows-native",
    "wsl",
)
PROFILE_VALUES = (*PLATFORM_IDS, "ambiguous", "unsupported", "unspecified")
EXECUTABLE_ALLOWLIST = (
    "claude",
    "codex",
    "cursor",
    "docker",
    "gemini",
    "git",
    "node",
    "nvidia-smi",
    "ollama",
    "python",
)
CLIENT_PATHS = {
    "claude": "CLAUDE.md",
    "codex": "AGENTS.md",
    "copilot": ".github/copilot-instructions.md",
    "cursor": ".cursor/rules/eco.mdc",
    "gemini": "GEMINI.md",
}
CLIENT_ALLOWLIST = tuple(sorted(CLIENT_PATHS))
RUNTIME_SECURITY_CAPABILITIES = (
    "runtime.credential-resolution",
    "runtime.loop-execution",
    "runtime.model-routing",
    "runtime.network-denial",
    "runtime.process-isolation",
    "runtime.repository-read-broker",
    "runtime.workspace-write-broker",
)

_SCHEMA_BY_KIND = {
    "PlatformProfile": "platform-profile.schema.json",
    "AdapterCapabilityProfile": "adapter-capability-profile.schema.json",
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class _ProbeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_schema(kind: str) -> dict[str, Any]:
    source = resources.files("eco_cli").joinpath("schemas", _SCHEMA_BY_KIND[kind])
    return json.loads(source.read_text(encoding="utf-8"))


def _contract_errors(kind: str, document: Any) -> list[str]:
    validator = Draft202012Validator(_load_schema(kind))
    errors = sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    sanitized: list[str] = []
    for error in errors:
        location = "$" + "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}"
            for part in error.absolute_path
        )
        sanitized.append(f"{location}: {error.validator or 'invalid'}")
    if errors or not isinstance(document, dict):
        return sanitized

    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        expected = profile_document_digest(document)
        if metadata.get("profileDigest") != expected:
            sanitized.append("$.metadata.profileDigest: digest")

    spec = document.get("spec")
    if not isinstance(spec, dict):
        return sanitized
    if kind == "PlatformProfile":
        expected_inventories = {
            "contexts": ("container", "hosted-ci", "wsl"),
            "executables": EXECUTABLE_ALLOWLIST,
            "clients": CLIENT_ALLOWLIST,
            "semantics": (
                "client.projection-presence",
                "environment.reference-resolution",
                "executable.path-resolution",
                "filesystem.security-semantics",
                "process.shell-execution",
            ),
            "runtimeSecurity": RUNTIME_SECURITY_CAPABILITIES,
        }
        for field, expected_ids in expected_inventories.items():
            items = spec.get(field)
            ids = [item.get("id") for item in items if isinstance(item, dict)] if isinstance(items, list) else []
            if ids != list(expected_ids):
                sanitized.append(f"$.spec.{field}: exact-inventory")
        classification = spec.get("classification")
        metadata = document.get("metadata")
        if (
            isinstance(classification, dict)
            and isinstance(metadata, dict)
            and classification.get("detected") in PLATFORM_IDS
            and metadata.get("id") != classification.get("detected")
        ):
            sanitized.append("$.metadata.id: detected-profile-mismatch")
    capabilities = spec.get("runtimeSecurity") if kind == "PlatformProfile" else spec.get("capabilities")
    if isinstance(capabilities, list):
        ids = [item.get("id") for item in capabilities if isinstance(item, dict)]
        if ids != sorted(ids):
            sanitized.append("$.spec.capabilities: order")
        if len(ids) != len(set(ids)):
            sanitized.append("$.spec.capabilities: duplicate")
        for index, item in enumerate(capabilities):
            if not isinstance(item, dict):
                continue
            if item.get("effective") is True and not (
                item.get("declared") == "declared"
                and item.get("detected") == "detected"
                and item.get("proven") == "proven"
                and isinstance(item.get("evidence"), dict)
            ):
                sanitized.append(f"$.spec.capabilities[{index}]: unproven-effective")
    return sanitized


def profile_document_digest(document: Mapping[str, Any]) -> str:
    body = copy.deepcopy(dict(document))
    metadata = body.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("profileDigest", None)
    return _semantic_digest(body)


def validate_platform_profile(document: Any) -> list[str]:
    """Return content-free validation errors for a PlatformProfile document."""

    return _contract_errors("PlatformProfile", document)


def validate_adapter_capability_profile(document: Any) -> list[str]:
    """Return content-free validation errors for a declaration-only adapter profile."""

    return _contract_errors("AdapterCapabilityProfile", document)


def _default_executables(status: str = "not-tested") -> list[dict[str, str]]:
    return [{"name": name, "status": status} for name in EXECUTABLE_ALLOWLIST]


def _default_clients(status: str = "not-tested") -> list[dict[str, str]]:
    return [{"id": client, "status": status} for client in CLIENT_ALLOWLIST]


def _runtime_security() -> list[dict[str, Any]]:
    return [
        {
            "capability": capability,
            "declared": "not-declared",
            "detected": "not-tested",
            "proven": "not-tested",
            "status": "not-tested",
            "evidenceDigest": None,
        }
        for capability in RUNTIME_SECURITY_CAPABILITIES
    ]


def _passive_semantics(inventory_detected: bool = True) -> list[dict[str, str]]:
    inventory_state = "detected" if inventory_detected else "not-tested"
    return [
        {"id": "client.projection-presence", "state": inventory_state},
        {"id": "environment.reference-resolution", "state": "not-tested"},
        {"id": "executable.path-resolution", "state": inventory_state},
        {"id": "filesystem.security-semantics", "state": "not-tested"},
        {"id": "process.shell-execution", "state": "not-tested"},
    ]


def _adapter_conformance() -> dict[str, Any]:
    return {
        "state": "not-tested",
        "declaredProfiles": 0,
        "detectedProfiles": 0,
        "provenProfiles": 0,
        "effectiveCapabilities": [],
    }


def _finalize_report(body: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(body)
    result["reportDigest"] = _semantic_digest(result)
    return result


def _blocked_report(code: str, declared_profile: object = None) -> dict[str, Any]:
    declared = declared_profile if declared_profile in PLATFORM_IDS else "unspecified"
    probe_body = {"version": PLATFORM_PROBE_VERSION, "status": "invalid"}
    return _finalize_report(
        {
            "available": False,
            "mode": "platform-conformance-read-only",
            "status": "blocked",
            "code": code,
            "profile": {
                "declared": declared,
                "detected": "unsupported",
                "proven": None,
            },
            "operatingSystem": {"family": "unsupported", "state": "blocked"},
            "contexts": [
                {"id": context, "state": "not-tested"}
                for context in ("container", "hosted-ci", "wsl")
            ],
            "probeDigest": _semantic_digest(probe_body),
            "executables": _default_executables(),
            "clients": _default_clients(),
            "semantics": _passive_semantics(False),
            "adapterConformance": _adapter_conformance(),
            "runtimeSecurity": _runtime_security(),
            "effectiveCapabilities": [],
            "safety": {
                "executionReady": False,
                "authorityCreated": False,
                "mutationPerformed": False,
                "networkAccessed": False,
            },
        }
    )


def _require_bool(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise _ProbeError(code)
    return value


def _normalize_named_bools(
    value: object,
    *,
    expected: Sequence[str],
    id_key: str,
    value_key: str,
    code: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(expected):
        raise _ProbeError(code)
    normalized: dict[str, bool] = {}
    for item in value:
        if not isinstance(item, dict) or set(item) != {id_key, value_key}:
            raise _ProbeError(code)
        identifier = item.get(id_key)
        if identifier not in expected or identifier in normalized:
            raise _ProbeError(code)
        normalized[str(identifier)] = _require_bool(item.get(value_key), code)
    if set(normalized) != set(expected):
        raise _ProbeError(code)
    return [{id_key: name, value_key: normalized[name]} for name in expected]


def _normalize_probe_inputs(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "os",
        "signals",
        "executables",
        "clients",
    }:
        raise _ProbeError("ECO_PLATFORM_PROBE_INPUT_INVALID")
    if value.get("version") != PLATFORM_PROBE_VERSION:
        raise _ProbeError("ECO_PLATFORM_PROBE_VERSION_UNSUPPORTED")

    os_input = value.get("os")
    if not isinstance(os_input, dict) or set(os_input) != {"name", "system"}:
        raise _ProbeError("ECO_PLATFORM_OS_INVALID")
    os_name, system = os_input.get("name"), os_input.get("system")
    valid_os_pairs = {("posix", "Linux"), ("posix", "Darwin"), ("nt", "Windows")}
    if (os_name, system) not in valid_os_pairs:
        if system in {"Linux", "Darwin", "Windows"}:
            raise _ProbeError("ECO_PLATFORM_OS_INCONSISTENT")
        raise _ProbeError("ECO_PLATFORM_OS_UNSUPPORTED")

    signals = value.get("signals")
    expected_signals = {
        "wsl": {"environment", "kernel"},
        "container": {"environment", "filesystem"},
        "hostedCi": {"environment", "provider"},
    }
    if not isinstance(signals, dict) or set(signals) != set(expected_signals):
        raise _ProbeError("ECO_PLATFORM_SIGNALS_INVALID")
    normalized_signals: dict[str, dict[str, bool]] = {}
    for signal, fields in expected_signals.items():
        item = signals.get(signal)
        if not isinstance(item, dict) or set(item) != fields:
            raise _ProbeError("ECO_PLATFORM_SIGNALS_INVALID")
        normalized_signals[signal] = {
            field: _require_bool(item.get(field), "ECO_PLATFORM_SIGNALS_INVALID")
            for field in sorted(fields)
        }

    return {
        "version": PLATFORM_PROBE_VERSION,
        "os": {"name": os_name, "system": system},
        "signals": normalized_signals,
        "executables": _normalize_named_bools(
            value.get("executables"),
            expected=EXECUTABLE_ALLOWLIST,
            id_key="name",
            value_key="present",
            code="ECO_PLATFORM_EXECUTABLES_INVALID",
        ),
        "clients": _normalize_named_bools(
            value.get("clients"),
            expected=CLIENT_ALLOWLIST,
            id_key="id",
            value_key="available",
            code="ECO_PLATFORM_CLIENTS_INVALID",
        ),
    }


def _regular_projection(repository: Path, relative: str) -> bool:
    try:
        mode = (repository / relative).lstat().st_mode
    except (FileNotFoundError, OSError):
        return False
    return stat.S_ISREG(mode)


def _host_probe(repository: Path | None) -> dict[str, Any]:
    system = host_platform.system()
    release = host_platform.release().lower()
    wsl_kernel = system == "Linux" and ("microsoft" in release or "wsl" in release)
    container_marker = system == "Linux" and Path("/.dockerenv").is_file()
    executables = [
        {"name": name, "present": shutil.which(name) is not None}
        for name in EXECUTABLE_ALLOWLIST
    ]
    clients = [
        {
            "id": client,
            "available": repository is not None
            and _regular_projection(repository, CLIENT_PATHS[client]),
        }
        for client in CLIENT_ALLOWLIST
    ]
    return {
        "version": PLATFORM_PROBE_VERSION,
        "os": {"name": os.name, "system": system},
        "signals": {
            "wsl": {"environment": False, "kernel": wsl_kernel},
            "container": {"environment": False, "filesystem": container_marker},
            "hostedCi": {"environment": False, "provider": False},
        },
        "executables": executables,
        "clients": clients,
    }


def _classify(probe: Mapping[str, Any]) -> tuple[str, str, list[dict[str, str]], str | None]:
    signals = probe["signals"]
    context_map = {
        "container": (signals["container"]["environment"], signals["container"]["filesystem"]),
        "hosted-ci": (signals["hostedCi"]["environment"], signals["hostedCi"]["provider"]),
        "wsl": (signals["wsl"]["environment"], signals["wsl"]["kernel"]),
    }
    contexts: list[dict[str, str]] = []
    detected_contexts: list[str] = []
    uncorroborated = False
    for context in ("container", "hosted-ci", "wsl"):
        hint, marker = context_map[context]
        if marker:
            state = "detected"
            detected_contexts.append(context)
        elif hint:
            state = "reported-hint"
            uncorroborated = True
        else:
            state = "absent"
        contexts.append({"id": context, "state": state})

    system = probe["os"]["system"]
    family = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(system, "unsupported")
    if uncorroborated:
        return "ambiguous", family, contexts, "ECO_PLATFORM_HINT_UNCORROBORATED"
    if len(detected_contexts) > 1:
        return "ambiguous", family, contexts, "ECO_PLATFORM_CONTEXT_AMBIGUOUS"
    if detected_contexts:
        detected = detected_contexts[0]
        if detected == "wsl" and system != "Linux":
            return "ambiguous", family, contexts, "ECO_PLATFORM_CONTEXT_INCONSISTENT"
        return detected, family, contexts, None
    native = {"Linux": "linux-native", "Darwin": "macos", "Windows": "windows-native"}
    return native.get(system, "unsupported"), family, contexts, None


def platform_doctor(
    declared_profile: str | None = None,
    *,
    repository: Path | None = None,
    probe_inputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic passive inventory; it never creates runtime authority.

    ``probe_inputs`` exists for conformance fixtures. It is a normalized observation,
    not trusted evidence, and cannot populate ``proven`` or effective capabilities.
    """

    try:
        if declared_profile is not None and declared_profile not in PLATFORM_IDS:
            raise _ProbeError("ECO_PLATFORM_DECLARATION_INVALID")
        raw_probe = _host_probe(repository) if probe_inputs is None else copy.deepcopy(probe_inputs)
        probe = _normalize_probe_inputs(raw_probe)
        detected, family, contexts, classification_error = _classify(probe)
        code = classification_error
        if code is None and declared_profile is not None and declared_profile != detected:
            code = "ECO_PLATFORM_DECLARATION_MISMATCH"
        if code is None and detected not in PLATFORM_IDS:
            code = "ECO_PLATFORM_UNSUPPORTED"

        available = code is None
        body = {
            "available": available,
            "mode": "platform-conformance-read-only",
            "status": "pass" if available else "blocked",
            "code": "ECO_PLATFORM_INVENTORY_COMPLETE" if available else code,
            "profile": {
                "declared": declared_profile or "unspecified",
                "detected": detected,
                "proven": None,
            },
            "operatingSystem": {
                "family": family,
                "state": "detected" if family != "unsupported" else "blocked",
            },
            "contexts": contexts,
            "probeDigest": _semantic_digest(probe),
            "executables": [
                {"name": item["name"], "status": "present" if item["present"] else "absent"}
                for item in probe["executables"]
            ],
            "clients": [
                {"id": item["id"], "status": "surface-present" if item["available"] else "absent"}
                for item in probe["clients"]
            ],
            "semantics": _passive_semantics(),
            "adapterConformance": _adapter_conformance(),
            "runtimeSecurity": _runtime_security(),
            "effectiveCapabilities": [],
            "safety": {
                "executionReady": False,
                "authorityCreated": False,
                "mutationPerformed": False,
                "networkAccessed": False,
            },
        }
        return _finalize_report(body)
    except _ProbeError as exc:
        return _blocked_report(exc.code, declared_profile)
    except Exception:
        return _blocked_report("ECO_PLATFORM_PROBE_FAILED", declared_profile)


def platform_profile_document(report: Mapping[str, Any], *, profile_id: str) -> dict[str, Any]:
    """Project a doctor report into the versioned, non-authorizing profile contract."""

    if profile_id not in PLATFORM_IDS:
        raise ValueError("profile id is unsupported")
    document: dict[str, Any] = {
        "apiVersion": PLATFORM_API_VERSION,
        "kind": "PlatformProfile",
        "metadata": {"id": profile_id, "profileDigest": "0" * 64},
        "spec": {
            "classification": copy.deepcopy(report["profile"]),
            "operatingSystem": copy.deepcopy(report["operatingSystem"]),
            "contexts": copy.deepcopy(report["contexts"]),
            "executables": [
                {"id": item["name"], "state": item["status"]}
                for item in report["executables"]
            ],
            "clients": [
                {"id": item["id"], "state": item["status"]}
                for item in report["clients"]
            ],
            "semantics": copy.deepcopy(report["semantics"]),
            "adapterConformance": copy.deepcopy(report["adapterConformance"]),
            "runtimeSecurity": [
                {
                    "id": item["capability"],
                    "declared": item["declared"],
                    "detected": item["detected"],
                    "proven": item["proven"],
                    "effective": False,
                }
                for item in report["runtimeSecurity"]
            ],
            "effectiveCapabilities": [],
            "safety": copy.deepcopy(report["safety"]),
        },
    }
    document["metadata"]["profileDigest"] = profile_document_digest(document)
    return document


def adapter_capability_profile_document(
    *,
    profile_id: str,
    adapter_id: str,
    platform_profile_digest: str,
    deployment_identity_digest: str,
    declared_capabilities: Sequence[str],
) -> dict[str, Any]:
    """Build a deterministic declaration-only adapter profile without probing it."""

    if not _ID_RE.fullmatch(profile_id) or not _ID_RE.fullmatch(adapter_id):
        raise ValueError("adapter profile id is invalid")
    if not _SHA256_RE.fullmatch(platform_profile_digest) or not _SHA256_RE.fullmatch(
        deployment_identity_digest
    ):
        raise ValueError("adapter profile binding digest is invalid")
    if (
        not isinstance(declared_capabilities, Sequence)
        or isinstance(declared_capabilities, (str, bytes))
        or len(declared_capabilities) > 128
        or any(
            not isinstance(capability, str) or not _CAPABILITY_RE.fullmatch(capability)
            for capability in declared_capabilities
        )
        or len(set(declared_capabilities)) != len(declared_capabilities)
    ):
        raise ValueError("adapter capability declaration is invalid")
    capabilities = sorted(declared_capabilities)
    document: dict[str, Any] = {
        "apiVersion": ADAPTER_API_VERSION,
        "kind": "AdapterCapabilityProfile",
        "metadata": {
            "id": profile_id,
            "adapterId": adapter_id,
            "profileDigest": "0" * 64,
        },
        "spec": {
            "authority": "declaration-and-inventory-only",
            "platformProfileDigest": platform_profile_digest,
            "deploymentIdentityDigest": deployment_identity_digest,
            "capabilities": [
                {
                    "id": capability,
                    "declared": "declared",
                    "detected": "not-tested",
                    "proven": "not-tested",
                    "effective": False,
                }
                for capability in capabilities
            ],
            "effectiveCapabilities": [],
            "safety": {"authorityCreated": False, "executionReady": False},
        },
    }
    document["metadata"]["profileDigest"] = profile_document_digest(document)
    return document


__all__ = [
    "ADAPTER_API_VERSION",
    "CLIENT_ALLOWLIST",
    "EXECUTABLE_ALLOWLIST",
    "PLATFORM_API_VERSION",
    "PLATFORM_IDS",
    "RUNTIME_SECURITY_CAPABILITIES",
    "adapter_capability_profile_document",
    "platform_doctor",
    "platform_profile_document",
    "profile_document_digest",
    "validate_adapter_capability_profile",
    "validate_platform_profile",
]
