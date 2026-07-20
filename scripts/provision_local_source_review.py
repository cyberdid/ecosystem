#!/usr/bin/env python3
"""Provision one exact local source-review deployment with signed evidence.

This is an explicit operator ceremony.  It probes a canonical literal-loopback
OpenAI-compatible endpoint, binds the result to the repository project,
deployment identity, typed endpoint reference, resolved endpoint digest, and
reported model, then publishes the public observation and private evidence
envelope as a locked, rollback-capable pair.

The script intentionally grants no deployment authority and writes no secret
to the repository.  HMAC remains the v1 evidence-envelope algorithm; therefore
the operator signing key and the runtime process must remain separate trust
boundaries until the evidence protocol gains an algorithm-bound Ed25519 policy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

import yaml  # noqa: E402

from eco_runtime.contracts import API_VERSION  # noqa: E402
from eco_runtime.digests import (  # noqa: E402
    canonical_json,
    deployment_identity_digest,
    semantic_digest,
)
from eco_runtime.evidence import HmacEvidenceSigner  # noqa: E402
from eco_runtime.errors import RuntimePolicyError  # noqa: E402


MAX_RESPONSE_BYTES = 1_048_576
MAX_PROBE_OUTPUT_BYTES = 262_144
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 10_000
MAX_JSON_STRING_BYTES = 262_144
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
COMPLETIONS_PATH = "/v1/chat/completions"

PROBE_SUITE = {
    "id": "adapter-conformance-v1",
    "version": "1.1.0",
    "wireContract": {
        "profile": "eco-openai-typed-production-v1",
        "httpStatus": 200,
        "duplicateJsonKeys": "deny",
        "toolChoice": "none",
        "tools": [],
        "response": "id-model-single-choice-usage",
    },
    "probes": [
        {
            "id": "text-basic",
            "kind": "chat-completion+json_schema",
            "expectation": "non-empty schema-bound assistant text with exact production envelope",
        },
        {
            "id": "structured-output-strict",
            "kind": "chat-completion+json_schema",
            "expectation": "schema-valid JSON object with finish_reason stop",
        },
    ],
}
STRUCTURED_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["fact", "confidence"],
    "properties": {
        "fact": {"type": "string"},
        "confidence": {"enum": ["low", "medium", "high"]},
    },
}
TEXT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["text"],
    "properties": {"text": {"type": "string"}},
}


class ProvisioningContext:
    def __init__(
        self,
        *,
        repository: Path,
        project_id: str,
        deployment: dict[str, Any],
        binding: dict[str, str],
        observed_path: Path,
    ) -> None:
        self.repository = repository
        self.project_id = project_id
        self.deployment = deployment
        self.binding = binding
        self.observed_path = observed_path


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(req.full_url, code, "redirect denied", headers, fp)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_loopback_endpoint(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 2048
        or value.strip() != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("endpoint is invalid")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or not 1 <= port <= 65_535
        or parsed.netloc != f"127.0.0.1:{port}"
        or parsed.path != COMPLETIONS_PATH
        or parsed.query
        or parsed.fragment
        or "%" in value
        or "\\" in value
    ):
        raise ValueError("endpoint must be the canonical literal-loopback completion URL")
    canonical = f"http://127.0.0.1:{port}{COMPLETIONS_PATH}"
    if value != canonical:
        raise ValueError("endpoint is not canonical")
    return canonical


def _validate_json_bounds(document: object) -> None:
    nodes = 0
    pending: list[tuple[object, int]] = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("provider JSON exceeds structural bounds")
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    not isinstance(key, str)
                    or len(key.encode("utf-8")) > 1024
                ):
                    raise ValueError("provider JSON key is invalid")
                pending.append((item, depth + 1))
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise ValueError("provider JSON string exceeds bound")
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise ValueError("provider JSON contains an unsupported value")


def _reject_json_constant(_value: str) -> None:
    raise ValueError("provider JSON contains a non-finite number")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("provider JSON contains a duplicate key")
        result[key] = value
    return result


def _post(endpoint: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    endpoint = _normalize_loopback_endpoint(endpoint)
    encoded_payload = canonical_json(payload).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=encoded_payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    with opener.open(request, timeout=timeout) as response:
        if getattr(response, "status", None) != 200:
            raise ValueError("provider response status is invalid")
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("provider response length is invalid") from exc
            if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
                raise ValueError("provider response exceeds byte bound")
        encoded = response.read(MAX_RESPONSE_BYTES + 1)
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("provider response exceeds byte bound")
    try:
        document = json.loads(
            encoded.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError("provider response is not bounded JSON") from exc
    _validate_json_bounds(document)
    if not isinstance(document, dict):
        raise ValueError("provider response is not an object")
    return document


def _completion_choice(
    response: dict[str, Any], requested_model: str, maximum_output_tokens: int
) -> tuple[dict[str, Any], str]:
    if not isinstance(requested_model, str) or not requested_model:
        raise ValueError("requested model is invalid")
    reported_model = response.get("model")
    choices = response.get("choices")
    usage = response.get("usage")
    if (
        reported_model != requested_model
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
    ):
        raise ValueError("provider response does not match requested model and shape")
    choice = choices[0]
    message = choice.get("message")
    input_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
    output_tokens = usage.get("completion_tokens") if isinstance(usage, dict) else None
    total_tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
    if (
        not isinstance(response.get("id"), str)
        or not response["id"]
        or choice.get("index") != 0
        or choice.get("finish_reason") not in {"stop", "length"}
        or not isinstance(message, dict)
        or message.get("role") != "assistant"
        or "tool_calls" in message
        or not isinstance(message.get("content"), str)
        or not all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (input_tokens, output_tokens, total_tokens)
        )
        or total_tokens != input_tokens + output_tokens
        or output_tokens > maximum_output_tokens
        or len(message.get("content", "").encode("utf-8")) > MAX_PROBE_OUTPUT_BYTES
    ):
        raise ValueError("provider completion choice is invalid")
    return choice, reported_model


def _probe(
    endpoint: str, model: str, timeout: int
) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    reported_models: set[str] = set()
    text_payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Return only output conforming to the supplied JSON schema.",
            },
            {"role": "user", "content": "Reply with one short sentence about testing."}
        ],
        "max_tokens": 512,
        "temperature": 0.0,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "eco_structured_output",
                "strict": True,
                "schema": TEXT_SCHEMA,
            },
        },
        "tool_choice": "none",
        "tools": [],
    }
    text_response = _post(endpoint, text_payload, timeout)
    text_choice, reported_model = _completion_choice(text_response, model, 512)
    reported_models.add(reported_model)
    text_ok = text_choice["finish_reason"] == "stop"
    if text_ok:
        try:
            parsed_text = json.loads(
                text_choice["message"]["content"],
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_json_constant,
            )
            text_ok = (
                isinstance(parsed_text, dict)
                and set(parsed_text) == {"text"}
                and isinstance(parsed_text["text"], str)
                and bool(parsed_text["text"].strip())
            )
        except (ValueError, TypeError, RecursionError):
            text_ok = False
    results.append(
        {
            "id": "text-basic",
            "status": "pass" if text_ok else "fail",
            "attempts": 1,
            "successes": 1 if text_ok else 0,
            "evidenceDigest": semantic_digest(
                {"probe": "text-basic", "request": text_payload, "response": text_response}
            ),
        }
    )
    structured_payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Return only output conforming to the supplied JSON schema.",
            },
            {
                "role": "user",
                "content": "State one fact about software testing in the required JSON form.",
            }
        ],
        "max_tokens": 200,
        "temperature": 0.0,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "eco_structured_output",
                "strict": True,
                "schema": STRUCTURED_SCHEMA,
            },
        },
        "tool_choice": "none",
        "tools": [],
    }
    structured_response = _post(endpoint, structured_payload, timeout)
    structured_choice, reported_model = _completion_choice(structured_response, model, 200)
    reported_models.add(reported_model)
    structured_ok = structured_choice["finish_reason"] == "stop"
    if structured_ok:
        try:
            parsed = json.loads(
                structured_choice["message"]["content"],
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_json_constant,
            )
            _validate_json_bounds(parsed)
            structured_ok = (
                isinstance(parsed, dict)
                and set(parsed) == {"fact", "confidence"}
                and isinstance(parsed["fact"], str)
                and bool(parsed["fact"].strip())
                and parsed["confidence"] in {"low", "medium", "high"}
            )
        except (ValueError, TypeError, RecursionError):
            structured_ok = False
    results.append(
        {
            "id": "structured-output-strict",
            "status": "pass" if structured_ok else "fail",
            "attempts": 1,
            "successes": 1 if structured_ok else 0,
            "evidenceDigest": semantic_digest(
                {
                    "probe": "structured-output-strict",
                    "request": structured_payload,
                    "response": structured_response,
                }
            ),
        }
    )
    return results, sorted(reported_models)


def _within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _reject_symlink_components(root: Path, path: Path) -> None:
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError("governed path contains a symbolic link")


def _load_context(
    repository: Path,
    deployment_id: str,
    endpoint_env: str,
    endpoint: str,
) -> ProvisioningContext:
    if ENV_NAME_RE.fullmatch(endpoint_env) is None:
        raise ValueError("endpoint environment name is invalid")
    endpoint = _normalize_loopback_endpoint(endpoint)
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise ValueError("repository root is invalid")
    project = yaml.safe_load(
        (repository / ".ai" / "project.yaml").read_text(encoding="utf-8")
    )
    project_id = project.get("metadata", {}).get("name") if isinstance(project, dict) else None
    if (
        not isinstance(project_id, str)
        or len(project_id) > 128
        or PROJECT_ID_RE.fullmatch(project_id) is None
    ):
        raise ValueError("project identity is invalid")
    catalog = yaml.safe_load(
        (repository / ".ai" / "deployments.yaml").read_text(encoding="utf-8")
    )
    deployments = catalog.get("deployments", []) if isinstance(catalog, dict) else []
    matches = [
        item for item in deployments if isinstance(item, dict) and item.get("id") == deployment_id
    ]
    if len(matches) != 1:
        raise ValueError("deployment must be declared exactly once")
    deployment = matches[0]
    expected_endpoint_ref = f"env:{endpoint_env}"
    if (
        deployment.get("provider") != "local"
        or deployment.get("adapter") != "openai-compatible"
        or deployment.get("endpointRef") != expected_endpoint_ref
        or deployment.get("enabled") is not True
        or SAFE_ID_RE.fullmatch(deployment_id) is None
        or not isinstance(deployment.get("model"), str)
        or not 1 <= len(deployment["model"]) <= 512
        or not {"model.text", "model.structured-output"}.issubset(
            set(deployment.get("declaredCapabilities", []))
        )
    ):
        raise ValueError("deployment does not match the local provisioning boundary")
    identity_digest = deployment_identity_digest(deployment)
    endpoint_reference_digest = semantic_digest({"endpointRef": expected_endpoint_ref})
    if deployment["identity"]["endpointReferenceDigest"] != endpoint_reference_digest:
        raise ValueError("deployment endpoint identity does not match endpoint environment")
    observed_ref = deployment.get("observedCapabilitiesRef")
    observed_relative = Path(observed_ref) if isinstance(observed_ref, str) else None
    if (
        observed_relative is None
        or observed_relative.is_absolute()
        or len(observed_relative.parts) != 3
        or observed_relative.parts[:2] != ("evals", "observed")
        or observed_ref != f"evals/observed/{observed_relative.name}"
    ):
        raise ValueError("observed capabilities path is invalid")
    governed = repository / ".ai" / "evals" / "observed"
    observed_path = repository / ".ai" / observed_relative
    if observed_path.parent != governed or observed_path.suffix != ".json":
        raise ValueError("observation must be a direct JSON file in .ai/evals/observed")
    _reject_symlink_components(repository, observed_path)
    binding = {
        "projectId": project_id,
        "endpointRef": expected_endpoint_ref,
        "endpointReferenceDigest": endpoint_reference_digest,
        "resolvedEndpointDigest": semantic_digest({"endpointUrl": endpoint}),
        "requestedModel": deployment["model"],
    }
    # Force evaluation now so incomplete/mismatched identity fails before egress.
    if not identity_digest:
        raise ValueError("deployment identity is invalid")
    return ProvisioningContext(
        repository=repository,
        project_id=project_id,
        deployment=deployment,
        binding=binding,
        observed_path=observed_path,
    )


def _external_output_path(repository: Path, output: Path) -> Path:
    repository = repository.resolve(strict=True)
    raw_output = output.expanduser()
    if not raw_output.is_absolute():
        raw_output = Path.cwd() / raw_output
    raw_output = Path(os.path.abspath(raw_output))
    raw_parent = raw_output.parent
    if raw_parent.is_symlink() or raw_parent.resolve(strict=True) != raw_parent:
        raise ValueError("private evidence path cannot traverse symbolic links")
    output = raw_parent / raw_output.name
    if (
        _within(output, repository)
        or output.name in {"", ".", ".."}
        or len(output.name.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in output.name)
    ):
        raise ValueError("private evidence output must be outside the repository")
    parent = output.parent
    parent_stat = parent.lstat()
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or (hasattr(os, "getuid") and parent_stat.st_uid != os.getuid())
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
        or stat.S_IMODE(parent_stat.st_mode) & 0o700 != 0o700
    ):
        raise ValueError("private evidence parent must be owner-only and operator-owned")
    if output.exists() or output.is_symlink():
        output_stat = output.lstat()
        if (
            not stat.S_ISREG(output_stat.st_mode)
            or stat.S_ISLNK(output_stat.st_mode)
            or output_stat.st_nlink != 1
            or (hasattr(os, "getuid") and output_stat.st_uid != os.getuid())
            or stat.S_IMODE(output_stat.st_mode) & 0o077
        ):
            raise ValueError("existing private evidence output is unsafe")
    return output


def _validate_publish_target(path: Path, *, private: bool) -> None:
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_nlink != 1
            or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            raise ValueError("publication target is unsafe")


def _stage(path: Path, content: bytes, mode: int) -> Path:
    staging = path.with_name(f".{path.name}.staging-{secrets.token_hex(12)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(staging, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("staging write failed")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        staging.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    return staging


def _acquire_lock(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    return descriptor


def _restore(path: Path, previous: bytes | None, mode: int) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    rollback = _stage(path, previous, mode)
    try:
        os.replace(rollback, path)
    finally:
        rollback.unlink(missing_ok=True)


def _publish_outputs(
    observed_path: Path,
    observed_content: bytes,
    envelope_path: Path,
    envelope_content: bytes,
) -> None:
    observed_path.parent.mkdir(parents=True, exist_ok=True)
    _validate_publish_target(observed_path, private=False)
    _validate_publish_target(envelope_path, private=True)
    lock_paths = sorted(
        (
            observed_path.with_name(f".{observed_path.name}.provision.lock"),
            envelope_path.with_name(f".{envelope_path.name}.provision.lock"),
        ),
        key=lambda item: str(item),
    )
    locks: list[tuple[Path, int]] = []
    stages: list[Path] = []
    try:
        for lock_path in lock_paths:
            locks.append((lock_path, _acquire_lock(lock_path)))
        # Validate again under the cooperative lock.
        _validate_publish_target(observed_path, private=False)
        _validate_publish_target(envelope_path, private=True)
        previous_observed = observed_path.read_bytes() if observed_path.exists() else None
        previous_envelope = envelope_path.read_bytes() if envelope_path.exists() else None
        observed_mode = (
            stat.S_IMODE(observed_path.stat().st_mode) if observed_path.exists() else 0o644
        )
        envelope_mode = 0o600
        staged_observed = _stage(observed_path, observed_content, observed_mode)
        staged_envelope = _stage(envelope_path, envelope_content, envelope_mode)
        stages.extend((staged_observed, staged_envelope))
        os.replace(staged_envelope, envelope_path)
        stages.remove(staged_envelope)
        try:
            os.replace(staged_observed, observed_path)
            stages.remove(staged_observed)
        except Exception:
            _restore(envelope_path, previous_envelope, envelope_mode)
            _restore(observed_path, previous_observed, observed_mode)
            raise
        for parent in {observed_path.parent, envelope_path.parent}:
            try:
                descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                pass
    finally:
        for staging in stages:
            staging.unlink(missing_ok=True)
        for lock_path, descriptor in reversed(locks):
            os.close(descriptor)
            lock_path.unlink(missing_ok=True)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument(
        "--endpoint-env",
        default="ECO_LOCAL_OPENAI_ENDPOINT",
        help="Environment variable holding the exact loopback completion URL",
    )
    parser.add_argument(
        "--evidence-key-env",
        default="ECO_LOCAL_ADAPTER_EVIDENCE_KEY",
        help="Environment variable holding the operator evidence key",
    )
    parser.add_argument("--issuer-id", default="local-adapter-authority")
    parser.add_argument("--key-id", default="local-adapter-v1")
    parser.add_argument("--envelope-out", type=Path, required=True)
    parser.add_argument("--validity-minutes", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser.parse_args()


def _run(args: argparse.Namespace) -> int:
    if (
        ENV_NAME_RE.fullmatch(args.endpoint_env) is None
        or ENV_NAME_RE.fullmatch(args.evidence_key_env) is None
        or SAFE_ID_RE.fullmatch(args.deployment_id) is None
        or SAFE_ID_RE.fullmatch(args.issuer_id) is None
        or SAFE_ID_RE.fullmatch(args.key_id) is None
        or not 1 <= args.validity_minutes <= 1440
        or not 1 <= args.timeout_seconds <= 300
    ):
        raise ValueError("provisioning arguments are outside policy bounds")
    endpoint_value = os.environ.get(args.endpoint_env)
    key_value = os.environ.get(args.evidence_key_env)
    if not endpoint_value or not key_value or len(key_value.encode("utf-8")) < 32:
        raise ValueError("required environment values are unavailable")
    endpoint = _normalize_loopback_endpoint(endpoint_value)
    context = _load_context(args.repo, args.deployment_id, args.endpoint_env, endpoint)
    envelope_path = _external_output_path(context.repository, args.envelope_out)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    valid_until = now + timedelta(minutes=args.validity_minutes)
    probes, reported_models = _probe(
        endpoint, context.deployment["model"], args.timeout_seconds
    )
    expected_probe_ids = [item["id"] for item in PROBE_SUITE["probes"]]
    status = (
        "pass"
        if [item.get("id") for item in probes] == expected_probe_ids
        and all(item.get("status") == "pass" for item in probes)
        and reported_models == [context.deployment["model"]]
        else "fail"
    )
    suite_digest = semantic_digest({"suite": PROBE_SUITE})
    observation = {
        "apiVersion": API_VERSION,
        "kind": "AdapterConformanceProfile",
        "metadata": {
            "id": f"{args.deployment_id}-observation",
            "deploymentId": args.deployment_id,
            "testedAt": _utc(now),
            "validUntil": _utc(valid_until),
        },
        "spec": {
            "deploymentIdentityDigest": deployment_identity_digest(context.deployment),
            "adapterVersion": context.deployment["identity"]["adapterVersion"],
            "suite": {
                "id": PROBE_SUITE["id"],
                "version": PROBE_SUITE["version"],
                "digest": suite_digest,
            },
            "status": status,
            "effectiveCapabilities": (
                ["model.text", "model.structured-output"] if status == "pass" else []
            ),
            "probes": probes,
            "deviationCodes": [] if status == "pass" else ["ECO_ADAPTER_PROBE_FAILED"],
        },
    }
    published = False
    if status == "pass":
        envelope = HmacEvidenceSigner(
            args.issuer_id, args.key_id, key_value.encode("utf-8")
        ).sign(
            observation,
            envelope_id=f"adapter-evidence-{semantic_digest(observation)[:32]}",
            issued_at=now,
            expires_at=valid_until,
            attestation={**context.binding, "reportedModels": reported_models},
        )
        _publish_outputs(
            context.observed_path,
            canonical_json(observation).encode("utf-8"),
            envelope_path,
            envelope,
        )
        published = True
    print(
        json.dumps(
            {
                "status": status,
                "published": published,
                "suiteDigest": suite_digest,
                "deploymentIdentityDigest": observation["spec"]["deploymentIdentityDigest"],
                "resolvedEndpointDigest": context.binding["resolvedEndpointDigest"],
                "validUntil": observation["metadata"]["validUntil"],
                "probes": [
                    {"id": item["id"], "status": item["status"]} for item in probes
                ],
            },
            indent=2,
        )
    )
    return 0 if status == "pass" else 1


def main() -> int:
    try:
        return _run(_arguments())
    except (
        KeyError,
        OSError,
        RuntimePolicyError,
        ValueError,
        yaml.YAMLError,
        urllib.error.URLError,
    ) as exc:
        print(f"ERROR: provisioning failed ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
