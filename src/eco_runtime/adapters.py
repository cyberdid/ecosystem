from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from .contracts import API_VERSION, validate_record
from .digests import deployment_identity_digest, semantic_digest
from .errors import ContractValidationError, RuntimeAdapterError, RuntimePolicyError


ADAPTER_VERSION = "openai-compatible-v1"
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise RuntimeAdapterError("ECO_CLOCK_INVALID", "Adapter clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RuntimeAdapterError("ECO_ENDPOINT_BINDING_INVALID", "Endpoint binding time is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeAdapterError("ECO_ENDPOINT_BINDING_INVALID", "Endpoint binding time has no timezone")
    return parsed.astimezone(timezone.utc)


def _normalized_endpoint(endpoint_url: str, profile: str) -> str:
    if not isinstance(endpoint_url, str) or len(endpoint_url) > 2048:
        raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Resolved endpoint is invalid")
    try:
        parsed = urlsplit(endpoint_url)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Resolved endpoint is invalid") from exc
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or parsed.path != "/v1/chat/completions"
        or "\\" in parsed.path
        or "%" in parsed.path
    ):
        raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Resolved endpoint is invalid")
    host = parsed.hostname.lower()
    if profile == "local-loopback-http":
        if parsed.scheme != "http":
            raise RuntimeAdapterError("ECO_ENDPOINT_POLICY_DENIED", "Local endpoint must use loopback HTTP")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise RuntimeAdapterError(
                "ECO_ENDPOINT_POLICY_DENIED", "Local endpoint must use a literal loopback address"
            ) from exc
        if not address.is_loopback:
            raise RuntimeAdapterError(
                "ECO_ENDPOINT_POLICY_DENIED", "Local endpoint must use a literal loopback address"
            )
    elif profile == "direct-cloud-https":
        if parsed.scheme != "https":
            raise RuntimeAdapterError("ECO_ENDPOINT_POLICY_DENIED", "Cloud endpoint must use HTTPS")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Cloud endpoint host is invalid") from exc
            labels = ascii_host.split(".")
            if len(labels) < 2 or any(_HOST_LABEL.fullmatch(label) is None for label in labels):
                raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Cloud endpoint host is invalid")
            if ascii_host.endswith((".local", ".localhost")):
                raise RuntimeAdapterError("ECO_ENDPOINT_POLICY_DENIED", "Cloud endpoint is not public")
            host = ascii_host
        else:
            if not address.is_global:
                raise RuntimeAdapterError("ECO_ENDPOINT_POLICY_DENIED", "Cloud endpoint is not public")
    else:
        raise RuntimeAdapterError("ECO_ADAPTER_PROFILE_UNSUPPORTED", "Adapter profile is unsupported")
    if port is not None and not 1 <= port <= 65535:
        raise RuntimeAdapterError("ECO_ENDPOINT_INVALID", "Resolved endpoint port is invalid")
    display_host = f"[{host}]" if ":" in host else host
    authority = display_host if port is None else f"{display_host}:{port}"
    return urlunsplit((parsed.scheme, authority, parsed.path, "", ""))


@dataclass(frozen=True)
class OpenAIChatInvocation:
    """Credential-free request handed only to the broker-owned transport."""

    endpoint_url: str
    model: str
    request_id: str
    input_text: str = field(repr=False)
    max_output_tokens: int
    temperature_millis: int


class OpenAICompatibleInvoker(Protocol):
    """Explicit network seam. Implementations own credentials and HTTP state."""

    def invoke(self, request: OpenAIChatInvocation, *, timeout_ms: int) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class AdapterInvocationResult:
    record: dict[str, Any]
    untrusted_output: str = field(repr=False)


class PinnedOpenAICompatibleDeployment:
    """Exact canonical identity plus one resolved local or cloud endpoint."""

    def __init__(
        self,
        deployment: Mapping[str, Any],
        *,
        endpoint_url: str,
        transport_profile: str,
        resolved_at: datetime,
        valid_until: datetime,
        maximum_timeout_ms: int = 120_000,
    ) -> None:
        if not isinstance(maximum_timeout_ms, int) or maximum_timeout_ms < 1:
            raise ValueError("maximum_timeout_ms must be a positive integer")
        candidate = copy.deepcopy(dict(deployment))
        if candidate.get("enabled") is not True:
            raise RuntimeAdapterError("ECO_DEPLOYMENT_DISABLED", "Deployment is not enabled")
        if candidate.get("adapter") != "openai-compatible":
            raise RuntimeAdapterError("ECO_ADAPTER_PROFILE_UNSUPPORTED", "Deployment adapter is unsupported")
        try:
            identity_digest = deployment_identity_digest(candidate)
        except RuntimePolicyError as exc:
            raise RuntimeAdapterError(exc.code, "Deployment identity is invalid") from exc
        identity = candidate["identity"]
        if identity["adapterVersion"] != ADAPTER_VERSION:
            raise RuntimeAdapterError("ECO_ADAPTER_VERSION_MISMATCH", "Adapter version is not pinned")
        normalized_endpoint = _normalized_endpoint(endpoint_url, transport_profile)
        resolved_at_text = _utc(resolved_at)
        valid_until_text = _utc(valid_until)
        if valid_until.astimezone(timezone.utc) <= resolved_at.astimezone(timezone.utc):
            raise RuntimeAdapterError("ECO_ENDPOINT_BINDING_INVALID", "Endpoint binding lifetime is invalid")
        credential_mode = "none" if transport_profile == "local-loopback-http" else "transport-owned"
        binding_id = f"endpoint-{semantic_digest({'deploymentId': candidate['id'], 'endpoint': normalized_endpoint})}"
        binding = {
            "apiVersion": API_VERSION,
            "kind": "EndpointBinding",
            "metadata": {
                "id": binding_id,
                "deploymentId": candidate["id"],
                "resolvedAt": resolved_at_text,
                "validUntil": valid_until_text,
            },
            "spec": {
                "deploymentIdentityDigest": identity_digest,
                "endpointReferenceDigest": identity["endpointReferenceDigest"],
                "resolvedEndpointDigest": semantic_digest({"endpointUrl": normalized_endpoint}),
                "adapter": "openai-compatible",
                "adapterVersion": ADAPTER_VERSION,
                "model": candidate["model"],
                "transportProfile": transport_profile,
                "credentialMode": credential_mode,
            },
        }
        try:
            validate_record(binding)
        except ContractValidationError as exc:
            raise RuntimeAdapterError("ECO_ENDPOINT_BINDING_INVALID", "Endpoint binding is invalid") from exc
        self._deployment = candidate
        self._identity_digest = identity_digest
        self._endpoint_url = normalized_endpoint
        self._binding = binding
        self._binding_digest = semantic_digest(binding)
        self._maximum_timeout_ms = maximum_timeout_ms

    @property
    def deployment_id(self) -> str:
        return self._deployment["id"]

    @property
    def model(self) -> str:
        return self._deployment["model"]

    @property
    def identity_digest(self) -> str:
        return self._identity_digest

    @property
    def endpoint_binding_digest(self) -> str:
        return self._binding_digest

    def endpoint_binding(self) -> dict[str, Any]:
        return copy.deepcopy(self._binding)


class OpenAICompatibleAdapter:
    """One-shot pinned adapter with no routing or automatic fallback behavior."""

    def __init__(
        self,
        deployment: PinnedOpenAICompatibleDeployment,
        invoker: OpenAICompatibleInvoker,
    ) -> None:
        self._deployment = deployment
        self._invoker = invoker

    def invoke(
        self,
        request: dict[str, Any],
        input_text: str,
        *,
        now: datetime,
    ) -> AdapterInvocationResult:
        try:
            request = copy.deepcopy(validate_record(request))
        except ContractValidationError as exc:
            raise RuntimeAdapterError("ECO_MODEL_REQUEST_INVALID", "Model request is invalid") from exc
        if request["kind"] != "ModelRequest" or not isinstance(input_text, str):
            raise RuntimeAdapterError("ECO_MODEL_REQUEST_INVALID", "Model request is invalid")
        now_utc = now.astimezone(timezone.utc) if now.tzinfo is not None else None
        if now_utc is None:
            raise RuntimeAdapterError("ECO_CLOCK_INVALID", "Adapter clock must be timezone-aware")
        binding = self._deployment._binding
        if not (_parse_time(binding["metadata"]["resolvedAt"]) <= now_utc < _parse_time(binding["metadata"]["validUntil"])):
            raise RuntimeAdapterError("ECO_ENDPOINT_BINDING_EXPIRED", "Endpoint binding is not currently valid")
        spec = request["spec"]
        if (
            spec["deploymentId"] != self._deployment.deployment_id
            or spec["deploymentIdentityDigest"] != self._deployment.identity_digest
            or spec["endpointBindingDigest"] != self._deployment.endpoint_binding_digest
            or spec["timeoutMs"] > self._deployment._maximum_timeout_ms
        ):
            raise RuntimeAdapterError("ECO_MODEL_ROUTE_MISMATCH", "Model request route is not pinned")
        try:
            encoded_input = input_text.encode("utf-8")
        except UnicodeEncodeError:
            raise RuntimeAdapterError("ECO_MODEL_INPUT_MISMATCH", "Model input is not valid UTF-8") from None
        if (
            len(encoded_input) != spec["input"]["byteLength"]
            or hashlib.sha256(encoded_input).hexdigest() != spec["input"]["contentDigest"]
        ):
            raise RuntimeAdapterError("ECO_MODEL_INPUT_MISMATCH", "Model input does not match its binding")
        invocation = OpenAIChatInvocation(
            endpoint_url=self._deployment._endpoint_url,
            model=self._deployment.model,
            request_id=request["metadata"]["id"],
            input_text=input_text,
            max_output_tokens=spec["parameters"]["maxOutputTokens"],
            temperature_millis=spec["parameters"]["temperatureMillis"],
        )
        try:
            response = self._invoker.invoke(invocation, timeout_ms=spec["timeoutMs"])
        except TimeoutError:
            raise RuntimeAdapterError("ECO_ADAPTER_TIMEOUT", "Model invocation timed out") from None
        except Exception:
            raise RuntimeAdapterError("ECO_ADAPTER_TRANSPORT", "Model transport failed") from None
        return self._normalize_response(request, response, now=now)

    def _normalize_response(
        self,
        request: dict[str, Any],
        response: Mapping[str, Any],
        *,
        now: datetime,
    ) -> AdapterInvocationResult:
        try:
            provider_id = response["id"]
            reported_model = response["model"]
            choices = response["choices"]
            usage = response["usage"]
            choice = choices[0]
            message = choice["message"]
            content = message["content"]
            finish_reason = choice["finish_reason"]
            input_tokens = usage["prompt_tokens"]
            output_tokens = usage["completion_tokens"]
            total_tokens = usage["total_tokens"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeAdapterError("ECO_ADAPTER_RESPONSE_INVALID", "Model response is invalid") from exc
        values_are_valid = (
            isinstance(provider_id, str)
            and bool(provider_id)
            and isinstance(reported_model, str)
            and reported_model == self._deployment.model
            and isinstance(choices, list)
            and len(choices) == 1
            and isinstance(choice, Mapping)
            and choice.get("index") == 0
            and isinstance(message, Mapping)
            and message.get("role") == "assistant"
            and "tool_calls" not in message
            and isinstance(content, str)
            and finish_reason in {"stop", "length"}
            and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in (input_tokens, output_tokens, total_tokens))
            and total_tokens == input_tokens + output_tokens
        )
        if not values_are_valid:
            raise RuntimeAdapterError("ECO_ADAPTER_RESPONSE_INVALID", "Model response is invalid")
        parameters = request["spec"]["parameters"]
        try:
            encoded_output = content.encode("utf-8")
        except UnicodeEncodeError:
            raise RuntimeAdapterError("ECO_ADAPTER_RESPONSE_INVALID", "Model response is invalid") from None
        if output_tokens > parameters["maxOutputTokens"] or len(encoded_output) > parameters["maxOutputBytes"]:
            raise RuntimeAdapterError("ECO_ADAPTER_OUTPUT_LIMIT", "Model output exceeds its approved limit")
        request_digest = semantic_digest(request)
        record_id = f"model-result-{semantic_digest({'requestDigest': request_digest})}"
        record = {
            "apiVersion": API_VERSION,
            "kind": "ModelResult",
            "metadata": {
                "id": record_id,
                "runId": request["metadata"]["runId"],
                "requestId": request["metadata"]["id"],
                "createdAt": _utc(now),
            },
            "spec": {
                "modelRequestDigest": request_digest,
                "deploymentId": self._deployment.deployment_id,
                "deploymentIdentityDigest": self._deployment.identity_digest,
                "endpointBindingDigest": self._deployment.endpoint_binding_digest,
                "adapterVersion": ADAPTER_VERSION,
                "providerRequestIdDigest": semantic_digest({"providerRequestId": provider_id}),
                "reportedModelDigest": semantic_digest({"model": reported_model}),
                "output": {
                    "contentDigest": hashlib.sha256(encoded_output).hexdigest(),
                    "byteLength": len(encoded_output),
                    "dataClass": request["spec"]["input"]["dataClass"],
                    "trust": "P0",
                },
                "usage": {
                    "inputTokens": input_tokens,
                    "outputTokens": output_tokens,
                    "totalTokens": total_tokens,
                },
                "finishReason": finish_reason,
            },
        }
        try:
            validate_record(record)
        except ContractValidationError as exc:
            raise RuntimeAdapterError("ECO_ADAPTER_RESPONSE_INVALID", "Model result is invalid") from exc
        return AdapterInvocationResult(record=record, untrusted_output=content)
