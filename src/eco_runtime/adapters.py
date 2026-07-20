from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit
from urllib import error as urllib_error
from urllib import request as urllib_request

from .contracts import API_VERSION, validate_record
from .digests import canonical_json, deployment_identity_digest, semantic_digest
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
class OpenAITypedChatMessage:
    """One broker-assigned message; payload bytes cannot select their role."""

    role: Literal["system", "user"]
    channel: Literal[
        "trusted_instruction",
        "runtime_state",
        "untrusted_source",
        "untrusted_artifact",
    ]
    trust: Literal["trusted", "P0"]
    content: str = field(repr=False)

    def __post_init__(self) -> None:
        allowed = {
            "trusted_instruction": ("system", "trusted"),
            "runtime_state": ("user", "trusted"),
            "untrusted_source": ("user", "P0"),
            "untrusted_artifact": ("user", "P0"),
        }
        if allowed.get(self.channel) != (self.role, self.trust):
            raise ValueError("message authority is invalid")
        if not isinstance(self.content, str):
            raise TypeError("message content must be text")


@dataclass(frozen=True)
class OpenAITypedChatInvocation:
    """Typed, credential-free request handed to the broker-owned transport.

    ``tools`` is structurally fixed to an empty tuple and ``tool_choice`` is
    fixed to ``none``.  A transport must serialize those values explicitly;
    it must not infer provider defaults.
    """

    endpoint_url: str
    model: str
    request_id: str
    messages: tuple[OpenAITypedChatMessage, ...] = field(repr=False)
    response_schema: Mapping[str, Any] = field(repr=False)
    max_output_tokens: int
    temperature_millis: int
    tools: tuple[Mapping[str, Any], ...] = ()
    tool_choice: Literal["none"] = "none"

    def __post_init__(self) -> None:
        messages = tuple(self.messages)
        if not messages or messages[0].channel != "trusted_instruction":
            raise ValueError("typed invocation must start with its trusted instruction")
        if self.tools != () or self.tool_choice != "none":
            raise ValueError("typed invocation tools must remain disabled")
        if not isinstance(self.response_schema, Mapping):
            raise TypeError("response_schema must be a mapping")
        object.__setattr__(self, "messages", messages)
        object.__setattr__(
            self,
            "response_schema",
            MappingProxyType(copy.deepcopy(dict(self.response_schema))),
        )


class OpenAITypedCompatibleInvoker(Protocol):
    """Network seam for typed OpenAI-compatible chat requests."""

    def invoke(
        self, request: OpenAITypedChatInvocation, *, timeout_ms: int
    ) -> Mapping[str, Any]: ...


class _NoRedirects(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_GRAMMAR_UNSUPPORTED_KEYWORDS = ("$schema", "minLength", "maxLength", "uniqueItems")


def grammar_safe_response_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Project a response schema onto the subset provider grammars can express.

    ``minLength``/``maxLength``/``uniqueItems`` are not expressible in the
    grammar engines behind OpenAI-compatible structured output (llama.cpp
    silently degrades to unconstrained generation when they are present, and
    the OpenAI structured-output subset excludes them). The wire schema is
    only a generation constraint hint: the caller keeps validating the
    response against the complete original schema, so removing these keywords
    here narrows nothing at the authoritative boundary.
    """

    def _walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            return {
                key: _walk(value)
                for key, value in node.items()
                if key not in _GRAMMAR_UNSUPPORTED_KEYWORDS
            }
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    return _walk(dict(schema))


class LoopbackOpenAITypedHTTPInvoker:
    """Bounded credential-free HTTP transport for a pinned loopback endpoint."""

    def __init__(self, *, maximum_response_bytes: int = 8 * 1024 * 1024) -> None:
        if (
            not isinstance(maximum_response_bytes, int)
            or isinstance(maximum_response_bytes, bool)
            or maximum_response_bytes < 1
        ):
            raise ValueError("maximum_response_bytes must be a positive integer")
        self._maximum_response_bytes = maximum_response_bytes
        self._opener = urllib_request.build_opener(
            urllib_request.ProxyHandler({}), _NoRedirects()
        )

    def invoke(
        self, request: OpenAITypedChatInvocation, *, timeout_ms: int
    ) -> Mapping[str, Any]:
        if not isinstance(request, OpenAITypedChatInvocation):
            raise TypeError("request must be OpenAITypedChatInvocation")
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        # Recheck at the concrete network boundary; construction through a
        # pinned deployment is not treated as sufficient transport authority.
        endpoint = _normalized_endpoint(request.endpoint_url, "local-loopback-http")
        body = canonical_json(
            {
                "max_tokens": request.max_output_tokens,
                "messages": [
                    {"content": message.content, "role": message.role}
                    for message in request.messages
                ],
                "model": request.model,
                "response_format": {
                    "json_schema": {
                        "name": "eco_structured_output",
                        "schema": grammar_safe_response_schema(request.response_schema),
                        "strict": True,
                    },
                    "type": "json_schema",
                },
                "temperature": request.temperature_millis / 1000,
                "tool_choice": "none",
                "tools": [],
            }
        ).encode("utf-8")
        network_request = urllib_request.Request(
            endpoint,
            data=body,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(
                network_request, timeout=timeout_ms / 1000
            ) as response:
                if getattr(response, "status", None) != 200:
                    raise OSError("unexpected provider status")
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        declared = int(length)
                    except (TypeError, ValueError):
                        raise OSError("invalid provider content length") from None
                    if declared < 0 or declared > self._maximum_response_bytes:
                        raise OSError("provider response exceeded limit")
                payload = response.read(self._maximum_response_bytes + 1)
        except (TimeoutError, socket.timeout):
            raise TimeoutError("loopback model transport timed out") from None
        except (OSError, urllib_error.URLError, urllib_error.HTTPError):
            raise OSError("loopback model transport failed") from None
        if len(payload) > self._maximum_response_bytes:
            raise OSError("loopback model transport failed")
        try:
            value = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_envelope_keys,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("non-finite")
                ),
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            _DuplicateEnvelopeKey,
            ValueError,
        ):
            raise OSError("loopback model transport failed") from None
        if not isinstance(value, dict):
            raise OSError("loopback model transport failed")
        return value


_TYPED_ENVELOPE_FORMAT = "eco.openai-typed-messages/v1"
_TYPED_ENVELOPE_KEYS = {
    "attempt",
    "format",
    "roleId",
    "runtimeState",
    "trustedInstruction",
    "trustedOutputSchema",
    "untrustedArtifacts",
    "untrustedSources",
}
_TYPED_PAYLOAD_KEYS = {
    "binding",
    "contentBase64",
    "mediaType",
    "sourceEntryId",
    "trust",
}


class _DuplicateEnvelopeKey(ValueError):
    pass


def _reject_duplicate_envelope_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateEnvelopeKey(key)
        value[key] = item
    return value


def _typed_payload_message(
    value: Any, *, channel: Literal["untrusted_source", "untrusted_artifact"]
) -> OpenAITypedChatMessage:
    if not isinstance(value, dict) or set(value) != _TYPED_PAYLOAD_KEYS:
        raise RuntimeAdapterError(
            "ECO_MODEL_INPUT_MISMATCH", "Typed model input is invalid"
        )
    binding = value["binding"]
    encoded = value["contentBase64"]
    media_type = value["mediaType"]
    entry_id = value["sourceEntryId"]
    if (
        not isinstance(binding, dict)
        or not isinstance(encoded, str)
        or not isinstance(media_type, str)
        or not media_type
        or (entry_id is not None and not isinstance(entry_id, str))
        or value["trust"] != "P0"
    ):
        raise RuntimeAdapterError(
            "ECO_MODEL_INPUT_MISMATCH", "Typed model input is invalid"
        )
    try:
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError("non-canonical base64")
        content = raw.decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise RuntimeAdapterError(
            "ECO_MODEL_INPUT_MISMATCH", "Typed model input is invalid"
        ) from None
    message_content = canonical_json(
        {
            "binding": binding,
            "channel": channel,
            "content": content,
            "mediaType": media_type,
            "sourceEntryId": entry_id,
            "trust": "P0",
        }
    )
    return OpenAITypedChatMessage(
        role="user", channel=channel, trust="P0", content=message_content
    )


def _parse_typed_envelope(
    input_text: str,
) -> tuple[tuple[OpenAITypedChatMessage, ...], Mapping[str, Any]]:
    try:
        value = json.loads(
            input_text,
            object_pairs_hook=_reject_duplicate_envelope_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")),
        )
        if not isinstance(value, dict) or set(value) != _TYPED_ENVELOPE_KEYS:
            raise ValueError("shape")
        if canonical_json(value) != input_text:
            raise ValueError("non-canonical")
        if value["format"] != _TYPED_ENVELOPE_FORMAT:
            raise ValueError("format")
        if not isinstance(value["roleId"], str) or not value["roleId"]:
            raise ValueError("role")
        if value["attempt"] not in {1, 2} or isinstance(value["attempt"], bool):
            raise ValueError("attempt")
        instruction = value["trustedInstruction"]
        output_schema = value["trustedOutputSchema"]
        runtime_state = value["runtimeState"]
        sources = value["untrustedSources"]
        artifacts = value["untrustedArtifacts"]
        if (
            not isinstance(instruction, str)
            or not instruction
            or not isinstance(output_schema, dict)
            or not isinstance(runtime_state, dict)
            or not isinstance(sources, list)
            or not isinstance(artifacts, list)
            or len(sources) > 256
            or len(artifacts) > 256
        ):
            raise ValueError("channels")
        messages = [
            OpenAITypedChatMessage(
                role="system",
                channel="trusted_instruction",
                trust="trusted",
                content=instruction,
            ),
            OpenAITypedChatMessage(
                role="user",
                channel="runtime_state",
                trust="trusted",
                content=canonical_json(runtime_state),
            ),
        ]
        messages.extend(
            _typed_payload_message(item, channel="untrusted_source")
            for item in sources
        )
        messages.extend(
            _typed_payload_message(item, channel="untrusted_artifact")
            for item in artifacts
        )
        return tuple(messages), output_schema
    except RuntimeAdapterError:
        raise
    except (
        ContractValidationError,
        json.JSONDecodeError,
        _DuplicateEnvelopeKey,
        RecursionError,
        RuntimePolicyError,
        TypeError,
        UnicodeError,
        ValueError,
    ):
        raise RuntimeAdapterError(
            "ECO_MODEL_INPUT_MISMATCH", "Typed model input is invalid"
        ) from None


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
        # The id must be content-addressed over every field that reaches the
        # sealed record: the durable store binds one immutable digest per record
        # id, and a later resolution with the same deployment/endpoint but a new
        # resolvedAt/validUntil window must coexist as history, not collide.
        binding_id = "endpoint-" + semantic_digest(
            {
                "deploymentId": candidate["id"],
                "endpoint": normalized_endpoint,
                "resolvedAt": resolved_at_text,
                "validUntil": valid_until_text,
            }
        )
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


class TypedOpenAICompatibleAdapter:
    """OpenAI-compatible adapter that preserves authority-separated channels.

    The canonical input envelope is checked against ``ModelRequest`` before it
    is parsed.  Only this adapter assigns provider roles.  Inert source bytes
    therefore cannot manufacture a system message or enable a tool channel.
    """

    def __init__(
        self,
        deployment: PinnedOpenAICompatibleDeployment,
        invoker: OpenAITypedCompatibleInvoker,
    ) -> None:
        self._deployment = deployment
        self._invoker = invoker
        # Response normalization is deliberately shared with the established
        # one-shot adapter so typed and legacy calls have identical result
        # contracts and provider-output rejection rules.
        self._response_adapter = OpenAICompatibleAdapter(deployment, invoker)  # type: ignore[arg-type]

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
            raise RuntimeAdapterError(
                "ECO_MODEL_REQUEST_INVALID", "Model request is invalid"
            ) from exc
        if request["kind"] != "ModelRequest" or not isinstance(input_text, str):
            raise RuntimeAdapterError(
                "ECO_MODEL_REQUEST_INVALID", "Model request is invalid"
            )
        now_utc = now.astimezone(timezone.utc) if now.tzinfo is not None else None
        if now_utc is None:
            raise RuntimeAdapterError(
                "ECO_CLOCK_INVALID", "Adapter clock must be timezone-aware"
            )
        binding = self._deployment._binding
        if not (
            _parse_time(binding["metadata"]["resolvedAt"])
            <= now_utc
            < _parse_time(binding["metadata"]["validUntil"])
        ):
            raise RuntimeAdapterError(
                "ECO_ENDPOINT_BINDING_EXPIRED",
                "Endpoint binding is not currently valid",
            )
        spec = request["spec"]
        if (
            spec["deploymentId"] != self._deployment.deployment_id
            or spec["deploymentIdentityDigest"] != self._deployment.identity_digest
            or spec["endpointBindingDigest"]
            != self._deployment.endpoint_binding_digest
            or spec["timeoutMs"] > self._deployment._maximum_timeout_ms
        ):
            raise RuntimeAdapterError(
                "ECO_MODEL_ROUTE_MISMATCH", "Model request route is not pinned"
            )
        try:
            encoded_input = input_text.encode("utf-8")
        except UnicodeEncodeError:
            raise RuntimeAdapterError(
                "ECO_MODEL_INPUT_MISMATCH", "Model input is not valid UTF-8"
            ) from None
        if (
            len(encoded_input) != spec["input"]["byteLength"]
            or hashlib.sha256(encoded_input).hexdigest()
            != spec["input"]["contentDigest"]
        ):
            raise RuntimeAdapterError(
                "ECO_MODEL_INPUT_MISMATCH",
                "Model input does not match its binding",
            )
        messages, output_schema = _parse_typed_envelope(input_text)
        invocation = OpenAITypedChatInvocation(
            endpoint_url=self._deployment._endpoint_url,
            model=self._deployment.model,
            request_id=request["metadata"]["id"],
            messages=messages,
            response_schema=output_schema,
            max_output_tokens=spec["parameters"]["maxOutputTokens"],
            temperature_millis=spec["parameters"]["temperatureMillis"],
            tools=(),
            tool_choice="none",
        )
        try:
            response = self._invoker.invoke(invocation, timeout_ms=spec["timeoutMs"])
        except TimeoutError:
            raise RuntimeAdapterError(
                "ECO_ADAPTER_TIMEOUT", "Model invocation timed out"
            ) from None
        except Exception:
            raise RuntimeAdapterError(
                "ECO_ADAPTER_TRANSPORT", "Model transport failed"
            ) from None
        return self._response_adapter._normalize_response(request, response, now=now)
