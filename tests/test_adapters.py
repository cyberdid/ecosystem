from __future__ import annotations

import copy
import hashlib
import unittest
from datetime import timedelta

from eco_runtime.adapters import (
    ADAPTER_VERSION,
    OpenAIChatInvocation,
    OpenAICompatibleAdapter,
    PinnedOpenAICompatibleDeployment,
)
from eco_runtime.contracts import API_VERSION, validate_record
from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.errors import RuntimeAdapterError
from tests.test_policy import NOW


DIGEST = "a" * 64
INPUT = "review this repository"


def deployment(*, mode: str) -> dict:
    local = mode == "local-loopback-http"
    endpoint_ref = "env:ECO_LOCAL_MODEL_ENDPOINT" if local else "config:approved-cloud-endpoint"
    value = {
        "id": "local-pinned" if local else "cloud-pinned",
        "provider": "local" if local else "approved-cloud-provider",
        "adapter": "openai-compatible",
        "model": "model-revision-exact",
        "endpointRef": endpoint_ref,
        "zone": "Z1" if local else "Z3",
        "allowedDataClasses": ["D0", "D1"],
        "artifactTrust": "P1",
        "declaredCapabilities": ["model.text"],
        "observedCapabilitiesRef": f".ai/evals/observed/{'local' if local else 'cloud'}.json",
        "retention": "local-no-store" if local else "contract-no-store",
        "trainingUse": "prohibited",
        "region": "local" if local else "eu-approved",
        "identity": {
            "adapterVersion": ADAPTER_VERSION,
            "modelRevision": "sha256:exact-model-revision",
            "runtimeEngine": "vllm" if local else "provider-api",
            "runtimeVersion": "1.2.3" if local else "2026-07-01",
            "quantization": "none",
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
        "enabled": True,
    }
    return value


def pinned(*, mode: str, valid_until=None) -> PinnedOpenAICompatibleDeployment:
    endpoint = (
        "http://127.0.0.1:8000/v1/chat/completions"
        if mode == "local-loopback-http"
        else "https://api.approved.example/v1/chat/completions"
    )
    return PinnedOpenAICompatibleDeployment(
        deployment(mode=mode),
        endpoint_url=endpoint,
        transport_profile=mode,
        resolved_at=NOW - timedelta(minutes=1),
        valid_until=valid_until or NOW + timedelta(minutes=10),
        maximum_timeout_ms=10_000,
    )


def model_request(target: PinnedOpenAICompatibleDeployment) -> dict:
    encoded = INPUT.encode()
    return {
        "apiVersion": API_VERSION,
        "kind": "ModelRequest",
        "metadata": {"id": "model-request-1", "runId": "run-1", "createdAt": "2026-07-15T12:00:00Z"},
        "spec": {
            "planDigest": DIGEST,
            "deploymentId": target.deployment_id,
            "deploymentIdentityDigest": target.identity_digest,
            "endpointBindingDigest": target.endpoint_binding_digest,
            "input": {
                "artifactRecordDigest": DIGEST,
                "contentDigest": hashlib.sha256(encoded).hexdigest(),
                "byteLength": len(encoded),
                "dataClass": "D1",
                "trust": "P1",
            },
            "parameters": {
                "maxOutputTokens": 100,
                "maxOutputBytes": 4096,
                "temperatureMillis": 0,
            },
            "timeoutMs": 5_000,
            "fallbackPolicy": "none",
        },
    }


def response(*, content: str = "review complete", model: str = "model-revision-exact") -> dict:
    return {
        "id": "provider-request-private-1",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 4, "completion_tokens": 3, "total_tokens": 7},
    }


class RecordingInvoker:
    def __init__(self, result=None, failure: BaseException | None = None) -> None:
        self.result = response() if result is None else result
        self.failure = failure
        self.calls: list[tuple[OpenAIChatInvocation, int]] = []

    def invoke(self, request: OpenAIChatInvocation, *, timeout_ms: int):
        self.calls.append((request, timeout_ms))
        if self.failure is not None:
            raise self.failure
        return copy.deepcopy(self.result)


class OpenAICompatibleAdapterTests(unittest.TestCase):
    def assert_code(self, code: str, operation) -> RuntimeAdapterError:
        with self.assertRaises(RuntimeAdapterError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_local_and_direct_cloud_use_same_pinned_semantics(self) -> None:
        expected_profiles = {
            "local-loopback-http": "none",
            "direct-cloud-https": "transport-owned",
        }
        for mode, credential_mode in expected_profiles.items():
            with self.subTest(mode=mode):
                target = pinned(mode=mode)
                invoker = RecordingInvoker()
                result = OpenAICompatibleAdapter(target, invoker).invoke(
                    model_request(target), INPUT, now=NOW
                )
                self.assertEqual(result.untrusted_output, "review complete")
                self.assertEqual(result.record["spec"]["deploymentIdentityDigest"], target.identity_digest)
                self.assertEqual(result.record["spec"]["endpointBindingDigest"], target.endpoint_binding_digest)
                self.assertEqual(result.record["spec"]["output"]["trust"], "P0")
                self.assertEqual(len(invoker.calls), 1)
                invocation, timeout = invoker.calls[0]
                self.assertEqual(timeout, 5_000)
                self.assertEqual(invocation.model, "model-revision-exact")
                self.assertNotIn("credential", vars(invocation))
                self.assertNotIn(INPUT, repr(invocation))
                self.assertNotIn("provider-request-private-1", str(result.record))
                self.assertNotIn("review complete", repr(result))
                binding = target.endpoint_binding()
                self.assertEqual(binding["spec"]["transportProfile"], mode)
                self.assertEqual(binding["spec"]["credentialMode"], credential_mode)
                self.assertNotIn("endpointUrl", str(binding))
                validate_record(binding)
                validate_record(result.record)

    def test_identity_endpoint_and_input_mismatch_fail_before_invocation(self) -> None:
        target = pinned(mode="direct-cloud-https")
        for field in ("deploymentIdentityDigest", "endpointBindingDigest"):
            with self.subTest(field=field):
                request = model_request(target)
                request["spec"][field] = "b" * 64
                invoker = RecordingInvoker()
                self.assert_code(
                    "ECO_MODEL_ROUTE_MISMATCH",
                    lambda request=request: OpenAICompatibleAdapter(target, invoker).invoke(
                        request, INPUT, now=NOW
                    ),
                )
                self.assertEqual(invoker.calls, [])
        invoker = RecordingInvoker()
        self.assert_code(
            "ECO_MODEL_INPUT_MISMATCH",
            lambda: OpenAICompatibleAdapter(target, invoker).invoke(
                model_request(target), INPUT + " changed", now=NOW
            ),
        )
        self.assertEqual(invoker.calls, [])

    def test_timeout_and_transport_errors_are_sanitized_without_fallback(self) -> None:
        marker = "ECO_PRIVATE_PROVIDER_BODY_MUST_NOT_ESCAPE"
        target = pinned(mode="direct-cloud-https")
        for failure, code in (
            (TimeoutError(marker), "ECO_ADAPTER_TIMEOUT"),
            (OSError(marker), "ECO_ADAPTER_TRANSPORT"),
        ):
            with self.subTest(code=code):
                invoker = RecordingInvoker(failure=failure)
                error = self.assert_code(
                    code,
                    lambda: OpenAICompatibleAdapter(target, invoker).invoke(
                        model_request(target), INPUT, now=NOW
                    ),
                )
                self.assertNotIn(marker, str(error))
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)
                self.assertEqual(len(invoker.calls), 1)
                self.assertEqual(model_request(target)["spec"]["fallbackPolicy"], "none")

    def test_response_model_shape_usage_and_output_limits_fail_closed(self) -> None:
        target = pinned(mode="local-loopback-http")
        cases = [
            (response(model="alias-not-pinned"), "ECO_ADAPTER_RESPONSE_INVALID"),
            ({"error": "private provider body"}, "ECO_ADAPTER_RESPONSE_INVALID"),
            (response(content="x" * 5000), "ECO_ADAPTER_OUTPUT_LIMIT"),
        ]
        tool_response = response()
        tool_response["choices"][0]["message"]["tool_calls"] = [{"id": "unsupported"}]
        cases.append((tool_response, "ECO_ADAPTER_RESPONSE_INVALID"))
        for provider_response, code in cases:
            with self.subTest(code=code):
                invoker = RecordingInvoker(result=provider_response)
                self.assert_code(
                    code,
                    lambda: OpenAICompatibleAdapter(target, invoker).invoke(
                        model_request(target), INPUT, now=NOW
                    ),
                )
                self.assertEqual(len(invoker.calls), 1)

    def test_endpoint_profiles_are_explicit_and_fail_closed(self) -> None:
        local = deployment(mode="local-loopback-http")
        cloud = deployment(mode="direct-cloud-https")
        invalid = [
            (local, "http://192.168.1.10/v1/chat/completions", "local-loopback-http"),
            (local, "http://localhost/v1/chat/completions", "local-loopback-http"),
            (cloud, "http://api.approved.example/v1/chat/completions", "direct-cloud-https"),
            (cloud, "https://127.0.0.1/v1/chat/completions", "direct-cloud-https"),
            (cloud, "https://api.approved.example/other", "direct-cloud-https"),
        ]
        for candidate, endpoint, mode in invalid:
            with self.subTest(endpoint=endpoint):
                self.assert_code(
                    "ECO_ENDPOINT_POLICY_DENIED" if endpoint.endswith("chat/completions") else "ECO_ENDPOINT_INVALID",
                    lambda candidate=candidate, endpoint=endpoint, mode=mode: PinnedOpenAICompatibleDeployment(
                        candidate,
                        endpoint_url=endpoint,
                        transport_profile=mode,
                        resolved_at=NOW,
                        valid_until=NOW + timedelta(minutes=1),
                    ),
                )

    def test_exact_adapter_revision_and_binding_lifetime_are_enforced(self) -> None:
        candidate = deployment(mode="local-loopback-http")
        candidate["identity"]["adapterVersion"] = "unverified-version"
        self.assert_code(
            "ECO_ADAPTER_VERSION_MISMATCH",
            lambda: PinnedOpenAICompatibleDeployment(
                candidate,
                endpoint_url="http://127.0.0.1:8000/v1/chat/completions",
                transport_profile="local-loopback-http",
                resolved_at=NOW,
                valid_until=NOW + timedelta(minutes=1),
            ),
        )
        target = pinned(mode="local-loopback-http", valid_until=NOW - timedelta(seconds=1))
        invoker = RecordingInvoker()
        self.assert_code(
            "ECO_ENDPOINT_BINDING_EXPIRED",
            lambda: OpenAICompatibleAdapter(target, invoker).invoke(
                model_request(target), INPUT, now=NOW
            ),
        )
        self.assertEqual(invoker.calls, [])

    def test_deployment_identity_is_exact_not_transport_compatibility(self) -> None:
        candidate = deployment(mode="direct-cloud-https")
        target = pinned(mode="direct-cloud-https")
        self.assertEqual(target.identity_digest, deployment_identity_digest(candidate))
        changed = copy.deepcopy(candidate)
        changed["identity"]["modelRevision"] = "another-revision"
        self.assertNotEqual(target.identity_digest, deployment_identity_digest(changed))


if __name__ == "__main__":
    unittest.main()
