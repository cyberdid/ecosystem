from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

import yaml

from eco_runtime.digests import canonical_json, deployment_identity_digest, semantic_digest
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.evidence import (
    EvidenceIssuerPolicy,
    EvidenceTrustStore,
    HmacEvidenceSigner,
    ObservationBindingExpectation,
    TrustedEvidenceIngestor,
)
from eco_runtime.policy import PolicyEngine
from tests import test_policy as policy_fixtures


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "provision_local_source_review.py"
SPEC = importlib.util.spec_from_file_location("provision_local_source_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError("provisioning script cannot be loaded")
SCRIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCRIPT)


@contextmanager
def _resolved_tempdir():
    """A ``TemporaryDirectory`` whose yielded name is symlink-resolved.

    On macOS ``/var`` and ``/tmp`` resolve into ``/private``; the provisioning
    ceremony legitimately rejects any evidence path that traverses a symlink,
    so a raw tempdir name would trip its anti-symlink guard. ``resolve()`` is a
    no-op on Linux CI and leaves deliberately-created symlinks inside the test
    untouched.
    """

    with tempfile.TemporaryDirectory() as directory:
        yield str(Path(directory).resolve())


class _Response:
    def __init__(
        self,
        payload: bytes,
        *,
        content_length: int | None = None,
        status: int = 200,
    ) -> None:
        self._payload = payload
        self.status = status
        self.headers = {
            "Content-Length": str(len(payload) if content_length is None else content_length)
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, amount: int = -1) -> bytes:
        return self._payload if amount < 0 else self._payload[:amount]


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests = []

    def open(self, request, *, timeout: int):
        self.requests.append((request, timeout))
        return self.response


def _deployment(identifier: str = "local-test") -> dict:
    endpoint_ref = "env:ECO_TEST_ENDPOINT"
    return {
        "id": identifier,
        "provider": "local",
        "adapter": "openai-compatible",
        "model": "fixture-model.gguf",
        "endpointRef": endpoint_ref,
        "observedCapabilitiesRef": f"evals/observed/{identifier}.json",
        "declaredCapabilities": ["model.text", "model.structured-output"],
        "enabled": True,
        "identity": {
            "adapterVersion": "openai-compatible-v1",
            "modelRevision": "fixture-revision",
            "runtimeEngine": "fixture",
            "runtimeVersion": "1",
            "quantization": "fixture",
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
    }


def _repository(root: Path, deployment: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    ai = root / ".ai"
    ai.mkdir()
    (ai / "project.yaml").write_text(
        yaml.safe_dump({"metadata": {"name": "fixture-project"}}), encoding="utf-8"
    )
    (ai / "deployments.yaml").write_text(
        yaml.safe_dump({"deployments": [deployment or _deployment()]}), encoding="utf-8"
    )
    return root


class SecureProvisioningTests(unittest.TestCase):
    def test_endpoint_requires_exact_canonical_literal_loopback_completion_url(self) -> None:
        accepted = "http://127.0.0.1:8080/v1/chat/completions"
        self.assertEqual(SCRIPT._normalize_loopback_endpoint(accepted), accepted)
        denied = (
            "https://127.0.0.1:8080/v1/chat/completions",
            "http://127.0.0.1/v1/chat/completions",
            "http://127.0.0.1.evil.test:8080/v1/chat/completions",
            "http://127.0.0.1@evil.test:8080/v1/chat/completions",
            "http://user@127.0.0.1:8080/v1/chat/completions",
            "http://127.0.0.1:8080/v1/chat/completions?next=http://evil.test",
            "http://127.0.0.1:8080/v1/chat/completions#fragment",
            "http://127.0.0.1:8080//v1/chat/completions",
            "http://127.0.0.1:8080/v1/%63hat/completions",
            "http://[::1]:8080/v1/chat/completions",
        )
        for endpoint in denied:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                SCRIPT._normalize_loopback_endpoint(endpoint)

    def test_transport_disables_proxy_and_redirect_and_bounds_response(self) -> None:
        payload = canonical_json(
            {
                "id": "request-1",
                "model": "fixture-model.gguf",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ok"},
                    }
                ],
            }
        ).encode()
        opener = _Opener(_Response(payload))
        with mock.patch.object(SCRIPT.urllib.request, "build_opener", return_value=opener) as build:
            response = SCRIPT._post(
                "http://127.0.0.1:8080/v1/chat/completions",
                {"model": "fixture-model.gguf"},
                5,
            )
        self.assertEqual(response["model"], "fixture-model.gguf")
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(item, SCRIPT.urllib.request.ProxyHandler) for item in handlers))
        proxy = next(item for item in handlers if isinstance(item, SCRIPT.urllib.request.ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertTrue(any(isinstance(item, SCRIPT._NoRedirectHandler) for item in handlers))

        oversized = _Opener(
            _Response(b"{}", content_length=SCRIPT.MAX_RESPONSE_BYTES + 1)
        )
        with mock.patch.object(SCRIPT.urllib.request, "build_opener", return_value=oversized):
            with self.assertRaises(ValueError):
                SCRIPT._post(
                    "http://127.0.0.1:8080/v1/chat/completions", {}, 5
                )

        wrong_status = _Opener(_Response(payload, status=201))
        with mock.patch.object(SCRIPT.urllib.request, "build_opener", return_value=wrong_status):
            with self.assertRaises(ValueError):
                SCRIPT._post(
                    "http://127.0.0.1:8080/v1/chat/completions", {}, 5
                )

        duplicate = _Opener(_Response(b'{"id":"first","id":"second"}'))
        with mock.patch.object(SCRIPT.urllib.request, "build_opener", return_value=duplicate):
            with self.assertRaises(ValueError):
                SCRIPT._post(
                    "http://127.0.0.1:8080/v1/chat/completions", {}, 5
                )

    def test_response_contract_rejects_depth_shape_and_reported_model_drift(self) -> None:
        valid = {
            "id": "request-1",
            "model": "fixture-model.gguf",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "ok"},
                }
            ],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3,
            },
        }
        choice, reported = SCRIPT._completion_choice(valid, "fixture-model.gguf", 10)
        self.assertEqual(choice["message"]["content"], "ok")
        self.assertEqual(reported, "fixture-model.gguf")
        for invalid in (
            {**valid, "model": "other-model"},
            {**valid, "choices": []},
            {**valid, "choices": [{"finish_reason": "stop", "message": "bad"}]},
            {**valid, "usage": {}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SCRIPT._completion_choice(invalid, "fixture-model.gguf", 10)

        nested: object = "leaf"
        for _ in range(SCRIPT.MAX_JSON_DEPTH + 1):
            nested = [nested]
        with self.assertRaises(ValueError):
            SCRIPT._validate_json_bounds(nested)

    def test_probe_uses_the_production_typed_wire_shape(self) -> None:
        responses = iter(
            (
                {
                    "id": "text-request",
                    "model": "fixture-model.gguf",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": '{"text":"testing works"}',
                            },
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 4,
                        "completion_tokens": 2,
                        "total_tokens": 6,
                    },
                },
                {
                    "id": "structured-request",
                    "model": "fixture-model.gguf",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": '{"fact":"tests detect regressions","confidence":"high"}',
                            },
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 5,
                        "completion_tokens": 3,
                        "total_tokens": 8,
                    },
                },
            )
        )
        payloads = []

        def provider(_endpoint, payload, _timeout):
            payloads.append(payload)
            return next(responses)

        with mock.patch.object(SCRIPT, "_post", side_effect=provider):
            probes, models = SCRIPT._probe(
                "http://127.0.0.1:8080/v1/chat/completions",
                "fixture-model.gguf",
                5,
            )
        self.assertEqual([item["status"] for item in probes], ["pass", "pass"])
        self.assertEqual(models, ["fixture-model.gguf"])
        expected_keys = {
            "max_tokens",
            "messages",
            "model",
            "response_format",
            "temperature",
            "tool_choice",
            "tools",
        }
        for payload in payloads:
            self.assertEqual(set(payload), expected_keys)
            self.assertEqual(payload["tools"], [])
            self.assertEqual(payload["tool_choice"], "none")
            self.assertEqual(payload["messages"][0]["role"], "system")
            self.assertEqual(
                payload["response_format"]["json_schema"]["name"],
                "eco_structured_output",
            )

    def test_context_binds_project_endpoint_reference_resolved_url_and_model(self) -> None:
        with _resolved_tempdir() as directory:
            root = _repository(Path(directory))
            endpoint = "http://127.0.0.1:8080/v1/chat/completions"
            context = SCRIPT._load_context(
                root, "local-test", "ECO_TEST_ENDPOINT", endpoint
            )
            self.assertEqual(context.project_id, "fixture-project")
            self.assertEqual(context.deployment["model"], "fixture-model.gguf")
            self.assertEqual(context.binding["endpointRef"], "env:ECO_TEST_ENDPOINT")
            self.assertEqual(
                context.binding["endpointReferenceDigest"],
                semantic_digest({"endpointRef": "env:ECO_TEST_ENDPOINT"}),
            )
            self.assertEqual(
                context.binding["resolvedEndpointDigest"],
                semantic_digest({"endpointUrl": endpoint}),
            )
            self.assertEqual(
                context.observed_path,
                root / ".ai" / "evals" / "observed" / "local-test.json",
            )

            changed = _deployment()
            changed["endpointRef"] = "env:OTHER_ENDPOINT"
            changed["identity"]["endpointReferenceDigest"] = semantic_digest(
                {"endpointRef": "env:OTHER_ENDPOINT"}
            )
            other = root / "other"
            other.mkdir()
            _repository(other, changed)
            with self.assertRaises(ValueError):
                SCRIPT._load_context(
                    other, "local-test", "ECO_TEST_ENDPOINT", endpoint
                )

    def test_ingestion_can_require_exact_project_endpoint_and_model_binding(self) -> None:
        now = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)
        endpoint_ref = "env:ECO_TEST_ENDPOINT"
        endpoint_digest = semantic_digest({"endpointRef": endpoint_ref})
        resolved_digest = semantic_digest(
            {"endpoint": "http://127.0.0.1:8080/v1/chat/completions"}
        )
        suite_digest = "b" * 64
        record = {
            "apiVersion": "runtime.ai.ecosystem/v1alpha1",
            "kind": "AdapterConformanceProfile",
            "metadata": {
                "id": "local-test-observation",
                "deploymentId": "local-test",
                "testedAt": "2026-07-20T10:00:00Z",
                "validUntil": "2026-07-20T11:00:00Z",
            },
            "spec": {
                "deploymentIdentityDigest": "a" * 64,
                "adapterVersion": "openai-compatible-v1",
                "suite": {
                    "id": "adapter-conformance-v1",
                    "version": "1.0.0",
                    "digest": suite_digest,
                },
                "status": "pass",
                "effectiveCapabilities": [
                    "model.text",
                    "model.structured-output",
                ],
                "probes": [
                    {
                        "id": "text-basic",
                        "status": "pass",
                        "attempts": 1,
                        "successes": 1,
                        "evidenceDigest": "c" * 64,
                    }
                ],
                "deviationCodes": [],
            },
        }
        key = b"operator-evidence-key-that-is-long-enough"
        attestation = {
            "projectId": "fixture-project",
            "endpointRef": endpoint_ref,
            "endpointReferenceDigest": endpoint_digest,
            "resolvedEndpointDigest": resolved_digest,
            "requestedModel": "fixture-model.gguf",
            "reportedModels": ["fixture-model.gguf"],
        }
        encoded = HmacEvidenceSigner("issuer", "key-1", key).sign(
            record,
            envelope_id="local-test-envelope",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            attestation=attestation,
        )
        contradictory = dict(attestation)
        contradictory["endpointReferenceDigest"] = "f" * 64
        with self.assertRaises(ValueError):
            HmacEvidenceSigner("issuer", "key-1", key).sign(
                record,
                envelope_id="contradictory-envelope",
                issued_at=now,
                expires_at=now + timedelta(hours=1),
                attestation=contradictory,
            )
        ingestor = TrustedEvidenceIngestor(
            EvidenceTrustStore(
                (
                    EvidenceIssuerPolicy(
                        "issuer",
                        "key-1",
                        key,
                        frozenset({"AdapterConformanceProfile"}),
                        allowed_deployments=frozenset({"local-test"}),
                        allowed_suite_digests=frozenset({suite_digest}),
                    ),
                )
            )
        )

        verified = ingestor.ingest_observed_capabilities(
            encoded,
            expected_deployment_id="local-test",
            expected_deployment_identity_digest="a" * 64,
            trusted_suite_digests=frozenset({suite_digest}),
            expected_project_id="fixture-project",
            expected_endpoint_ref=endpoint_ref,
            expected_endpoint_reference_digest=endpoint_digest,
            expected_resolved_endpoint_digest=resolved_digest,
            expected_model="fixture-model.gguf",
            now=now,
        )
        self.assertEqual(verified.as_dict()["metadata"]["deploymentId"], "local-test")
        with self.assertRaises(RuntimePolicyError) as caught:
            ingestor.ingest_observed_capabilities(
                encoded,
                expected_deployment_id="local-test",
                expected_deployment_identity_digest="a" * 64,
                trusted_suite_digests=frozenset({suite_digest}),
                expected_resolved_endpoint_digest="d" * 64,
                now=now,
            )
        self.assertEqual(caught.exception.code, "ECO_OBSERVATION_EVIDENCE_MISMATCH")

        project_restricted = TrustedEvidenceIngestor(
            EvidenceTrustStore(
                (
                    EvidenceIssuerPolicy(
                        "issuer",
                        "key-1",
                        key,
                        frozenset({"AdapterConformanceProfile"}),
                        allowed_projects=frozenset({"another-project"}),
                        allowed_deployments=frozenset({"local-test"}),
                        allowed_suite_digests=frozenset({suite_digest}),
                    ),
                )
            )
        )
        with self.assertRaises(RuntimePolicyError) as caught:
            project_restricted.ingest_observed_capabilities(
                encoded,
                expected_deployment_id="local-test",
                expected_deployment_identity_digest="a" * 64,
                trusted_suite_digests=frozenset({suite_digest}),
                expected_project_id="fixture-project",
                now=now,
            )
        self.assertEqual(caught.exception.code, "ECO_OBSERVATION_EVIDENCE_MISMATCH")

        tampered = json.loads(encoded)
        tampered["attestation"]["resolvedEndpointDigest"] = "e" * 64
        tampered_bytes = canonical_json(tampered).encode()
        with self.assertRaises(RuntimePolicyError) as caught:
            ingestor.ingest_observed_capabilities(
                tampered_bytes,
                expected_deployment_id="local-test",
                expected_deployment_identity_digest="a" * 64,
                trusted_suite_digests=frozenset({suite_digest}),
                expected_resolved_endpoint_digest="e" * 64,
                now=now,
            )
        self.assertEqual(caught.exception.code, "ECO_EVIDENCE_SIGNATURE_INVALID")

    def test_policy_engine_requires_explicit_expectation_for_configured_observation(self) -> None:
        bundle, observations = policy_fixtures.policy_bundle()
        deployment = bundle["deployments"]["deployments"][0]
        deployment_id = deployment["id"]
        endpoint_ref = deployment["endpointRef"]
        endpoint_digest = semantic_digest({"endpointRef": endpoint_ref})
        resolved_digest = semantic_digest(
            {"endpointUrl": "http://127.0.0.1:8080/v1/chat/completions"}
        )
        bundle["trust"]["conformance"] = {
            "trustedSuites": [
                {
                    "id": "adapter-conformance-v1",
                    "version": "1.0.0",
                    "digest": policy_fixtures.DIGEST,
                }
            ],
            "requiredObservations": [
                {
                    "deploymentId": deployment_id,
                    "suiteDigest": policy_fixtures.DIGEST,
                    "envelopeRef": "env:ECO_UNUSED_TEST_ENVELOPE",
                }
            ],
        }
        key = policy_fixtures.TEST_EVIDENCE_KEY
        encoded = HmacEvidenceSigner("operator-1", "key-1", key).sign(
            observations[deployment_id],
            envelope_id="policy-exact-observation",
            issued_at=policy_fixtures.NOW,
            expires_at=policy_fixtures.NOW + timedelta(minutes=30),
            attestation={
                "projectId": "sample",
                "endpointRef": endpoint_ref,
                "endpointReferenceDigest": endpoint_digest,
                "resolvedEndpointDigest": resolved_digest,
                "requestedModel": deployment["model"],
                "reportedModels": [deployment["model"]],
            },
        )
        policies = (
            EvidenceIssuerPolicy(
                "operator-1",
                "key-1",
                key,
                frozenset({"AdapterConformanceProfile"}),
                allowed_projects=frozenset({"sample"}),
                allowed_deployments=frozenset({deployment_id}),
                allowed_suite_digests=frozenset({policy_fixtures.DIGEST}),
            ),
        )
        common = {
            "evidence_policies": policies,
            "evidence_now": policy_fixtures.NOW,
            "trusted_suite_digests": {policy_fixtures.DIGEST},
        }
        with self.assertRaises(RuntimePolicyError) as caught:
            PolicyEngine(bundle, {deployment_id: encoded}, **common)
        self.assertEqual(caught.exception.code, "ECO_EVIDENCE_UNTRUSTED")

        expectation = ObservationBindingExpectation(
            project_id="sample",
            endpoint_ref=endpoint_ref,
            endpoint_reference_digest=endpoint_digest,
            resolved_endpoint_digest=resolved_digest,
            model=deployment["model"],
        )
        engine = PolicyEngine(
            bundle,
            {deployment_id: encoded},
            observation_expectations={deployment_id: expectation},
            **common,
        )
        self.assertEqual(
            engine._observations[deployment_id]["metadata"]["deploymentId"],
            deployment_id,
        )

    def test_observed_path_cannot_escape_governed_directory(self) -> None:
        for observed_ref in ("../../outside.json", "/tmp/outside.json", "evals/other.json"):
            with self.subTest(observed_ref=observed_ref), _resolved_tempdir() as directory:
                deployment = _deployment()
                deployment["observedCapabilitiesRef"] = observed_ref
                root = _repository(Path(directory), deployment)
                with self.assertRaises(ValueError):
                    SCRIPT._load_context(
                        root,
                        "local-test",
                        "ECO_TEST_ENDPOINT",
                        "http://127.0.0.1:8080/v1/chat/completions",
                    )

    @unittest.skipUnless(os.name == "posix", "POSIX symbolic-link contract")
    def test_observed_leaf_symlink_and_non_enabled_deployment_are_rejected(self) -> None:
        endpoint = "http://127.0.0.1:8080/v1/chat/completions"
        with _resolved_tempdir() as directory:
            root = _repository(Path(directory))
            observed = root / ".ai" / "evals" / "observed"
            observed.mkdir(parents=True)
            victim = observed / "victim.json"
            victim.write_bytes(b"victim")
            (observed / "local-test.json").symlink_to(victim)
            with self.assertRaises(ValueError):
                SCRIPT._load_context(root, "local-test", "ECO_TEST_ENDPOINT", endpoint)

        for enabled in (False, None, "true"):
            with self.subTest(enabled=enabled), _resolved_tempdir() as directory:
                deployment = _deployment()
                if enabled is None:
                    deployment.pop("enabled")
                else:
                    deployment["enabled"] = enabled
                root = _repository(Path(directory), deployment)
                with self.assertRaises(ValueError):
                    SCRIPT._load_context(
                        root, "local-test", "ECO_TEST_ENDPOINT", endpoint
                    )

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and mode contract")
    def test_external_output_is_outside_repo_private_and_not_linked(self) -> None:
        with _resolved_tempdir() as directory:
            base = Path(directory)
            repo = base / "repo"
            repo.mkdir()
            outside = base / "private"
            outside.mkdir(mode=0o700)
            output = outside / "evidence.json"
            self.assertEqual(SCRIPT._external_output_path(repo, output), output)
            with self.assertRaises(ValueError):
                SCRIPT._external_output_path(repo, repo / "evidence.json")

            os.chmod(outside, 0o755)
            with self.assertRaises(ValueError):
                SCRIPT._external_output_path(repo, output)
            os.chmod(outside, 0o700)

            source = outside / "source"
            source.write_bytes(b"old")
            os.link(source, output)
            with self.assertRaises(ValueError):
                SCRIPT._external_output_path(repo, output)

            output.unlink()
            alias = base / "private-alias"
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                SCRIPT._external_output_path(repo, alias / "evidence.json")

    @unittest.skipUnless(os.name == "posix", "POSIX atomic publication contract")
    def test_publication_is_atomic_private_locked_and_rolls_back(self) -> None:
        with _resolved_tempdir() as directory:
            base = Path(directory)
            observed_parent = base / "repo" / ".ai" / "evals" / "observed"
            observed_parent.mkdir(parents=True)
            observed = observed_parent / "local.json"
            private = base / "private"
            private.mkdir(mode=0o700)
            envelope = private / "local.envelope.json"
            SCRIPT._publish_outputs(observed, b"observation-v1", envelope, b"envelope-v1")
            self.assertEqual(observed.read_bytes(), b"observation-v1")
            self.assertEqual(envelope.read_bytes(), b"envelope-v1")
            self.assertEqual(stat.S_IMODE(envelope.stat().st_mode), 0o600)

            lock = envelope.with_name(f".{envelope.name}.provision.lock")
            lock.write_bytes(b"busy")
            with self.assertRaises(FileExistsError):
                SCRIPT._publish_outputs(observed, b"observation-v2", envelope, b"envelope-v2")
            self.assertEqual(observed.read_bytes(), b"observation-v1")
            self.assertEqual(envelope.read_bytes(), b"envelope-v1")
            lock.unlink()

            real_replace = SCRIPT.os.replace

            def fail_observation(source, destination):
                if Path(destination) == observed:
                    raise OSError("simulated second publish failure")
                return real_replace(source, destination)

            with mock.patch.object(SCRIPT.os, "replace", side_effect=fail_observation):
                with self.assertRaises(OSError):
                    SCRIPT._publish_outputs(
                        observed, b"observation-v2", envelope, b"envelope-v2"
                    )
            self.assertEqual(observed.read_bytes(), b"observation-v1")
            self.assertEqual(envelope.read_bytes(), b"envelope-v1")

    @unittest.skipUnless(os.name == "posix", "POSIX private output contract")
    def test_failed_probe_does_not_replace_last_valid_evidence(self) -> None:
        with _resolved_tempdir() as directory:
            base = Path(directory)
            repo = _repository(base / "repo")
            observed = repo / ".ai" / "evals" / "observed" / "local-test.json"
            observed.parent.mkdir(parents=True)
            observed.write_bytes(b"last-valid-observation")
            private = base / "private"
            private.mkdir(mode=0o700)
            envelope = private / "local.envelope.json"
            envelope.write_bytes(b"last-valid-envelope")
            envelope.chmod(0o600)
            args = SCRIPT.argparse.Namespace(
                repo=repo,
                deployment_id="local-test",
                endpoint_env="ECO_TEST_ENDPOINT",
                evidence_key_env="ECO_TEST_EVIDENCE_KEY",
                issuer_id="issuer",
                key_id="key-1",
                envelope_out=envelope,
                validity_minutes=60,
                timeout_seconds=5,
            )
            failed_probe = [
                {
                    "id": "text-basic",
                    "status": "fail",
                    "attempts": 1,
                    "successes": 0,
                    "evidenceDigest": "f" * 64,
                }
            ]
            environment = {
                "ECO_TEST_ENDPOINT": "http://127.0.0.1:8080/v1/chat/completions",
                "ECO_TEST_EVIDENCE_KEY": "k" * 32,
            }
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(
                    SCRIPT,
                    "_probe",
                    return_value=(failed_probe, ["fixture-model.gguf"]),
                ),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(SCRIPT._run(args), 1)
            self.assertEqual(observed.read_bytes(), b"last-valid-observation")
            self.assertEqual(envelope.read_bytes(), b"last-valid-envelope")
            self.assertEqual(stat.S_IMODE(envelope.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX private output contract")
    def test_successful_run_publishes_an_exact_bound_verifiable_envelope(self) -> None:
        with _resolved_tempdir() as directory:
            base = Path(directory)
            repo = _repository(base / "repo")
            private = base / "private"
            private.mkdir(mode=0o700)
            envelope = private / "local.envelope.json"
            args = SCRIPT.argparse.Namespace(
                repo=repo,
                deployment_id="local-test",
                endpoint_env="ECO_TEST_ENDPOINT",
                evidence_key_env="ECO_TEST_EVIDENCE_KEY",
                issuer_id="issuer",
                key_id="key-1",
                envelope_out=envelope,
                validity_minutes=60,
                timeout_seconds=5,
            )
            probes = [
                {
                    "id": probe_id,
                    "status": "pass",
                    "attempts": 1,
                    "successes": 1,
                    "evidenceDigest": digest * 64,
                }
                for probe_id, digest in (
                    ("text-basic", "c"),
                    ("structured-output-strict", "d"),
                )
            ]
            endpoint = "http://127.0.0.1:8080/v1/chat/completions"
            key = "k" * 32
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "ECO_TEST_ENDPOINT": endpoint,
                        "ECO_TEST_EVIDENCE_KEY": key,
                    },
                    clear=False,
                ),
                mock.patch.object(
                    SCRIPT,
                    "_probe",
                    return_value=(probes, ["fixture-model.gguf"]),
                ),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(SCRIPT._run(args), 0)
            observed = repo / ".ai" / "evals" / "observed" / "local-test.json"
            self.assertNotIn("binding", json.loads(observed.read_bytes())["spec"])
            encoded = envelope.read_bytes()
            value = json.loads(encoded)
            self.assertEqual(value["protocol"], "eco-trusted-evidence-v2")
            self.assertEqual(value["attestation"]["projectId"], "fixture-project")
            self.assertEqual(value["attestation"]["requestedModel"], "fixture-model.gguf")
            self.assertEqual(
                value["attestation"]["resolvedEndpointDigest"],
                semantic_digest({"endpointUrl": endpoint}),
            )
            suite_digest = semantic_digest({"suite": SCRIPT.PROBE_SUITE})
            ingestor = TrustedEvidenceIngestor(
                EvidenceTrustStore(
                    (
                        EvidenceIssuerPolicy(
                            "issuer",
                            "key-1",
                            key.encode(),
                            frozenset({"AdapterConformanceProfile"}),
                            allowed_deployments=frozenset({"local-test"}),
                            allowed_suite_digests=frozenset({suite_digest}),
                        ),
                    )
                )
            )
            ingestor.ingest_observed_capabilities(
                encoded,
                expected_deployment_id="local-test",
                expected_deployment_identity_digest=deployment_identity_digest(_deployment()),
                trusted_suite_digests=frozenset({suite_digest}),
                expected_project_id="fixture-project",
                expected_endpoint_ref="env:ECO_TEST_ENDPOINT",
                expected_endpoint_reference_digest=semantic_digest(
                    {"endpointRef": "env:ECO_TEST_ENDPOINT"}
                ),
                expected_resolved_endpoint_digest=semantic_digest(
                    {"endpointUrl": endpoint}
                ),
                expected_model="fixture-model.gguf",
                now=datetime.now(timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
