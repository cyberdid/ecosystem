from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from eco_cli.cli import main
from eco_cli.config import dump_yaml
from eco_cli.constants import CONFIG_FILES
from eco_cli.templates import starter_bundle
from eco_runtime.adapters import ADAPTER_VERSION
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import canonical_json, deployment_identity_digest, semantic_digest
from eco_runtime.evidence import HmacEvidenceSigner


EVIDENCE_KEY = "e" * 32
HMAC_KEY = "h" * 32
PROOF_KEY = "p" * 32
SUITE_DIGEST = "a" * 64


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _role_output(schema: dict) -> dict:
    properties = set(schema.get("properties", {}))
    if "objective" in properties:
        return {
            "objective": "Answer the bounded question",
            "analysisQuestions": ["What does the source state?"],
            "sourceEntryIds": ["question", "source-1"],
            "uncertainty": "low",
            "openQuestions": [],
        }
    if "claims" in properties:
        return {
            "claims": [
                {
                    "id": "claim-1",
                    "statement": "The source states alpha.",
                    "classification": "fact",
                    "evidence": [
                        {
                            "id": "evidence-1",
                            "sourceEntryId": "source-1",
                            "observation": "alpha",
                            "relation": "supports",
                        }
                    ],
                }
            ],
            "uncertainty": "low",
            "openQuestions": [],
        }
    if "verifications" in properties:
        return {
            "verifications": [
                {
                    "claimId": "claim-1",
                    "evidenceIds": ["evidence-1"],
                    "status": "verified",
                }
            ],
            "uncertainty": "none",
            "openQuestions": [],
        }
    if "report" in properties:
        return {
            "report": "Alpha is supported by the supplied source.",
            "claimIds": ["claim-1"],
            "unsupportedClaimIds": [],
            "uncertainty": "low",
            "openQuestions": [],
        }
    if "verdict" in properties:
        return {
            "verdict": "accepted",
            "findings": [],
            "reviewedClaimIds": ["claim-1"],
        }
    raise AssertionError("unexpected role schema")


class _Provider:
    def __init__(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers["Content-Length"])
                request = json.loads(self.rfile.read(length))
                owner.calls.append(request)
                content = canonical_json(
                    _role_output(request["response_format"]["json_schema"]["schema"])
                )
                response = json.dumps(
                    {
                        "id": f"provider-{len(owner.calls)}",
                        "model": "fixture-model",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": content},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 1,
                            "total_tokens": 2,
                        },
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_: object) -> None:
                return

        self.calls: list[dict] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_Provider":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1/chat/completions"


class SourceReviewCLIProductionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.external = self.root / "external"
        self.repo.mkdir()
        self.external.mkdir(mode=0o700)
        os.chmod(self.external, 0o700)
        self.created = datetime.now(timezone.utc).replace(microsecond=0)
        self.deadline = self.created + timedelta(minutes=20)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_bundle(
        self, endpoint: str, *, authority_deadline: datetime | None = None
    ) -> tuple[dict, bytes]:
        authority_deadline = authority_deadline or (self.deadline + timedelta(minutes=5))
        bundle = starter_bundle("sample")
        if not any(
            item["id"] == "model.structured-output"
            for item in bundle["capabilities"]["capabilities"]
        ):
            bundle["capabilities"]["capabilities"].append(
                {
                    "id": "model.structured-output",
                    "description": "Produce output validated against an explicit JSON Schema.",
                    "actionClass": "A0",
                    "sideEffect": False,
                    "defaultSandbox": "inspect",
                }
            )
        endpoint_ref = "env:ECO_LOCAL_OPENAI_ENDPOINT"
        deployment = {
            "id": "local-source-review",
            "provider": "local",
            "adapter": "openai-compatible",
            "model": "fixture-model",
            "endpointRef": endpoint_ref,
            "zone": "Z1",
            "allowedDataClasses": ["D0", "D1"],
            "artifactTrust": "P1",
            "declaredCapabilities": ["model.text", "model.structured-output"],
            "observedCapabilitiesRef": "evals/observed/local-source-review.json",
            "retention": "test-no-store",
            "trainingUse": "prohibited",
            "region": "local",
            "identity": {
                "adapterVersion": ADAPTER_VERSION,
                "modelRevision": "fixture-revision-1",
                "runtimeEngine": "fixture-runtime",
                "runtimeVersion": "1.0.0",
                "quantization": "none",
                "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
            },
            "enabled": True,
        }
        bundle["deployments"]["deployments"] = [deployment]
        bundle["deployments"]["logicalRoles"]["review.private"] = {
            "requiredCapabilities": ["model.text", "model.structured-output"],
            "allowedDataClasses": ["D0", "D1"],
            "allowedZones": ["Z1"],
            "minimumArtifactTrust": "P1",
            "maximumActionClass": "A0",
            "candidates": [deployment["id"]],
        }
        issuer = {
            "id": "local-eval-authority",
            "keyId": "local-eval-v1",
            "verificationKeyRef": "env:ECO_LOCAL_ADAPTER_EVIDENCE_KEY",
            "allowedKinds": ["RepositorySnapshot", "AdapterConformanceProfile"],
            "allowedProjects": ["sample"],
            "allowedDeployments": [deployment["id"]],
            "allowedSuiteDigests": [SUITE_DIGEST],
        }
        bundle["trust"]["evidence"]["issuers"] = [issuer]
        bundle["trust"]["repositorySnapshot"]["issuer"] = {
            "id": issuer["id"],
            "keyId": issuer["keyId"],
            "recordIssuerType": "operator",
        }
        bundle["trust"]["conformance"] = {
            "trustedSuites": [
                {"id": "adapter-conformance-v1", "version": "1.0.0", "digest": SUITE_DIGEST}
            ],
            "requiredObservations": [
                {
                    "deploymentId": deployment["id"],
                    "suiteDigest": SUITE_DIGEST,
                    "envelopeRef": "env:ECO_LOCAL_ADAPTER_ENVELOPE_FILE",
                }
            ],
        }
        observation = {
            "apiVersion": API_VERSION,
            "kind": "AdapterConformanceProfile",
            "metadata": {
                "id": "local-source-review-observation",
                "deploymentId": deployment["id"],
                "testedAt": _utc(self.created - timedelta(minutes=1)),
                "validUntil": _utc(authority_deadline),
            },
            "spec": {
                "deploymentIdentityDigest": deployment_identity_digest(deployment),
                "adapterVersion": ADAPTER_VERSION,
                "suite": {
                    "id": "adapter-conformance-v1",
                    "version": "1.0.0",
                    "digest": SUITE_DIGEST,
                },
                "status": "pass",
                "effectiveCapabilities": ["model.text", "model.structured-output"],
                "probes": [
                    {
                        "id": "text-basic",
                        "status": "pass",
                        "attempts": 1,
                        "successes": 1,
                        "evidenceDigest": SUITE_DIGEST,
                    },
                    {
                        "id": "structured-output-strict",
                        "status": "pass",
                        "attempts": 1,
                        "successes": 1,
                        "evidenceDigest": SUITE_DIGEST,
                    },
                ],
                "deviationCodes": [],
            },
        }
        envelope = HmacEvidenceSigner(
            issuer["id"], issuer["keyId"], EVIDENCE_KEY.encode()
        ).sign(
            observation,
            envelope_id="local-source-review-envelope",
            issued_at=self.created - timedelta(minutes=1),
            expires_at=authority_deadline,
        )
        config = self.repo / ".ai"
        config.mkdir()
        for name, document in bundle.items():
            (config / CONFIG_FILES[name]).write_text(dump_yaml(document), encoding="utf-8")
        observed = config / "evals" / "observed"
        observed.mkdir(parents=True)
        (observed / "local-source-review.json").write_text(
            canonical_json(observation), encoding="utf-8"
        )
        evidence_path = self.external / "observation-envelope.json"
        evidence_path.write_bytes(envelope)
        os.chmod(evidence_path, 0o600)
        return bundle, envelope

    def _write_sources(self) -> str:
        source_dir = self.repo / "sources"
        source_dir.mkdir()
        question = b"What does the source state?"
        source = b"alpha"
        (source_dir / "question.txt").write_bytes(question)
        (source_dir / "source.txt").write_bytes(source)
        manifest = {
            "bundleId": "source-bundle-1",
            "dataClass": "D1",
            "question": {
                "id": "question",
                "path": "sources/question.txt",
                "mediaType": "text/plain",
                "dataClass": "D1",
                "sha256": hashlib.sha256(question).hexdigest(),
                "byteLength": len(question),
            },
            "sources": [
                {
                    "id": "source-1",
                    "path": "sources/source.txt",
                    "mediaType": "text/plain",
                    "dataClass": "D1",
                    "sha256": hashlib.sha256(source).hexdigest(),
                    "byteLength": len(source),
                }
            ],
        }
        (source_dir / "manifest.json").write_text(
            canonical_json(manifest), encoding="utf-8"
        )
        return "sources/manifest.json"

    def _arguments(self, manifest: str) -> list[str]:
        return [
            "--repo", str(self.repo),
            "team", "run", "source-review",
            "--manifest", manifest,
            "--database", str(self.external / "runtime.sqlite3"),
            "--artifact-store", str(self.external / "artifacts"),
            "--run-id", "run-1",
            "--store-id", "store-1",
            "--created-at", _utc(self.created),
            "--deadline-at", _utc(self.deadline),
            "--json",
        ]

    def _repo_snapshot(self) -> dict[str, tuple[str, int]]:
        return {
            path.relative_to(self.repo).as_posix(): (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                path.stat().st_mode,
            )
            for path in self.repo.rglob("*")
            if path.is_file()
        }

    def test_production_composition_and_restart_have_exactly_five_http_calls(self) -> None:
        manifest = self._write_sources()
        with _Provider() as provider:
            self._write_bundle(provider.endpoint)
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                repository_before = self._repo_snapshot()
                first_stdout = io.StringIO()
                with contextlib.redirect_stdout(first_stdout):
                    first = main(self._arguments(manifest))
                self.assertEqual(first, 0, first_stdout.getvalue())
                first_result = json.loads(first_stdout.getvalue())
                self.assertEqual(first_result["status"], "succeeded")
                self.assertEqual(first_result["code"], "accepted")
                self.assertEqual(len(provider.calls), 5)
                self.assertNotIn("Alpha is supported", first_stdout.getvalue())
                self.assertIsNotNone(first_result["reportArtifact"])

                second_stdout = io.StringIO()
                with contextlib.redirect_stdout(second_stdout):
                    second = main(self._arguments(manifest))
                self.assertEqual(second, 0, second_stdout.getvalue())
                self.assertEqual(len(provider.calls), 5)
                self.assertEqual(
                    json.loads(second_stdout.getvalue())["reportArtifact"],
                    first_result["reportArtifact"],
                )
                self.assertEqual(self._repo_snapshot(), repository_before)

    def test_second_run_with_new_run_id_shares_the_durable_store(self) -> None:
        manifest = self._write_sources()
        with _Provider() as provider:
            self._write_bundle(provider.endpoint)
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                first_stdout = io.StringIO()
                with contextlib.redirect_stdout(first_stdout):
                    first = main(self._arguments(manifest))
                self.assertEqual(first, 0, first_stdout.getvalue())
                self.assertEqual(len(provider.calls), 5)

                arguments = self._arguments(manifest)
                arguments[arguments.index("run-1")] = "run-2"
                second_stdout = io.StringIO()
                with contextlib.redirect_stdout(second_stdout):
                    second = main(arguments)
                self.assertEqual(second, 0, second_stdout.getvalue())
                second_result = json.loads(second_stdout.getvalue())
                self.assertEqual(second_result["status"], "succeeded")
                self.assertFalse(second_result["replayed"])
                self.assertEqual(len(provider.calls), 10)

    def test_evidence_expiring_before_deadline_blocks_before_http_or_state_write(self) -> None:
        manifest = self._write_sources()
        with _Provider() as provider:
            self._write_bundle(
                provider.endpoint,
                authority_deadline=self.created + timedelta(minutes=5),
            )
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(self._arguments(manifest))
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["code"], "ECO_SOURCE_REVIEW_EVIDENCE_WINDOW")
            self.assertEqual(provider.calls, [])
            self.assertFalse((self.external / "runtime.sqlite3").exists())
            self.assertFalse((self.external / "artifacts").exists())

    def test_stale_created_at_blocks_before_http_or_state_write(self) -> None:
        self.created -= timedelta(minutes=10)
        manifest = self._write_sources()
        with _Provider() as provider:
            self._write_bundle(provider.endpoint)
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(self._arguments(manifest))
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())["code"], "ECO_SOURCE_REVIEW_TIME_INVALID")
            self.assertEqual(provider.calls, [])
            self.assertFalse((self.external / "runtime.sqlite3").exists())
            self.assertFalse((self.external / "artifacts").exists())

    def test_package_default_disabled_deployments_fail_closed(self) -> None:
        manifest = self._write_sources()
        bundle = starter_bundle("sample")
        config = self.repo / ".ai"
        config.mkdir()
        for name, document in bundle.items():
            (config / CONFIG_FILES[name]).write_text(dump_yaml(document), encoding="utf-8")
        environment = {
            "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
            "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
        }
        arguments = [*self._arguments(manifest), "--check"]
        with mock.patch.dict(os.environ, environment, clear=False):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(arguments)
        self.assertEqual(code, 1)
        self.assertEqual(
            json.loads(output.getvalue())["code"],
            "ECO_SOURCE_REVIEW_DEPLOYMENT_COUNT",
        )
        self.assertFalse((self.external / "runtime.sqlite3").exists())
        self.assertFalse((self.external / "artifacts").exists())

    def _route_records(self, bundle: dict) -> dict:
        from eco_routing import DeterministicModelRouter
        from eco_routing.contracts import (
            CANONICAL_MODEL_ROLES,
            ROUTING_API_VERSION,
            seal_routing_record,
        )
        from eco_routing.router import DeploymentCandidate

        now = datetime.now(timezone.utc).replace(microsecond=0)
        projected = copy.deepcopy(bundle["deployments"]["deployments"][0])
        projected["retention"] = "no-retention"
        route_candidate = DeploymentCandidate.from_canonical_deployment(projected)

        def sealed(kind: str, identifier: str, spec: dict) -> dict:
            return seal_routing_record(
                {
                    "apiVersion": ROUTING_API_VERSION,
                    "kind": kind,
                    "metadata": {"id": identifier, "createdAt": _utc(now)},
                    "spec": spec,
                }
            )

        routing_policy = seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": "ModelRoutingPolicy",
                "metadata": {
                    "id": "route-policy-1",
                    "createdAt": _utc(now),
                    "revision": 1,
                },
                "spec": {
                    "defaultDecision": "deny",
                    "decisionTtlSeconds": 300,
                    "roles": [
                        {
                            "role": role,
                            "requiredCapabilities": [
                                "model.structured-output",
                                "model.text",
                            ],
                            "allowedActionClasses": ["A0", "A1"],
                            "allowedDataClasses": ["D0", "D1"],
                            "allowedZones": ["Z1"],
                            "allowedRetentions": ["no-retention"],
                            "candidateIds": [route_candidate.deployment_id],
                            "maximumCostMicrousd": 0,
                            "fallback": {
                                "maxRouteAttempts": 1,
                                "retryableFailureClasses": [],
                            },
                        }
                        for role in CANONICAL_MODEL_ROLES
                    ],
                },
            }
        )
        prices = seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": "TrustedPriceCatalog",
                "metadata": {
                    "id": "route-prices-1",
                    "createdAt": _utc(now),
                    "revision": 1,
                },
                "spec": {
                    "authority": "operator",
                    "currency": "microUSD",
                    "validFrom": _utc(now - timedelta(minutes=5)),
                    "validUntil": _utc(now + timedelta(hours=1)),
                    "sourceProvenanceDigest": SUITE_DIGEST,
                    "entries": [
                        {
                            "deploymentId": route_candidate.deployment_id,
                            "deploymentIdentityDigest": route_candidate.identity_digest,
                            "inputMicrousdPerMillionTokens": 0,
                            "outputMicrousdPerMillionTokens": 0,
                            "fixedRequestMicrousd": 0,
                        }
                    ],
                },
            }
        )
        capability_observation = sealed(
            "ObservedModelCapabilities",
            "route-observation-1",
            {
                "authority": "trusted-observation",
                "deploymentId": route_candidate.deployment_id,
                "deploymentIdentityDigest": route_candidate.identity_digest,
                "capabilities": ["model.structured-output", "model.text"],
                "contextWindowTokens": 32768,
                "latencyP95Millis": 50,
                "observedAt": _utc(now - timedelta(minutes=1)),
                "validUntil": _utc(now + timedelta(minutes=30)),
                "evidenceEnvelopeDigest": semantic_digest({"envelope": "route"}),
                "suiteDigest": SUITE_DIGEST,
            },
        )
        request = sealed(
            "ModelRouteRequest",
            "route-request-1",
            {
                "role": "eco-researcher",
                "actionClass": "A0",
                "dataClass": "D1",
                "workloadClass": "research",
                "requiredCapabilities": ["model.structured-output"],
                "requiredContextTokens": 8192,
                "inputTokenCeiling": 1000,
                "outputTokenCeiling": 1000,
                "allowedZones": ["Z1"],
                "allowedRetentions": ["no-retention"],
                "allowCloud": False,
                "maximumCostMicrousd": 0,
                "deadlineAt": _utc(now + timedelta(minutes=15)),
                "executionProfile": "m6.1-local-zero-cost",
                "policyDigest": routing_policy["metadata"]["recordDigest"],
                "contextDigest": semantic_digest({"trustedContext": "route"}),
            },
        )
        outcome = DeterministicModelRouter(routing_policy, prices).route(
            request,
            [route_candidate],
            [capability_observation],
            now=now,
            decision_id="route-decision-1",
            explain_id="route-explain-1",
        )
        decision = outcome.decision
        assert decision["spec"]["decision"] == "allowed", decision["spec"]["reasonCode"]
        return {
            "policy": routing_policy,
            "prices": prices,
            "observation": capability_observation,
            "request": request,
            "decision": decision,
        }

    def _write_route_files(self, decision: dict, request: dict) -> list[str]:
        decision_path = self.root / "route-decision.json"
        request_path = self.root / "route-request.json"
        decision_path.write_text(canonical_json(decision), encoding="utf-8")
        request_path.write_text(canonical_json(request), encoding="utf-8")
        return [
            "--route-decision", str(decision_path),
            "--route-request", str(request_path),
        ]

    def test_route_decision_is_consumed_durably_and_replay_safe(self) -> None:
        manifest = self._write_sources()
        with _Provider() as provider:
            bundle, _envelope = self._write_bundle(provider.endpoint)
            records = self._route_records(bundle)
            decision, request = records["decision"], records["request"]
            route_arguments = self._write_route_files(decision, request)
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                first_stdout = io.StringIO()
                with contextlib.redirect_stdout(first_stdout):
                    first = main([*self._arguments(manifest), *route_arguments])
                self.assertEqual(first, 0, first_stdout.getvalue())
                first_result = json.loads(first_stdout.getvalue())
                self.assertEqual(first_result["status"], "succeeded")
                self.assertFalse(first_result["routeConsumption"]["replayed"])
                self.assertEqual(
                    first_result["routeConsumption"]["routeDigest"],
                    decision["metadata"]["recordDigest"],
                )
                self.assertEqual(len(provider.calls), 5)
                journal_path = self.external / "runtime.sqlite3.routes"
                self.assertTrue(journal_path.exists())

                second_stdout = io.StringIO()
                with contextlib.redirect_stdout(second_stdout):
                    second = main([*self._arguments(manifest), *route_arguments])
                self.assertEqual(second, 0, second_stdout.getvalue())
                second_result = json.loads(second_stdout.getvalue())
                self.assertTrue(second_result["routeConsumption"]["replayed"])
                self.assertEqual(len(provider.calls), 5)

    def test_mismatched_route_blocks_before_http_or_state_write(self) -> None:
        manifest = self._write_sources()
        with _Provider() as provider:
            bundle, _envelope = self._write_bundle(provider.endpoint)
            records = self._route_records(bundle)
            decision, request = records["decision"], records["request"]
            tampered = copy.deepcopy(decision)
            del tampered["metadata"]["recordDigest"]
            tampered["spec"]["selected"]["deploymentIdentityDigest"] = "b" * 64
            from eco_routing.contracts import seal_routing_record

            tampered = seal_routing_record(tampered)
            route_arguments = self._write_route_files(tampered, request)
            environment = {
                "ECO_LOCAL_OPENAI_ENDPOINT": provider.endpoint,
                "ECO_LOCAL_ADAPTER_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_LOCAL_ADAPTER_ENVELOPE_FILE": str(
                    self.external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main([*self._arguments(manifest), *route_arguments])
            self.assertEqual(code, 1)
            self.assertEqual(
                json.loads(output.getvalue())["code"], "ECO_ROUTE_BINDING_MISMATCH"
            )
            self.assertEqual(provider.calls, [])
            self.assertFalse((self.external / "runtime.sqlite3").exists())
            self.assertFalse((self.external / "runtime.sqlite3.routes").exists())

    def test_route_plan_cli_selects_the_governed_deployment(self) -> None:
        with _Provider() as provider:
            bundle, _envelope = self._write_bundle(provider.endpoint)
            deployments_path = self.repo / ".ai" / CONFIG_FILES["deployments"]
            normalized = copy.deepcopy(bundle["deployments"])
            normalized["deployments"][0]["retention"] = "no-retention"
            deployments_path.write_text(dump_yaml(normalized), encoding="utf-8")
            records = self._route_records(bundle)
            paths = {}
            for name in ("policy", "prices", "request", "observation"):
                paths[name] = self.root / f"plan-{name}.json"
                paths[name].write_text(
                    canonical_json(records[name]), encoding="utf-8"
                )
            arguments = [
                "--repo", str(self.repo),
                "route", "plan",
                "--policy", str(paths["policy"]),
                "--prices", str(paths["prices"]),
                "--request", str(paths["request"]),
                "--observation", str(paths["observation"]),
                "--json",
            ]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(arguments)
            self.assertEqual(code, 0, stdout.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["decision"]["spec"]["decision"], "allowed")
            self.assertEqual(
                result["decision"]["spec"]["selected"]["deploymentId"],
                "local-source-review",
            )


if __name__ == "__main__":
    unittest.main()
