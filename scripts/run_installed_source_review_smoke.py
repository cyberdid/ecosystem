#!/usr/bin/env python3
"""Run one synthetic five-role source review against literal loopback only.

The script is intentionally independent of ``tests/`` so an installed wheel can
be exercised from a source checkout without importing test helpers.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_cli.cli import main as eco_main
from eco_cli.config import dump_yaml
from eco_cli.constants import CONFIG_FILES
from eco_cli.source_review import _SOURCE_LIMITS, source_review_route_contract
from eco_cli.templates import starter_bundle
from eco_orchestration.source_bundle import (
    load_source_bundle_manifest,
    verify_source_bundle_files,
)
from eco_routing import (
    CANONICAL_MODEL_ROLES,
    ROUTING_API_VERSION,
    DeploymentCandidate,
    DeterministicModelRouter,
    Ed25519RouteAuthoritySigner,
    seal_routing_record,
)
from eco_runtime.adapters import ADAPTER_VERSION
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import canonical_json, deployment_identity_digest, semantic_digest
from eco_runtime.evidence import HmacEvidenceSigner


EVIDENCE_KEY = "installed-evidence-key-32-bytes!!"
HMAC_KEY = "installed-runtime-key-32-bytes!!!"
PROOF_KEY = "installed-proof-key-32-bytes!!!!!"
SUITE_DIGEST = "a" * 64
PRIVATE_SENTINEL = "installed-source-review-private-sentinel"
ROUTE_PRIVATE_KEY = b"r" * 32
ROUTE_PUBLIC_KEY_ENV = "ECO_INSTALLED_SMOKE_ROUTE_PUBLIC_KEY"


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _role_output(schema: dict[str, Any]) -> dict[str, Any]:
    properties = set(schema.get("properties", {}))
    if "objective" in properties:
        return {
            "objective": "Answer the bounded synthetic question",
            "analysisQuestions": ["What does the synthetic source state?"],
            "sourceEntryIds": ["question", "source-1"],
            "uncertainty": "low",
            "openQuestions": [],
        }
    if "claims" in properties:
        return {
            "claims": [
                {
                    "id": "claim-1",
                    "statement": "The synthetic source states alpha.",
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
            "report": "Alpha is supported by the supplied synthetic source.",
            "claimIds": ["claim-1"],
            "unsupportedClaimIds": [],
            "uncertainty": "low",
            "openQuestions": [],
        }
    if "verdict" in properties:
        return {"verdict": "accepted", "findings": [], "reviewedClaimIds": ["claim-1"]}
    raise RuntimeError("installed smoke received an unknown role schema")


class _LoopbackProvider:
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
                        "id": f"installed-provider-{len(owner.calls)}",
                        "model": "installed-fixture-model",
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
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_: object) -> None:
                return

        self.calls: list[dict[str, Any]] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_LoopbackProvider":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1/chat/completions"


def _snapshot(repository: Path) -> tuple[tuple[str, str, int], ...]:
    return tuple(
        sorted(
            (
                path.relative_to(repository).as_posix(),
                hashlib.sha256(path.read_bytes()).hexdigest(),
                path.stat().st_mtime_ns,
            )
            for path in repository.rglob("*")
            if path.is_file()
        )
    )


def _control_plane_files(external: Path) -> tuple[Path, ...]:
    """Return durable runtime/control files, excluding private artifact payloads."""

    artifact_root = external / "artifacts"
    files: list[Path] = []
    for path in external.rglob("*"):
        if not path.is_file():
            continue
        try:
            path.relative_to(artifact_root)
        except ValueError:
            files.append(path)
    return tuple(sorted(files, key=lambda item: item.as_posix()))


def _write_fixture(
    repository: Path,
    external: Path,
    endpoint: str,
    *,
    created: datetime,
    deadline: datetime,
) -> tuple[str, list[str], str]:
    bundle = starter_bundle("installed-smoke")
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
    endpoint_ref = "env:ECO_INSTALLED_SMOKE_ENDPOINT"
    deployment = {
        "id": "installed-source-review",
        "provider": "local",
        "adapter": "openai-compatible",
        "model": "installed-fixture-model",
        "endpointRef": endpoint_ref,
        "zone": "Z1",
        "allowedDataClasses": ["D0", "D1"],
        "artifactTrust": "P1",
        "declaredCapabilities": ["model.text", "model.structured-output"],
        "observedCapabilitiesRef": "evals/observed/installed-source-review.json",
        "retention": "test-no-store",
        "trainingUse": "prohibited",
        "region": "local",
        "identity": {
            "adapterVersion": ADAPTER_VERSION,
            "modelRevision": "installed-fixture-revision-1",
            "runtimeEngine": "installed-scripted-loopback",
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
        "id": "installed-eval-authority",
        "keyId": "installed-eval-v1",
        "verificationKeyRef": "env:ECO_INSTALLED_SMOKE_EVIDENCE_KEY",
        "allowedKinds": ["RepositorySnapshot", "AdapterConformanceProfile"],
        "allowedProjects": ["installed-smoke"],
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
                "envelopeRef": "env:ECO_INSTALLED_SMOKE_ENVELOPE_FILE",
            }
        ],
    }
    public_key = Ed25519PrivateKey.from_private_bytes(
        ROUTE_PRIVATE_KEY
    ).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    bundle["trust"]["routeAuthority"] = {
        "issuerId": "installed-route-authority",
        "keyId": "installed-route-v1",
        "algorithm": "ed25519",
        "publicKeyRef": f"env:{ROUTE_PUBLIC_KEY_ENV}",
    }
    observation = {
        "apiVersion": API_VERSION,
        "kind": "AdapterConformanceProfile",
        "metadata": {
            "id": "installed-source-review-observation",
            "deploymentId": deployment["id"],
            "testedAt": _utc(created - timedelta(minutes=1)),
            "validUntil": _utc(deadline + timedelta(minutes=5)),
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
                    "id": probe,
                    "status": "pass",
                    "attempts": 1,
                    "successes": 1,
                    "evidenceDigest": SUITE_DIGEST,
                }
                for probe in ("text-basic", "structured-output-strict")
            ],
            "deviationCodes": [],
        },
    }
    envelope = HmacEvidenceSigner(
        issuer["id"], issuer["keyId"], EVIDENCE_KEY.encode("utf-8")
    ).sign(
        observation,
        envelope_id="installed-source-review-envelope",
        issued_at=created - timedelta(minutes=1),
        expires_at=deadline + timedelta(minutes=5),
        attestation={
            "projectId": "installed-smoke",
            "endpointRef": endpoint_ref,
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
            "resolvedEndpointDigest": semantic_digest({"endpointUrl": endpoint}),
            "requestedModel": deployment["model"],
            "reportedModels": [deployment["model"]],
        },
    )
    config = repository / ".ai"
    config.mkdir()
    for name, document in bundle.items():
        (config / CONFIG_FILES[name]).write_text(dump_yaml(document), encoding="utf-8")
    observed = config / "evals" / "observed"
    observed.mkdir(parents=True)
    (observed / "installed-source-review.json").write_text(
        canonical_json(observation), encoding="utf-8"
    )
    envelope_path = external / "observation-envelope.json"
    envelope_path.write_bytes(envelope)
    os.chmod(envelope_path, 0o600)

    sources = repository / "sources"
    sources.mkdir()
    question = b"What does the synthetic source state?"
    source = f"alpha {PRIVATE_SENTINEL}".encode("utf-8")
    (sources / "question.txt").write_bytes(question)
    (sources / "source.txt").write_bytes(source)
    manifest = {
        "bundleId": "installed-source-bundle-1",
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
    (sources / "manifest.json").write_text(canonical_json(manifest), encoding="utf-8")
    manifest_path = "sources/manifest.json"
    route_arguments = _write_route_records(
        repository,
        external,
        bundle,
        manifest_path,
        created=created,
        deadline=deadline,
    )
    return manifest_path, route_arguments, public_key.hex()


def _write_route_records(
    repository: Path,
    external: Path,
    bundle: dict[str, Any],
    manifest_path: str,
    *,
    created: datetime,
    deadline: datetime,
) -> list[str]:
    """Create all five exact-route inputs consumed by source-review."""

    now = created
    projected = copy.deepcopy(bundle["deployments"]["deployments"][0])
    projected["retention"] = "no-retention"
    candidate = DeploymentCandidate.from_canonical_deployment(projected)

    def sealed(kind: str, identifier: str, spec: dict[str, Any]) -> dict[str, Any]:
        return seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": kind,
                "metadata": {"id": identifier, "createdAt": _utc(now)},
                "spec": spec,
            }
        )

    policy = seal_routing_record(
        {
            "apiVersion": ROUTING_API_VERSION,
            "kind": "ModelRoutingPolicy",
            "metadata": {
                "id": "installed-route-policy-1",
                "createdAt": _utc(now),
                "revision": 1,
            },
            "spec": {
                "defaultDecision": "deny",
                "decisionTtlSeconds": 3600,
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
                        "candidateIds": [candidate.deployment_id],
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
                "id": "installed-route-prices-1",
                "createdAt": _utc(now),
                "revision": 1,
            },
            "spec": {
                "authority": "operator",
                "currency": "microUSD",
                "validFrom": _utc(now - timedelta(minutes=5)),
                "validUntil": _utc(deadline + timedelta(minutes=5)),
                "sourceProvenanceDigest": SUITE_DIGEST,
                "entries": [
                    {
                        "deploymentId": candidate.deployment_id,
                        "deploymentIdentityDigest": candidate.identity_digest,
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
        "installed-route-observation-1",
        {
            "authority": "trusted-observation",
            "deploymentId": candidate.deployment_id,
            "deploymentIdentityDigest": candidate.identity_digest,
            "capabilities": ["model.structured-output", "model.text"],
            "contextWindowTokens": 32768,
            "latencyP95Millis": 50,
            "observedAt": _utc(now - timedelta(minutes=1)),
            "validUntil": _utc(deadline + timedelta(minutes=5)),
            "evidenceEnvelopeDigest": semantic_digest({"envelope": "installed-route"}),
            "suiteDigest": SUITE_DIGEST,
        },
    )
    manifest = load_source_bundle_manifest(
        repository, manifest_path, limits=_SOURCE_LIMITS
    )
    source_verification = verify_source_bundle_files(
        repository, manifest, limits=_SOURCE_LIMITS
    )
    contract = source_review_route_contract(
        project_id="installed-smoke",
        team_id="research-team",
        run_id="installed-run-1",
        store_id="installed-store-1",
        created_at=_utc(created),
        deadline_at=_utc(deadline),
        manifest=manifest,
        source_verification=source_verification,
        deployment=bundle["deployments"]["deployments"][0],
        policy_digest=policy["metadata"]["recordDigest"],
    )
    request = sealed(
        "ModelRouteRequest",
        "installed-route-request-1",
        contract["requestSpec"],
    )
    outcome = DeterministicModelRouter(policy, prices).route(
        request,
        [candidate],
        [capability_observation],
        now=now,
        decision_id="installed-route-decision-1",
        explain_id="installed-route-explain-1",
    )
    if outcome.decision["spec"]["decision"] != "allowed":
        raise RuntimeError(
            "installed source-review route was denied: "
            f"{outcome.decision['spec']['reasonCode']}"
        )
    authority = Ed25519RouteAuthoritySigner(
        "installed-route-authority",
        "installed-route-v1",
        ROUTE_PRIVATE_KEY,
    ).sign(
        outcome.decision,
        request,
        envelope_id="installed-route-envelope-1",
        issued_at=now,
        expires_at=deadline,
    )
    records: tuple[tuple[str, str, bytes], ...] = (
        ("--route-decision", "route-decision.json", canonical_json(outcome.decision).encode()),
        ("--route-request", "route-request.json", canonical_json(request).encode()),
        ("--route-policy", "route-policy.json", canonical_json(policy).encode()),
        ("--route-prices", "route-prices.json", canonical_json(prices).encode()),
        ("--route-authority", "route-authority.json", authority),
    )
    arguments: list[str] = []
    for option, filename, content in records:
        path = external / filename
        path.write_bytes(content)
        arguments.extend((option, str(path)))
    return arguments


def run() -> dict[str, Any]:
    created = datetime.now(timezone.utc).replace(microsecond=0)
    deadline = created + timedelta(minutes=20)
    with tempfile.TemporaryDirectory(prefix="eco-installed-source-review-") as temporary:
        root = Path(temporary)
        repository = root / "repo"
        external = root / "external"
        repository.mkdir()
        external.mkdir(mode=0o700)
        os.chmod(external, 0o700)
        with _LoopbackProvider() as provider:
            manifest, route_arguments, route_public_key = _write_fixture(
                repository,
                external,
                provider.endpoint,
                created=created,
                deadline=deadline,
            )
            before = _snapshot(repository)
            environment = {
                "ECO_INSTALLED_SMOKE_ENDPOINT": provider.endpoint,
                "ECO_INSTALLED_SMOKE_EVIDENCE_KEY": EVIDENCE_KEY,
                "ECO_INSTALLED_SMOKE_ENVELOPE_FILE": str(
                    external / "observation-envelope.json"
                ),
                "ECO_SOURCE_REVIEW_HMAC_KEY": HMAC_KEY,
                "ECO_SOURCE_REVIEW_PROOF_KEY": PROOF_KEY,
                ROUTE_PUBLIC_KEY_ENV: route_public_key,
                "HTTP_PROXY": "http://203.0.113.1:9",
                "HTTPS_PROXY": "http://203.0.113.1:9",
                "NO_PROXY": "",
            }
            previous = {name: os.environ.get(name) for name in environment}
            os.environ.update(environment)
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):
                    code = eco_main(
                        [
                            "--repo",
                            str(repository),
                            "team",
                            "run",
                            "source-review",
                            "--manifest",
                            manifest,
                            "--database",
                            str(external / "runtime.sqlite3"),
                            "--artifact-store",
                            str(external / "artifacts"),
                            "--run-id",
                            "installed-run-1",
                            "--store-id",
                            "installed-store-1",
                            "--created-at",
                            _utc(created),
                            "--deadline-at",
                            _utc(deadline),
                            *route_arguments,
                            "--json",
                        ]
                    )
            finally:
                for name, value in previous.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            result = json.loads(output.getvalue())
            if code != 0 or result.get("status") != "succeeded":
                raise RuntimeError(f"installed source-review smoke failed: {result.get('code')}")
            if len(provider.calls) != 5:
                raise RuntimeError("installed source-review did not execute exactly five roles")
            route_consumption = result.get("routeConsumption")
            route_usage = result.get("routeUsage")
            if (
                not isinstance(route_consumption, dict)
                or route_consumption.get("replayed") is not False
            ):
                raise RuntimeError("installed source-review did not consume its exact route")
            if not isinstance(route_usage, dict) or route_usage.get("entries") != 5:
                raise RuntimeError("installed source-review did not reserve all five route effects")
            if PRIVATE_SENTINEL in output.getvalue():
                raise RuntimeError("installed source-review leaked private source content")
            control_plane_files = _control_plane_files(external)
            if not control_plane_files:
                raise RuntimeError("installed source-review produced no control-plane evidence")
            private_bytes = PRIVATE_SENTINEL.encode("utf-8")
            if any(private_bytes in path.read_bytes() for path in control_plane_files):
                raise RuntimeError(
                    "installed source-review leaked private source content into control-plane state"
                )
            if _snapshot(repository) != before:
                raise RuntimeError("installed source-review mutated repository bytes or mtimes")
            return {
                "available": True,
                "operation": "installed-source-review-smoke",
                "status": "pass",
                "provider": "literal-loopback-scripted",
                "externalNetwork": False,
                "roleCalls": len(provider.calls),
                "routeConsumptionEntries": 1,
                "routeUsageEntries": route_usage["entries"],
                "controlPlaneFilesScanned": len(control_plane_files),
                "repositoryIdentity": "bytes-and-mtime-unchanged",
                "privateSentinel": "absent-from-output-and-control-plane",
            }


def main() -> int:
    try:
        report = run()
    except Exception as exc:
        print(
            json.dumps(
                {
                    "available": False,
                    "operation": "installed-source-review-smoke",
                    "status": "blocked",
                    "reason": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
