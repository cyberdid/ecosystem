from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from eco_cli.templates import starter_bundle
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.evidence import (
    EvidenceIssuerPolicy,
    EvidenceTrustStore,
    HmacEvidenceSigner,
    TrustedEvidenceIngestor,
)
from eco_runtime.evaluation import (
    CrossDeploymentEvaluationRunner,
    EvaluationCase,
    EvaluationEvidenceSigner,
    EvaluationSuite,
    PinnedEvaluationDeployment,
    UsageTolerance,
    normalized_output_digest,
)
from eco_runtime.live_evaluation import (
    ClaudeCliEvaluationAdapter,
    OllamaEvaluationAdapter,
    executable_sha256,
)
from eco_runtime.policy import PolicyEngine


PROMPT = (
    "You are a deterministic conformance probe. Output the exact ASCII token READY and "
    "nothing else. Do not add punctuation, whitespace, or explanation."
)
CASE_ID = "text-basic"
OBSERVATION_KEY_DOMAIN = b"eco-m2-live-observation-signing-v1"
PUBLICATION_KEY_DOMAIN = b"eco-m2-live-publication-signing-v1"
PUBLICATION_AUTH_DOMAIN = "eco-m2-live-publication-authentication-v1"


def _deployment(
    *,
    identifier: str,
    provider: str,
    adapter: str,
    model: str,
    endpoint_ref: str,
    zone: str,
    adapter_version: str,
    model_revision: str,
    runtime_engine: str,
    runtime_version: str,
    quantization: str,
) -> dict:
    return {
        "id": identifier,
        "provider": provider,
        "adapter": adapter,
        "model": model,
        "endpointRef": endpoint_ref,
        "zone": zone,
        "allowedDataClasses": ["D0"],
        "artifactTrust": "P1",
        "declaredCapabilities": ["model.text"],
        "retention": (
            "local-runtime-dependent" if zone == "Z1" else "provider-subscription-policy"
        ),
        "trainingUse": "prohibited" if zone == "Z1" else "unknown",
        "region": "local" if zone == "Z1" else "provider-managed",
        "identity": {
            "adapterVersion": adapter_version,
            "modelRevision": model_revision,
            "runtimeEngine": runtime_engine,
            "runtimeVersion": runtime_version,
            "quantization": quantization,
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
        "enabled": False,
    }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _publish_documents(output: Path, documents: Mapping[Path, bytes]) -> None:
    """Publish one complete evidence tree without replacing an earlier run."""

    if not documents:
        raise ValueError("live evidence publication cannot be empty")
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    lock_path = output.parent / f".{output.name}.publish.lock"
    try:
        lock_descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise FileExistsError("live evidence publication is already in progress") from exc
    stage: Path | None = None
    try:
        os.close(lock_descriptor)
        if output.exists():
            raise FileExistsError("live evidence output already exists")
        stage = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
        )
        directories = {stage}
        for relative_path, value in documents.items():
            if (
                not isinstance(relative_path, Path)
                or relative_path.is_absolute()
                or not relative_path.parts
                or any(part in {"", ".", ".."} for part in relative_path.parts)
                or not isinstance(value, bytes)
            ):
                raise ValueError("live evidence document path or payload is invalid")
            destination = stage / relative_path
            _write_bytes(destination, value)
            directories.update(destination.parents)
        for directory in sorted(
            (item for item in directories if item == stage or stage in item.parents),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _rename_directory_noreplace(stage, output)
        stage = None
        _fsync_directory(output.parent)
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
        _fsync_directory(output.parent)


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without ever replacing a race winner."""

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise RuntimeError("atomic no-replace publication is unsupported")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError("live evidence output already exists")
        raise OSError(error, "atomic evidence publication failed")
    if os.name == "nt":
        try:
            os.rename(source, destination)
        except FileExistsError:
            raise FileExistsError("live evidence output already exists") from None
        return
    raise RuntimeError("atomic no-replace publication is unsupported on this platform")


def _trusted_observation_documents(
    observations: tuple[dict, ...],
    *,
    signing_key: bytes,
    key_id: str,
    issuer_id: str,
) -> dict[Path, bytes]:
    """Prepare independently ingestible observation envelopes for a future policy gate."""

    signer = HmacEvidenceSigner(issuer_id, key_id, signing_key)
    documents: dict[Path, bytes] = {}
    for observation in observations:
        tested_at = datetime.fromisoformat(
            observation["metadata"]["testedAt"].replace("Z", "+00:00")
        )
        valid_until = datetime.fromisoformat(
            observation["metadata"]["validUntil"].replace("Z", "+00:00")
        )
        deployment_id = observation["metadata"]["deploymentId"]
        documents[
            Path("trusted-observations") / f"{deployment_id}.envelope.json"
        ] = signer.sign(
            observation,
            envelope_id=f"trusted-{observation['metadata']['id']}",
            issued_at=tested_at,
            expires_at=valid_until,
        )
    return documents


def _observation_signing_key(signing_key: bytes) -> bytes:
    return hmac.new(signing_key, OBSERVATION_KEY_DOMAIN, hashlib.sha256).digest()


def _publication_manifest_document(
    documents: Mapping[Path, bytes],
    *,
    signing_key: bytes,
    key_id: str,
    evaluated_at: datetime,
) -> bytes:
    publication_key = hmac.new(signing_key, PUBLICATION_KEY_DOMAIN, hashlib.sha256).digest()
    payload = {
        "domain": PUBLICATION_AUTH_DOMAIN,
        "version": "1",
        "evaluatedAt": evaluated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": [
            {
                "path": path.as_posix(),
                "byteLength": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }
            for path, value in sorted(documents.items(), key=lambda item: item[0].as_posix())
        ],
    }
    authentication = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _json_bytes(
        {
            "manifest": payload,
            "manifestDigest": semantic_digest(payload),
            "signature": {
                "algorithm": "HMAC-SHA256",
                "keyId": key_id,
                "value": hmac.new(publication_key, authentication, hashlib.sha256).hexdigest(),
            },
        }
    )


def _policy_gate_documents(
    *,
    deployments: tuple[dict, ...],
    observations: tuple[dict, ...],
    trusted_documents: Mapping[Path, bytes],
    observation_key: bytes,
    key_id: str,
    issuer_id: str,
    suite_digest: str,
    evaluated_at: datetime,
    evaluation_evidence_digest: str,
) -> dict[Path, bytes]:
    """Cryptographically ingest every observation and allow-plan the local D0 route."""

    deployment_by_id = {item["id"]: item for item in deployments}
    deployment_ids = frozenset(deployment_by_id)
    trust_policy = EvidenceIssuerPolicy(
        issuer_id=issuer_id,
        key_id=key_id,
        verification_key=observation_key,
        allowed_kinds=frozenset({"AdapterConformanceProfile"}),
        allowed_deployments=deployment_ids,
        allowed_suite_digests=frozenset({suite_digest}),
    )
    ingestor = TrustedEvidenceIngestor(EvidenceTrustStore((trust_policy,)))
    verified_receipts = []
    envelope_by_deployment: dict[str, bytes] = {}
    for observation in observations:
        deployment_id = observation["metadata"]["deploymentId"]
        deployment = deployment_by_id[deployment_id]
        path = Path("trusted-observations") / f"{deployment_id}.envelope.json"
        encoded = trusted_documents[path]
        verified = ingestor.ingest_observed_capabilities(
            encoded,
            expected_deployment_id=deployment_id,
            expected_deployment_identity_digest=deployment_identity_digest(deployment),
            trusted_suite_digests=frozenset({suite_digest}),
            now=evaluated_at,
        )
        if semantic_digest(verified.as_dict()) != semantic_digest(observation):
            raise RuntimeError("Trusted observation changed during verification")
        envelope_by_deployment[deployment_id] = encoded
        verified_receipts.append(
            {
                "deploymentId": deployment_id,
                "deploymentIdentityDigest": deployment_identity_digest(deployment),
                "observationDigest": semantic_digest(observation),
                "evidence": verified.provenance.as_dict(),
            }
        )

    local_candidates = [item for item in deployments if item["zone"] == "Z1"]
    if len(local_candidates) != 1:
        raise RuntimeError("Policy gate requires exactly one local deployment")
    local = copy.deepcopy(local_candidates[0])
    local["enabled"] = True
    local["observedCapabilitiesRef"] = (
        f"trusted-observations/{local['id']}.envelope.json"
    )
    bundle = starter_bundle("m2-live-policy-gate")
    bundle["deployments"]["deployments"] = [local]
    bundle["deployments"]["logicalRoles"]["code.read"]["candidates"] = [local["id"]]
    artifact_ref = "artifact://m2-live/instruction"
    run_id = "m2-live-policy-gate-run"
    timestamp = evaluated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    prompt_bytes = PROMPT.encode("utf-8")
    artifact = {
        "apiVersion": API_VERSION,
        "kind": "ArtifactRecord",
        "metadata": {"id": "m2-live-instruction", "runId": run_id, "createdAt": timestamp},
        "spec": {
            "role": "input",
            "mediaType": "text/plain",
            "byteLength": len(prompt_bytes),
            "sha256": hashlib.sha256(prompt_bytes).hexdigest(),
            "dataClass": "D0",
            "trust": "P1",
            "producer": {"type": "runtime", "id": "m2-live-evaluation-runner"},
            "storageRef": artifact_ref,
            "retention": "ephemeral",
        },
    }
    request = {
        "apiVersion": API_VERSION,
        "kind": "RunRequest",
        "metadata": {
            "id": "m2-live-policy-gate-request",
            "createdAt": timestamp,
            "actor": {"type": "automation", "id": "m2-live-evaluation-runner"},
        },
        "spec": {
            "projectId": "m2-live-policy-gate",
            "logicalRole": "code.read",
            "dataClass": "D0",
            "classificationAuthority": "project-policy",
            "deploymentPin": local["id"],
            "task": {"type": "conformance", "instructionRef": artifact_ref, "inputRefs": []},
            "requestedTools": [],
            "constraints": {
                "maximumActionClass": "A0",
                "sandbox": "inspect",
                "agentNetwork": "deny",
                "toolNetwork": "deny",
            },
            "budget": {
                "maxDurationSeconds": 120,
                "maxModelRequests": 1,
                "maxToolRequests": 0,
                "maxInputBytes": 4096,
                "maxOutputBytes": 4096,
                "maxTotalTokens": 20000,
                "maxCostMicrousd": 0,
            },
            "fallbackPolicy": "none",
        },
    }
    engine = PolicyEngine(
        bundle,
        {local["id"]: envelope_by_deployment[local["id"]]},
        {artifact_ref: artifact},
        evidence_policies=(trust_policy,),
        evidence_now=evaluated_at,
        trusted_suite_digests={suite_digest},
    )
    result = engine.plan_run(
        request,
        run_id=run_id,
        plan_id="m2-live-policy-gate-plan",
        decision_id="m2-live-policy-gate-decision",
        now=evaluated_at,
    )
    if result.plan is None or result.decision["spec"]["effect"] != "allow":
        raise RuntimeError("Trusted local observation did not pass the PolicyEngine gate")
    plan_provenance = result.plan["spec"]["route"]["observedCapabilitiesEvidence"]
    if plan_provenance["envelopeDigest"] != hashlib.sha256(
        envelope_by_deployment[local["id"]]
    ).hexdigest():
        raise RuntimeError("Policy plan is not bound to the trusted observation envelope")

    trust_receipt = {
        "status": "pass",
        "issuerId": issuer_id,
        "keyId": key_id,
        "verificationKeyFingerprint": hashlib.sha256(observation_key).hexdigest(),
        "allowedKinds": ["AdapterConformanceProfile"],
        "allowedDeployments": sorted(deployment_ids),
        "allowedSuiteDigests": [suite_digest],
        "verifiedAt": timestamp,
        "evaluationEvidenceDigest": evaluation_evidence_digest,
        "observations": sorted(verified_receipts, key=lambda item: item["deploymentId"]),
    }
    gate_receipt = {
        "status": "pass",
        "deploymentId": local["id"],
        "deploymentIdentityDigest": deployment_identity_digest(local),
        "evaluationEvidenceDigest": evaluation_evidence_digest,
        "runRequestDigest": semantic_digest(request),
        "planDigest": semantic_digest(result.plan),
        "decisionDigest": semantic_digest(result.decision),
        "observationEvidence": plan_provenance,
        "verifiedAt": timestamp,
    }
    return {
        Path("trust-policy-receipt.json"): _json_bytes(trust_receipt),
        Path("policy-gate-receipt.json"): _json_bytes(gate_receipt),
        Path("policy-gate/run-request.json"): _json_bytes(request),
        Path("policy-gate/run-plan.json"): _json_bytes(result.plan),
        Path("policy-gate/policy-decision.json"): _json_bytes(result.decision),
    }


def _verified_executable_digest(executable: str, expected_digest: str) -> str:
    actual_digest = executable_sha256(executable)
    if (
        len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
        or not hmac.compare_digest(actual_digest, expected_digest)
    ):
        raise ValueError("Provider executable does not match the expected SHA-256 digest")
    return actual_digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the M2 local/cloud conformance probe")
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--signing-key-file", required=True, type=Path)
    parser.add_argument("--signing-key-id", default="m2-live-evaluation-key-1")
    parser.add_argument(
        "--trusted-observation-issuer-id", default="m2-live-evaluation-runner"
    )
    parser.add_argument("--ollama-model", default="qwen3:0.6b")
    parser.add_argument("--ollama-version", required=True)
    parser.add_argument("--ollama-manifest-digest", required=True)
    parser.add_argument("--claude-executable", required=True)
    parser.add_argument("--claude-version", required=True)
    parser.add_argument("--claude-executable-digest", required=True)
    parser.add_argument("--claude-model", default="claude-sonnet-5")
    args = parser.parse_args()

    signing_key = args.signing_key_file.read_bytes()
    if len(signing_key) < 32:
        raise SystemExit("signing key must contain at least 32 bytes")
    try:
        actual_claude_digest = _verified_executable_digest(
            args.claude_executable, args.claude_executable_digest
        )
    except (ValueError, RuntimeError):
        raise SystemExit(
            "Claude CLI executable does not match the expected SHA-256 digest"
        ) from None
    evaluated_at = datetime.now(timezone.utc)

    local = _deployment(
        identifier="local-ollama-qwen3-0.6b",
        provider="local",
        adapter="ollama-evaluation",
        model=args.ollama_model,
        endpoint_ref="config:ollama-loopback-qwen3-0.6b",
        zone="Z1",
        adapter_version="ollama-eval-v1",
        model_revision=f"sha256:{args.ollama_manifest_digest}",
        runtime_engine="ollama",
        runtime_version=args.ollama_version,
        quantization="manifest-pinned",
    )
    cloud = _deployment(
        identifier="cloud-claude-sonnet-5",
        provider="anthropic",
        adapter="provider-cli-evaluation",
        model=args.claude_model,
        endpoint_ref="config:claude-cli-broker",
        zone="Z3",
        adapter_version="claude-cli-eval-v1",
        model_revision=f"provider-alias:{args.claude_model}",
        runtime_engine="claude-code-cli",
        runtime_version=f"{args.claude_version}+sha256:{actual_claude_digest}",
        quantization="provider-managed",
    )
    local_digest = deployment_identity_digest(local)
    cloud_digest = deployment_identity_digest(cloud)
    deployments = (
        PinnedEvaluationDeployment(local["id"], local_digest, "ollama-eval-v1"),
        PinnedEvaluationDeployment(cloud["id"], cloud_digest, "claude-cli-eval-v1"),
    )
    adapters = {
        local["id"]: OllamaEvaluationAdapter(
            local["id"],
            "ollama-eval-v1",
            local_digest,
            args.ollama_model,
            args.ollama_manifest_digest,
        ),
        cloud["id"]: ClaudeCliEvaluationAdapter(
            cloud["id"],
            "claude-cli-eval-v1",
            cloud_digest,
            args.claude_model,
            args.claude_executable,
            actual_claude_digest,
        ),
    }
    suite = EvaluationSuite(
        "m2-live-local-cloud",
        "1.0.0",
        (
            EvaluationCase(
                CASE_ID,
                PROMPT,
                normalized_output_digest("READY"),
                UsageTolerance(
                    input_tokens=20_000,
                    output_tokens=32,
                    total_tokens=20_000,
                ),
            ),
        ),
    )
    signer = EvaluationEvidenceSigner(key=signing_key, key_id=args.signing_key_id)
    run = CrossDeploymentEvaluationRunner(
        signer=signer,
        timeout_seconds=90,
        max_output_bytes=4_096,
    ).run(suite, deployments, adapters, evaluated_at=evaluated_at)
    signer.verify(run.evidence, observations=run.observations)

    summary = {
        "status": run.evidence.payload["status"],
        "suiteDigest": suite.digest,
        "evidenceDigest": run.evidence.digest,
        "evaluatedAt": run.evidence.payload["evaluatedAt"],
        "deploymentIds": sorted(adapters),
    }
    documents = {
        Path("deployment-identities.json"): _json_bytes({
            "suite": suite.reference(),
            "deployments": [
                {"record": local, "identityDigest": local_digest},
                {"record": cloud, "identityDigest": cloud_digest},
            ],
        }),
        Path("signed-evidence.json"): _json_bytes(run.evidence.as_dict()),
        Path("summary.json"): _json_bytes(summary),
    }
    for observation in run.observations:
        documents[
            Path("observations") / f"{observation['metadata']['deploymentId']}.json"
        ] = _json_bytes(observation)
    observation_key = _observation_signing_key(signing_key)
    trusted_documents = _trusted_observation_documents(
        run.observations,
        signing_key=observation_key,
        key_id=args.signing_key_id,
        issuer_id=args.trusted_observation_issuer_id,
    )
    documents.update(trusted_documents)
    documents.update(
        _policy_gate_documents(
            deployments=(local, cloud),
            observations=run.observations,
            trusted_documents=trusted_documents,
            observation_key=observation_key,
            key_id=args.signing_key_id,
            issuer_id=args.trusted_observation_issuer_id,
            suite_digest=suite.digest,
            evaluated_at=evaluated_at,
            evaluation_evidence_digest=run.evidence.digest,
        )
    )
    documents[Path("publication-manifest.json")] = _publication_manifest_document(
        documents,
        signing_key=signing_key,
        key_id=args.signing_key_id,
        evaluated_at=evaluated_at,
    )
    _publish_documents(args.output_directory, documents)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
