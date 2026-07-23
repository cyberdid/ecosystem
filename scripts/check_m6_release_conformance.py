#!/usr/bin/env python3
"""Deterministic local M6 release-conformance check.

The check proves that initializing and authenticating the new private route
journals neither serializes their HMAC key nor mutates bytes/mtimes of tracked
repository files.  It deliberately emits only counts and digests.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from eco_cli.cli import main as eco_main
from eco_routing import (
    CANONICAL_MODEL_ROLES,
    ROUTING_API_VERSION,
    DeploymentCandidate,
    DeterministicModelRouter,
    DurableRouteConsumptionJournal,
    DurableRouteUsageJournal,
    route_consumer_digest,
    route_execution_plan_digest,
    seal_routing_record,
)
from eco_runtime.digests import semantic_digest


_SECRET_SENTINEL = b"m6-release-journal-secret-sentinel-2026"
_CONTENT_SENTINEL = "m6-release-private-content-sentinel-2026"
_WORKFLOW_EFFECT_DIGEST = "e" * 64


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _route_fixture(now: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    endpoint_ref = "env:ECO_RELEASE_CONFORMANCE_ENDPOINT"
    deployment = {
        "id": "release-local",
        "provider": "local",
        "adapter": "openai-compatible",
        "model": "release-fixture-model",
        "endpointRef": endpoint_ref,
        "zone": "Z1",
        "allowedDataClasses": ["D0", "D1"],
        "artifactTrust": "P2",
        "declaredCapabilities": ["model.text", "model.structured-output"],
        "observedCapabilitiesRef": "evals/observed/release-local.json",
        "retention": "local-runtime-dependent",
        "trainingUse": "prohibited",
        "region": "local",
        "identity": {
            "adapterVersion": "openai-compatible-v1",
            "modelRevision": "release-fixture-revision-1",
            "runtimeEngine": "release-conformance",
            "runtimeVersion": "1.0.0",
            "quantization": "none",
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
        "enabled": True,
    }
    candidate = DeploymentCandidate.from_canonical_deployment(deployment)

    def sealed(
        kind: str,
        identifier: str,
        spec: dict[str, Any],
        *,
        revision: int | None = None,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {"id": identifier, "createdAt": _utc(now)}
        if revision is not None:
            metadata["revision"] = revision
        return seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": kind,
                "metadata": metadata,
                "spec": spec,
            }
        )

    policy = sealed(
        "ModelRoutingPolicy",
        "release-policy-1",
        {
            "defaultDecision": "deny",
            "decisionTtlSeconds": 1800,
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
                    "allowedRetentions": ["local-runtime-dependent"],
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
        revision=1,
    )
    prices = sealed(
        "TrustedPriceCatalog",
        "release-prices-1",
        {
            "authority": "operator",
            "currency": "microUSD",
            "validFrom": _utc(now - timedelta(minutes=5)),
            "validUntil": _utc(now + timedelta(minutes=30)),
            "sourceProvenanceDigest": "a" * 64,
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
        revision=1,
    )
    observation = sealed(
        "ObservedModelCapabilities",
        "release-observation-1",
        {
            "authority": "trusted-observation",
            "deploymentId": candidate.deployment_id,
            "deploymentIdentityDigest": candidate.identity_digest,
            "capabilities": ["model.structured-output", "model.text"],
            "contextWindowTokens": 32768,
            "latencyP95Millis": 25,
            "observedAt": _utc(now - timedelta(minutes=1)),
            "validUntil": _utc(now + timedelta(minutes=20)),
            "evidenceEnvelopeDigest": semantic_digest({"envelope": "release"}),
            "suiteDigest": "a" * 64,
        },
    )
    execution_plan_digest = route_execution_plan_digest(
        {
            "projectId": "release-conformance",
            "runId": "release-run-1",
            "maximumCalls": 1,
            "privateContent": _CONTENT_SENTINEL,
        }
    )
    request = sealed(
        "ModelRouteRequest",
        "release-request-1",
        {
            "role": "eco-researcher",
            "actionClass": "A1",
            "dataClass": "D1",
            "workloadClass": "review",
            "requiredCapabilities": ["model.structured-output"],
            "requiredContextTokens": 1024,
            "inputTokenCeiling": 100,
            "outputTokenCeiling": 100,
            "allowedZones": ["Z1"],
            "allowedRetentions": ["local-runtime-dependent"],
            "allowCloud": False,
            "maximumCostMicrousd": 0,
            "deadlineAt": _utc(now + timedelta(minutes=10)),
            "executionProfile": "standard",
            "policyDigest": policy["metadata"]["recordDigest"],
            "contextDigest": semantic_digest({"trustedContext": "release-fixture"}),
            "executionPlanDigest": execution_plan_digest,
            "aggregateBudget": {
                "maximumCalls": 1,
                "inputTokenCeiling": 100,
                "outputTokenCeiling": 100,
                "maximumCostMicrousd": 0,
            },
        },
    )
    outcome = DeterministicModelRouter(policy, prices).route(
        request,
        [candidate],
        [observation],
        now=now,
        decision_id="release-decision-1",
        explain_id="release-explain-1",
    )
    if outcome.decision["spec"]["decision"] != "allowed":
        raise RuntimeError(
            "release route was denied: "
            f"{outcome.decision['spec']['reasonCode']}"
        )
    return outcome.decision, request


def _tracked_paths(repository: Path) -> tuple[Path, ...]:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("tracked repository inventory is unavailable") from exc
    paths = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("tracked repository path is not UTF-8") from exc
        path = repository.joinpath(*Path(relative).parts)
        try:
            path.relative_to(repository)
        except ValueError as exc:
            raise RuntimeError("tracked repository path escapes its root") from exc
        paths.append(path)
    return tuple(paths)


def _snapshot(repository: Path) -> tuple[tuple[str, str, int, int], ...]:
    records = []
    for path in _tracked_paths(repository):
        info = path.lstat()
        relative = path.relative_to(repository).as_posix()
        if path.is_symlink():
            content = os.readlink(path).encode("utf-8")
        elif path.is_file():
            content = path.read_bytes()
        else:
            raise RuntimeError("tracked repository entry is not a file")
        records.append(
            (
                relative,
                hashlib.sha256(content).hexdigest(),
                len(content),
                info.st_mtime_ns,
            )
        )
    return tuple(records)


def _journal_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted((path for path in root.rglob("*") if path.is_file()), key=str))


def run(repository: Path) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    before = _snapshot(repository)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    decision, request = _route_fixture(now)
    selected = decision["spec"]["selected"]
    consumer_digest = route_consumer_digest(
        decision,
        request,
        consumer_kind="release-conformance",
        consumer_id="release-run-1",
        effect_digest=_WORKFLOW_EFFECT_DIGEST,
    )
    with tempfile.TemporaryDirectory(prefix="eco-m6-release-conformance-") as temporary:
        private = Path(temporary) / "private"
        with DurableRouteConsumptionJournal(
            private / "route-consumption.sqlite3",
            hmac_key=_SECRET_SENTINEL,
            key_id="m6-release-consumption-v1",
        ) as consumption:
            consumption.consume(
                decision,
                request,
                expected_deployment_id=selected["deploymentId"],
                expected_deployment_identity_digest=selected[
                    "deploymentIdentityDigest"
                ],
                consumer_kind="release-conformance",
                consumer_id="release-run-1",
                consumer_digest=consumer_digest,
                now=now + timedelta(seconds=1),
            )
            consumption_state = consumption.verify()
        with DurableRouteUsageJournal(
            private / "route-usage.sqlite3",
            hmac_key=_SECRET_SENTINEL,
            key_id="m6-release-usage-v1",
        ) as usage:
            usage.reserve(
                decision,
                request,
                consumer_kind="release-conformance",
                consumer_id="release-run-1",
                workflow_effect_digest=_WORKFLOW_EFFECT_DIGEST,
                effect_id="release-effect-1",
                effect_digest="f" * 64,
                input_tokens=1,
                output_tokens=1,
                cost_microusd=0,
                now=now + timedelta(seconds=1),
            )
            usage_state = usage.verify()
        files = _journal_files(private)
        if not files:
            raise RuntimeError("route journal conformance produced no durable files")
        if any(_SECRET_SENTINEL in path.read_bytes() for path in files):
            raise RuntimeError("route journal serialized a secret sentinel")
        content_bytes = _CONTENT_SENTINEL.encode("utf-8")
        if any(content_bytes in path.read_bytes() for path in files):
            raise RuntimeError("route journal serialized private content")
        journal_digest = hashlib.sha256(
            b"".join(hashlib.sha256(path.read_bytes()).digest() for path in files)
        ).hexdigest()
        cli_output = io.StringIO()
        with contextlib.redirect_stdout(cli_output):
            cli_code = eco_main(
                [
                    "--repo",
                    str(repository),
                    "loops",
                    "validate",
                    "wiki-health-check",
                    "--json",
                ]
            )
        if cli_code != 0:
            raise RuntimeError("deterministic loop validation failed")
        if (
            _CONTENT_SENTINEL in cli_output.getvalue()
            or _SECRET_SENTINEL.decode("utf-8") in cli_output.getvalue()
        ):
            raise RuntimeError("deterministic CLI output leaked a sentinel")
    after = _snapshot(repository)
    if before != after:
        raise RuntimeError("release conformance mutated tracked repository bytes or mtimes")
    return {
        "available": True,
        "operation": "m6-release-conformance",
        "status": "pass",
        "trackedFiles": len(before),
        "journalFiles": len(files),
        "journalDigest": journal_digest,
        "consumptionEntries": consumption_state["entries"],
        "usageEntries": usage_state["entries"],
        "deterministicCli": "wiki-health-check-loop-valid",
        "repositoryIdentity": "bytes-and-mtime-unchanged",
        "secretSentinel": "absent",
        "privateContentSentinel": "absent-from-journals-and-cli-output",
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="check_m6_release_conformance.py")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        report = run(args.repo)
    except Exception as exc:
        report = {
            "available": False,
            "operation": "m6-release-conformance",
            "status": "blocked",
            "reason": str(exc),
        }
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
