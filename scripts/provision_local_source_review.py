#!/usr/bin/env python3
"""Operator provisioning for one live local source-review deployment.

Probes an operator-supplied loopback OpenAI-compatible endpoint with the two
capabilities the workflow needs (plain text and strict JSON-schema structured
output), then writes the observed AdapterConformanceProfile into the
repository and an HMAC-signed evidence envelope into a private external
directory. The runtime never signs its own evidence: this script is the
explicit operator ceremony, and its signing key must stay outside Git.

The probed deployment must already be declared in `.ai/deployments.yaml`;
this script grants nothing and edits no canonical contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


PROBE_SUITE = {
    "id": "adapter-conformance-v1",
    "version": "1.0.0",
    "probes": [
        {
            "id": "text-basic",
            "kind": "chat-completion",
            "expectation": "non-empty assistant text with finish_reason stop",
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


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _post(endpoint: str, payload: dict, timeout: int) -> dict:
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _probe(endpoint: str, model: str, timeout: int) -> list[dict]:
    results = []
    text_payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": "Reply with one short sentence about testing."}
        ],
        "max_tokens": 512,
        "temperature": 0,
    }
    text_response = _post(endpoint, text_payload, timeout)
    text_choice = text_response["choices"][0]
    text_ok = (
        text_choice["finish_reason"] == "stop"
        and isinstance(text_choice["message"]["content"], str)
        and text_choice["message"]["content"].strip() != ""
    )
    results.append(
        {
            "id": "text-basic",
            "status": "pass" if text_ok else "fail",
            "attempts": 1,
            "successes": 1 if text_ok else 0,
            "evidenceDigest": hashlib.sha256(
                canonical_json(
                    {"probe": "text-basic", "request": text_payload, "response": text_response}
                ).encode("utf-8")
            ).hexdigest(),
        }
    )
    structured_payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": "State one fact about software testing in the required JSON form.",
            }
        ],
        "max_tokens": 200,
        "temperature": 0,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "conformance-probe",
                "strict": True,
                "schema": STRUCTURED_SCHEMA,
            },
        },
    }
    structured_response = _post(endpoint, structured_payload, timeout)
    structured_choice = structured_response["choices"][0]
    structured_ok = structured_choice["finish_reason"] == "stop"
    if structured_ok:
        try:
            parsed = json.loads(structured_choice["message"]["content"])
            structured_ok = (
                isinstance(parsed, dict)
                and set(parsed) == {"fact", "confidence"}
                and isinstance(parsed["fact"], str)
                and parsed["confidence"] in {"low", "medium", "high"}
            )
        except (ValueError, TypeError):
            structured_ok = False
    results.append(
        {
            "id": "structured-output-strict",
            "status": "pass" if structured_ok else "fail",
            "attempts": 1,
            "successes": 1 if structured_ok else 0,
            "evidenceDigest": hashlib.sha256(
                canonical_json(
                    {
                        "probe": "structured-output-strict",
                        "request": structured_payload,
                        "response": structured_response,
                    }
                ).encode("utf-8")
            ).hexdigest(),
        }
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument(
        "--endpoint-env",
        default="ECO_LOCAL_OPENAI_ENDPOINT",
        help="Environment variable holding the loopback endpoint URL",
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
    args = parser.parse_args()

    endpoint = os.environ.get(args.endpoint_env)
    key_value = os.environ.get(args.evidence_key_env)
    if not endpoint or not key_value or len(key_value.encode("utf-8")) < 32:
        print(
            "ERROR: endpoint and a >=32-byte evidence key are required in the environment",
            file=sys.stderr,
        )
        return 2
    if not endpoint.startswith("http://127.0.0.1"):
        print("ERROR: only a literal loopback endpoint is provisionable", file=sys.stderr)
        return 2

    deployments = yaml.safe_load(
        (args.repo / ".ai" / "deployments.yaml").read_text(encoding="utf-8")
    )
    matches = [
        item
        for item in deployments.get("deployments", [])
        if item.get("id") == args.deployment_id
    ]
    if len(matches) != 1:
        print("ERROR: the deployment must be declared exactly once", file=sys.stderr)
        return 2
    deployment = matches[0]

    now = datetime.now(timezone.utc).replace(microsecond=0)
    valid_until = now + timedelta(minutes=args.validity_minutes)
    probes = _probe(endpoint, deployment["model"], args.timeout_seconds)
    status = "pass" if all(item["status"] == "pass" for item in probes) else "fail"
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
            "deploymentIdentityDigest": deployment_identity_digest(deployment),
            "adapterVersion": deployment["identity"]["adapterVersion"],
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
            "deviationCodes": [],
        },
    }
    observed_ref = deployment.get("observedCapabilitiesRef")
    if not observed_ref:
        print("ERROR: the deployment must declare observedCapabilitiesRef", file=sys.stderr)
        return 2
    observed_path = (args.repo / ".ai" / observed_ref).resolve()
    observed_path.parent.mkdir(parents=True, exist_ok=True)
    observed_path.write_text(canonical_json(observation), encoding="utf-8")

    envelope = HmacEvidenceSigner(
        args.issuer_id, args.key_id, key_value.encode("utf-8")
    ).sign(
        observation,
        envelope_id=f"{args.deployment_id}-envelope",
        issued_at=now,
        expires_at=valid_until,
    )
    args.envelope_out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.envelope_out.write_bytes(envelope)
    os.chmod(args.envelope_out, 0o600)

    print(
        json.dumps(
            {
                "status": status,
                "suiteDigest": suite_digest,
                "deploymentIdentityDigest": observation["spec"]["deploymentIdentityDigest"],
                "observedPath": str(observed_path),
                "envelopePath": str(args.envelope_out),
                "validUntil": observation["metadata"]["validUntil"],
                "probes": [
                    {"id": item["id"], "status": item["status"]} for item in probes
                ],
            },
            indent=2,
        )
    )
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
