from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from eco_runtime.digests import semantic_digest
from eco_runtime.evidence import EvidenceIssuerPolicy, EvidenceTrustStore


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_m2_live_evaluation.py"
SPEC = importlib.util.spec_from_file_location("run_m2_live_evaluation", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError("live evaluation script cannot be loaded")
SCRIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCRIPT)

KEY = b"live-fixture-signing-key-with-32-bytes!"
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


def observation(
    deployment_id: str = "local-live",
    identity_digest: str = "a" * 64,
    adapter_version: str = "adapter-v1",
) -> dict:
    probe = {
        "caseId": "text-basic",
        "status": "pass",
        "deviationCode": None,
        "normalizedOutputDigest": "c" * 64,
        "usage": {
            "inputTokens": 3,
            "outputTokens": 1,
            "totalTokens": 4,
            "modelRequests": 1,
        },
    }
    return {
        "apiVersion": "runtime.ai.ecosystem/v1alpha1",
        "kind": "AdapterConformanceProfile",
        "metadata": {
            "id": f"eval-{deployment_id}-1",
            "deploymentId": deployment_id,
            "testedAt": "2026-07-15T12:00:00Z",
            "validUntil": "2026-07-16T12:00:00Z",
        },
        "spec": {
            "deploymentIdentityDigest": identity_digest,
            "adapterVersion": adapter_version,
            "suite": {"id": "m2-live", "version": "1", "digest": "b" * 64},
            "status": "pass",
            "effectiveCapabilities": ["model.text"],
            "probes": [
                {
                    "id": "text-basic",
                    "status": "pass",
                    "attempts": 1,
                    "successes": 1,
                    "evidenceDigest": semantic_digest(probe),
                    "metrics": {"inputTokens": 3, "outputTokens": 1},
                }
            ],
            "deviationCodes": [],
        },
    }


class LiveEvidenceFixtureTests(unittest.TestCase):
    def test_case_id_and_executable_digest_are_grounded(self) -> None:
        self.assertEqual(SCRIPT.CASE_ID, "text-basic")
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "provider-cli"
            executable.write_bytes(b"exact executable bytes")
            expected = hashlib.sha256(b"exact executable bytes").hexdigest()
            self.assertEqual(
                SCRIPT._verified_executable_digest(str(executable), expected), expected
            )
            with self.assertRaises(ValueError):
                SCRIPT._verified_executable_digest(str(executable), "0" * 64)

    def test_publish_is_complete_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            output = parent / "run-1"
            documents = {
                Path("summary.json"): b'{"status":"pass"}\n',
                Path("observations/local.json"): b'{"kind":"fixture"}\n',
            }
            SCRIPT._publish_documents(output, documents)
            self.assertEqual((output / "summary.json").read_bytes(), documents[Path("summary.json")])
            self.assertEqual(
                (output / "observations/local.json").read_bytes(),
                documents[Path("observations/local.json")],
            )

            with self.assertRaises(FileExistsError):
                SCRIPT._publish_documents(output, {Path("summary.json"): b"changed"})
            self.assertEqual((output / "summary.json").read_bytes(), documents[Path("summary.json")])
            self.assertFalse((parent / ".run-1.publish.lock").exists())
            self.assertEqual(list(parent.glob(".run-1.staging-*")), [])

    def test_atomic_rename_never_replaces_a_race_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            source = parent / "staging"
            destination = parent / "published"
            source.mkdir()
            destination.mkdir()
            (source / "source.txt").write_text("source")
            (destination / "winner.txt").write_text("winner")
            with self.assertRaises(FileExistsError):
                SCRIPT._rename_directory_noreplace(source, destination)
            self.assertEqual((destination / "winner.txt").read_text(), "winner")
            self.assertTrue(source.is_dir())

    def test_publication_manifest_authenticates_exact_files(self) -> None:
        documents = {
            Path("summary.json"): b'{"status":"pass"}\n',
            Path("policy-gate/run-plan.json"): b'{"kind":"RunPlan"}\n',
        }
        encoded = SCRIPT._publication_manifest_document(
            documents,
            signing_key=KEY,
            key_id="live-key-1",
            evaluated_at=NOW,
        )
        value = json.loads(encoded)
        self.assertEqual(value["manifestDigest"], semantic_digest(value["manifest"]))
        for entry in value["manifest"]["files"]:
            payload = documents[Path(entry["path"])]
            self.assertEqual(entry["byteLength"], len(payload))
            self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())
        publication_key = hmac.new(
            KEY, SCRIPT.PUBLICATION_KEY_DOMAIN, hashlib.sha256
        ).digest()
        authentication = json.dumps(
            value["manifest"], sort_keys=True, separators=(",", ":")
        ).encode()
        self.assertTrue(
            hmac.compare_digest(
                value["signature"]["value"],
                hmac.new(publication_key, authentication, hashlib.sha256).hexdigest(),
            )
        )

    def test_trusted_observation_envelope_is_verifiable(self) -> None:
        record = observation()
        documents = SCRIPT._trusted_observation_documents(
            (record,),
            signing_key=SCRIPT._observation_signing_key(KEY),
            key_id="live-key-1",
            issuer_id="live-runner-1",
        )
        encoded = documents[
            Path("trusted-observations/local-live.envelope.json")
        ]
        trust_store = EvidenceTrustStore(
            (
                EvidenceIssuerPolicy(
                    issuer_id="live-runner-1",
                    key_id="live-key-1",
                    verification_key=SCRIPT._observation_signing_key(KEY),
                    allowed_kinds=frozenset({"AdapterConformanceProfile"}),
                    allowed_deployments=frozenset({"local-live"}),
                    allowed_suite_digests=frozenset({"b" * 64}),
                ),
            )
        )
        opened, _policy, envelope = trust_store.open(encoded, now=NOW)
        self.assertEqual(opened, record)
        self.assertEqual(envelope["subject"]["digest"], semantic_digest(record))

    def test_trusted_observations_pass_the_real_local_policy_gate(self) -> None:
        local = SCRIPT._deployment(
            identifier="local-live",
            provider="local",
            adapter="local-eval",
            model="local-model",
            endpoint_ref="config:local-loopback",
            zone="Z1",
            adapter_version="adapter-v1",
            model_revision="sha256:" + "1" * 64,
            runtime_engine="fixture-local",
            runtime_version="1",
            quantization="fixture",
        )
        cloud = SCRIPT._deployment(
            identifier="cloud-live",
            provider="fixture-cloud",
            adapter="cloud-eval",
            model="cloud-model",
            endpoint_ref="config:cloud-broker",
            zone="Z3",
            adapter_version="adapter-v1",
            model_revision="provider-alias:cloud-model",
            runtime_engine="fixture-cloud",
            runtime_version="1",
            quantization="provider-managed",
        )
        records = (
            observation("local-live", SCRIPT.deployment_identity_digest(local)),
            observation("cloud-live", SCRIPT.deployment_identity_digest(cloud)),
        )
        observation_key = SCRIPT._observation_signing_key(KEY)
        trusted = SCRIPT._trusted_observation_documents(
            records,
            signing_key=observation_key,
            key_id="live-key-1",
            issuer_id="live-runner-1",
        )
        receipts = SCRIPT._policy_gate_documents(
            deployments=(local, cloud),
            observations=records,
            trusted_documents=trusted,
            observation_key=observation_key,
            key_id="live-key-1",
            issuer_id="live-runner-1",
            suite_digest="b" * 64,
            evaluated_at=NOW,
            evaluation_evidence_digest="d" * 64,
        )
        gate = json.loads(receipts[Path("policy-gate-receipt.json")])
        trust = json.loads(receipts[Path("trust-policy-receipt.json")])
        plan_record = json.loads(receipts[Path("policy-gate/run-plan.json")])
        decision_record = json.loads(receipts[Path("policy-gate/policy-decision.json")])
        self.assertEqual(gate["status"], "pass")
        self.assertEqual(gate["deploymentId"], "local-live")
        self.assertEqual(trust["status"], "pass")
        self.assertEqual(len(trust["observations"]), 2)
        self.assertEqual(gate["planDigest"], semantic_digest(plan_record))
        self.assertEqual(gate["decisionDigest"], semantic_digest(decision_record))


if __name__ == "__main__":
    unittest.main()
