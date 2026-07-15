from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.policy import PolicyEngine
from eco_runtime.evidence import (
    EvidenceIssuerPolicy,
    EvidenceTrustStore,
    HmacEvidenceSigner,
    LinuxRepositorySnapshotGenerator,
    SnapshotEntryClassification,
    TrustedEvidenceIngestor,
)
from eco_runtime.repository import repository_root_identity
from tests.test_policy import (
    DIGEST,
    NOW,
    artifact_registry,
    exact_deployment,
    observation,
    plan,
    policy_bundle,
    run_request,
    tool_request_for,
)


SNAPSHOT_KEY = b"s" * 32
OBSERVATION_KEY = b"o" * 32


class TrustedEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.outside = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.outside_root = Path(self.outside.name)
        (self.root / "README.md").write_text("trusted snapshot\n", encoding="utf-8")
        (self.root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
        (self.root / "binary.bin").write_bytes(b"abc\x00def")
        (self.root / "hard.txt").write_text("hardlink", encoding="utf-8")
        os.link(self.root / "hard.txt", self.root / "hard-alias.txt")
        (self.outside_root / "outside.txt").write_text("outside", encoding="utf-8")
        os.symlink(self.outside_root / "outside.txt", self.root / "link.txt")

        self.policies = (
            EvidenceIssuerPolicy(
                "snapshot-authority",
                "snapshot-key-1",
                SNAPSHOT_KEY,
                frozenset({"RepositorySnapshot"}),
                allowed_projects=frozenset({"sample"}),
            ),
            EvidenceIssuerPolicy(
                "evaluation-authority",
                "evaluation-key-1",
                OBSERVATION_KEY,
                frozenset({"AdapterConformanceProfile"}),
                allowed_deployments=frozenset({"dgx-test"}),
                allowed_suite_digests=frozenset({DIGEST}),
            ),
        )
        self.ingestor = TrustedEvidenceIngestor(EvidenceTrustStore(self.policies))
        self.snapshot_signer = HmacEvidenceSigner(
            "snapshot-authority", "snapshot-key-1", SNAPSHOT_KEY
        )
        self.observation_signer = HmacEvidenceSigner(
            "evaluation-authority", "evaluation-key-1", OBSERVATION_KEY
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.outside.cleanup()

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimePolicyError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def snapshot(self) -> dict:
        with LinuxRepositorySnapshotGenerator(self.root) as generator:
            return generator.generate(
                snapshot_id="snapshot-1",
                project_id="sample",
                issuer_type="runtime",
                issuer_id="snapshot-authority",
                snapshot_trust="P1",
                classifications={
                    "README.md": SnapshotEntryClassification("D1", "P1", "operator")
                },
                now=NOW,
                source_revision="fixture-revision",
            )

    def test_snapshot_generation_is_explicit_signed_and_root_bound(self) -> None:
        snapshot = self.snapshot()
        self.assertEqual([item["path"] for item in snapshot["spec"]["entries"]], ["README.md"])
        self.assertEqual(
            snapshot["spec"]["entries"][0]["contentDigest"],
            hashlib.sha256(b"trusted snapshot\n").hexdigest(),
        )
        self.assertEqual(snapshot["spec"]["rootIdentityDigest"], repository_root_identity(self.root))
        encoded = self.snapshot_signer.sign(
            snapshot,
            envelope_id="snapshot-envelope-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
        )
        trusted = self.ingestor.ingest_repository_snapshot(
            encoded,
            expected_project_id="sample",
            expected_root_identity_digest=repository_root_identity(self.root),
            now=NOW,
        )
        self.assertEqual(semantic_digest(trusted.as_dict()), semantic_digest(snapshot))
        with self.assertRaises(AttributeError):
            trusted.issuer_id = "forged-authority"

        envelope = json.loads(encoded.decode("utf-8"))
        envelope["record"]["spec"]["entries"][0]["contentDigest"] = "f" * 64
        tampered = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        self.assert_code(
            "ECO_EVIDENCE_SIGNATURE_INVALID",
            lambda: self.ingestor.ingest_repository_snapshot(
                tampered,
                expected_project_id="sample",
                expected_root_identity_digest=repository_root_identity(self.root),
                now=NOW,
            ),
        )
        self.assert_code(
            "ECO_SNAPSHOT_EVIDENCE_MISMATCH",
            lambda: self.ingestor.ingest_repository_snapshot(
                encoded,
                expected_project_id="sample",
                expected_root_identity_digest="f" * 64,
                now=NOW,
            ),
        )

    def test_snapshot_generator_rejects_protected_escape_hardlink_and_binary(self) -> None:
        cases = {
            ".env": "ECO_SNAPSHOT_PATH_DENIED",
            "link.txt": "ECO_SNAPSHOT_PATH_ESCAPE",
            "hard.txt": "ECO_SNAPSHOT_FILE_UNSAFE",
            "binary.bin": "ECO_SNAPSHOT_BINARY_DENIED",
        }
        with LinuxRepositorySnapshotGenerator(self.root) as generator:
            for path, code in cases.items():
                with self.subTest(path=path):
                    self.assert_code(
                        code,
                        lambda path=path: generator.generate(
                            snapshot_id=f"snapshot-{path.replace('.', '-')}",
                            project_id="sample",
                            issuer_type="runtime",
                            issuer_id="snapshot-authority",
                            snapshot_trust="P1",
                            classifications={
                                path: SnapshotEntryClassification("D1", "P1", "operator")
                            },
                            now=NOW,
                        ),
                    )

    def test_snapshot_unknown_issuer_expiry_and_future_time_fail_closed(self) -> None:
        snapshot = self.snapshot()
        unknown = HmacEvidenceSigner("unknown-authority", "unknown-key", b"u" * 32).sign(
            snapshot,
            envelope_id="unknown-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
        )
        self.assert_code(
            "ECO_EVIDENCE_ISSUER_UNTRUSTED",
            lambda: self.ingestor.ingest_repository_snapshot(
                unknown,
                expected_project_id="sample",
                expected_root_identity_digest=repository_root_identity(self.root),
                now=NOW,
            ),
        )
        expired = self.snapshot_signer.sign(
            snapshot,
            envelope_id="expired-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=1),
        )
        self.assert_code(
            "ECO_EVIDENCE_EXPIRED",
            lambda: self.ingestor.ingest_repository_snapshot(
                expired,
                expected_project_id="sample",
                expected_root_identity_digest=repository_root_identity(self.root),
                now=NOW + timedelta(seconds=1),
            ),
        )
        future = self.snapshot_signer.sign(
            snapshot,
            envelope_id="future-envelope",
            issued_at=NOW + timedelta(minutes=10),
            expires_at=NOW + timedelta(minutes=20),
        )
        self.assert_code(
            "ECO_EVIDENCE_WINDOW_INVALID",
            lambda: self.ingestor.ingest_repository_snapshot(
                future,
                expected_project_id="sample",
                expected_root_identity_digest=repository_root_identity(self.root),
                now=NOW,
            ),
        )

    def test_signed_observation_is_identity_suite_time_and_id_bound(self) -> None:
        deployment = exact_deployment()
        record = observation(deployment)
        encoded = self.observation_signer.sign(
            record,
            envelope_id="observation-envelope-1",
            issued_at=NOW,
            expires_at=record_valid_until(record),
        )
        trusted = self.ingestor.ingest_observed_capabilities(
            encoded,
            expected_deployment_id="dgx-test",
            expected_deployment_identity_digest=deployment_identity_digest(deployment),
            trusted_suite_digests=frozenset({DIGEST}),
            now=NOW,
        )
        self.assertEqual(semantic_digest(trusted.as_dict()), semantic_digest(record))
        self.assert_code(
            "ECO_OBSERVATION_EVIDENCE_MISMATCH",
            lambda: self.ingestor.ingest_observed_capabilities(
                encoded,
                expected_deployment_id="other-deployment",
                expected_deployment_identity_digest=deployment_identity_digest(deployment),
                trusted_suite_digests=frozenset({DIGEST}),
                now=NOW,
            ),
        )

    def test_policy_engine_accepts_only_ingested_evidence_by_default(self) -> None:
        snapshot = self.snapshot()
        snapshot_encoded = self.snapshot_signer.sign(
            snapshot,
            envelope_id="snapshot-policy-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
        )
        deployment = exact_deployment()
        record = observation(deployment)
        observation_encoded = self.observation_signer.sign(
            record,
            envelope_id="observation-policy-envelope",
            issued_at=NOW,
            expires_at=record_valid_until(record),
        )
        bundle, _ = policy_bundle()
        engine = PolicyEngine(
            bundle,
            {"dgx-test": observation_encoded},
            artifact_registry(),
            repository_snapshot=snapshot_encoded,
            evidence_policies=self.policies,
            evidence_now=NOW,
            repository_root_identity_digest=repository_root_identity(self.root),
            trusted_suite_digests={DIGEST},
        )
        self.assertEqual(len(engine.config_digest), 64)
        planning = plan(engine)
        self.assertIsNotNone(planning.plan)
        self.assertEqual(
            planning.plan["spec"]["route"]["observedCapabilitiesEvidence"]["envelopeDigest"],
            hashlib.sha256(observation_encoded).hexdigest(),
        )
        self.assertEqual(
            planning.plan["spec"]["repositorySnapshot"]["evidence"]["envelopeDigest"],
            hashlib.sha256(snapshot_encoded).hexdigest(),
        )
        forged_plan = copy.deepcopy(planning.plan)
        forged_plan["spec"]["route"]["observedCapabilitiesEvidence"]["keyId"] = "forged-key"
        self.assert_code(
            "ECO_PLAN_UNTRUSTED",
            lambda: engine.activate_plan(forged_plan, planning.decision, now=NOW),
        )

        changed = copy.deepcopy(record)
        changed["spec"]["effectiveCapabilities"] = ["model.text"]
        conflicting = self.observation_signer.sign(
            changed,
            envelope_id="observation-policy-envelope",
            issued_at=NOW,
            expires_at=record_valid_until(record),
        )
        self.ingestor.ingest_observed_capabilities(
            observation_encoded,
            expected_deployment_id="dgx-test",
            expected_deployment_identity_digest=deployment_identity_digest(deployment),
            trusted_suite_digests=frozenset({DIGEST}),
            now=NOW,
        )
        self.assert_code(
            "ECO_EVIDENCE_ID_CONFLICT",
            lambda: self.ingestor.ingest_observed_capabilities(
                conflicting,
                expected_deployment_id="dgx-test",
                expected_deployment_identity_digest=deployment_identity_digest(deployment),
                trusted_suite_digests=frozenset({DIGEST}),
                now=NOW,
            ),
        )

    def test_policy_engine_caps_decision_and_reverifies_expiry_at_activation(self) -> None:
        deployment = exact_deployment()
        record = observation(deployment)
        encoded = self.observation_signer.sign(
            record,
            envelope_id="short-lived-observation-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=1),
        )
        snapshot = self.snapshot()
        snapshot_encoded = self.snapshot_signer.sign(
            snapshot,
            envelope_id="activation-snapshot-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
        )
        bundle, _ = policy_bundle()
        engine = PolicyEngine(
            bundle,
            {"dgx-test": encoded},
            artifact_registry(),
            repository_snapshot=snapshot_encoded,
            evidence_policies=self.policies,
            evidence_now=NOW,
            repository_root_identity_digest=repository_root_identity(self.root),
            trusted_suite_digests={DIGEST},
        )
        planning = plan(engine)
        self.assertIsNotNone(planning.plan)
        self.assertEqual(
            planning.decision["spec"]["constraints"]["expiresAt"],
            "2026-07-15T12:00:01Z",
        )
        self.assert_code(
            "ECO_EVIDENCE_EXPIRED",
            lambda: engine.activate_plan(
                planning.plan,
                planning.decision,
                now=NOW + timedelta(seconds=2),
            ),
        )

    def test_tool_allow_cannot_outlive_its_signed_evidence(self) -> None:
        deployment = exact_deployment()
        record = observation(deployment)
        observation_encoded = self.observation_signer.sign(
            record,
            envelope_id="tool-expiry-observation-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
        )
        snapshot = self.snapshot()
        snapshot_encoded = self.snapshot_signer.sign(
            snapshot,
            envelope_id="tool-expiry-snapshot-envelope",
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
        )
        bundle, _ = policy_bundle()
        engine = PolicyEngine(
            bundle,
            {"dgx-test": observation_encoded},
            artifact_registry(),
            repository_snapshot=snapshot_encoded,
            evidence_policies=self.policies,
            evidence_now=NOW,
            repository_root_identity_digest=repository_root_identity(self.root),
            trusted_suite_digests={DIGEST},
        )
        planning = plan(engine)
        engine.activate_plan(planning.plan, planning.decision, now=NOW)
        request = tool_request_for(planning.plan)
        request["metadata"]["createdAt"] = "2026-07-15T12:00:01Z"
        decision = engine.authorize_tool(
            planning.plan,
            request,
            decision_id="tool-evidence-expiry-decision",
            now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(
            decision["spec"]["constraints"]["expiresAt"], "2026-07-15T12:00:05Z"
        )
        self.assert_code(
            "ECO_DECISION_EXPIRED",
            lambda: engine.consume_decision(
                decision, request, now=NOW + timedelta(seconds=6)
            ),
        )


def record_valid_until(record: dict):
    from datetime import datetime

    value = record["metadata"]["validUntil"]
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


if __name__ == "__main__":
    unittest.main()
