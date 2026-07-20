from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from eco_runtime.evidence import HmacEvidenceSigner
from eco_runtime.digests import semantic_digest
from eco_runtime.repository import repository_root_identity
from eco_runtime.trust_diagnostics import _issuer_policies, runtime_trust_diagnostics
from tests.test_policy import DIGEST, exact_deployment, observation


NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
KEY = b"trust-diagnostics-test-key-32bytes!"


class RuntimeTrustDiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.entries = {
            "wiki/index.md": b"# Index\n",
            "wiki/architecture.md": b"# Architecture\n",
        }
        for path, content in self.entries.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        self.evidence_path = Path(self.temp.name) / "snapshot.evidence"
        self.bundle = {
            "project": {"metadata": {"name": "sample"}},
            "trust": {
                "evidence": {
                    "issuers": [
                        {
                            "id": "operator-1",
                            "keyId": "snapshot-key-1",
                            "verificationKeyRef": "env:ECO_TEST_TRUST_KEY",
                            "allowedKinds": ["RepositorySnapshot"],
                            "allowedProjects": ["sample"],
                            "allowedDeployments": [],
                            "allowedSuiteDigests": [],
                        }
                    ]
                },
                "repositorySnapshot": {
                    "issuer": {
                        "id": "operator-1",
                        "keyId": "snapshot-key-1",
                        "recordIssuerType": "operator",
                    },
                    "envelopeRef": "env:ECO_TEST_SNAPSHOT_EVIDENCE",
                    "entries": [
                        {
                            "path": path,
                            "dataClass": "D0",
                            "trust": "P1",
                            "classificationAuthority": "policy",
                        }
                        for path in self.entries
                    ],
                },
                "conformance": {"trustedSuites": [], "requiredObservations": []},
            },
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _snapshot(self, *, extra_entry: bool = False) -> dict:
        entries = [
            {
                "path": path,
                "contentDigest": hashlib.sha256(content).hexdigest(),
                "byteLength": len(content),
                "dataClass": "D0",
                "trust": "P1",
                "classificationAuthority": "policy",
            }
            for path, content in self.entries.items()
        ]
        if extra_entry:
            entries.append(
                {
                    "path": "wiki/extra.md",
                    "contentDigest": "a" * 64,
                    "byteLength": 1,
                    "dataClass": "D0",
                    "trust": "P1",
                    "classificationAuthority": "policy",
                }
            )
        return {
            "apiVersion": "runtime.ai.ecosystem/v1alpha1",
            "kind": "RepositorySnapshot",
            "metadata": {
                "id": "snapshot-1",
                "projectId": "sample",
                "createdAt": "2026-07-16T11:59:00Z",
                "issuer": {"type": "operator", "id": "operator-1"},
            },
            "spec": {
                "rootIdentityDigest": repository_root_identity(self.root),
                "trust": "P1",
                "entries": entries,
            },
        }

    def _write_snapshot(self, *, extra_entry: bool = False) -> None:
        encoded = HmacEvidenceSigner("operator-1", "snapshot-key-1", KEY).sign(
            self._snapshot(extra_entry=extra_entry),
            envelope_id="snapshot-envelope-1",
            issued_at=NOW - timedelta(minutes=1),
            expires_at=NOW + timedelta(minutes=5),
        )
        self.evidence_path.write_bytes(encoded)
        os.chmod(self.evidence_path, 0o600)

    def test_verifies_exact_externally_signed_snapshot_without_enabling_execution(self) -> None:
        self._write_snapshot()
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertTrue(result["available"])
        self.assertFalse(result["executionReady"])
        self.assertEqual(result["evidence"]["verifiedSnapshotEntries"], 2)
        self.assertEqual(
            [item["component"] for item in result["checks"]],
            ["trust-config", "evidence-key", "repository-snapshot", "conformance"],
        )
        self.assertEqual(result["safety"]["repositoryRead"], "not-started")
        self.assertEqual(result["safety"]["modelEgress"], "not-used")
        self.assertEqual(
            result["execution"]["code"], "ECO_RUNTIME_TRUST_VERIFICATION_ONLY"
        )

    def test_missing_key_fails_closed_without_echoing_environment_value(self) -> None:
        marker = "SECRET_KEY_MUST_NOT_ESCAPE"
        with mock.patch.dict(
            os.environ,
            {"ECO_TEST_SNAPSHOT_EVIDENCE": marker},
            clear=True,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        serialized = repr(result)
        self.assertFalse(result["available"])
        self.assertEqual(result["checks"][-1]["code"], "ECO_RUNTIME_TRUST_KEY_UNAVAILABLE")
        self.assertNotIn(marker, serialized)

    def test_snapshot_scope_must_exactly_match_the_fixed_allowlist(self) -> None:
        self._write_snapshot(extra_entry=True)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(
            result["checks"][-1]["code"], "ECO_RUNTIME_TRUST_SNAPSHOT_SCOPE_INVALID"
        )

    def test_insecure_external_evidence_file_is_rejected_without_echoing_path(self) -> None:
        self._write_snapshot()
        os.chmod(self.evidence_path, 0o644)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(
            result["checks"][-1]["code"], "ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED"
        )
        self.assertNotIn(str(self.evidence_path), repr(result))

    def test_evidence_inside_the_governed_repository_is_rejected(self) -> None:
        self._write_snapshot()
        in_repository = self.root / "snapshot.evidence"
        in_repository.write_bytes(self.evidence_path.read_bytes())
        os.chmod(in_repository, 0o600)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(in_repository),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(
            result["checks"][-1]["code"], "ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED"
        )
        self.assertNotIn(str(in_repository), repr(result))

    def test_symlinked_external_evidence_is_rejected(self) -> None:
        self._write_snapshot()
        link = Path(self.temp.name) / "linked.evidence"
        link.symlink_to(self.evidence_path)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(link),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertEqual(
            result["checks"][-1]["code"], "ECO_RUNTIME_TRUST_EVIDENCE_LOCATION_DENIED"
        )
        self.assertNotIn(str(link), repr(result))

    def test_malformed_external_evidence_is_sanitized(self) -> None:
        marker = b"PRIVATE_EVIDENCE_CONTENT_MUST_NOT_ESCAPE"
        self.evidence_path.write_bytes(marker)
        os.chmod(self.evidence_path, 0o600)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertEqual(result["checks"][-1]["code"], "ECO_EVIDENCE_INVALID")
        self.assertNotIn(marker.decode(), repr(result))

    def test_each_required_conformance_envelope_is_verified(self) -> None:
        self._write_snapshot()
        deployment = exact_deployment("local-test")
        endpoint = "http://127.0.0.1:8080/v1/chat/completions"
        endpoint_ref = deployment["endpointRef"]
        conformance_path = Path(self.temp.name) / "conformance.evidence"
        conformance_path.write_bytes(
            HmacEvidenceSigner("operator-1", "snapshot-key-1", KEY).sign(
                observation(deployment),
                envelope_id="conformance-envelope-1",
                issued_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=5),
                attestation={
                    "projectId": "sample",
                    "endpointRef": endpoint_ref,
                    "endpointReferenceDigest": semantic_digest(
                        {"endpointRef": endpoint_ref}
                    ),
                    "resolvedEndpointDigest": semantic_digest(
                        {"endpointUrl": endpoint}
                    ),
                    "requestedModel": deployment["model"],
                    "reportedModels": [deployment["model"]],
                },
            )
        )
        os.chmod(conformance_path, 0o600)
        issuer = self.bundle["trust"]["evidence"]["issuers"][0]
        issuer["allowedKinds"] = ["RepositorySnapshot", "AdapterConformanceProfile"]
        issuer["allowedDeployments"] = [deployment["id"]]
        issuer["allowedSuiteDigests"] = [DIGEST]
        self.bundle["deployments"] = {"deployments": [deployment]}
        self.bundle["trust"]["conformance"] = {
            "trustedSuites": [
                {"id": "adapter-conformance-v1", "version": "1.0.0", "digest": DIGEST}
            ],
            "requiredObservations": [
                {
                    "deploymentId": deployment["id"],
                    "suiteDigest": DIGEST,
                    "envelopeRef": "env:ECO_TEST_CONFORMANCE_EVIDENCE",
                }
            ],
        }
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
                "ECO_TEST_CONFORMANCE_EVIDENCE": str(conformance_path),
                endpoint_ref[4:]: endpoint,
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertTrue(result["available"])
        self.assertEqual(result["checks"][-1], {
            "component": "conformance",
            "status": "ready",
            "code": "ECO_RUNTIME_TRUST_CONFORMANCE_VERIFIED",
        })

        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
                "ECO_TEST_CONFORMANCE_EVIDENCE": str(conformance_path),
                endpoint_ref[4:]: "http://127.0.0.1:8081/v1/chat/completions",
            },
            clear=False,
        ):
            changed_endpoint = runtime_trust_diagnostics(
                self.root, self.bundle, now=NOW
            )
        self.assertFalse(changed_endpoint["available"])
        self.assertEqual(
            changed_endpoint["checks"][-1]["code"],
            "ECO_OBSERVATION_EVIDENCE_MISMATCH",
        )

    def test_required_issuer_id_preserves_all_exact_key_rotations(self) -> None:
        rotated = dict(self.bundle["trust"]["evidence"]["issuers"][0])
        rotated["keyId"] = "snapshot-key-2"
        rotated["verificationKeyRef"] = "env:ECO_TEST_TRUST_KEY_2"
        self.bundle["trust"]["evidence"]["issuers"].append(rotated)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_TRUST_KEY_2": (b"r" * 32).decode("ascii"),
            },
            clear=False,
        ):
            policies = _issuer_policies(
                self.bundle["trust"],
                required_issuer_ids=frozenset({"operator-1"}),
            )

        self.assertEqual(
            {(policy.issuer_id, policy.key_id) for policy in policies},
            {
                ("operator-1", "snapshot-key-1"),
                ("operator-1", "snapshot-key-2"),
            },
        )

    def test_snapshot_must_use_the_exact_configured_key_id(self) -> None:
        rotated_key = b"r" * 32
        rotated = dict(self.bundle["trust"]["evidence"]["issuers"][0])
        rotated["keyId"] = "snapshot-key-2"
        rotated["verificationKeyRef"] = "env:ECO_TEST_TRUST_KEY_2"
        self.bundle["trust"]["evidence"]["issuers"].append(rotated)
        self.evidence_path.write_bytes(
            HmacEvidenceSigner("operator-1", "snapshot-key-2", rotated_key).sign(
                self._snapshot(),
                envelope_id="snapshot-envelope-rotated",
                issued_at=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=5),
            )
        )
        os.chmod(self.evidence_path, 0o600)
        with mock.patch.dict(
            os.environ,
            {
                "ECO_TEST_TRUST_KEY": KEY.decode("ascii"),
                "ECO_TEST_TRUST_KEY_2": rotated_key.decode("ascii"),
                "ECO_TEST_SNAPSHOT_EVIDENCE": str(self.evidence_path),
            },
            clear=False,
        ):
            result = runtime_trust_diagnostics(self.root, self.bundle, now=NOW)

        self.assertFalse(result["available"])
        self.assertEqual(
            result["checks"][-1]["code"],
            "ECO_RUNTIME_TRUST_SNAPSHOT_ISSUER_MISMATCH",
        )


if __name__ == "__main__":
    unittest.main()
