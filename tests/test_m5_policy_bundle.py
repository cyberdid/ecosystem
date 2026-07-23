from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.digests import canonical_json
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.policy_bundle import PolicyTrustAnchor, TeamPolicyVerifier

from tests.m5_fixtures import (
    PROJECT_ID,
    envelope_bytes,
    policy_bundle,
    seal,
    trust_anchor,
)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def parsed(raw: bytes) -> dict:
    return json.loads(raw)


class SignedTeamPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle, self.signer = policy_bundle()
        self.raw = envelope_bytes(self.bundle, self.signer)
        self.anchor = trust_anchor(self.signer)
        self.verifier = TeamPolicyVerifier(self.anchor)

    def verify(self, raw: bytes | None = None):
        return self.verifier.verify(
            self.raw if raw is None else raw,
            expected_project_id=PROJECT_ID,
            now=NOW,
        )

    def test_valid_signature_returns_immutable_non_authorizing_result(self) -> None:
        result = self.verify()
        self.assertTrue(result.signature_verified)
        self.assertFalse(result.activation_eligible)
        self.assertFalse(result.authority_created)
        self.assertEqual(result.currentness, "not-established")
        self.assertEqual(result.revision, 1)
        with self.assertRaises(TypeError):
            result.bundle["kind"] = "Other"
        with self.assertRaises(FrozenInstanceError):
            result.revision = 2

    def test_tampering_signed_body_or_signature_fails(self) -> None:
        for mutation in ("bundle", "subject", "issuer", "signature"):
            document = parsed(self.raw)
            if mutation == "bundle":
                document["bundle"]["metadata"]["id"] = "tampered"
            elif mutation == "subject":
                document["subject"]["revision"] = 2
            elif mutation == "issuer":
                document["issuer"]["teamId"] = "team-attacker"
            else:
                original = document["signature"]["value"]
                flipped = "B" if original.startswith("A") else "A"
                document["signature"]["value"] = flipped + original[1:]
            raw = canonical_json(document).encode("utf-8")
            with self.subTest(mutation=mutation), self.assertRaises(RuntimePolicyError):
                self.verify(raw)

    def test_algorithm_confusion_and_unknown_envelope_fields_fail(self) -> None:
        document = parsed(self.raw)
        document["signature"]["algorithm"] = "HMAC-SHA256"
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(canonical_json(document).encode("utf-8"))
        self.assertEqual(caught.exception.code, "ECO_TEAM_POLICY_ALGORITHM_UNSUPPORTED")

        document = parsed(self.raw)
        document["privateKey"] = "must-not-leak"
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(canonical_json(document).encode("utf-8"))
        self.assertNotIn("must-not-leak", str(caught.exception))

    def test_noncanonical_duplicate_bom_and_oversized_inputs_fail(self) -> None:
        cases = [
            self.raw + b"\n",
            b"\xef\xbb\xbf" + self.raw,
            b'{"protocol":"a","protocol":"b"}',
            b"{" + b" " * (2 * 1024 * 1024) + b"}",
        ]
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(RuntimePolicyError):
                self.verify(raw)

    def test_untrusted_key_cannot_self_bootstrap_from_bundle(self) -> None:
        attacker_bundle, attacker = policy_bundle(Ed25519PrivateKey.generate())
        attacker_raw = envelope_bytes(attacker_bundle, attacker)
        with self.assertRaises(RuntimePolicyError):
            self.verify(attacker_raw)

    def test_wrong_project_and_trust_anchor_are_rejected(self) -> None:
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verifier.verify(self.raw, expected_project_id="project-other", now=NOW)
        self.assertEqual(caught.exception.code, "ECO_TEAM_POLICY_PROJECT_UNTRUSTED")

        attacker = Ed25519PrivateKey.generate()
        wrong_anchor = trust_anchor(attacker)
        with self.assertRaises(RuntimePolicyError):
            TeamPolicyVerifier(wrong_anchor).verify(
                self.raw, expected_project_id=PROJECT_ID, now=NOW
            )

    def test_policy_and_anchor_validity_are_enforced(self) -> None:
        with self.assertRaises(RuntimePolicyError) as expired:
            self.verifier.verify(
                self.raw,
                expected_project_id=PROJECT_ID,
                now=datetime(2026, 8, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(expired.exception.code, "ECO_TEAM_POLICY_EXPIRED_OR_NOT_YET_VALID")

        future_raw = envelope_bytes(
            self.bundle, self.signer, issued_at="2026-07-16T12:02:00Z"
        )
        with self.assertRaises(RuntimePolicyError):
            self.verify(future_raw)

        too_short_anchor = PolicyTrustAnchor(
            team_id=self.anchor.team_id,
            key_id=self.anchor.key_id,
            public_key=self.anchor.public_key,
            allowed_project_ids=self.anchor.allowed_project_ids,
            not_before=NOW - timedelta(days=2),
            not_after=NOW - timedelta(days=1),
        )
        with self.assertRaises(RuntimePolicyError):
            TeamPolicyVerifier(too_short_anchor).verify(
                self.raw, expected_project_id=PROJECT_ID, now=NOW
            )

        created_after_issue = copy.deepcopy(self.bundle)
        created_after_issue["metadata"]["createdAt"] = "2026-07-16T12:03:00Z"
        seal(created_after_issue)
        with self.assertRaises(RuntimePolicyError):
            self.verify(envelope_bytes(created_after_issue, self.signer))

        anchor_expires_first = PolicyTrustAnchor(
            team_id=self.anchor.team_id,
            key_id=self.anchor.key_id,
            public_key=self.anchor.public_key,
            allowed_project_ids=self.anchor.allowed_project_ids,
            not_before=NOW - timedelta(days=2),
            not_after=datetime(2026, 7, 20, tzinfo=timezone.utc),
        )
        with self.assertRaises(RuntimePolicyError):
            TeamPolicyVerifier(anchor_expires_first).verify(
                self.raw, expected_project_id=PROJECT_ID, now=NOW
            )

    def test_expected_predecessor_is_an_explicit_non_activation_check(self) -> None:
        bundle, signer = policy_bundle(revision=2)
        verifier = TeamPolicyVerifier(trust_anchor(signer))
        raw = envelope_bytes(bundle, signer)
        result = verifier.verify(
            raw,
            expected_project_id=PROJECT_ID,
            now=NOW,
            expected_previous=(1, "a" * 64),
        )
        self.assertFalse(result.activation_eligible)
        with self.assertRaises(RuntimePolicyError) as caught:
            verifier.verify(
                raw,
                expected_project_id=PROJECT_ID,
                now=NOW,
                expected_previous=(1, "b" * 64),
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_POLICY_PREDECESSOR_MISMATCH")

    def test_errors_do_not_echo_signature_key_or_payload(self) -> None:
        document = parsed(self.raw)
        canary = "secret-canary-do-not-echo"
        document["signature"]["value"] = canary
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(canonical_json(document).encode("utf-8"))
        message = str(caught.exception)
        self.assertNotIn(canary, message)
        self.assertNotIn(self.anchor.public_key.hex(), message)


if __name__ == "__main__":
    unittest.main()
