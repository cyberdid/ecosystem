from __future__ import annotations

import base64
import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from importlib import resources

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from eco_runtime.digests import canonical_json
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.policy_bundle import PolicyTrustAnchor
from eco_runtime.team_identity import identity_key_id
from eco_runtime.team_rotation import (
    TEAM_KEY_ROTATION_PROTOCOL,
    TeamKeyRotationVerifier,
    policy_trust_anchor_digest,
    team_key_rotation_replay_identity,
    team_key_rotation_signature_message,
)

from tests.m5_fixtures import PROJECT_ID, TEAM_ID, trust_anchor

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
ISSUED_AT = "2026-07-16T12:00:00Z"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_bytes(signer: Ed25519PrivateKey) -> bytes:
    return signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def new_anchor(
    signer: Ed25519PrivateKey,
    *,
    team_id: str = TEAM_ID,
    projects: tuple[str, ...] = (PROJECT_ID,),
    not_before: datetime = datetime(2026, 7, 15, tzinfo=timezone.utc),
    not_after: datetime = datetime(2026, 12, 1, tzinfo=timezone.utc),
) -> PolicyTrustAnchor:
    key = public_bytes(signer)
    return PolicyTrustAnchor(
        team_id=team_id,
        key_id=identity_key_id(key),
        public_key=key,
        allowed_project_ids=projects,
        not_before=not_before,
        not_after=not_after,
    )


def anchor_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rotation_bytes(
    old_signer: Ed25519PrivateKey,
    new_signer: Ed25519PrivateKey,
    current: PolicyTrustAnchor,
    expected_new: PolicyTrustAnchor,
    *,
    team_id: str = TEAM_ID,
    projects: tuple[str, ...] | None = None,
    issued_at: str = ISSUED_AT,
    nonce: bytes = b"n" * 32,
) -> bytes:
    project_ids = projects or expected_new.allowed_project_ids
    claims = {
        "protocol": TEAM_KEY_ROTATION_PROTOCOL,
        "teamId": team_id,
        "projectIds": list(project_ids),
        "oldAnchor": {
            "anchorDigest": policy_trust_anchor_digest(current),
            "keyId": current.key_id,
        },
        "newAnchor": {
            "anchorDigest": policy_trust_anchor_digest(expected_new),
            "keyId": expected_new.key_id,
            "publicKey": {
                "algorithm": "Ed25519",
                "encoding": "raw-base64url",
                "value": b64url(expected_new.public_key),
            },
            "validity": {
                "notBefore": anchor_time(expected_new.not_before),
                "notAfter": anchor_time(expected_new.not_after),
            },
        },
        "nonce": b64url(nonce),
        "issuedAt": issued_at,
    }
    body = {**claims, "rotationId": team_key_rotation_replay_identity(claims)}
    message = team_key_rotation_signature_message(body)
    envelope = {
        **body,
        "signatures": {
            "old": {
                "algorithm": "Ed25519",
                "keyId": current.key_id,
                "value": b64url(old_signer.sign(message)),
            },
            "new": {
                "algorithm": "Ed25519",
                "keyId": expected_new.key_id,
                "value": b64url(new_signer.sign(message)),
            },
        },
    }
    return canonical_json(envelope).encode("utf-8")


class TeamKeyRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_signer = Ed25519PrivateKey.generate()
        self.new_signer = Ed25519PrivateKey.generate()
        self.current = trust_anchor(self.old_signer)
        self.expected_new = new_anchor(self.new_signer)
        self.raw = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            self.expected_new,
        )
        self.verifier = TeamKeyRotationVerifier(self.current, self.expected_new)

    def verify(self, raw: bytes | None = None, *, now: datetime = NOW):
        return self.verifier.verify(
            self.raw if raw is None else raw,
            expected_project_id=PROJECT_ID,
            now=now,
        )

    def test_schema_is_valid(self) -> None:
        schema = json.loads(
            resources.files("eco_runtime")
            .joinpath("schemas", "team-key-rotation.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)

    def test_valid_rotation_is_immutable_sanitized_and_non_activating(self) -> None:
        verified = self.verify()
        self.assertTrue(verified.signatures_verified)
        self.assertFalse(verified.activation_eligible)
        self.assertFalse(verified.authority_created)
        self.assertEqual(verified.currentness, "not-established")
        self.assertEqual(verified.rotation_id, verified.replay_identity)
        self.assertEqual(verified.project_ids, (PROJECT_ID,))
        self.assertEqual(verified.old_key_id, self.current.key_id)
        self.assertEqual(verified.new_key_id, self.expected_new.key_id)
        raw_signatures = json.loads(self.raw)["signatures"]
        self.assertNotIn(raw_signatures["old"]["value"], repr(verified))
        self.assertNotIn(raw_signatures["new"]["value"], repr(verified))
        with self.assertRaises(FrozenInstanceError):
            verified.team_id = "team-other"

    def test_both_signatures_are_mandatory_and_bound_to_the_same_body(self) -> None:
        for missing in ("old", "new"):
            document = json.loads(self.raw)
            del document["signatures"][missing]
            with self.subTest(missing=missing), self.assertRaises(RuntimePolicyError):
                self.verify(canonical_json(document).encode("utf-8"))

        document = json.loads(self.raw)
        document["signatures"]["old"]["value"], document["signatures"]["new"][
            "value"
        ] = (
            document["signatures"]["new"]["value"],
            document["signatures"]["old"]["value"],
        )
        with self.assertRaises(RuntimePolicyError):
            self.verify(canonical_json(document).encode("utf-8"))

    def test_algorithm_confusion_fails_closed(self) -> None:
        for signature_name in ("old", "new"):
            document = json.loads(self.raw)
            document["signatures"][signature_name]["algorithm"] = "HMAC-SHA256"
            with self.subTest(signature=signature_name), self.assertRaises(
                RuntimePolicyError
            ) as caught:
                self.verify(canonical_json(document).encode("utf-8"))
            self.assertEqual(
                caught.exception.code, "ECO_TEAM_ROTATION_ALGORITHM_UNSUPPORTED"
            )

    def test_tamper_replay_recalculation_without_resigning_is_rejected(self) -> None:
        document = json.loads(self.raw)
        document["nonce"] = b64url(b"t" * 32)
        claims = {
            key: value
            for key, value in document.items()
            if key not in {"rotationId", "signatures"}
        }
        document["rotationId"] = team_key_rotation_replay_identity(claims)
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(canonical_json(document).encode("utf-8"))
        self.assertEqual(caught.exception.code, "ECO_TEAM_ROTATION_SIGNATURE_INVALID")

    def test_replay_identity_is_stable_and_nonce_specific(self) -> None:
        first = self.verify()
        repeated = self.verify()
        other_raw = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            self.expected_new,
            nonce=b"o" * 32,
        )
        other = self.verify(other_raw)
        self.assertEqual(first.replay_identity, repeated.replay_identity)
        self.assertEqual(first.envelope_digest, repeated.envelope_digest)
        self.assertNotEqual(first.replay_identity, other.replay_identity)

    def test_wrong_team_and_project_scope_are_rejected_even_when_signed(self) -> None:
        wrong_team = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            self.expected_new,
            team_id="team-other",
        )
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(wrong_team)
        self.assertEqual(caught.exception.code, "ECO_TEAM_ROTATION_TEAM_INVALID")

        wrong_project = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            self.expected_new,
            projects=("project-other",),
        )
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(wrong_project)
        self.assertEqual(caught.exception.code, "ECO_TEAM_ROTATION_PROJECT_UNTRUSTED")

        with self.assertRaises(RuntimePolicyError):
            self.verifier.verify(
                self.raw, expected_project_id="project-other", now=NOW
            )

    def test_wrong_current_or_externally_provisioned_new_anchor_is_rejected(self) -> None:
        attacker = Ed25519PrivateKey.generate()
        wrong_current = trust_anchor(attacker)
        with self.assertRaises(RuntimePolicyError):
            TeamKeyRotationVerifier(wrong_current, self.expected_new).verify(
                self.raw, expected_project_id=PROJECT_ID, now=NOW
            )

        wrong_new = new_anchor(attacker)
        with self.assertRaises(RuntimePolicyError) as caught:
            TeamKeyRotationVerifier(self.current, wrong_new).verify(
                self.raw, expected_project_id=PROJECT_ID, now=NOW
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_ROTATION_ANCHOR_MISMATCH")

    def test_issue_and_anchor_windows_are_enforced(self) -> None:
        stale_now = NOW + timedelta(minutes=16)
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(now=stale_now)
        self.assertEqual(
            caught.exception.code, "ECO_TEAM_ROTATION_EXPIRED_OR_NOT_YET_VALID"
        )

        future = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            self.expected_new,
            issued_at="2026-07-16T12:02:00Z",
        )
        with self.assertRaises(RuntimePolicyError):
            self.verify(future)

        future_new = new_anchor(
            self.new_signer,
            not_before=NOW + timedelta(minutes=1),
        )
        future_new_raw = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            future_new,
        )
        with self.assertRaises(RuntimePolicyError):
            TeamKeyRotationVerifier(self.current, future_new).verify(
                future_new_raw, expected_project_id=PROJECT_ID, now=NOW
            )

        long_lived = new_anchor(
            self.new_signer,
            not_after=datetime(2028, 1, 1, tzinfo=timezone.utc),
        )
        long_lived_raw = rotation_bytes(
            self.old_signer,
            self.new_signer,
            self.current,
            long_lived,
        )
        with self.assertRaises(RuntimePolicyError):
            TeamKeyRotationVerifier(self.current, long_lived).verify(
                long_lived_raw, expected_project_id=PROJECT_ID, now=NOW
            )

    def test_noncanonical_duplicate_bom_unknown_and_oversized_inputs_fail(self) -> None:
        unknown = json.loads(self.raw)
        unknown["privateKey"] = "must-not-leak"
        cases = [
            self.raw + b"\n",
            b"\xef\xbb\xbf" + self.raw,
            b'{"protocol":"a","protocol":"b"}',
            canonical_json(unknown).encode("utf-8"),
            b"{" + b" " * (64 * 1024) + b"}",
        ]
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(RuntimePolicyError):
                self.verify(raw)

    def test_failures_never_echo_keys_signatures_or_payload(self) -> None:
        document = json.loads(self.raw)
        canary = "secret-canary-do-not-echo"
        document["privateKey"] = canary
        with self.assertRaises(RuntimePolicyError) as caught:
            self.verify(canonical_json(document).encode("utf-8"))
        message = str(caught.exception)
        self.assertNotIn(canary, message)
        self.assertNotIn(self.current.public_key.hex(), message)
        self.assertNotIn(self.expected_new.public_key.hex(), message)


if __name__ == "__main__":
    unittest.main()
