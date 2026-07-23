from __future__ import annotations

import base64
import copy
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimePolicyError
from eco_runtime.team_approval import (
    ResolvedApprovalKey,
    TeamApprovalVerifier,
    approval_record_digest,
    approval_vote_message,
    validate_team_approval_record,
)
from eco_runtime.team_identity import identity_key_id


NOW = datetime(2026, 7, 16, 12, 2, tzinfo=timezone.utc)
TEAM_DIGEST = semantic_digest("team-1")
POLICY_DIGEST = semantic_digest("policy-7")
REQUESTER_MEMBERSHIP = semantic_digest("requester-membership")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _finalize(record: dict) -> dict:
    record["metadata"]["recordDigest"] = approval_record_digest(record)
    return record


def approval_profile(*, quorum: int = 2) -> dict:
    return _finalize(
        {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "ApprovalProfile",
            "metadata": {
                "id": "profile-1",
                "createdAt": "2026-07-16T12:00:00Z",
                "recordDigest": "0" * 64,
            },
            "spec": {
                "purpose": "runtime-action",
                "team": {"id": "team-1", "digest": TEAM_DIGEST},
                "policy": {
                    "id": "policy-1",
                    "revision": 7,
                    "digest": POLICY_DIGEST,
                    "revocationEpoch": 3,
                },
                "requiredApproverRole": "approver",
                "quorum": quorum,
                "validity": {
                    "notBefore": "2026-07-16T11:00:00Z",
                    "notAfter": "2026-07-16T13:00:00Z",
                },
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def approval_request(profile: dict) -> dict:
    return _finalize(
        {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "TeamApprovalRequest",
            "metadata": {
                "id": "request-1",
                "createdAt": "2026-07-16T12:00:00Z",
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": {
                    "kind": "ApprovalProfile",
                    "id": profile["metadata"]["id"],
                    "digest": profile["metadata"]["recordDigest"],
                },
                "requester": {
                    "principalId": "requester-1",
                    "membershipDigest": REQUESTER_MEMBERSHIP,
                },
                "action": {
                    "capability": "workspace.write",
                    "actionClass": "A2",
                    "operation": "repository.replace",
                    "digest": semantic_digest("exact-action"),
                },
                "resource": {
                    "kind": "WorkspaceChangeProposal",
                    "id": "proposal-1",
                    "digest": semantic_digest("exact-resource"),
                },
                "snapshot": {
                    "kind": "RepositorySnapshot",
                    "id": "snapshot-1",
                    "digest": semantic_digest("exact-snapshot"),
                },
                "policy": copy.deepcopy(profile["spec"]["policy"]),
                "expiresAt": "2026-07-16T12:10:00Z",
                "safety": {
                    "humanApprovalRequired": True,
                    "permissionsGranted": False,
                },
            },
        }
    )


def approval_vote(
    profile: dict,
    request: dict,
    *,
    private_key: Ed25519PrivateKey,
    principal_id: str,
    membership_digest: str,
    suffix: str,
    decision: str = "approve",
) -> dict:
    key_id = identity_key_id(_public_key(private_key))
    vote = {
        "apiVersion": "authority.ai.ecosystem/v1alpha1",
        "kind": "TeamApprovalVote",
        "metadata": {
            "id": f"vote-{suffix}",
            "createdAt": "2026-07-16T12:01:00Z",
            "recordDigest": "0" * 64,
        },
        "spec": {
            "profile": {
                "kind": "ApprovalProfile",
                "id": profile["metadata"]["id"],
                "digest": profile["metadata"]["recordDigest"],
            },
            "request": {
                "kind": "TeamApprovalRequest",
                "id": request["metadata"]["id"],
                "digest": request["metadata"]["recordDigest"],
            },
            "approver": {
                "principalId": principal_id,
                "keyId": key_id,
                "membershipDigest": membership_digest,
            },
            "decision": decision,
            "issuedAt": "2026-07-16T12:01:00Z",
            "expiresAt": "2026-07-16T12:06:00Z",
            "signature": {"algorithm": "Ed25519", "value": "A" * 86},
        },
    }
    vote["spec"]["signature"]["value"] = _b64url(
        private_key.sign(approval_vote_message(vote))
    )
    return _finalize(vote)


class Resolver:
    def __init__(self, keys: list[ResolvedApprovalKey]):
        self.keys = {(item.principal_id, item.key_id): item for item in keys}
        self.calls: list[dict] = []

    def resolve_active_key(self, **arguments):
        self.calls.append(arguments)
        return self.keys.get((arguments["principal_id"], arguments["key_id"]))


class AtomicHook:
    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.intents = []

    def consume_team_action_permit(self, intent):
        self.intents.append(intent)
        if intent.permit_digest in self.seen:
            return None
        self.seen.add(intent.permit_digest)
        return semantic_digest(
            {
                "permit": intent.permit_digest,
                "consumedAt": intent.consumed_at.isoformat(),
            }
        )


class TeamApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = approval_profile()
        self.request = approval_request(self.profile)
        self.private_keys = {
            "approver-1": Ed25519PrivateKey.from_private_bytes(b"a" * 32),
            "approver-2": Ed25519PrivateKey.from_private_bytes(b"b" * 32),
            "requester-1": Ed25519PrivateKey.from_private_bytes(b"r" * 32),
        }
        self.memberships = {
            principal: semantic_digest(f"membership:{principal}")
            for principal in self.private_keys
        }
        resolved = [self._resolved(name) for name in self.private_keys]
        self.resolver = Resolver(resolved)
        self.verifier = TeamApprovalVerifier(self.resolver)

    def _resolved(
        self, principal_id: str, *, key: Ed25519PrivateKey | None = None,
        roles: tuple[str, ...] = ("approver",)
    ) -> ResolvedApprovalKey:
        private_key = key or self.private_keys[principal_id]
        public_key = _public_key(private_key)
        return ResolvedApprovalKey(
            team_id="team-1",
            principal_id=principal_id,
            key_id=identity_key_id(public_key),
            membership_digest=self.memberships[principal_id],
            roles=roles,
            policy_digest=POLICY_DIGEST,
            revocation_epoch=3,
            not_before=NOW - timedelta(hours=1),
            not_after=NOW + timedelta(hours=1),
            public_key=public_key,
        )

    def _vote(self, principal_id: str, suffix: str | None = None, **changes) -> dict:
        return approval_vote(
            self.profile,
            self.request,
            private_key=changes.pop("private_key", self.private_keys[principal_id]),
            principal_id=principal_id,
            membership_digest=changes.pop(
                "membership_digest", self.memberships[principal_id]
            ),
            suffix=suffix or principal_id[-1],
            **changes,
        )

    def _verify_with(
        self,
        verifier: TeamApprovalVerifier,
        vote: dict,
        *,
        request: dict | None = None,
        now: datetime = NOW,
    ):
        return verifier.verify_vote(
            self.profile,
            request or self.request,
            vote,
            expected_requester_principal_id="requester-1",
            expected_requester_membership_digest=REQUESTER_MEMBERSHIP,
            now=now,
        )

    def _build_with(
        self,
        verifier: TeamApprovalVerifier,
        votes: list[dict],
        *,
        permit_id: str,
        nonce: bytes,
    ):
        return verifier.build_action_permit(
            self.profile,
            self.request,
            votes,
            permit_id=permit_id,
            consumption_nonce=nonce,
            expected_requester_principal_id="requester-1",
            expected_requester_membership_digest=REQUESTER_MEMBERSHIP,
            now=NOW,
        )

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimePolicyError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), "Team approval verification failed closed")

    def test_closed_contracts_and_non_self_referential_digests(self) -> None:
        self.assertEqual(validate_team_approval_record(self.profile), self.profile)
        self.assertEqual(validate_team_approval_record(self.request), self.request)
        changed = copy.deepcopy(self.request)
        changed["spec"]["snapshot"]["digest"] = semantic_digest("other-snapshot")
        self.assertNotEqual(approval_record_digest(changed), self.request["metadata"]["recordDigest"])

        unknown = copy.deepcopy(self.request)
        unknown["spec"]["rawPath"] = "customer/private/secret.txt"
        unknown["metadata"]["recordDigest"] = approval_record_digest(unknown)
        with self.assertRaises(ContractValidationError) as caught:
            validate_team_approval_record(unknown)
        self.assertNotIn("customer/private/secret.txt", str(caught.exception))

        invalid_time = copy.deepcopy(self.profile)
        invalid_time["spec"]["validity"]["notAfter"] = "2026-07-16T10:00:00Z"
        invalid_time["metadata"]["recordDigest"] = approval_record_digest(invalid_time)
        with self.assertRaises(ContractValidationError):
            validate_team_approval_record(invalid_time)

    def test_ed25519_vote_uses_external_active_key_and_exact_bindings(self) -> None:
        vote = self._vote("approver-1")
        verified = self._verify_with(self.verifier, vote)
        self.assertTrue(verified.signature_verified)
        self.assertFalse(verified.authority_created)
        self.assertEqual(verified.request_digest, self.request["metadata"]["recordDigest"])
        call = self.resolver.calls[-1]
        self.assertEqual(call["policy_digest"], POLICY_DIGEST)
        self.assertEqual(call["revocation_epoch"], 3)
        self.assertEqual(call["profile_digest"], self.profile["metadata"]["recordDigest"])
        self.assertEqual(call["required_role"], "approver")
        self.assertEqual(call["quorum"], 2)

        tampered = copy.deepcopy(vote)
        tampered["spec"]["decision"] = "deny"
        tampered["metadata"]["recordDigest"] = approval_record_digest(tampered)
        self.assert_code(
            "ECO_TEAM_APPROVAL_SIGNATURE_INVALID",
            lambda: self._verify_with(self.verifier, tampered),
        )

        changed_request = copy.deepcopy(self.request)
        changed_request["spec"]["resource"]["digest"] = semantic_digest("other-resource")
        changed_request["metadata"]["recordDigest"] = approval_record_digest(changed_request)
        self.assert_code(
            "ECO_TEAM_APPROVAL_BINDING_INVALID",
            lambda: self._verify_with(
                self.verifier, vote, request=changed_request
            ),
        )

    def test_requester_cannot_approve_and_untrusted_or_wrong_role_key_fails(self) -> None:
        requester_vote = self._vote("requester-1", "requester")
        self.assert_code(
            "ECO_TEAM_APPROVAL_REQUESTER_CONFLICT",
            lambda: self._verify_with(self.verifier, requester_vote),
        )
        self.assert_code(
            "ECO_TEAM_APPROVAL_BINDING_INVALID",
            lambda: self.verifier.verify_vote(
                self.profile,
                self.request,
                self._vote("approver-1"),
                expected_requester_principal_id="forged-requester",
                expected_requester_membership_digest=REQUESTER_MEMBERSHIP,
                now=NOW,
            ),
        )

        missing = TeamApprovalVerifier(Resolver([]))
        self.assert_code(
            "ECO_TEAM_APPROVAL_KEY_UNTRUSTED",
            lambda: self._verify_with(missing, self._vote("approver-1")),
        )

        wrong_role = TeamApprovalVerifier(
            Resolver([self._resolved("approver-1", roles=("viewer",))])
        )
        self.assert_code(
            "ECO_TEAM_APPROVAL_KEY_UNTRUSTED",
            lambda: self._verify_with(wrong_role, self._vote("approver-1")),
        )

    def test_quorum_counts_distinct_principals_and_copies_exact_subject(self) -> None:
        raw_votes = [
            self._vote(principal)
            for principal in ("approver-1", "approver-2")
        ]
        permit = self._build_with(
            self.verifier,
            raw_votes,
            permit_id="permit-1",
            nonce=b"n" * 32,
        )
        record = permit.as_dict()
        self.assertEqual(validate_team_approval_record(record), record)
        self.assertEqual(record["spec"]["action"], self.request["spec"]["action"])
        self.assertEqual(record["spec"]["resource"], self.request["spec"]["resource"])
        self.assertEqual(record["spec"]["snapshot"], self.request["spec"]["snapshot"])
        self.assertEqual(record["spec"]["policy"], self.request["spec"]["policy"])
        self.assertEqual(
            [item["principalId"] for item in record["spec"]["approvers"]],
            ["approver-1", "approver-2"],
        )
        self.assertFalse(record["spec"]["safety"]["runtimeAuthorityCreated"])

        self.assert_code(
            "ECO_TEAM_APPROVAL_QUORUM",
            lambda: self._build_with(
                self.verifier,
                raw_votes[:1],
                permit_id="permit-short",
                nonce=b"s" * 32,
            ),
        )
        self.assert_code(
            "ECO_TEAM_APPROVAL_DUPLICATE_PRINCIPAL",
            lambda: self._build_with(
                self.verifier,
                [raw_votes[0], raw_votes[0]],
                permit_id="permit-duplicate",
                nonce=b"d" * 32,
            ),
        )

    def test_deny_vote_cannot_form_permit_and_two_keys_are_not_two_people(self) -> None:
        approved = self._vote("approver-1")
        denied = self._vote("approver-2", decision="deny")
        self.assert_code(
            "ECO_TEAM_APPROVAL_VOTE_DENIED",
            lambda: self._build_with(
                self.verifier,
                [approved, denied],
                permit_id="permit-denied",
                nonce=b"x" * 32,
            ),
        )

        second_key = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
        second_resolved = self._resolved("approver-1", key=second_key)
        resolver = Resolver([self._resolved("approver-1"), second_resolved])
        verifier = TeamApprovalVerifier(resolver)
        first = self._vote("approver-1", "key-a")
        second_vote = self._vote(
            "approver-1", "key-c", private_key=second_key
        )
        self.assert_code(
            "ECO_TEAM_APPROVAL_DUPLICATE_PRINCIPAL",
            lambda: self._build_with(
                verifier,
                [first, second_vote],
                permit_id="permit-two-keys",
                nonce=b"k" * 32,
            ),
        )

    def test_immutable_permit_requires_atomic_single_use_store_hook(self) -> None:
        votes = [
            self._vote(principal)
            for principal in ("approver-1", "approver-2")
        ]
        permit = self._build_with(
            self.verifier,
            votes,
            permit_id="permit-consume",
            nonce=b"z" * 32,
        )
        with self.assertRaises(TypeError):
            permit.record["spec"]["quorum"] = 1
        hook = AtomicHook()
        consumed = permit.consume_with(hook, now=NOW + timedelta(seconds=1))
        self.assertEqual(consumed.permit_digest, permit.permit_digest)
        self.assertEqual(len(hook.intents), 1)
        self.assertEqual(
            hook.intents[0].snapshot_digest,
            self.request["spec"]["snapshot"]["digest"],
        )
        self.assert_code(
            "ECO_TEAM_APPROVAL_PERMIT_CONSUMED",
            lambda: permit.consume_with(hook, now=NOW + timedelta(seconds=2)),
        )

        self.assert_code(
            "ECO_TEAM_APPROVAL_EXPIRED",
            lambda: permit.consume_with(
                hook, now=datetime(2026, 7, 16, 12, 6, tzinfo=timezone.utc)
            ),
        )


if __name__ == "__main__":
    unittest.main()
