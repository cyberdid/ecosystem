from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.digests import canonical_json
from eco_runtime.policy_bundle import PolicyTrustAnchor, policy_signature_message
from eco_runtime.team_access import team_access_binding_id, team_access_policy_digest
from eco_runtime.team_approval import approval_record_digest
from eco_runtime.team_identity import (
    AUTHORITY_API_VERSION,
    approval_policy_context_digest,
    authority_record_digest,
    identity_key_fingerprint,
    identity_key_id,
    membership_binding_id,
)

CREATED = "2026-07-16T12:00:00Z"
NOT_BEFORE = "2026-07-01T00:00:00Z"
NOT_AFTER = "2026-08-01T00:00:00Z"
POLICY_NOT_BEFORE = "2026-07-16T00:00:00Z"
PROJECT_ID = "project-alpha"
TEAM_ID = "team-alpha"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def seal(record: dict) -> dict:
    record["metadata"]["recordDigest"] = authority_record_digest(record)
    return record


def binding(record: dict) -> dict:
    return {
        "kind": record["kind"],
        "id": record["metadata"]["id"],
        "digest": record["metadata"]["recordDigest"],
    }


def team_record() -> dict:
    return seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "TeamIdentity",
            "metadata": {
                "id": TEAM_ID,
                "version": 1,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "status": "active",
                "validity": {"notBefore": NOT_BEFORE, "notAfter": NOT_AFTER},
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def principal_record(*, identifier: str = "principal-alice", principal_type: str = "human") -> dict:
    controller = None
    if principal_type != "human":
        controller = binding(team_record())
    return seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "PrincipalIdentity",
            "metadata": {
                "id": identifier,
                "version": 1,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "type": principal_type,
                "status": "active",
                "validity": {"notBefore": NOT_BEFORE, "notAfter": NOT_AFTER},
                "controller": controller,
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def membership_record(team: dict, principal: dict) -> dict:
    return seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "MembershipBinding",
            "metadata": {
                "id": membership_binding_id(
                    team["metadata"]["id"], principal["metadata"]["id"]
                ),
                "version": 1,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "team": binding(team),
                "principal": binding(principal),
                "status": "active",
                "validity": {"notBefore": NOT_BEFORE, "notAfter": NOT_AFTER},
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def key_record(
    subject: dict, public_key: bytes, *, purpose: str = "policy-signing"
) -> dict:
    fingerprint = identity_key_fingerprint(public_key)
    return seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "IdentityKey",
            "metadata": {
                "id": identity_key_id(public_key),
                "version": 1,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "subject": binding(subject),
                "purpose": purpose,
                "algorithm": "Ed25519",
                "publicKey": {"encoding": "raw-base64url", "value": b64url(public_key)},
                "fingerprint": {"algorithm": "SHA-256", "digest": fingerprint},
                "status": "active",
                "validity": {"notBefore": NOT_BEFORE, "notAfter": NOT_AFTER},
                "safety": {
                    "privateKeyPresent": False,
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                },
            },
        }
    )


def policy_bundle(private_key: Ed25519PrivateKey | None = None, *, revision: int = 1) -> tuple[dict, Ed25519PrivateKey]:
    signer = private_key or Ed25519PrivateKey.generate()
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    team = team_record()
    principal = principal_record()
    membership = membership_record(team, principal)
    key = key_record(team, public_key)
    previous = None
    if revision > 1:
        previous = {"revision": revision - 1, "digest": "a" * 64}
    bundle = seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "TeamPolicyBundle",
            "metadata": {
                "id": "team-policy-alpha",
                "revision": revision,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": "identity-catalog-only",
                "authorityMode": "deny-all",
                "team": binding(team),
                "targetProjectIds": [PROJECT_ID],
                "validity": {
                    "notBefore": POLICY_NOT_BEFORE,
                    "notAfter": NOT_AFTER,
                },
                "previous": previous,
                "documents": {
                    "teams": [team],
                    "principals": [principal],
                    "memberships": [membership],
                    "keys": [key],
                },
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                    "policyActivated": False,
                    "privateKeyPresent": False,
                },
            },
        }
    )
    return bundle, signer


def envelope_bytes(
    bundle: dict,
    signer: Ed25519PrivateKey,
    *,
    team_id: str = TEAM_ID,
    key_id: str | None = None,
    issued_at: str = CREATED,
) -> bytes:
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    body = {
        "protocol": "eco-team-policy-envelope-v1",
        "envelopeId": "envelope-alpha",
        "issuer": {"teamId": team_id, "keyId": key_id or identity_key_id(public_key)},
        "issuedAt": issued_at,
        "subject": {
            "kind": "TeamPolicyBundle",
            "id": bundle["metadata"]["id"],
            "revision": bundle["metadata"]["revision"],
            "digest": bundle["metadata"]["recordDigest"],
        },
        "bundle": copy.deepcopy(bundle),
    }
    signature = signer.sign(policy_signature_message(body))
    envelope = {**body, "signature": {"algorithm": "Ed25519", "value": b64url(signature)}}
    return canonical_json(envelope).encode("utf-8")


def trust_anchor(signer: Ed25519PrivateKey) -> PolicyTrustAnchor:
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PolicyTrustAnchor(
        team_id=TEAM_ID,
        key_id=identity_key_id(public_key),
        public_key=public_key,
        allowed_project_ids=(PROJECT_ID,),
        not_before=datetime(2026, 7, 1, tzinfo=timezone.utc),
        not_after=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )


def bounded_policy_bundle(
    *,
    runtime_subject_digest: str,
    runtime_write_subject_digest: str | None = None,
    policy_signer: Ed25519PrivateKey | None = None,
) -> tuple[
    dict,
    Ed25519PrivateKey,
    dict[str, Ed25519PrivateKey],
    dict[str, Ed25519PrivateKey],
]:
    policy_signer = policy_signer or Ed25519PrivateKey.from_private_bytes(b"p" * 32)
    approval_signers = {
        "approver-1": Ed25519PrivateKey.from_private_bytes(b"a" * 32),
        "approver-2": Ed25519PrivateKey.from_private_bytes(b"b" * 32),
    }
    actor_signers = {
        "approver-1": Ed25519PrivateKey.from_private_bytes(b"c" * 32),
        "approver-2": Ed25519PrivateKey.from_private_bytes(b"d" * 32),
        "requester-1": Ed25519PrivateKey.from_private_bytes(b"r" * 32),
    }
    team = team_record()
    principals = [
        principal_record(identifier=identifier)
        for identifier in ("approver-1", "approver-2", "requester-1")
    ]
    principal_by_id = {item["metadata"]["id"]: item for item in principals}
    memberships = [membership_record(team, item) for item in principals]
    membership_by_principal = {
        item["spec"]["principal"]["id"]: item for item in memberships
    }
    policy_public = policy_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keys = [key_record(team, policy_public)]
    for principal_id, signer in approval_signers.items():
        public_key = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        keys.append(
            key_record(
                principal_by_id[principal_id],
                public_key,
                purpose="approval-signing",
            )
        )
    for principal_id, signer in actor_signers.items():
        public_key = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        keys.append(
            key_record(
                principal_by_id[principal_id],
                public_key,
                purpose="workload-authentication",
            )
        )

    team_binding = binding(team)
    policy_context = {
        "id": "access-project-alpha",
        "revision": 1,
        "digest": approval_policy_context_digest(
            bundle_id="team-policy-alpha",
            bundle_revision=1,
            team=team_binding,
            target_project_ids=[PROJECT_ID],
            access_policy_id="access-project-alpha",
            access_policy_revision=1,
        ),
        "revocationEpoch": 0,
    }
    approval_profile = {
        "apiVersion": AUTHORITY_API_VERSION,
        "kind": "ApprovalProfile",
        "metadata": {
            "id": "profile-writers",
            "createdAt": CREATED,
            "recordDigest": "0" * 64,
        },
        "spec": {
            "purpose": "runtime-action",
            "team": {"id": team["metadata"]["id"], "digest": team["metadata"]["recordDigest"]},
            "policy": policy_context,
            "requiredApproverRole": "approver",
            "quorum": 2,
            "validity": {
                "notBefore": POLICY_NOT_BEFORE,
                "notAfter": "2026-07-31T00:00:00Z",
            },
            "safety": {
                "permissionsGranted": False,
                "runtimeAuthorityCreated": False,
            },
        },
    }
    approval_profile["metadata"]["recordDigest"] = approval_record_digest(
        approval_profile
    )
    recovery_profile = copy.deepcopy(approval_profile)
    recovery_profile["metadata"]["id"] = "profile-recovery"
    recovery_profile["metadata"]["recordDigest"] = "0" * 64
    recovery_profile["spec"]["purpose"] = "emergency-recovery"
    recovery_profile["metadata"]["recordDigest"] = approval_record_digest(
        recovery_profile
    )

    def actor_binding(principal_id: str, role_id: str) -> dict:
        principal_binding = binding(principal_by_id[principal_id])
        membership_binding = binding(membership_by_principal[principal_id])
        return {
            "id": team_access_binding_id(
                principal_binding, membership_binding, role_id
            ),
            "principal": principal_binding,
            "membership": membership_binding,
            "roleId": role_id,
        }

    def constraints(data_classes: list[str]) -> dict:
        return {
            "projectId": PROJECT_ID,
            "environmentId": "development",
            "dataClasses": data_classes,
            "notBefore": POLICY_NOT_BEFORE,
            "notAfter": "2026-07-31T00:00:00Z",
        }

    exact_read_resource = {
        "kind": "repository-entry",
        "id": "operation-1",
        "digest": runtime_subject_digest,
    }
    exact_write_resource = {
        "kind": "repository-entry",
        "id": "operation-1",
        "digest": runtime_write_subject_digest or runtime_subject_digest,
    }
    access_policy = {
        "apiVersion": AUTHORITY_API_VERSION,
        "kind": "TeamAccessPolicy",
        "metadata": {
            "id": "access-project-alpha",
            "revision": 1,
            "createdAt": CREATED,
            "recordDigest": "0" * 64,
        },
        "spec": {
            "profile": "bounded-team-access-v1",
            "defaultEffect": "deny",
            "roles": [
                {
                    "id": "approver",
                    "statements": [
                        {
                            "id": "inspect-policy",
                            "effect": "allow",
                            "action": "policy.inspect",
                            "actionClass": "A0",
                            "resource": {
                                "kind": "policy-record",
                                "id": "approval-scope",
                                "digest": "d" * 64,
                            },
                            "constraints": constraints(["D0"]),
                            "approvalProfile": None,
                        }
                    ],
                },
                {
                    "id": "operator",
                    "statements": [
                        {
                            "id": "read-operation",
                            "effect": "allow",
                            "action": "repository.read",
                            "actionClass": "A1",
                            "resource": copy.deepcopy(exact_read_resource),
                            "constraints": constraints(["D0", "D1"]),
                            "approvalProfile": None,
                        },
                        {
                            "id": "write-operation",
                            "effect": "allow",
                            "action": "repository.write",
                            "actionClass": "A2",
                            "resource": copy.deepcopy(exact_write_resource),
                            "constraints": constraints(["D0", "D1"]),
                            "approvalProfile": {
                                "kind": "ApprovalProfile",
                                "id": approval_profile["metadata"]["id"],
                                "digest": approval_profile["metadata"]["recordDigest"],
                            },
                        },
                    ],
                },
            ],
            "bindings": sorted(
                [
                    actor_binding("approver-1", "approver"),
                    actor_binding("approver-2", "approver"),
                    actor_binding("requester-1", "operator"),
                ],
                key=lambda item: item["id"],
            ),
            "safety": {
                "maximumAllowActionClass": "A2",
                "d4AllowDenied": True,
                "highImpactAllowDenied": True,
                "wildcardsAllowed": False,
                "roleInheritanceAllowed": False,
                "standaloneAuthorityCreated": False,
            },
        },
    }
    access_policy["metadata"]["recordDigest"] = team_access_policy_digest(
        access_policy
    )

    bundle = seal(
        {
            "apiVersion": AUTHORITY_API_VERSION,
            "kind": "TeamPolicyBundle",
            "metadata": {
                "id": "team-policy-alpha",
                "revision": 1,
                "createdAt": CREATED,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": "bounded-team-access-v1",
                "authorityMode": "narrowing-only",
                "team": team_binding,
                "targetProjectIds": [PROJECT_ID],
                "validity": {
                    "notBefore": POLICY_NOT_BEFORE,
                    "notAfter": NOT_AFTER,
                },
                "previous": None,
                "documents": {
                    "teams": [team],
                    "principals": sorted(
                        principals, key=lambda item: item["metadata"]["id"]
                    ),
                    "memberships": sorted(
                        memberships, key=lambda item: item["metadata"]["id"]
                    ),
                    "keys": sorted(keys, key=lambda item: item["metadata"]["id"]),
                    "accessPolicies": [access_policy],
                    "approvalProfiles": sorted(
                        [approval_profile, recovery_profile],
                        key=lambda item: item["metadata"]["id"],
                    ),
                },
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                    "policyActivated": False,
                    "privateKeyPresent": False,
                },
            },
        }
    )
    return bundle, policy_signer, approval_signers, actor_signers
