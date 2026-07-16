from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.digests import canonical_json
from eco_runtime.policy_bundle import PolicyTrustAnchor, policy_signature_message
from eco_runtime.team_identity import (
    AUTHORITY_API_VERSION,
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


def key_record(team: dict, public_key: bytes) -> dict:
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
                "subject": binding(team),
                "purpose": "policy-signing",
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
