from __future__ import annotations

"""Parameter-bound human approval primitives.

``ApprovalSigner`` is a deliberately small HMAC reference adapter for an
embedded/single-user deployment.  Production deployments must put a WebAuthn,
OIDC, or equivalent independently authenticated human-identity adapter behind
``ApprovalTrustStore``; the journal never treats possession of its own audit
key as evidence of human approval.
"""

import copy
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .digests import canonical_json, semantic_digest
from .errors import RuntimeStoreError


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ASSURANCE = frozenset(
    {"local-os-session", "webauthn", "hardware-backed", "federated-mfa"}
)
_ENVELOPE_FIELDS = frozenset(
    {
        "protocol",
        "approvalId",
        "subjectDigest",
        "humanId",
        "assurance",
        "keyId",
        "challengeNonce",
        "issuedAt",
        "expiresAt",
        "signature",
    }
)


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("approval timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise RuntimeStoreError("ECO_APPROVAL_INVALID", f"Approval {field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise RuntimeStoreError("ECO_APPROVAL_INVALID", f"Approval {field} is invalid")
    return value


def approval_subject_payload(
    *,
    store_id: str,
    project_id: str,
    run_id: str,
    plan_digest: str,
    policy_decision_digest: str,
    proposal_digest: str,
    action_class: str,
    operation_kind: str,
    root_identity_digest: str,
    base_digest: str,
    target_ref_digest: str,
    desired_digest: str,
    rollback_digest: str,
    display_digest: str,
    limits_digest: str,
) -> dict[str, str]:
    """Return the complete, non-wildcard approval subject.

    Every write-affecting parameter is represented.  Callers cannot approve a
    path prefix, a future patch, or a mutable display summary.
    """

    if action_class != "A2":
        raise RuntimeStoreError("ECO_APPROVAL_SCOPE", "Single-file workspace writes require A2")
    if operation_kind not in {"create", "replace"}:
        raise RuntimeStoreError("ECO_APPROVAL_SCOPE", "Write kind must be create or replace")
    return {
        "domain": "eco-change-approval-subject-v1",
        "storeId": _identifier(store_id, "store id"),
        "projectId": _identifier(project_id, "project id"),
        "runId": _identifier(run_id, "run id"),
        "planDigest": _digest(plan_digest, "plan digest"),
        "policyDecisionDigest": _digest(policy_decision_digest, "policy decision digest"),
        "proposalDigest": _digest(proposal_digest, "proposal digest"),
        "actionClass": action_class,
        "operationKind": operation_kind,
        "rootIdentityDigest": _digest(root_identity_digest, "root identity digest"),
        "baseDigest": _digest(base_digest, "base digest"),
        "targetRefDigest": _digest(target_ref_digest, "target reference digest"),
        "desiredDigest": _digest(desired_digest, "desired digest"),
        "rollbackDigest": _digest(rollback_digest, "rollback digest"),
        "displayDigest": _digest(display_digest, "display digest"),
        "limitsDigest": _digest(limits_digest, "limits digest"),
    }


def approval_subject_digest(**fields: str) -> str:
    return semantic_digest(approval_subject_payload(**fields))


@dataclass(frozen=True)
class ApprovalKeyPolicy:
    key_id: str
    human_id: str
    assurance: str
    verification_key: bytes

    def __post_init__(self) -> None:
        _identifier(self.key_id, "key id")
        _identifier(self.human_id, "human id")
        if self.assurance not in _ASSURANCE:
            raise ValueError("unsupported approval assurance")
        if not isinstance(self.verification_key, bytes) or len(self.verification_key) < 32:
            raise ValueError("approval verification key must contain at least 32 bytes")


@dataclass(frozen=True)
class VerifiedApproval:
    envelope: dict[str, Any]
    envelope_digest: str


def _signed_payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {name: envelope[name] for name in sorted(_ENVELOPE_FIELDS - {"signature"})}


class ApprovalSigner:
    """HMAC reference signer standing in for an authenticated human adapter."""

    def __init__(self, policy: ApprovalKeyPolicy):
        self._policy = policy

    def sign(
        self,
        *,
        approval_id: str,
        subject_digest: str,
        challenge_nonce: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any]:
        if expires_at.astimezone(timezone.utc) <= issued_at.astimezone(timezone.utc):
            raise ValueError("approval expiry must follow issue time")
        envelope: dict[str, Any] = {
            "protocol": "eco-approval-envelope-v1",
            "approvalId": _identifier(approval_id, "id"),
            "subjectDigest": _digest(subject_digest, "subject digest"),
            "humanId": self._policy.human_id,
            "assurance": self._policy.assurance,
            "keyId": self._policy.key_id,
            "challengeNonce": _identifier(challenge_nonce, "challenge nonce"),
            "issuedAt": _utc(issued_at),
            "expiresAt": _utc(expires_at),
        }
        envelope["signature"] = hmac.new(
            self._policy.verification_key,
            canonical_json(_signed_payload(envelope)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return copy.deepcopy(envelope)


class ApprovalTrustStore:
    """Verify approval envelopes against configured identity/assurance policy."""

    def __init__(self, policies: Mapping[str, ApprovalKeyPolicy]):
        self._policies = dict(policies)
        if not self._policies or any(key != policy.key_id for key, policy in self._policies.items()):
            raise ValueError("approval policies must be keyed by their exact key id")

    def _verify_signature(
        self, envelope: Mapping[str, Any], *, expected_subject_digest: str
    ) -> tuple[dict[str, Any], datetime, datetime, ApprovalKeyPolicy]:
        if not isinstance(envelope, Mapping) or set(envelope) != _ENVELOPE_FIELDS:
            raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval envelope shape is invalid")
        candidate = copy.deepcopy(dict(envelope))
        if candidate["protocol"] != "eco-approval-envelope-v1":
            raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval protocol is unsupported")
        for field in ("approvalId", "humanId", "keyId", "challengeNonce"):
            _identifier(candidate[field], field)
        _digest(candidate["subjectDigest"], "subject digest")
        _digest(candidate["signature"], "signature")
        if candidate["subjectDigest"] != expected_subject_digest:
            raise RuntimeStoreError("ECO_APPROVAL_MISMATCH", "Approval subject does not match proposal")
        policy = self._policies.get(candidate["keyId"])
        if (
            policy is None
            or candidate["humanId"] != policy.human_id
            or candidate["assurance"] != policy.assurance
        ):
            raise RuntimeStoreError("ECO_APPROVAL_UNTRUSTED", "Approval identity policy is not trusted")
        issued_at = parse_utc(candidate["issuedAt"])
        expires_at = parse_utc(candidate["expiresAt"])
        if expires_at <= issued_at:
            raise RuntimeStoreError("ECO_APPROVAL_INVALID", "Approval validity window is invalid")
        expected = hmac.new(
            policy.verification_key,
            canonical_json(_signed_payload(candidate)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(candidate["signature"], expected):
            raise RuntimeStoreError("ECO_APPROVAL_UNTRUSTED", "Approval signature is invalid")
        return candidate, issued_at, expires_at, policy

    def verify(
        self,
        envelope: Mapping[str, Any],
        *,
        expected_subject_digest: str,
        now: datetime,
    ) -> VerifiedApproval:
        candidate, issued_at, expires_at, _ = self._verify_signature(
            envelope, expected_subject_digest=expected_subject_digest
        )
        current = now.astimezone(timezone.utc)
        if issued_at > current:
            raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Approval issue time is in the future")
        if expires_at <= current:
            raise RuntimeStoreError("ECO_APPROVAL_EXPIRED", "Approval is expired")
        return VerifiedApproval(candidate, semantic_digest(candidate))

    def verify_historical(
        self, envelope: Mapping[str, Any], *, expected_subject_digest: str
    ) -> VerifiedApproval:
        """Re-authenticate stored history without treating normal expiry as corruption."""

        candidate, _, _, _ = self._verify_signature(
            envelope, expected_subject_digest=expected_subject_digest
        )
        return VerifiedApproval(candidate, semantic_digest(candidate))


def build_approval_grant(
    verified: VerifiedApproval,
    *,
    run_id: str,
    approval_request_id: str,
    approval_request_digest: str,
    proposal_id: str,
    proposal_digest: str,
    display_digest: str,
) -> dict[str, Any]:
    """Build the deterministic runtime ``ApprovalGrant`` schema wrapper.

    The HMAC reference envelope retains its stronger challenge binding in the
    journal.  This wrapper exposes the canonical runtime vocabulary so callers
    do not need an ambiguous translation layer.
    """

    envelope = verified.envelope
    challenge_digest = semantic_digest(
        {"domain": "eco-approval-challenge-v1", "nonce": envelope["challengeNonce"]}
    )
    for value, field in (
        (run_id, "run id"), (approval_request_id, "approval request id"),
        (proposal_id, "proposal id"),
    ):
        _identifier(value, field)
    for value, field in (
        (approval_request_digest, "approval request digest"),
        (proposal_digest, "proposal digest"), (display_digest, "display digest"),
    ):
        _digest(value, field)
    return {
        "apiVersion": "runtime.ai.ecosystem/v1alpha1",
        "kind": "ApprovalGrant",
        "metadata": {
            "id": envelope["approvalId"], "runId": run_id, "createdAt": envelope["issuedAt"],
        },
        "spec": {
            "approvalRequest": {"id": approval_request_id, "digest": approval_request_digest},
            "proposal": {"id": proposal_id, "digest": proposal_digest},
            "subject": {"kind": "WorkspaceChangeProposal", "id": proposal_id,
                        "digest": proposal_digest},
            "authoritySubjectDigest": envelope["subjectDigest"],
            "displayDigest": display_digest,
            "decision": "approve",
            "approver": {
                "type": "human", "issuerId": envelope["humanId"],
                "subjectId": envelope["humanId"], "assurance": envelope["assurance"],
                "challengeDigest": challenge_digest,
            },
            "constraints": {"singleUse": True, "expiresAt": envelope["expiresAt"]},
            "signedEnvelope": {
                "protocol": "eco-approval-envelope-v1", "envelopeId": envelope["approvalId"],
                "issuer": {"id": envelope["humanId"], "keyId": envelope["keyId"]},
                "subjectDigest": envelope["subjectDigest"], "issuedAt": envelope["issuedAt"],
                "expiresAt": envelope["expiresAt"],
                "signature": {"algorithm": "HMAC-SHA256", "tag": envelope["signature"]},
            },
        },
    }
