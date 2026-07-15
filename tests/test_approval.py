from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from eco_runtime.approval import (
    ApprovalKeyPolicy,
    ApprovalSigner,
    ApprovalTrustStore,
    approval_subject_digest,
    build_approval_grant,
)
from eco_runtime.contracts import validate_record
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError


NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
KEY = b"h" * 32


def subject(**overrides: str) -> str:
    fields = {
        "store_id": "change-store-1",
        "project_id": "project-1",
        "run_id": "run-1",
        "plan_digest": semantic_digest("plan"),
        "policy_decision_digest": semantic_digest("policy-decision"),
        "proposal_digest": semantic_digest("proposal"),
        "action_class": "A2",
        "operation_kind": "replace",
        "root_identity_digest": semantic_digest("root"),
        "base_digest": semantic_digest("before"),
        "target_ref_digest": semantic_digest("target-ref"),
        "desired_digest": semantic_digest("after"),
        "rollback_digest": semantic_digest("rollback"),
        "display_digest": semantic_digest("display"),
        "limits_digest": semantic_digest({"maxBytes": 10, "maxFiles": 1}),
    }
    fields.update(overrides)
    return approval_subject_digest(**fields)


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = ApprovalKeyPolicy(
            key_id="human-key-1", human_id="operator-1", assurance="local-os-session",
            verification_key=KEY,
        )
        self.signer = ApprovalSigner(self.policy)
        self.trust = ApprovalTrustStore({self.policy.key_id: self.policy})

    def envelope(self) -> dict:
        return self.signer.sign(
            approval_id="approval-1", subject_digest=subject(), challenge_nonce="challenge-1",
            issued_at=NOW, expires_at=NOW + timedelta(minutes=5),
        )

    def assert_code(self, code: str, call) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)

    def test_reference_signer_is_identity_and_assurance_bound(self) -> None:
        verified = self.trust.verify(
            self.envelope(), expected_subject_digest=subject(), now=NOW + timedelta(seconds=1)
        )
        self.assertEqual(verified.envelope["humanId"], "operator-1")
        self.assertEqual(verified.envelope["assurance"], "local-os-session")

    def test_every_write_parameter_changes_the_subject(self) -> None:
        baseline = subject()
        changes = {
            "store_id": "change-store-2", "project_id": "project-2", "run_id": "run-2",
            "plan_digest": semantic_digest("plan-2"),
            "policy_decision_digest": semantic_digest("policy-decision-2"),
            "proposal_digest": semantic_digest("proposal-2"),
            "operation_kind": "create", "root_identity_digest": semantic_digest("root-2"),
            "base_digest": semantic_digest("before-2"), "target_ref_digest": semantic_digest("target-2"),
            "desired_digest": semantic_digest("after-2"), "rollback_digest": semantic_digest("rollback-2"),
            "display_digest": semantic_digest("display-2"), "limits_digest": semantic_digest("limits-2"),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(subject(**{field: value}), baseline)

    def test_tamper_wrong_subject_expiry_and_unknown_fields_fail_closed(self) -> None:
        tampered = copy.deepcopy(self.envelope())
        tampered["humanId"] = "attacker-1"
        self.assert_code(
            "ECO_APPROVAL_UNTRUSTED",
            lambda: self.trust.verify(tampered, expected_subject_digest=subject(), now=NOW),
        )
        self.assert_code(
            "ECO_APPROVAL_MISMATCH",
            lambda: self.trust.verify(self.envelope(), expected_subject_digest=semantic_digest("other"), now=NOW),
        )
        self.assert_code(
            "ECO_APPROVAL_EXPIRED",
            lambda: self.trust.verify(self.envelope(), expected_subject_digest=subject(), now=NOW + timedelta(minutes=6)),
        )
        extra = self.envelope()
        extra["path"] = "private.txt"
        self.assert_code(
            "ECO_APPROVAL_INVALID",
            lambda: self.trust.verify(extra, expected_subject_digest=subject(), now=NOW),
        )

    def test_verified_envelope_builds_the_canonical_approval_grant(self) -> None:
        verified = self.trust.verify(
            self.envelope(), expected_subject_digest=subject(), now=NOW
        )
        grant = build_approval_grant(
            verified, run_id="run-1", approval_request_id="approval-request-1",
            approval_request_digest=semantic_digest("approval-request"),
            proposal_id="proposal-1", proposal_digest=semantic_digest("proposal-record"),
            display_digest=semantic_digest("display"),
        )
        self.assertEqual(validate_record(grant), grant)
        self.assertEqual(grant["spec"]["approver"]["assurance"], "local-os-session")


if __name__ == "__main__":
    unittest.main()
