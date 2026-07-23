from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from eco_gsc import (
    HumanApproval,
    PromotionError,
    gate_skill_proposal,
    promote_skill,
)

VALID = """---
name: promote-demo
description: A demo skill for promotion.
---

# Promote demo

Use this workflow for a demo.

1. First step.
2. Second step.
3. Third step.

Hard stop: never bypass the gate or grant new authority.
"""

ALLOWED = ["demo.run", "demo.verify"]
DECLARED = ["demo.run"]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _promote(text, root, *, approver="alice", approved_digest=None):
    approval = HumanApproval(approver_id=approver, approved_digest=approved_digest or _digest(text))
    return promote_skill(
        text, declared_capabilities=DECLARED, allowed_capabilities=ALLOWED,
        approval=approval, skills_root=root,
    )


class GscPromoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_admissible_approved_proposal_is_written(self) -> None:
        receipt = _promote(VALID, self.root)
        self.assertEqual(receipt.skill_id, "promote-demo")
        self.assertEqual(receipt.approver_id, "alice")
        written = self.root / "promote-demo" / "SKILL.md"
        self.assertTrue(written.exists())
        self.assertEqual(written.read_text(encoding="utf-8"), VALID)

    def test_gate_is_rerun_inadmissible_proposal_rejected(self) -> None:
        no_stop = VALID.replace("Hard stop: never bypass the gate or grant new authority.\n", "")
        with self.assertRaises(PromotionError) as ctx:
            _promote(no_stop, self.root)
        self.assertEqual(ctx.exception.code, "ECO_GSC_NOT_ADMISSIBLE")

    def test_approval_must_bind_exact_content_digest(self) -> None:
        # approve a different digest than the proposal -> mismatch, no write
        with self.assertRaises(PromotionError) as ctx:
            _promote(VALID, self.root, approved_digest="0" * 64)
        self.assertEqual(ctx.exception.code, "ECO_GSC_APPROVAL_MISMATCH")
        self.assertFalse((self.root / "promote-demo").exists())

    def test_no_overwrite_of_existing_skill(self) -> None:
        _promote(VALID, self.root)
        with self.assertRaises(PromotionError) as ctx:
            _promote(VALID, self.root)
        self.assertEqual(ctx.exception.code, "ECO_GSC_ALREADY_EXISTS")

    def test_capability_escalation_blocks_promotion(self) -> None:
        approval = HumanApproval(approver_id="alice", approved_digest=_digest(VALID))
        with self.assertRaises(PromotionError) as ctx:
            promote_skill(
                VALID, declared_capabilities=["repository.write"], allowed_capabilities=ALLOWED,
                approval=approval, skills_root=self.root,
            )
        self.assertEqual(ctx.exception.code, "ECO_GSC_NOT_ADMISSIBLE")

    def test_invalid_approval_rejected(self) -> None:
        with self.assertRaises(PromotionError):
            HumanApproval(approver_id="", approved_digest=_digest(VALID))
        with self.assertRaises(PromotionError):
            HumanApproval(approver_id="alice", approved_digest="not-a-digest")

    def test_receipt_is_content_free(self) -> None:
        rec = _promote(VALID, self.root).as_record()
        self.assertEqual(set(rec), {"skillId", "contentDigest", "approverId", "path"})

    def test_gate_and_promote_agree_on_digest(self) -> None:
        verdict = gate_skill_proposal(VALID, declared_capabilities=DECLARED, allowed_capabilities=ALLOWED)
        receipt = _promote(VALID, self.root, approved_digest=verdict.content_digest)
        self.assertEqual(receipt.content_digest, verdict.content_digest)


if __name__ == "__main__":
    unittest.main()
