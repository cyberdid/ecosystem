from __future__ import annotations

"""L0 promotion: turn an admissible proposal into a real skill file.

Promotion is never automatic. It re-runs the gate (a caller's claim of
admissibility is not trusted), requires an explicit human approval bound to the
exact content digest (approving *this* proposal, never a substitute), and refuses
to overwrite an existing skill. It writes the ``SKILL.md`` into a caller-supplied
skills root and returns a content-free receipt. It does not touch the built-in
package registry — a promoted skill belongs to the project that approved it.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gate import ProposalVerdict, gate_skill_proposal

_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class PromotionError(Exception):
    """Typed, fail-closed promotion error. Carries a stable code only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class HumanApproval:
    """An explicit human approval bound to one exact content digest."""

    approver_id: str
    approved_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.approver_id, str) or not self.approver_id.strip():
            raise PromotionError("ECO_GSC_APPROVAL_INVALID")
        if not isinstance(self.approved_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.approved_digest) is None:
            raise PromotionError("ECO_GSC_APPROVAL_INVALID")


@dataclass(frozen=True)
class PromotionReceipt:
    skill_id: str
    content_digest: str
    approver_id: str
    path: str

    def as_record(self) -> dict[str, Any]:
        return {
            "skillId": self.skill_id,
            "contentDigest": self.content_digest,
            "approverId": self.approver_id,
            "path": self.path,
        }


def promote_skill(
    proposal_text: str,
    *,
    declared_capabilities: list[str],
    allowed_capabilities: list[str],
    approval: HumanApproval,
    skills_root: str | Path,
) -> PromotionReceipt:
    """Promote an approved, admissible proposal into ``skills_root/<name>/SKILL.md``."""

    if not isinstance(approval, HumanApproval):
        raise PromotionError("ECO_GSC_APPROVAL_INVALID")

    # Re-run the gate; never trust a claim of admissibility.
    verdict: ProposalVerdict = gate_skill_proposal(
        proposal_text,
        declared_capabilities=declared_capabilities,
        allowed_capabilities=allowed_capabilities,
    )
    if not verdict.admissible:
        raise PromotionError("ECO_GSC_NOT_ADMISSIBLE")
    if verdict.content_digest is None or verdict.skill_name is None:
        raise PromotionError("ECO_GSC_NOT_ADMISSIBLE")

    # Approval binds the exact content; an approved digest cannot be spent on a
    # different proposal.
    if approval.approved_digest != verdict.content_digest:
        raise PromotionError("ECO_GSC_APPROVAL_MISMATCH")

    name = verdict.skill_name
    if _NAME_RE.fullmatch(name) is None:
        raise PromotionError("ECO_GSC_NAME_INVALID")

    root = Path(skills_root)
    if not root.is_dir():
        raise PromotionError("ECO_GSC_SKILLS_ROOT_INVALID")
    target = root / name / "SKILL.md"
    if target.exists():
        raise PromotionError("ECO_GSC_ALREADY_EXISTS")

    target.parent.mkdir(parents=True, exist_ok=False)
    target.write_text(proposal_text, encoding="utf-8")

    return PromotionReceipt(
        skill_id=name,
        content_digest=verdict.content_digest,
        approver_id=approval.approver_id,
        path=str(target),
    )
