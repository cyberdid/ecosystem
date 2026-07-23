from __future__ import annotations

"""Deterministic gate for a proposed skill.

Given a proposed ``SKILL.md`` plus its declared capabilities and the capabilities
policy allows, decide admissibility. The verdict is content-free about the
proposal body (it reports codes and reasons, not the raw text) and never mutates
any registry: promotion is a separate, human-owned step (L0).
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

_NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_STEP_RE = re.compile(r"^\s*\d+\.\s+\S", re.MULTILINE)
_HARD_STOP_RE = re.compile(r"^Hard stop:\s+\S", re.MULTILINE)
_MIN_STEPS = 3
_MAX_BODY_BYTES = 20_000

# Fail-closed hygiene: obvious secret shapes and self-authorizing directives.
_SECRET_RES = (
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(api[_-]?key|password|secret)\b\s*[:=]\s*\S{6,}"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
)
_BYPASS_RES = (
    re.compile(r"(?i)\b(bypass|disable|ignore|skip)\b.{0,40}\b(policy|broker|gate|approval|hard stop)\b"),
    re.compile(r"(?i)\bgrant(s|ing)?\b.{0,30}\b(itself|own)\b.{0,30}\b(permission|authority|capability)\b"),
)


@dataclass(frozen=True)
class ProposalVerdict:
    admissible: bool
    code: str
    reasons: tuple[str, ...] = ()
    content_digest: str | None = None
    skill_name: str | None = None

    def as_record(self) -> dict[str, Any]:
        return {
            "admissible": self.admissible,
            "code": self.code,
            "reasons": list(self.reasons),
            "contentDigest": self.content_digest,
            "skillName": self.skill_name,
        }


def _parse_frontmatter(text: str) -> tuple[str | None, str | None, str]:
    """Return (name, description, body) from a ``---`` frontmatter block."""

    stripped = text.lstrip("﻿")
    if not stripped.startswith("---"):
        return None, None, text
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        return None, None, text
    front, body = parts[1], parts[2]
    name = description = None
    for line in front.splitlines():
        if line.startswith("name:"):
            name = line[len("name:"):].strip()
        elif line.startswith("description:"):
            description = line[len("description:"):].strip()
    return name, description, body


def gate_skill_proposal(
    proposal_text: str,
    *,
    declared_capabilities: list[str],
    allowed_capabilities: list[str],
) -> ProposalVerdict:
    """Decide whether a proposed skill is admissible for promotion (L0)."""

    reasons: list[str] = []
    if not isinstance(proposal_text, str) or not proposal_text.strip():
        return ProposalVerdict(False, "ECO_GSC_EMPTY", ("proposal is empty",))
    if len(proposal_text.encode("utf-8")) > _MAX_BODY_BYTES:
        return ProposalVerdict(False, "ECO_GSC_TOO_LARGE", ("proposal exceeds the bounded size",))

    name, description, body = _parse_frontmatter(proposal_text)
    if name is None or _NAME_RE.fullmatch(name) is None or len(name) > 80:
        reasons.append("frontmatter name missing or not a kebab identifier")
    if not description:
        reasons.append("frontmatter description missing")
    if reasons:
        return ProposalVerdict(False, "ECO_GSC_FRONTMATTER_INVALID", tuple(reasons))

    if len(_STEP_RE.findall(body)) < _MIN_STEPS:
        return ProposalVerdict(
            False, "ECO_GSC_INSUFFICIENT_STEPS", (f"fewer than {_MIN_STEPS} numbered steps",)
        )
    if _HARD_STOP_RE.search(body) is None:
        return ProposalVerdict(False, "ECO_GSC_NO_HARD_STOP", ("no explicit 'Hard stop:' line",))

    # Narrowing: a proposal may never declare capability policy does not allow.
    allowed = set(allowed_capabilities)
    escalated = sorted(set(declared_capabilities) - allowed)
    if escalated:
        return ProposalVerdict(
            False, "ECO_GSC_CAPABILITY_ESCALATION", tuple(f"capability not allowed: {c}" for c in escalated)
        )

    # Hygiene: no secrets, no self-authorizing / enforcement-bypass directives.
    if any(rx.search(proposal_text) for rx in _SECRET_RES):
        return ProposalVerdict(False, "ECO_GSC_SECRET_DETECTED", ("secret-like material in proposal",))
    # The 'Hard stop:' line legitimately names what must NEVER be done ("never
    # bypass the gate"); scan the directive body with hard-stop lines removed so
    # a prohibition is not mistaken for an instruction.
    directive_body = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("Hard stop:")
    )
    if any(rx.search(directive_body) for rx in _BYPASS_RES):
        return ProposalVerdict(
            False, "ECO_GSC_HARD_STOP_WEAKENED", ("proposal instructs bypassing enforcement",)
        )

    digest = hashlib.sha256(proposal_text.encode("utf-8")).hexdigest()
    return ProposalVerdict(True, "ECO_GSC_OK", (), digest, skill_name=name)
