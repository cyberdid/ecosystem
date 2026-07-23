"""Gated Self-Creation (GSC) engine — the deterministic gate.

An agent or model may *propose* a new skill freely; this gate decides whether the
proposal is admissible for promotion. It is fail-closed and L0 by default: an
admissible verdict means "ready for a human to approve and promote", never an
automatic registry mutation. The gate checks structure, capability narrowing,
secret hygiene and hard-stop integrity — a proposal that weakens its own hard
stop, escalates capability, or embeds a secret is rejected. Generation (a model
writing the SKILL.md) is the input; this gate is the enforcement.
"""

from .gate import ProposalVerdict, gate_skill_proposal
from .promote import HumanApproval, PromotionError, PromotionReceipt, promote_skill

__all__ = [
    "ProposalVerdict",
    "gate_skill_proposal",
    "HumanApproval",
    "PromotionError",
    "PromotionReceipt",
    "promote_skill",
]
