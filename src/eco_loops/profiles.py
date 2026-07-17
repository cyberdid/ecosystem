from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from eco_runtime.digests import semantic_digest

from .contracts import LoopBudget, LoopDefinition, RetryPolicy


def _deadline(value: datetime | None) -> datetime:
    return value or (datetime.now(timezone.utc) + timedelta(minutes=5))


def source_review_outline(*, deadline: datetime | None = None) -> LoopDefinition:
    """Generic state outline only; the fixed M6.1 runner remains authoritative."""

    return LoopDefinition(
        loop_id="source-review",
        version="1",
        objective_digest=semantic_digest(
            {"objective": "produce a source-bound report with explicit uncertainty"}
        ),
        gate_digest=semantic_digest(
            {"gate": "fixed source-review structural and evidence-integrity gate", "revision": 1}
        ),
        profile="source-review-outline/v1",
        side_effect_mode="report-only",
        deterministic=False,
        executable=False,
        budget=LoopBudget(
            max_attempts=7,
            max_iterations=2,
            deadline=_deadline(deadline),
            max_tokens=1,
            max_cost_microusd=0,
            max_storage_bytes=1,
        ),
        retry=RetryPolicy(allowed_reason_codes=frozenset(), max_stagnant_iterations=1),
    )


def wiki_health_compatibility(*, deadline: datetime | None = None) -> LoopDefinition:
    return LoopDefinition(
        loop_id="wiki-health-check",
        version="1",
        objective_digest=semantic_digest(
            {"objective": "verify the fixed trusted D0 wiki snapshot without model or writes"}
        ),
        gate_digest=semantic_digest(
            {"gate": "existing wiki-health-check deterministic integrity gate", "revision": 1}
        ),
        profile="wiki-health-check-compat/v1",
        side_effect_mode="report-only",
        deterministic=True,
        executable=True,
        budget=LoopBudget(
            max_attempts=1,
            max_iterations=1,
            deadline=_deadline(deadline),
            max_tokens=0,
            max_cost_microusd=0,
            max_storage_bytes=0,
        ),
        retry=RetryPolicy(allowed_reason_codes=frozenset(), max_stagnant_iterations=1),
    )


def profile(name: str, *, deadline: datetime | None = None) -> LoopDefinition:
    if name == "source-review":
        return source_review_outline(deadline=deadline)
    if name == "wiki-health-check":
        return wiki_health_compatibility(deadline=deadline)
    raise KeyError(name)


def validate_profile(definition: LoopDefinition) -> dict[str, object]:
    return {
        "available": True,
        "loop": definition.loop_id,
        "profile": definition.profile,
        "definitionDigest": definition.digest,
        "deterministic": definition.deterministic,
        "executable": definition.executable,
        "sideEffectMode": definition.side_effect_mode,
        "stateOutline": list(definition.state_outline),
        "nonClaims": [
            "no-distributed-durability",
            "no-arbitrary-code-execution",
            "no-scheduling",
            "no-new-write-authority",
        ],
    }
