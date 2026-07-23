from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from eco_runtime.digests import semantic_digest

from .contracts import AttemptResult, GateOutcome, LoopCheckpoint


def wiki_health_executor(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
) -> tuple[
    Callable[[LoopCheckpoint], AttemptResult],
    Callable[[LoopCheckpoint, AttemptResult], GateOutcome],
    dict[str, Any],
]:
    """Adapt the existing workflow once; do not reproduce any of its effects."""

    result_holder: dict[str, Any] = {}

    def execute(_: LoopCheckpoint) -> AttemptResult:
        from eco_runtime.no_model_execution import execute_wiki_health_check

        result = execute_wiki_health_check(repository, bundle)
        result_holder["result"] = result
        evidence_digest = semantic_digest(
            {
                "workflow": result.get("workflow"),
                "status": result.get("status"),
                "code": result.get("code"),
                "reportDigest": result.get("report", {}).get("digest"),
            }
        )
        if result.get("available") and result.get("status") == "succeeded":
            return AttemptResult(
                outcome="candidate",
                reason_code="ECO_LOOP_CANDIDATE_READY",
                candidate_digest=result["report"]["digest"],
                evidence_digest=evidence_digest,
            )
        return AttemptResult(
            outcome="fatal-error",
            reason_code="ECO_LOOP_COMPATIBILITY_FAILED",
            candidate_digest=semantic_digest({"candidate": "blocked"}),
            evidence_digest=evidence_digest,
        )

    def gate(_: LoopCheckpoint, attempt: AttemptResult) -> GateOutcome:
        result = result_holder.get("result", {})
        passed = (
            result.get("available") is True
            and result.get("status") == "succeeded"
            and result.get("report", {}).get("digest") == attempt.candidate_digest
        )
        return GateOutcome(
            outcome="pass" if passed else "fail",
            reason_code="ECO_LOOP_GATE_PASSED" if passed else "ECO_LOOP_GATE_FAILED",
            progress_digest=attempt.candidate_digest,
            evidence_digest=semantic_digest(
                {
                    "compatibilityGate": "wiki-health-check",
                    "candidateDigest": attempt.candidate_digest,
                    "passed": passed,
                }
            ),
        )

    return execute, gate, result_holder
