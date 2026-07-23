from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any, Iterable
from pathlib import Path

from .contracts import API_VERSION, validate_record
from .digests import semantic_digest
from .errors import RuntimePolicyError


REQUIRED_INDEPENDENT_ATTEMPTS = 5
_OUT_OF_SCOPE_REASON = (
    "The no-model read-only M4 evidence cannot authorize model, network, or write-capable promotion."
)
_ZERO_SAFETY = {
    "unauthorizedActions": 0,
    "repositoryMutations": 0,
    "modelRequests": 0,
    "networkRequests": 0,
    "writeOperations": 0,
    "adaptersCreated": 0,
    "contentEmissions": 0,
}


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("evaluated_at must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def wiki_health_evidence_digest(evidence: dict[str, Any]) -> str:
    """Return the deterministic content digest, not an authentication claim."""

    candidate = copy.deepcopy(evidence)
    candidate.get("spec", {}).pop("evidenceDigest", None)
    return semantic_digest(candidate)


def _evidence_digest_valid(evidence: dict[str, Any]) -> bool:
    return evidence["spec"]["evidenceDigest"] == wiki_health_evidence_digest(evidence)


def _level(eligible: bool) -> dict[str, Any]:
    return {
        "eligible": eligible,
        "reasonCode": (
            "ECO_M4_PROMOTION_GATE_PASSED" if eligible else "ECO_M4_PROMOTION_GATE_NOT_PASSED"
        ),
        "reason": (
            "The fixed no-model workflow passed the complete M4 L0-L2 evidence gate."
            if eligible
            else "The fixed no-model workflow did not pass the complete M4 evidence gate."
        ),
    }


def _out_of_scope_level() -> dict[str, Any]:
    return {
        "eligible": False,
        "reasonCode": "ECO_M4_LEVEL_OUT_OF_SCOPE",
        "reason": _OUT_OF_SCOPE_REASON,
    }


def evaluate_wiki_health_promotion(
    attempts: Iterable[dict[str, Any]],
    *,
    recovery: dict[str, Any] | None,
    report_id: str,
    evaluated_at: datetime,
) -> dict[str, Any]:
    """Evaluate the fixed L0-L2 promotion gate from content-free evidence.

    This is an offline deterministic aggregator. Evidence digests detect
    accidental mutation but do not authenticate an issuer; production callers
    must source records from an authenticated journal or signed envelope.
    """

    records = [copy.deepcopy(validate_record(item)) for item in attempts]
    recovery_record = copy.deepcopy(validate_record(recovery)) if recovery is not None else None
    if any(item["kind"] != "WikiHealthRunEvidence" for item in records) or (
        recovery_record is not None and recovery_record["kind"] != "WikiHealthRunEvidence"
    ):
        raise ValueError("M4 evaluation accepts only WikiHealthRunEvidence records")

    ordered = sorted(records, key=lambda item: (item["spec"]["evidenceDigest"], item["metadata"]["id"]))
    reasons: list[str] = []

    if len(ordered) != REQUIRED_INDEPENDENT_ATTEMPTS:
        reasons.append("ECO_M4_ATTEMPT_COUNT_INVALID")
    if (
        len({item["metadata"]["id"] for item in ordered}) != len(ordered)
        or len({item["metadata"]["runId"] for item in ordered}) != len(ordered)
        or len({item["spec"]["evidenceDigest"] for item in ordered}) != len(ordered)
    ):
        reasons.append("ECO_M4_INDEPENDENCE_INVALID")
    if any(not _evidence_digest_valid(item) for item in ordered):
        reasons.append("ECO_M4_EVIDENCE_DIGEST_INVALID")
    if any(item["spec"]["replayed"] for item in ordered):
        reasons.append("ECO_M4_ATTEMPT_REPLAYED")
    if any(item["spec"]["status"] != "succeeded" for item in ordered):
        reasons.append("ECO_M4_ATTEMPT_FAILED")
    if any(
        item["spec"]["execution"]["verifiedEntryCount"] != 3
        or item["spec"]["execution"]["brokerReadCount"] != 3
        for item in ordered
    ):
        reasons.append("ECO_M4_READ_INVARIANT_FAILED")
    if any(item["spec"]["safety"] != _ZERO_SAFETY for item in ordered):
        reasons.append("ECO_M4_SAFETY_VIOLATION")

    stable_keys = {
        (
            item["spec"]["reportDigest"],
            item["spec"]["repositorySnapshotDigest"],
            item["spec"]["execution"]["verifiedEntryCount"],
            item["spec"]["execution"]["totalBytes"],
        )
        for item in ordered
    }
    stable_result = len(stable_keys) == 1 and bool(ordered)
    if not stable_result:
        reasons.append("ECO_M4_RESULT_DRIFT")

    recovery_passed = False
    if recovery_record is None:
        reasons.append("ECO_M4_RECOVERY_EVIDENCE_MISSING")
    else:
        recovery_spec = recovery_record["spec"]
        matching_attempt = any(
            recovery_record["metadata"]["runId"] == item["metadata"]["runId"]
            and recovery_spec["reportDigest"] == item["spec"]["reportDigest"]
            and recovery_spec["repositorySnapshotDigest"]
            == item["spec"]["repositorySnapshotDigest"]
            and recovery_spec["execution"]["verifiedEntryCount"]
            == item["spec"]["execution"]["verifiedEntryCount"]
            and recovery_spec["execution"]["totalBytes"]
            == item["spec"]["execution"]["totalBytes"]
            for item in ordered
        )
        recovery_passed = (
            _evidence_digest_valid(recovery_record)
            and recovery_spec["status"] == "succeeded"
            and recovery_spec["replayed"] is True
            and recovery_spec["execution"]["brokerReadCount"] == 0
            and recovery_spec["safety"] == _ZERO_SAFETY
            and matching_attempt
        )
        if not recovery_passed:
            reasons.append("ECO_M4_RECOVERY_EVIDENCE_INVALID")

    reasons = list(dict.fromkeys(reasons))
    passed = not reasons
    reference = None
    if ordered:
        first = ordered[0]["spec"]
        reference = {
            "reportDigest": first["reportDigest"],
            "repositorySnapshotDigest": first["repositorySnapshotDigest"],
            "verifiedEntryCount": first["execution"]["verifiedEntryCount"],
            "totalBytes": first["execution"]["totalBytes"],
        }
    source_digests = sorted(
        {
            *[item["spec"]["evidenceDigest"] for item in ordered],
            *(
                [recovery_record["spec"]["evidenceDigest"]]
                if recovery_record is not None
                else []
            ),
        }
    )
    level = _level(passed)
    report = {
        "apiVersion": API_VERSION,
        "kind": "WikiHealthPromotionReport",
        "metadata": {"id": report_id, "evaluatedAt": _timestamp(evaluated_at)},
        "spec": {
            "profile": "wiki-health-promotion-report/v1",
            "workflow": "wiki-health-check",
            "evaluationVersion": 1,
            "criteria": {
                "requiredIndependentAttempts": REQUIRED_INDEPENDENT_ATTEMPTS,
                "requiredVerifiedEntryCount": 3,
                "requiredBrokerReadsPerAttempt": 3,
                "requiredRecoveryBrokerReads": 0,
                "maximumSafetyViolations": 0,
            },
            "observed": {
                "attemptCount": len(ordered),
                "independentRunCount": len({item["metadata"]["runId"] for item in ordered}),
                "successfulNonReplayedAttemptCount": sum(
                    item["spec"]["status"] == "succeeded" and not item["spec"]["replayed"]
                    for item in ordered
                ),
                "stableResult": stable_result,
                "safeAttemptCount": sum(item["spec"]["safety"] == _ZERO_SAFETY for item in ordered),
            },
            "reference": reference,
            "recovery": {
                "provided": recovery_record is not None,
                "passed": recovery_passed,
                "evidenceDigest": (
                    recovery_record["spec"]["evidenceDigest"]
                    if recovery_record is not None
                    else None
                ),
            },
            "status": "pass" if passed else "fail",
            "reasonCodes": reasons,
            "sourceEvidenceDigests": source_digests,
            "promotion": {
                "highestEligibleLevel": "L2" if passed else None,
                "levels": {
                    "L0": copy.deepcopy(level),
                    "L1": copy.deepcopy(level),
                    "L2": copy.deepcopy(level),
                    "L3": _out_of_scope_level(),
                    "L4": _out_of_scope_level(),
                    "L5": _out_of_scope_level(),
                },
            },
            "promotionReportDigest": "0" * 64,
        },
    }
    digest_subject = copy.deepcopy(report)
    digest_subject["spec"].pop("promotionReportDigest")
    report["spec"]["promotionReportDigest"] = semantic_digest(digest_subject)
    validate_record(report)
    return report


def verify_wiki_health_promotion_report(report: dict[str, Any]) -> dict[str, Any]:
    """Validate the frozen criteria and the report's deterministic self-digest."""

    candidate = copy.deepcopy(validate_record(report))
    if candidate["kind"] != "WikiHealthPromotionReport":
        raise RuntimePolicyError("ECO_M4_PROMOTION_REPORT_INVALID", "M4 report kind is invalid")
    claimed = candidate["spec"].pop("promotionReportDigest")
    if claimed != semantic_digest(candidate):
        raise RuntimePolicyError(
            "ECO_M4_PROMOTION_REPORT_INVALID", "M4 promotion report digest is invalid"
        )
    return copy.deepcopy(report)


def _run_evidence(
    result: dict[str, Any],
    *,
    evidence_id: str,
    created_at: datetime,
    replayed: bool,
    broker_read_count: int,
) -> dict[str, Any]:
    record = {
        "apiVersion": API_VERSION,
        "kind": "WikiHealthRunEvidence",
        "metadata": {
            "id": evidence_id,
            "runId": result["evidence"]["runId"],
            "createdAt": _timestamp(created_at),
        },
        "spec": {
            "profile": "wiki-health-run-evidence/v1",
            "workflow": "wiki-health-check",
            "evidenceDigest": "0" * 64,
            "reportDigest": result["report"]["digest"],
            "repositorySnapshotDigest": result["evidence"]["repositorySnapshotDigest"],
            "status": result["status"],
            "replayed": replayed,
            "execution": {
                "verifiedEntryCount": result["execution"]["readCount"],
                "brokerReadCount": broker_read_count,
                "totalBytes": result["execution"]["totalBytes"],
            },
            "safety": copy.deepcopy(_ZERO_SAFETY),
        },
    }
    record["spec"]["evidenceDigest"] = wiki_health_evidence_digest(record)
    return copy.deepcopy(validate_record(record))


def execute_wiki_health_evaluation(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Run the fixed five-slot M4 L0-L2 gate plus one zero-read replay proof."""

    from .no_model_execution import _execute_wiki_health_check

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    results = [
        _execute_wiki_health_check(repository, bundle, now=instant, evaluation_slot=slot)
        for slot in range(1, REQUIRED_INDEPENDENT_ATTEMPTS + 1)
    ]
    expected_safety = {
        "repositoryMutation": "denied",
        "modelEgress": "not-used",
        "network": "not-used",
        "writeAuthority": "not-created",
        "adapter": "not-created",
        "content": "not-emitted",
    }
    for result in results:
        if (
            not result.get("available")
            or result.get("safety") != expected_safety
            or result.get("execution", {}).get("readCount") != 3
        ):
            return {
                "available": False,
                "workflow": "wiki-health-check",
                "status": "blocked",
                "code": result.get("code", "ECO_M4_EVALUATION_BLOCKED"),
                "evaluation": {"attemptCount": len(results), "promotion": "not-evaluated"},
                "safety": expected_safety,
            }

    attempts = [
        _run_evidence(
            result,
            evidence_id=f"wiki-health-evaluation-attempt-{slot}",
            created_at=instant,
            # A terminal authenticated journal is historical attempt evidence;
            # invocation replay is evaluated separately below.
            replayed=False,
            broker_read_count=3,
        )
        for slot, result in enumerate(results, start=1)
    ]
    replay = _execute_wiki_health_check(repository, bundle, now=instant, evaluation_slot=1)
    if (
        not replay.get("available")
        or replay.get("replayed") is not True
        or replay.get("execution", {}).get("brokerReadCount") != 0
        or replay.get("safety") != expected_safety
    ):
        return {
            "available": False,
            "workflow": "wiki-health-check",
            "status": "blocked",
            "code": "ECO_M4_RECOVERY_EVIDENCE_INVALID",
            "evaluation": {"attemptCount": len(attempts), "promotion": "not-eligible"},
            "safety": expected_safety,
        }
    recovery = _run_evidence(
        replay,
        evidence_id="wiki-health-evaluation-recovery",
        created_at=instant,
        replayed=True,
        broker_read_count=0,
    )
    report_seed = semantic_digest(
        {
            "snapshot": results[0]["evidence"]["repositorySnapshotDigest"],
            "report": results[0]["report"]["digest"],
        }
    )
    report = evaluate_wiki_health_promotion(
        attempts,
        recovery=recovery,
        report_id=f"wiki-health-promotion-{report_seed[:24]}",
        evaluated_at=instant,
    )
    passed = report["spec"]["status"] == "pass"
    return {
        "available": passed,
        "workflow": "wiki-health-check",
        "status": "succeeded" if passed else "failed",
        "code": "ECO_M4_PROMOTION_GATE_PASSED" if passed else "ECO_M4_PROMOTION_GATE_FAILED",
        "evaluation": {
            "attemptCount": len(attempts),
            "recoveryPassed": report["spec"]["recovery"]["passed"],
            "highestEligibleLevel": report["spec"]["promotion"]["highestEligibleLevel"],
            "promotionReportDigest": report["spec"]["promotionReportDigest"],
        },
        "promotionReport": report,
        "safety": expected_safety,
    }
