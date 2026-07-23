from __future__ import annotations

import copy
import unittest
from datetime import datetime, timezone

from eco_runtime.contracts import API_VERSION, validate_record
from eco_runtime.errors import ContractValidationError, RuntimePolicyError
from eco_runtime.wiki_health_evaluation import (
    evaluate_wiki_health_promotion,
    verify_wiki_health_promotion_report,
    wiki_health_evidence_digest,
)


NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)
ZERO_SAFETY = {
    "unauthorizedActions": 0,
    "repositoryMutations": 0,
    "modelRequests": 0,
    "networkRequests": 0,
    "writeOperations": 0,
    "adaptersCreated": 0,
    "contentEmissions": 0,
}


def evidence(index: int, *, replayed: bool = False, run_id: str | None = None) -> dict:
    record = {
        "apiVersion": API_VERSION,
        "kind": "WikiHealthRunEvidence",
        "metadata": {
            "id": f"m4-evidence-{index}{'-replay' if replayed else ''}",
            "runId": run_id or f"m4-independent-run-{index}",
            "createdAt": f"2026-07-16T12:00:{index:02d}Z",
        },
        "spec": {
            "profile": "wiki-health-run-evidence/v1",
            "workflow": "wiki-health-check",
            "evidenceDigest": "0" * 64,
            "reportDigest": "a" * 64,
            "repositorySnapshotDigest": "b" * 64,
            "status": "succeeded",
            "replayed": replayed,
            "execution": {
                "verifiedEntryCount": 3,
                "brokerReadCount": 0 if replayed else 3,
                "totalBytes": 12_345,
            },
            "safety": copy.deepcopy(ZERO_SAFETY),
        },
    }
    record["spec"]["evidenceDigest"] = wiki_health_evidence_digest(record)
    validate_record(record)
    return record


def passing_evidence() -> tuple[list[dict], dict]:
    attempts = [evidence(index) for index in range(1, 6)]
    recovery = evidence(9, replayed=True, run_id=attempts[0]["metadata"]["runId"])
    return attempts, recovery


class WikiHealthPromotionEvaluationTests(unittest.TestCase):
    def evaluate(self, attempts: list[dict], recovery: dict | None) -> dict:
        return evaluate_wiki_health_promotion(
            attempts, recovery=recovery, report_id="m4-promotion-1", evaluated_at=NOW
        )

    def test_exact_five_independent_attempts_and_recovery_promote_only_to_l2(self) -> None:
        attempts, recovery = passing_evidence()
        report = self.evaluate(list(reversed(attempts)), recovery)
        self.assertEqual(report["spec"]["status"], "pass")
        self.assertEqual(report["spec"]["promotion"]["highestEligibleLevel"], "L2")
        for level in ("L0", "L1", "L2"):
            self.assertTrue(report["spec"]["promotion"]["levels"][level]["eligible"])
        for level in ("L3", "L4", "L5"):
            self.assertFalse(report["spec"]["promotion"]["levels"][level]["eligible"])
        self.assertEqual(report, self.evaluate(attempts, recovery))
        verified = verify_wiki_health_promotion_report(report)
        self.assertEqual(verified, report)
        self.assertIsNot(verified, report)

    def test_insufficient_attempts_and_missing_recovery_fail(self) -> None:
        attempts, _ = passing_evidence()
        report = self.evaluate(attempts[:4], None)
        self.assertEqual(report["spec"]["status"], "fail")
        self.assertIn("ECO_M4_ATTEMPT_COUNT_INVALID", report["spec"]["reasonCodes"])
        self.assertIn("ECO_M4_RECOVERY_EVIDENCE_MISSING", report["spec"]["reasonCodes"])
        self.assertIsNone(report["spec"]["promotion"]["highestEligibleLevel"])

    def test_failure_result_drift_and_safety_violation_each_block_promotion(self) -> None:
        attempts, recovery = passing_evidence()
        attempts[0]["spec"]["status"] = "failed"
        attempts[1]["spec"]["reportDigest"] = "c" * 64
        attempts[2]["spec"]["safety"]["networkRequests"] = 1
        for item in attempts[:3]:
            item["spec"]["evidenceDigest"] = wiki_health_evidence_digest(item)
        report = self.evaluate(attempts, recovery)
        self.assertEqual(report["spec"]["status"], "fail")
        self.assertIn("ECO_M4_ATTEMPT_FAILED", report["spec"]["reasonCodes"])
        self.assertIn("ECO_M4_RESULT_DRIFT", report["spec"]["reasonCodes"])
        self.assertIn("ECO_M4_SAFETY_VIOLATION", report["spec"]["reasonCodes"])

    def test_duplicate_run_and_replayed_attempt_are_not_independent(self) -> None:
        attempts, recovery = passing_evidence()
        attempts[1]["metadata"]["runId"] = attempts[0]["metadata"]["runId"]
        attempts[1]["spec"]["replayed"] = True
        attempts[1]["spec"]["execution"]["brokerReadCount"] = 0
        attempts[1]["spec"]["evidenceDigest"] = wiki_health_evidence_digest(attempts[1])
        report = self.evaluate(attempts, recovery)
        self.assertIn("ECO_M4_INDEPENDENCE_INVALID", report["spec"]["reasonCodes"])
        self.assertIn("ECO_M4_ATTEMPT_REPLAYED", report["spec"]["reasonCodes"])

    def test_mutated_evidence_digest_and_invalid_recovery_fail_closed(self) -> None:
        attempts, recovery = passing_evidence()
        attempts[0]["spec"]["execution"]["totalBytes"] += 1
        recovery["spec"]["execution"]["brokerReadCount"] = 1
        recovery["spec"]["evidenceDigest"] = wiki_health_evidence_digest(recovery)
        report = self.evaluate(attempts, recovery)
        self.assertIn("ECO_M4_EVIDENCE_DIGEST_INVALID", report["spec"]["reasonCodes"])
        self.assertIn("ECO_M4_RECOVERY_EVIDENCE_INVALID", report["spec"]["reasonCodes"])

    def test_contract_rejects_extra_fields_and_frozen_threshold_tampering(self) -> None:
        attempts, recovery = passing_evidence()
        forged = copy.deepcopy(attempts[0])
        forged["spec"]["path"] = "wiki/private.md"
        with self.assertRaises(ContractValidationError):
            self.evaluate([forged, *attempts[1:]], recovery)

        report = self.evaluate(attempts, recovery)
        report["spec"]["criteria"]["requiredIndependentAttempts"] = 4
        with self.assertRaises(ContractValidationError):
            verify_wiki_health_promotion_report(report)

    def test_report_digest_tampering_is_detected(self) -> None:
        attempts, recovery = passing_evidence()
        report = self.evaluate(attempts, recovery)
        report["spec"]["promotionReportDigest"] = "f" * 64
        with self.assertRaises(RuntimePolicyError) as caught:
            verify_wiki_health_promotion_report(report)
        self.assertEqual(caught.exception.code, "ECO_M4_PROMOTION_REPORT_INVALID")


if __name__ == "__main__":
    unittest.main()
