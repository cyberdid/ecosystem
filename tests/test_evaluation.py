from __future__ import annotations

import copy
import json
import time
import unittest
from datetime import datetime, timezone

from eco_runtime.contracts import validate_record
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.evaluation import (
    CrossDeploymentEvaluationRunner,
    EvaluationCase,
    EvaluationEvidenceSigner,
    EvaluationInvocation,
    EvaluationRequest,
    EvaluationSuite,
    EvaluationUsage,
    PinnedEvaluationDeployment,
    SignedEvaluationEvidence,
    UsageTolerance,
    normalized_output_digest,
)


KEY = b"evaluation-signing-key-for-tests-32b!"
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
LOCAL_IDENTITY = "a" * 64
CLOUD_IDENTITY = "b" * 64


class MockEvaluationAdapter:
    def __init__(
        self,
        deployment_id: str,
        adapter_version: str,
        identity_digest: str,
        responses: dict[str, tuple[str, EvaluationUsage]],
        *,
        delay: float = 0,
    ) -> None:
        self.deployment_id = deployment_id
        self.adapter_version = adapter_version
        self._identity_digest = identity_digest
        self._responses = responses
        self._delay = delay
        self.seen: list[EvaluationRequest] = []

    def invoke(
        self, request: EvaluationRequest, *, timeout_seconds: float
    ) -> EvaluationInvocation:
        self.seen.append(request)
        if self._delay:
            time.sleep(self._delay)
        output, usage = self._responses[request.case_id]
        return EvaluationInvocation(self._identity_digest, output, usage)


class CrossDeploymentEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = EvaluationEvidenceSigner(key=KEY, key_id="eval-test-key")
        self.runner = CrossDeploymentEvaluationRunner(signer=self.signer, timeout_seconds=0.03)
        self.deployments = (
            PinnedEvaluationDeployment("local-pinned", LOCAL_IDENTITY, "adapter-v1"),
            PinnedEvaluationDeployment("cloud-pinned", CLOUD_IDENTITY, "adapter-v1"),
        )
        usage = EvaluationUsage(4, 2, 6)
        self.suite = EvaluationSuite(
            "m2-parity",
            "1.0.0",
            (
                EvaluationCase(
                    "deterministic-text",
                    "private prompt sentinel: do not persist",
                    normalized_output_digest("résumé\n"),
                ),
            ),
        )
        self.responses = {"deterministic-text": ("re\u0301sume\u0301\r\n", usage)}

    def adapters(self):
        return {
            "local-pinned": MockEvaluationAdapter(
                "local-pinned", "adapter-v1", LOCAL_IDENTITY, self.responses
            ),
            "cloud-pinned": MockEvaluationAdapter(
                "cloud-pinned", "adapter-v1", CLOUD_IDENTITY, self.responses
            ),
        }

    def assert_payload_rejected(self, mutator) -> None:
        result = self.runner.run(
            self.suite, self.deployments, self.adapters(), evaluated_at=NOW
        )
        payload = copy.deepcopy(result.evidence.payload)
        mutator(payload)
        with self.assertRaises(RuntimeStoreError) as caught:
            self.signer.sign(payload)
        self.assertEqual(caught.exception.code, "ECO_EVAL_EVIDENCE_INVALID")

    def test_identical_suite_emits_valid_signed_parity_observations(self) -> None:
        adapters = self.adapters()
        result = self.runner.run(self.suite, self.deployments, adapters, evaluated_at=NOW)
        payload = self.signer.verify(result.evidence, observations=result.observations)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["comparisons"][0]["status"], "parity")
        self.assertEqual([item["spec"]["status"] for item in result.observations], ["pass", "pass"])
        for observation in result.observations:
            validate_record(observation)
        self.assertEqual(adapters["local-pinned"].seen[0], adapters["cloud-pinned"].seen[0])

        serialized = json.dumps(result.evidence.as_dict(), sort_keys=True)
        self.assertNotIn("private prompt sentinel", serialized)
        self.assertNotIn("résumé", serialized)
        self.assertNotIn("configured-at-runtime", serialized)

        repeated = self.runner.run(self.suite, self.deployments, self.adapters(), evaluated_at=NOW)
        self.assertEqual(result.evidence.canonical_payload, repeated.evidence.canonical_payload)
        self.assertEqual(result.evidence.signature, repeated.evidence.signature)

    def test_output_divergence_fails_both_profiles_without_output_content(self) -> None:
        suite = EvaluationSuite(
            "m2-divergence", "1", (EvaluationCase("compare", "secret input"),)
        )
        usage = EvaluationUsage(1, 1, 2)
        adapters = {
            "local-pinned": MockEvaluationAdapter(
                "local-pinned", "adapter-v1", LOCAL_IDENTITY, {"compare": ("LOCAL SECRET", usage)}
            ),
            "cloud-pinned": MockEvaluationAdapter(
                "cloud-pinned", "adapter-v1", CLOUD_IDENTITY, {"compare": ("CLOUD SECRET", usage)}
            ),
        }
        result = self.runner.run(suite, self.deployments, adapters, evaluated_at=NOW)
        payload = result.evidence.payload
        self.assertEqual(payload["comparisons"][0]["status"], "divergence")
        for observation in result.observations:
            self.assertEqual(observation["spec"]["status"], "fail")
            self.assertIn("ECO_EVAL_OUTPUT_DIVERGENCE", observation["spec"]["deviationCodes"])
        serialized = json.dumps(result.evidence.as_dict())
        self.assertNotIn("LOCAL SECRET", serialized)
        self.assertNotIn("CLOUD SECRET", serialized)
        self.assertNotIn("secret input", serialized)

    def test_usage_divergence_obeys_explicit_tolerance(self) -> None:
        suite = EvaluationSuite(
            "m2-usage",
            "1",
            (
                EvaluationCase(
                    "usage", "input", usage_tolerance=UsageTolerance(input_tokens=1)
                ),
            ),
        )
        adapters = {
            "local-pinned": MockEvaluationAdapter(
                "local-pinned",
                "adapter-v1",
                LOCAL_IDENTITY,
                {"usage": ("same", EvaluationUsage(2, 1, 3))},
            ),
            "cloud-pinned": MockEvaluationAdapter(
                "cloud-pinned",
                "adapter-v1",
                CLOUD_IDENTITY,
                {"usage": ("same", EvaluationUsage(4, 1, 5))},
            ),
        }
        result = self.runner.run(suite, self.deployments, adapters, evaluated_at=NOW)
        self.assertEqual(result.evidence.payload["comparisons"][0]["status"], "divergence")
        self.assertTrue(
            all(
                "ECO_EVAL_USAGE_DIVERGENCE" in item["spec"]["deviationCodes"]
                for item in result.observations
            )
        )

    def test_timeout_is_fail_closed_and_sanitized(self) -> None:
        adapters = self.adapters()
        adapters["cloud-pinned"] = MockEvaluationAdapter(
            "cloud-pinned",
            "adapter-v1",
            CLOUD_IDENTITY,
            self.responses,
            delay=0.08,
        )
        result = self.runner.run(self.suite, self.deployments, adapters, evaluated_at=NOW)
        cloud = next(
            item for item in result.observations if item["metadata"]["deploymentId"] == "cloud-pinned"
        )
        self.assertEqual(cloud["spec"]["status"], "fail")
        self.assertEqual(cloud["spec"]["deviationCodes"], ["ECO_EVAL_TIMEOUT"])
        self.assertEqual(result.evidence.payload["comparisons"][0]["status"], "not-comparable")

    def test_identity_mismatch_and_signature_tamper_are_rejected(self) -> None:
        adapters = self.adapters()
        adapters["cloud-pinned"] = MockEvaluationAdapter(
            "cloud-pinned", "adapter-v1", "c" * 64, self.responses
        )
        result = self.runner.run(self.suite, self.deployments, adapters, evaluated_at=NOW)
        cloud = next(
            item for item in result.observations if item["metadata"]["deploymentId"] == "cloud-pinned"
        )
        self.assertEqual(cloud["spec"]["deviationCodes"], ["ECO_DEPLOYMENT_IDENTITY_MISMATCH"])
        tampered = SignedEvaluationEvidence(
            result.evidence.canonical_payload,
            result.evidence.key_id,
            "0" * 64,
        )
        with self.assertRaises(RuntimeStoreError) as caught:
            self.signer.verify(tampered, observations=result.observations)
        self.assertEqual(caught.exception.code, "ECO_EVAL_SIGNATURE_INVALID")

        altered_observations = [
            {**item, "metadata": dict(item["metadata"]), "spec": dict(item["spec"])}
            for item in result.observations
        ]
        local = next(
            item
            for item in altered_observations
            if item["metadata"]["deploymentId"] == "local-pinned"
        )
        local["spec"]["status"] = "fail"
        with self.assertRaises(RuntimeStoreError):
            self.signer.verify(result.evidence, observations=tuple(altered_observations))

    def test_evidence_rejects_invalid_time_probe_and_usage_shapes(self) -> None:
        mutations = (
            lambda payload: payload.__setitem__("evaluatedAt", "not-a-time"),
            lambda payload: payload["deployments"][0].__setitem__("probes", []),
            lambda payload: payload["deployments"][0]["probes"][0]["usage"].__setitem__(
                "totalTokens", 999
            ),
            lambda payload: payload["deployments"][0]["probes"][0].__setitem__(
                "caseId", "../unsafe"
            ),
            lambda payload: payload["deployments"][0]["probes"][0].pop(
                "normalizedOutputDigest"
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_payload_rejected(mutation)

    def test_evidence_rejects_inconsistent_comparison_and_derived_statuses(self) -> None:
        mutations = (
            lambda payload: payload["comparisons"][0].__setitem__(
                "rightDeploymentId", payload["comparisons"][0]["leftDeploymentId"]
            ),
            lambda payload: payload["comparisons"][0].__setitem__("cases", []),
            lambda payload: payload["comparisons"][0]["cases"][0].__setitem__(
                "status", "output-divergence"
            ),
            lambda payload: payload["comparisons"][0].__setitem__(
                "status", "divergence"
            ),
            lambda payload: payload["deployments"][0].__setitem__("status", "fail"),
            lambda payload: payload.__setitem__("status", "fail"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_payload_rejected(mutation)

    def test_observation_fields_must_reconcile_not_only_their_digest(self) -> None:
        result = self.runner.run(
            self.suite, self.deployments, self.adapters(), evaluated_at=NOW
        )
        observations = [copy.deepcopy(item) for item in result.observations]
        observations[0]["spec"]["status"] = "fail"
        payload = copy.deepcopy(result.evidence.payload)
        deployment_id = observations[0]["metadata"]["deploymentId"]
        deployment = next(
            item for item in payload["deployments"] if item["deploymentId"] == deployment_id
        )
        deployment["observationDigest"] = semantic_digest(observations[0])
        resigned = self.signer.sign(payload)

        with self.assertRaises(RuntimeStoreError) as caught:
            self.signer.verify(resigned, observations=tuple(observations))
        self.assertEqual(caught.exception.code, "ECO_EVAL_EVIDENCE_INVALID")


if __name__ == "__main__":
    unittest.main()
