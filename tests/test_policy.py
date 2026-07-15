from __future__ import annotations

import copy
import threading
import unittest
from datetime import datetime, timedelta, timezone

from eco_cli.templates import starter_bundle
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.evidence import EvidenceIssuerPolicy, HmacEvidenceSigner
from eco_runtime.policy import PolicyEngine


NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64
TEST_EVIDENCE_KEY = b"policy-fixture-evidence-key-32-bytes"


def exact_deployment(identifier: str = "dgx-test") -> dict:
    endpoint_ref = f"env:ECO_{identifier.upper().replace('-', '_')}_ENDPOINT"
    return {
        "id": identifier,
        "provider": "local",
        "adapter": "fake-openai-compatible",
        "model": "fixture-model",
        "endpointRef": endpoint_ref,
        "zone": "Z1",
        "allowedDataClasses": ["D0", "D1"],
        "artifactTrust": "P1",
        "declaredCapabilities": ["model.text", "model.tool-calling"],
        "observedCapabilitiesRef": f"evals/observed/{identifier}.json",
        "retention": "test-no-store",
        "trainingUse": "prohibited",
        "region": "local-test",
        "identity": {
            "adapterVersion": "0.1.0",
            "modelRevision": "fixture-revision-1",
            "runtimeEngine": "fake-runtime",
            "runtimeVersion": "1.0.0",
            "quantization": "none",
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
        "enabled": True,
    }


def observation(deployment: dict) -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "AdapterConformanceProfile",
        "metadata": {
            "id": f"{deployment['id']}-observation-1",
            "deploymentId": deployment["id"],
            "testedAt": "2026-07-01T00:00:00Z",
            "validUntil": "2026-08-01T00:00:00Z",
        },
        "spec": {
            "deploymentIdentityDigest": deployment_identity_digest(deployment),
            "adapterVersion": "0.1.0",
            "suite": {
                "id": "adapter-conformance-v1",
                "version": "1.0.0",
                "digest": DIGEST,
            },
            "status": "pass",
            "effectiveCapabilities": ["model.text", "model.tool-calling"],
            "probes": [
                {
                    "id": "text-basic",
                    "status": "pass",
                    "attempts": 3,
                    "successes": 3,
                    "evidenceDigest": DIGEST,
                },
                {
                    "id": "tool-call-normalization",
                    "status": "pass",
                    "attempts": 3,
                    "successes": 3,
                    "evidenceDigest": DIGEST,
                },
            ],
            "deviationCodes": [],
        },
    }


def policy_bundle() -> tuple[dict, dict[str, dict]]:
    bundle = starter_bundle("sample")
    deployment = exact_deployment()
    bundle["deployments"]["deployments"] = [deployment]
    role = bundle["deployments"]["logicalRoles"]["code.read"]
    role["candidates"] = [deployment["id"]]
    observations = {deployment["id"]: observation(deployment)}
    return bundle, observations


def artifact_registry(data_class: str = "D1") -> dict[str, dict]:
    ref = "artifact://inputs/instruction-1"
    return {
        ref: {
            "apiVersion": API_VERSION,
            "kind": "ArtifactRecord",
            "metadata": {"id": "instruction-1", "runId": "run-1", "createdAt": "2026-07-15T11:59:00Z"},
            "spec": {
                "role": "input",
                "mediaType": "text/plain",
                "byteLength": 32,
                "sha256": DIGEST,
                "dataClass": data_class,
                "trust": "P1",
                "producer": {"type": "operator", "id": "operator-1"},
                "parentRefs": [],
                "storageRef": ref,
                "retention": "run",
            },
        }
    }


def repository_snapshot(
    *,
    root_identity_digest: str = DIGEST,
    content_digest: str = DIGEST,
    byte_length: int = 14,
    data_class: str = "D1",
) -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RepositorySnapshot",
        "metadata": {
            "id": "repository-snapshot-1",
            "projectId": "sample",
            "createdAt": "2026-07-15T11:58:00Z",
            "issuer": {"type": "operator", "id": "operator-1"},
        },
        "spec": {
            "rootIdentityDigest": root_identity_digest,
            "trust": "P1",
            "sourceRevision": "fixture-revision",
            "entries": [
                {
                    "path": "README.md",
                    "contentDigest": content_digest,
                    "byteLength": byte_length,
                    "dataClass": data_class,
                    "trust": "P1",
                    "classificationAuthority": "operator",
                }
            ],
        },
    }


def run_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RunRequest",
        "metadata": {
            "id": "request-1",
            "createdAt": "2026-07-15T12:00:00Z",
            "actor": {"type": "human", "id": "operator-1"},
        },
        "spec": {
            "projectId": "sample",
            "logicalRole": "code.read",
            "dataClass": "D1",
            "classificationAuthority": "operator",
            "deploymentPin": "dgx-test",
            "task": {
                "type": "repository.review",
                "instructionRef": "artifact://inputs/instruction-1",
                "inputRefs": [],
            },
            "requestedTools": ["repository.read"],
            "constraints": {
                "maximumActionClass": "A1",
                "sandbox": "inspect",
                "agentNetwork": "deny",
                "toolNetwork": "deny",
            },
            "budget": {
                "maxDurationSeconds": 60,
                "maxModelRequests": 1,
                "maxToolRequests": 5,
                "maxInputBytes": 100_000,
                "maxOutputBytes": 10_000,
                "maxTotalTokens": 10_000,
                "maxCostMicrousd": 1_000_000,
            },
            "fallbackPolicy": "none",
        },
    }


def plan(engine: PolicyEngine, request: dict | None = None):
    return engine.plan_run(
        request or run_request(),
        run_id="run-1",
        plan_id="plan-1",
        decision_id="decision-run-1",
        now=NOW,
    )


def trusted_policy_engine(
    bundle: dict,
    observations: dict[str, dict],
    artifacts: dict[str, dict] | None = None,
    *,
    repository_snapshot_record: dict | None = None,
    trusted_suite_digests: set[str] | None = None,
    **kwargs,
) -> PolicyEngine:
    """Test-only signed composition helper; production exposes no unsigned constructor."""

    suites = set(trusted_suite_digests or {DIGEST})
    signed_suite = sorted(suites)[0]
    deployments = {item["id"]: item for item in bundle["deployments"]["deployments"]}
    signer = HmacEvidenceSigner("operator-1", "policy-test-key", TEST_EVIDENCE_KEY)
    envelopes: dict[str, bytes] = {}
    for deployment_id, raw in observations.items():
        normalized = copy.deepcopy(raw)
        normalized["metadata"]["deploymentId"] = deployment_id
        normalized["metadata"]["testedAt"] = "2026-07-01T00:00:00Z"
        normalized["metadata"]["validUntil"] = "2026-08-01T00:00:00Z"
        normalized["spec"]["deploymentIdentityDigest"] = deployment_identity_digest(
            deployments[deployment_id]
        )
        normalized["spec"]["suite"]["digest"] = signed_suite
        envelopes[deployment_id] = signer.sign(
            normalized,
            envelope_id=f"policy-test-{deployment_id}",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
        )
    snapshot_envelope = None
    root_identity = None
    if repository_snapshot_record is not None:
        snapshot_envelope = signer.sign(
            repository_snapshot_record,
            envelope_id="policy-test-repository-snapshot",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=30),
        )
        root_identity = repository_snapshot_record["spec"]["rootIdentityDigest"]
    policies = (
        EvidenceIssuerPolicy(
            "operator-1",
            "policy-test-key",
            TEST_EVIDENCE_KEY,
            frozenset({"AdapterConformanceProfile", "RepositorySnapshot"}),
            allowed_projects=frozenset({bundle["project"]["metadata"]["name"]}),
            allowed_deployments=frozenset(observations),
            allowed_suite_digests=frozenset(suites),
        ),
    )
    engine = PolicyEngine(
        bundle,
        envelopes,
        artifacts,
        repository_snapshot=snapshot_envelope,
        evidence_policies=policies,
        evidence_now=NOW,
        repository_root_identity_digest=root_identity,
        trusted_suite_digests=suites,
        **kwargs,
    )
    # Policy semantic tests deliberately mutate already-authenticated records. This
    # assignment exists only in the tests package and is not an installed runtime API.
    engine._observations = copy.deepcopy(observations)
    engine._refresh_trusted_evidence = lambda _now: None
    return engine


def tool_request_for(plan_record: dict, path: str = "README.md") -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ToolRequest",
        "metadata": {
            "id": "tool-request-1",
            "runId": "run-1",
            "createdAt": "2026-07-15T12:00:01Z",
            "source": "model",
        },
        "spec": {
            "planDigest": semantic_digest(plan_record),
            "toolId": "repository.read",
            "arguments": {"path": path},
        },
    }


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle, self.observations = policy_bundle()
        self.artifacts = artifact_registry()
        self.repository_snapshot = repository_snapshot()

    def engine(self) -> PolicyEngine:
        return trusted_policy_engine(
            self.bundle,
            self.observations,
            self.artifacts,
            repository_snapshot_record=self.repository_snapshot,
            trusted_suite_digests={DIGEST},
        )

    def test_unsigned_runtime_evidence_is_rejected_by_default(self) -> None:
        with self.assertRaises(RuntimePolicyError) as captured:
            PolicyEngine(
                self.bundle,
                self.observations,
                self.artifacts,
                repository_snapshot=self.repository_snapshot,
                trusted_suite_digests={DIGEST},
            )
        self.assertEqual(captured.exception.code, "ECO_EVIDENCE_UNTRUSTED")

    def test_policy_engine_owns_an_exact_trust_policy_verifier(self) -> None:
        class ForgedPolicy(EvidenceIssuerPolicy):
            pass

        forged = ForgedPolicy(
            "operator-1",
            "forged-key",
            TEST_EVIDENCE_KEY,
            frozenset({"AdapterConformanceProfile"}),
            allowed_deployments=frozenset({"dgx-test"}),
            allowed_suite_digests=frozenset({DIGEST}),
        )
        with self.assertRaises(RuntimePolicyError) as captured:
            PolicyEngine(
                self.bundle,
                {"dgx-test": b"not-signed"},
                self.artifacts,
                evidence_policies=(forged,),
                evidence_now=NOW,
                trusted_suite_digests={DIGEST},
            )
        self.assertEqual(captured.exception.code, "ECO_EVIDENCE_UNTRUSTED")

    def assert_denied(self, result, code: str) -> None:
        self.assertIsNone(result.plan)
        self.assertEqual(result.decision["spec"]["effect"], "deny")
        self.assertEqual(result.decision["spec"]["reasonCodes"], [code])

    def test_valid_run_is_planned_and_digest_bound(self) -> None:
        engine = self.engine()
        result = plan(engine)
        self.assertIsNotNone(result.plan)
        self.assertEqual(result.decision["spec"]["effect"], "allow")
        mutated = copy.deepcopy(result.plan)
        mutated["spec"]["budget"]["maxOutputBytes"] += 1
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(mutated, result.decision, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_PLAN_UNTRUSTED")
        engine.activate_plan(result.plan, result.decision, now=NOW)
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(result.plan, result.decision, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_DECISION_REPLAYED")

    def test_tool_decision_is_bound_to_exact_arguments(self) -> None:
        engine = self.engine()
        run_result = plan(engine)
        tool_request = tool_request_for(run_result.plan)
        engine.activate_plan(run_result.plan, run_result.decision, now=NOW)
        decision = engine.authorize_tool(
            run_result.plan, tool_request, decision_id="decision-tool-1", now=NOW
        )
        self.assertEqual(decision["spec"]["effect"], "allow")
        mutated = copy.deepcopy(tool_request)
        mutated["spec"]["arguments"]["path"] = "pyproject.toml"
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.consume_decision(decision, mutated, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_DECISION_MISMATCH")
        engine.consume_decision(decision, tool_request, now=NOW)
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.consume_decision(decision, tool_request, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_DECISION_REPLAYED")

    def test_invalid_tool_arguments_are_denied_without_echo(self) -> None:
        engine = self.engine()
        run_result = plan(engine)
        tool_request = tool_request_for(run_result.plan, "../ECO_TEST_SECRET_DO_NOT_ECHO")
        engine.activate_plan(run_result.plan, run_result.decision, now=NOW)
        decision = engine.authorize_tool(
            run_result.plan, tool_request, decision_id="decision-tool-1", now=NOW
        )
        self.assertEqual(decision["spec"]["effect"], "deny")
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", str(decision))

    def test_unknown_role_is_denied(self) -> None:
        request = run_request()
        request["spec"]["logicalRole"] = "unknown.role"
        self.assert_denied(plan(self.engine(), request), "ECO_UNKNOWN_ROLE")

    def test_disabled_pinned_deployment_is_terminal(self) -> None:
        self.bundle["deployments"]["deployments"][0]["enabled"] = False
        alternate = exact_deployment("alternate")
        self.bundle["deployments"]["deployments"].append(alternate)
        self.bundle["deployments"]["logicalRoles"]["code.read"]["candidates"].append("alternate")
        self.observations["alternate"] = observation(alternate)
        self.assert_denied(plan(self.engine()), "ECO_DEPLOYMENT_DISABLED")

    def test_data_zone_and_trust_intersection_fail_closed(self) -> None:
        request = run_request()
        request["spec"]["dataClass"] = "D2"
        self.assert_denied(plan(self.engine(), request), "ECO_DATA_CLASS_DENIED")

        self.bundle, self.observations = policy_bundle()
        self.bundle["deployments"]["deployments"][0]["zone"] = "Z4"
        self.assert_denied(plan(self.engine()), "ECO_ZONE_DENIED")

        self.bundle, self.observations = policy_bundle()
        self.bundle["deployments"]["logicalRoles"]["code.read"]["minimumArtifactTrust"] = "P2"
        self.assert_denied(plan(self.engine()), "ECO_ARTIFACT_TRUST_INSUFFICIENT")

    def test_observation_must_be_fresh_and_identity_bound(self) -> None:
        missing_engine = trusted_policy_engine(
            self.bundle,
            {},
            self.artifacts,
            repository_snapshot_record=self.repository_snapshot,
            trusted_suite_digests={DIGEST},
        )
        self.assert_denied(plan(missing_engine), "ECO_OBSERVATION_MISSING")

        self.observations["dgx-test"]["metadata"]["validUntil"] = "2026-07-15T11:59:59Z"
        self.assert_denied(plan(self.engine()), "ECO_OBSERVATION_STALE")

        self.bundle, self.observations = policy_bundle()
        self.observations["dgx-test"]["spec"]["deploymentIdentityDigest"] = "b" * 64
        self.assert_denied(plan(self.engine()), "ECO_OBSERVATION_MISMATCH")

    def test_declared_and_observed_capability_intersection_is_required(self) -> None:
        self.observations["dgx-test"]["spec"]["effectiveCapabilities"] = []
        self.assert_denied(plan(self.engine()), "ECO_CAPABILITY_UNAVAILABLE")

    def test_unpinned_multiple_candidates_are_ambiguous(self) -> None:
        alternate = exact_deployment("alternate")
        self.bundle["deployments"]["deployments"].append(alternate)
        self.bundle["deployments"]["logicalRoles"]["code.read"]["candidates"].append("alternate")
        self.observations["alternate"] = observation(alternate)
        request = run_request()
        del request["spec"]["deploymentPin"]
        self.assert_denied(plan(self.engine(), request), "ECO_ROUTE_AMBIGUOUS")

    def test_requested_tool_must_be_m2_broker_owned(self) -> None:
        request = run_request()
        request["spec"]["requestedTools"] = ["tests.run"]
        self.assert_denied(plan(self.engine(), request), "ECO_TOOL_NOT_ALLOWED")

    def test_engine_uses_deep_copied_policy_snapshot(self) -> None:
        engine = self.engine()
        self.bundle["project"]["metadata"]["name"] = "mutated-after-snapshot"
        result = plan(engine)
        self.assertIsNotNone(result.plan)
        self.assertEqual(result.plan["spec"]["project"]["id"], "sample")

    def test_semantic_digest_is_order_stable_and_rejects_nan(self) -> None:
        self.assertEqual(semantic_digest({"a": 1, "b": 2}), semantic_digest({"b": 2, "a": 1}))
        with self.assertRaises(RuntimePolicyError) as captured:
            semantic_digest({"bad": float("nan")})
        self.assertEqual(captured.exception.code, "ECO_CANONICALIZATION_FAILED")

    def test_expired_decision_does_not_authorize(self) -> None:
        engine = trusted_policy_engine(
            self.bundle,
            self.observations,
            self.artifacts,
            repository_snapshot_record=self.repository_snapshot,
            trusted_suite_digests={DIGEST},
            decision_ttl_seconds=1,
        )
        result = plan(engine)
        later = datetime(2026, 7, 15, 12, 0, 2, tzinfo=timezone.utc)
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(result.plan, result.decision, now=later)
        self.assertEqual(captured.exception.code, "ECO_DECISION_EXPIRED")

    def test_forged_decision_and_forged_plan_are_rejected(self) -> None:
        engine = self.engine()
        result = plan(engine)

        forged_decision = copy.deepcopy(result.decision)
        forged_decision["metadata"]["id"] = "forged-decision"
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(result.plan, forged_decision, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_DECISION_UNTRUSTED")

        forged_plan = copy.deepcopy(result.plan)
        forged_plan["metadata"]["id"] = "forged-plan"
        forged_plan["spec"]["tools"][0]["catalogDigest"] = "b" * 64
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(forged_plan, result.decision, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_PLAN_UNTRUSTED")

    def test_decision_run_and_policy_binding_are_enforced(self) -> None:
        engine = self.engine()
        result = plan(engine)

        wrong_run = copy.deepcopy(result.decision)
        wrong_run["metadata"]["runId"] = "another-run"
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(result.plan, wrong_run, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_DECISION_MISMATCH")

        wrong_policy = copy.deepcopy(result.decision)
        wrong_policy["spec"]["policySnapshot"]["semanticConfigDigest"] = "b" * 64
        with self.assertRaises(RuntimePolicyError) as captured:
            engine.activate_plan(result.plan, wrong_policy, now=NOW)
        self.assertEqual(captured.exception.code, "ECO_CONFIG_DRIFT")

    def test_concurrent_decision_consume_allows_exactly_once(self) -> None:
        engine = self.engine()
        result = plan(engine)
        engine.activate_plan(result.plan, result.decision, now=NOW)
        request = tool_request_for(result.plan)
        decision = engine.authorize_tool(result.plan, request, decision_id="tool-decision", now=NOW)
        outcomes: list[str] = []
        lock = threading.Lock()

        def consume() -> None:
            try:
                engine.consume_decision(decision, request, now=NOW)
                outcome = "allowed"
            except RuntimePolicyError as exc:
                outcome = exc.code
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=consume) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ECO_DECISION_REPLAYED", "allowed"])

    def test_zero_tool_budget_denies_requested_tool(self) -> None:
        request = run_request()
        request["spec"]["budget"]["maxToolRequests"] = 0
        self.assert_denied(plan(self.engine(), request), "ECO_BUDGET_INVALID")

    def test_initial_artifact_bytes_must_fit_input_budget(self) -> None:
        request = run_request()
        request["spec"]["budget"]["maxInputBytes"] = 1
        self.assert_denied(plan(self.engine(), request), "ECO_BUDGET_INVALID")

    def test_repository_read_descriptor_is_code_owned(self) -> None:
        tool = self.bundle["tools"]["tools"][0]
        tool["transport"] = "http"
        tool["binding"] = "https://attacker.invalid"
        self.assert_denied(plan(self.engine()), "ECO_TOOL_BINDING_MISMATCH")

    def test_invalid_canonical_trust_fails_at_engine_construction(self) -> None:
        self.bundle["deployments"]["logicalRoles"]["code.read"]["minimumArtifactTrust"] = "PX"
        with self.assertRaises(RuntimePolicyError) as captured:
            self.engine()
        self.assertEqual(captured.exception.code, "ECO_CONFIG_INVALID")

    def test_malformed_canonical_item_fails_typed_at_construction(self) -> None:
        self.bundle["tools"]["tools"] = ["not-an-object"]
        with self.assertRaises(RuntimePolicyError) as captured:
            self.engine()
        self.assertEqual(captured.exception.code, "ECO_CONFIG_INVALID")

    def test_repository_read_requires_a_trusted_snapshot(self) -> None:
        engine = trusted_policy_engine(
            self.bundle,
            self.observations,
            self.artifacts,
            trusted_suite_digests={DIGEST},
        )
        self.assert_denied(plan(engine), "ECO_REPOSITORY_SNAPSHOT_MISSING")

    def test_tool_request_time_is_bound_to_plan_and_runtime_clock(self) -> None:
        engine = self.engine()
        result = plan(engine)
        engine.activate_plan(result.plan, result.decision, now=NOW)
        for index, created_at in enumerate(
            ("2026-07-15T11:59:59Z", "2099-01-01T00:00:00Z"),
            start=1,
        ):
            request = tool_request_for(result.plan)
            request["metadata"]["id"] = f"timed-tool-{index}"
            request["metadata"]["createdAt"] = created_at
            decision = engine.authorize_tool(
                result.plan,
                request,
                decision_id=f"timed-decision-{index}",
                now=NOW,
            )
            self.assertEqual(decision["spec"]["effect"], "deny")
            self.assertEqual(decision["spec"]["reasonCodes"], ["ECO_TOOL_REQUEST_TIME_INVALID"])

    def test_artifact_classification_controls_route(self) -> None:
        self.artifacts = artifact_registry("D2")
        self.assert_denied(plan(self.engine()), "ECO_DATA_CLASS_DENIED")

        self.artifacts = artifact_registry("D4")
        self.assert_denied(plan(self.engine()), "ECO_DATA_CLASS_DENIED")

        self.artifacts = {}
        self.assert_denied(plan(self.engine()), "ECO_ARTIFACT_MISSING")

    def test_future_request_and_naive_clock_are_rejected(self) -> None:
        request = run_request()
        request["metadata"]["createdAt"] = "2099-01-01T00:00:00Z"
        self.assert_denied(plan(self.engine(), request), "ECO_REQUEST_TIME_INVALID")
        with self.assertRaises(RuntimePolicyError) as captured:
            self.engine().plan_run(
                run_request(),
                run_id="run-1",
                plan_id="plan-1",
                decision_id="decision-1",
                now=datetime(2026, 7, 15, 12, 0, 0),
            )
        self.assertEqual(captured.exception.code, "ECO_CLOCK_INVALID")

    def test_observation_semantics_and_suite_are_enforced(self) -> None:
        untrusted = trusted_policy_engine(
            self.bundle,
            self.observations,
            self.artifacts,
            repository_snapshot_record=self.repository_snapshot,
            trusted_suite_digests={"b" * 64},
        )
        self.assert_denied(plan(untrusted), "ECO_EVALUATION_SUITE_UNTRUSTED")

        self.observations["dgx-test"]["spec"]["probes"][0]["successes"] = 4
        self.assert_denied(plan(self.engine()), "ECO_OBSERVATION_INVALID")

        self.bundle, self.observations = policy_bundle()
        self.artifacts = artifact_registry()
        self.observations["dgx-test"]["spec"]["probes"][1]["status"] = "fail"
        self.assert_denied(plan(self.engine()), "ECO_CAPABILITY_UNVERIFIED")

    def test_observation_excessive_lifetime_is_stale(self) -> None:
        self.observations["dgx-test"]["metadata"]["testedAt"] = "2020-01-01T00:00:00Z"
        self.observations["dgx-test"]["metadata"]["validUntil"] = "2030-01-01T00:00:00Z"
        self.assert_denied(plan(self.engine()), "ECO_OBSERVATION_STALE")

    def test_endpoint_reference_digest_mismatch_is_denied(self) -> None:
        self.bundle["deployments"]["deployments"][0]["endpointRef"] = "env:CHANGED_ENDPOINT"
        with self.assertRaises(RuntimePolicyError) as captured:
            self.engine()
        self.assertEqual(captured.exception.code, "ECO_IDENTITY_MISMATCH")


if __name__ == "__main__":
    unittest.main()
