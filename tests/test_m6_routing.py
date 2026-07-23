from __future__ import annotations

import copy
import itertools
import json
import unittest
from datetime import datetime, timedelta, timezone

from eco_routing import (
    CANONICAL_MODEL_ROLES,
    DeploymentCandidate,
    DeterministicModelRouter,
    ROUTING_API_VERSION,
    candidates_from_deployment_catalog,
    routing_contract_errors,
    routing_record_digest,
    routing_schema_bundle_digest,
    seal_routing_record,
    validate_routing_record,
)
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def deployment(identifier: str, *, local: bool, latency: int = 100) -> dict:
    endpoint_ref = f"env:ECO_{identifier.upper().replace('-', '_')}_ENDPOINT"
    return {
        "id": identifier,
        "provider": "local" if local else "approved-cloud",
        "adapter": "openai-compatible",
        "model": f"model-{identifier}",
        "endpointRef": endpoint_ref,
        "zone": "Z1" if local else "Z3",
        "allowedDataClasses": ["D0", "D1", "D2"] if local else ["D0", "D1"],
        "artifactTrust": "P2",
        "declaredCapabilities": ["model.text", "model.structured-output"],
        "observedCapabilitiesRef": f".ai/evals/observed/{identifier}.json",
        "retention": "local-runtime-dependent" if local else "contractual",
        "trainingUse": "prohibited",
        "region": "local" if local else "eu-approved",
        "identity": {
            "adapterVersion": "openai-compatible-v1",
            "modelRevision": "sha256:model-revision-1",
            "runtimeEngine": "test-runtime",
            "runtimeVersion": "1.0.0",
            "quantization": "none",
            "endpointReferenceDigest": semantic_digest({"endpointRef": endpoint_ref}),
        },
        "enabled": True,
        "_testLatency": latency,
    }


def candidate(value: dict) -> DeploymentCandidate:
    projected = copy.deepcopy(value)
    projected.pop("_testLatency", None)
    return DeploymentCandidate.from_canonical_deployment(projected)


def record(kind: str, identifier: str, spec: dict, *, revision: int | None = None) -> dict:
    metadata = {"id": identifier, "createdAt": timestamp(NOW)}
    if revision is not None:
        metadata["revision"] = revision
    return seal_routing_record(
        {
            "apiVersion": ROUTING_API_VERSION,
            "kind": kind,
            "metadata": metadata,
            "spec": spec,
        }
    )


def policy(*, candidates: list[str] | None = None) -> dict:
    candidate_ids = candidates or ["local-a", "cloud-b"]
    roles = []
    for role in CANONICAL_MODEL_ROLES:
        roles.append(
            {
                "role": role,
                "requiredCapabilities": ["model.structured-output", "model.text"],
                "allowedActionClasses": ["A0", "A1", "A2"],
                "allowedDataClasses": ["D0", "D1", "D2"],
                "allowedZones": ["Z1", "Z3"],
                "allowedRetentions": ["contractual", "local-runtime-dependent"],
                "candidateIds": list(candidate_ids),
                "maximumCostMicrousd": 1000,
                "fallback": {
                    "maxRouteAttempts": 2,
                    "retryableFailureClasses": ["capacity", "transport-retryable"],
                },
            }
        )
    return record(
        "ModelRoutingPolicy",
        "policy-1",
        {"defaultDecision": "deny", "decisionTtlSeconds": 300, "roles": roles},
        revision=1,
    )


def price_catalog(candidates: list[DeploymentCandidate], *, zero_local: bool = False) -> dict:
    entries = []
    for item in sorted(candidates, key=lambda value: value.deployment_id):
        local = item.deployment_id.startswith("local")
        entries.append(
            {
                "deploymentId": item.deployment_id,
                "deploymentIdentityDigest": item.identity_digest,
                "inputMicrousdPerMillionTokens": 0 if local and zero_local else (1000 if local else 2000),
                "outputMicrousdPerMillionTokens": 0 if local and zero_local else (2000 if local else 4000),
                "fixedRequestMicrousd": 0 if local else 2,
            }
        )
    return record(
        "TrustedPriceCatalog",
        "prices-1",
        {
            "authority": "operator",
            "currency": "microUSD",
            "validFrom": timestamp(NOW - timedelta(hours=1)),
            "validUntil": timestamp(NOW + timedelta(hours=2)),
            "sourceProvenanceDigest": DIGEST,
            "entries": entries,
        },
        revision=1,
    )


def observation(item: DeploymentCandidate, *, latency: int, valid_minutes: int = 30) -> dict:
    return record(
        "ObservedModelCapabilities",
        f"observation-{item.deployment_id}",
        {
            "authority": "trusted-observation",
            "deploymentId": item.deployment_id,
            "deploymentIdentityDigest": item.identity_digest,
            "capabilities": ["model.structured-output", "model.text"],
            "contextWindowTokens": 32768,
            "latencyP95Millis": latency,
            "observedAt": timestamp(NOW - timedelta(minutes=1)),
            "validUntil": timestamp(NOW + timedelta(minutes=valid_minutes)),
            "evidenceEnvelopeDigest": semantic_digest({"envelope": item.deployment_id}),
            "suiteDigest": DIGEST,
        },
    )


def route_request(policy_record: dict, **overrides: object) -> dict:
    spec = {
        "role": "eco-researcher",
        "actionClass": "A1",
        "dataClass": "D1",
        "workloadClass": "research",
        "requiredCapabilities": ["model.structured-output"],
        "requiredContextTokens": 8192,
        "inputTokenCeiling": 1000,
        "outputTokenCeiling": 1000,
        "allowedZones": ["Z1", "Z3"],
        "allowedRetentions": ["contractual", "local-runtime-dependent"],
        "allowCloud": True,
        "maximumCostMicrousd": 100,
        "deadlineAt": timestamp(NOW + timedelta(seconds=10)),
        "executionProfile": "standard",
        "policyDigest": policy_record["metadata"]["recordDigest"],
        "contextDigest": semantic_digest({"trustedContext": "fixture"}),
    }
    spec.update(overrides)
    for key in ("requiredCapabilities", "allowedZones", "allowedRetentions"):
        spec[key] = sorted(spec[key])
    return record("ModelRouteRequest", "request-1", spec)


class RoutingContractTests(unittest.TestCase):
    def test_registry_is_additive_and_records_validate(self) -> None:
        local = candidate(deployment("local-a", local=True))
        cloud = candidate(deployment("cloud-b", local=False))
        p = policy()
        records = [
            p,
            price_catalog([local, cloud]),
            observation(local, latency=100),
            route_request(p),
        ]
        for item in records:
            self.assertEqual(validate_routing_record(item), item)
            self.assertEqual(routing_contract_errors(item), [])
            self.assertEqual(item["metadata"]["recordDigest"], routing_record_digest(item))
        self.assertRegex(routing_schema_bundle_digest(), r"^[a-f0-9]{64}$")

    def test_policy_requires_every_canonical_role_once_in_order(self) -> None:
        value = policy()
        value["spec"]["roles"][0]["role"] = "eco-worker"
        value = seal_routing_record(value)
        with self.assertRaises(ContractValidationError):
            validate_routing_record(value)


class DeterministicRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = candidate(deployment("local-a", local=True))
        self.cloud = candidate(deployment("cloud-b", local=False))
        self.policy = policy()
        self.prices = price_catalog([self.local, self.cloud])
        self.observations = [
            observation(self.local, latency=200),
            observation(self.cloud, latency=100),
        ]
        self.router = DeterministicModelRouter(self.policy, self.prices)

    def route(self, request: dict | None = None, **kwargs: object):
        return self.router.route(
            request or route_request(self.policy),
            kwargs.pop("candidates", [self.local, self.cloud]),
            kwargs.pop("observations", self.observations),
            now=kwargs.pop("now", NOW),
            decision_id=kwargs.pop("decision_id", "decision-1"),
            explain_id=kwargs.pop("explain_id", "explain-1"),
        )

    def test_ordering_is_permutation_invariant_and_cost_first(self) -> None:
        first = self.route()
        second = self.route(
            candidates=[self.cloud, self.local],
            observations=list(reversed(self.observations)),
        )
        self.assertEqual(first.decision, second.decision)
        self.assertEqual(first.explain, second.explain)
        selected = first.decision["spec"]["selected"]
        self.assertEqual(selected["deploymentId"], "local-a")
        self.assertEqual(selected["reservedCostMicrousd"], 3)

    def test_property_all_three_candidate_permutations_are_identical(self) -> None:
        third = candidate(deployment("cloud-c", local=False))
        p = policy(candidates=["local-a", "cloud-b", "cloud-c"])
        candidates = [self.local, self.cloud, third]
        observations = [
            observation(self.local, latency=200),
            observation(self.cloud, latency=100),
            observation(third, latency=100),
        ]
        router = DeterministicModelRouter(p, price_catalog(candidates))
        expected = None
        for candidate_order in itertools.permutations(candidates):
            for observation_order in itertools.permutations(observations):
                outcome = router.route(
                    route_request(p), candidate_order, observation_order,
                    now=NOW, decision_id="property-decision", explain_id="property-explain"
                )
                projection = (outcome.decision, outcome.explain)
                if expected is None:
                    expected = projection
                self.assertEqual(projection, expected)

    def test_no_candidate_is_a_typed_denial(self) -> None:
        outcome = self.route(candidates=[])
        self.assertEqual(outcome.decision["spec"]["decision"], "denied")
        self.assertEqual(outcome.decision["spec"]["reasonCode"], "no-eligible-candidate")
        self.assertIsNone(outcome.decision["spec"]["selected"])

    def test_stale_price_catalog_denies_before_routing(self) -> None:
        stale = copy.deepcopy(self.prices)
        stale["spec"]["validFrom"] = timestamp(NOW - timedelta(hours=2))
        stale["spec"]["validUntil"] = timestamp(NOW - timedelta(hours=1))
        stale = seal_routing_record(stale)
        router = DeterministicModelRouter(self.policy, stale)
        outcome = router.route(
            route_request(self.policy), self.local and [self.local], [self.observations[0]],
            now=NOW, decision_id="denied", explain_id="denied-explain"
        )
        self.assertEqual(outcome.decision["spec"]["reasonCode"], "price-catalog-stale")

    def test_stale_evidence_is_not_eligible(self) -> None:
        stale = observation(self.local, latency=100, valid_minutes=1)
        outcome = self.route(
            route_request(self.policy, deadlineAt=timestamp(NOW + timedelta(minutes=5))),
            candidates=[self.local], observations=[stale], now=NOW + timedelta(minutes=2)
        )
        self.assertIn("capability-evidence-stale", outcome.explain["spec"]["candidates"][0]["reasonCodes"])

    def test_policy_binding_and_action_are_fail_closed(self) -> None:
        wrong = route_request(self.policy, policyDigest="b" * 64)
        self.assertEqual(self.route(wrong).decision["spec"]["reasonCode"], "policy-binding-mismatch")
        action = route_request(self.policy, actionClass="A4")
        self.assertEqual(self.route(action).decision["spec"]["reasonCode"], "request-policy-denied")

    def test_candidate_filters_are_explicit(self) -> None:
        cases = {
            "zone-denied": route_request(self.policy, allowedZones=["Z0"]),
            "retention-denied": route_request(self.policy, allowedRetentions=["no-retention"]),
            "cost-denied": route_request(self.policy, maximumCostMicrousd=0),
            "deadline-insufficient": route_request(
                self.policy, deadlineAt=timestamp(NOW + timedelta(milliseconds=50))
            ),
            "context-window-insufficient": route_request(self.policy, requiredContextTokens=65536),
        }
        for reason, request in cases.items():
            with self.subTest(reason=reason):
                outcome = self.route(request, candidates=[self.local], observations=[self.observations[0]])
                self.assertEqual(outcome.decision["spec"]["decision"], "denied")
                self.assertIn(reason, outcome.explain["spec"]["candidates"][0]["reasonCodes"])

    def test_data_class_is_checked_by_role_and_deployment(self) -> None:
        role_denial = route_request(self.policy, dataClass="D3")
        self.assertEqual(self.route(role_denial).decision["spec"]["reasonCode"], "request-policy-denied")
        local_only = route_request(self.policy, dataClass="D2")
        outcome = self.route(
            local_only, candidates=[self.cloud], observations=[self.observations[1]]
        )
        self.assertIn("data-class-denied", outcome.explain["spec"]["candidates"][0]["reasonCodes"])

    def test_provider_identity_drift_denies_candidate(self) -> None:
        drifted = copy.deepcopy(self.observations[0])
        drifted["spec"]["deploymentIdentityDigest"] = "b" * 64
        drifted = seal_routing_record(drifted)
        outcome = self.route(candidates=[self.local], observations=[drifted])
        reasons = outcome.explain["spec"]["candidates"][0]["reasonCodes"]
        self.assertIn("provider-identity-drift", reasons)

    def test_price_catalog_is_copied_and_cloud_cost_is_computed_by_router(self) -> None:
        mutable = copy.deepcopy(self.prices)
        router = DeterministicModelRouter(self.policy, mutable)
        mutable["spec"]["entries"][0]["fixedRequestMicrousd"] = 999999
        outcome = router.route(
            route_request(self.policy), [self.local], [self.observations[0]],
            now=NOW, decision_id="copy-decision", explain_id="copy-explain"
        )
        self.assertEqual(outcome.decision["spec"]["selected"]["reservedCostMicrousd"], 3)
        self.assertNotIn("reservedCostMicrousd", route_request(self.policy)["spec"])
        cloud = router.route(
            route_request(self.policy), [self.cloud], [self.observations[1]],
            now=NOW, decision_id="cloud-cost", explain_id="cloud-cost-explain"
        )
        self.assertEqual(cloud.decision["spec"]["selected"]["reservedCostMicrousd"], 8)

    def test_price_identity_drift_denies_candidate(self) -> None:
        prices = copy.deepcopy(self.prices)
        local_entry = next(
            item for item in prices["spec"]["entries"] if item["deploymentId"] == "local-a"
        )
        local_entry["deploymentIdentityDigest"] = "b" * 64
        prices["spec"]["entries"] = sorted(
            prices["spec"]["entries"],
            key=lambda item: (item["deploymentId"], item["deploymentIdentityDigest"]),
        )
        prices = seal_routing_record(prices)
        router = DeterministicModelRouter(self.policy, prices)
        outcome = router.route(
            route_request(self.policy), [self.local], [self.observations[0]],
            now=NOW, decision_id="price-drift", explain_id="price-drift-explain"
        )
        self.assertIn(
            "provider-identity-drift",
            outcome.explain["spec"]["candidates"][0]["reasonCodes"],
        )

    def test_m61_profile_remains_local_and_zero_cost(self) -> None:
        prices = price_catalog([self.local, self.cloud], zero_local=True)
        router = DeterministicModelRouter(self.policy, prices)
        request = route_request(
            self.policy,
            executionProfile="m6.1-local-zero-cost",
            allowCloud=False,
            maximumCostMicrousd=0,
        )
        outcome = router.route(
            request, [self.cloud, self.local], self.observations,
            now=NOW, decision_id="local-decision", explain_id="local-explain"
        )
        selected = outcome.decision["spec"]["selected"]
        self.assertEqual(selected["deploymentId"], "local-a")
        self.assertEqual(selected["reservedCostMicrousd"], 0)
        invalid_request = route_request(
            self.policy,
            executionProfile="m6.1-local-zero-cost",
            allowCloud=True,
            maximumCostMicrousd=0,
        )
        self.assertEqual(
            router.route(
                invalid_request, [self.local], [self.observations[0]],
                now=NOW, decision_id="bad-local", explain_id="bad-local-explain"
            ).decision["spec"]["reasonCode"],
            "request-policy-denied",
        )

    def test_explain_contains_only_digests_and_reason_codes(self) -> None:
        explain = self.route().explain
        encoded = json.dumps(explain, sort_keys=True)
        for forbidden in (
            "local-a",
            "cloud-b",
            "approved-cloud",
            "model-local",
            "endpoint",
            "secret://",
            "ECO_LOCAL_A_ENDPOINT",
            ".ai/evals",
        ):
            self.assertNotIn(forbidden, encoded)


class FallbackRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = candidate(deployment("local-a", local=True))
        self.cloud = candidate(deployment("cloud-b", local=False))
        self.policy = policy()
        self.request = route_request(self.policy)
        self.observations = [
            observation(self.local, latency=200),
            observation(self.cloud, latency=100),
        ]
        self.router = DeterministicModelRouter(
            self.policy, price_catalog([self.local, self.cloud])
        )
        self.first = self.router.route(
            self.request, [self.local, self.cloud], self.observations,
            now=NOW, decision_id="initial", explain_id="initial-explain"
        ).decision

    def fallback(self, failure: str, **kwargs: object):
        return self.router.fallback(
            self.request,
            self.first,
            failure,
            kwargs.pop("candidates", [self.local, self.cloud]),
            kwargs.pop("observations", self.observations),
            now=kwargs.pop("now", NOW + timedelta(seconds=1)),
            decision_id="fallback",
            explain_id="fallback-explain",
        )

    def test_retryable_transport_failure_gets_fresh_second_route(self) -> None:
        outcome = self.fallback("transport-retryable")
        self.assertEqual(outcome.decision["spec"]["decision"], "allowed")
        self.assertEqual(outcome.decision["spec"]["routeAttempt"], 2)
        self.assertEqual(outcome.decision["spec"]["selected"]["deploymentId"], "cloud-b")
        self.assertEqual(
            outcome.decision["spec"]["fallbackFromDigest"],
            self.first["metadata"]["recordDigest"],
        )

    def test_policy_privacy_authority_schema_and_ambiguous_never_fallback(self) -> None:
        for failure in ("policy", "privacy", "authority", "schema", "ambiguous", "budget"):
            with self.subTest(failure=failure):
                outcome = self.fallback(failure)
                self.assertEqual(outcome.decision["spec"]["decision"], "denied")
                self.assertEqual(outcome.decision["spec"]["reasonCode"], "fallback-not-authorized")

    def test_identity_drift_never_falls_through_to_another_provider(self) -> None:
        changed = deployment("local-a", local=True)
        changed["identity"]["modelRevision"] = "sha256:different"
        drifted = candidate(changed)
        outcome = self.fallback("capacity", candidates=[drifted, self.cloud])
        self.assertEqual(outcome.decision["spec"]["reasonCode"], "fallback-identity-drift")

    def test_expired_prior_decision_cannot_authorize_fallback(self) -> None:
        outcome = self.fallback("capacity", now=NOW + timedelta(minutes=6))
        self.assertEqual(outcome.decision["spec"]["reasonCode"], "fallback-not-authorized")

    def test_fallback_uses_fresh_evidence(self) -> None:
        stale_soon = copy.deepcopy(self.observations)
        for item in stale_soon:
            item["spec"]["validUntil"] = timestamp(NOW + timedelta(seconds=1))
            item.update(seal_routing_record(item))
        outcome = self.fallback(
            "capacity",
            now=NOW + timedelta(seconds=2),
            observations=stale_soon,
        )
        self.assertEqual(outcome.decision["spec"]["decision"], "denied")
        self.assertIn(
            "capability-evidence-stale",
            next(
                item for item in outcome.explain["spec"]["candidates"]
                if item["outcome"] != "excluded"
            )["reasonCodes"],
        )


class DeploymentProjectionTests(unittest.TestCase):
    def test_projection_reuses_canonical_identity_without_endpoint_output(self) -> None:
        first = deployment("local-a", local=True)
        first.pop("_testLatency")
        second = deployment("cloud-b", local=False)
        second.pop("_testLatency")
        catalog = {
            "apiVersion": "ai.ecosystem/v1alpha1",
            "kind": "DeploymentCatalog",
            "deployments": [first, second],
            "logicalRoles": {},
        }
        projected = candidates_from_deployment_catalog(catalog)
        self.assertEqual([item.deployment_id for item in projected], ["local-a", "cloud-b"])
        self.assertNotIn("endpoint", repr(projected).lower())


if __name__ == "__main__":
    unittest.main()
