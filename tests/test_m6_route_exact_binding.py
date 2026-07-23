"""M6 route/effect hardening: exact plans, authority and aggregate budgets."""

from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from eco_routing import (
    DeterministicModelRouter,
    DurableRouteConsumptionJournal,
    RouteAggregateUsage,
    RoutingError,
    VerifiedRouteAuthority,
    route_consumer_digest,
    route_execution_plan_digest,
    reserve_route_effect,
    seal_routing_record,
    validate_routing_record,
    verify_exact_route_binding,
    verify_route_binding,
)
from eco_runtime.errors import ContractValidationError

from tests.test_m6_routing import (
    NOW,
    candidate,
    deployment,
    observation,
    policy,
    price_catalog,
    route_request,
    timestamp,
)


KEY = b"e" * 32
EFFECT_DIGEST = "e" * 64


def _reseal(record: dict, mutate) -> dict:
    changed = copy.deepcopy(record)
    del changed["metadata"]["recordDigest"]
    mutate(changed)
    return seal_routing_record(changed)


class _AuthorityVerifier:
    def __init__(self, *, issuer_id: str = "route-authority", key_id: str = "route-key-v1"):
        self.issuer_id = issuer_id
        self.key_id = key_id
        self.calls = 0

    def verify_route_authority(self, *, decision, request, now):
        self.calls += 1
        return VerifiedRouteAuthority(
            issuer_id=self.issuer_id,
            key_id=self.key_id,
            algorithm="ed25519",
            evidence_digest="f" * 64,
            route_decision_digest=decision["metadata"]["recordDigest"],
            route_request_digest=request["metadata"]["recordDigest"],
            policy_digest=decision["spec"]["policyDigest"],
            price_catalog_digest=decision["spec"]["priceCatalogDigest"],
            execution_plan_digest=decision["spec"]["executionPlanDigest"],
            valid_until=timestamp(now + timedelta(minutes=5)),
        )


class ExactRouteBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = candidate(deployment("local-a", local=True))
        self.policy = policy(candidates=["local-a"])
        self.prices = price_catalog([self.local])
        self.plan_digest = route_execution_plan_digest(
            {
                "projectId": "project-1",
                "teamId": "team-1",
                "runId": "run-1",
                "manifestDigest": "1" * 64,
                "sourceBundleDigest": "2" * 64,
                "roles": ["eco-researcher", "eco-grader"],
                "maximumCalls": 5,
            }
        )
        self.aggregate_budget = {
            "maximumCalls": 5,
            "inputTokenCeiling": 5000,
            "outputTokenCeiling": 5000,
            "maximumCostMicrousd": 100,
        }
        self.request = route_request(
            self.policy,
            allowCloud=False,
            executionPlanDigest=self.plan_digest,
            aggregateBudget=self.aggregate_budget,
        )
        self.router = DeterministicModelRouter(self.policy, self.prices)
        self.decision = self.router.route(
            self.request,
            [self.local],
            [observation(self.local, latency=50)],
            now=NOW,
            decision_id="exact-decision-1",
            explain_id="exact-explain-1",
        ).decision
        self.selected = self.decision["spec"]["selected"]
        self.verifier = _AuthorityVerifier()

    def _trusted_arguments(self) -> dict:
        return {
            "expected_policy_digest": self.policy["metadata"]["recordDigest"],
            "expected_price_catalog_digest": self.prices["metadata"]["recordDigest"],
            "expected_execution_plan_digest": self.plan_digest,
            "authority_verifier": self.verifier,
            "expected_route_issuer_id": "route-authority",
            "expected_route_key_id": "route-key-v1",
            "expected_route_algorithm": "ed25519",
        }

    def test_plan_digest_is_domain_separated_and_change_sensitive(self) -> None:
        same = route_execution_plan_digest(
            {
                "projectId": "project-1",
                "teamId": "team-1",
                "runId": "run-1",
                "manifestDigest": "1" * 64,
                "sourceBundleDigest": "2" * 64,
                "roles": ["eco-researcher", "eco-grader"],
                "maximumCalls": 5,
            }
        )
        changed = route_execution_plan_digest({"projectId": "project-1", "maximumCalls": 6})
        self.assertEqual(same, self.plan_digest)
        self.assertNotEqual(changed, self.plan_digest)
        with self.assertRaises(RoutingError) as caught:
            route_execution_plan_digest({"notJson": object()})
        self.assertEqual(caught.exception.code, "ECO_ROUTE_EXECUTION_PLAN_INVALID")

    def test_aggregate_reservation_is_worst_case_and_bound_to_plan(self) -> None:
        self.assertEqual(self.decision["spec"]["executionPlanDigest"], self.plan_digest)
        self.assertEqual(self.selected["reservedCostMicrousd"], 15)
        self.assertEqual(
            self.selected["aggregateReservation"],
            {
                "maximumCalls": 5,
                "inputTokenCeiling": 5000,
                "outputTokenCeiling": 5000,
                "reservedCostMicrousd": 15,
            },
        )

    def test_contract_rejects_partial_or_laundered_aggregate_budget(self) -> None:
        partial = route_request(self.policy, executionPlanDigest=self.plan_digest)
        with self.assertRaises(ContractValidationError):
            validate_routing_record(partial)
        too_small = route_request(
            self.policy,
            executionPlanDigest=self.plan_digest,
            aggregateBudget={
                "maximumCalls": 5,
                "inputTokenCeiling": 999,
                "outputTokenCeiling": 5000,
                "maximumCostMicrousd": 100,
            },
        )
        with self.assertRaises(ContractValidationError):
            validate_routing_record(too_small)

    def test_exact_verification_binds_trusted_inputs_and_authority(self) -> None:
        decision, request = verify_exact_route_binding(
            self.decision,
            self.request,
            expected_deployment_id=self.selected["deploymentId"],
            expected_deployment_identity_digest=self.selected["deploymentIdentityDigest"],
            now=NOW + timedelta(seconds=1),
            **self._trusted_arguments(),
        )
        self.assertEqual(decision, self.decision)
        self.assertEqual(request, self.request)
        self.assertEqual(self.verifier.calls, 1)
        cases = (
            {"expected_policy_digest": "a" * 64},
            {"expected_price_catalog_digest": "b" * 64},
            {"expected_execution_plan_digest": "c" * 64},
            {"expected_route_key_id": "other-key"},
        )
        for override in cases:
            arguments = self._trusted_arguments()
            arguments.update(override)
            with self.subTest(field=next(iter(override))):
                with self.assertRaises(RoutingError):
                    verify_route_binding(
                        self.decision,
                        self.request,
                        expected_deployment_id=self.selected["deploymentId"],
                        expected_deployment_identity_digest=self.selected[
                            "deploymentIdentityDigest"
                        ],
                        now=NOW + timedelta(seconds=1),
                        **arguments,
                    )

    def test_exact_verification_cannot_omit_authority_or_aggregate_reservation(self) -> None:
        with self.assertRaises(RoutingError) as caught:
            verify_route_binding(
                self.decision,
                self.request,
                expected_deployment_id=self.selected["deploymentId"],
                expected_deployment_identity_digest=self.selected["deploymentIdentityDigest"],
                now=NOW,
                expected_execution_plan_digest=self.plan_digest,
                expected_route_issuer_id="route-authority",
            )
        self.assertEqual(caught.exception.code, "ECO_ROUTE_AUTHORITY_REQUIRED")
        stripped = _reseal(
            self.decision,
            lambda value: value["spec"]["selected"].pop("aggregateReservation"),
        )
        with self.assertRaises(ContractValidationError):
            validate_routing_record(stripped)

    def test_consumer_digest_covers_effect_request_and_plan(self) -> None:
        first = route_consumer_digest(
            self.decision,
            self.request,
            consumer_kind="source-review",
            consumer_id="run-1",
            effect_digest=EFFECT_DIGEST,
        )
        other_effect = route_consumer_digest(
            self.decision,
            self.request,
            consumer_kind="source-review",
            consumer_id="run-1",
            effect_digest="d" * 64,
        )
        self.assertNotEqual(first, other_effect)

    def test_aggregate_usage_reserves_each_effect_and_fails_closed(self) -> None:
        usage = reserve_route_effect(
            self.decision,
            self.request,
            RouteAggregateUsage(),
            input_tokens=900,
            output_tokens=900,
            cost_microusd=3,
        )
        self.assertEqual(usage, RouteAggregateUsage(1, 900, 900, 3))
        with self.assertRaises(RoutingError) as caught:
            reserve_route_effect(
                self.decision,
                self.request,
                usage,
                input_tokens=1001,
                output_tokens=1,
                cost_microusd=1,
            )
        self.assertEqual(caught.exception.code, "ECO_ROUTE_CALL_BUDGET_EXCEEDED")
        full = RouteAggregateUsage(5, 4500, 4500, 15)
        with self.assertRaises(RoutingError) as caught:
            reserve_route_effect(
                self.decision,
                self.request,
                full,
                input_tokens=1,
                output_tokens=1,
                cost_microusd=0,
            )
        self.assertEqual(caught.exception.code, "ECO_ROUTE_AGGREGATE_BUDGET_EXCEEDED")

    def test_consume_exact_derives_binding_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with DurableRouteConsumptionJournal(
                Path(temporary) / "private" / "routes.sqlite3",
                hmac_key=KEY,
                key_id="exact-route-v1",
            ) as journal:
                arguments = {
                    "expected_deployment_id": self.selected["deploymentId"],
                    "expected_deployment_identity_digest": self.selected[
                        "deploymentIdentityDigest"
                    ],
                    **self._trusted_arguments(),
                    "consumer_kind": "source-review",
                    "consumer_id": "run-1",
                    "effect_digest": EFFECT_DIGEST,
                    "now": NOW + timedelta(seconds=1),
                }
                first = journal.consume_exact(self.decision, self.request, **arguments)
                replay = journal.consume_exact(self.decision, self.request, **arguments)
                self.assertFalse(first["replayed"])
                self.assertTrue(replay["replayed"])
                status = journal.status(first["routeDigest"])
                self.assertEqual(
                    status["consumerDigest"],
                    route_consumer_digest(
                        self.decision,
                        self.request,
                        consumer_kind="source-review",
                        consumer_id="run-1",
                        effect_digest=EFFECT_DIGEST,
                    ),
                )


class StrictFallbackChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = candidate(deployment("local-a", local=True))
        self.cloud = candidate(deployment("cloud-b", local=False))
        self.policy = policy()
        self.prices = price_catalog([self.local, self.cloud])
        self.plan_digest = route_execution_plan_digest(
            {"projectId": "project-1", "runId": "fallback-run", "maximumCalls": 2}
        )
        self.request = route_request(
            self.policy,
            executionPlanDigest=self.plan_digest,
            aggregateBudget={
                "maximumCalls": 2,
                "inputTokenCeiling": 2000,
                "outputTokenCeiling": 2000,
                "maximumCostMicrousd": 100,
            },
        )
        self.verifier = _AuthorityVerifier()
        router = DeterministicModelRouter(self.policy, self.prices)
        observations = [
            observation(self.local, latency=50),
            observation(self.cloud, latency=100),
        ]
        self.first = router.route(
            self.request,
            [self.local, self.cloud],
            observations,
            now=NOW,
            decision_id="first",
            explain_id="first-explain",
        ).decision
        self.second = router.fallback(
            self.request,
            self.first,
            "capacity",
            [self.local, self.cloud],
            observations,
            now=NOW + timedelta(seconds=1),
            decision_id="second",
            explain_id="second-explain",
        ).decision

    def _consume(self, journal, decision, *, consumer_id="run-1", effect_digest=EFFECT_DIGEST):
        selected = decision["spec"]["selected"]
        return journal.consume_exact(
            decision,
            self.request,
            expected_deployment_id=selected["deploymentId"],
            expected_deployment_identity_digest=selected["deploymentIdentityDigest"],
            expected_policy_digest=self.policy["metadata"]["recordDigest"],
            expected_price_catalog_digest=self.prices["metadata"]["recordDigest"],
            expected_execution_plan_digest=self.plan_digest,
            authority_verifier=self.verifier,
            expected_route_issuer_id="route-authority",
            expected_route_key_id="route-key-v1",
            expected_route_algorithm="ed25519",
            consumer_kind="source-review",
            consumer_id=consumer_id,
            effect_digest=effect_digest,
            now=NOW + timedelta(seconds=1),
        )

    def test_fallback_must_continue_exact_consumed_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with DurableRouteConsumptionJournal(
                Path(temporary) / "private" / "routes.sqlite3",
                hmac_key=KEY,
                key_id="fallback-route-v1",
            ) as journal:
                self._consume(journal, self.first)
                for override in (
                    {"consumer_id": "run-2"},
                    {"effect_digest": "d" * 64},
                ):
                    with self.subTest(override=override):
                        with self.assertRaises(RoutingError) as caught:
                            self._consume(journal, self.second, **override)
                        self.assertEqual(
                            caught.exception.code,
                            "ECO_ROUTE_FALLBACK_PREDECESSOR_MISMATCH",
                        )
                receipt = self._consume(journal, self.second)
                self.assertFalse(receipt["replayed"])


if __name__ == "__main__":
    unittest.main()
