from __future__ import annotations

import copy
import json
import unittest
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_routing import (
    DeterministicModelRouter,
    Ed25519RouteAuthoritySigner,
    Ed25519RouteAuthorityVerifier,
    RoutingError,
    route_execution_plan_digest,
    verify_exact_route_binding,
)
from eco_runtime.digests import canonical_json

from tests.test_m6_routing import (
    NOW,
    candidate,
    deployment,
    observation,
    policy,
    price_catalog,
    route_request,
)


PRIVATE_KEY = b"r" * 32


class RouteAuthorityEnvelopeTests(unittest.TestCase):
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
                "maximumCalls": 5,
            }
        )
        self.request = route_request(
            self.policy,
            allowCloud=False,
            executionPlanDigest=self.plan_digest,
            aggregateBudget={
                "maximumCalls": 5,
                "inputTokenCeiling": 5000,
                "outputTokenCeiling": 5000,
                "maximumCostMicrousd": 100,
            },
        )
        self.decision = DeterministicModelRouter(self.policy, self.prices).route(
            self.request,
            [self.local],
            [observation(self.local, latency=50)],
            now=NOW,
            decision_id="authority-decision-1",
            explain_id="authority-explain-1",
        ).decision
        self.private = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY)
        self.public_key = self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.envelope = Ed25519RouteAuthoritySigner(
            "route-authority",
            "route-key-v1",
            PRIVATE_KEY,
        ).sign(
            self.decision,
            self.request,
            envelope_id="route-envelope-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
        )

    def _verify(self, verifier: Ed25519RouteAuthorityVerifier) -> None:
        selected = self.decision["spec"]["selected"]
        verify_exact_route_binding(
            self.decision,
            self.request,
            expected_deployment_id=selected["deploymentId"],
            expected_deployment_identity_digest=selected[
                "deploymentIdentityDigest"
            ],
            expected_policy_digest=self.policy["metadata"]["recordDigest"],
            expected_price_catalog_digest=self.prices["metadata"]["recordDigest"],
            expected_execution_plan_digest=self.plan_digest,
            authority_verifier=verifier,
            expected_route_issuer_id="route-authority",
            expected_route_key_id="route-key-v1",
            expected_route_algorithm="ed25519",
            now=NOW + timedelta(seconds=1),
        )

    def test_signed_envelope_authenticates_every_exact_route_binding(self) -> None:
        self._verify(Ed25519RouteAuthorityVerifier(self.envelope, self.public_key))

    def test_signature_key_and_binding_tamper_fail_closed(self) -> None:
        tampered = json.loads(self.envelope)
        tampered["bindings"]["executionPlanDigest"] = "f" * 64
        encoded = canonical_json(tampered).encode("utf-8")
        cases = (
            Ed25519RouteAuthorityVerifier(encoded, self.public_key),
            Ed25519RouteAuthorityVerifier(self.envelope, b"x" * 32),
        )
        for verifier in cases:
            with self.subTest(verifier=type(verifier).__name__):
                with self.assertRaises(RoutingError):
                    self._verify(verifier)

    def test_route_substitution_and_expired_envelope_fail_closed(self) -> None:
        changed = copy.deepcopy(self.decision)
        changed["metadata"]["recordDigest"] = "a" * 64
        verifier = Ed25519RouteAuthorityVerifier(self.envelope, self.public_key)
        with self.assertRaises(RoutingError):
            verifier.verify_route_authority(
                decision=changed,
                request=self.request,
                now=NOW + timedelta(seconds=1),
            )
        with self.assertRaises(RoutingError):
            verifier.verify_route_authority(
                decision=self.decision,
                request=self.request,
                now=NOW + timedelta(minutes=11),
            )
