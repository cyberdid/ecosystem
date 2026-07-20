"""Durable aggregate usage accounting for exact M6 routes."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

from eco_routing import (
    DeterministicModelRouter,
    DurableRouteUsageJournal,
    RoutingError,
    route_consumer_digest,
    route_execution_plan_digest,
)

from tests.test_m6_routing import (
    NOW,
    candidate,
    deployment,
    observation,
    policy,
    price_catalog,
    route_request,
)


KEY = b"u" * 32
WORKFLOW_EFFECT_DIGEST = "e" * 64


class DurableRouteUsageJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "private" / "route-usage.sqlite3"
        self.local = candidate(deployment("local-a", local=True))
        self.policy = policy(candidates=["local-a"])
        self.prices = price_catalog([self.local])
        self.plan_digest = route_execution_plan_digest(
            {"projectId": "project-1", "runId": "run-1", "maximumCalls": 2}
        )
        self.request = self._request(maximum_calls=2)
        self.decision = self._decision(self.request, "usage-decision")
        self.consumer_digest = route_consumer_digest(
            self.decision,
            self.request,
            consumer_kind="source-review",
            consumer_id="run-1",
            effect_digest=WORKFLOW_EFFECT_DIGEST,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _request(self, *, maximum_calls: int) -> dict:
        return route_request(
            self.policy,
            allowCloud=False,
            executionPlanDigest=self.plan_digest,
            aggregateBudget={
                "maximumCalls": maximum_calls,
                "inputTokenCeiling": 1000 * maximum_calls,
                "outputTokenCeiling": 1000 * maximum_calls,
                "maximumCostMicrousd": 100,
            },
        )

    def _decision(self, request: dict, identifier: str) -> dict:
        return DeterministicModelRouter(self.policy, self.prices).route(
            request,
            [self.local],
            [observation(self.local, latency=50)],
            now=NOW,
            decision_id=identifier,
            explain_id=f"{identifier}-explain",
        ).decision

    def _journal(self, *, key: bytes = KEY) -> DurableRouteUsageJournal:
        return DurableRouteUsageJournal(self.path, hmac_key=key, key_id="route-usage-v1")

    def _reserve(
        self,
        journal: DurableRouteUsageJournal,
        effect_id: str,
        *,
        effect_digest: str | None = None,
        now=NOW + timedelta(seconds=1),
        input_tokens: int = 1000,
        output_tokens: int = 1000,
        cost_microusd: int = 3,
        decision: dict | None = None,
        request: dict | None = None,
    ) -> dict:
        return journal.reserve(
            decision or self.decision,
            request or self.request,
            consumer_kind="source-review",
            consumer_id="run-1",
            workflow_effect_digest=WORKFLOW_EFFECT_DIGEST,
            effect_id=effect_id,
            effect_digest=effect_digest or (effect_id[0] * 64),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_microusd=cost_microusd,
            now=now,
        )

    def test_reopen_preserves_usage_but_expired_replay_cannot_enable_egress(self) -> None:
        with self._journal() as journal:
            first = self._reserve(journal, "a-effect")
            self.assertFalse(first["replayed"])
            self.assertEqual(first["usage"]["calls"], 1)
        with self._journal() as reopened:
            self.assertEqual(reopened.verify()["entries"], 1)
            self.assertEqual(reopened.status(self.consumer_digest)["costMicrousd"], 3)
            with self.assertRaises(RoutingError) as caught:
                self._reserve(
                    reopened,
                    "a-effect",
                    now=NOW + timedelta(hours=12),
                )
            self.assertEqual(caught.exception.code, "ECO_ROUTE_EXPIRED")
            self.assertEqual(reopened.verify()["entries"], 1)

    def test_duplicate_effect_is_idempotent_but_changed_replay_is_denied(self) -> None:
        with self._journal() as journal:
            first = self._reserve(journal, "a-effect")
            replay = self._reserve(journal, "a-effect")
            self.assertFalse(first["replayed"])
            self.assertTrue(replay["replayed"])
            self.assertEqual(replay["entryHash"], first["entryHash"])
            self.assertEqual(replay["sequence"], first["sequence"])
            self.assertEqual(replay["usage"], first["usage"])
            with self.assertRaises(RoutingError) as caught:
                self._reserve(journal, "a-effect", effect_digest="b" * 64)
            self.assertEqual(caught.exception.code, "ECO_ROUTE_EFFECT_REPLAY_MISMATCH")
            self.assertEqual(journal.status(self.consumer_digest)["calls"], 1)
            self.assertEqual(journal.verify()["entries"], 1)

    def test_budget_exhaustion_is_atomic_and_does_not_advance_state(self) -> None:
        with self._journal() as journal:
            self._reserve(journal, "a-effect")
            second = self._reserve(journal, "b-effect")
            self.assertEqual(second["usage"], {
                "calls": 2,
                "inputTokens": 2000,
                "outputTokens": 2000,
                "costMicrousd": 6,
            })
            with self.assertRaises(RoutingError) as caught:
                self._reserve(journal, "c-effect")
            self.assertEqual(caught.exception.code, "ECO_ROUTE_AGGREGATE_BUDGET_EXCEEDED")
            self.assertEqual(journal.verify()["entries"], 2)
            self.assertEqual(journal.status(self.consumer_digest)["calls"], 2)

    def test_new_effect_after_route_expiry_is_denied_without_write(self) -> None:
        with self._journal() as journal:
            with self.assertRaises(RoutingError) as caught:
                self._reserve(journal, "a-effect", now=NOW + timedelta(hours=12))
            self.assertEqual(caught.exception.code, "ECO_ROUTE_EXPIRED")
            self.assertEqual(journal.verify()["entries"], 0)

    def test_wrong_key_and_tampered_projection_fail_closed(self) -> None:
        with self._journal() as journal:
            self._reserve(journal, "a-effect")
        with self.assertRaises(RoutingError) as caught:
            self._journal(key=b"x" * 32)
        self.assertEqual(caught.exception.code, "ECO_ROUTE_USAGE_TAMPERED")
        connection = sqlite3.connect(self.path)
        connection.execute("UPDATE aggregate_usage SET calls = calls + 1")
        connection.commit()
        connection.close()
        with self.assertRaises(RoutingError) as caught:
            self._journal()
        self.assertEqual(caught.exception.code, "ECO_ROUTE_USAGE_TAMPERED")

    def test_immutable_entries_and_missing_guard_fail_closed(self) -> None:
        with self._journal() as journal:
            self._reserve(journal, "a-effect")
        connection = sqlite3.connect(self.path)
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("UPDATE reserved_effects SET effect_id = 'evil'")
        connection.execute("DROP TRIGGER reserved_effects_immutable_update")
        connection.commit()
        connection.close()
        with self.assertRaises(RoutingError) as caught:
            self._journal()
        self.assertEqual(caught.exception.code, "ECO_ROUTE_USAGE_TAMPERED")

    def test_two_connections_cannot_atomically_overspend_one_call_budget(self) -> None:
        one_request = self._request(maximum_calls=1)
        one_decision = self._decision(one_request, "one-call-decision")
        first = self._journal()
        second = self._journal()
        barrier = threading.Barrier(2)

        def reserve(journal: DurableRouteUsageJournal, effect_id: str) -> str:
            barrier.wait(timeout=5)
            try:
                self._reserve(
                    journal,
                    effect_id,
                    decision=one_decision,
                    request=one_request,
                )
            except RoutingError as exc:
                return exc.code
            return "reserved"

        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(
                    pool.map(
                        lambda pair: reserve(*pair),
                        ((first, "a-effect"), (second, "b-effect")),
                    )
                )
            self.assertEqual(
                sorted(results),
                ["ECO_ROUTE_AGGREGATE_BUDGET_EXCEEDED", "reserved"],
            )
            self.assertEqual(first.verify()["entries"], 1)
        finally:
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
