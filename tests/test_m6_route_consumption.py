"""M6.4 durable route consumption and the eco route CLI composition."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from eco_cli.cli import main
from eco_routing import (
    DeterministicModelRouter,
    DurableRouteConsumptionJournal,
    RoutingError,
    verify_route_binding,
)
from eco_routing.contracts import seal_routing_record

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


KEY = b"r" * 32
CONSUMER = {
    "consumer_kind": "source-review",
    "consumer_id": "run-1",
    "consumer_digest": "c" * 64,
}


def _reseal(record: dict, mutate) -> dict:
    changed = copy.deepcopy(record)
    del changed["metadata"]["recordDigest"]
    mutate(changed)
    return seal_routing_record(changed)


class RouteConsumptionJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.local = deployment("local-a", local=True, latency=50)
        self.candidate = candidate(self.local)
        self.policy = policy(candidates=["local-a"])
        self.prices = price_catalog([self.candidate])
        self.observations = [observation(self.candidate, latency=50)]
        self.request = route_request(self.policy, allowCloud=False)
        router = DeterministicModelRouter(self.policy, self.prices)
        outcome = router.route(
            self.request,
            [self.candidate],
            self.observations,
            now=NOW,
            decision_id="decision-1",
            explain_id="explain-1",
        )
        self.decision = outcome.decision
        self.assertEqual(self.decision["spec"]["decision"], "allowed")
        self.selected = self.decision["spec"]["selected"]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _journal(self) -> DurableRouteConsumptionJournal:
        return DurableRouteConsumptionJournal(
            self.state / "routes.sqlite3", hmac_key=KEY, key_id="route-test-v1"
        )

    def _consume(self, journal: DurableRouteConsumptionJournal, **overrides):
        arguments = {
            "expected_deployment_id": self.selected["deploymentId"],
            "expected_deployment_identity_digest": self.selected["deploymentIdentityDigest"],
            "now": NOW + timedelta(seconds=1),
            **CONSUMER,
        }
        arguments.update(overrides)
        return journal.consume(self.decision, self.request, **arguments)

    def test_consume_is_single_use_with_idempotent_replay(self) -> None:
        with self._journal() as journal:
            first = self._consume(journal)
            self.assertFalse(first["replayed"])
            replay = self._consume(journal)
            self.assertTrue(replay["replayed"])
            self.assertEqual(first["routeDigest"], replay["routeDigest"])
            with self.assertRaises(RoutingError) as caught:
                self._consume(journal, consumer_id="run-2")
            self.assertEqual(caught.exception.code, "ECO_ROUTE_ALREADY_CONSUMED")
            state = journal.verify()
            self.assertEqual(state["entries"], 1)
            status = journal.status(first["routeDigest"])
            self.assertEqual(status["consumerId"], "run-1")

    def test_binding_mismatches_are_typed_and_write_nothing(self) -> None:
        cases = [
            ({"expected_deployment_id": "other-deployment"}, "ECO_ROUTE_BINDING_MISMATCH"),
            (
                {"expected_deployment_identity_digest": "b" * 64},
                "ECO_ROUTE_BINDING_MISMATCH",
            ),
            ({"cost_reservation_microusd": self.selected["reservedCostMicrousd"] + 1},
             "ECO_ROUTE_BINDING_MISMATCH"),
            ({"now": NOW + timedelta(hours=6)}, "ECO_ROUTE_EXPIRED"),
        ]
        with self._journal() as journal:
            for overrides, code in cases:
                with self.subTest(code=code, overrides=sorted(overrides)):
                    with self.assertRaises(RoutingError) as caught:
                        self._consume(journal, **overrides)
                    self.assertEqual(caught.exception.code, code)
            self.assertEqual(journal.verify()["entries"], 0)

    def test_denied_decision_and_cross_request_are_rejected(self) -> None:
        denied = _reseal(
            self.decision,
            lambda value: value["spec"].update(
                {
                    "decision": "denied",
                    "selected": None,
                    "reasonCode": "no-eligible-candidate",
                }
            ),
        )
        other_request = route_request(self.policy, inputTokenCeiling=999)
        with self._journal() as journal:
            with self.assertRaises(RoutingError) as caught:
                journal.consume(
                    denied,
                    self.request,
                    expected_deployment_id=self.selected["deploymentId"],
                    expected_deployment_identity_digest=self.selected[
                        "deploymentIdentityDigest"
                    ],
                    now=NOW,
                    **CONSUMER,
                )
            self.assertEqual(caught.exception.code, "ECO_ROUTE_NOT_ALLOWED")
            with self.assertRaises(RoutingError) as caught:
                journal.consume(
                    self.decision,
                    other_request,
                    expected_deployment_id=self.selected["deploymentId"],
                    expected_deployment_identity_digest=self.selected[
                        "deploymentIdentityDigest"
                    ],
                    now=NOW,
                    **CONSUMER,
                )
            self.assertEqual(caught.exception.code, "ECO_ROUTE_BINDING_MISMATCH")
            self.assertEqual(journal.verify()["entries"], 0)

    def test_fallback_requires_its_consumed_predecessor(self) -> None:
        second = _reseal(
            self.decision,
            lambda value: (
                value["metadata"].update({"id": "decision-2"}),
                value["spec"].update(
                    {
                        "routeAttempt": 2,
                        "fallbackFromDigest": self.decision["metadata"]["recordDigest"],
                    }
                ),
            ),
        )
        with self._journal() as journal:
            with self.assertRaises(RoutingError) as caught:
                journal.consume(
                    second,
                    self.request,
                    expected_deployment_id=self.selected["deploymentId"],
                    expected_deployment_identity_digest=self.selected[
                        "deploymentIdentityDigest"
                    ],
                    now=NOW,
                    **CONSUMER,
                )
            self.assertEqual(
                caught.exception.code, "ECO_ROUTE_FALLBACK_PREDECESSOR_MISSING"
            )
            self._consume(journal)
            receipt = journal.consume(
                second,
                self.request,
                expected_deployment_id=self.selected["deploymentId"],
                expected_deployment_identity_digest=self.selected[
                    "deploymentIdentityDigest"
                ],
                now=NOW,
                consumer_kind="source-review",
                consumer_id="run-2",
                consumer_digest="d" * 64,
            )
            self.assertFalse(receipt["replayed"])
            self.assertEqual(journal.verify()["entries"], 2)

    def test_tampered_rows_and_wrong_key_fail_closed(self) -> None:
        with self._journal() as journal:
            self._consume(journal)
        path = self.state / "routes.sqlite3"
        with self.assertRaises(RoutingError) as caught:
            DurableRouteConsumptionJournal(path, hmac_key=b"x" * 32, key_id="route-test-v1")
        self.assertEqual(caught.exception.code, "ECO_ROUTE_JOURNAL_TAMPERED")
        connection = sqlite3.connect(path)
        connection.execute("DROP TRIGGER consumed_routes_immutable_update")
        connection.execute("UPDATE consumed_routes SET consumer_id = 'evil'")
        connection.commit()
        connection.close()
        with self.assertRaises(RoutingError) as caught:
            DurableRouteConsumptionJournal(path, hmac_key=KEY, key_id="route-test-v1")
        self.assertEqual(caught.exception.code, "ECO_ROUTE_JOURNAL_TAMPERED")

    def test_immutability_triggers_protect_consumptions(self) -> None:
        with self._journal() as journal:
            self._consume(journal)
        connection = sqlite3.connect(self.state / "routes.sqlite3")
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("UPDATE consumed_routes SET consumer_id = 'evil'")
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM consumed_routes")
        connection.close()

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_journal_files_are_private(self) -> None:
        with self._journal() as journal:
            self._consume(journal)
        directory = self.state.lstat()
        database = (self.state / "routes.sqlite3").lstat()
        self.assertEqual(stat.S_IMODE(directory.st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(database.st_mode), 0o600)

    def test_verify_route_binding_is_pure_and_returns_records(self) -> None:
        decision, request = verify_route_binding(
            self.decision,
            self.request,
            expected_deployment_id=self.selected["deploymentId"],
            expected_deployment_identity_digest=self.selected["deploymentIdentityDigest"],
            now=NOW,
        )
        self.assertEqual(decision["metadata"]["recordDigest"], self.decision["metadata"]["recordDigest"])
        self.assertEqual(request["metadata"]["recordDigest"], self.request["metadata"]["recordDigest"])
        self.assertFalse((self.state / "routes.sqlite3").exists())


class RoutePlanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["--repo", str(self.repo), "init"]), 0)
        self.local = deployment("local-a", local=True)
        self.candidate = candidate(self.local)
        self.policy = policy(candidates=["local-a"])
        self.prices = price_catalog([self.candidate])
        self.request = route_request(self.policy, allowCloud=False)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _plan(self, *extra: str) -> tuple[int, dict]:
        arguments = [
            "--repo", str(self.repo),
            "route", "plan",
            "--policy", str(self._write("policy.json", self.policy)),
            "--prices", str(self._write("prices.json", self.prices)),
            "--request", str(self._write("request.json", self.request)),
            "--observation",
            str(
                self._write(
                    "observation.json", observation(self.candidate, latency=50)
                )
            ),
            "--at", timestamp(NOW),
            "--json",
            *extra,
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(arguments)
        return code, json.loads(stdout.getvalue())

    def test_starter_repo_without_enabled_deployment_is_a_typed_denial(self) -> None:
        code, result = self._plan()
        self.assertEqual(code, 1)
        self.assertEqual(result["decision"]["spec"]["decision"], "denied")
        self.assertIsNone(result["decision"]["spec"]["selected"])
        self.assertIn("decision", result)
        self.assertIn("explain", result)
        surface = json.dumps(result)
        self.assertNotIn("ECO_LOCAL_A_ENDPOINT", surface)

    def test_invalid_inputs_fail_with_sanitized_errors(self) -> None:
        missing = [
            "--repo", str(self.repo),
            "route", "plan",
            "--policy", str(self.root / "absent.json"),
            "--prices", str(self._write("prices.json", self.prices)),
            "--request", str(self._write("request.json", self.request)),
            "--json",
        ]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main(missing), 2)
        self.assertIn("policy", stderr.getvalue())
        bad_time = io.StringIO()
        with contextlib.redirect_stderr(bad_time):
            code, _payload = None, None
            code = main(
                [
                    "--repo", str(self.repo),
                    "route", "plan",
                    "--policy", str(self._write("policy.json", self.policy)),
                    "--prices", str(self._write("prices.json", self.prices)),
                    "--request", str(self._write("request.json", self.request)),
                    "--at", "not-a-time",
                    "--json",
                ]
            )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
