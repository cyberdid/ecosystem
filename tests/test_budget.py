from __future__ import annotations

import copy
import threading
import unittest

from eco_runtime.budget import BudgetLedger
from eco_runtime.errors import RuntimeBudgetError
from tests.test_runtime_contracts import run_plan


class BudgetLedgerTests(unittest.TestCase):
    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeBudgetError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_initial_artifact_bytes_are_charged(self) -> None:
        ledger = BudgetLedger(run_plan())
        self.assertEqual(ledger.snapshot().input_bytes, 42)
        ledger.consume_input_bytes(8)
        self.assertEqual(ledger.snapshot().input_bytes, 50)

    def test_initial_inputs_cannot_exceed_budget(self) -> None:
        plan = run_plan()
        plan["spec"]["budget"]["maxInputBytes"] = 41
        self.assert_code("ECO_BUDGET_EXHAUSTED", lambda: BudgetLedger(plan))

    def test_tool_reservation_is_atomic_under_concurrency(self) -> None:
        plan = run_plan()
        plan["spec"]["budget"]["maxToolRequests"] = 1
        ledger = BudgetLedger(plan)
        barrier = threading.Barrier(2)
        outcomes: list[str] = []

        def reserve() -> None:
            barrier.wait()
            try:
                ledger.reserve_tool_request()
                outcomes.append("allowed")
            except RuntimeBudgetError as exc:
                outcomes.append(exc.code)

        threads = [threading.Thread(target=reserve) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ECO_TOOL_BUDGET_EXHAUSTED", "allowed"])
        self.assertEqual(ledger.snapshot().tool_requests, 1)

    def test_model_usage_update_is_all_or_nothing(self) -> None:
        plan = run_plan()
        plan["spec"]["budget"]["maxTotalTokens"] = 10
        ledger = BudgetLedger(plan)
        self.assert_code(
            "ECO_TOKEN_BUDGET_EXHAUSTED",
            lambda: ledger.consume_model_usage(output_bytes=1, tokens=11, cost_microusd=1),
        )
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.model_requests, 0)
        self.assertEqual(snapshot.output_bytes, 0)
        self.assertEqual(snapshot.total_tokens, 0)
        self.assertEqual(snapshot.cost_microusd, 0)

    def test_duration_uses_monotonic_clock(self) -> None:
        clock = [100.0]
        plan = copy.deepcopy(run_plan())
        plan["spec"]["budget"]["maxDurationSeconds"] = 5
        ledger = BudgetLedger(plan, clock=lambda: clock[0])
        clock[0] = 106.0
        self.assert_code("ECO_DURATION_EXHAUSTED", ledger.reserve_tool_request)

    def test_input_reservations_prevent_concurrent_overspend_and_release_on_failure(self) -> None:
        plan = run_plan()
        plan["spec"]["budget"]["maxInputBytes"] = 50
        ledger = BudgetLedger(plan)
        reservation = ledger.reserve_input_bytes(8)
        self.assertEqual(ledger.snapshot().reserved_input_bytes, 8)
        self.assert_code(
            "ECO_INPUT_BUDGET_EXHAUSTED",
            lambda: ledger.reserve_input_bytes(1),
        )
        reservation.release()
        self.assertEqual(ledger.snapshot().reserved_input_bytes, 0)
        second = ledger.reserve_input_bytes(8)
        second.commit(8)
        self.assertEqual(ledger.snapshot().input_bytes, 50)

    def test_reservation_cannot_commit_more_than_reserved(self) -> None:
        ledger = BudgetLedger(run_plan())
        reservation = ledger.reserve_input_bytes(5)
        self.assert_code("ECO_INPUT_BUDGET_EXHAUSTED", lambda: reservation.commit(6))
        reservation.release()


if __name__ == "__main__":
    unittest.main()
