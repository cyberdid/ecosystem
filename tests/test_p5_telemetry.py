from __future__ import annotations

import json
import unittest

from eco_telemetry import CostRecord, TelemetryError, TelemetryLedger


class TelemetryLedgerTests(unittest.TestCase):
    def test_records_aggregate_per_role_and_total(self) -> None:
        ledger = TelemetryLedger()
        ledger.record(CostRecord("run-1", "planner", tokens=100, cost_microusd=200, elapsed_ms=50))
        ledger.record(CostRecord("run-1", "worker", tokens=300, cost_microusd=400, elapsed_ms=80))
        ledger.record(CostRecord("run-1", "planner", tokens=50, cost_microusd=60, elapsed_ms=10))
        s = ledger.summary()
        self.assertEqual((s.total_tokens, s.total_cost_microusd, s.total_elapsed_ms), (450, 660, 140))
        self.assertEqual(s.per_role["planner"], {"tokens": 150, "costMicrousd": 260, "elapsedMs": 60, "events": 2})

    def test_cost_cap_stops_before_breach_fail_closed(self) -> None:
        ledger = TelemetryLedger(cost_cap_microusd=500)
        ledger.record(CostRecord("r", "a", tokens=10, cost_microusd=300, elapsed_ms=1))
        with self.assertRaises(TelemetryError) as ctx:
            ledger.record(CostRecord("r", "b", tokens=10, cost_microusd=300, elapsed_ms=1))
        self.assertEqual(ctx.exception.code, "ECO_TELEMETRY_CAP_EXCEEDED")
        # breaching record was NOT admitted
        self.assertEqual(ledger.summary().total_cost_microusd, 300)
        self.assertTrue(ledger.within_caps)

    def test_token_cap_stops_before_breach(self) -> None:
        ledger = TelemetryLedger(token_cap=100)
        ledger.record(CostRecord("r", "a", tokens=100, cost_microusd=1, elapsed_ms=1))
        with self.assertRaises(TelemetryError) as ctx:
            ledger.record(CostRecord("r", "a", tokens=1, cost_microusd=1, elapsed_ms=1))
        self.assertEqual(ctx.exception.code, "ECO_TELEMETRY_CAP_EXCEEDED")

    def test_summary_headroom_and_caps(self) -> None:
        ledger = TelemetryLedger(cost_cap_microusd=1000, token_cap=1000)
        ledger.record(CostRecord("r", "a", tokens=200, cost_microusd=300, elapsed_ms=5))
        rec = ledger.summary().as_record()
        self.assertEqual(rec["costHeadroomMicrousd"], 700)
        self.assertEqual(rec["tokenHeadroom"], 800)

    def test_record_is_content_free(self) -> None:
        rec = CostRecord("run-x", "grader", tokens=5, cost_microusd=5, elapsed_ms=5).as_record()
        blob = json.dumps(rec)
        # only ids and numbers, no content keys
        self.assertEqual(set(rec), {"runId", "roleId", "tokens", "costMicrousd", "elapsedMs"})
        self.assertNotIn("prompt", blob)
        self.assertNotIn("output", blob)

    def test_invalid_inputs_rejected(self) -> None:
        with self.assertRaises(TelemetryError):
            CostRecord("BAD ID", "a", tokens=1, cost_microusd=1, elapsed_ms=1)
        with self.assertRaises(TelemetryError):
            CostRecord("r", "a", tokens=-1, cost_microusd=1, elapsed_ms=1)
        with self.assertRaises(TelemetryError):
            TelemetryLedger(cost_cap_microusd=-5)


if __name__ == "__main__":
    unittest.main()
