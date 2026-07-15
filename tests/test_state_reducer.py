from __future__ import annotations

import copy
import unittest

from eco_runtime.errors import RuntimeStateError
from eco_runtime.state_reducer import RunProjection, RunState, reduce_run_event


DIGEST = "a" * 64


class PureRunReducerTests(unittest.TestCase):
    def test_reducer_is_deterministic_and_does_not_mutate_inputs(self) -> None:
        projection = RunProjection.initial()
        spec = {"type": "run.received", "outcome": "pending", "subjectId": "request-1"}
        original = copy.deepcopy(spec)
        first = reduce_run_event(projection, "run.received", spec)
        second = reduce_run_event(projection, "run.received", spec)
        self.assertEqual(first, second)
        self.assertEqual(first.state, RunState.RECEIVED)
        self.assertEqual(projection, RunProjection.initial())
        self.assertEqual(spec, original)

    def test_projection_round_trip_is_canonical(self) -> None:
        projection = RunProjection.from_parts(
            state=RunState.RUNNING,
            tool_states={
                "request-b": ("allowed", "b" * 64),
                "request-a": ("completed", DIGEST),
            },
            adapter_completed=False,
            adapter_failed=False,
            budget_exhausted=False,
        )
        self.assertEqual(projection.tool_states[0][0], "request-a")
        self.assertEqual(
            projection.tool_map(),
            {
                "request-a": ("completed", DIGEST),
                "request-b": ("allowed", "b" * 64),
            },
        )

    def test_failed_tool_requires_result_digest_without_partial_mutation(self) -> None:
        projection = RunProjection.from_parts(
            state=RunState.RUNNING,
            tool_states={"tool-request-1": ("allowed", DIGEST)},
            adapter_completed=False,
            adapter_failed=False,
            budget_exhausted=False,
        )
        with self.assertRaises(RuntimeStateError) as caught:
            reduce_run_event(
                projection,
                "tool.failed",
                {
                    "type": "tool.failed",
                    "outcome": "failed",
                    "subjectId": "tool-request-1",
                    "subjectDigest": DIGEST,
                },
            )
        self.assertEqual(caught.exception.code, "ECO_TOOL_EVENT_BINDING")
        self.assertEqual(projection.tool_map()["tool-request-1"][0], "allowed")


if __name__ == "__main__":
    unittest.main()
