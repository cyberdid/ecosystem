from __future__ import annotations

import copy
import threading
import unittest

from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimeStateError
from eco_runtime.state import RunEventChain, RunState


BASE_TIME = "2026-07-15T12:00:00Z"
DIGEST = "a" * 64
PRODUCER_CAPABILITIES = {
    producer: (f"{producer}-issuer-1", object())
    for producer in ("runtime", "policy", "broker", "adapter")
}


def new_chain() -> RunEventChain:
    return RunEventChain("run-1", PRODUCER_CAPABILITIES)


def event(
    sequence: int,
    event_type: str,
    outcome: str,
    producer: str,
    previous: str | None,
    *,
    run_id: str = "run-1",
    occurred_at: str = BASE_TIME,
    subject_id: str | None = None,
    subject_digest: str | None = None,
    result_digest: str | None = None,
) -> dict:
    spec = {"type": event_type, "outcome": outcome}
    if subject_id is not None:
        spec["subjectId"] = subject_id
    if subject_digest is not None:
        spec["subjectDigest"] = subject_digest
    if result_digest is not None:
        spec["resultDigest"] = result_digest
    return {
        "apiVersion": API_VERSION,
        "kind": "RunEvent",
        "metadata": {
            "id": f"event-{sequence}-{event_type}",
            "runId": run_id,
            "sequence": sequence,
            "occurredAt": occurred_at,
            "producer": producer,
            "producerIssuer": PRODUCER_CAPABILITIES[producer][0],
            "previousEventDigest": previous,
        },
        "spec": spec,
    }


def append_event(
    chain: RunEventChain,
    event_type: str,
    outcome: str,
    producer: str,
    **kwargs: str,
) -> RunState:
    if event_type.startswith("tool."):
        kwargs.setdefault("subject_id", "tool-request-1")
        kwargs.setdefault("subject_digest", DIGEST)
    if event_type in {"tool.completed", "tool.failed"}:
        kwargs.setdefault("result_digest", DIGEST)
    candidate = event(
        len(chain.events()) + 1,
        event_type,
        outcome,
        producer,
        chain.head_digest,
        **kwargs,
    )
    return chain.append(candidate, PRODUCER_CAPABILITIES[producer][1])


def running_chain() -> RunEventChain:
    chain = new_chain()
    append_event(chain, "run.received", "pending", "runtime")
    append_event(chain, "run.validated", "success", "runtime")
    append_event(chain, "plan.created", "success", "runtime")
    append_event(chain, "policy.allowed", "success", "policy")
    append_event(chain, "adapter.started", "pending", "adapter")
    return chain


class RunEventChainTests(unittest.TestCase):
    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStateError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_happy_path_reaches_exactly_one_terminal_state(self) -> None:
        chain = running_chain()
        append_event(chain, "tool.requested", "pending", "runtime")
        append_event(chain, "tool.allowed", "success", "policy")
        append_event(chain, "tool.completed", "success", "broker")
        append_event(chain, "adapter.completed", "success", "adapter")
        self.assertEqual(append_event(chain, "run.succeeded", "success", "runtime"), RunState.SUCCEEDED)
        self.assert_code("ECO_RUN_TERMINAL", lambda: append_event(chain, "run.failed", "failed", "runtime"))

    def test_policy_denial_is_terminal_without_execution(self) -> None:
        chain = new_chain()
        append_event(chain, "run.received", "pending", "runtime")
        append_event(chain, "run.validated", "success", "runtime")
        append_event(chain, "plan.created", "success", "runtime")
        self.assertEqual(append_event(chain, "policy.denied", "denied", "policy"), RunState.DENIED)
        self.assert_code("ECO_RUN_TERMINAL", lambda: append_event(chain, "adapter.started", "pending", "adapter"))

    def test_exhaustion_requires_explicit_terminal_event(self) -> None:
        chain = running_chain()
        append_event(chain, "budget.exhausted", "exhausted", "runtime")
        self.assert_code(
            "ECO_RUN_SUCCESS_INVALID",
            lambda: append_event(chain, "run.succeeded", "success", "runtime"),
        )
        self.assertEqual(append_event(chain, "run.exhausted", "exhausted", "runtime"), RunState.EXHAUSTED)

    def test_tool_lifecycle_is_correlated_and_ordered(self) -> None:
        chain = running_chain()
        self.assert_code(
            "ECO_TOOL_EVENT_BINDING",
            lambda: append_event(chain, "tool.completed", "success", "broker"),
        )
        append_event(chain, "tool.requested", "pending", "runtime")
        append_event(chain, "tool.denied", "denied", "policy")
        self.assert_code(
            "ECO_TOOL_EVENT_ORDER",
            lambda: append_event(chain, "tool.completed", "success", "broker"),
        )

    def test_failed_tool_event_requires_exact_outcome_reference_shape(self) -> None:
        chain = running_chain()
        append_event(chain, "tool.requested", "pending", "runtime")
        append_event(chain, "tool.allowed", "success", "policy")
        candidate = event(
            len(chain.events()) + 1,
            "tool.failed",
            "failed",
            "broker",
            chain.head_digest,
            subject_id="tool-request-1",
            subject_digest=DIGEST,
        )
        self.assert_code(
            "ECO_TOOL_EVENT_BINDING",
            lambda: chain.append(candidate, PRODUCER_CAPABILITIES["broker"][1]),
        )
        candidate["spec"]["resultDigest"] = DIGEST
        self.assertEqual(
            chain.append(candidate, PRODUCER_CAPABILITIES["broker"][1]),
            RunState.RUNNING,
        )

    def test_adapter_failure_or_open_tool_cannot_be_recorded_as_success(self) -> None:
        failed = running_chain()
        append_event(failed, "adapter.failed", "failed", "adapter")
        self.assert_code(
            "ECO_RUN_SUCCESS_INVALID",
            lambda: append_event(failed, "run.succeeded", "success", "runtime"),
        )

        open_tool = running_chain()
        append_event(open_tool, "tool.requested", "pending", "runtime")
        self.assert_code(
            "ECO_ADAPTER_EVENT_ORDER",
            lambda: append_event(open_tool, "adapter.completed", "success", "adapter"),
        )

    def test_terminal_state_requires_explicit_tool_cancellation(self) -> None:
        chain = running_chain()
        append_event(chain, "tool.requested", "pending", "runtime")
        append_event(chain, "tool.allowed", "success", "policy")
        append_event(chain, "budget.exhausted", "exhausted", "runtime")
        self.assert_code(
            "ECO_TOOL_EVENT_ORDER",
            lambda: append_event(chain, "run.exhausted", "exhausted", "runtime"),
        )
        append_event(chain, "tool.cancelled", "cancelled", "runtime")
        self.assertEqual(
            append_event(chain, "run.exhausted", "exhausted", "runtime"),
            RunState.EXHAUSTED,
        )

    def test_out_of_order_event_fails_closed_without_mutating_chain(self) -> None:
        chain = new_chain()
        candidate = event(1, "plan.created", "success", "runtime", None)
        self.assert_code(
            "ECO_STATE_TRANSITION",
            lambda: chain.append(candidate, PRODUCER_CAPABILITIES["runtime"][1]),
        )
        self.assertEqual(chain.state, RunState.NEW)
        self.assertEqual(chain.events(), ())

    def test_sequence_chain_run_time_outcome_and_producer_are_enforced(self) -> None:
        chain = new_chain()
        first = event(1, "run.received", "pending", "runtime", None)
        chain.append(first, PRODUCER_CAPABILITIES["runtime"][1])
        cases = [
            ("ECO_EVENT_SEQUENCE", event(3, "run.validated", "success", "runtime", chain.head_digest)),
            ("ECO_EVENT_CHAIN_MISMATCH", event(2, "run.validated", "success", "runtime", "b" * 64)),
            (
                "ECO_EVENT_RUN_MISMATCH",
                event(2, "run.validated", "success", "runtime", chain.head_digest, run_id="run-2"),
            ),
            (
                "ECO_EVENT_TIME_REVERSED",
                event(
                    2,
                    "run.validated",
                    "success",
                    "runtime",
                    chain.head_digest,
                    occurred_at="2026-07-15T11:59:59Z",
                ),
            ),
            ("ECO_EVENT_OUTCOME", event(2, "run.validated", "failed", "runtime", chain.head_digest)),
            ("ECO_EVENT_PRODUCER", event(2, "run.validated", "success", "broker", chain.head_digest)),
        ]
        for code, candidate in cases:
            with self.subTest(code=code):
                token = PRODUCER_CAPABILITIES[candidate["metadata"]["producer"]][1]
                self.assert_code(code, lambda candidate=candidate, token=token: chain.append(candidate, token))
                self.assertEqual(len(chain.events()), 1)

    def test_spoofed_producer_label_without_capability_is_denied(self) -> None:
        chain = new_chain()
        candidate = event(1, "run.received", "pending", "runtime", None)
        self.assert_code(
            "ECO_EVENT_PRODUCER_UNTRUSTED",
            lambda: chain.append(candidate, PRODUCER_CAPABILITIES["broker"][1]),
        )
        candidate["metadata"]["producerIssuer"] = "attacker"
        self.assert_code(
            "ECO_EVENT_PRODUCER_UNTRUSTED",
            lambda: chain.append(candidate, PRODUCER_CAPABILITIES["runtime"][1]),
        )

    def test_invalid_contract_is_wrapped_without_echoing_untrusted_content(self) -> None:
        candidate = event(1, "run.received", "pending", "runtime", None)
        candidate["metadata"].pop("previousEventDigest")
        chain = new_chain()
        self.assert_code(
            "ECO_EVENT_INVALID",
            lambda: chain.append(candidate, PRODUCER_CAPABILITIES["runtime"][1]),
        )

    def test_stored_events_and_head_are_immune_to_caller_mutation(self) -> None:
        chain = new_chain()
        candidate = event(1, "run.received", "pending", "runtime", None)
        expected_digest = semantic_digest(candidate)
        chain.append(candidate, PRODUCER_CAPABILITIES["runtime"][1])
        candidate["spec"]["outcome"] = "failed"
        returned = list(chain.events())
        returned[0]["spec"]["outcome"] = "failed"
        self.assertEqual(chain.head_digest, expected_digest)
        self.assertEqual(chain.events()[0]["spec"]["outcome"], "pending")

    def test_concurrent_append_serializes_the_chain(self) -> None:
        chain = new_chain()
        chain.append(
            event(1, "run.received", "pending", "runtime", None),
            PRODUCER_CAPABILITIES["runtime"][1],
        )
        head = chain.head_digest
        candidates = [
            event(2, "run.validated", "success", "runtime", head),
            event(2, "run.validated", "success", "runtime", head),
        ]
        candidates[1]["metadata"]["id"] = "event-2-competing"
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def append(candidate: dict) -> None:
            barrier.wait()
            try:
                chain.append(copy.deepcopy(candidate), PRODUCER_CAPABILITIES["runtime"][1])
                outcomes.append("allowed")
            except RuntimeStateError as exc:
                outcomes.append(exc.code)

        threads = [threading.Thread(target=append, args=(candidate,)) for candidate in candidates]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("allowed"), 1)
        self.assertEqual(len(chain.events()), 2)
        self.assertEqual(chain.state, RunState.VALIDATED)


if __name__ == "__main__":
    unittest.main()
