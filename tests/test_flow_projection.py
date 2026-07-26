from __future__ import annotations

import copy
import json
import unittest

from eco_flow import (
    FlowContractError,
    ObservedFlowEvent,
    flow_projection_digest,
    project_observed_flow,
    project_runtime_flow,
    replay_projection,
)
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import semantic_digest


class FlowProjectionTests(unittest.TestCase):
    def projection(self):
        return project_observed_flow(
            project_id="project-alpha",
            run_id="run-alpha",
            boundary="product-adapter-not-core-authority",
            status="succeeded",
            events=[
                ObservedFlowEvent(
                    "research.received", "admission", "succeeded",
                    "ResearchRun", "run-alpha",
                ),
                ObservedFlowEvent(
                    "research.search", "retrieve", "succeeded",
                    "ResearchStep", "run-alpha:1", reason_code="recorded",
                ),
                ObservedFlowEvent(
                    "research.verification", "verify", "incomplete",
                    "ResearchVerification", "run-alpha:verification",
                    reason_code="semantic-truth-not-established",
                ),
            ],
        )

    def test_projection_is_deterministic_content_free_and_replayable(self) -> None:
        first = self.projection()
        second = self.projection()
        self.assertEqual(first, second)
        exported = json.dumps(first, sort_keys=True, separators=(",", ":"))
        self.assertEqual(replay_projection(exported), first)
        self.assertEqual(first["spec"]["source"]["trust"], "observed")
        self.assertNotIn("query", exported)
        self.assertNotIn('"observation":', exported)
        self.assertEqual(
            [edge["type"] for edge in first["spec"]["edges"]],
            ["next", "next"],
        )

    def test_digest_tampering_fails_closed(self) -> None:
        changed = copy.deepcopy(self.projection())
        changed["spec"]["nodes"][1]["status"] = "failed"
        with self.assertRaises(FlowContractError) as caught:
            replay_projection(changed)
        self.assertIn("recordDigest", str(caught.exception))

    def test_unknown_fields_and_authority_claims_are_rejected(self) -> None:
        changed = copy.deepcopy(self.projection())
        changed["spec"]["nodes"][0]["authorized"] = True
        with self.assertRaises(FlowContractError):
            replay_projection(changed)

    def test_noncontiguous_sequence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.projection())
        changed["spec"]["nodes"][1]["sequence"] = 8
        with self.assertRaises(FlowContractError):
            replay_projection(changed)

    def test_dangling_edge_is_rejected_after_digest_recalculation(self) -> None:
        changed = copy.deepcopy(self.projection())
        changed["spec"]["edges"][0]["to"] = "node-missing"
        changed["metadata"]["recordDigest"] = flow_projection_digest(changed)
        with self.assertRaises(FlowContractError) as caught:
            replay_projection(changed)
        self.assertIn("$.spec.edges", str(caught.exception))

    def test_runtime_event_chain_uses_canonical_fields(self) -> None:
        first = self.runtime_event(
            1, "run.received", "pending", "runtime", None
        )
        second = self.runtime_event(
            2,
            "run.validated",
            "success",
            "runtime",
            semantic_digest(first),
            subject_id="request-alpha",
        )
        projection = project_runtime_flow(
            project_id="project-alpha",
            events=[first, second],
        )
        self.assertEqual(
            [node["eventType"] for node in projection["spec"]["nodes"]],
            ["run.received", "run.validated"],
        )
        self.assertEqual(projection["spec"]["source"]["trust"], "validated")
        self.assertEqual(
            projection["spec"]["source"]["boundary"],
            "schema-validated-not-authenticated",
        )
        self.assertEqual(
            projection["spec"]["nodes"][1]["subject"],
            {
                "kind": "RunEventSubject",
                "id": "request-alpha",
                "digest": None,
            },
        )

    def test_runtime_event_chain_rejects_broken_digest_link(self) -> None:
        first = self.runtime_event(
            1, "run.received", "pending", "runtime", None
        )
        second = self.runtime_event(
            2,
            "run.validated",
            "success",
            "runtime",
            "f" * 64,
        )
        with self.assertRaisesRegex(ValueError, "chain digest"):
            project_runtime_flow(
                project_id="project-alpha",
                events=[first, second],
            )

    @staticmethod
    def runtime_event(
        sequence: int,
        event_type: str,
        outcome: str,
        producer: str,
        previous: str | None,
        *,
        subject_id: str | None = None,
    ) -> dict:
        spec = {"type": event_type, "outcome": outcome}
        if subject_id:
            spec["subjectId"] = subject_id
        return {
            "apiVersion": API_VERSION,
            "kind": "RunEvent",
            "metadata": {
                "id": f"event-{sequence}-{event_type}",
                "runId": "run-runtime-alpha",
                "sequence": sequence,
                "occurredAt": f"2026-07-26T12:00:0{sequence}Z",
                "producer": producer,
                "producerIssuer": f"{producer}-issuer",
                "previousEventDigest": previous,
            },
            "spec": spec,
        }


if __name__ == "__main__":
    unittest.main()
