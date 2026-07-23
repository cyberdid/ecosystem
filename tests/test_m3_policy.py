from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import semantic_digest
from tests.test_policy import (
    DIGEST,
    NOW,
    artifact_registry,
    policy_bundle,
    repository_snapshot,
    run_request,
    trusted_policy_engine,
)


def write_arguments(*, path: str = "README.md", operation: str = "replace") -> dict:
    before = (
        {"state": "absent"}
        if operation == "create"
        else {
            "state": "present",
            "fileType": "regular",
            "encoding": "UTF-8",
            "contentDigest": DIGEST,
            "byteLength": 14,
            "mode": 0o644,
        }
    )
    return {
        "path": path,
        "operation": operation,
        "expectedBefore": before,
        "candidateArtifact": {
            "artifactRecordDigest": "b" * 64,
            "contentDigest": "c" * 64,
            "byteLength": 18,
            "dataClass": "D1",
            "trust": "P1",
            "availabilityProofDigest": "d" * 64,
            "fileType": "regular",
            "encoding": "UTF-8",
            "mode": 0o644,
        },
    }


class M3WritePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle, self.observations = policy_bundle()
        role = self.bundle["deployments"]["logicalRoles"]["code.read"]
        role["maximumActionClass"] = "A2"
        tool = next(
            item for item in self.bundle["tools"]["tools"] if item["id"] == "repository.write"
        )
        tool["enabled"] = True
        self.snapshot = repository_snapshot()
        self.engine = trusted_policy_engine(
            self.bundle,
            self.observations,
            artifact_registry(),
            repository_snapshot_record=self.snapshot,
            trusted_suite_digests={DIGEST},
        )

    def request(self) -> dict:
        request = run_request()
        request["spec"]["task"]["type"] = "repository.change"
        request["spec"]["requestedTools"] = ["repository.write"]
        request["spec"]["constraints"]["maximumActionClass"] = "A2"
        request["spec"]["constraints"]["sandbox"] = "workspace-change"
        return request

    def planned(self):
        return self.engine.plan_run(
            self.request(),
            run_id="run-1",
            plan_id="write-plan-1",
            decision_id="write-plan-decision-1",
            now=NOW,
        )

    @staticmethod
    def tool_request(plan: dict, arguments: dict) -> dict:
        return {
            "apiVersion": API_VERSION,
            "kind": "ToolRequest",
            "metadata": {
                "id": "write-request-1",
                "runId": "run-1",
                "createdAt": "2026-07-15T12:00:01Z",
                "source": "model",
            },
            "spec": {
                "planDigest": semantic_digest(plan),
                "toolId": "repository.write",
                "arguments": arguments,
            },
        }

    def authorize(self, arguments: dict):
        planned = self.planned()
        self.assertIsNotNone(planned.plan)
        return self.engine.authorize_tool(
            planned.plan,
            self.tool_request(planned.plan, arguments),
            decision_id=f"write-tool-{semantic_digest(arguments)[:16]}",
            now=NOW + timedelta(seconds=2),
            require_in_memory_activation=False,
        )

    def test_a2_write_plan_uses_workspace_change_and_snapshot_binding(self) -> None:
        result = self.planned()
        self.assertEqual(result.decision["spec"]["effect"], "allow")
        self.assertEqual(result.plan["spec"]["effectivePolicy"]["sandbox"], "workspace-change")
        self.assertEqual(result.plan["spec"]["effectivePolicy"]["maximumActionClass"], "A2")
        self.assertEqual(result.plan["spec"]["repositorySnapshot"]["digest"], semantic_digest(self.snapshot))
        self.assertEqual(result.plan["spec"]["tools"][0]["actionClass"], "A2")

    def test_exact_replace_precondition_is_allowed(self) -> None:
        decision = self.authorize(write_arguments())
        self.assertEqual(decision["spec"]["effect"], "allow")

    def test_replace_with_changed_digest_is_denied(self) -> None:
        arguments = write_arguments()
        arguments["expectedBefore"]["contentDigest"] = "e" * 64
        decision = self.authorize(arguments)
        self.assertEqual(decision["spec"]["reasonCodes"], ["ECO_WRITE_PRECONDITION_MISMATCH"])

    def test_create_requires_path_absent_from_snapshot(self) -> None:
        denied = self.authorize(write_arguments(operation="create"))
        self.assertEqual(denied["spec"]["reasonCodes"], ["ECO_WRITE_PRECONDITION_MISMATCH"])
        allowed = self.authorize(write_arguments(path="NEW.md", operation="create"))
        self.assertEqual(allowed["spec"]["effect"], "allow")

    def test_protected_path_and_candidate_data_class_fail_closed(self) -> None:
        protected = self.authorize(write_arguments(path=".git/config", operation="create"))
        self.assertEqual(protected["spec"]["reasonCodes"], ["ECO_PROTECTED_PATH"])
        arguments = write_arguments()
        arguments["candidateArtifact"]["dataClass"] = "D3"
        denied = self.authorize(arguments)
        self.assertEqual(denied["spec"]["reasonCodes"], ["ECO_DATA_CLASS_DENIED"])

    def test_a2_request_cannot_use_inspect_sandbox(self) -> None:
        request = self.request()
        request["spec"]["constraints"]["sandbox"] = "inspect"
        with self.assertRaises(Exception):
            self.engine.plan_run(
                request,
                run_id="run-1",
                plan_id="bad-plan",
                decision_id="bad-decision",
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
