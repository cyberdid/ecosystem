from __future__ import annotations

import unittest

from eco_teams.contracts import validate_record
from eco_teams.reference_manifests import (
    REFERENCE_MANIFESTS,
    evaluator_optimizer_manifest,
    orchestrator_workers_manifest,
)


class ReferenceAgentManifestTests(unittest.TestCase):
    def test_both_reference_manifests_validate(self) -> None:
        for build in (evaluator_optimizer_manifest, orchestrator_workers_manifest):
            # validate_record raises ContractValidationError on any structural fault
            validate_record(build())

    def test_registry_exposes_both_topologies(self) -> None:
        self.assertEqual(sorted(REFERENCE_MANIFESTS), ["evaluator-optimizer", "orchestrator-workers"])
        for build in REFERENCE_MANIFESTS.values():
            validate_record(build())

    def test_evaluator_never_delegates_to_optimizer(self) -> None:
        roles = {r["id"]: r for r in evaluator_optimizer_manifest()["spec"]["roles"]}
        # separation of duties: the reviewer is never the author's delegator
        self.assertEqual(roles["evaluator"]["delegatesTo"], [])
        self.assertIn("evaluator", roles["optimizer"]["delegatesTo"])

    def test_delegation_never_expands_authority(self) -> None:
        manifest = orchestrator_workers_manifest()
        roles = {r["id"]: r for r in manifest["spec"]["roles"]}
        orch = roles["orchestrator"]
        for target_id in orch["delegatesTo"]:
            target = roles[target_id]
            self.assertTrue(set(target["dataClasses"]) <= set(orch["dataClasses"]))
            self.assertLessEqual(target["budget"]["maxTokens"], orch["budget"]["maxTokens"])

    def test_role_budgets_within_team_budget(self) -> None:
        for build in REFERENCE_MANIFESTS.values():
            spec = build()["spec"]
            for role in spec["roles"]:
                self.assertLessEqual(role["budget"]["maxTokens"], spec["budget"]["maxTotalTokens"])
                self.assertLessEqual(role["budget"]["maxCostMicrousd"], spec["budget"]["maxCostMicrousd"])


if __name__ == "__main__":
    unittest.main()
