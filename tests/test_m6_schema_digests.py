"""M6.8 release pins for every additive contract registry."""

from __future__ import annotations

import unittest

from eco_memory.contracts import memory_schema_bundle_digest
from eco_orchestration.contracts import orchestration_schema_bundle_digest
from eco_research.contracts import research_schema_bundle_digest
from eco_routing.contracts import routing_schema_bundle_digest
from eco_runtime.contracts import schema_bundle_digest as runtime_schema_bundle_digest
from eco_teams.contracts import schema_bundle_digest as teams_schema_bundle_digest


class M6ReleaseSchemaDigestTests(unittest.TestCase):
    def test_runtime_digest_remains_the_pinned_m5_boundary(self) -> None:
        self.assertEqual(
            runtime_schema_bundle_digest(),
            "d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d",
        )

    def test_additive_m6_registry_digests_are_release_pinned(self) -> None:
        self.assertEqual(
            {
                "orchestration": orchestration_schema_bundle_digest(),
                "routing": routing_schema_bundle_digest(),
                "memory": memory_schema_bundle_digest(),
                "teams": teams_schema_bundle_digest(),
                "research": research_schema_bundle_digest(),
            },
            {
                "orchestration": "3f14b0eac62f123a273e57f5e062eb5331489c3a8b4b16045c247c503367b3e8",
                "routing": "c489fc4da4dc0fc91cf0d7b4d4ebee51a319c7cbfe670c3e6873e658465e0227",
                "memory": "ccce592db66ba0e99047aff344f163aa125b5ddf3c91e85cc009694a51f82713",
                "teams": "79be7bfe4e26fe8c534018c1620497812f9a6cd9cd0b200302812e8098d398d4",
                "research": "b7a1d821c8682874336938795e9467486e067e1485f5f8fcee0d598f4f47dd00",
            },
        )


if __name__ == "__main__":
    unittest.main()
