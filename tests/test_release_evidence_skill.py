from __future__ import annotations

import hashlib
import unittest
from importlib import resources

from eco_skills import load_builtin_registry


class ReleaseEvidenceSkillTests(unittest.TestCase):
    def test_registry_binds_exact_skill_and_dependency(self) -> None:
        registry = load_builtin_registry()
        skill = next(
            item for item in registry.skills if item.identifier == "release-evidence-audit"
        )
        self.assertEqual(
            hashlib.sha256(skill.content).hexdigest(),
            skill.record["contentDigest"],
        )
        self.assertEqual(skill.record["dependencies"], ["source-review-evidence"])

    def test_skill_has_closed_output_and_effect_hard_stop(self) -> None:
        content = resources.files("eco_skills").joinpath(
            "catalog", "release-evidence-audit", "SKILL.md"
        ).read_text(encoding="utf-8")
        for required in (
            "release/canonical-plan.md",
            "Status: approved",
            "byte-for-byte",
            "decisionMarker",
            "NOT_ESTABLISHED",
            "Hard stop:",
        ):
            self.assertIn(required, content)
        for forbidden_effect in ("never call shell", "Python", "web", "write"):
            self.assertIn(forbidden_effect, content)


if __name__ == "__main__":
    unittest.main()
