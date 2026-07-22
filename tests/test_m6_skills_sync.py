from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from eco_cli.cli import main
from eco_skills import (
    SkillSyncError,
    check_skills,
    load_builtin_registry,
    plan_skills,
    sync_skills,
    uninstall_skills,
)
from eco_skills.sync import _canonical_path, validate_registry


class SkillRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_builtin_registry()
        self.document = copy.deepcopy(self.registry.document)
        self.resources = {
            skill.record["resource"]: skill.content for skill in self.registry.skills
        }

    def validate(self, document: dict) -> None:
        validate_registry(document, resource_reader=self.resources.__getitem__)

    def test_builtin_registry_is_closed_digest_bound_and_sorted(self) -> None:
        self.assertEqual(len(self.registry.skills), 7)
        self.assertEqual(
            [skill.identifier for skill in self.registry.skills],
            sorted(skill.identifier for skill in self.registry.skills),
        )
        for skill in self.registry.skills:
            self.assertEqual(
                hashlib.sha256(skill.content).hexdigest(), skill.record["contentDigest"]
            )
            for required in (
                "source",
                "license",
                "owner",
                "capabilities",
                "dependencies",
                "tests",
                "evidence",
                "revocation",
                "compatibility",
            ):
                self.assertIn(required, skill.record)

    def test_traversal_resource_is_rejected_without_read(self) -> None:
        self.document["skills"][0]["resource"] = "../SKILL.md"
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_REGISTRY_INVALID"):
            self.validate(self.document)

    def test_case_and_unicode_identifiers_are_rejected(self) -> None:
        for value in ("Bounded-loop-authoring", "source-reviéw-evidence"):
            document = copy.deepcopy(self.document)
            document["skills"][0]["id"] = value
            with self.subTest(value=value), self.assertRaises(SkillSyncError):
                self.validate(document)

    def test_non_nfc_resource_is_rejected(self) -> None:
        self.document["skills"][0]["resource"] = "bounded-loop-authoring/SKÍLL.md"
        with self.assertRaises(SkillSyncError):
            self.validate(self.document)

    def test_content_digest_mismatch_is_rejected(self) -> None:
        self.document["skills"][0]["contentDigest"] = "0" * 64
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_RESOURCE_INVALID"):
            self.validate(self.document)

    def test_dependency_cycle_is_rejected(self) -> None:
        first, second = self.document["skills"][:2]
        first["dependencies"] = [second["id"]]
        second["dependencies"] = [first["id"]]
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_DEPENDENCY_CYCLE"):
            self.validate(self.document)

    def test_instruction_only_surfaces_cannot_claim_native_parity(self) -> None:
        self.document["skills"][0]["compatibility"]["copilot"] = {
            "mode": "native",
            "limitations": [],
        }
        with self.assertRaisesRegex(
            SkillSyncError, "ECO_SKILL_COMPATIBILITY_OVERCLAIM"
        ):
            self.validate(self.document)

    def test_revocation_state_requires_an_explanation(self) -> None:
        self.document["skills"][0]["revocation"] = {
            "revoked": True,
            "reason": None,
        }
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_REGISTRY_INVALID"):
            self.validate(self.document)

    def test_noncanonical_projection_paths_are_rejected(self) -> None:
        for value in ("../outside", "a\\b", "a//b", "café/skill"):
            with self.subTest(value=value), self.assertRaises(SkillSyncError):
                _canonical_path(value)


class SkillSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_plan_is_deterministic_and_zero_write(self) -> None:
        first = plan_skills(self.repo)
        second = plan_skills(self.repo)
        self.assertEqual(first, second)
        self.assertTrue(first["available"])
        self.assertEqual(first["skillCount"], 7)
        self.assertEqual(first["projectionCount"], 30)
        self.assertEqual(first["counts"], {"create": 30})
        self.assertFalse((self.repo / ".ai").exists())
        self.assertFalse(first["safety"]["skillCodeExecuted"])

    def test_sync_check_resync_and_uninstall_lifecycle(self) -> None:
        first = sync_skills(self.repo)
        self.assertTrue(first["available"])
        self.assertEqual(first["changed"], 30)
        self.assertTrue(check_skills(self.repo)["available"])
        second = sync_skills(self.repo)
        self.assertEqual(second["changed"], 0)
        sibling = self.repo / ".agents/skills/user-owned.txt"
        sibling.parent.mkdir(parents=True, exist_ok=True)
        sibling.write_text("preserve", encoding="utf-8")
        removed = uninstall_skills(self.repo)
        self.assertEqual(removed["removed"], 30)
        self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")
        self.assertEqual(uninstall_skills(self.repo)["status"], "absent")

    def test_native_frontmatter_stays_first_and_subset_is_honest(self) -> None:
        sync_skills(self.repo)
        native = (self.repo / ".agents/skills/bounded-loop-authoring/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertTrue(native.startswith("---\n"))
        self.assertIn("eco-skills:managed", native[:512])
        copilot = (
            self.repo / ".github/instructions/eco-skills.instructions.md"
        ).read_text(encoding="utf-8")
        self.assertIn("instruction-only projection", copilot)
        self.assertIn("semantic parity are not claimed", copilot)

    def test_unmanaged_target_is_never_overwritten(self) -> None:
        target = self.repo / ".agents/skills/bounded-loop-authoring/SKILL.md"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"user bytes\n")
        plan = plan_skills(self.repo)
        self.assertFalse(plan["available"])
        self.assertIn("conflict", plan["counts"])
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_SYNC_BLOCKED"):
            sync_skills(self.repo)
        self.assertEqual(target.read_bytes(), b"user bytes\n")

    def test_forged_marker_without_lock_does_not_create_ownership(self) -> None:
        target = self.repo / ".agents/skills/bounded-loop-authoring/SKILL.md"
        target.parent.mkdir(parents=True)
        target.write_text(
            '<!-- eco-skills:managed surface="codex" registry="fake" -->\n',
            encoding="utf-8",
        )
        self.assertFalse(plan_skills(self.repo)["available"])
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_SYNC_BLOCKED"):
            sync_skills(self.repo)

    def test_drift_blocks_sync_and_uninstall(self) -> None:
        sync_skills(self.repo)
        target = self.repo / ".claude/skills/source-review-evidence/SKILL.md"
        target.write_bytes(target.read_bytes() + b"user edit\n")
        self.assertFalse(check_skills(self.repo)["available"])
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_SYNC_BLOCKED"):
            sync_skills(self.repo)
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_UNINSTALL_BLOCKED"):
            uninstall_skills(self.repo)
        self.assertTrue(target.read_bytes().endswith(b"user edit\n"))

    def test_symlinked_parent_is_refused_without_touching_target(self) -> None:
        outside = self.repo / "outside"
        outside.mkdir()
        (self.repo / ".agents").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_PATH_ALIAS"):
            plan_skills(self.repo)
        self.assertEqual(list(outside.iterdir()), [])

    def test_case_alias_parent_is_refused(self) -> None:
        (self.repo / ".AGENTS").mkdir()
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_PATH_ALIAS"):
            plan_skills(self.repo)

    def test_hardlinked_target_is_refused(self) -> None:
        source = self.repo / "user-skill.md"
        source.write_text("preserve", encoding="utf-8")
        target = self.repo / ".agents/skills/bounded-loop-authoring/SKILL.md"
        target.parent.mkdir(parents=True)
        os.link(source, target)
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_PATH_ALIAS"):
            plan_skills(self.repo)
        self.assertEqual(source.read_text(encoding="utf-8"), "preserve")

    def test_sync_failure_rolls_back_all_written_files(self) -> None:
        from eco_skills import sync as module

        real = module._atomic_write
        calls = 0

        def fail_third(path: Path, content: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected")
            real(path, content)

        with mock.patch.object(module, "_atomic_write", side_effect=fail_third):
            with self.assertRaisesRegex(
                SkillSyncError, "ECO_SKILL_SYNC_ROLLED_BACK"
            ):
                sync_skills(self.repo)
        self.assertEqual(plan_skills(self.repo)["counts"], {"create": 30})
        self.assertFalse((self.repo / ".ai/skills/eco-skills.lock.json").exists())

    def test_uninstall_failure_restores_complete_owned_set(self) -> None:
        from eco_skills import sync as module

        sync_skills(self.repo)
        real = module._remove
        calls = 0

        def fail_third(path: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected")
            real(path)

        with mock.patch.object(module, "_remove", side_effect=fail_third):
            with self.assertRaisesRegex(
                SkillSyncError, "ECO_SKILL_UNINSTALL_ROLLED_BACK"
            ):
                uninstall_skills(self.repo)
        self.assertTrue(check_skills(self.repo)["available"])

    def test_tampered_lock_cannot_redirect_uninstall(self) -> None:
        sync_skills(self.repo)
        protected = self.repo / "README.md"
        protected.write_text(
            '<!-- eco-skills:managed surface="codex" registry="fake" -->\nkeep\n',
            encoding="utf-8",
        )
        lock_path = self.repo / ".ai/skills/eco-skills.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["files"][0]["path"] = "README.md"
        lock["files"][0]["contentDigest"] = hashlib.sha256(
            protected.read_bytes()
        ).hexdigest()
        lock_path.write_text(json.dumps(lock, sort_keys=True), encoding="utf-8")
        with self.assertRaisesRegex(SkillSyncError, "ECO_SKILL_LOCK_INVALID"):
            uninstall_skills(self.repo)
        self.assertTrue(protected.exists())

    def test_cli_json_lifecycle_and_check_exit_status(self) -> None:
        def run(*arguments: str) -> tuple[int, dict, str]:
            output, error = StringIO(), StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                code = main(["--repo", str(self.repo), "skills", *arguments, "--json"])
            return code, json.loads(output.getvalue()), error.getvalue()

        code, plan, _ = run("plan")
        self.assertEqual(code, 0)
        self.assertTrue(plan["available"])
        code, check, _ = run("check")
        self.assertEqual(code, 1)
        self.assertFalse(check["available"])
        self.assertEqual(run("sync")[0], 0)
        self.assertEqual(run("check")[0], 0)
        self.assertEqual(run("uninstall")[0], 0)


if __name__ == "__main__":
    unittest.main()
