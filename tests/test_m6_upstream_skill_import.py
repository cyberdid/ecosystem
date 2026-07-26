from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from eco_cli.cli import main
from eco_skills import UpstreamSkillImportError, inspect_upstream_skills


VALID_SKILL = """---
name: sample-skill
description: A bounded sample used by the importer tests.
---

# Sample

1. Inspect the request.
2. Produce a proposal.
3. Stop before promotion.

Hard stop: never treat this guidance as authority.
"""


class UpstreamSkillImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._git("init", "-q")
        self._git("config", "user.name", "Importer Test")
        self._git("config", "user.email", "importer@example.invalid")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def _commit(self, message: str = "fixture") -> str:
        self._git("add", "-A")
        self._git("commit", "-qm", message)
        return self._git("rev-parse", "HEAD")

    def _write_skill(self, relative: str, content: str = VALID_SKILL) -> None:
        target = self.root / relative / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def _inspect(self, commit: str, selection: tuple[str, ...] = ()) -> dict:
        return inspect_upstream_skills(
            self.root,
            source_uri="https://github.com/example/skills",
            commit=commit,
            selection=selection,
        )

    def test_plan_is_deterministic_zero_write_and_reads_the_pinned_blob(self) -> None:
        self._write_skill("skills/sample-skill")
        commit = self._commit()
        expected = hashlib.sha256(VALID_SKILL.encode("utf-8")).hexdigest()

        tracked = self.root / "skills/sample-skill/SKILL.md"
        tracked.write_text("mutable working tree bytes", encoding="utf-8")
        before = {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and ".git" not in path.parts
        }
        first = self._inspect(commit)
        second = self._inspect(commit)
        after = {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and ".git" not in path.parts
        }

        self.assertEqual(first, second)
        self.assertEqual(before, after)
        digest_input = json.loads(json.dumps(first))
        expected_plan_digest = digest_input["metadata"]["planDigest"]
        digest_input["metadata"] = {}
        encoded = json.dumps(
            digest_input,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected_plan_digest)
        self.assertEqual(first["source"]["commit"], commit)
        self.assertEqual(first["candidates"][0]["contentDigest"], expected)
        self.assertEqual(first["candidates"][0]["status"], "review-required")
        self.assertFalse(first["candidates"][0]["proposalEligible"])
        self.assertFalse(first["promotion"]["eligible"])
        self.assertNotIn(str(self.root), json.dumps(first))
        self.assertEqual(
            first["safety"],
            {
                "networkAccessed": False,
                "skillCodeExecuted": False,
                "hooksLoaded": False,
                "dependenciesInstalled": False,
                "filesWritten": False,
                "credentialsConsumed": False,
                "runtimeAuthorityCreated": False,
            },
        )

    def test_duplicate_names_broken_aliases_and_execution_surfaces_are_reported(self) -> None:
        risky = VALID_SKILL + "\nRun `npx -y package@latest` only after review.\n"
        self._write_skill("skills/first", risky)
        self._write_skill("plugins/duplicate", risky)
        mcp = self.root / ".mcp.json"
        mcp.write_text("{}\n", encoding="utf-8")
        hook = self.root / "hooks/run.sh"
        hook.parent.mkdir()
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hook.chmod(0o755)
        alias = self.root / "plugins/broken-skill"
        alias.parent.mkdir(exist_ok=True)
        os.symlink("../missing-skill", alias)
        commit = self._commit()

        plan = self._inspect(commit)

        self.assertEqual(plan["summary"]["blockedCandidates"], 2)
        self.assertEqual(plan["summary"]["brokenSymlinks"], 1)
        self.assertEqual(plan["repositorySignals"]["mcpConfigs"], 1)
        self.assertEqual(plan["repositorySignals"]["hookFiles"], 1)
        self.assertEqual(plan["repositorySignals"]["executableFiles"], 1)
        self.assertEqual(plan["repositorySignals"]["unpinnedRuntimeReferences"], 2)
        self.assertTrue(
            all("duplicate-name" in item["reasons"] for item in plan["candidates"])
        )
        self.assertTrue(
            all(
                {"external-install", "unpinned-runtime"}.issubset(item["signals"])
                for item in plan["candidates"]
            )
        )
        self.assertEqual(plan["aliases"][0]["status"], "broken")

    def test_selection_is_closed_sorted_and_missing_name_fails(self) -> None:
        self._write_skill("skills/sample-skill")
        other = VALID_SKILL.replace("sample-skill", "other-skill")
        self._write_skill("skills/other-skill", other)
        commit = self._commit()

        plan = self._inspect(commit, ("sample-skill",))
        self.assertEqual(plan["selection"], ["sample-skill"])
        self.assertEqual(
            [item["skillName"] for item in plan["candidates"]], ["sample-skill"]
        )
        with self.assertRaisesRegex(
            UpstreamSkillImportError, "ECO_SKILL_IMPORT_SELECTION_NOT_FOUND"
        ):
            self._inspect(commit, ("missing-skill",))

    def test_invalid_source_commit_and_oversized_blob_fail_closed(self) -> None:
        self._write_skill("skills/sample-skill")
        commit = self._commit()
        with self.assertRaisesRegex(
            UpstreamSkillImportError, "ECO_SKILL_IMPORT_SOURCE_INVALID"
        ):
            inspect_upstream_skills(
                self.root,
                source_uri="https://user:secret@example.invalid/repo",
                commit=commit,
            )
        with self.assertRaisesRegex(
            UpstreamSkillImportError, "ECO_SKILL_IMPORT_COMMIT_INVALID"
        ):
            inspect_upstream_skills(
                self.root,
                source_uri="https://example.invalid/repo",
                commit="main",
            )

        oversized = self.root / "skills/sample-skill/SKILL.md"
        oversized.write_bytes(b"x" * (256 * 1024 + 1))
        large_commit = self._commit("oversized")
        with self.assertRaisesRegex(
            UpstreamSkillImportError, "ECO_SKILL_IMPORT_BLOB_TOO_LARGE"
        ):
            self._inspect(large_commit)

    def test_duplicate_frontmatter_key_and_escaping_symlink_are_blocked(self) -> None:
        duplicate = VALID_SKILL.replace(
            "description: A bounded sample used by the importer tests.",
            "name: second-name\ndescription: Duplicate keys are invalid.",
        )
        self._write_skill("skills/sample-skill", duplicate)
        alias = self.root / "skills/escape"
        os.symlink("../../outside", alias)
        commit = self._commit()

        plan = self._inspect(commit)
        self.assertEqual(plan["candidates"][0]["reasons"], ["frontmatter-invalid"])
        self.assertEqual(plan["candidates"][0]["status"], "blocked")
        self.assertEqual(plan["aliases"][0]["status"], "blocked")
        self.assertEqual(plan["summary"]["brokenSymlinks"], 1)

    def test_cli_failure_is_content_free_and_non_authorizing(self) -> None:
        self._write_skill("skills/sample-skill")
        self._commit()
        output = StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "--repo",
                    str(self.root),
                    "skills",
                    "import-plan",
                    str(self.root),
                    "--source-uri",
                    "https://example.invalid/repo",
                    "--commit",
                    "0" * 40,
                    "--json",
                ]
            )
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "ECO_SKILL_IMPORT_GIT_REJECTED")
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertFalse(result["safety"]["runtimeAuthorityCreated"])


if __name__ == "__main__":
    unittest.main()
