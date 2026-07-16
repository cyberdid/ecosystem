from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from eco_cli.cli import main


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "adoption"
FIXTURE_NAMES = ("minimal-python", "typescript-monorepo")
CANONICAL_PATHS = (
    ".ai/project.yaml",
    ".ai/instructions.yaml",
    ".ai/capabilities.yaml",
    ".ai/deployments.yaml",
    ".ai/tools.yaml",
    ".ai/trust.yaml",
)
PROJECTION_PATHS = (
    "AGENTS.md",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
    "GEMINI.md",
    ".cursor/rules/eco.mdc",
)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURE_ROOT / name / "fixture.json").read_text(encoding="utf-8"))


def materialize_fixture(root: Path, fixture: dict[str, Any]) -> None:
    root.mkdir(parents=True)
    for item in fixture["files"]:
        path = root / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(item["text"].encode("utf-8"))


def tree_contents(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    result: dict[str, tuple[str, bytes | str | None]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ("symlink", os.readlink(path))
        elif path.is_dir():
            result[relative] = ("directory", None)
        else:
            result[relative] = ("file", path.read_bytes())
    return result


def tree_contents_and_mtime(
    root: Path,
) -> dict[str, tuple[str, bytes | str | None, int]]:
    return {
        relative: (kind, content, (root / relative).lstat().st_mtime_ns)
        for relative, (kind, content) in tree_contents(root).items()
    }


class AdoptionFixtureTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eco adoption ")
        self.base = Path(self.temporary.name)
        self.secret_placeholders: tuple[str, ...] = ()
        self.repository_counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_repository(self, fixture_name: str) -> tuple[Path, dict[str, Any]]:
        fixture = load_fixture(fixture_name)
        self.repository_counter += 1
        # The parent path contains spaces; the repository basename remains a
        # portable project identifier on Linux, macOS, and Windows.
        root = self.base / f"{fixture_name}-{self.repository_counter}"
        materialize_fixture(root, fixture)
        self.secret_placeholders = tuple(fixture["secretPlaceholders"])
        return root, fixture

    def run_cli(self, root: Path, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(root), *arguments])
        output, error = stdout.getvalue(), stderr.getvalue()
        for placeholder in self.secret_placeholders:
            self.assertNotIn(placeholder, output)
            self.assertNotIn(placeholder, error)
        return code, output, error

    def run_json(
        self, root: Path, *arguments: str
    ) -> tuple[int, dict[str, Any], str, str]:
        code, output, error = self.run_cli(root, *arguments)
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            self.fail(f"CLI did not emit one JSON document: {exc}; stdout={output!r}")
        self.assertIsInstance(payload, dict)
        return code, payload, output, error

    def assert_plan(
        self,
        root: Path,
        payload: dict[str, Any],
        fixture: dict[str, Any],
        *,
        mode: str,
    ) -> str:
        self.assertEqual(
            set(payload), {"available", "operation", "status", "planDigest", "plan"}
        )
        self.assertTrue(payload["available"])
        self.assertEqual(payload["operation"], "adopt")
        self.assertEqual(payload["status"], "planned")
        self.assertRegex(payload["planDigest"], SHA256_RE)
        plan = payload["plan"]
        self.assertEqual(plan["apiVersion"], "adoption.ai.ecosystem/v1alpha1")
        self.assertEqual(plan["kind"], "ProjectAdoptionPlan")
        self.assertIn(plan["status"]["state"], {"ready", "clean"})
        self.assertEqual(plan["status"]["blockers"], [])
        self.assertEqual(plan["spec"]["mode"], mode)
        self.assertEqual(plan["planDigest"], payload["planDigest"])

        operations = plan["spec"]["operations"]
        self.assertIsInstance(operations, list)
        by_path = {item["path"]: item for item in operations}
        self.assertEqual(len(by_path), len(operations), "operation paths must be unique")
        if mode == "fresh":
            for path in CANONICAL_PATHS:
                self.assertIn(path, by_path)
                self.assertEqual(by_path[path]["action"], "create-canonical")
        if mode in {"fresh", "existing-config"}:
            existing = set(fixture["existingInstructionSurfaces"])
            for path in PROJECTION_PATHS:
                self.assertIn(path, by_path)
                expected = (
                    "append-managed-block" if path in existing else "create-managed-surface"
                )
                self.assertEqual(by_path[path]["action"], expected)

        for operation in operations:
            path = operation["path"]
            self.assertIsInstance(path, str)
            self.assertFalse(PurePosixPath(path).is_absolute())
            self.assertNotIn("..", PurePosixPath(path).parts)
            self.assertNotIn("\\", path)
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(str(root), serialized)
        for placeholder in fixture["secretPlaceholders"]:
            self.assertNotIn(placeholder, serialized)
        return payload["planDigest"]

    def plan_fresh(
        self, root: Path, fixture: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        code, payload, _, error = self.run_json(root, "adopt", "--dry-run", "--json")
        self.assertEqual(code, 0, error)
        return self.assert_plan(root, payload, fixture, mode="fresh"), payload

    def apply(
        self, root: Path, plan_digest: str, *, expected_status: str, expected_changed: bool
    ) -> dict[str, Any]:
        code, payload, _, error = self.run_json(
            root, "adopt", "--apply", plan_digest, "--json"
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(
            set(payload), {"available", "operation", "status", "planDigest", "changed"}
        )
        self.assertTrue(payload["available"])
        self.assertEqual(payload["operation"], "adopt")
        self.assertEqual(payload["status"], expected_status)
        self.assertEqual(payload["planDigest"], plan_digest)
        self.assertIs(payload["changed"], expected_changed)
        return payload

    def test_fixture_manifests_define_exact_portable_before_images(self) -> None:
        python_fixture = load_fixture("minimal-python")
        typescript_fixture = load_fixture("typescript-monorepo")
        python_files = {item["path"]: item["text"].encode() for item in python_fixture["files"]}
        typescript_files = {
            item["path"]: item["text"].encode() for item in typescript_fixture["files"]
        }
        self.assertFalse(python_files["AGENTS.md"].endswith(b"\n"))
        self.assertIn(b"\r\n", typescript_files["CLAUDE.md"])
        self.assertNotIn(b"\r\n", typescript_files["package.json"])
        for fixture in (python_fixture, typescript_fixture):
            self.assertTrue(all(value.startswith("env:FIXTURE_") for value in fixture["secretPlaceholders"]))
            paths = [item["path"] for item in fixture["files"]]
            self.assertEqual(len(paths), len(set(paths)))
            for path in paths:
                self.assertFalse(PurePosixPath(path).is_absolute())
                self.assertNotIn("..", PurePosixPath(path).parts)

    def test_dry_run_apply_and_reinstall_are_scoped_and_idempotent(self) -> None:
        for fixture_name in FIXTURE_NAMES:
            with self.subTest(fixture=fixture_name):
                root, fixture = self.create_repository(fixture_name)
                original = tree_contents_and_mtime(root)
                digest, _ = self.plan_fresh(root, fixture)
                self.assertEqual(tree_contents_and_mtime(root), original)

                self.apply(root, digest, expected_status="applied", expected_changed=True)
                installed = tree_contents_and_mtime(root)
                existing_surfaces = set(fixture["existingInstructionSurfaces"])
                for item in fixture["files"]:
                    path = item["path"]
                    original_bytes = item["text"].encode("utf-8")
                    installed_bytes = (root / path).read_bytes()
                    if path in existing_surfaces:
                        self.assertTrue(installed_bytes.startswith(original_bytes.rstrip()))
                    else:
                        self.assertEqual(installed_bytes, original_bytes)
                for surface in PROJECTION_PATHS:
                    content = (root / surface).read_bytes()
                    self.assertEqual(content.count(b"<!-- eco:managed:start"), 1)
                    self.assertEqual(content.count(b"<!-- eco:managed:end -->"), 1)

                code, repeated_plan, _, error = self.run_json(
                    root, "adopt", "--dry-run", "--json"
                )
                self.assertEqual(code, 0, error)
                repeated_digest = self.assert_plan(
                    root, repeated_plan, fixture, mode="reinstall"
                )
                after_repeated_plan = tree_contents_and_mtime(root)
                self.assertEqual(after_repeated_plan, installed)
                self.apply(
                    root,
                    repeated_digest,
                    expected_status="no-op",
                    expected_changed=False,
                )
                self.assertEqual(tree_contents_and_mtime(root), installed)

    def test_changed_surface_invalidates_plan_without_partial_mutation(self) -> None:
        for fixture_name in FIXTURE_NAMES:
            with self.subTest(fixture=fixture_name):
                root, fixture = self.create_repository(fixture_name)
                digest, _ = self.plan_fresh(root, fixture)
                target = root / fixture["existingInstructionSurfaces"][0]
                target.write_bytes(target.read_bytes() + b"\nchanged-after-plan\n")
                before_apply = tree_contents_and_mtime(root)
                code, payload, _, _ = self.run_json(
                    root, "adopt", "--apply", digest, "--json"
                )
                self.assertNotEqual(code, 0)
                self.assertFalse(payload["available"])
                self.assertEqual(payload["operation"], "adopt")
                self.assertEqual(payload["status"], "blocked")
                self.assertEqual(payload["code"], "ECO_ADOPTION_PLAN_CHANGED")
                self.assertEqual(payload["planDigest"], digest)
                self.assertIs(payload["changed"], False)
                self.assertEqual(tree_contents_and_mtime(root), before_apply)

    def test_tracked_secret_placeholder_is_counted_but_never_emitted(self) -> None:
        root, fixture = self.create_repository("minimal-python")
        subprocess.run(
            ["git", "-C", str(root), "init", "--quiet"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "add", "."],
            check=True,
            capture_output=True,
        )
        code, payload, output, error = self.run_json(
            root, "adopt", "--dry-run", "--json"
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(payload["plan"]["spec"]["discovery"]["potentialSecretLocationCount"], 1)
        self.assertIn(
            "ECO_ADOPTION_SECRET_LOCATIONS_PRESENT",
            payload["plan"]["status"]["warnings"],
        )
        for placeholder in fixture["secretPlaceholders"]:
            self.assertNotIn(placeholder, output + error)

    def test_existing_valid_config_requires_explicit_adoption(self) -> None:
        root, fixture = self.create_repository("minimal-python")
        code, _, error = self.run_cli(root, "init", "--name", fixture["projectId"])
        self.assertEqual(code, 0, error)
        configured = tree_contents_and_mtime(root)

        code, payload, _, _ = self.run_json(root, "adopt", "--dry-run", "--json")
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["operation"], "adopt")
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["code"], "ECO_ADOPTION_CONFIG_EXISTS")
        self.assertEqual(tree_contents_and_mtime(root), configured)

        code, payload, _, error = self.run_json(
            root,
            "adopt",
            "--adopt-existing-config",
            "--dry-run",
            "--json",
        )
        self.assertEqual(code, 0, error)
        self.assert_plan(root, payload, fixture, mode="existing-config")
        self.assertEqual(tree_contents_and_mtime(root), configured)

    def test_uninstall_restores_before_images_and_can_remove_owned_config(self) -> None:
        for fixture_name in FIXTURE_NAMES:
            with self.subTest(fixture=fixture_name, remove_config=False):
                root, fixture = self.create_repository(fixture_name)
                original = tree_contents(root)
                digest, _ = self.plan_fresh(root, fixture)
                self.apply(root, digest, expected_status="applied", expected_changed=True)
                code, _, error = self.run_cli(root, "uninstall")
                self.assertEqual(code, 0, error)
                self.assertTrue((root / ".ai").is_dir())
                remaining = {
                    path: value
                    for path, value in tree_contents(root).items()
                    if path != ".ai" and not path.startswith(".ai/")
                }
                self.assertEqual(remaining, original)

            with self.subTest(fixture=fixture_name, remove_config=True):
                root, fixture = self.create_repository(f"{fixture_name}")
                original = tree_contents(root)
                digest, _ = self.plan_fresh(root, fixture)
                self.apply(root, digest, expected_status="applied", expected_changed=True)
                code, _, error = self.run_cli(
                    root, "uninstall", "--remove-config", "--yes"
                )
                self.assertEqual(code, 0, error)
                self.assertFalse((root / ".ai").exists())
                self.assertEqual(tree_contents(root), original)

    def test_projection_escape_is_blocked_without_external_mutation(self) -> None:
        root, fixture = self.create_repository("minimal-python")
        code, _, error = self.run_cli(root, "init", "--name", fixture["projectId"])
        self.assertEqual(code, 0, error)
        instructions_path = root / ".ai/instructions.yaml"
        instructions = yaml.safe_load(instructions_path.read_text(encoding="utf-8"))
        instructions["projections"]["codex"] = "../outside.md"
        instructions_path.write_text(
            yaml.safe_dump(instructions, sort_keys=False), encoding="utf-8", newline="\n"
        )
        outside = root.parent / "outside.md"
        before = tree_contents_and_mtime(root)
        code, payload, _, _ = self.run_json(
            root,
            "adopt",
            "--adopt-existing-config",
            "--dry-run",
            "--json",
        )
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["code"], "ECO_ADOPTION_PATH_UNSAFE")
        self.assertFalse(outside.exists())
        self.assertEqual(tree_contents_and_mtime(root), before)

    def test_symlink_surface_is_blocked_without_following_target(self) -> None:
        root, _ = self.create_repository("minimal-python")
        target = root.parent / "symlink-canary.md"
        target.write_bytes(b"env:FIXTURE_SYMLINK_CANARY\n")
        surface = root / "AGENTS.md"
        surface.unlink()
        try:
            surface.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        before_target = target.read_bytes()
        before = tree_contents_and_mtime(root)
        code, payload, output, error = self.run_json(root, "adopt", "--dry-run", "--json")
        self.assertNotEqual(code, 0)
        self.assertEqual(payload["code"], "ECO_ADOPTION_PATH_UNSAFE")
        self.assertFalse(payload["available"])
        self.assertNotIn("env:FIXTURE_SYMLINK_CANARY", output + error)
        self.assertEqual(target.read_bytes(), before_target)
        self.assertEqual(tree_contents_and_mtime(root), before)
        self.assertFalse((root / ".ai").exists())

    def test_hardlinked_surface_is_blocked_without_mutating_peer(self) -> None:
        root, _ = self.create_repository("minimal-python")
        peer = root.parent / "hardlink-canary.md"
        peer.write_bytes(b"env:FIXTURE_HARDLINK_CANARY\n")
        surface = root / "AGENTS.md"
        surface.unlink()
        try:
            os.link(peer, surface)
        except OSError as exc:
            self.skipTest(f"hardlink creation is unavailable: {exc}")
        before_peer = peer.read_bytes()
        before = tree_contents_and_mtime(root)
        code, payload, output, error = self.run_json(root, "adopt", "--dry-run", "--json")
        self.assertNotEqual(code, 0)
        self.assertEqual(payload["code"], "ECO_ADOPTION_PATH_UNSAFE")
        self.assertFalse(payload["available"])
        self.assertNotIn("env:FIXTURE_HARDLINK_CANARY", output + error)
        self.assertEqual(peer.read_bytes(), before_peer)
        self.assertEqual(tree_contents_and_mtime(root), before)
        self.assertFalse((root / ".ai").exists())


if __name__ == "__main__":
    unittest.main()
