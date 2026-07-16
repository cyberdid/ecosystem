from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib import resources
from io import StringIO
from pathlib import Path
from typing import Any
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

from eco_cli.adoption import (
    _exclusive_adoption_lock,
    apply_adoption,
    plan_adoption,
)
from eco_cli.cli import main
from eco_cli.errors import EcoError


PLACEHOLDER = "env:FIXTURE_SAFETY_TOKEN"


def write_fixture(root: Path, *, projection: bytes | None = None) -> None:
    root.mkdir(parents=True)
    (root / "README.md").write_bytes(b"# Adoption safety fixture\n")
    (root / "config").mkdir()
    (root / "config/runtime.env").write_bytes(
        f"TOKEN={PLACEHOLDER}\n".encode("utf-8")
    )
    if projection is not None:
        (root / "AGENTS.md").write_bytes(projection)


def tree_state(
    root: Path, *, include_mtime: bool
) -> dict[str, tuple[str, bytes | str | None, int | None]]:
    result: dict[str, tuple[str, bytes | str | None, int | None]] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind, content = "symlink", os.readlink(path)
        elif path.is_dir():
            kind, content = "directory", None
        else:
            kind, content = "file", path.read_bytes()
        result[relative] = (
            kind,
            content,
            path.lstat().st_mtime_ns if include_mtime else None,
        )
    return result


class AdoptionSafetyTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eco-adoption-safety-")
        self.base = Path(self.temporary.name)
        self.counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repository(self, *, projection: bytes | None = b"# Existing guidance\n") -> Path:
        self.counter += 1
        root = self.base / f"repo-{self.counter}"
        write_fixture(root, projection=projection)
        return root

    def run_cli(self, root: Path, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(root), *arguments])
        output, error = stdout.getvalue(), stderr.getvalue()
        self.assertNotIn(PLACEHOLDER, output)
        self.assertNotIn(PLACEHOLDER, error)
        return code, output, error

    def run_json(
        self, root: Path, *arguments: str
    ) -> tuple[int, dict[str, Any], str, str]:
        code, output, error = self.run_cli(root, *arguments)
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            self.fail(f"expected one JSON document: {exc}; stdout={output!r}")
        self.assertIsInstance(payload, dict)
        return code, payload, output, error

    def adopt(self, root: Path, *, existing_config: bool = False) -> dict[str, Any]:
        plan = plan_adoption(root, adopt_existing_config=existing_config)
        self.assertIn(plan["status"]["state"], {"ready", "clean"})
        result = apply_adoption(
            root,
            expected_plan_digest=plan["planDigest"],
            adopt_existing_config=existing_config,
        )
        self.assertTrue(result["applied"])
        return plan

    def test_generated_plan_and_receipt_validate_against_packaged_schemas(self) -> None:
        root = self.repository()
        plan = plan_adoption(root)
        plan_schema = json.loads(
            resources.files("eco_cli")
            .joinpath("schemas", "adoption-plan.schema.json")
            .read_text(encoding="utf-8")
        )
        receipt_schema = json.loads(
            resources.files("eco_cli")
            .joinpath("schemas", "adoption-receipt.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(plan_schema)
        Draft202012Validator.check_schema(receipt_schema)
        self.assertEqual(list(Draft202012Validator(plan_schema).iter_errors(plan)), [])

        apply_adoption(root, expected_plan_digest=plan["planDigest"])
        receipt = json.loads((root / ".ai/adoption.json").read_text(encoding="utf-8"))
        self.assertEqual(
            list(Draft202012Validator(receipt_schema).iter_errors(receipt)), []
        )
        self.assertEqual(receipt["spec"]["appliedPlanDigest"], plan["planDigest"])

    def test_local_state_ignore_excludes_render_state_and_before_images(self) -> None:
        root = self.repository()
        subprocess.run(
            ["git", "-C", str(root), "init", "--quiet"],
            check=True,
            capture_output=True,
        )
        self.adopt(root)
        state_ignore = root / ".ai/.state/.gitignore"
        self.assertEqual(state_ignore.read_bytes(), b"*\n!.gitignore\n")
        render_state = json.loads(
            (root / ".ai/.state/render.json").read_text(encoding="utf-8")
        )
        backups = [item["backup"] for item in render_state["outputs"] if item["backup"]]
        self.assertTrue(backups)

        ignored = [".ai/.state/render.json", *[f".ai/{item}" for item in backups]]
        for relative in ignored:
            result = subprocess.run(
                ["git", "-C", str(root), "check-ignore", "--quiet", "--", relative],
                check=False,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, relative)
        visible_ignore = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "check-ignore",
                "--quiet",
                "--",
                ".ai/.state/.gitignore",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(visible_ignore.returncode, 1)
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout
        self.assertIn(".ai/.state/.gitignore", status)
        self.assertNotIn(".ai/.state/render.json", status)
        self.assertTrue(all(f".ai/{item}" not in status for item in backups))

    def test_remove_config_preflight_refuses_canonical_drift_without_mutation(self) -> None:
        root = self.repository()
        self.adopt(root)
        project = root / ".ai/project.yaml"
        project.write_bytes(project.read_bytes() + b"\n# operator drift\n")
        before = tree_state(root, include_mtime=True)
        code, _, error = self.run_cli(root, "uninstall", "--remove-config", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("ECO_ADOPTION_CONFIG_DRIFT", error)
        self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_remove_config_preflight_refuses_unknown_entry_without_mutation(self) -> None:
        root = self.repository()
        self.adopt(root)
        unknown = root / ".ai/operator-note.txt"
        unknown.write_bytes(b"operator-owned\n")
        before = tree_state(root, include_mtime=True)
        code, _, error = self.run_cli(root, "uninstall", "--remove-config", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("ECO_ADOPTION_UNKNOWN_CONFIG_ENTRY", error)
        self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_existing_config_adoption_cannot_remove_preexisting_canonical_files(self) -> None:
        root = self.repository()
        code, _, error = self.run_cli(root, "init", "--name", "existing-project")
        self.assertEqual(code, 0, error)
        self.adopt(root, existing_config=True)
        before = tree_state(root, include_mtime=True)
        code, _, error = self.run_cli(root, "uninstall", "--remove-config", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("ECO_ADOPTION_PREEXISTING_CONFIG", error)
        self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_non_utf8_projection_is_blocked_without_creating_config(self) -> None:
        root = self.repository(projection=b"\xff\xfe\x00not-utf8")
        before = tree_state(root, include_mtime=True)
        code, payload, output, error = self.run_json(
            root, "adopt", "--dry-run", "--json"
        )
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["code"], "ECO_ADOPTION_PATH_UNSAFE")
        self.assertNotIn("not-utf8", output + error)
        self.assertEqual(tree_state(root, include_mtime=True), before)
        self.assertFalse((root / ".ai").exists())

    def test_injected_apply_failure_restores_exact_original_tree(self) -> None:
        root = self.repository()
        original = tree_state(root, include_mtime=False)
        plan = plan_adoption(root)
        with mock.patch(
            "eco_cli.adoption._build_receipt",
            side_effect=OSError("injected after projection/state writes"),
        ):
            with self.assertRaises(OSError):
                apply_adoption(root, expected_plan_digest=plan["planDigest"])
        self.assertEqual(tree_state(root, include_mtime=False), original)
        self.assertFalse((root / ".ai").exists())
        self.assertFalse((root / ".github").exists())
        self.assertFalse((root / ".cursor").exists())

    def test_exclusive_lock_returns_busy_without_repository_mutation(self) -> None:
        root = self.repository()
        plan = plan_adoption(root)
        before = tree_state(root, include_mtime=True)
        with _exclusive_adoption_lock(root.resolve()):
            code, payload, _, _ = self.run_json(
                root,
                "adopt",
                "--apply",
                plan["planDigest"],
                "--json",
            )
        self.assertNotEqual(code, 0)
        self.assertFalse(payload["available"])
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["code"], "ECO_ADOPTION_BUSY")
        self.assertIs(payload["changed"], False)
        self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_uninstall_rejects_tampered_backup_authority_without_mutation(self) -> None:
        for tamper in ("bytes", "path", "hardlink"):
            with self.subTest(tamper=tamper):
                root = self.repository()
                self.adopt(root)
                state_path = root / ".ai/.state/render.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                agents = next(
                    item for item in state["outputs"] if item["path"] == "AGENTS.md"
                )
                self.assertIsInstance(agents["backup"], str)
                backup = root / ".ai" / agents["backup"]
                self.assertTrue(backup.is_file())

                if tamper == "bytes":
                    backup.write_bytes(b"tampered before-image\n")
                elif tamper == "path":
                    agents["backup"] = "project.yaml"
                    state_path.write_text(
                        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
                        + "\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                else:
                    peer = root / "backup-hardlink-peer.bin"
                    try:
                        os.link(backup, peer)
                    except OSError as exc:
                        raise unittest.SkipTest(
                            f"hardlink creation is unavailable: {exc}"
                        ) from exc

                before = tree_state(root, include_mtime=True)
                code, _, _ = self.run_cli(root, "uninstall")
                self.assertNotEqual(code, 0)
                self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_forged_marker_without_trusted_render_state_never_mutates(self) -> None:
        forged = (
            b"operator-owned prefix\n\n"
            b"<!-- eco:managed:start forged=\"true\" -->\n"
            b"untrusted marker body\n"
            b"<!-- eco:managed:end -->\n"
        )
        for state_mode in ("missing", "deleted", "corrupt"):
            with self.subTest(state=state_mode):
                root = self.repository(projection=forged if state_mode == "missing" else None)
                if state_mode != "missing":
                    self.adopt(root)
                    (root / "AGENTS.md").write_bytes(forged)
                    state_path = root / ".ai/.state/render.json"
                    if state_mode == "deleted":
                        state_path.unlink()
                    else:
                        state_path.write_bytes(b"{not-valid-json")

                before = tree_state(root, include_mtime=True)
                code, _, _ = self.run_cli(root, "uninstall")
                self.assertNotEqual(code, 0)
                self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_adoption_never_claims_marker_without_ownership_state(self) -> None:
        forged = (
            b"operator-owned prefix\n\n"
            b"<!-- eco:managed:start forged=\"true\" -->\n"
            b"untrusted marker body\n"
            b"<!-- eco:managed:end -->\n"
        )
        root = self.repository(projection=forged)
        before = tree_state(root, include_mtime=True)
        code, payload, _, _ = self.run_json(root, "adopt", "--dry-run", "--json")
        self.assertNotEqual(code, 0)
        self.assertEqual(payload["code"], "ECO_ADOPTION_OWNERSHIP_AMBIGUOUS")
        self.assertEqual(tree_state(root, include_mtime=True), before)
        self.assertFalse((root / ".ai").exists())

    def test_rollback_preserves_concurrent_user_bytes_and_reports_conflict(self) -> None:
        root = self.repository()
        original = tree_state(root, include_mtime=False)
        concurrent = b"concurrent user bytes must survive rollback\n"
        expected = dict(original)
        expected["AGENTS.md"] = ("file", concurrent, None)
        plan = plan_adoption(root)

        def fail_after_concurrent_write(_context: Any) -> dict[str, Any]:
            (root / "AGENTS.md").write_bytes(concurrent)
            raise OSError("injected receipt failure")

        with mock.patch(
            "eco_cli.adoption._build_receipt",
            side_effect=fail_after_concurrent_write,
        ):
            with self.assertRaises(EcoError) as caught:
                apply_adoption(root, expected_plan_digest=plan["planDigest"])
        self.assertEqual(str(caught.exception), "ECO_ADOPTION_ROLLBACK_CONFLICT")
        self.assertEqual((root / "AGENTS.md").read_bytes(), concurrent)
        self.assertEqual(tree_state(root, include_mtime=False), expected)
        self.assertFalse((root / ".ai").exists())
        self.assertFalse((root / ".github").exists())
        self.assertFalse((root / ".cursor").exists())

    def test_uninstall_rejects_aliased_or_nonregular_projection_state(self) -> None:
        for topology in ("state-parent-symlink", "render-symlink", "render-hardlink", "render-directory"):
            with self.subTest(topology=topology):
                root = self.repository()
                self.adopt(root)
                external = self.base / f"outside-{topology}-{self.counter}"
                external.mkdir()
                (external / "canary.bin").write_bytes(b"outside must not change\n")
                state_directory = root / ".ai/.state"
                render = state_directory / "render.json"

                if topology == "state-parent-symlink":
                    moved = external / "state"
                    state_directory.rename(moved)
                    try:
                        state_directory.symlink_to(moved, target_is_directory=True)
                    except OSError as exc:
                        raise unittest.SkipTest(
                            f"directory symlink creation is unavailable: {exc}"
                        ) from exc
                elif topology == "render-symlink":
                    target = external / "render.json"
                    render.replace(target)
                    try:
                        render.symlink_to(target)
                    except OSError as exc:
                        raise unittest.SkipTest(
                            f"file symlink creation is unavailable: {exc}"
                        ) from exc
                elif topology == "render-hardlink":
                    peer = external / "render-peer.json"
                    try:
                        os.link(render, peer)
                    except OSError as exc:
                        raise unittest.SkipTest(
                            f"hardlink creation is unavailable: {exc}"
                        ) from exc
                else:
                    render.unlink()
                    render.mkdir()

                before_repo = tree_state(root, include_mtime=True)
                before_outside = tree_state(external, include_mtime=True)
                code, _, _ = self.run_cli(root, "uninstall")
                self.assertNotEqual(code, 0)
                self.assertEqual(tree_state(root, include_mtime=True), before_repo)
                self.assertEqual(tree_state(external, include_mtime=True), before_outside)

    def test_unsafe_per_user_lock_topology_is_sanitized_and_nonmutating(self) -> None:
        identity = (
            f"uid:{os.getuid()}" if hasattr(os, "getuid") else f"home:{Path.home()}"
        )
        identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]

        for topology in ("root-symlink", "file-symlink", "file-hardlink"):
            with self.subTest(topology=topology):
                root = self.repository()
                plan = plan_adoption(root)
                private_temp = self.base / f"lock-temp-{topology}-{self.counter}"
                private_temp.mkdir()
                lock_root = private_temp / f"eco-adoption-locks-{identity_digest}"
                lock_name = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()
                lock_path = lock_root / f"{lock_name}.lock"
                external = self.base / f"lock-outside-{topology}-{self.counter}"
                external.mkdir()
                target = external / "canary.lock"
                target.write_bytes(b"external lock canary\n")

                if topology == "root-symlink":
                    try:
                        lock_root.symlink_to(external, target_is_directory=True)
                    except OSError as exc:
                        raise unittest.SkipTest(
                            f"directory symlink creation is unavailable: {exc}"
                        ) from exc
                else:
                    lock_root.mkdir(mode=0o700)
                    if os.name == "posix":
                        os.chmod(lock_root, 0o700)
                    if topology == "file-symlink":
                        try:
                            lock_path.symlink_to(target)
                        except OSError as exc:
                            raise unittest.SkipTest(
                                f"file symlink creation is unavailable: {exc}"
                            ) from exc
                    else:
                        try:
                            os.link(target, lock_path)
                        except OSError as exc:
                            raise unittest.SkipTest(
                                f"hardlink creation is unavailable: {exc}"
                            ) from exc

                before_repo = tree_state(root, include_mtime=True)
                before_outside = tree_state(external, include_mtime=True)
                with mock.patch(
                    "eco_cli.adoption.tempfile.gettempdir",
                    return_value=str(private_temp),
                ):
                    code, payload, output, error = self.run_json(
                        root,
                        "adopt",
                        "--apply",
                        plan["planDigest"],
                        "--json",
                    )
                self.assertNotEqual(code, 0)
                self.assertFalse(payload["available"])
                self.assertEqual(payload["code"], "ECO_ADOPTION_LOCK_UNSAFE")
                self.assertNotIn(str(target), output + error)
                self.assertNotIn("external lock canary", output + error)
                self.assertEqual(tree_state(root, include_mtime=True), before_repo)
                self.assertEqual(tree_state(external, include_mtime=True), before_outside)

    def test_concurrent_canonical_edit_during_remove_preflight_survives(self) -> None:
        from eco_cli import adoption as adoption_module

        root = self.repository()
        self.adopt(root)
        project = root / ".ai/project.yaml"
        concurrent = b"concurrent canonical edit must survive\n"
        before = tree_state(root, include_mtime=False)
        expected = dict(before)
        expected[".ai/project.yaml"] = ("file", concurrent, None)
        original_verified_backup = adoption_module._verified_backup
        injected = False

        def inject_during_preflight(*args: Any, **kwargs: Any):
            nonlocal injected
            result = original_verified_backup(*args, **kwargs)
            if not injected:
                injected = True
                project.write_bytes(concurrent)
            return result

        with mock.patch(
            "eco_cli.adoption._verified_backup",
            side_effect=inject_during_preflight,
        ):
            code, _, error = self.run_cli(
                root, "uninstall", "--remove-config", "--yes"
            )
        self.assertNotEqual(code, 0)
        self.assertIn("ECO_ADOPTION_CONFIG_DRIFT", error)
        self.assertTrue(injected)
        self.assertEqual(project.read_bytes(), concurrent)
        self.assertEqual(tree_state(root, include_mtime=False), expected)

    def test_concurrent_projection_edit_after_backup_verification_survives(self) -> None:
        from eco_cli import compiler as compiler_module

        root = self.repository()
        self.adopt(root)
        agents = root / "AGENTS.md"
        concurrent = b"concurrent projection edit must survive\n"
        before = tree_state(root, include_mtime=False)
        expected = dict(before)
        expected["AGENTS.md"] = ("file", concurrent, None)
        original_verified_backup = compiler_module._verified_backup
        injected = False

        def inject_after_backup_verification(*args: Any, **kwargs: Any):
            nonlocal injected
            result = original_verified_backup(*args, **kwargs)
            if not injected:
                injected = True
                agents.write_bytes(concurrent)
            return result

        with mock.patch(
            "eco_cli.compiler._verified_backup",
            side_effect=inject_after_backup_verification,
        ):
            code, _, _ = self.run_cli(root, "uninstall")
        self.assertNotEqual(code, 0)
        self.assertTrue(injected)
        self.assertEqual(agents.read_bytes(), concurrent)
        self.assertEqual(tree_state(root, include_mtime=False), expected)

    def test_duplicate_projection_target_emits_one_sanitized_plan_error_json(self) -> None:
        root = self.repository()
        code, _, error = self.run_cli(root, "init", "--name", "duplicate-target")
        self.assertEqual(code, 0, error)
        instructions_path = root / ".ai/instructions.yaml"
        instructions = yaml.safe_load(instructions_path.read_text(encoding="utf-8"))
        instructions["projections"]["claude"] = "AGENTS.md"
        instructions_path.write_text(
            yaml.safe_dump(instructions, sort_keys=False),
            encoding="utf-8",
            newline="\n",
        )
        code, payload, output, error = self.run_json(
            root,
            "adopt",
            "--adopt-existing-config",
            "--dry-run",
            "--json",
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(
            payload,
            {
                "available": False,
                "operation": "adopt",
                "status": "blocked",
                "code": "ECO_ADOPTION_PLAN_INVALID",
                "planDigest": None,
                "plan": None,
            },
        )
        self.assertEqual(error, "")
        self.assertNotIn(str(root), output)
        self.assertNotIn("Existing guidance", output)

    def test_late_apply_oserror_emits_one_sanitized_generic_json(self) -> None:
        root = self.repository()
        plan = plan_adoption(root)
        original = tree_state(root, include_mtime=False)
        sensitive_message = f"late failure at {root}: Existing guidance; {PLACEHOLDER}"
        with mock.patch(
            "eco_cli.adoption._build_receipt",
            side_effect=OSError(sensitive_message),
        ):
            code, payload, output, error = self.run_json(
                root,
                "adopt",
                "--apply",
                plan["planDigest"],
                "--json",
            )
        self.assertNotEqual(code, 0)
        self.assertEqual(
            payload,
            {
                "available": False,
                "operation": "adopt",
                "status": "blocked",
                "code": "ECO_ADOPTION_FAILED",
                "planDigest": plan["planDigest"],
                "changed": False,
            },
        )
        self.assertEqual(error, "")
        self.assertNotIn(str(root), output)
        self.assertNotIn(sensitive_message, output)
        self.assertNotIn("Existing guidance", output)
        self.assertEqual(tree_state(root, include_mtime=False), original)

    def test_projection_state_backup_metadata_must_match_ownership_mode(self) -> None:
        for case in ("adopted-without-backup", "replaced-without-backup", "created-with-backup"):
            with self.subTest(case=case):
                root = self.repository()
                self.adopt(root)
                state_path = root / ".ai/.state/render.json"
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if case in {"adopted-without-backup", "replaced-without-backup"}:
                    entry = next(
                        item for item in state["outputs"] if item["path"] == "AGENTS.md"
                    )
                    entry["mode"] = case.split("-", 1)[0]
                    entry["backup"] = None
                    entry["backupDigest"] = None
                    entry["backupSize"] = None
                else:
                    entry = next(
                        item for item in state["outputs"] if item["path"] == "CLAUDE.md"
                    )
                    self.assertEqual(entry["mode"], "created")
                    forged = b"forged backup for a created surface\n"
                    backup = root / ".ai/.state/backups/forged-created.bak"
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    backup.write_bytes(forged)
                    entry["backup"] = ".state/backups/forged-created.bak"
                    entry["backupDigest"] = hashlib.sha256(forged).hexdigest()
                    entry["backupSize"] = len(forged)
                state_path.write_text(
                    json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )

                before = tree_state(root, include_mtime=True)
                code, _, _ = self.run_cli(root, "uninstall")
                self.assertNotEqual(code, 0)
                self.assertEqual(tree_state(root, include_mtime=True), before)

    def test_unknown_empty_config_directory_blocks_full_remove_without_mutation(self) -> None:
        root = self.repository()
        self.adopt(root)
        (root / ".ai/operator-empty").mkdir()
        before = tree_state(root, include_mtime=True)
        code, _, error = self.run_cli(root, "uninstall", "--remove-config", "--yes")
        self.assertNotEqual(code, 0)
        self.assertIn("ECO_ADOPTION_UNKNOWN_CONFIG_ENTRY", error)
        self.assertEqual(tree_state(root, include_mtime=True), before)


if __name__ == "__main__":
    unittest.main()
