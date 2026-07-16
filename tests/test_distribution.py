from __future__ import annotations

import builtins
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any
from unittest import mock

from eco_cli.cli import main
from eco_cli.distribution import (
    MAX_WHEEL_BYTES,
    build_distribution_manifest,
    distribution_manifest_digest,
    installer_plan,
    installer_plan_digest,
    verify_distribution,
)


FIXTURE = Path(__file__).parent / "fixtures" / "distribution" / "portable-bundle.json"
SENSITIVE = "distribution-secret-canary"
VERIFY_SAFETY = {
    "authorityCreated": False,
    "installationPerformed": False,
    "projectMutation": False,
    "networkAccessed": False,
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class DistributionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eco-distribution-")
        self.workspace = Path(self.temporary.name)
        self.bundle = self.workspace / "bundle with spaces та юнікод"
        self.bundle.mkdir()
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.lock = self._write_entry(self.fixture["lock"])
        self.main_wheel = self._write_entry(self.fixture["mainWheel"])
        self.dependency_wheels = tuple(
            self._write_entry(entry) for entry in self.fixture["dependencyWheels"]
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_entry(self, entry: dict[str, Any]) -> Path:
        path = self.bundle / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if "entries" not in entry:
            path.write_bytes(entry["content"].encode("utf-8"))
            return path
        members = [copy.deepcopy(member) for member in entry["entries"]]
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for member in members:
                info = zipfile.ZipInfo(member["path"], date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, member["content"].encode("utf-8"))
        return path

    def _manifest(self, *, dependencies: tuple[Path, ...] | None = None) -> dict[str, Any]:
        return build_distribution_manifest(
            self.main_wheel,
            dependency_wheels=dependencies or self.dependency_wheels,
            version=self.fixture["version"],
            lock_digest=sha256_bytes(self.lock.read_bytes()),
            source_revision=self.fixture["sourceRevision"],
        )

    def _manifest_file(
        self, manifest: dict[str, Any], *, name: str = "distribution manifest.json"
    ) -> Path:
        directory = self.workspace / "manifests with spaces та юнікод"
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        return path

    def _run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(list(arguments))
        output, error = stdout.getvalue(), stderr.getvalue()
        self.assertNotIn(SENSITIVE, output + error)
        self.assertNotIn(str(self.workspace), output + error)
        return code, output, error

    def assert_sanitized(self, value: object) -> None:
        serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(str(self.workspace), serialized)
        self.assertNotIn(SENSITIVE, serialized)
        self.assertNotIn("/private/", serialized)
        self.assertNotIn("C:\\", serialized)

    def assert_verified(self, report: dict[str, Any]) -> None:
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report.get("available", report.get("valid", False)))
        self.assertEqual(report["safety"], VERIFY_SAFETY)
        self.assert_sanitized(report)

    def assert_blocked(self, report: dict[str, Any]) -> None:
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(report.get("available", report.get("valid", False)))
        self.assertEqual(report["safety"], VERIFY_SAFETY)
        self.assert_sanitized(report)

    def _snapshot(self) -> dict[str, tuple[str, bytes | None, int]]:
        return {
            path.relative_to(self.bundle).as_posix(): (
                "directory" if path.is_dir() else "file",
                None if path.is_dir() else path.read_bytes(),
                path.lstat().st_mtime_ns,
            )
            for path in self.bundle.rglob("*")
        }

    def _install_no_side_effect_traps(self, stack: ExitStack) -> None:
        real_open = builtins.open
        real_path_open = Path.open
        real_os_open = os.open
        real_getenv = os.getenv
        real_environ_getitem = type(os.environ).__getitem__

        def reject_write_mode(mode: str) -> None:
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise AssertionError("distribution verification must not write files")

        def guarded_open(
            file: object, mode: str = "r", *args: object, **kwargs: object
        ) -> Any:
            reject_write_mode(mode)
            return real_open(file, mode, *args, **kwargs)

        def guarded_path_open(
            path: Path, mode: str = "r", *args: object, **kwargs: object
        ) -> Any:
            reject_write_mode(mode)
            return real_path_open(path, mode, *args, **kwargs)

        def guarded_os_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            if flags & write_flags:
                raise AssertionError("distribution verification must not write files")
            if dir_fd is None:
                return real_os_open(path, flags, mode)
            return real_os_open(path, flags, mode, dir_fd=dir_fd)

        def guarded_getenv(key: str, default: str | None = None) -> str | None:
            if key == "ECO_DISTRIBUTION_SECRET":
                raise AssertionError("distribution verification must not read secrets")
            return real_getenv(key, default)

        def guarded_environ_getitem(environment: Any, key: str) -> str:
            if key == "ECO_DISTRIBUTION_SECRET":
                raise AssertionError("distribution verification must not read secrets")
            return real_environ_getitem(environment, key)

        forbidden_process = AssertionError(
            "distribution verification must not invoke processes"
        )
        forbidden_network = AssertionError(
            "distribution verification must remain offline"
        )
        stack.enter_context(
            mock.patch.dict(
                os.environ, {"ECO_DISTRIBUTION_SECRET": SENSITIVE}, clear=False
            )
        )
        stack.enter_context(mock.patch.object(builtins, "open", side_effect=guarded_open))
        stack.enter_context(
            mock.patch.object(Path, "open", autospec=True, side_effect=guarded_path_open)
        )
        stack.enter_context(mock.patch.object(os, "open", side_effect=guarded_os_open))
        stack.enter_context(mock.patch.object(os, "getenv", side_effect=guarded_getenv))
        stack.enter_context(
            mock.patch.object(type(os.environ), "__getitem__", guarded_environ_getitem)
        )
        for name in ("run", "Popen", "call", "check_call", "check_output"):
            stack.enter_context(
                mock.patch.object(subprocess, name, side_effect=forbidden_process)
            )
        stack.enter_context(mock.patch.object(os, "system", side_effect=forbidden_process))
        for target in (
            "socket.socket",
            "socket.create_connection",
            "urllib.request.urlopen",
        ):
            stack.enter_context(mock.patch(target, side_effect=forbidden_network))
        for name in (
            "write_bytes",
            "write_text",
            "touch",
            "mkdir",
            "rmdir",
            "unlink",
            "rename",
            "replace",
            "chmod",
            "symlink_to",
            "hardlink_to",
        ):
            stack.enter_context(
                mock.patch.object(Path, name, side_effect=AssertionError("write"))
            )
        for name in ("mkdir", "makedirs", "remove", "unlink", "rename", "replace"):
            stack.enter_context(
                mock.patch.object(os, name, side_effect=AssertionError("write"))
            )

    def test_manifest_is_deterministic_and_exactly_binds_offline_inputs(self) -> None:
        original = self._snapshot()
        first = self._manifest()
        second = self._manifest(dependencies=tuple(reversed(self.dependency_wheels)))
        self.assertEqual(first, second)
        self.assertEqual(
            first["metadata"]["manifestDigest"], distribution_manifest_digest(first)
        )
        self.assertEqual(self._snapshot(), original)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertIn(self.fixture["version"], serialized)
        self.assertIn(self.fixture["sourceRevision"], serialized)
        self.assertIn(sha256_bytes(self.lock.read_bytes()), serialized)
        for wheel in (self.main_wheel, *self.dependency_wheels):
            self.assertIn(wheel.name, serialized)
            self.assertIn(sha256_bytes(wheel.read_bytes()), serialized)
        self.assertNotIn(self.fixture["lock"]["content"], serialized)
        for wheel in self.fixture["dependencyWheels"]:
            for entry in wheel["entries"]:
                self.assertNotIn(entry["content"], serialized)
        for entry in self.fixture["mainWheel"]["entries"]:
            self.assertNotIn(entry["content"], serialized)
            if entry["path"].startswith("eco_cli/schemas/"):
                self.assertIn(entry["path"], serialized)
                self.assertIn(sha256_bytes(entry["content"].encode("utf-8")), serialized)
        self.assert_sanitized(first)
        self.assert_verified(verify_distribution(first, self.bundle))
        self.assertEqual(
            verify_distribution(copy.deepcopy(first), self.bundle),
            verify_distribution(copy.deepcopy(first), self.bundle),
        )

    def test_two_component_dependency_version_is_validated_by_both_verifiers(self) -> None:
        entry = copy.deepcopy(self.fixture["dependencyWheels"][0])
        entry["path"] = "pycparser-3.0-py3-none-any.whl"
        for member in entry["entries"]:
            member["path"] = member["path"].replace(
                "jsonschema-4.25.1", "pycparser-3.0"
            ).replace("jsonschema", "pycparser")
            member["content"] = member["content"].replace(
                "jsonschema-4.25.1", "pycparser-3.0"
            ).replace("jsonschema", "pycparser").replace(
                "Version: 4.25.1", "Version: 3.0"
            )
        dependency = self._write_entry(entry)
        manifest = self._manifest(
            dependencies=(*self.dependency_wheels, dependency)
        )
        self.assert_verified(verify_distribution(manifest, self.bundle))

        manifest_file = self._manifest_file(
            manifest, name="two-component-wheel-version.json"
        )
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        verified = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assert_verified(json.loads(verified.stdout))

    def test_verify_is_offline_read_only_and_never_invokes_installers(self) -> None:
        manifest = self._manifest()
        before = self._snapshot()
        with ExitStack() as stack:
            self._install_no_side_effect_traps(stack)
            report = verify_distribution(copy.deepcopy(manifest), self.bundle)
        self.assert_verified(report)
        self.assertEqual(self._snapshot(), before)

    def test_wheel_and_lock_tamper_truncation_and_oversize_fail_closed(self) -> None:
        targets = (self.main_wheel, *self.dependency_wheels, self.lock)
        for target in targets:
            with self.subTest(target=target.name):
                original = target.read_bytes()
                manifest = self._manifest()
                target.write_bytes(original + b"tamper")
                self.assert_blocked(verify_distribution(manifest, self.bundle))
                target.write_bytes(original)

        manifest = self._manifest()
        missing = self.dependency_wheels[0]
        missing_bytes = missing.read_bytes()
        missing.unlink()
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        missing.write_bytes(missing_bytes)

        manifest = self._manifest()
        extra = self.bundle / "undeclared_dependency-1.0.0-py3-none-any.whl"
        extra.write_bytes(b"undeclared wheel")
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        extra.unlink()

        manifest = self._manifest()
        self.main_wheel.write_bytes(b"")
        self.assert_blocked(verify_distribution(manifest, self.bundle))

        original_main = self._write_entry(self.fixture["mainWheel"]).read_bytes()
        manifest = self._manifest()
        with self.main_wheel.open("wb") as handle:
            handle.truncate(MAX_WHEEL_BYTES + 1)
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        self.main_wheel.write_bytes(original_main)

    def test_unknown_and_duplicate_manifest_inputs_fail_closed(self) -> None:
        manifest = self._manifest()
        unknown = copy.deepcopy(manifest)
        unknown["rawEnvironment"] = {"TOKEN": SENSITIVE}
        report = verify_distribution(unknown, self.bundle)
        self.assert_blocked(report)
        self.assertNotIn(SENSITIVE, json.dumps(report))

        digest_tamper = copy.deepcopy(manifest)
        digest_tamper["metadata"]["manifestDigest"] = "0" * 64
        self.assert_blocked(verify_distribution(digest_tamper, self.bundle))

        artifact_tamper = copy.deepcopy(manifest)
        artifact_tamper["spec"]["mainArtifact"]["sha256"] = "0" * 64
        artifact_tamper["metadata"]["manifestDigest"] = distribution_manifest_digest(
            artifact_tamper
        )
        self.assert_blocked(verify_distribution(artifact_tamper, self.bundle))

        schema_tamper = copy.deepcopy(manifest)
        schema_tamper["spec"]["schemaEntries"][0]["sha256"] = "0" * 64
        schema_tamper["metadata"]["manifestDigest"] = distribution_manifest_digest(
            schema_tamper
        )
        self.assert_blocked(verify_distribution(schema_tamper, self.bundle))

        duplicate = copy.deepcopy(manifest)
        duplicate["spec"]["dependencyArtifacts"].append(
            copy.deepcopy(duplicate["spec"]["dependencyArtifacts"][0])
        )
        duplicate["metadata"]["manifestDigest"] = distribution_manifest_digest(duplicate)
        self.assert_blocked(verify_distribution(duplicate, self.bundle))

        with self.assertRaises((TypeError, ValueError)):
            build_distribution_manifest(
                self.main_wheel,
                dependency_wheels=(
                    self.dependency_wheels[0],
                    self.dependency_wheels[0],
                ),
                version=self.fixture["version"],
                lock_digest=sha256_bytes(self.lock.read_bytes()),
                source_revision=self.fixture["sourceRevision"],
            )

    def test_library_and_stdlib_reject_float_encoded_integer_sizes(self) -> None:
        manifest = self._manifest()
        manifest["spec"]["mainArtifact"]["size"] = float(
            manifest["spec"]["mainArtifact"]["size"]
        )
        manifest["metadata"]["manifestDigest"] = distribution_manifest_digest(
            manifest
        )
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        manifest_file = self._manifest_file(manifest, name="float-size.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        blocked = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assert_blocked(json.loads(blocked.stdout))

    def test_non_pep427_wheel_filename_and_identity_are_rejected(self) -> None:
        manifest = self._manifest()
        renamed = self.main_wheel.with_name("not-a-pep427-wheel.whl")
        self.main_wheel.rename(renamed)
        self.main_wheel = renamed
        manifest["spec"]["mainArtifact"]["filename"] = renamed.name
        manifest["metadata"]["manifestDigest"] = distribution_manifest_digest(
            manifest
        )
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        with self.assertRaises(ValueError):
            build_distribution_manifest(
                self.main_wheel,
                dependency_wheels=self.dependency_wheels,
                version=self.fixture["version"],
                lock_digest=sha256_bytes(self.lock.read_bytes()),
                source_revision=self.fixture["sourceRevision"],
            )

        manifest_file = self._manifest_file(manifest, name="invalid-wheel-name.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        blocked = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assert_blocked(json.loads(blocked.stdout))

    def test_pep427_filename_must_match_embedded_metadata_identity(self) -> None:
        manifest = self._manifest()
        renamed = self.main_wheel.with_name(
            "other_package-0.4.0-py3-none-any.whl"
        )
        self.main_wheel.rename(renamed)
        self.main_wheel = renamed
        manifest["spec"]["mainArtifact"]["filename"] = renamed.name
        manifest["metadata"]["manifestDigest"] = distribution_manifest_digest(
            manifest
        )
        self.assert_blocked(verify_distribution(manifest, self.bundle))
        with self.assertRaises(ValueError):
            build_distribution_manifest(
                self.main_wheel,
                dependency_wheels=self.dependency_wheels,
                version=self.fixture["version"],
                lock_digest=sha256_bytes(self.lock.read_bytes()),
                source_revision=self.fixture["sourceRevision"],
            )

        manifest_file = self._manifest_file(manifest, name="wheel-name-mismatch.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        blocked = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assert_blocked(json.loads(blocked.stdout))

    def test_symlinked_artifact_is_rejected_where_supported(self) -> None:
        manifest = self._manifest()
        external = self.workspace / "external wheel.whl"
        external.write_bytes(self.main_wheel.read_bytes())
        self.main_wheel.unlink()
        try:
            self.main_wheel.symlink_to(external)
        except OSError as exc:
            self.skipTest(f"symlink primitive unavailable: {type(exc).__name__}")
        self.assert_blocked(verify_distribution(manifest, self.bundle))

    def test_hardlinked_artifact_is_rejected_where_supported(self) -> None:
        manifest = self._manifest()
        peer = self.workspace / "hardlink peer.whl"
        peer.write_bytes(self.main_wheel.read_bytes())
        self.main_wheel.unlink()
        try:
            os.link(peer, self.main_wheel)
        except OSError as exc:
            self.skipTest(f"hardlink primitive unavailable: {type(exc).__name__}")
        self.assertGreater(self.main_wheel.stat().st_nlink, 1)
        self.assert_blocked(verify_distribution(manifest, self.bundle))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO primitive is unavailable")
    def test_fifo_artifact_is_rejected_without_opening_it(self) -> None:
        manifest = self._manifest()
        self.main_wheel.unlink()
        os.mkfifo(self.main_wheel)
        real_open = builtins.open
        real_path_open = Path.open
        real_os_open = os.open

        def reject_fifo_open(file: object, *args: object, **kwargs: object) -> Any:
            if Path(file) == self.main_wheel:
                raise AssertionError("verifier must reject FIFO before opening it")
            return real_open(file, *args, **kwargs)

        def reject_fifo_path_open(
            path: Path, *args: object, **kwargs: object
        ) -> Any:
            if path == self.main_wheel:
                raise AssertionError("verifier must reject FIFO before opening it")
            return real_path_open(path, *args, **kwargs)

        def reject_fifo_os_open(
            file: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if Path(file) == self.main_wheel:
                raise AssertionError("verifier must reject FIFO before opening it")
            if dir_fd is None:
                return real_os_open(file, flags, mode)
            return real_os_open(file, flags, mode, dir_fd=dir_fd)

        with (
            mock.patch.object(builtins, "open", side_effect=reject_fifo_open),
            mock.patch.object(
                Path, "open", autospec=True, side_effect=reject_fifo_path_open
            ),
            mock.patch.object(os, "open", side_effect=reject_fifo_os_open),
        ):
            report = verify_distribution(manifest, self.bundle)
        self.assert_blocked(report)

    def test_installer_plan_is_deterministic_preview_only_and_non_authorizing(self) -> None:
        manifest = self._manifest()
        before = self._snapshot()
        with ExitStack() as stack:
            self._install_no_side_effect_traps(stack)
            first = installer_plan(
                copy.deepcopy(manifest), adapter="venv-pip", operation="install"
            )
            second = installer_plan(
                copy.deepcopy(manifest), adapter="venv-pip", operation="install"
            )
        self.assertEqual(first, second)
        self.assertEqual(first["metadata"]["planDigest"], installer_plan_digest(first))
        self.assertEqual(self._snapshot(), before)
        serialized = json.dumps(first, ensure_ascii=False, sort_keys=True)
        self.assertNotIn('"proven": "proven"', serialized)
        self.assertNotIn('"effective": true', serialized)
        self.assertNotIn("http://", serialized)
        self.assertNotIn("https://", serialized)
        self.assertIsInstance(first["spec"]["argv"], list)
        self.assertTrue(all(isinstance(item, str) for item in first["spec"]["argv"]))
        self.assertIn("--no-index", first["spec"]["argv"])
        self.assertIn("<verified-bundle>", first["spec"]["argv"])
        self.assertFalse(first["spec"]["preconditions"]["administratorRequired"])
        self.assertTrue(first["spec"]["preconditions"]["projectAdoptionSeparate"])
        self.assertTrue(all(value is False for value in first["spec"]["safety"].values()))
        self.assert_sanitized(first)

    def test_cli_verify_and_plan_are_offline_read_only_and_sanitized(self) -> None:
        manifest = self._manifest()
        manifest_file = self._manifest_file(manifest)
        before = self._snapshot()
        with ExitStack() as stack:
            self._install_no_side_effect_traps(stack)
            verify_code, verify_output, verify_error = self._run_cli(
                "distribution",
                "verify",
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
                "--json",
            )
            plan_code, plan_output, plan_error = self._run_cli(
                "distribution",
                "plan",
                "--manifest",
                str(manifest_file),
                "--adapter",
                "venv-pip",
                "--operation",
                "install",
                "--json",
            )
        self.assertEqual(verify_code, 0, verify_error)
        self.assert_verified(json.loads(verify_output))
        self.assertEqual(plan_code, 0, plan_error)
        plan = json.loads(plan_output)
        self.assertEqual(plan["kind"], "InstallerPlan")
        self.assertEqual(plan["metadata"]["planDigest"], installer_plan_digest(plan))
        self.assertTrue(all(value is False for value in plan["spec"]["safety"].values()))
        self.assert_sanitized(plan)
        self.assertEqual(self._snapshot(), before)

    def test_cli_malformed_duplicate_manifest_and_lock_tamper_fail_closed(self) -> None:
        manifest = self._manifest()
        valid_file = self._manifest_file(manifest, name="valid.json")
        malformed = valid_file.with_name("malformed.json")
        malformed.write_text('{"secret":"' + SENSITIVE, encoding="utf-8")
        duplicate = valid_file.with_name("duplicate.json")
        duplicate.write_text(
            json.dumps(manifest).replace(
                '"kind": "DistributionManifest"',
                '"kind": "DistributionManifest", "kind": "DistributionManifest"',
                1,
            ),
            encoding="utf-8",
        )

        with ExitStack() as stack:
            self._install_no_side_effect_traps(stack)
            malformed_result = self._run_cli(
                "distribution",
                "verify",
                "--manifest",
                str(malformed),
                "--bundle-root",
                str(self.bundle),
                "--json",
            )
            duplicate_result = self._run_cli(
                "distribution",
                "verify",
                "--manifest",
                str(duplicate),
                "--bundle-root",
                str(self.bundle),
                "--json",
            )
        for code, output, error in (malformed_result, duplicate_result):
            self.assertNotEqual(code, 0, error)
            if output.strip():
                self.assert_blocked(json.loads(output))

        self.lock.write_bytes(self.lock.read_bytes() + b"tamper")
        with ExitStack() as stack:
            self._install_no_side_effect_traps(stack)
            code, output, error = self._run_cli(
                "distribution",
                "verify",
                "--manifest",
                str(valid_file),
                "--bundle-root",
                str(self.bundle),
                "--json",
            )
        self.assertNotEqual(code, 0, error)
        self.assert_blocked(json.loads(output))

    def test_stdlib_verifier_matches_manifest_and_lock_fail_closed(self) -> None:
        manifest_file = self._manifest_file(self._manifest(), name="standalone.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        command = (
            sys.executable,
            str(script),
            "--manifest",
            str(manifest_file),
            "--bundle-root",
            str(self.bundle),
        )
        passed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assert_verified(json.loads(passed.stdout))

        self.lock.write_bytes(self.lock.read_bytes() + b"tamper")
        blocked = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertNotEqual(blocked.returncode, 0)
        report = json.loads(blocked.stdout)
        self.assert_blocked(report)
        self.assert_sanitized(report)

    def test_stdlib_and_library_reject_the_same_invalid_schema_path(self) -> None:
        manifest = self._manifest()
        manifest["spec"]["schemaEntries"][0]["path"] = (
            "eco_cli/schemas/invalid:name.json"
        )
        manifest["metadata"]["manifestDigest"] = distribution_manifest_digest(
            manifest
        )
        self.assert_blocked(verify_distribution(manifest, self.bundle))

        manifest_file = self._manifest_file(manifest, name="invalid-schema-path.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        blocked = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assert_blocked(json.loads(blocked.stdout))

    def test_stdlib_and_library_reject_integer_boolean_aliases(self) -> None:
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        mutations = {
            "safety-zero": ("safety", "networkAccessed", 0),
            "support-one": ("support", "offlineWheelhouse", 1),
        }
        for name, (section, key, value) in mutations.items():
            with self.subTest(case=name):
                manifest = self._manifest()
                manifest["spec"][section][key] = value
                manifest["metadata"]["manifestDigest"] = (
                    distribution_manifest_digest(manifest)
                )
                self.assert_blocked(verify_distribution(manifest, self.bundle))
                manifest_file = self._manifest_file(
                    manifest, name=f"{name}.json"
                )
                blocked = subprocess.run(
                    (
                        sys.executable,
                        str(script),
                        "--manifest",
                        str(manifest_file),
                        "--bundle-root",
                        str(self.bundle),
                    ),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(blocked.returncode, 0)
                self.assert_blocked(json.loads(blocked.stdout))

    def test_stdlib_and_library_reject_oversized_manifest_identity(self) -> None:
        manifest = self._manifest()
        original_version = self.fixture["version"]
        oversized_version = "1" * 65 + ".0.0"
        wheel_fixture = copy.deepcopy(self.fixture["mainWheel"])
        wheel_fixture["path"] = wheel_fixture["path"].replace(
            original_version, oversized_version
        )
        for entry in wheel_fixture["entries"]:
            entry["path"] = entry["path"].replace(
                original_version, oversized_version
            )
            entry["content"] = entry["content"].replace(
                original_version, oversized_version
            )
        self.main_wheel.unlink()
        self.main_wheel = self._write_entry(wheel_fixture)
        main_bytes = self.main_wheel.read_bytes()
        manifest["metadata"].update(
            {
                "id": f"ai-ecosystem-harness-{oversized_version}",
                "version": oversized_version,
            }
        )
        manifest["spec"]["package"]["version"] = oversized_version
        manifest["spec"]["mainArtifact"] = {
            "filename": self.main_wheel.name,
            "sha256": sha256_bytes(main_bytes),
            "size": len(main_bytes),
        }
        manifest["metadata"]["manifestDigest"] = distribution_manifest_digest(
            manifest
        )
        self.assert_blocked(verify_distribution(manifest, self.bundle))

        manifest_file = self._manifest_file(manifest, name="oversized-id.json")
        script = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
        blocked = subprocess.run(
            (
                sys.executable,
                str(script),
                "--manifest",
                str(manifest_file),
                "--bundle-root",
                str(self.bundle),
            ),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(blocked.returncode, 0)
        self.assert_blocked(json.loads(blocked.stdout))


if __name__ == "__main__":
    unittest.main()
