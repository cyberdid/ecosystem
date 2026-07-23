from __future__ import annotations

import builtins
import copy
import inspect
import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any
from unittest import mock

from eco_cli.cli import main
from eco_cli.platform_profiles import (
    adapter_capability_profile_document,
    platform_doctor,
    platform_profile_document,
    profile_document_digest,
    validate_adapter_capability_profile,
    validate_platform_profile,
)
from eco_runtime.digests import semantic_digest


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "platform"
PROFILE_IDS = (
    "container",
    "hosted-ci",
    "linux-native",
    "macos",
    "windows-native",
    "wsl",
)
EXECUTABLE_ALLOWLIST = (
    "claude",
    "codex",
    "cursor",
    "docker",
    "gemini",
    "git",
    "node",
    "nvidia-smi",
    "ollama",
    "python",
)
CLIENT_ALLOWLIST = ("claude", "codex", "copilot", "cursor", "gemini")
SENSITIVE = "env:FIXTURE_PLATFORM_TOKEN"
SAFETY = {
    "executionReady": False,
    "authorityCreated": False,
    "mutationPerformed": False,
    "networkAccessed": False,
}


def fixture(profile_id: str) -> dict[str, Any]:
    return json.loads((FIXTURE_ROOT / f"{profile_id}.json").read_text(encoding="utf-8"))


def report_without_digest(report: dict[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(report)
    body.pop("reportDigest", None)
    return body


def adapter_capability_profile() -> dict[str, Any]:
    return adapter_capability_profile_document(
        profile_id="fixture-adapter-linux",
        adapter_id="fixture-adapter",
        platform_profile_digest="1" * 64,
        deployment_identity_digest="2" * 64,
        declared_capabilities=(
            "runtime.process-isolation",
            "runtime.network-denial",
        ),
    )


class PlatformConformanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eco-platform-fixture-")
        self.repo = Path(self.temporary.name) / "repo with spaces"
        self.repo.mkdir()
        (self.repo / "README.md").write_bytes(b"# platform fixture\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(self.repo), *arguments])
        output, error = stdout.getvalue(), stderr.getvalue()
        self.assertNotIn(SENSITIVE, output + error)
        self.assertNotIn(str(self.repo), output + error)
        return code, output, error

    def assert_sanitized(self, report: dict[str, Any]) -> None:
        serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(SENSITIVE, serialized)
        self.assertNotIn(str(self.repo), serialized)
        self.assertNotIn("/usr/", serialized)
        self.assertNotIn("C:\\", serialized)
        for item in report.get("executables", []):
            self.assertEqual(set(item), {"name", "status"})
            self.assertIn(item["name"], EXECUTABLE_ALLOWLIST)
            self.assertIn(item["status"], {"present", "absent", "not-tested"})
        for item in report.get("clients", []):
            self.assertEqual(set(item), {"id", "status"})
            self.assertIn(item["id"], CLIENT_ALLOWLIST)
            self.assertIn(item["status"], {"surface-present", "absent", "not-tested"})

    def assert_stable_digest(self, report: dict[str, Any]) -> None:
        self.assertEqual(report["reportDigest"], semantic_digest(report_without_digest(report)))

    def assert_non_authoritative(self, report: dict[str, Any]) -> None:
        self.assertEqual(report["safety"], SAFETY)
        self.assertIsNone(report["profile"]["proven"])
        self.assertTrue(
            all(item["status"] == "not-tested" for item in report["runtimeSecurity"])
        )
        self.assertTrue(
            all(item["evidenceDigest"] is None for item in report["runtimeSecurity"])
        )

    def test_all_fixture_profiles_separate_declared_detected_and_proven(self) -> None:
        for profile_id in PROFILE_IDS:
            with self.subTest(profile=profile_id):
                document = fixture(profile_id)
                original = copy.deepcopy(document)
                first = platform_doctor(
                    document["declaredProfile"],
                    repository=self.repo,
                    probe_inputs=document["probeInputs"],
                )
                second = platform_doctor(
                    document["declaredProfile"],
                    repository=self.repo,
                    probe_inputs=copy.deepcopy(document["probeInputs"]),
                )
                self.assertEqual(first, second)
                self.assertEqual(document, original)
                self.assertTrue(first["available"])
                self.assertEqual(first["mode"], "platform-conformance-read-only")
                self.assertEqual(first["status"], "pass")
                self.assertEqual(first["profile"]["declared"], profile_id)
                self.assertEqual(first["profile"]["detected"], profile_id)
                self.assertEqual(
                    [item["name"] for item in first["executables"]],
                    list(EXECUTABLE_ALLOWLIST),
                )
                self.assertEqual(
                    [item["id"] for item in first["clients"]], list(CLIENT_ALLOWLIST)
                )
                self.assert_non_authoritative(first)
                self.assert_sanitized(first)
                self.assert_stable_digest(first)

    def test_doctor_exposes_no_unsigned_evidence_channel(self) -> None:
        self.assertNotIn("conformance_evidence", inspect.signature(platform_doctor).parameters)
        document = fixture("linux-native")
        baseline = platform_doctor(
            "linux-native", repository=self.repo, probe_inputs=document["probeInputs"]
        )
        self.assert_non_authoritative(baseline)

        unsigned_evidence = {
            "apiVersion": "platform.ai.ecosystem/v1alpha1",
            "kind": "PlatformConformanceEvidence",
            "metadata": {"id": "caller-supplied", "profile": "linux-native"},
            "spec": {
                "version": 1,
                "probeDigest": baseline["probeDigest"],
                "capabilities": [
                    item["capability"] for item in baseline["runtimeSecurity"]
                ],
                "status": "pass",
            },
        }
        poisoned_inputs = copy.deepcopy(document["probeInputs"])
        poisoned_inputs["conformanceEvidence"] = [unsigned_evidence]
        result = platform_doctor(
            "linux-native", repository=self.repo, probe_inputs=poisoned_inputs
        )
        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "blocked")
        self.assert_non_authoritative(result)
        self.assert_sanitized(result)
        self.assert_stable_digest(result)

        with self.assertRaises(TypeError):
            platform_doctor(
                "linux-native",
                repository=self.repo,
                probe_inputs=document["probeInputs"],
                conformance_evidence=(unsigned_evidence,),
            )

    def test_spoofed_markers_duplicates_and_unsupported_platform_fail_closed(self) -> None:
        base = fixture("linux-native")["probeInputs"]
        cases: list[tuple[str, str, dict[str, Any]]] = []
        os_spoof = copy.deepcopy(base)
        os_spoof["os"] = {"name": "nt", "system": "Linux"}
        cases.append(("os", "windows-native", os_spoof))
        wsl_spoof = copy.deepcopy(base)
        wsl_spoof["signals"]["wsl"] = {"environment": True, "kernel": False}
        cases.append(("wsl", "wsl", wsl_spoof))
        container_spoof = copy.deepcopy(base)
        container_spoof["signals"]["container"] = {
            "environment": True,
            "filesystem": False,
        }
        cases.append(("container", "container", container_spoof))
        ci_spoof = copy.deepcopy(base)
        ci_spoof["signals"]["hostedCi"] = {"environment": True, "provider": False}
        cases.append(("ci", "hosted-ci", ci_spoof))
        duplicate_executable = copy.deepcopy(base)
        duplicate_executable["executables"].append(
            copy.deepcopy(duplicate_executable["executables"][0])
        )
        cases.append(("duplicate-executable", "linux-native", duplicate_executable))
        duplicate_client = copy.deepcopy(base)
        duplicate_client["clients"].append(copy.deepcopy(duplicate_client["clients"][0]))
        cases.append(("duplicate-client", "linux-native", duplicate_client))
        unsupported = copy.deepcopy(base)
        unsupported["os"] = {"name": "posix", "system": "SunOS"}
        cases.append(("unsupported", "solaris", unsupported))
        raw_environment = copy.deepcopy(base)
        raw_environment["rawEnvironment"] = {"TOKEN": SENSITIVE}
        cases.append(("raw-environment", "linux-native", raw_environment))
        nested_runtime_evidence = copy.deepcopy(base)
        nested_runtime_evidence["signals"]["wsl"]["runtimeSecurity"] = {
            "status": "proven",
            "evidenceDigest": "f" * 64,
        }
        cases.append(("nested-runtime-evidence", "linux-native", nested_runtime_evidence))
        wsl_in_container = copy.deepcopy(base)
        wsl_in_container["signals"]["wsl"] = {"environment": True, "kernel": True}
        wsl_in_container["signals"]["container"] = {
            "environment": True,
            "filesystem": True,
        }
        cases.append(("wsl-in-container", "wsl", wsl_in_container))
        container_in_hosted_ci = copy.deepcopy(base)
        container_in_hosted_ci["signals"]["container"] = {
            "environment": True,
            "filesystem": True,
        }
        container_in_hosted_ci["signals"]["hostedCi"] = {
            "environment": True,
            "provider": True,
        }
        cases.append(("container-in-hosted-ci", "hosted-ci", container_in_hosted_ci))

        for name, declared, inputs in cases:
            with self.subTest(case=name):
                result = platform_doctor(
                    declared, repository=self.repo, probe_inputs=inputs
                )
                self.assertFalse(result["available"])
                self.assertEqual(result["status"], "blocked")
                self.assert_non_authoritative(result)
                self.assert_sanitized(result)
                self.assert_stable_digest(result)

    def test_changed_probe_inputs_change_digests_without_creating_authority(self) -> None:
        document = fixture("linux-native")
        baseline = platform_doctor(
            "linux-native", repository=self.repo, probe_inputs=document["probeInputs"]
        )
        changed = copy.deepcopy(document["probeInputs"])
        docker = next(item for item in changed["executables"] if item["name"] == "docker")
        docker["present"] = not docker["present"]
        result = platform_doctor(
            "linux-native", repository=self.repo, probe_inputs=changed
        )
        self.assertNotEqual(result["probeDigest"], baseline["probeDigest"])
        self.assertNotEqual(result["reportDigest"], baseline["reportDigest"])
        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "pass")
        self.assert_non_authoritative(baseline)
        self.assert_non_authoritative(result)
        self.assert_sanitized(result)
        self.assert_stable_digest(result)

    def test_platform_profile_document_is_deterministic_closed_and_non_authorizing(
        self,
    ) -> None:
        probe = fixture("linux-native")["probeInputs"]
        report = platform_doctor(
            "linux-native", repository=self.repo, probe_inputs=probe
        )
        first = platform_profile_document(report, profile_id="linux-native")
        second = platform_profile_document(
            copy.deepcopy(report), profile_id="linux-native"
        )
        self.assertEqual(first, second)
        self.assertEqual(validate_platform_profile(first), [])
        self.assertEqual(
            first["metadata"]["profileDigest"], profile_document_digest(first)
        )
        self.assertEqual(first["spec"]["effectiveCapabilities"], [])
        self.assertEqual(first["spec"]["safety"], SAFETY)
        self.assertTrue(
            all(
                item["effective"] is False and "evidence" not in item
                for item in first["spec"]["runtimeSecurity"]
            )
        )

        unknown = copy.deepcopy(first)
        unknown["spec"]["rawEnvironment"] = {"TOKEN": SENSITIVE}
        unknown["metadata"]["profileDigest"] = profile_document_digest(unknown)
        unknown_errors = validate_platform_profile(unknown)
        self.assertTrue(
            any("additionalProperties" in error for error in unknown_errors),
            unknown_errors,
        )
        self.assertNotIn(SENSITIVE, json.dumps(unknown_errors))

        tampered = copy.deepcopy(first)
        tampered["spec"]["classification"]["detected"] = "wsl"
        self.assertIn("$.metadata.profileDigest: digest", validate_platform_profile(tampered))

        unproven_effective = copy.deepcopy(first)
        capability = unproven_effective["spec"]["runtimeSecurity"][0]
        capability.update(
            {
                "declared": "declared",
                "detected": "detected",
                "proven": "proven",
                "effective": True,
            }
        )
        unproven_effective["spec"]["effectiveCapabilities"] = [capability["id"]]
        unproven_effective["metadata"]["profileDigest"] = profile_document_digest(
            unproven_effective
        )
        errors = validate_platform_profile(unproven_effective)
        self.assertTrue(
            any(
                marker in error
                for error in errors
                for marker in ("unproven-effective", ".effective: const", ".proven: enum")
            ),
            errors,
        )

    def test_adapter_capability_profile_is_closed_digest_bound_and_non_authorizing(
        self,
    ) -> None:
        document = adapter_capability_profile()
        reordered = adapter_capability_profile_document(
            profile_id="fixture-adapter-linux",
            adapter_id="fixture-adapter",
            platform_profile_digest="1" * 64,
            deployment_identity_digest="2" * 64,
            declared_capabilities=(
                "runtime.network-denial",
                "runtime.process-isolation",
            ),
        )
        self.assertEqual(document, reordered)
        self.assertEqual(validate_adapter_capability_profile(document), [])
        self.assertEqual(
            document["metadata"]["profileDigest"], profile_document_digest(document)
        )

        tampered = copy.deepcopy(document)
        tampered["spec"]["deploymentIdentityDigest"] = "3" * 64
        self.assertIn(
            "$.metadata.profileDigest: digest",
            validate_adapter_capability_profile(tampered),
        )

        unknown = copy.deepcopy(document)
        unknown["spec"]["credentials"] = SENSITIVE
        unknown["metadata"]["profileDigest"] = profile_document_digest(unknown)
        unknown_errors = validate_adapter_capability_profile(unknown)
        self.assertTrue(
            any("additionalProperties" in error for error in unknown_errors),
            unknown_errors,
        )
        self.assertNotIn(SENSITIVE, json.dumps(unknown_errors))

        duplicate = copy.deepcopy(document)
        duplicate["spec"]["capabilities"].append(
            copy.deepcopy(duplicate["spec"]["capabilities"][0])
        )
        duplicate["metadata"]["profileDigest"] = profile_document_digest(duplicate)
        duplicate_errors = validate_adapter_capability_profile(duplicate)
        self.assertTrue(
            any("duplicate" in error for error in duplicate_errors), duplicate_errors
        )

        unproven_effective = copy.deepcopy(document)
        capability = unproven_effective["spec"]["capabilities"][0]
        capability.update(
            {"detected": "detected", "proven": "proven", "effective": True}
        )
        unproven_effective["spec"]["effectiveCapabilities"] = [capability["id"]]
        unproven_effective["metadata"]["profileDigest"] = profile_document_digest(
            unproven_effective
        )
        errors = validate_adapter_capability_profile(unproven_effective)
        self.assertTrue(
            any(
                marker in error
                for error in errors
                for marker in ("unproven-effective", ".effective: const", ".proven: enum")
            ),
            errors,
        )

    def test_cli_declared_profile_passes_on_match_and_blocks_on_mismatch(self) -> None:
        probe = fixture("linux-native")["probeInputs"]
        with mock.patch(
            "eco_cli.platform_profiles._host_probe", return_value=copy.deepcopy(probe)
        ):
            pass_code, pass_output, pass_error = self.run_cli(
                "platform",
                "doctor",
                "--json",
                "--declared-profile",
                "linux-native",
            )
            mismatch_code, mismatch_output, mismatch_error = self.run_cli(
                "platform",
                "doctor",
                "--json",
                "--declared-profile",
                "wsl",
            )

        self.assertEqual(pass_code, 0, pass_error)
        matching = json.loads(pass_output)
        self.assertTrue(matching["available"])
        self.assertEqual(matching["status"], "pass")
        self.assertEqual(
            matching["profile"],
            {"declared": "linux-native", "detected": "linux-native", "proven": None},
        )
        self.assert_non_authoritative(matching)
        self.assert_sanitized(matching)
        self.assert_stable_digest(matching)

        self.assertEqual(mismatch_code, 1, mismatch_error)
        mismatch = json.loads(mismatch_output)
        self.assertFalse(mismatch["available"])
        self.assertEqual(mismatch["status"], "blocked")
        self.assertEqual(mismatch["code"], "ECO_PLATFORM_DECLARATION_MISMATCH")
        self.assertEqual(
            mismatch["profile"],
            {"declared": "wsl", "detected": "linux-native", "proven": None},
        )
        self.assert_non_authoritative(mismatch)
        self.assert_sanitized(mismatch)
        self.assert_stable_digest(mismatch)

    def test_cli_doctor_is_read_only_and_discovery_never_invokes_executables(self) -> None:
        (self.repo / "AGENTS.md").write_bytes(b"client projection\n")
        (self.repo / "CLAUDE.md").write_bytes(b"client projection\n")
        secret_canaries = {
            self.repo / ".env",
            self.repo / "credentials.json",
        }
        for path in secret_canaries:
            path.write_text(SENSITIVE, encoding="utf-8")
        before = {
            path.relative_to(self.repo).as_posix(): (
                "directory" if path.is_dir() else "file",
                None if path.is_dir() else path.read_bytes(),
                path.lstat().st_mtime_ns,
            )
            for path in self.repo.rglob("*")
        }
        discovered: list[str] = []

        def which(name: str) -> str | None:
            discovered.append(name)
            return f"/private/toolchain/{name}" if name in {"git", "python"} else None

        real_open = builtins.open
        real_path_open = Path.open
        real_getenv = os.getenv
        real_environ_getitem = type(os.environ).__getitem__

        def guard_file_access(path: object, mode: str) -> None:
            requested = Path(path).resolve(strict=False)
            if requested in {item.resolve(strict=False) for item in secret_canaries}:
                raise AssertionError("platform doctor must never read secret canaries")
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise AssertionError("platform doctor must never write files")

        def guarded_open(
            file: object, mode: str = "r", *args: object, **kwargs: object
        ) -> Any:
            guard_file_access(file, mode)
            return real_open(file, mode, *args, **kwargs)

        def guarded_path_open(
            path: Path, mode: str = "r", *args: object, **kwargs: object
        ) -> Any:
            guard_file_access(path, mode)
            return real_path_open(path, mode, *args, **kwargs)

        def guarded_getenv(key: str, default: str | None = None) -> str | None:
            if key == "FIXTURE_PLATFORM_TOKEN":
                raise AssertionError("platform doctor must never resolve secret environment")
            return real_getenv(key, default)

        def guarded_environ_getitem(environment: Any, key: str) -> str:
            if key == "FIXTURE_PLATFORM_TOKEN":
                raise AssertionError("platform doctor must never resolve secret environment")
            return real_environ_getitem(environment, key)

        forbidden_process = AssertionError(
            "platform doctor must never invoke executables"
        )
        forbidden_network = AssertionError("platform doctor must never access the network")

        # Warm the platform-detection cache before the mocks below. On Windows
        # with Python 3.11, ``platform.uname()`` shells out (subprocess/os.system)
        # for the OS version, which this test deliberately forbids; caching it
        # first keeps OS detection working while still proving the doctor itself
        # launches no process and performs no write. Python 3.12 uses ``_wmi``
        # instead, which is why only 3.11 needed this.
        platform.uname()

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.dict(
                    os.environ, {"FIXTURE_PLATFORM_TOKEN": SENSITIVE}, clear=False
                )
            )
            stack.enter_context(
                mock.patch.object(builtins, "open", side_effect=guarded_open)
            )
            stack.enter_context(
                mock.patch.object(
                    Path, "open", autospec=True, side_effect=guarded_path_open
                )
            )
            stack.enter_context(mock.patch.object(os, "getenv", side_effect=guarded_getenv))
            stack.enter_context(
                mock.patch.object(
                    type(os.environ), "__getitem__", guarded_environ_getitem
                )
            )
            stack.enter_context(mock.patch.object(shutil, "which", side_effect=which))
            for name in ("run", "Popen", "call", "check_call", "check_output"):
                stack.enter_context(
                    mock.patch.object(subprocess, name, side_effect=forbidden_process)
                )
            stack.enter_context(
                mock.patch.object(os, "system", side_effect=forbidden_process)
            )
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
            _real_os_open = os.open
            _write_flags = (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
                | getattr(os, "O_TEMPORARY", 0)
            )

            def _write_only_guard(path, flags, *args, **kwargs):
                # A read-only open is not a write; the doctor legitimately reads
                # (on some platforms/versions its reads route through os.open).
                # Only a write-intent open violates read-only discovery.
                if flags & _write_flags:
                    raise AssertionError("write")
                return _real_os_open(path, flags, *args, **kwargs)

            stack.enter_context(mock.patch.object(os, "open", side_effect=_write_only_guard))
            code, output, error = self.run_cli("platform", "doctor", "--json")
        self.assertEqual(code, 0, f"exit={code} stdout={output!r} stderr={error!r}")
        report = json.loads(output)
        self.assertEqual(sorted(set(discovered)), list(EXECUTABLE_ALLOWLIST))
        self.assertEqual(discovered, list(EXECUTABLE_ALLOWLIST))
        self.assert_sanitized(report)
        self.assert_stable_digest(report)
        self.assert_non_authoritative(report)
        clients = {item["id"]: item["status"] for item in report["clients"]}
        self.assertEqual(clients["codex"], "surface-present")
        self.assertEqual(clients["claude"], "surface-present")
        after = {
            path.relative_to(self.repo).as_posix(): (
                "directory" if path.is_dir() else "file",
                None if path.is_dir() else path.read_bytes(),
                path.lstat().st_mtime_ns,
            )
            for path in self.repo.rglob("*")
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
