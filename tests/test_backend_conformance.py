from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import StringIO
from typing import Any
from unittest import mock

from eco_cli.platform_profiles import platform_doctor, platform_profile_document
from eco_cli.cli import main
from eco_runtime.backend_conformance import (
    OBSERVED_CAPABILITIES,
    PROBE_IDS,
    SUITE_DIGEST,
    SUITE_ID,
    run_backend_conformance,
)
from eco_runtime.contracts import validate_record
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimePolicyError
from eco_runtime.evidence import (
    EvidenceIssuerPolicy,
    EvidenceTrustStore,
    HmacEvidenceSigner,
    TrustedEvidenceIngestor,
)
from eco_runtime.isolation import LaunchResult


PLATFORM_FIXTURES = Path(__file__).parent / "fixtures" / "platform"
NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
DISTRIBUTION_DIGEST = "d" * 64
BACKEND_INSTANCE_DIGEST = "b" * 64
SIGNING_KEY = b"backend-conformance-test-key-0001"
SENSITIVE = "backend-secret-canary"


class FakeLauncher:
    def __init__(
        self,
        *,
        failing_probe: str | None = None,
        leak: bool = False,
        inherit_environment: bool = False,
    ) -> None:
        self.failing_probe = failing_probe
        self.leak = leak
        self.inherit_environment = inherit_environment
        self.preflight_calls = 0
        self.launch_calls: list[tuple[object, object]] = []

    def _preflight(self) -> None:
        self.preflight_calls += 1

    def launch(
        self,
        request: object,
        contract: object,
        *,
        credential_resolver: object,
    ) -> LaunchResult:
        del credential_resolver
        self.launch_calls.append((request, contract))
        source = request.arguments[1]  # type: ignore[attr-defined]
        if "ECO_PROBE:output-limit" in source:
            probe_id = "output-and-deadline-bounds"
            if probe_id != self.failing_probe:
                raise RuntimePolicyError(
                    "ECO_ISOLATION_OUTPUT_LIMIT", "synthetic output was bounded"
                )
        elif "ECO_PROBE:deadline" in source:
            probe_id = "output-and-deadline-bounds"
            if probe_id != self.failing_probe:
                raise RuntimePolicyError(
                    "ECO_ISOLATION_TIMEOUT", "synthetic deadline was bounded"
                )
        else:
            marker = source.split("# ECO_PROBE:", 1)[1].splitlines()[0]
            probe_id = marker
        if probe_id == "clean-environment-and-fs-boundary" and (
            os.environ.get("ECO_CONFORMANCE_HOST_CANARY") != "must-not-cross"
            or self.inherit_environment
        ):
            return LaunchResult(0, b"ECO_BACKEND_PROBE_FAIL\n", b"")
        if probe_id == self.failing_probe:
            leaked = SENSITIVE.encode("utf-8") if self.leak else b"probe failed"
            return LaunchResult(1, leaked, b"/private/conformance/root")
        return LaunchResult(0, b"ECO_BACKEND_PROBE_PASS\n", b"")


class BackendConformanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="eco-backend-conformance-")
        self.workspace = Path(self.temporary.name)
        self.repository = self.workspace / "repository with spaces та юнікод"
        self.test_root = self.workspace / "isolated test root"
        self.repository.mkdir()
        self.test_root.mkdir()
        self.test_root.chmod(0o700)
        (self.repository / "README.md").write_text("project\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def platform_profile(self, profile_id: str = "linux-native") -> dict[str, Any]:
        fixture = json.loads(
            (PLATFORM_FIXTURES / f"{profile_id}.json").read_text(encoding="utf-8")
        )
        report = platform_doctor(
            profile_id,
            repository=self.repository,
            probe_inputs=fixture["probeInputs"],
        )
        return platform_profile_document(report, profile_id=profile_id)

    def run_profile(
        self,
        profile: dict[str, Any],
        *,
        launcher: object | None,
        active: bool = True,
        suite_digest: str = SUITE_DIGEST,
        test_root: Path | None = None,
        host_system: str = "Linux",
        machine: str = "x86_64",
    ) -> dict[str, Any]:
        return run_backend_conformance(
            profile,
            test_root=test_root or self.test_root,
            repository=self.repository,
            distribution_manifest_digest=DISTRIBUTION_DIGEST,
            backend_instance_digest=BACKEND_INSTANCE_DIGEST,
            suite_digest=suite_digest,
            active=active,
            now=NOW,
            launcher=launcher,
            host_system=host_system,
            machine=machine,
        )

    def snapshot(self) -> dict[str, tuple[str, bytes | None, int]]:
        return {
            path.relative_to(self.workspace).as_posix(): (
                "directory" if path.is_dir() else "file",
                None if path.is_dir() else path.read_bytes(),
                path.lstat().st_mtime_ns,
            )
            for path in self.workspace.rglob("*")
        }

    def install_zero_effect_traps(self, stack: ExitStack) -> None:
        forbidden_process = AssertionError("backend runner must not invoke a process")
        forbidden_network = AssertionError("backend runner must not access a network")
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

    def assert_sanitized(self, profile: dict[str, Any]) -> None:
        serialized = json.dumps(profile, ensure_ascii=False, sort_keys=True)
        self.assertNotIn(str(self.workspace), serialized)
        self.assertNotIn(SENSITIVE, serialized)
        self.assertNotIn("/private/", serialized)
        self.assertNotIn("C:\\", serialized)
        self.assertFalse(profile["spec"]["safety"]["authenticated"])
        self.assertFalse(profile["spec"]["safety"]["authorityCreated"])
        self.assertFalse(profile["spec"]["safety"]["runtimeConsumed"])
        self.assertFalse(profile["spec"]["safety"]["projectMutation"])
        self.assertFalse(profile["spec"]["safety"]["rawOutputPersisted"])

    def test_suite_and_profile_schema_are_exact_deterministic_and_non_authorizing(self) -> None:
        self.assertEqual(SUITE_ID, "linux-namespace-boundary")
        self.assertEqual(len(SUITE_DIGEST), 64)
        self.assertEqual(tuple(PROBE_IDS), tuple(sorted(PROBE_IDS)))
        self.assertEqual(len(PROBE_IDS), 5)
        self.assertEqual(tuple(OBSERVED_CAPABILITIES), tuple(sorted(OBSERVED_CAPABILITIES)))
        launcher = FakeLauncher()
        first = self.run_profile(self.platform_profile(), launcher=launcher)
        second = self.run_profile(self.platform_profile(), launcher=FakeLauncher())
        self.assertEqual(first, second)
        self.assertEqual(validate_record(first), first)
        self.assertEqual(first["kind"], "PlatformBackendConformanceProfile")
        self.assertEqual(first["spec"]["suite"]["id"], SUITE_ID)
        self.assertEqual(first["spec"]["suite"]["digest"], SUITE_DIGEST)
        self.assertEqual(first["spec"]["suite"]["probeIds"], list(PROBE_IDS))
        self.assertEqual([item["id"] for item in first["spec"]["probes"]], list(PROBE_IDS))
        self.assert_sanitized(first)

        unknown = copy.deepcopy(first)
        unknown["rawOutput"] = SENSITIVE
        duplicate_probe = copy.deepcopy(first)
        duplicate_probe["spec"]["probes"][1] = copy.deepcopy(
            duplicate_probe["spec"]["probes"][0]
        )
        inconsistent_pass = copy.deepcopy(first)
        inconsistent_pass["spec"]["probes"][0]["status"] = "fail"
        unsafe = copy.deepcopy(first)
        unsafe["spec"]["safety"]["authenticated"] = True
        context_relabel = copy.deepcopy(first)
        context_relabel["spec"]["platform"]["context"] = "wsl"
        supported_platform_relabel = copy.deepcopy(first)
        supported_platform_relabel["metadata"]["platformProfileId"] = "windows-native"
        supported_platform_relabel["spec"]["platform"].update(
            {"id": "windows-native", "operatingSystem": "windows", "context": "native"}
        )
        for name, invalid in (
            ("unknown", unknown),
            ("duplicate-probe", duplicate_probe),
            ("inconsistent-pass", inconsistent_pass),
            ("unsafe", unsafe),
            ("context-relabel", context_relabel),
            ("supported-platform-relabel", supported_platform_relabel),
        ):
            with self.subTest(invalid=name):
                with self.assertRaises(ContractValidationError) as caught:
                    validate_record(invalid)
                self.assertNotIn(SENSITIVE, str(caught.exception))

    def test_unsupported_or_inactive_context_never_invokes_or_mutates(self) -> None:
        cases = (
            (self.platform_profile("macos"), "Darwin", "aarch64"),
            (self.platform_profile("container"), "Linux", "x86_64"),
        )
        for profile, host_system, machine in cases:
            with self.subTest(profile=profile["metadata"]["id"]):
                launcher = FakeLauncher()
                before = self.snapshot()
                with ExitStack() as stack:
                    self.install_zero_effect_traps(stack)
                    result = self.run_profile(
                        profile,
                        launcher=launcher,
                        host_system=host_system,
                        machine=machine,
                    )
                self.assertEqual(result["spec"]["status"], "unsupported")
                self.assertEqual(launcher.preflight_calls, 0)
                self.assertEqual(launcher.launch_calls, [])
                self.assertEqual(self.snapshot(), before)
                self.assert_sanitized(result)

    def test_live_context_is_detected_independently_before_backend_launch(self) -> None:
        profile = self.platform_profile("linux-native")
        before = self.snapshot()
        with mock.patch(
            "eco_runtime.backend_conformance._live_context", return_value="wsl"
        ):
            result = self.run_profile(profile, launcher=None)
        self.assertEqual(result["spec"]["status"], "unsupported")
        self.assertEqual(
            result["spec"]["deviationCodes"], ["ECO_BACKEND_CONTEXT_MISMATCH"]
        )
        self.assertEqual(self.snapshot(), before)
        self.assert_sanitized(result)

    def test_invalid_suite_or_root_fails_before_process_or_mutation(self) -> None:
        invalid_root = self.repository / "inside-project"
        invalid_root.mkdir()
        invalid_root.chmod(0o700)
        cases = (
            ("suite", "0" * 64, self.test_root, True, "ECO_CONFORMANCE_SUITE_MISMATCH"),
            ("root", SUITE_DIGEST, invalid_root, True, "ECO_CONFORMANCE_ROOT_INVALID"),
            (
                "confirmation",
                SUITE_DIGEST,
                self.test_root,
                False,
                "ECO_CONFORMANCE_CONFIRMATION_REQUIRED",
            ),
        )
        for name, suite_digest, test_root, active, code in cases:
            with self.subTest(case=name):
                launcher = FakeLauncher()
                before = self.snapshot()
                with ExitStack() as stack:
                    self.install_zero_effect_traps(stack)
                    with self.assertRaises(RuntimePolicyError) as caught:
                        self.run_profile(
                            self.platform_profile(),
                            launcher=launcher,
                            suite_digest=suite_digest,
                            test_root=test_root,
                            active=active,
                        )
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(launcher.preflight_calls, 0)
                self.assertEqual(launcher.launch_calls, [])
                self.assertEqual(self.snapshot(), before)

    def test_injected_launcher_pass_fail_and_raw_output_are_content_free(self) -> None:
        passed_launcher = FakeLauncher()
        passed = self.run_profile(self.platform_profile(), launcher=passed_launcher)
        self.assertEqual(passed["spec"]["status"], "pass")
        self.assertEqual(passed["spec"]["observedCapabilities"], list(OBSERVED_CAPABILITIES))
        self.assertEqual(passed_launcher.preflight_calls, 1)
        self.assertEqual(len(passed_launcher.launch_calls), len(PROBE_IDS) + 1)
        self.assert_sanitized(passed)

        failed_launcher = FakeLauncher(failing_probe=PROBE_IDS[0], leak=True)
        failed = self.run_profile(self.platform_profile(), launcher=failed_launcher)
        self.assertEqual(failed["spec"]["status"], "fail")
        self.assertEqual(failed["spec"]["observedCapabilities"], [])
        self.assertIn("fail", {item["status"] for item in failed["spec"]["probes"]})
        self.assert_sanitized(failed)

        inherited = self.run_profile(
            self.platform_profile(), launcher=FakeLauncher(inherit_environment=True)
        )
        self.assertEqual(inherited["spec"]["status"], "fail")
        clean_probe = next(
            item
            for item in inherited["spec"]["probes"]
            if item["id"] == "clean-environment-and-fs-boundary"
        )
        self.assertEqual(clean_probe["status"], "fail")
        self.assert_sanitized(inherited)

    def test_cli_non_object_profile_fails_closed_with_sanitized_json(self) -> None:
        for index, payload in enumerate(("null", "1", "[1]", '["x"]')):
            with self.subTest(payload=payload):
                profile_file = self.workspace / f"non-object-{index}.json"
                profile_file.write_text(payload, encoding="utf-8")
                stdout, stderr = StringIO(), StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = main(
                        [
                            "--repo",
                            str(self.repository),
                            "conformance",
                            "run",
                            "--active",
                            "--platform-profile",
                            str(profile_file),
                            "--test-root",
                            str(self.test_root),
                            "--suite",
                            SUITE_ID,
                            "--suite-digest",
                            SUITE_DIGEST,
                            "--distribution-manifest-digest",
                            DISTRIBUTION_DIGEST,
                            "--backend-instance-digest",
                            BACKEND_INSTANCE_DIGEST,
                            "--json",
                        ]
                    )
                self.assertEqual(code, 1)
                self.assertEqual(stderr.getvalue(), "")
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(
                    report["code"], "ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID"
                )
                serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
                self.assertNotIn(str(self.workspace), serialized)
                self.assertNotIn(SENSITIVE, serialized)
                self.assertTrue(
                    all(value is False for value in report["safety"].values())
                )

    def test_signed_profile_ingests_exactly_and_replay_or_mismatch_fails_closed(self) -> None:
        record = self.run_profile(self.platform_profile(), launcher=FakeLauncher())
        signer = HmacEvidenceSigner("backend-authority", "backend-key-1", SIGNING_KEY)
        encoded = signer.sign(
            record,
            envelope_id="backend-envelope-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )
        policy = EvidenceIssuerPolicy(
            "backend-authority",
            "backend-key-1",
            SIGNING_KEY,
            frozenset({"PlatformBackendConformanceProfile"}),
            allowed_suite_digests=frozenset({SUITE_DIGEST}),
            allowed_platform_profiles=frozenset({"linux-native"}),
            allowed_backend_instances=frozenset({BACKEND_INSTANCE_DIGEST}),
            allowed_runner_digests=frozenset({record["spec"]["runnerDigest"]}),
            allowed_backend_implementation_digests=frozenset(
                {record["spec"]["backend"]["implementationDigest"]}
            ),
        )
        ingestor = TrustedEvidenceIngestor(EvidenceTrustStore((policy,)))
        expected = {
            "expected_platform_profile_id": record["metadata"]["platformProfileId"],
            "expected_platform_profile_digest": record["spec"]["platformProfileDigest"],
            "expected_backend_instance_digest": BACKEND_INSTANCE_DIGEST,
            "expected_backend_implementation_digest": record["spec"]["backend"][
                "implementationDigest"
            ],
            "expected_runner_digest": record["spec"]["runnerDigest"],
            "expected_distribution_manifest_digest": DISTRIBUTION_DIGEST,
            "trusted_suite_digests": frozenset({SUITE_DIGEST}),
            "now": NOW,
        }
        trusted = ingestor.ingest_platform_backend_conformance(encoded, **expected)
        self.assertEqual(semantic_digest(trusted.as_dict()), semantic_digest(record))
        replay = ingestor.ingest_platform_backend_conformance(encoded, **expected)
        self.assertEqual(replay.provenance.envelope_digest, trusted.provenance.envelope_digest)

        mismatches = (
            ("expected_platform_profile_id", "wsl"),
            ("expected_platform_profile_digest", "a" * 64),
            ("expected_backend_instance_digest", "a" * 64),
            ("expected_backend_implementation_digest", "a" * 64),
            ("expected_runner_digest", "a" * 64),
            ("expected_distribution_manifest_digest", "a" * 64),
            ("trusted_suite_digests", frozenset({"a" * 64})),
        )
        for key, value in mismatches:
            with self.subTest(binding=key):
                arguments = {**expected, key: value}
                with self.assertRaises(RuntimePolicyError):
                    TrustedEvidenceIngestor(EvidenceTrustStore((policy,))).ingest_platform_backend_conformance(
                        encoded, **arguments
                    )

        changed = copy.deepcopy(record)
        changed["spec"]["backend"]["instanceDigest"] = "a" * 64
        conflicting = signer.sign(
            changed,
            envelope_id="backend-envelope-1",
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )
        with self.assertRaises(RuntimePolicyError) as caught:
            ingestor.ingest_platform_backend_conformance(conflicting, **expected)
        self.assertEqual(caught.exception.code, "ECO_EVIDENCE_ID_CONFLICT")


if __name__ == "__main__":
    unittest.main()
