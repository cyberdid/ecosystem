from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

from eco_cli.cli import main
from eco_cli.config import validate_repository
from eco_runtime.errors import RuntimePolicyError
from eco_runtime.integration import runtime_diagnostics


NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)


class RuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = Path(__file__).resolve().parents[1]
        errors, self.bundle, self.paths = validate_repository(self.repository, ".ai")
        self.assertEqual(errors, [])
        self.probe_path = self.paths["project"].relative_to(self.repository).as_posix()

    def test_diagnostics_constructs_every_runtime_boundary_without_execution(self) -> None:
        before = {
            path.relative_to(self.repository).as_posix()
            for path in self.repository.rglob("*")
        }
        result = runtime_diagnostics(
            self.repository,
            self.bundle,
            probe_path=self.probe_path,
            now=NOW,
        )
        after = {
            path.relative_to(self.repository).as_posix()
            for path in self.repository.rglob("*")
        }

        self.assertTrue(result["available"])
        self.assertFalse(result["executionReady"])
        self.assertEqual(
            [item["component"] for item in result["checks"]],
            ["policy", "store", "snapshot", "broker", "orchestrator"],
        )
        self.assertTrue(all(item["status"] == "ready" for item in result["checks"]))
        self.assertEqual(
            result["execution"]["code"], "ECO_RUNTIME_TRUST_BOOTSTRAP_REQUIRED"
        )
        self.assertEqual(result["safety"]["writeAuthority"], "not-created")
        self.assertEqual(before, after)

    def test_diagnostics_sanitizes_runtime_exception_messages(self) -> None:
        marker = "PRIVATE_RUNTIME_DETAIL_MUST_NOT_ESCAPE"
        with mock.patch(
            "eco_runtime.integration.PolicyEngine",
            side_effect=RuntimePolicyError("ECO_CONFIG_INVALID", marker),
        ):
            result = runtime_diagnostics(
                self.repository,
                self.bundle,
                probe_path=self.probe_path,
                now=NOW,
            )

        serialized = json.dumps(result)
        self.assertNotIn(marker, serialized)
        self.assertFalse(result["available"])
        self.assertEqual(
            result["checks"],
            [
                {
                    "component": "policy",
                    "status": "blocked",
                    "code": "ECO_CONFIG_INVALID",
                }
            ],
        )

    def test_diagnostics_rejects_untrusted_exception_codes(self) -> None:
        marker = "PRIVATE_CODE_MUST_NOT_ESCAPE"
        with mock.patch(
            "eco_runtime.integration.PolicyEngine",
            side_effect=RuntimePolicyError(marker, "safe-looking message"),
        ):
            result = runtime_diagnostics(
                self.repository,
                self.bundle,
                probe_path=self.probe_path,
                now=NOW,
            )

        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(
            result["checks"][0]["code"], "ECO_RUNTIME_PROBE_FAILED"
        )

    def test_runtime_doctor_is_reachable_from_installed_cli_surface(self) -> None:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "--repo",
                    str(self.repository),
                    "runtime",
                    "doctor",
                    "--json",
                ]
            )

        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(result["available"])
        self.assertFalse(result["executionReady"])
        self.assertNotIn(str(self.repository), stdout.getvalue())
        self.assertNotIn("eco-runtime-doctor-", stdout.getvalue())

    def test_invalid_configuration_fails_before_runtime_construction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr), mock.patch(
                "eco_runtime.integration.runtime_diagnostics"
            ) as diagnostics:
                code = main(
                    [
                        "--repo",
                        str(repository),
                        "runtime",
                        "doctor",
                        "--json",
                    ]
                )

        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(result["available"])
        self.assertEqual(result["checks"][0]["code"], "ECO_CONFIG_INVALID")
        diagnostics.assert_not_called()


if __name__ == "__main__":
    unittest.main()
