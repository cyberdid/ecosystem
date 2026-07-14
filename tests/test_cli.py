from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import yaml

from eco_cli.audit import audit_repository
from eco_cli.cli import main
from eco_cli.constants import MANAGED_START_PREFIX


class EcoCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--repo", str(self.repo), *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def init(self) -> None:
        code, _, error = self.run_cli("init", "--name", "sample")
        self.assertEqual(code, 0, error)

    def test_init_validate_render_doctor_and_uninstall(self) -> None:
        self.init()
        self.assertEqual(self.run_cli("validate")[0], 0)
        self.assertEqual(self.run_cli("render")[0], 0)
        self.assertIn(MANAGED_START_PREFIX, (self.repo / "AGENTS.md").read_text(encoding="utf-8"))
        self.assertEqual(self.run_cli("render", "--check")[0], 0)
        self.assertEqual(self.run_cli("doctor")[0], 0)
        self.assertEqual(self.run_cli("lock")[0], 0)
        lock = json.loads((self.repo / ".ai/locks/ecosystem.lock.json").read_text(encoding="utf-8"))
        self.assertIn("instructions", lock["inputs"])
        self.assertEqual(self.run_cli("uninstall")[0], 0)
        self.assertFalse((self.repo / "AGENTS.md").exists())
        self.assertTrue((self.repo / ".ai/project.yaml").exists())

    def test_projection_drift_is_detected_and_repaired(self) -> None:
        self.init()
        self.assertEqual(self.run_cli("render")[0], 0)
        path = self.repo / ".ai/instructions.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["purpose"] = "A changed purpose that remains long enough for schema validation."
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        self.assertEqual(self.run_cli("render", "--check")[0], 1)
        self.assertEqual(self.run_cli("render")[0], 0)
        self.assertEqual(self.run_cli("render", "--check")[0], 0)

    def test_unmanaged_surface_requires_explicit_adoption(self) -> None:
        self.init()
        (self.repo / "AGENTS.md").write_text("# Existing instructions\n", encoding="utf-8")
        code, _, error = self.run_cli("render")
        self.assertEqual(code, 2)
        self.assertIn("Unmanaged vendor surfaces", error)
        self.assertEqual(self.run_cli("render", "--adopt")[0], 0)
        content = (self.repo / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("# Existing instructions", content)
        self.assertIn(MANAGED_START_PREFIX, content)
        self.assertEqual(self.run_cli("uninstall")[0], 0)
        self.assertEqual((self.repo / "AGENTS.md").read_text(encoding="utf-8"), "# Existing instructions\n")

    def test_force_creates_backup_and_uninstall_restores_original(self) -> None:
        self.init()
        original = "# Existing instructions\n\nDo not lose me.\n"
        (self.repo / "AGENTS.md").write_text(original, encoding="utf-8")
        self.assertEqual(self.run_cli("render", "--force")[0], 0)
        self.assertNotEqual((self.repo / "AGENTS.md").read_text(encoding="utf-8"), original)
        self.assertEqual(self.run_cli("uninstall")[0], 0)
        self.assertEqual((self.repo / "AGENTS.md").read_text(encoding="utf-8"), original)

    def test_secret_literal_is_rejected_without_printing_value(self) -> None:
        self.init()
        path = self.repo / ".ai/tools.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["tools"][0]["credentialRef"] = "literal-super-secret-value"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        code, _, error = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("credentialRef", error)
        self.assertNotIn("literal-super-secret-value", error)

    def test_cross_contract_capability_mismatch_is_rejected(self) -> None:
        self.init()
        path = self.repo / ".ai/tools.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["tools"][0]["capability"] = "missing.capability"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        code, _, error = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("unknown capability", error)

    def test_projection_path_cannot_escape_repository(self) -> None:
        self.init()
        path = self.repo / ".ai/instructions.yaml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        document["projections"]["codex"] = "../outside.md"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        code, _, error = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("projections.codex", error)
        self.assertFalse((self.repo.parent / "outside.md").exists())

    def test_audit_reports_locations_not_secret_values(self) -> None:
        (self.repo / "config.yaml").write_text("api_key: should-not-be-returned\n", encoding="utf-8")
        (self.repo / "README.md").write_text(
            "Use `env:`, `config:`, or `secret://` references.\n", encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(self.repo), "init"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "config.yaml", "README.md"],
            check=True,
            capture_output=True,
        )
        result = audit_repository(self.repo)
        serialized = json.dumps(result)
        self.assertNotIn("should-not-be-returned", serialized)
        self.assertEqual(
            result["potentialSecretLocations"],
            [
                {
                    "path": "config.yaml",
                    "line": 1,
                    "reason": "secret-like key; value intentionally not displayed",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
