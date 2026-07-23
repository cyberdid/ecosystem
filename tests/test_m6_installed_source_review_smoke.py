"""Standalone installed-wheel source-review smoke helper."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class InstalledSourceReviewSmokeTests(unittest.TestCase):
    def test_standalone_script_runs_five_roles_on_literal_loopback(self) -> None:
        repository = Path(__file__).parents[1]
        result = subprocess.run(
            [sys.executable, str(repository / "scripts" / "run_installed_source_review_smoke.py")],
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["provider"], "literal-loopback-scripted")
        self.assertFalse(report["externalNetwork"])
        self.assertEqual(report["roleCalls"], 5)
        self.assertEqual(report["routeConsumptionEntries"], 1)
        self.assertEqual(report["routeUsageEntries"], 5)
        self.assertGreater(report["controlPlaneFilesScanned"], 0)
        self.assertEqual(
            report["privateSentinel"], "absent-from-output-and-control-plane"
        )


if __name__ == "__main__":
    unittest.main()
