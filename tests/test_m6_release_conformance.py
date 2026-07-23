"""Local deterministic M6 release-conformance entrypoint."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


class M6ReleaseConformanceTests(unittest.TestCase):
    def test_journal_secret_and_repository_identity_conformance(self) -> None:
        repository = Path(__file__).parents[1]
        result = subprocess.run(
            [
                sys.executable,
                str(repository / "scripts" / "check_m6_release_conformance.py"),
                "--repo",
                str(repository),
            ],
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["secretSentinel"], "absent")
        self.assertEqual(
            report["privateContentSentinel"],
            "absent-from-journals-and-cli-output",
        )
        self.assertEqual(report["repositoryIdentity"], "bytes-and-mtime-unchanged")
        self.assertEqual(report["deterministicCli"], "wiki-health-check-loop-valid")
        self.assertEqual(report["consumptionEntries"], 1)
        self.assertEqual(report["usageEntries"], 1)
        self.assertGreater(report["trackedFiles"], 0)
        self.assertGreaterEqual(report["journalFiles"], 2)


if __name__ == "__main__":
    unittest.main()
