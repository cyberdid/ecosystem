from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from eco_cli.cli import main
from eco_runtime.digests import canonical_json

from tests.m5_fixtures import (
    PROJECT_ID,
    TEAM_ID,
    b64url,
    envelope_bytes,
    policy_bundle,
    team_record,
    trust_anchor,
)

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


class AuthorityCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.external = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name).resolve()
        self.external_root = Path(self.external.name).resolve()
        self.bundle, self.signer = policy_bundle()
        self.envelope = self.repo / "policy-envelope.json"
        self.envelope.write_bytes(envelope_bytes(self.bundle, self.signer))
        self.record = self.repo / "team-record.json"
        self.record.write_bytes(canonical_json(team_record()).encode("utf-8"))
        anchor = trust_anchor(self.signer)
        public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        anchor_document = {
            "profile": "eco-team-policy-trust-anchor-v1",
            "teamId": TEAM_ID,
            "keyId": anchor.key_id,
            "publicKey": {"encoding": "raw-base64url", "value": b64url(public_key)},
            "allowedProjectIds": [PROJECT_ID],
            "validity": {
                "notBefore": "2026-07-01T00:00:00Z",
                "notAfter": "2026-09-01T00:00:00Z",
            },
        }
        self.anchor = self.external_root / "trust-anchor.json"
        self.anchor.write_bytes(canonical_json(anchor_document).encode("utf-8"))

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.external.cleanup()

    def run_cli(self, *arguments: str) -> tuple[int, dict, str]:
        stdout, stderr = StringIO(), StringIO()
        with (
            patch("eco_cli.authority.observed_at", return_value=NOW),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = main(["--repo", str(self.repo), *arguments, "--json"])
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def snapshot(self) -> dict[str, tuple[bytes, int]]:
        return {
            str(path): (path.read_bytes(), path.stat().st_mtime_ns)
            for root in (self.repo, self.external_root)
            for path in root.iterdir()
            if path.is_file()
        }

    def test_policy_verify_is_authenticated_but_never_activation_eligible(self) -> None:
        before = self.snapshot()
        with patch("eco_runtime.policy.PolicyEngine", side_effect=AssertionError("not allowed")):
            code, result, error = self.run_cli(
                "policy",
                "verify",
                "--envelope",
                str(self.envelope),
                "--trust-anchor",
                str(self.anchor),
                "--project",
                PROJECT_ID,
            )
        self.assertEqual(code, 0, error)
        self.assertTrue(result["available"])
        self.assertEqual(
            result["authenticity"], "relative-to-supplied-anchor"
        )
        self.assertEqual(result["trustBasis"], "caller-supplied-external-anchor")
        self.assertEqual(result["currentness"], "not-established")
        self.assertFalse(result["activationEligible"])
        self.assertFalse(result["safety"]["runtimeAuthorityCreated"])
        self.assertEqual(before, self.snapshot())

    def test_policy_and_identity_inspection_do_not_claim_authenticity(self) -> None:
        policy_record = self.repo / "policy-record.json"
        policy_record.write_bytes(canonical_json(self.bundle).encode("utf-8"))
        code, policy, error = self.run_cli(
            "policy", "inspect", "--record", str(policy_record)
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(policy["authenticity"], "not-established")
        self.assertFalse(policy["activationEligible"])

        code, identity, error = self.run_cli(
            "identity", "inspect", "--record", str(self.record)
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(identity["statusClaim"], "active")
        self.assertEqual(identity["currentness"], "not-established")
        self.assertFalse(identity["safety"]["permissionsGranted"])

    def test_project_controlled_anchor_is_rejected(self) -> None:
        local_anchor = self.repo / "trust-anchor.json"
        local_anchor.write_bytes(self.anchor.read_bytes())
        code, result, _ = self.run_cli(
            "policy",
            "verify",
            "--envelope",
            str(self.envelope),
            "--trust-anchor",
            str(local_anchor),
            "--project",
            PROJECT_ID,
        )
        self.assertEqual(code, 1)
        self.assertEqual(
            result["code"], "ECO_AUTHORITY_TRUST_ANCHOR_PROJECT_CONTROLLED"
        )

    def test_symlink_hardlink_and_noncanonical_json_fail_closed(self) -> None:
        symlink = self.repo / "symlink.json"
        try:
            symlink.symlink_to(self.record)
        except OSError:
            # Some Windows runners do not grant symlink creation to the test user.
            pass
        else:
            code, result, _ = self.run_cli(
                "identity", "inspect", "--record", str(symlink)
            )
            self.assertEqual(code, 1)
            self.assertEqual(result["code"], "ECO_AUTHORITY_INPUT_INVALID")

        hardlink = self.repo / "hardlink.json"
        os.link(self.record, hardlink)
        code, result, _ = self.run_cli(
            "identity", "inspect", "--record", str(self.record)
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "ECO_AUTHORITY_INPUT_INVALID")

        noncanonical = self.repo / "noncanonical.json"
        noncanonical.write_text(json.dumps(team_record(), indent=2), encoding="utf-8")
        code, result, _ = self.run_cli(
            "identity", "inspect", "--record", str(noncanonical)
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["code"], "ECO_AUTHORITY_INPUT_NONCANONICAL")

    def test_errors_are_sanitized_and_help_has_no_signer_surface(self) -> None:
        canary = "secret-private-key-canary"
        broken = self.repo / "broken.json"
        broken.write_text(f'{{"privateKey":"{canary}"}}', encoding="utf-8")
        code, result, error = self.run_cli(
            "identity", "inspect", "--record", str(broken)
        )
        self.assertEqual(code, 1)
        rendered = canonical_json(result) + error
        self.assertNotIn(canary, rendered)
        self.assertNotIn(str(broken), rendered)

        stdout = StringIO()
        with redirect_stdout(stdout), self.assertRaises(SystemExit):
            main(["policy", "--help"])
        help_text = stdout.getvalue()
        self.assertNotIn("private-key", help_text)
        self.assertNotIn("{verify,inspect,sign}", help_text.lower())
        self.assertNotIn("\n    sign ", help_text.lower())


if __name__ == "__main__":
    unittest.main()
