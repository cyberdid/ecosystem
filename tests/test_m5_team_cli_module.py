from __future__ import annotations

import json
import io
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from eco_cli.errors import EcoError
from eco_cli.cli import main
from eco_cli.team import (
    activate_team_policy_file,
    doctor_team_authority,
    load_hmac_key_from_env,
    open_team_authority,
)
from eco_runtime.digests import canonical_json
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.team_authority import (
    GENESIS_DIGEST,
    TEAM_AUTHORITY_APPLICATION_ID,
    TEAM_AUTHORITY_SCHEMA_VERSION,
)
from tests.m5_fixtures import (
    PROJECT_ID,
    TEAM_ID,
    b64url,
    envelope_bytes,
    policy_bundle,
    trust_anchor,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
HMAC_KEY = b"m5-cli-module-hmac-key-32-bytes!"
HMAC_ENV = "ECO_TEAM_AUTHORITY_HMAC_HEX"


class TeamCliModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.project_temp = tempfile.TemporaryDirectory()
        self.external_temp = tempfile.TemporaryDirectory()
        self.project = Path(self.project_temp.name).resolve()
        self.external = Path(self.external_temp.name).resolve()
        self.database = self.external / "authority.db"
        self.environment = {HMAC_ENV: HMAC_KEY.hex()}
        self.bundle, self.signer = policy_bundle()
        self.envelope = self.project / "signed-policy-envelope.json"
        self.envelope.write_bytes(envelope_bytes(self.bundle, self.signer))

        anchor = trust_anchor(self.signer)
        public_key = self.signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.anchor = self.external / "trust-anchor.json"
        self.anchor.write_bytes(
            canonical_json(
                {
                    "profile": "eco-team-policy-trust-anchor-v1",
                    "teamId": TEAM_ID,
                    "keyId": anchor.key_id,
                    "publicKey": {
                        "encoding": "raw-base64url",
                        "value": b64url(public_key),
                    },
                    "allowedProjectIds": [PROJECT_ID],
                    "validity": {
                        "notBefore": "2026-07-01T00:00:00Z",
                        "notAfter": "2026-09-01T00:00:00Z",
                    },
                }
            ).encode("utf-8")
        )

    def tearDown(self) -> None:
        self.project_temp.cleanup()
        self.external_temp.cleanup()

    def open_arguments(self) -> dict:
        return {
            "database_path": self.database,
            "trust_anchor_path": self.anchor,
            "forbidden_root": self.project,
            "project_id": PROJECT_ID,
            "audit_key_id": "team-audit-key-1",
            "hmac_env": HMAC_ENV,
            "environ": self.environment,
            "store_id": "team-authority-cli-1",
        }

    def assert_eco_code(self, code: str, operation) -> None:
        with self.assertRaises(EcoError) as caught:
            operation()
        self.assertEqual(str(caught.exception), code)

    def assert_sanitized(self, result: dict) -> None:
        rendered = canonical_json(result)
        self.assertNotIn(self.environment[HMAC_ENV], rendered)
        self.assertNotIn(str(self.project), rendered)
        self.assertNotIn(str(self.external), rendered)
        self.assertNotIn(self.envelope.read_text(encoding="utf-8"), rendered)

    def initialize_authority(self) -> str:
        with open_team_authority(**self.open_arguments()) as authority:
            return authority.snapshot()["authoritySnapshotDigest"]

    def test_hmac_env_is_exact_hex_and_failures_never_echo_input(self) -> None:
        self.assertEqual(
            load_hmac_key_from_env(HMAC_ENV, environ=self.environment), HMAC_KEY
        )
        self.assert_eco_code(
            "ECO_TEAM_HMAC_MISSING",
            lambda: load_hmac_key_from_env(HMAC_ENV, environ={}),
        )
        secret_canary = "not-hex-secret-canary"
        with self.assertRaises(EcoError) as caught:
            load_hmac_key_from_env(HMAC_ENV, environ={HMAC_ENV: secret_canary})
        self.assertEqual(str(caught.exception), "ECO_TEAM_HMAC_INVALID")
        self.assertNotIn(secret_canary, str(caught.exception))
        self.assert_eco_code(
            "ECO_TEAM_HMAC_ENV_NAME_INVALID",
            lambda: load_hmac_key_from_env("not a valid name", environ={}),
        )

    def test_project_controlled_database_and_anchor_are_rejected(self) -> None:
        local_anchor = self.project / "anchor.json"
        local_anchor.write_bytes(self.anchor.read_bytes())
        arguments = self.open_arguments()
        arguments["trust_anchor_path"] = local_anchor
        self.assert_eco_code(
            "ECO_AUTHORITY_TRUST_ANCHOR_PROJECT_CONTROLLED",
            lambda: open_team_authority(**arguments),
        )

        arguments = self.open_arguments()
        arguments["database_path"] = self.project / "authority.db"
        self.assert_eco_code(
            "ECO_TEAM_AUTHORITY_PROJECT_CONTROLLED",
            lambda: open_team_authority(**arguments),
        )
        self.assertFalse((self.project / "authority.db").exists())

    def test_doctor_requires_existing_store_and_returns_sanitized_state(self) -> None:
        self.assert_eco_code(
            "ECO_TEAM_DATABASE_MISSING",
            lambda: doctor_team_authority(**self.open_arguments()),
        )
        with open_team_authority(**self.open_arguments()) as authority:
            expected = authority.snapshot()
        result = doctor_team_authority(**self.open_arguments())
        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["authoritySnapshotDigest"], expected["authoritySnapshotDigest"])
        self.assertEqual(result["activePolicy"]["revision"], 0)
        self.assertFalse(result["safety"]["repositoryMutation"])
        self.assert_sanitized(result)

    def test_activation_uses_exact_predecessor_and_returns_no_raw_material(self) -> None:
        genesis_snapshot = self.initialize_authority()
        result = activate_team_policy_file(
            envelope_path=self.envelope,
            activation_id="cli-activation-1",
            expected_previous=(0, GENESIS_DIGEST),
            expected_snapshot_digest=genesis_snapshot,
            now=NOW,
            **self.open_arguments(),
        )
        self.assertEqual(result["status"], "activated")
        self.assertEqual(result["activePolicy"]["revision"], 1)
        self.assertFalse(result["replayed"])
        self.assert_sanitized(result)

        replay = activate_team_policy_file(
            envelope_path=self.envelope,
            activation_id="cli-activation-1",
            expected_previous=(0, GENESIS_DIGEST),
            expected_snapshot_digest=genesis_snapshot,
            now=NOW,
            **self.open_arguments(),
        )
        self.assertTrue(replay["replayed"])
        self.assert_sanitized(replay)

    def test_activation_requires_a_preprovisioned_snapshot(self) -> None:
        self.assert_eco_code(
            "ECO_TEAM_DATABASE_MISSING",
            lambda: activate_team_policy_file(
                envelope_path=self.envelope,
                activation_id="cli-activation-without-store",
                expected_previous=(0, GENESIS_DIGEST),
                expected_snapshot_digest="f" * 64,
                now=NOW,
                **self.open_arguments(),
            ),
        )
        self.assertFalse(self.database.exists())

    def test_tampered_database_fails_doctor_with_sanitized_error(self) -> None:
        with open_team_authority(**self.open_arguments()):
            pass
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE authority_heads SET snapshot_digest=? WHERE singleton=1",
            ("f" * 64,),
        )
        connection.commit()
        connection.close()

        with self.assertRaises(RuntimeStoreError) as caught:
            doctor_team_authority(**self.open_arguments())
        self.assertEqual(caught.exception.code, "ECO_TEAM_AUTHORITY_CORRUPT")
        rendered = str(caught.exception)
        self.assertNotIn(str(self.database), rendered)
        self.assertNotIn(self.environment[HMAC_ENV], rendered)

    def test_tampered_signed_envelope_does_not_advance_authority(self) -> None:
        genesis_snapshot = self.initialize_authority()
        document = json.loads(self.envelope.read_bytes())
        document["bundle"]["metadata"]["id"] = "tampered-policy"
        self.envelope.write_bytes(canonical_json(document).encode("utf-8"))
        with self.assertRaises(RuntimeStoreError):
            activate_team_policy_file(
                envelope_path=self.envelope,
                activation_id="cli-activation-tampered",
                expected_previous=(0, GENESIS_DIGEST),
                expected_snapshot_digest=genesis_snapshot,
                now=NOW,
                **self.open_arguments(),
            )
        result = doctor_team_authority(**self.open_arguments())
        self.assertEqual(result["stateRevision"], 0)
        self.assertEqual(result["activePolicy"]["revision"], 0)

    def test_public_cli_wires_explicit_activation_and_doctor(self) -> None:
        genesis_snapshot = self.initialize_authority()
        base = [
            "--repo",
            str(self.project),
            "team",
            "activate",
            "--database",
            str(self.database),
            "--trust-anchor",
            str(self.anchor),
            "--project",
            PROJECT_ID,
            "--audit-key-id",
            "team-audit-key-1",
            "--hmac-env",
            HMAC_ENV,
            "--store-id",
            "team-authority-cli-1",
            "--envelope",
            str(self.envelope),
            "--activation-id",
            "cli-activation-public",
            "--expected-revision",
            "0",
            "--expected-digest",
            GENESIS_DIGEST,
            "--expected-snapshot-digest",
            genesis_snapshot,
            "--apply",
            "--json",
        ]
        output = io.StringIO()
        with patch.dict("os.environ", self.environment, clear=False), redirect_stdout(output):
            self.assertEqual(main(base), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "activated")
        self.assert_sanitized(result)

    def test_public_cli_sanitizes_non_sqlite_database_failures(self) -> None:
        canary = "non-sqlite-private-content-canary"
        self.database.write_text(canary, encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        arguments = [
            "--repo",
            str(self.project),
            "team",
            "doctor",
            "--database",
            str(self.database),
            "--trust-anchor",
            str(self.anchor),
            "--project",
            PROJECT_ID,
            "--audit-key-id",
            "team-audit-key-1",
            "--hmac-env",
            HMAC_ENV,
            "--store-id",
            "team-authority-cli-1",
            "--json",
        ]
        with (
            patch.dict("os.environ", self.environment, clear=False),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(main(arguments), 1)
        result = json.loads(stdout.getvalue())
        rendered = canonical_json(result) + stderr.getvalue()
        self.assertEqual(result["code"], "ECO_TEAM_AUTHORITY_CORRUPT")
        self.assertNotIn(canary, rendered)
        self.assertNotIn(str(self.database), rendered)
        self.assertNotIn(self.environment[HMAC_ENV], rendered)

        self.database.unlink()
        connection = sqlite3.connect(self.database)
        connection.execute(f"PRAGMA application_id={TEAM_AUTHORITY_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={TEAM_AUTHORITY_SCHEMA_VERSION}")
        connection.execute("CREATE TABLE store_meta (singleton INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO store_meta VALUES (1)")
        connection.commit()
        connection.close()
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict("os.environ", self.environment, clear=False),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(main(arguments), 1)
        malformed = json.loads(stdout.getvalue())
        rendered = canonical_json(malformed) + stderr.getvalue()
        self.assertEqual(malformed["code"], "ECO_TEAM_AUTHORITY_CORRUPT")
        self.assertNotIn(str(self.database), rendered)
        self.assertNotIn(self.environment[HMAC_ENV], rendered)


if __name__ == "__main__":
    unittest.main()
