from __future__ import annotations

import copy
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.digests import canonical_json
from eco_runtime.errors import RuntimeStoreError
from eco_runtime.policy_bundle import policy_signature_message
from eco_runtime.team_authority import GENESIS_DIGEST, SQLiteTeamAuthority
from tests.m5_fixtures import (
    PROJECT_ID,
    b64url,
    envelope_bytes,
    policy_bundle,
    seal,
    trust_anchor,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
AUDIT_KEY = b"m5-team-authority-audit-key-v1!!"


def signed_envelope(bundle: dict, signer: Ed25519PrivateKey, envelope_id: str) -> bytes:
    document = json.loads(envelope_bytes(bundle, signer))
    document["envelopeId"] = envelope_id
    body = {key: value for key, value in document.items() if key != "signature"}
    document["signature"]["value"] = b64url(signer.sign(policy_signature_message(body)))
    return canonical_json(document).encode("utf-8")


class SQLiteTeamAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "team-authority.db"
        self.bundle, self.signer = policy_bundle()
        self.anchor = trust_anchor(self.signer)
        self.raw = signed_envelope(self.bundle, self.signer, "envelope-1")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self, **overrides) -> SQLiteTeamAuthority:
        arguments = {
            "hmac_key": AUDIT_KEY,
            "key_id": "audit-key-1",
            "trust_anchor": self.anchor,
            "project_id": PROJECT_ID,
            "store_id": "team-authority-1",
        }
        arguments.update(overrides)
        return SQLiteTeamAuthority(self.path, **arguments)

    def assert_code(self, code: str, operation) -> None:
        with self.assertRaises(RuntimeStoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def activate(self, store: SQLiteTeamAuthority, *, now: datetime = NOW) -> dict:
        snapshot = store.snapshot()
        return store.activate_policy(
            self.raw,
            activation_id="activation-1",
            expected_previous=(0, GENESIS_DIGEST),
            expected_snapshot_digest=snapshot["authoritySnapshotDigest"],
            now=now,
        )

    def revision_two(
        self, previous_digest: str, *, bundle_id: str = "team-policy-alpha", envelope_id: str = "envelope-2"
    ) -> bytes:
        candidate, _ = policy_bundle(self.signer, revision=2)
        candidate["metadata"]["id"] = bundle_id
        candidate["spec"]["previous"] = {"revision": 1, "digest": previous_digest}
        seal(candidate)
        return signed_envelope(candidate, self.signer, envelope_id)

    def test_activation_persists_epochs_snapshot_and_exact_replay(self) -> None:
        with self.store() as store:
            initial = store.snapshot()
            self.assertEqual(initial["activePolicy"]["revision"], 0)
            activated = self.activate(store)
            self.assertFalse(activated["replayed"])
            self.assertEqual(activated["epochs"], {
                "policy": 1, "identity": 1, "revocation": 0, "emergency": 0
            })
            self.assertNotEqual(activated["authoritySnapshotDigest"], initial["authoritySnapshotDigest"])
            replayed = self.activate(store)
            self.assertTrue(replayed["replayed"])
            store.verify()
            expected = store.snapshot()

        with self.store() as reopened:
            self.assertEqual(reopened.snapshot(), expected)
            reopened.assert_live(
                expected_snapshot_digest=expected["authoritySnapshotDigest"], now=NOW
            )

    def test_monotonic_predecessor_and_caller_cas_are_both_required(self) -> None:
        with self.store() as store:
            first = self.activate(store)
            raw_v2 = self.revision_two(first["activePolicy"]["digest"])
            second = store.activate_policy(
                raw_v2,
                activation_id="activation-2",
                expected_previous=(1, first["activePolicy"]["digest"]),
                expected_snapshot_digest=first["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=1),
            )
            self.assertEqual(second["activePolicy"]["revision"], 2)
            self.assertEqual(second["epochs"]["policy"], 2)
            # The identity catalog did not change merely because policy revision advanced.
            self.assertEqual(second["epochs"]["identity"], 1)

            self.assert_code(
                "ECO_TEAM_AUTHORITY_REVISION_CONFLICT",
                lambda: store.activate_policy(
                    self.revision_two("f" * 64, envelope_id="envelope-wrong"),
                    activation_id="activation-wrong",
                    expected_previous=(1, "f" * 64),
                    expected_snapshot_digest=second["authoritySnapshotDigest"],
                    now=NOW + timedelta(seconds=2),
                ),
            )

    def test_two_connections_cannot_activate_competing_revision(self) -> None:
        with self.store() as seed:
            first = self.activate(seed)
        raw_a = self.revision_two(
            first["activePolicy"]["digest"], bundle_id="team-policy-a", envelope_id="envelope-a"
        )
        raw_b = self.revision_two(
            first["activePolicy"]["digest"], bundle_id="team-policy-b", envelope_id="envelope-b"
        )
        one = self.store()
        two = self.store()
        barrier = threading.Barrier(2)
        results: list[str] = []
        lock = threading.Lock()

        def activate(store: SQLiteTeamAuthority, raw: bytes, identifier: str) -> None:
            barrier.wait()
            try:
                store.activate_policy(
                    raw,
                    activation_id=identifier,
                    expected_previous=(1, first["activePolicy"]["digest"]),
                    expected_snapshot_digest=first["authoritySnapshotDigest"],
                    now=NOW + timedelta(seconds=1),
                )
                result = "activated"
            except RuntimeStoreError as exc:
                result = exc.code
            with lock:
                results.append(result)

        threads = [
            threading.Thread(target=activate, args=(one, raw_a, "activation-a")),
            threading.Thread(target=activate, args=(two, raw_b, "activation-b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        one.close()
        two.close()
        self.assertEqual(
            sorted(results),
            ["ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT", "activated"],
        )
        with self.store() as verified:
            self.assertEqual(verified.snapshot()["activePolicy"]["revision"], 2)
            verified.verify()

    def test_exact_revocation_is_append_only_and_blocks_reintroduction(self) -> None:
        with self.store() as store:
            activated = self.activate(store)
            principal = json.loads(self.raw)["bundle"]["spec"]["documents"]["principals"][0]
            revoked = store.revoke(
                revocation_id="revocation-1",
                subject_kind="PrincipalIdentity",
                subject_id=principal["metadata"]["id"],
                subject_digest=principal["metadata"]["recordDigest"],
                reason_code="ECO_SECURITY_RESPONSE",
                expected_snapshot_digest=activated["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=1),
            )
            self.assertEqual(revoked["epochs"]["revocation"], 1)
            self.assertTrue(
                store.is_revoked(
                    subject_kind="PrincipalIdentity", subject_id=principal["metadata"]["id"]
                )
            )
            replay = store.revoke(
                revocation_id="revocation-1",
                subject_kind="PrincipalIdentity",
                subject_id=principal["metadata"]["id"],
                subject_digest=principal["metadata"]["recordDigest"],
                reason_code="ECO_SECURITY_RESPONSE",
                expected_snapshot_digest=activated["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=1),
            )
            self.assertTrue(replay["replayed"])
            raw_v2 = self.revision_two(revoked["activePolicy"]["digest"])
            self.assert_code(
                "ECO_TEAM_AUTHORITY_REVOKED_SUBJECT",
                lambda: store.activate_policy(
                    raw_v2,
                    activation_id="activation-2",
                    expected_previous=(1, revoked["activePolicy"]["digest"]),
                    expected_snapshot_digest=revoked["authoritySnapshotDigest"],
                    now=NOW + timedelta(seconds=2),
                ),
            )

    def test_activation_snapshot_cas_covers_non_policy_epoch_changes(self) -> None:
        with self.store() as store:
            active = self.activate(store)
            denied = store.set_emergency_deny(
                event_id="emergency-cas-1",
                enabled=True,
                reason_code="ECO_EMERGENCY_OPERATOR_DENY",
                expected_snapshot_digest=active["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=1),
            )
            raw_v2 = self.revision_two(active["activePolicy"]["digest"])
            self.assert_code(
                "ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT",
                lambda: store.activate_policy(
                    raw_v2,
                    activation_id="activation-stale-snapshot",
                    expected_previous=(1, active["activePolicy"]["digest"]),
                    expected_snapshot_digest=active["authoritySnapshotDigest"],
                    now=NOW + timedelta(seconds=2),
                ),
            )
            self.assertEqual(
                store.snapshot()["authoritySnapshotDigest"],
                denied["authoritySnapshotDigest"],
            )

    def test_emergency_deny_is_non_expiring_and_plain_disable_is_rejected(self) -> None:
        with self.store() as store:
            active = self.activate(store)
            denied = store.set_emergency_deny(
                event_id="emergency-enable-1",
                enabled=True,
                reason_code="ECO_EMERGENCY_OPERATOR_DENY",
                expected_snapshot_digest=active["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=1),
            )
            self.assertTrue(denied["emergencyDeny"])
            self.assertEqual(denied["epochs"]["emergency"], 1)
            self.assert_code(
                "ECO_TEAM_AUTHORITY_EMERGENCY_DENY",
                lambda: store.assert_live(
                    expected_snapshot_digest=denied["authoritySnapshotDigest"],
                    now=NOW + timedelta(days=1),
                ),
            )
            self.assert_code(
                "ECO_TEAM_AUTHORITY_RECOVERY_APPROVAL_REQUIRED",
                lambda: store.set_emergency_deny(
                    event_id="emergency-disable-1",
                    enabled=False,
                    reason_code="ECO_EMERGENCY_RECOVERY_COMPLETE",
                    expected_snapshot_digest=denied["authoritySnapshotDigest"],
                    now=NOW + timedelta(seconds=2),
                ),
            )
            unchanged = store.snapshot()
            self.assertTrue(unchanged["emergencyDeny"])
            self.assertEqual(
                unchanged["authoritySnapshotDigest"],
                denied["authoritySnapshotDigest"],
            )

    def test_stale_snapshot_and_clock_rollback_fail_without_state_change(self) -> None:
        with self.store() as store:
            active = self.activate(store)
            before = store.snapshot()
            self.assert_code(
                "ECO_TEAM_AUTHORITY_SNAPSHOT_CONFLICT",
                lambda: store.set_emergency_deny(
                    event_id="emergency-stale",
                    enabled=True,
                    reason_code="ECO_EMERGENCY_OPERATOR_DENY",
                    expected_snapshot_digest=GENESIS_DIGEST,
                    now=NOW + timedelta(seconds=1),
                ),
            )
            self.assert_code(
                "ECO_TEAM_AUTHORITY_CLOCK_ROLLBACK",
                lambda: store.revoke(
                    revocation_id="revocation-clock",
                    subject_kind="TeamIdentity",
                    subject_id=self.anchor.team_id,
                    subject_digest=json.loads(self.raw)["bundle"]["spec"]["documents"]["teams"][0]["metadata"]["recordDigest"],
                    reason_code="ECO_SECURITY_RESPONSE",
                    expected_snapshot_digest=active["authoritySnapshotDigest"],
                    now=NOW - timedelta(seconds=1),
                ),
            )
            self.assertEqual(store.snapshot(), before)

    def test_anchor_wrong_key_raw_envelope_and_projection_tamper_fail_reopen(self) -> None:
        with self.store() as store:
            self.activate(store)
        other_bundle, other_signer = policy_bundle()
        del other_bundle
        self.assert_code(
            "ECO_TEAM_AUTHORITY_CORRUPT",
            lambda: self.store(trust_anchor=trust_anchor(other_signer)),
        )

        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER policy_activations_immutable_update")
        connection.execute(
            "UPDATE policy_activations SET raw_envelope=? WHERE activation_id='activation-1'",
            (b"{}",),
        )
        connection.commit()
        connection.close()
        self.assert_code("ECO_TEAM_AUTHORITY_CORRUPT", lambda: self.store())

    def test_private_external_location_and_hardlink_are_rejected(self) -> None:
        governed = self.root / "project"
        governed.mkdir(mode=0o700)
        self.assert_code(
            "ECO_TEAM_AUTHORITY_LOCATION_DENIED",
            lambda: SQLiteTeamAuthority(
                governed / "authority.db",
                hmac_key=AUDIT_KEY,
                key_id="audit-key-1",
                trust_anchor=self.anchor,
                project_id=PROJECT_ID,
                forbidden_root=governed,
            ),
        )
        if os.name == "posix":
            with self.store():
                pass
            alias = self.root / "alias.db"
            os.link(self.path, alias)
            self.assert_code("ECO_TEAM_AUTHORITY_FILE_UNSAFE", lambda: self.store())


if __name__ == "__main__":
    unittest.main()
