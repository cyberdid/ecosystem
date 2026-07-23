from __future__ import annotations

import copy
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_runtime.contracts import contract_errors, schema_bundle_digest, validate_record
from eco_runtime.errors import ContractValidationError
from eco_runtime.team_identity import (
    authority_contract_errors,
    authority_record_digest,
    authority_schema_bundle_digest,
    identity_key_fingerprint,
    identity_key_id,
    membership_binding_id,
    validate_authority_record,
)

from tests.m5_fixtures import (
    binding,
    key_record,
    membership_record,
    policy_bundle,
    principal_record,
    seal,
    team_record,
)


class TeamIdentityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.team = team_record()
        self.principal = principal_record()
        self.membership = membership_record(self.team, self.principal)
        self.key = key_record(self.team, self.public_key)
        self.bundle = policy_bundle(self.private_key)[0]

    def test_all_authority_records_validate_through_both_entry_points(self) -> None:
        for record in (
            self.team,
            self.principal,
            self.membership,
            self.key,
            self.bundle,
        ):
            with self.subTest(kind=record["kind"]):
                self.assertIs(validate_record(record), record)
                self.assertIs(validate_authority_record(record), record)
                self.assertEqual(contract_errors(record), [])

    def test_m4_schema_digest_is_unchanged_and_authority_has_separate_digest(self) -> None:
        self.assertEqual(
            schema_bundle_digest(),
            "d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d",
        )
        digest = authority_schema_bundle_digest()
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertNotEqual(digest, schema_bundle_digest())

    def test_record_digest_excludes_itself_and_binds_every_other_field(self) -> None:
        reloaded = copy.deepcopy(self.team)
        self.assertEqual(authority_record_digest(reloaded), self.team["metadata"]["recordDigest"])
        reloaded["spec"]["status"] = "suspended"
        self.assertNotEqual(authority_record_digest(reloaded), self.team["metadata"]["recordDigest"])
        self.assertIn("recordDigest", " ".join(authority_contract_errors(reloaded)))

    def test_ids_and_timestamps_are_canonical(self) -> None:
        cases = []
        uppercase = copy.deepcopy(self.team)
        uppercase["metadata"]["id"] = "Team-Alpha"
        cases.append(uppercase)
        unicode_alias = copy.deepcopy(self.team)
        unicode_alias["metadata"]["id"] = "team-é"
        cases.append(unicode_alias)
        offset_time = copy.deepcopy(self.team)
        offset_time["metadata"]["createdAt"] = "2026-07-16T15:00:00+03:00"
        offset_time = seal(offset_time)
        cases.append(offset_time)
        reversed_time = copy.deepcopy(self.team)
        reversed_time["spec"]["validity"]["notAfter"] = "2026-06-01T00:00:00Z"
        reversed_time = seal(reversed_time)
        cases.append(reversed_time)
        for record in cases:
            with self.subTest(record=record):
                self.assertTrue(authority_contract_errors(record))

    def test_controller_rules_are_closed_and_self_controller_is_denied(self) -> None:
        human = copy.deepcopy(self.principal)
        human["spec"]["controller"] = binding(self.team)
        seal(human)
        self.assertTrue(authority_contract_errors(human))

        service = principal_record(identifier="service-build", principal_type="service")
        self.assertEqual(authority_contract_errors(service), [])
        service["spec"]["controller"] = None
        seal(service)
        self.assertTrue(authority_contract_errors(service))

        self_controlled = principal_record(identifier="service-loop", principal_type="service")
        self_controlled["spec"]["controller"] = {
            "kind": "PrincipalIdentity",
            "id": "service-loop",
            "digest": "a" * 64,
        }
        seal(self_controlled)
        self.assertTrue(authority_contract_errors(self_controlled))

    def test_deterministic_membership_and_key_identifiers(self) -> None:
        self.assertEqual(
            self.membership["metadata"]["id"],
            membership_binding_id("team-alpha", "principal-alice"),
        )
        self.assertEqual(self.key["metadata"]["id"], identity_key_id(self.public_key))
        self.assertEqual(
            self.key["spec"]["fingerprint"]["digest"],
            identity_key_fingerprint(self.public_key),
        )
        wrong = copy.deepcopy(self.key)
        wrong["spec"]["fingerprint"]["digest"] = "a" * 64
        seal(wrong)
        self.assertTrue(authority_contract_errors(wrong))

    def test_bundle_cross_references_and_catalog_order_fail_closed(self) -> None:
        wrong_team = copy.deepcopy(self.bundle)
        wrong_team["spec"]["team"]["digest"] = "a" * 64
        seal(wrong_team)
        self.assertTrue(authority_contract_errors(wrong_team))

        duplicate = copy.deepcopy(self.bundle)
        duplicate["spec"]["documents"]["principals"].append(
            copy.deepcopy(duplicate["spec"]["documents"]["principals"][0])
        )
        seal(duplicate)
        self.assertTrue(authority_contract_errors(duplicate))

        missing_subject = copy.deepcopy(self.bundle)
        missing_subject["spec"]["documents"]["keys"][0]["spec"]["subject"]["digest"] = "b" * 64
        seal(missing_subject["spec"]["documents"]["keys"][0])
        seal(missing_subject)
        self.assertTrue(authority_contract_errors(missing_subject))

        malformed_nested = copy.deepcopy(self.bundle)
        malformed_nested["spec"]["documents"]["principals"].append({})
        seal(malformed_nested)
        errors = authority_contract_errors(malformed_nested)
        self.assertTrue(errors)
        self.assertTrue(all("Traceback" not in item for item in errors))

    def test_policy_revision_predecessor_shape_is_exact(self) -> None:
        revision_one = copy.deepcopy(self.bundle)
        revision_one["spec"]["previous"] = {"revision": 1, "digest": "a" * 64}
        seal(revision_one)
        self.assertTrue(authority_contract_errors(revision_one))

        revision_two = policy_bundle(self.private_key, revision=2)[0]
        self.assertEqual(authority_contract_errors(revision_two), [])
        revision_two["spec"]["previous"]["revision"] = 2
        seal(revision_two)
        self.assertTrue(authority_contract_errors(revision_two))

    def test_active_dependents_require_active_containing_controller_and_subject(self) -> None:
        inactive_controller = copy.deepcopy(self.bundle)
        inactive_controller["spec"]["documents"]["principals"][0]["spec"][
            "type"
        ] = "service"
        inactive_controller["spec"]["documents"]["principals"][0]["spec"][
            "controller"
        ] = binding(inactive_controller["spec"]["documents"]["teams"][0])
        inactive_controller["spec"]["documents"]["teams"][0]["spec"][
            "status"
        ] = "suspended"
        seal(inactive_controller["spec"]["documents"]["teams"][0])
        principal = inactive_controller["spec"]["documents"]["principals"][0]
        principal["spec"]["controller"] = binding(
            inactive_controller["spec"]["documents"]["teams"][0]
        )
        seal(principal)
        membership = inactive_controller["spec"]["documents"]["memberships"][0]
        membership["spec"]["team"] = binding(
            inactive_controller["spec"]["documents"]["teams"][0]
        )
        membership["spec"]["principal"] = binding(principal)
        seal(membership)
        key = inactive_controller["spec"]["documents"]["keys"][0]
        key["spec"]["subject"] = binding(
            inactive_controller["spec"]["documents"]["teams"][0]
        )
        seal(key)
        inactive_controller["spec"]["team"] = binding(
            inactive_controller["spec"]["documents"]["teams"][0]
        )
        seal(inactive_controller)
        self.assertTrue(authority_contract_errors(inactive_controller))

        inactive_key_subject = copy.deepcopy(self.bundle)
        principal = inactive_key_subject["spec"]["documents"]["principals"][0]
        principal["spec"]["status"] = "suspended"
        seal(principal)
        key = inactive_key_subject["spec"]["documents"]["keys"][0]
        key["spec"]["purpose"] = "approval-signing"
        key["spec"]["subject"] = binding(principal)
        seal(key)
        inactive_key_subject["spec"]["documents"]["memberships"] = []
        seal(inactive_key_subject)
        self.assertTrue(authority_contract_errors(inactive_key_subject))

    def test_unknown_fields_and_authorizing_safety_flags_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.team)
        unknown["secret"] = "must-not-echo"
        errors = authority_contract_errors(unknown)
        self.assertTrue(errors)
        self.assertNotIn("must-not-echo", " ".join(errors))

        authority = copy.deepcopy(self.team)
        authority["spec"]["safety"]["permissionsGranted"] = True
        seal(authority)
        with self.assertRaises(ContractValidationError):
            validate_authority_record(authority)


if __name__ == "__main__":
    unittest.main()
