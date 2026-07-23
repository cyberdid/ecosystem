from __future__ import annotations

import copy
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from eco_runtime.errors import ContractValidationError
from eco_runtime.team_access import (
    evaluate_team_access,
    team_access_binding_id,
    team_access_contract_errors,
    team_access_policy_digest,
    validate_team_access_policy,
)

DIGEST_A, DIGEST_B, DIGEST_C = "a" * 64, "b" * 64, "c" * 64
NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


def principal() -> dict:
    return {"kind": "PrincipalIdentity", "id": "principal-alice", "digest": DIGEST_A}


def membership() -> dict:
    return {"kind": "MembershipBinding", "id": "membership-alice", "digest": DIGEST_B}


def repository_resource() -> dict:
    return {"kind": "repository-entry", "id": "readme", "digest": DIGEST_C}


def statement(*, identifier: str = "read-source", effect: str = "allow",
              action: str = "repository.read", action_class: str = "A1",
              resource: dict | None = None, environment_id: str = "development",
              data_classes: list[str] | None = None) -> dict:
    return {
        "id": identifier, "effect": effect, "action": action,
        "actionClass": action_class,
        "resource": copy.deepcopy(resource or repository_resource()),
        "constraints": {
            "projectId": "project-alpha", "environmentId": environment_id,
            "dataClasses": data_classes or ["D0", "D1"],
            "notBefore": "2026-07-16T00:00:00Z",
            "notAfter": "2026-07-17T00:00:00Z",
        },
        "approvalProfile": (
            {"kind": "ApprovalProfile", "id": "profile-writers", "digest": DIGEST_A}
            if action_class == "A2" and effect == "allow"
            else None
        ),
    }


def seal(document: dict) -> dict:
    document["metadata"]["recordDigest"] = team_access_policy_digest(document)
    return document


def policy() -> dict:
    actor, member, role_id = principal(), membership(), "reader"
    binding = {
        "id": team_access_binding_id(actor, member, role_id),
        "principal": actor, "membership": member, "roleId": role_id,
    }
    return seal({
        "apiVersion": "authority.ai.ecosystem/v1alpha1",
        "kind": "TeamAccessPolicy",
        "metadata": {"id": "access-project-alpha", "revision": 1,
                     "createdAt": "2026-07-16T00:00:00Z", "recordDigest": "0" * 64},
        "spec": {
            "profile": "bounded-team-access-v1", "defaultEffect": "deny",
            "roles": [{"id": role_id, "statements": [statement()]}],
            "bindings": [binding],
            "safety": {"maximumAllowActionClass": "A2", "d4AllowDenied": True,
                       "highImpactAllowDenied": True, "wildcardsAllowed": False,
                       "roleInheritanceAllowed": False,
                       "standaloneAuthorityCreated": False},
        },
    })


def request() -> dict:
    return {
        "principal": principal(), "membership": membership(),
        "action": "repository.read", "actionClass": "A1",
        "resource": repository_resource(), "projectId": "project-alpha",
        "environmentId": "development", "dataClass": "D1",
    }


class TeamAccessTests(unittest.TestCase):
    def test_contract_is_closed_and_digest_bound(self) -> None:
        document = policy()
        self.assertIs(validate_team_access_policy(document), document)
        unknown = copy.deepcopy(document)
        unknown["spec"]["roles"][0]["inherits"] = ["administrator"]
        errors = team_access_contract_errors(unknown)
        self.assertTrue(errors)
        self.assertNotIn("administrator", " ".join(errors))
        wildcard = copy.deepcopy(document)
        wildcard["spec"]["roles"][0]["statements"][0]["action"] = "*"
        seal(wildcard)
        self.assertTrue(team_access_contract_errors(wildcard))
        tampered = copy.deepcopy(document)
        tampered["spec"]["bindings"][0]["roleId"] = "other-role"
        self.assertTrue(team_access_contract_errors(tampered))

    def test_allow_is_immutable_sanitized_candidate_not_authority(self) -> None:
        decision = evaluate_team_access(policy(), request(), now=NOW)
        self.assertEqual((decision.team_effect, decision.code),
                         ("allow", "ECO_TEAM_ACCESS_ALLOW_CANDIDATE"))
        self.assertTrue(decision.narrowing_only)
        self.assertFalse(decision.effective_authorization)
        self.assertFalse(decision.runtime_authority_created)
        self.assertEqual(len(decision.matched_statement_digests), 1)
        self.assertNotIn("principal-alice", str(decision.as_dict()))
        self.assertNotIn("readme", str(decision.as_dict()))
        with self.assertRaises(FrozenInstanceError):
            decision.team_effect = "deny"

    def test_actor_and_membership_are_exactly_bound(self) -> None:
        for field in ("principal", "membership"):
            candidate = request()
            candidate[field]["digest"] = "f" * 64
            decision = evaluate_team_access(policy(), candidate, now=NOW)
            self.assertEqual((decision.team_effect, decision.code),
                             ("deny", "ECO_TEAM_ACCESS_ACTOR_UNBOUND"))

    def test_constraints_cannot_be_combined_across_statements(self) -> None:
        document = policy()
        document["spec"]["roles"][0]["statements"] = [
            statement(identifier="a-wrong-environment", environment_id="staging"),
            statement(identifier="b-other-action", action="code.execute", action_class="A2",
                      resource={"kind": "project", "id": "project-alpha", "digest": DIGEST_C}),
        ]
        seal(document)
        self.assertEqual(team_access_contract_errors(document), [])
        decision = evaluate_team_access(document, request(), now=NOW)
        self.assertEqual(decision.code, "ECO_TEAM_ACCESS_DEFAULT_DENY")

    def test_deny_precedence_is_global_across_assigned_statements(self) -> None:
        document = policy()
        document["spec"]["roles"][0]["statements"] = [
            statement(identifier="allow-read"),
            statement(identifier="deny-read", effect="deny"),
        ]
        seal(document)
        decision = evaluate_team_access(document, request(), now=NOW)
        self.assertEqual((decision.team_effect, decision.code),
                         ("deny", "ECO_TEAM_ACCESS_EXPLICIT_DENY"))
        self.assertEqual(len(decision.matched_statement_digests), 1)

    def test_d4_and_a3_a4_are_hard_denials(self) -> None:
        d4 = request()
        d4["dataClass"] = "D4"
        self.assertEqual(evaluate_team_access(policy(), d4, now=NOW).code,
                         "ECO_TEAM_ACCESS_D4_DENIED")
        for action, action_class, resource_kind in (
            ("external.write", "A3", "external-service"),
            ("production.change", "A4", "production-target"),
        ):
            high = request()
            high.update({"action": action, "actionClass": action_class,
                         "resource": {"kind": resource_kind, "id": "exact-target",
                                      "digest": DIGEST_C}})
            self.assertEqual(evaluate_team_access(policy(), high, now=NOW).code,
                             "ECO_TEAM_ACCESS_HIGH_IMPACT_DENIED")

    def test_policy_cannot_express_high_impact_or_d4_allow(self) -> None:
        high = policy()
        item = high["spec"]["roles"][0]["statements"][0]
        item.update({"action": "external.write", "actionClass": "A3",
                     "resource": {"kind": "external-service", "id": "exact-target",
                                  "digest": DIGEST_C}})
        seal(high)
        with self.assertRaises(ContractValidationError):
            validate_team_access_policy(high)
        d4 = policy()
        d4["spec"]["roles"][0]["statements"][0]["constraints"]["dataClasses"] = ["D4"]
        seal(d4)
        self.assertTrue(team_access_contract_errors(d4))

    def test_mismatch_time_and_malformed_requests_fail_closed(self) -> None:
        mismatched = request()
        mismatched["actionClass"] = "A0"
        self.assertEqual(evaluate_team_access(policy(), mismatched, now=NOW).code,
                         "ECO_TEAM_ACCESS_REQUEST_MISMATCH")
        expired = datetime(2026, 7, 17, tzinfo=timezone.utc)
        self.assertEqual(evaluate_team_access(policy(), request(), now=expired).code,
                         "ECO_TEAM_ACCESS_DEFAULT_DENY")
        malformed = request()
        malformed["secret"] = "do-not-echo"
        decision = evaluate_team_access(policy(), malformed, now=NOW)
        self.assertEqual(decision.code, "ECO_TEAM_ACCESS_REQUEST_INVALID")
        self.assertNotIn("do-not-echo", str(decision.as_dict()))


if __name__ == "__main__":
    unittest.main()
