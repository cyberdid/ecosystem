from __future__ import annotations

import base64
import copy
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eco_cli.templates import starter_bundle
from eco_runtime.digests import semantic_digest
from eco_runtime.errors import RuntimePolicyError, RuntimeStoreError
from eco_runtime.policy import PolicyEngine
from eco_runtime.policy_bundle import PolicyTrustAnchor
from eco_runtime.store import SQLiteRuntimeStore
from eco_runtime.team_actor import (
    actor_assertion_message,
    recovery_actor_operation_digest,
    runtime_actor_operation_digest,
)
from eco_runtime.team_approval import approval_record_digest, approval_vote_message
from eco_runtime.team_authority import (
    GENESIS_DIGEST,
    SQLiteTeamAuthority,
    emergency_recovery_action_digest,
    emergency_recovery_resource_digest,
)
from eco_runtime.team_identity import identity_key_id
from eco_runtime.team_migration import rotate_authority_generation
from eco_runtime.team_runtime import (
    DurableRuntimeDecisionAuthority,
    PolicyEngineRuntimeDecisionAuthority,
    TeamAuthorizationGate,
    team_action_binding_digest,
    team_resource_binding_digest,
)
from tests.m5_fixtures import (
    PROJECT_ID,
    bounded_policy_bundle,
    envelope_bytes,
    trust_anchor,
)
from tests.test_m5_team_rotation import new_anchor, rotation_bytes


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
SUBJECT_DIGEST = "e" * 64
AUDIT_KEY = b"m5-integrated-authority-audit-key!"


def runtime_subject(*, tool_id: str = "repository.read") -> dict:
    return {
        "apiVersion": "runtime.ai.ecosystem/v1alpha1",
        "kind": "ToolRequest",
        "metadata": {
            "id": "operation-1",
            "runId": "run-1",
            "createdAt": "2026-07-16T12:00:00Z",
            "source": "runtime",
        },
        "spec": {
            "planDigest": "f" * 64,
            "toolId": tool_id,
            "arguments": {},
        },
    }


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class TeamRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "authority.db"
        self.subject = runtime_subject()
        self.write_subject = runtime_subject(tool_id="repository.write")
        subject_digest = semantic_digest(self.subject)
        write_subject_digest = semantic_digest(self.write_subject)
        (
            self.bundle,
            self.policy_signer,
            self.approval_signers,
            self.actor_signers,
        ) = bounded_policy_bundle(
            runtime_subject_digest=subject_digest,
            runtime_write_subject_digest=write_subject_digest,
        )
        self.raw = envelope_bytes(self.bundle, self.policy_signer)
        self.store = SQLiteTeamAuthority(
            self.path,
            hmac_key=AUDIT_KEY,
            key_id="audit-key-1",
            trust_anchor=trust_anchor(self.policy_signer),
            project_id=PROJECT_ID,
            store_id="team-authority-1",
        )
        genesis_snapshot = self.store.snapshot()["authoritySnapshotDigest"]
        self.active = self.store.activate_policy(
            self.raw,
            activation_id="activation-1",
            expected_previous=(0, GENESIS_DIGEST),
            expected_snapshot_digest=genesis_snapshot,
            now=NOW,
        )
        self.engine = PolicyEngine(starter_bundle("sample"), {})
        self.allow = self.engine._decision(
            decision_id="runtime-allow",
            run_id="run-1",
            now=NOW,
            subject_kind="ToolRequest",
            subject_id="operation-1",
            subject_digest=subject_digest,
            effect="allow",
            reason_codes=["ECO_TOOL_ALLOWED"],
        )
        self.deny = self.engine._decision(
            decision_id="runtime-deny",
            run_id="run-1",
            now=NOW,
            subject_kind="ToolRequest",
            subject_id="operation-1",
            subject_digest=subject_digest,
            effect="deny",
            reason_codes=["ECO_TOOL_DENIED"],
        )
        self.write_allow = self.engine._decision(
            decision_id="runtime-write-allow",
            run_id="run-1",
            now=NOW,
            subject_kind="ToolRequest",
            subject_id="operation-1",
            subject_digest=write_subject_digest,
            effect="allow",
            reason_codes=["ECO_TOOL_ALLOWED"],
        )
        self.gate = TeamAuthorizationGate(
            self.store, PolicyEngineRuntimeDecisionAuthority(self.engine)
        )
        documents = self.bundle["spec"]["documents"]
        self.principals = {
            item["metadata"]["id"]: item for item in documents["principals"]
        }
        self.memberships = {
            item["spec"]["principal"]["id"]: item
            for item in documents["memberships"]
        }

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def team_request(self, *, action: str, action_class: str) -> dict:
        return {
            "principal": {
                "kind": "PrincipalIdentity",
                "id": "requester-1",
                "digest": self.principals["requester-1"]["metadata"][
                    "recordDigest"
                ],
            },
            "membership": {
                "kind": "MembershipBinding",
                "id": self.memberships["requester-1"]["metadata"]["id"],
                "digest": self.memberships["requester-1"]["metadata"][
                    "recordDigest"
                ],
            },
            "action": action,
            "actionClass": action_class,
            "resource": {
                "kind": "repository-entry",
                "id": "operation-1",
                "digest": semantic_digest(
                    self.write_subject
                    if action == "repository.write"
                    else self.subject
                ),
            },
            "projectId": PROJECT_ID,
            "environmentId": "development",
            "dataClass": "D1",
        }

    def rotation_material(
        self, seed: bytes = b"q"
    ) -> tuple[PolicyTrustAnchor, bytes, bytes]:
        signer = Ed25519PrivateKey.from_private_bytes(seed * 32)
        anchor = new_anchor(signer)
        bundle, _, _, _ = bounded_policy_bundle(
            runtime_subject_digest=SUBJECT_DIGEST,
            policy_signer=signer,
        )
        return (
            anchor,
            envelope_bytes(bundle, signer),
            rotation_bytes(
                self.policy_signer,
                signer,
                trust_anchor(self.policy_signer),
                anchor,
            ),
        )

    def actor_assertion(
        self,
        *,
        principal_id: str,
        audience: str,
        operation_digest: str,
        snapshot_digest: str,
        nonce_seed: str = "actor-nonce-1",
        issued_at: str = "2026-07-16T12:00:00Z",
        expires_at: str = "2026-07-16T12:05:00Z",
    ) -> dict:
        signer = self.actor_signers[principal_id]
        public_key = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        principal = self.principals[principal_id]
        membership = self.memberships[principal_id]
        record = {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "AuthenticatedActorAssertion",
            "spec": {
                "team": copy.deepcopy(self.bundle["spec"]["team"]),
                "projectId": PROJECT_ID,
                "principal": {
                    "kind": "PrincipalIdentity",
                    "id": principal_id,
                    "digest": principal["metadata"]["recordDigest"],
                },
                "membership": {
                    "kind": "MembershipBinding",
                    "id": membership["metadata"]["id"],
                    "digest": membership["metadata"]["recordDigest"],
                },
                "keyId": identity_key_id(public_key),
                "audience": audience,
                "operationDigest": operation_digest,
                "authoritySnapshotDigest": snapshot_digest,
                "nonceDigest": semantic_digest(nonce_seed),
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "signature": {"algorithm": "Ed25519", "value": "A" * 86},
            },
        }
        record["spec"]["signature"]["value"] = _b64url(
            signer.sign(actor_assertion_message(record))
        )
        return record

    def runtime_actor_assertion(
        self, team_request: dict, *, decision: dict | None = None,
        subject: dict | None = None,
    ) -> dict:
        is_write = team_request.get("action") == "repository.write"
        selected_decision = decision or (
            self.write_allow if is_write else self.allow
        )
        selected_subject = subject or (
            self.write_subject if is_write else self.subject
        )
        return self.actor_assertion(
            principal_id="requester-1",
            audience="runtime-effect",
            operation_digest=runtime_actor_operation_digest(
                selected_decision, selected_subject, team_request
            ),
            snapshot_digest=self.store.snapshot()["authoritySnapshotDigest"],
        )

    def approval_request(self, team_request: dict) -> tuple[dict, dict]:
        profile = copy.deepcopy(
            next(
                item
                for item in self.bundle["spec"]["documents"]["approvalProfiles"]
                if item["spec"]["purpose"] == "runtime-action"
            )
        )
        record = {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "TeamApprovalRequest",
            "metadata": {
                "id": "request-write-1",
                "createdAt": "2026-07-16T12:00:30Z",
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": {
                    "kind": "ApprovalProfile",
                    "id": profile["metadata"]["id"],
                    "digest": profile["metadata"]["recordDigest"],
                },
                "requester": {
                    "principalId": "requester-1",
                    "membershipDigest": self.memberships["requester-1"][
                        "metadata"
                    ]["recordDigest"],
                },
                "action": {
                    "capability": "workspace.write",
                    "actionClass": "A2",
                    "operation": "repository.replace",
                    "digest": team_action_binding_digest(team_request),
                },
                "resource": {
                    "kind": "TeamAccessResource",
                    "id": "operation-1",
                    "digest": team_resource_binding_digest(team_request),
                },
                "snapshot": {
                    "kind": "AuthoritySnapshot",
                    "id": self.store.store_id,
                    "digest": self.active["authoritySnapshotDigest"],
                },
                "policy": copy.deepcopy(profile["spec"]["policy"]),
                "expiresAt": "2026-07-16T12:10:00Z",
                "safety": {
                    "humanApprovalRequired": True,
                    "permissionsGranted": False,
                },
            },
        }
        record["metadata"]["recordDigest"] = approval_record_digest(record)
        return profile, record

    def vote(self, profile: dict, request: dict, principal_id: str) -> dict:
        signer = self.approval_signers[principal_id]
        public_key = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        vote = {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "TeamApprovalVote",
            "metadata": {
                "id": f"vote-{principal_id}",
                "createdAt": "2026-07-16T12:01:00Z",
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": {
                    "kind": "ApprovalProfile",
                    "id": profile["metadata"]["id"],
                    "digest": profile["metadata"]["recordDigest"],
                },
                "request": {
                    "kind": "TeamApprovalRequest",
                    "id": request["metadata"]["id"],
                    "digest": request["metadata"]["recordDigest"],
                },
                "approver": {
                    "principalId": principal_id,
                    "keyId": identity_key_id(public_key),
                    "membershipDigest": self.memberships[principal_id]["metadata"][
                        "recordDigest"
                    ],
                },
                "decision": "approve",
                "issuedAt": "2026-07-16T12:01:00Z",
                "expiresAt": "2026-07-16T12:06:00Z",
                "signature": {"algorithm": "Ed25519", "value": "A" * 86},
            },
        }
        vote["spec"]["signature"]["value"] = _b64url(
            signer.sign(approval_vote_message(vote))
        )
        vote["metadata"]["recordDigest"] = approval_record_digest(vote)
        return vote

    def issued_permit(self, team_request: dict):
        profile, request = self.approval_request(team_request)
        votes = [
            self.vote(profile, request, principal)
            for principal in ("approver-1", "approver-2")
        ]
        return self.store.issue_team_action_permit(
            profile,
            request,
            votes,
            permit_id="permit-write-1",
            consumption_nonce=b"n" * 32,
            expected_requester_principal_id="requester-1",
            expected_requester_membership_digest=self.memberships["requester-1"][
                "metadata"
            ]["recordDigest"],
            now=datetime(2026, 7, 16, 12, 2, tzinfo=timezone.utc),
        )

    def recovery_request(self, denied: dict) -> tuple[dict, dict]:
        profile = copy.deepcopy(
            next(
                item
                for item in self.bundle["spec"]["documents"]["approvalProfiles"]
                if item["spec"]["purpose"] == "emergency-recovery"
            )
        )
        record = {
            "apiVersion": "authority.ai.ecosystem/v1alpha1",
            "kind": "TeamApprovalRequest",
            "metadata": {
                "id": "request-recovery-1",
                "createdAt": "2026-07-16T12:00:20Z",
                "recordDigest": "0" * 64,
            },
            "spec": {
                "profile": {
                    "kind": "ApprovalProfile",
                    "id": profile["metadata"]["id"],
                    "digest": profile["metadata"]["recordDigest"],
                },
                "requester": {
                    "principalId": "requester-1",
                    "membershipDigest": self.memberships["requester-1"][
                        "metadata"
                    ]["recordDigest"],
                },
                "action": {
                    "capability": "authority.emergency",
                    "actionClass": "A2",
                    "operation": "emergency.disable",
                    "digest": emergency_recovery_action_digest(
                        store_id=self.store.store_id,
                        authority_snapshot_digest=denied[
                            "authoritySnapshotDigest"
                        ],
                    ),
                },
                "resource": {
                    "kind": "AuthorityEmergencyState",
                    "id": self.store.store_id,
                    "digest": emergency_recovery_resource_digest(
                        store_id=self.store.store_id,
                        emergency_head_digest=denied["emergencyHeadDigest"],
                        emergency_epoch=denied["epochs"]["emergency"],
                    ),
                },
                "snapshot": {
                    "kind": "AuthoritySnapshot",
                    "id": self.store.store_id,
                    "digest": denied["authoritySnapshotDigest"],
                },
                "policy": copy.deepcopy(profile["spec"]["policy"]),
                "expiresAt": "2026-07-16T12:10:00Z",
                "safety": {
                    "humanApprovalRequired": True,
                    "permissionsGranted": False,
                },
            },
        }
        record["metadata"]["recordDigest"] = approval_record_digest(record)
        return profile, record

    def test_signed_bundle_active_actor_and_runtime_intersection(self) -> None:
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        allowed = self.gate.authorize(
            self.allow,
            self.subject,
            request,
            now=NOW,
            actor_assertion=self.runtime_actor_assertion(request),
        )
        self.assertEqual((allowed.effect, allowed.code), (
            "allow", "ECO_TEAM_AUTHORIZATION_ALLOWED"
        ))
        self.assertTrue(allowed.effective_authorization)

        denied = self.gate.authorize(
            self.deny,
            self.subject,
            request,
            now=NOW,
            actor_assertion=self.runtime_actor_assertion(
                request, decision=self.deny
            ),
        )
        self.assertEqual(denied.code, "ECO_TEAM_RUNTIME_POLICY_DENIED")
        forged = copy.deepcopy(request)
        forged["principal"]["digest"] = "f" * 64
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                self.subject,
                forged,
                now=NOW,
                actor_assertion=self.runtime_actor_assertion(request),
            ).effect,
            "deny",
        )

    def test_noop_runtime_authority_and_catalog_labels_are_not_authority(self) -> None:
        with self.assertRaises(TypeError):
            TeamAuthorizationGate(self.store, object())
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        decision = self.gate.authorize(
            self.allow,
            self.subject,
            request,
            now=NOW,
            actor_assertion={},
        )
        self.assertEqual(decision.effect, "deny")
        self.assertFalse(decision.effective_authorization)

    def test_actor_assertion_is_exact_signed_unexpired_and_not_substitutable(self) -> None:
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        expired = self.runtime_actor_assertion(request)
        expired["spec"]["expiresAt"] = "2026-07-16T12:00:30Z"
        expired["spec"]["signature"]["value"] = _b64url(
            self.actor_signers["requester-1"].sign(
                actor_assertion_message(expired)
            )
        )
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                self.subject,
                request,
                now=datetime(2026, 7, 16, 12, 1, tzinfo=timezone.utc),
                actor_assertion=expired,
            ).effect,
            "deny",
        )
        substituted = self.runtime_actor_assertion(request)
        substituted["spec"]["nonceDigest"] = semantic_digest("other-nonce")
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                self.subject,
                request,
                now=NOW,
                actor_assertion=substituted,
            ).effect,
            "deny",
        )

    def test_runtime_subject_action_and_resource_substitution_is_denied(self) -> None:
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        substituted_subject = copy.deepcopy(self.subject)
        substituted_subject["spec"]["toolId"] = "repository.write"
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                substituted_subject,
                request,
                now=NOW,
                actor_assertion=self.runtime_actor_assertion(request),
            ).effect,
            "deny",
        )
        substituted_request = copy.deepcopy(request)
        substituted_request["action"] = "model.invoke"
        substituted_request["actionClass"] = "A0"
        substituted_request["resource"]["kind"] = "deployment"
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                self.subject,
                substituted_request,
                now=NOW,
                actor_assertion=self.runtime_actor_assertion(request),
            ).effect,
            "deny",
        )

    def test_runtime_decision_replay_and_concurrency_execute_at_most_once(self) -> None:
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        assertion = self.runtime_actor_assertion(request)
        observed: list[str] = []
        self.gate.execute_authorized(
            self.allow,
            self.subject,
            request,
            now=NOW,
            actor_assertion=assertion,
            operation=lambda: observed.append("first"),
        )
        with self.assertRaises(RuntimePolicyError):
            self.gate.execute_authorized(
                self.allow,
                self.subject,
                request,
                now=NOW,
                actor_assertion=assertion,
                operation=lambda: observed.append("replay"),
            )
        self.assertEqual(observed, ["first"])

        # The signed team policy is exact, so use the original exact subject for
        # concurrency and a fresh engine/gate instance instead of broadening it.
        fresh_engine = PolicyEngine(starter_bundle("sample"), {})
        fresh_decision = fresh_engine._decision(
            decision_id="runtime-concurrent-exact",
            run_id="run-1",
            now=NOW,
            subject_kind="ToolRequest",
            subject_id="operation-1",
            subject_digest=semantic_digest(self.subject),
            effect="allow",
            reason_codes=["ECO_TOOL_ALLOWED"],
        )
        fresh_gate = TeamAuthorizationGate(
            self.store, PolicyEngineRuntimeDecisionAuthority(fresh_engine)
        )
        fresh_assertion = self.actor_assertion(
            principal_id="requester-1",
            audience="runtime-effect",
            operation_digest=runtime_actor_operation_digest(
                fresh_decision, self.subject, request
            ),
            snapshot_digest=self.store.snapshot()["authoritySnapshotDigest"],
            nonce_seed="concurrent-actor",
        )
        effects: list[str] = []
        failures: list[Exception] = []

        def worker() -> None:
            try:
                fresh_gate.execute_authorized(
                    fresh_decision,
                    self.subject,
                    request,
                    now=NOW,
                    actor_assertion=fresh_assertion,
                    operation=lambda: effects.append("effect"),
                )
            except Exception as exc:  # expected loser of the single-use race
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(effects, ["effect"])
        self.assertEqual(len(failures), 1)

    def test_runtime_claim_failure_does_not_consume_team_permit(self) -> None:
        request = self.team_request(
            action="repository.write", action_class="A2"
        )
        permit = self.issued_permit(request)
        with patch.object(
            PolicyEngineRuntimeDecisionAuthority,
            "claim_runtime_decision",
            side_effect=RuntimePolicyError(
                "ECO_DECISION_UNTRUSTED", "Decision claim rejected"
            ),
        ):
            with self.assertRaises(RuntimePolicyError):
                self.gate.execute_authorized(
                    self.write_allow,
                    self.write_subject,
                    request,
                    permit=permit,
                    now=datetime(2026, 7, 16, 12, 2, 1, tzinfo=timezone.utc),
                    actor_assertion=self.runtime_actor_assertion(request),
                    operation=lambda: self.fail("effect must not run"),
                )
        count = self.store._connection.execute(
            "SELECT COUNT(*) FROM permit_consumptions"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_durable_runtime_claim_survives_reopen_and_rejects_replay(self) -> None:
        runtime_path = Path(self.temp.name) / "runtime.db"
        capabilities = {
            "policy": object(),
            "broker": object(),
            "runtime": object(),
            "adapter": object(),
        }
        issuers = {
            "policy": "policy-engine",
            "broker": "repository-broker",
            "runtime": "runtime",
            "adapter": "adapter",
        }
        config_digest = self.allow["spec"]["policySnapshot"][
            "semanticConfigDigest"
        ]
        runtime_key = b"m5-durable-runtime-claim-key-32!"
        runtime_store = SQLiteRuntimeStore(
            runtime_path,
            hmac_key=runtime_key,
            key_id="runtime-key-1",
            policy_capability=capabilities["policy"],
            broker_capability=capabilities["broker"],
            runtime_capability=capabilities["runtime"],
            adapter_capability=capabilities["adapter"],
            producer_issuers=issuers,
        )
        try:
            runtime_store.issue_decision(
                self.allow,
                semantic_config_digest=config_digest,
                policy_capability=capabilities["policy"],
            )
            durable = DurableRuntimeDecisionAuthority(
                self.engine,
                runtime_store,
                semantic_config_digest=config_digest,
                policy_capability=capabilities["policy"],
            )
            gate = TeamAuthorizationGate(self.store, durable)
            request = self.team_request(
                action="repository.read", action_class="A1"
            )
            assertion = self.runtime_actor_assertion(request)
            observed: list[str] = []
            gate.execute_authorized(
                self.allow,
                self.subject,
                request,
                now=NOW,
                actor_assertion=assertion,
                operation=lambda: observed.append("effect"),
            )
            self.assertEqual(observed, ["effect"])
        finally:
            runtime_store.close()
        with SQLiteRuntimeStore(
            runtime_path,
            hmac_key=runtime_key,
            key_id="runtime-key-1",
            policy_capability=capabilities["policy"],
            broker_capability=capabilities["broker"],
            runtime_capability=capabilities["runtime"],
            adapter_capability=capabilities["adapter"],
            producer_issuers=issuers,
        ) as reopened:
            with self.assertRaises(RuntimeStoreError) as replayed:
                reopened.assert_decision_current(
                    self.allow,
                    self.subject,
                    now=NOW,
                    semantic_config_digest=config_digest,
                    policy_capability=capabilities["policy"],
                )
            self.assertEqual(replayed.exception.code, "ECO_DECISION_REPLAYED")

    def test_snapshot_race_after_runtime_claim_burns_decision_without_effect(self) -> None:
        request = self.team_request(
            action="repository.read", action_class="A1"
        )
        assertion = self.runtime_actor_assertion(request)
        original = PolicyEngineRuntimeDecisionAuthority.claim_runtime_decision

        def race(adapter, decision, subject, *, nonce, now):
            receipt = original(
                adapter, decision, subject, nonce=nonce, now=now
            )
            snapshot = self.store.snapshot()["authoritySnapshotDigest"]
            self.store.set_emergency_deny(
                event_id="emergency-runtime-race",
                enabled=True,
                reason_code="ECO_EMERGENCY_OPERATOR_DENY",
                expected_snapshot_digest=snapshot,
                now=now,
            )
            return receipt

        observed: list[str] = []
        with patch.object(
            PolicyEngineRuntimeDecisionAuthority,
            "claim_runtime_decision",
            autospec=True,
            side_effect=race,
        ):
            with self.assertRaises(RuntimeStoreError):
                self.gate.execute_authorized(
                    self.allow,
                    self.subject,
                    request,
                    now=NOW,
                    actor_assertion=assertion,
                    operation=lambda: observed.append("effect"),
                )
        self.assertEqual(observed, [])

    def test_quorum_permit_is_authority_issued_single_use_and_effect_guarded(self) -> None:
        request = self.team_request(
            action="repository.write", action_class="A2"
        )
        self.assertEqual(
            self.gate.authorize(
                self.write_allow,
                self.write_subject,
                request,
                now=NOW,
                actor_assertion=self.runtime_actor_assertion(request),
            ).code,
            "ECO_TEAM_APPROVAL_REQUIRED",
        )
        permit = self.issued_permit(request)
        observed: list[str] = []
        effect = self.gate.execute_authorized(
            self.write_allow,
            self.write_subject,
            request,
            permit=permit,
            now=datetime(2026, 7, 16, 12, 2, 1, tzinfo=timezone.utc),
            actor_assertion=self.runtime_actor_assertion(request),
            operation=lambda: observed.append("effect") or "receipt",
        )
        self.assertEqual(effect.result, "receipt")
        self.assertEqual(observed, ["effect"])
        self.assertIsNotNone(effect.permit_consumption)
        with self.assertRaises(RuntimePolicyError):
            self.gate.execute_authorized(
                self.write_allow,
                self.write_subject,
                request,
                permit=permit,
                now=datetime(2026, 7, 16, 12, 2, 2, tzinfo=timezone.utc),
                actor_assertion=self.runtime_actor_assertion(request),
                operation=lambda: observed.append("replayed"),
            )
        self.assertEqual(observed, ["effect"])

    def test_live_hmac_tamper_is_rejected_without_reopen(self) -> None:
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE authority_heads SET emergency_deny=1 WHERE singleton=1"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(RuntimeStoreError) as caught:
            self.store.snapshot()
        self.assertEqual(caught.exception.code, "ECO_TEAM_AUTHORITY_CORRUPT")

    def test_live_revocation_deletion_tamper_is_rejected_without_reopen(self) -> None:
        principal = self.principals["requester-1"]
        self.store.revoke(
            revocation_id="revocation-live-tamper",
            subject_kind="PrincipalIdentity",
            subject_id="requester-1",
            subject_digest=principal["metadata"]["recordDigest"],
            reason_code="ECO_SECURITY_RESPONSE",
            expected_snapshot_digest=self.active["authoritySnapshotDigest"],
            now=NOW + timedelta(seconds=1),
        )
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER revocations_immutable_delete")
        connection.execute(
            "DELETE FROM revocations WHERE revocation_id=?",
            ("revocation-live-tamper",),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(RuntimeStoreError) as caught:
            self.store.snapshot()
        self.assertEqual(caught.exception.code, "ECO_TEAM_AUTHORITY_CORRUPT")

    def test_emergency_disable_requires_exact_independent_recovery_quorum(self) -> None:
        denied = self.store.set_emergency_deny(
            event_id="emergency-enable-1",
            enabled=True,
            reason_code="ECO_EMERGENCY_OPERATOR_DENY",
            expected_snapshot_digest=self.active["authoritySnapshotDigest"],
            now=datetime(2026, 7, 16, 12, 0, 10, tzinfo=timezone.utc),
        )
        read_request = self.team_request(
            action="repository.read", action_class="A1"
        )
        self.assertEqual(
            self.gate.authorize(
                self.allow,
                self.subject,
                read_request,
                now=NOW,
                actor_assertion=self.runtime_actor_assertion(read_request),
            ).effect,
            "deny",
        )
        with self.assertRaises(RuntimeStoreError) as caught:
            self.store.set_emergency_deny(
                event_id="unsafe-disable",
                enabled=False,
                reason_code="ECO_EMERGENCY_RECOVERY_COMPLETE",
                expected_snapshot_digest=denied["authoritySnapshotDigest"],
                now=datetime(2026, 7, 16, 12, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(
            caught.exception.code,
            "ECO_TEAM_AUTHORITY_RECOVERY_APPROVAL_REQUIRED",
        )
        profile, request = self.recovery_request(denied)
        votes = [
            self.vote(profile, request, principal)
            for principal in ("approver-1", "approver-2")
        ]
        requester_assertion = self.actor_assertion(
            principal_id="requester-1",
            audience="emergency-recovery",
            operation_digest=recovery_actor_operation_digest(
                request["metadata"]["recordDigest"]
            ),
            snapshot_digest=denied["authoritySnapshotDigest"],
            nonce_seed="recovery-requester-1",
        )
        swapped_requester = self.actor_assertion(
            principal_id="approver-1",
            audience="emergency-recovery",
            operation_digest=recovery_actor_operation_digest(
                request["metadata"]["recordDigest"]
            ),
            snapshot_digest=denied["authoritySnapshotDigest"],
            nonce_seed="recovery-swapped-requester",
        )
        with self.assertRaises(RuntimeStoreError) as swapped:
            self.store.disable_emergency_deny(
                event_id="emergency-disable-swapped-requester",
                reason_code="ECO_EMERGENCY_RECOVERY_COMPLETE",
                expected_snapshot_digest=denied["authoritySnapshotDigest"],
                profile=profile,
                request=request,
                requester_assertion=swapped_requester,
                votes=votes,
                consumption_nonce=b"s" * 32,
                expected_requester_principal_id="requester-1",
                expected_requester_membership_digest=self.memberships[
                    "requester-1"
                ]["metadata"]["recordDigest"],
                now=datetime(2026, 7, 16, 12, 1, 30, tzinfo=timezone.utc),
            )
        self.assertEqual(
            swapped.exception.code,
            "ECO_TEAM_AUTHORITY_RECOVERY_REQUESTER_UNTRUSTED",
        )
        self.assertTrue(self.store.snapshot()["emergencyDeny"])
        recovered = self.store.disable_emergency_deny(
            event_id="emergency-disable-1",
            reason_code="ECO_EMERGENCY_RECOVERY_COMPLETE",
            expected_snapshot_digest=denied["authoritySnapshotDigest"],
            profile=profile,
            request=request,
            requester_assertion=requester_assertion,
            votes=votes,
            consumption_nonce=b"r" * 32,
            expected_requester_principal_id="requester-1",
            expected_requester_membership_digest=self.memberships["requester-1"][
                "metadata"
            ]["recordDigest"],
            now=datetime(2026, 7, 16, 12, 2, tzinfo=timezone.utc),
        )
        self.assertFalse(recovered["emergencyDeny"])
        self.assertEqual(recovered["epochs"]["emergency"], 2)
        self.store.verify()

    def test_verified_backup_reopens_with_exact_store_and_snapshot(self) -> None:
        backup_path = Path(self.temp.name) / "backup" / "authority.db"
        result = self.store.backup_to(
            backup_path,
            expected_snapshot_digest=self.active["authoritySnapshotDigest"],
            now=NOW,
        )
        self.assertTrue(result["verified"])
        self.assertEqual(len(result["databaseSha256"]), 64)
        with SQLiteTeamAuthority(
            backup_path,
            hmac_key=AUDIT_KEY,
            key_id="audit-key-1",
            trust_anchor=trust_anchor(self.policy_signer),
            project_id=PROJECT_ID,
            store_id="team-authority-1",
        ) as restored:
            self.assertEqual(
                restored.snapshot()["authoritySnapshotDigest"],
                self.active["authoritySnapshotDigest"],
            )

    def test_emergency_denied_store_can_be_backed_up_as_evidence(self) -> None:
        denied = self.store.set_emergency_deny(
            event_id="emergency-backup",
            enabled=True,
            reason_code="ECO_EMERGENCY_OPERATOR_DENY",
            expected_snapshot_digest=self.active["authoritySnapshotDigest"],
            now=NOW + timedelta(seconds=1),
        )
        backup_path = Path(self.temp.name) / "emergency-backup" / "authority.db"
        receipt = self.store.backup_to(
            backup_path,
            expected_snapshot_digest=denied["authoritySnapshotDigest"],
            now=NOW + timedelta(seconds=2),
        )
        self.assertTrue(receipt["verified"])
        with SQLiteTeamAuthority(
            backup_path,
            hmac_key=AUDIT_KEY,
            key_id="audit-key-1",
            trust_anchor=trust_anchor(self.policy_signer),
            project_id=PROJECT_ID,
            store_id="team-authority-1",
        ) as restored:
            restored.verify()
            self.assertTrue(restored.snapshot()["emergencyDeny"])

    def test_backup_publish_race_preserves_competing_target(self) -> None:
        target = Path(self.temp.name) / "backup-race" / "authority.db"
        original_link = os.link

        def publish_competitor(source: Path, destination: Path) -> None:
            Path(destination).write_bytes(b"competing-backup")
            original_link(source, destination)

        with patch(
            "eco_runtime.team_authority.os.link",
            side_effect=publish_competitor,
        ):
            with self.assertRaises(RuntimeStoreError) as caught:
                self.store.backup_to(
                    target,
                    expected_snapshot_digest=self.active[
                        "authoritySnapshotDigest"
                    ],
                    now=NOW,
                )
        self.assertEqual(
            caught.exception.code, "ECO_TEAM_AUTHORITY_BACKUP_PATH_INVALID"
        )
        self.assertEqual(target.read_bytes(), b"competing-backup")
        self.assertEqual(
            list(target.parent.glob(f".{target.name}.eco-stage-*")), []
        )

    def test_rotation_preflight_failures_leave_predecessor_unchanged(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        before = self.store.snapshot()

        def attempt(target: Path, **overrides: object) -> None:
            arguments: dict[str, object] = {
                "expected_current_snapshot_digest": before[
                    "authoritySnapshotDigest"
                ],
                "raw_rotation": rotation,
                "new_anchor": successor_anchor,
                "raw_successor_policy": successor_policy,
                "successor_database": target,
                "successor_hmac_key": b"successor-authority-hmac-key-32!",
                "successor_audit_key_id": "audit-key-successor",
                "successor_store_id": "team-authority-2",
                "activation_id": "activation-successor-1",
                "now": NOW,
            }
            arguments.update(overrides)
            with self.assertRaises((RuntimeStoreError, ValueError)):
                rotate_authority_generation(self.store, **arguments)  # type: ignore[arg-type]
            self.assertEqual(self.store.snapshot(), before)
            self.assertEqual(
                list(target.parent.glob(f".{target.name}.eco-stage-*")), []
            )

        forbidden = Path(self.temp.name) / "governed"
        forbidden.mkdir(mode=0o700)
        forbidden_target = forbidden / "authority.db"
        with self.subTest(case="forbidden-root"):
            attempt(forbidden_target, forbidden_root=forbidden)
            self.assertFalse(forbidden_target.exists())

        invalid_hmac_target = Path(self.temp.name) / "invalid-hmac" / "authority.db"
        with self.subTest(case="invalid-constructor-hmac"):
            attempt(invalid_hmac_target, successor_hmac_key=b"short")
            self.assertFalse(invalid_hmac_target.exists())

        invalid_key_target = Path(self.temp.name) / "invalid-key" / "authority.db"
        with self.subTest(case="invalid-constructor-key-id"):
            attempt(invalid_key_target, successor_audit_key_id="invalid key")
            self.assertFalse(invalid_key_target.exists())

        invalid_activation_target = (
            Path(self.temp.name) / "invalid-activation" / "authority.db"
        )
        with self.subTest(case="invalid-activation-id"):
            attempt(invalid_activation_target, activation_id="invalid activation")
            self.assertFalse(invalid_activation_target.exists())

        unsafe_target = Path(self.temp.name) / "unsafe-existing" / "authority.db"
        unsafe_target.mkdir(parents=True, mode=0o700)
        with self.subTest(case="unsafe-existing-target"):
            attempt(unsafe_target)
            self.assertTrue(unsafe_target.is_dir())

    @unittest.skipUnless(os.name == "posix", "POSIX permission model required")
    def test_rotation_insecure_parent_does_not_fence_predecessor(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        before = self.store.snapshot()
        parent = Path(self.temp.name) / "shared-successor"
        parent.mkdir(mode=0o755)
        target = parent / "authority.db"
        with self.assertRaises(RuntimeStoreError) as caught:
            rotate_authority_generation(
                self.store,
                expected_current_snapshot_digest=before[
                    "authoritySnapshotDigest"
                ],
                raw_rotation=rotation,
                new_anchor=successor_anchor,
                raw_successor_policy=successor_policy,
                successor_database=target,
                successor_hmac_key=b"successor-authority-hmac-key-32!",
                successor_audit_key_id="audit-key-successor",
                successor_store_id="team-authority-2",
                activation_id="activation-successor-1",
                now=NOW,
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_AUTHORITY_PERMISSIONS")
        self.assertEqual(self.store.snapshot(), before)
        self.assertFalse(target.exists())
        self.assertEqual(list(parent.glob(f".{target.name}.eco-stage-*")), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are required")
    def test_rotation_forbidden_symlink_parent_escape_is_rejected_preflight(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        before = self.store.snapshot()
        forbidden = Path(self.temp.name) / "governed-link-root"
        outside = Path(self.temp.name) / "outside-private"
        forbidden.mkdir(mode=0o700)
        outside.mkdir(mode=0o700)
        escape = forbidden / "escape"
        try:
            escape.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        target = escape / "authority.db"
        with self.assertRaises(RuntimeStoreError) as caught:
            rotate_authority_generation(
                self.store,
                expected_current_snapshot_digest=before[
                    "authoritySnapshotDigest"
                ],
                raw_rotation=rotation,
                new_anchor=successor_anchor,
                raw_successor_policy=successor_policy,
                successor_database=target,
                successor_hmac_key=b"successor-authority-hmac-key-32!",
                successor_audit_key_id="audit-key-successor",
                successor_store_id="team-authority-2",
                activation_id="activation-successor-1",
                now=NOW,
                forbidden_root=forbidden,
            )
        self.assertEqual(caught.exception.code, "ECO_TEAM_AUTHORITY_LOCATION_DENIED")
        self.assertEqual(self.store.snapshot(), before)
        self.assertFalse((outside / "authority.db").exists())
        self.assertEqual(list(outside.glob(".authority.db.eco-stage-*")), [])

    def test_rotation_carries_revocations_and_blocks_reintroduction(self) -> None:
        principal = self.principals["requester-1"]
        revoked = self.store.revoke(
            revocation_id="revocation-before-rotation",
            subject_kind="PrincipalIdentity",
            subject_id="requester-1",
            subject_digest=principal["metadata"]["recordDigest"],
            reason_code="ECO_SECURITY_RESPONSE",
            expected_snapshot_digest=self.active["authoritySnapshotDigest"],
            now=NOW + timedelta(seconds=1),
        )
        successor_anchor, successor_policy, rotation = self.rotation_material()
        target = Path(self.temp.name) / "revoked-successor" / "authority.db"
        with self.assertRaises(RuntimeStoreError) as caught:
            rotate_authority_generation(
                self.store,
                expected_current_snapshot_digest=revoked[
                    "authoritySnapshotDigest"
                ],
                raw_rotation=rotation,
                new_anchor=successor_anchor,
                raw_successor_policy=successor_policy,
                successor_database=target,
                successor_hmac_key=b"successor-authority-hmac-key-32!",
                successor_audit_key_id="audit-key-successor",
                successor_store_id="team-authority-2",
                activation_id="activation-successor-1",
                now=NOW + timedelta(seconds=2),
            )
        self.assertEqual(
            caught.exception.code, "ECO_TEAM_AUTHORITY_REVOKED_SUBJECT"
        )
        self.assertFalse(target.exists())
        pending = self.store.snapshot()
        self.assertEqual(pending["generationStatus"], "rotation-pending")
        evidence = Path(self.temp.name) / "pending-backup" / "authority.db"
        self.assertTrue(
            self.store.backup_to(
                evidence,
                expected_snapshot_digest=pending["authoritySnapshotDigest"],
                now=NOW + timedelta(seconds=3),
            )["verified"]
        )

    def test_rotation_publish_race_preserves_competing_target(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        target = Path(self.temp.name) / "rotation-race" / "authority.db"
        original_link = os.link

        def publish_competitor(source: Path, destination: Path) -> None:
            Path(destination).write_bytes(b"competing-successor")
            original_link(source, destination)

        with patch(
            "eco_runtime.team_authority.os.link",
            side_effect=publish_competitor,
        ):
            with self.assertRaises(RuntimeStoreError) as caught:
                rotate_authority_generation(
                    self.store,
                    expected_current_snapshot_digest=self.active[
                        "authoritySnapshotDigest"
                    ],
                    raw_rotation=rotation,
                    new_anchor=successor_anchor,
                    raw_successor_policy=successor_policy,
                    successor_database=target,
                    successor_hmac_key=b"successor-authority-hmac-key-32!",
                    successor_audit_key_id="audit-key-successor",
                    successor_store_id="team-authority-2",
                    activation_id="activation-successor-1",
                    now=NOW,
                )
        self.assertEqual(
            caught.exception.code, "ECO_TEAM_ROTATION_SUCCESSOR_PATH_INVALID"
        )
        self.assertEqual(target.read_bytes(), b"competing-successor")
        self.assertEqual(
            list(target.parent.glob(f".{target.name}.eco-stage-*")), []
        )
        self.assertEqual(
            self.store.snapshot()["generationStatus"], "rotation-pending"
        )

    def test_published_pending_successor_is_fail_closed_and_resumable(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        target = Path(self.temp.name) / "crash-resume" / "authority.db"
        with patch.object(
            SQLiteTeamAuthority,
            "finalize_successor_generation",
            side_effect=RuntimeStoreError(
                "ECO_TEST_CRASH", "simulated publication crash"
            ),
        ):
            with self.assertRaises(RuntimeStoreError) as crashed:
                rotate_authority_generation(
                    self.store,
                    expected_current_snapshot_digest=self.active[
                        "authoritySnapshotDigest"
                    ],
                    raw_rotation=rotation,
                    new_anchor=successor_anchor,
                    raw_successor_policy=successor_policy,
                    successor_database=target,
                    successor_hmac_key=b"successor-authority-hmac-key-32!",
                    successor_audit_key_id="audit-key-successor",
                    successor_store_id="team-authority-2",
                    activation_id="activation-successor-1",
                    now=NOW,
                )
        self.assertEqual(crashed.exception.code, "ECO_TEST_CRASH")
        self.assertTrue(target.exists())
        with SQLiteTeamAuthority(
            target,
            hmac_key=b"successor-authority-hmac-key-32!",
            key_id="audit-key-successor",
            trust_anchor=successor_anchor,
            project_id=PROJECT_ID,
            store_id="team-authority-2",
        ) as pending:
            state = pending.snapshot()
            self.assertEqual(state["generationStatus"], "pending-successor")
            with self.assertRaises(RuntimeStoreError) as inactive:
                pending.assert_live(
                    expected_snapshot_digest=state["authoritySnapshotDigest"],
                    now=NOW,
                )
            self.assertEqual(
                inactive.exception.code,
                "ECO_TEAM_AUTHORITY_GENERATION_INACTIVE",
            )
        resumed = rotate_authority_generation(
            self.store,
            expected_current_snapshot_digest=self.active[
                "authoritySnapshotDigest"
            ],
            raw_rotation=rotation,
            new_anchor=successor_anchor,
            raw_successor_policy=successor_policy,
            successor_database=target,
            successor_hmac_key=b"successor-authority-hmac-key-32!",
            successor_audit_key_id="audit-key-successor",
            successor_store_id="team-authority-2",
            activation_id="activation-successor-1",
            now=NOW,
        )
        self.assertTrue(resumed["verified"])
        self.assertEqual(self.store.snapshot()["generationStatus"], "retired")

    def test_retired_rotation_replays_only_to_the_same_target(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        target = Path(self.temp.name) / "retired-replay" / "authority.db"
        arguments = {
            "expected_current_snapshot_digest": self.active[
                "authoritySnapshotDigest"
            ],
            "raw_rotation": rotation,
            "new_anchor": successor_anchor,
            "raw_successor_policy": successor_policy,
            "successor_hmac_key": b"successor-authority-hmac-key-32!",
            "successor_audit_key_id": "audit-key-successor",
            "successor_store_id": "team-authority-2",
            "activation_id": "activation-successor-1",
            "now": NOW,
        }
        first = rotate_authority_generation(
            self.store, successor_database=target, **arguments
        )
        retired = self.store.snapshot()
        replay = rotate_authority_generation(
            self.store, successor_database=target, **arguments
        )
        self.assertEqual(replay["rotationCommitmentDigest"], first["rotationCommitmentDigest"])
        self.assertEqual(replay["successorSnapshotDigest"], first["successorSnapshotDigest"])
        self.assertEqual(self.store.snapshot(), retired)

        second_target = Path(self.temp.name) / "retired-fork" / "authority.db"
        with self.assertRaises(RuntimeStoreError) as forked:
            rotate_authority_generation(
                self.store, successor_database=second_target, **arguments
            )
        self.assertEqual(
            forked.exception.code, "ECO_TEAM_ROTATION_RESERVATION_CONFLICT"
        )
        self.assertEqual(self.store.snapshot(), retired)
        self.assertFalse(second_target.exists())
        self.assertEqual(
            list(second_target.parent.glob(f".{second_target.name}.eco-stage-*")),
            [],
        )

    def test_concurrent_two_target_rotation_creates_only_one_successor(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        targets = [
            Path(self.temp.name) / f"concurrent-{index}" / "authority.db"
            for index in range(2)
        ]
        barrier = threading.Barrier(2)
        results: list[str] = []

        def rotate(target: Path) -> None:
            barrier.wait()
            try:
                rotate_authority_generation(
                    self.store,
                    expected_current_snapshot_digest=self.active[
                        "authoritySnapshotDigest"
                    ],
                    raw_rotation=rotation,
                    new_anchor=successor_anchor,
                    raw_successor_policy=successor_policy,
                    successor_database=target,
                    successor_hmac_key=b"successor-authority-hmac-key-32!",
                    successor_audit_key_id="audit-key-successor",
                    successor_store_id="team-authority-2",
                    activation_id="activation-successor-1",
                    now=NOW,
                )
                results.append("success")
            except RuntimeStoreError as exc:
                results.append(exc.code)

        threads = [threading.Thread(target=rotate, args=(target,)) for target in targets]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(
            sorted(results),
            ["ECO_TEAM_ROTATION_RESERVATION_CONFLICT", "success"],
        )
        self.assertEqual(sum(target.exists() for target in targets), 1)
        self.assertEqual(self.store.snapshot()["generationStatus"], "retired")

    def test_dual_signed_rotation_creates_linked_successor_generation(self) -> None:
        successor_anchor, successor_policy, rotation = self.rotation_material()
        successor_path = Path(self.temp.name) / "successor" / "authority.db"
        receipt = rotate_authority_generation(
            self.store,
            expected_current_snapshot_digest=self.active[
                "authoritySnapshotDigest"
            ],
            raw_rotation=rotation,
            new_anchor=successor_anchor,
            raw_successor_policy=successor_policy,
            successor_database=successor_path,
            successor_hmac_key=b"successor-authority-hmac-key-32!",
            successor_audit_key_id="audit-key-successor",
            successor_store_id="team-authority-2",
            activation_id="activation-successor-1",
            now=NOW,
        )
        self.assertTrue(receipt["verified"])
        self.assertFalse(receipt["predecessorHistoryRewritten"])
        self.assertEqual(receipt["successorPolicyRevision"], 1)
        self.assertEqual(len(receipt["successorLocationDigest"]), 64)
        predecessor = self.store.snapshot()
        self.assertEqual(predecessor["generationStatus"], "retired")
        with self.assertRaises(RuntimeStoreError) as inactive:
            self.store.assert_live(
                expected_snapshot_digest=predecessor[
                    "authoritySnapshotDigest"
                ],
                now=NOW,
            )
        self.assertEqual(
            inactive.exception.code, "ECO_TEAM_AUTHORITY_GENERATION_INACTIVE"
        )
        with SQLiteTeamAuthority(
            successor_path,
            hmac_key=b"successor-authority-hmac-key-32!",
            key_id="audit-key-successor",
            trust_anchor=successor_anchor,
            project_id=PROJECT_ID,
            store_id="team-authority-2",
        ) as successor:
            successor.verify()
            self.assertEqual(
                successor.snapshot()["authoritySnapshotDigest"],
                receipt["successorSnapshotDigest"],
            )
            successor_backup = (
                Path(self.temp.name) / "successor-backup" / "authority.db"
            )
            backed_up = successor.backup_to(
                successor_backup,
                expected_snapshot_digest=receipt["successorSnapshotDigest"],
                now=NOW,
            )
            self.assertTrue(backed_up["verified"])
        with SQLiteTeamAuthority(
            successor_backup,
            hmac_key=b"successor-authority-hmac-key-32!",
            key_id="audit-key-successor",
            trust_anchor=successor_anchor,
            project_id=PROJECT_ID,
            store_id="team-authority-2",
        ) as restored_successor:
            restored_successor.verify()
            self.assertEqual(
                restored_successor.snapshot()["authoritySnapshotDigest"],
                receipt["successorSnapshotDigest"],
            )
        predecessor_backup = (
            Path(self.temp.name) / "predecessor-backup" / "authority.db"
        )
        backed_up = self.store.backup_to(
            predecessor_backup,
            expected_snapshot_digest=predecessor["authoritySnapshotDigest"],
            now=NOW,
        )
        self.assertTrue(backed_up["verified"])
        with SQLiteTeamAuthority(
            predecessor_backup,
            hmac_key=AUDIT_KEY,
            key_id="audit-key-1",
            trust_anchor=trust_anchor(self.policy_signer),
            project_id=PROJECT_ID,
            store_id="team-authority-1",
        ) as restored_predecessor:
            restored_predecessor.verify()
            self.assertEqual(
                restored_predecessor.snapshot()["generationStatus"], "retired"
            )
        second_target = Path(self.temp.name) / "successor-2" / "authority.db"
        with self.assertRaises(RuntimeStoreError) as replay:
            rotate_authority_generation(
                self.store,
                expected_current_snapshot_digest=self.active[
                    "authoritySnapshotDigest"
                ],
                raw_rotation=rotation,
                new_anchor=successor_anchor,
                raw_successor_policy=successor_policy,
                successor_database=second_target,
                successor_hmac_key=b"successor-authority-hmac-key-32!",
                successor_audit_key_id="audit-key-successor",
                successor_store_id="team-authority-2",
                activation_id="activation-successor-1",
                now=NOW,
            )
        self.assertEqual(
            replay.exception.code, "ECO_TEAM_ROTATION_RESERVATION_CONFLICT"
        )
        self.assertFalse(second_target.exists())


if __name__ == "__main__":
    unittest.main()
