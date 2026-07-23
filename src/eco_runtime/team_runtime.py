from __future__ import annotations

"""End-to-end M5 narrowing gate over an exact single-use runtime decision."""

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol, TypeVar

from .contracts import validate_record
from .digests import semantic_digest
from .errors import ContractValidationError, RuntimePolicyError, RuntimeStoreError
from .policy import PolicyEngine
from .store import SQLiteRuntimeStore
from .team_actor import runtime_actor_operation_digest
from .team_access import TeamAccessDecision, evaluate_team_access
from .team_approval import ConsumedActionPermit, VerifiedActionPermit
from .team_authority import SQLiteTeamAuthority


_T = TypeVar("_T")


RUNTIME_ACTION_SUBJECT_PROFILE: dict[str, tuple[str, str | None]] = {
    "repository.read": ("ToolRequest", "repository.read"),
    "repository.write": ("ToolRequest", "repository.write"),
    "model.invoke": ("ModelRequest", None),
}


def team_action_binding_digest(request: Mapping[str, Any]) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-runtime-action-v1",
            "action": request.get("action"),
            "actionClass": request.get("actionClass"),
            "projectId": request.get("projectId"),
            "environmentId": request.get("environmentId"),
            "dataClass": request.get("dataClass"),
        }
    )


def team_resource_binding_digest(request: Mapping[str, Any]) -> str:
    return semantic_digest(
        {
            "domain": "eco-team-runtime-resource-v1",
            "resource": request.get("resource"),
        }
    )


def _exact_runtime_subject_binding(
    decision: Mapping[str, Any],
    subject: Mapping[str, Any],
    team_request: Mapping[str, Any],
) -> bool:
    action = team_request.get("action")
    profile = RUNTIME_ACTION_SUBJECT_PROFILE.get(action)
    if profile is None:
        return False
    expected_kind, expected_tool_id = profile
    try:
        binding = {
            "kind": subject["kind"],
            "id": subject["metadata"]["id"],
            "digest": semantic_digest(subject),
        }
        resource = team_request["resource"]
        if binding != decision["spec"]["subject"] or binding["kind"] != expected_kind:
            return False
        # Repository actions authorize the exact ToolRequest because its
        # resource identifier is the request identifier.  Model invocation is
        # intentionally different: the runtime decision still binds the exact
        # ModelRequest, while M5 access policy binds the deployment selected by
        # that request.  Reusing repository subject/resource equality here
        # either made model.invoke unusable or encouraged callers to substitute
        # a request digest for deployment identity.
        if action == "model.invoke":
            spec = subject["spec"]
            if resource != {
                "kind": "deployment",
                "id": spec["deploymentId"],
                "digest": spec["deploymentIdentityDigest"],
            }:
                return False
            if team_request.get("dataClass") != spec["input"]["dataClass"]:
                return False
        elif (
            resource["id"] != binding["id"]
            or resource["digest"] != binding["digest"]
        ):
            return False
        if expected_tool_id is not None:
            return subject["spec"]["toolId"] == expected_tool_id
        return True
    except (KeyError, TypeError):
        return False


@dataclass(frozen=True, slots=True)
class TeamAuthorizationDecision:
    effect: str
    code: str
    runtime_decision_digest: str
    team_request_digest: str
    authority_snapshot_digest: str
    active_bundle_digest: str
    access_policy_digest: str
    principal_digest: str
    membership_digest: str
    action_class: str
    approval_profile_digest: str | None
    permit_digest: str | None
    effective_authorization: bool
    narrowing_only: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "code": self.code,
            "runtimeDecisionDigest": self.runtime_decision_digest,
            "teamRequestDigest": self.team_request_digest,
            "authoritySnapshotDigest": self.authority_snapshot_digest,
            "activeBundleDigest": self.active_bundle_digest,
            "accessPolicyDigest": self.access_policy_digest,
            "principalDigest": self.principal_digest,
            "membershipDigest": self.membership_digest,
            "actionClass": self.action_class,
            "approvalProfileDigest": self.approval_profile_digest,
            "permitDigest": self.permit_digest,
            "effectiveAuthorization": self.effective_authorization,
            "narrowingOnly": self.narrowing_only,
        }


@dataclass(frozen=True, slots=True)
class GuardedTeamEffect:
    decision: TeamAuthorizationDecision
    result: Any
    permit_consumption: ConsumedActionPermit | None
    runtime_claim_digest: str


class RuntimeDecisionAuthority(Protocol):
    """Trusted runtime-side source for exact, single-use policy authority."""

    def assert_current_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None: ...

    def claim_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        nonce: str,
        now: datetime,
    ) -> str: ...


class PolicyEngineRuntimeDecisionAuthority:
    """Concrete, non-duck-typed adapter over ``PolicyEngine`` single-use state."""

    __slots__ = ("_engine",)

    def __init__(self, engine: PolicyEngine) -> None:
        if not isinstance(engine, PolicyEngine):
            raise TypeError("engine must be the trusted PolicyEngine")
        self._engine = engine

    def assert_current_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None:
        self._engine.assert_decision_current(
            dict(decision), dict(subject), now=now
        )

    def claim_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        nonce: str,
        now: datetime,
    ) -> str:
        if not isinstance(nonce, str) or not nonce:
            raise RuntimePolicyError(
                "ECO_TEAM_RUNTIME_CLAIM_INVALID", "Runtime claim failed closed"
            )
        self._engine.consume_decision(dict(decision), dict(subject), now=now)
        return semantic_digest(
            {
                "domain": "eco-team-runtime-decision-claim-v1",
                "decisionDigest": semantic_digest(decision),
                "subjectDigest": semantic_digest(subject),
                "nonce": nonce,
            }
        )


class DurableRuntimeDecisionAuthority:
    """Restart-safe claim adapter over both PolicyEngine and SQLiteRuntimeStore.

    The decision must already have been issued into the configured runtime
    store by the trusted composition root.  Cross-database atomicity with the
    team authority is intentionally not claimed: a later team failure burns
    the runtime claim but can never create an effect.
    """

    __slots__ = (
        "_engine",
        "_store",
        "_semantic_config_digest",
        "_policy_capability",
    )

    def __init__(
        self,
        engine: PolicyEngine,
        store: SQLiteRuntimeStore,
        *,
        semantic_config_digest: str,
        policy_capability: object,
    ) -> None:
        if not isinstance(engine, PolicyEngine):
            raise TypeError("engine must be the trusted PolicyEngine")
        if not isinstance(store, SQLiteRuntimeStore):
            raise TypeError("store must be SQLiteRuntimeStore")
        if (
            not isinstance(semantic_config_digest, str)
            or len(semantic_config_digest) != 64
            or any(character not in "0123456789abcdef" for character in semantic_config_digest)
        ):
            raise ValueError("semantic_config_digest must be a lowercase sha256 digest")
        if policy_capability is None:
            raise ValueError("policy_capability must be the configured opaque capability")
        self._engine = engine
        self._store = store
        self._semantic_config_digest = semantic_config_digest
        self._policy_capability = policy_capability

    def assert_current_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        now: datetime,
    ) -> None:
        self._engine.assert_decision_current(
            dict(decision), dict(subject), now=now
        )
        self._store.assert_decision_current(
            dict(decision),
            dict(subject),
            now=now,
            semantic_config_digest=self._semantic_config_digest,
            policy_capability=self._policy_capability,
        )

    def claim_runtime_decision(
        self,
        decision: Mapping[str, Any],
        subject: Mapping[str, Any],
        *,
        nonce: str,
        now: datetime,
    ) -> str:
        if not isinstance(nonce, str) or not nonce:
            raise RuntimePolicyError(
                "ECO_TEAM_RUNTIME_CLAIM_INVALID", "Runtime claim failed closed"
            )
        # Consume the in-memory issuer first.  If durable consumption fails,
        # the authority is conservatively burned and no effect is attempted.
        self._engine.consume_decision(dict(decision), dict(subject), now=now)
        self._store.consume_decision(
            dict(decision),
            dict(subject),
            nonce=nonce,
            now=now,
            semantic_config_digest=self._semantic_config_digest,
            policy_capability=self._policy_capability,
        )
        return semantic_digest(
            {
                "domain": "eco-team-durable-runtime-decision-claim-v1",
                "runtimeStoreId": self._store.store_id,
                "decisionDigest": semantic_digest(decision),
                "subjectDigest": semantic_digest(subject),
                "nonce": nonce,
            }
        )


class TeamAuthorizationGate:
    """Intersect runtime allow, current team access and exact A2 quorum authority."""

    def __init__(
        self,
        authority: SQLiteTeamAuthority,
        runtime_decision_authority: (
            PolicyEngineRuntimeDecisionAuthority | DurableRuntimeDecisionAuthority
        ),
    ) -> None:
        if not isinstance(authority, SQLiteTeamAuthority):
            raise TypeError("authority must be SQLiteTeamAuthority")
        self._authority = authority
        if type(runtime_decision_authority) not in {
            PolicyEngineRuntimeDecisionAuthority,
            DurableRuntimeDecisionAuthority,
        }:
            raise TypeError(
                "runtime_decision_authority must be a trusted concrete adapter"
            )
        self._runtime_decision_authority = runtime_decision_authority

    @staticmethod
    def _expired(value: object, now: datetime) -> bool:
        if not isinstance(value, str):
            return True
        try:
            parsed = datetime.fromisoformat(
                value[:-1] + "+00:00" if value.endswith("Z") else value
            )
        except ValueError:
            return True
        return parsed.tzinfo is None or now.astimezone(timezone.utc) >= parsed.astimezone(
            timezone.utc
        )

    @staticmethod
    def _deny(
        *,
        code: str,
        runtime_digest: str,
        request_digest: str,
        snapshot: Mapping[str, Any],
        access_policy_digest: str = "0" * 64,
        principal_digest: str = "0" * 64,
        membership_digest: str = "0" * 64,
        action_class: str = "A4",
        approval_profile_digest: str | None = None,
        permit_digest: str | None = None,
    ) -> TeamAuthorizationDecision:
        return TeamAuthorizationDecision(
            effect="deny",
            code=code,
            runtime_decision_digest=runtime_digest,
            team_request_digest=request_digest,
            authority_snapshot_digest=str(
                snapshot.get("authoritySnapshotDigest", "0" * 64)
            ),
            active_bundle_digest=str(
                snapshot.get("activePolicy", {}).get("digest", "0" * 64)
            ),
            access_policy_digest=access_policy_digest,
            principal_digest=principal_digest,
            membership_digest=membership_digest,
            action_class=action_class,
            approval_profile_digest=approval_profile_digest,
            permit_digest=permit_digest,
            effective_authorization=False,
        )

    def authorize(
        self,
        runtime_policy_decision: dict[str, Any],
        runtime_subject: dict[str, Any],
        team_request: dict[str, Any],
        *,
        now: datetime,
        actor_assertion: Mapping[str, Any],
        permit: VerifiedActionPermit | None = None,
    ) -> TeamAuthorizationDecision:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RuntimePolicyError(
                "ECO_TEAM_AUTHORIZATION_TIME_INVALID",
                "Team authorization failed closed",
            )
        runtime_policy_decision = copy.deepcopy(runtime_policy_decision)
        runtime_subject = copy.deepcopy(runtime_subject)
        team_request = copy.deepcopy(team_request)
        actor_assertion = (
            copy.deepcopy(dict(actor_assertion))
            if isinstance(actor_assertion, Mapping)
            else {}
        )
        invalid_digest = semantic_digest(
            {"domain": "eco-team-authorization-invalid-input-v1"}
        )
        try:
            runtime_decision = validate_record(runtime_policy_decision)
            subject = validate_record(runtime_subject)
            if not _exact_runtime_subject_binding(
                runtime_decision, subject, team_request
            ):
                raise RuntimePolicyError(
                    "ECO_TEAM_RUNTIME_BINDING_MISMATCH",
                    "Runtime decision subject does not match the team request",
                )
            if runtime_decision["spec"]["effect"] == "allow":
                self._runtime_decision_authority.assert_current_runtime_decision(
                    runtime_decision, subject, now=now
                )
            runtime_digest = semantic_digest(runtime_decision)
        except (ContractValidationError, RuntimePolicyError, TypeError, KeyError):
            return self._deny(
                code="ECO_TEAM_RUNTIME_DECISION_INVALID",
                runtime_digest=invalid_digest,
                request_digest=invalid_digest,
                snapshot={},
            )
        request_digest = (
            semantic_digest(
                {"domain": "eco-team-runtime-request-v1", "request": team_request}
            )
            if isinstance(team_request, dict)
            else invalid_digest
        )
        snapshot = self._authority.snapshot()
        runtime_spec = runtime_decision["spec"]
        if (
            runtime_spec["effect"] != "allow"
            or self._expired(runtime_spec["constraints"]["expiresAt"], now)
        ):
            return self._deny(
                code="ECO_TEAM_RUNTIME_POLICY_DENIED",
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
            )
        if not isinstance(team_request, dict):
            return self._deny(
                code="ECO_TEAM_ACCESS_REQUEST_INVALID",
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
            )
        try:
            principal_id = team_request["principal"]["id"]
            membership_id = team_request["membership"]["id"]
            context = self._authority.active_access_context(
                principal_id=principal_id,
                membership_id=membership_id,
                expected_snapshot_digest=snapshot["authoritySnapshotDigest"],
                now=now,
            )
            self._authority.verify_actor_assertion(
                actor_assertion,
                expected_principal=context["principal"],
                expected_membership=context["membership"],
                expected_snapshot_digest=snapshot["authoritySnapshotDigest"],
                expected_audience="runtime-effect",
                expected_operation_digest=runtime_actor_operation_digest(
                    runtime_decision, subject, team_request
                ),
                now=now,
            )
        except (KeyError, TypeError, RuntimePolicyError, RuntimeStoreError):
            return self._deny(
                code="ECO_TEAM_AUTHORITY_ACTOR_INACTIVE",
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
            )
        principal_digest = context["principal"]["digest"]
        membership_digest = context["membership"]["digest"]
        action_class = str(team_request.get("actionClass", "A4"))
        access_policy_digest = context["accessPolicy"]["metadata"]["recordDigest"]
        if (
            team_request.get("principal") != context["principal"]
            or team_request.get("membership") != context["membership"]
            or not _exact_runtime_subject_binding(
                runtime_decision, subject, team_request
            )
        ):
            return self._deny(
                code="ECO_TEAM_RUNTIME_BINDING_MISMATCH",
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
                access_policy_digest=access_policy_digest,
                principal_digest=principal_digest,
                membership_digest=membership_digest,
                action_class=action_class,
            )
        team_decision: TeamAccessDecision = evaluate_team_access(
            context["accessPolicy"], team_request, now=now
        )
        if team_decision.team_effect != "allow":
            return self._deny(
                code=team_decision.code,
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
                access_policy_digest=access_policy_digest,
                principal_digest=principal_digest,
                membership_digest=membership_digest,
                action_class=action_class,
                approval_profile_digest=team_decision.approval_profile_digest,
            )
        permit_digest: str | None = None
        if action_class == "A2":
            approval_profile = next(
                (
                    item
                    for item in context["approvalProfiles"]
                    if item["metadata"]["id"]
                    == team_decision.approval_profile_id
                    and item["metadata"]["recordDigest"]
                    == team_decision.approval_profile_digest
                ),
                None,
            )
            if permit is None:
                return self._deny(
                    code="ECO_TEAM_APPROVAL_REQUIRED",
                    runtime_digest=runtime_digest,
                    request_digest=request_digest,
                    snapshot=snapshot,
                    access_policy_digest=access_policy_digest,
                    principal_digest=principal_digest,
                    membership_digest=membership_digest,
                    action_class=action_class,
                    approval_profile_digest=team_decision.approval_profile_digest,
                )
            record = permit.as_dict()
            expected_action_digest = team_action_binding_digest(team_request)
            expected_resource_digest = team_resource_binding_digest(team_request)
            spec = record.get("spec", {})
            try:
                self._authority.assert_issued_action_permit(
                    permit,
                    expected_snapshot_digest=snapshot["authoritySnapshotDigest"],
                    expected_requester_principal_id=principal_id,
                    expected_requester_membership_digest=membership_digest,
                    now=now,
                )
            except RuntimeStoreError:
                return self._deny(
                    code="ECO_TEAM_APPROVAL_INVALID",
                    runtime_digest=runtime_digest,
                    request_digest=request_digest,
                    snapshot=snapshot,
                    access_policy_digest=access_policy_digest,
                    principal_digest=principal_digest,
                    membership_digest=membership_digest,
                    action_class=action_class,
                    approval_profile_digest=team_decision.approval_profile_digest,
                )
            if (
                approval_profile is None
                or
                spec.get("profile", {}).get("id")
                != team_decision.approval_profile_id
                or spec.get("profile", {}).get("digest")
                != team_decision.approval_profile_digest
                or spec.get("action", {}).get("digest") != expected_action_digest
                or spec.get("resource", {}).get("digest")
                != expected_resource_digest
                or spec.get("snapshot")
                != {
                    "kind": "AuthoritySnapshot",
                    "id": self._authority.store_id,
                    "digest": snapshot["authoritySnapshotDigest"],
                }
                or spec.get("policy") != approval_profile["spec"]["policy"]
                or spec.get("policy", {}).get("revocationEpoch")
                != context["revocationEpoch"]
            ):
                return self._deny(
                    code="ECO_TEAM_APPROVAL_BINDING_INVALID",
                    runtime_digest=runtime_digest,
                    request_digest=request_digest,
                    snapshot=snapshot,
                    access_policy_digest=access_policy_digest,
                    principal_digest=principal_digest,
                    membership_digest=membership_digest,
                    action_class=action_class,
                    approval_profile_digest=team_decision.approval_profile_digest,
                )
            permit_digest = permit.permit_digest
        elif permit is not None:
            return self._deny(
                code="ECO_TEAM_APPROVAL_UNEXPECTED",
                runtime_digest=runtime_digest,
                request_digest=request_digest,
                snapshot=snapshot,
                access_policy_digest=access_policy_digest,
                principal_digest=principal_digest,
                membership_digest=membership_digest,
                action_class=action_class,
            )
        return TeamAuthorizationDecision(
            effect="allow",
            code="ECO_TEAM_AUTHORIZATION_ALLOWED",
            runtime_decision_digest=runtime_digest,
            team_request_digest=request_digest,
            authority_snapshot_digest=snapshot["authoritySnapshotDigest"],
            active_bundle_digest=context["activeBundleDigest"],
            access_policy_digest=access_policy_digest,
            principal_digest=principal_digest,
            membership_digest=membership_digest,
            action_class=action_class,
            approval_profile_digest=team_decision.approval_profile_digest,
            permit_digest=permit_digest,
            effective_authorization=True,
        )

    def execute_authorized(
        self,
        runtime_policy_decision: dict[str, Any],
        runtime_subject: dict[str, Any],
        team_request: dict[str, Any],
        *,
        now: datetime,
        operation: Callable[[], _T],
        actor_assertion: Mapping[str, Any],
        permit: VerifiedActionPermit | None = None,
    ) -> GuardedTeamEffect:
        runtime_policy_decision = copy.deepcopy(runtime_policy_decision)
        runtime_subject = copy.deepcopy(runtime_subject)
        team_request = copy.deepcopy(team_request)
        actor_assertion = (
            copy.deepcopy(dict(actor_assertion))
            if isinstance(actor_assertion, Mapping)
            else {}
        )
        decision = self.authorize(
            runtime_policy_decision,
            runtime_subject,
            team_request,
            now=now,
            actor_assertion=actor_assertion,
            permit=permit,
        )
        if decision.effect != "allow" or not decision.effective_authorization:
            raise RuntimePolicyError(
                decision.code, "Team authorization failed closed"
            )
        claim_nonce = semantic_digest(
            {
                "domain": "eco-team-runtime-effect-claim-nonce-v1",
                "runtimeDecisionDigest": decision.runtime_decision_digest,
                "teamRequestDigest": decision.team_request_digest,
                "actorAssertionDigest": semantic_digest(actor_assertion),
            }
        )
        try:
            runtime_claim_digest = (
                self._runtime_decision_authority.claim_runtime_decision(
                    runtime_policy_decision,
                    runtime_subject,
                    nonce=claim_nonce,
                    now=now,
                )
            )
        except (RuntimePolicyError, RuntimeStoreError) as exc:
            raise RuntimePolicyError(
                "ECO_TEAM_RUNTIME_CLAIM_REJECTED",
                "Runtime decision claim failed closed",
            ) from exc
        consumed: ConsumedActionPermit | None = None
        if decision.action_class == "A2":
            assert permit is not None
            consumed = permit.consume_with(self._authority, now=now)
        result = self._authority.effect_guard(
            expected_snapshot_digest=decision.authority_snapshot_digest,
            principal_id=team_request["principal"]["id"],
            membership_id=team_request["membership"]["id"],
            now=now,
            operation=operation,
        )
        return GuardedTeamEffect(
            decision=decision,
            result=result,
            permit_consumption=consumed,
            runtime_claim_digest=runtime_claim_digest,
        )
