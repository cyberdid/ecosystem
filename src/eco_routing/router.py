from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimePolicyError

from .contracts import (
    ROUTING_API_VERSION,
    routing_record_digest,
    seal_routing_record,
    validate_routing_record,
)
from .errors import RoutingError


_NON_FALLBACK_FAILURES = frozenset(
    {
        "policy",
        "privacy",
        "authority",
        "schema",
        "ambiguous",
        "provider-identity-drift",
        "deadline",
        "budget",
    }
)
_RETRYABLE_FAILURES = frozenset({"capacity", "transport-retryable"})


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RoutingError("ECO_ROUTING_CLOCK_INVALID", "Routing clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RoutingError("ECO_ROUTING_TIME_INVALID", "Routing timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RoutingError("ECO_ROUTING_TIME_INVALID", "Routing timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _safe_validate(record: Mapping[str, Any], kind: str) -> dict[str, Any]:
    try:
        validated = validate_routing_record(copy.deepcopy(dict(record)))
    except (ContractValidationError, TypeError, ValueError) as exc:
        raise RoutingError(
            "ECO_ROUTING_CONTRACT_INVALID", f"Trusted {kind} contract is invalid"
        ) from exc
    if validated["kind"] != kind:
        raise RoutingError("ECO_ROUTING_CONTRACT_INVALID", f"Trusted {kind} contract is invalid")
    return validated


@dataclass(frozen=True)
class DeploymentCandidate:
    """Credential-free, immutable projection of one canonical deployment.

    The raw endpoint reference is deliberately excluded. Its digest remains bound
    indirectly by ``deployment_identity_digest``.
    """

    deployment_id: str = field(repr=False)
    deployment_digest: str
    identity_digest: str
    candidate_digest: str
    provider_class: str
    zone: str
    retention: str
    allowed_data_classes: tuple[str, ...]
    enabled: bool

    @classmethod
    def from_canonical_deployment(cls, deployment: Mapping[str, Any]) -> "DeploymentCandidate":
        value = copy.deepcopy(dict(deployment))
        try:
            identity_digest = deployment_identity_digest(value)
        except RuntimePolicyError as exc:
            raise RoutingError("ECO_ROUTING_IDENTITY_INVALID", "Deployment identity is invalid") from exc
        required = {
            "id",
            "provider",
            "zone",
            "retention",
            "allowedDataClasses",
            "enabled",
        }
        if required - set(value):
            raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment projection is incomplete")
        if value["zone"] not in {f"Z{level}" for level in range(5)}:
            raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment zone is invalid")
        if value["retention"] not in {
            "no-retention",
            "local-runtime-dependent",
            "contractual",
        }:
            raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment retention is invalid")
        data_classes = value["allowedDataClasses"]
        if (
            not isinstance(data_classes, list)
            or not data_classes
            or len(data_classes) != len(set(data_classes))
            or any(item not in {f"D{level}" for level in range(5)} for item in data_classes)
        ):
            raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment data classes are invalid")
        if not isinstance(value["enabled"], bool):
            raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment enabled flag is invalid")
        deployment_digest = semantic_digest(value)
        candidate_digest = semantic_digest(
            {
                "domain": "eco-model-routing-candidate-v1alpha1",
                "deploymentId": value["id"],
                "deploymentDigest": deployment_digest,
                "deploymentIdentityDigest": identity_digest,
            }
        )
        return cls(
            deployment_id=value["id"],
            deployment_digest=deployment_digest,
            identity_digest=identity_digest,
            candidate_digest=candidate_digest,
            provider_class="local" if value["provider"] == "local" else "cloud",
            zone=value["zone"],
            retention=value["retention"],
            allowed_data_classes=tuple(sorted(data_classes)),
            enabled=value["enabled"],
        )


def candidates_from_deployment_catalog(catalog: Mapping[str, Any]) -> tuple[DeploymentCandidate, ...]:
    """Project canonical deployments into routing inputs without resolving endpoints."""

    value = copy.deepcopy(dict(catalog))
    if value.get("kind") != "DeploymentCatalog" or not isinstance(value.get("deployments"), list):
        raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment catalog is invalid")
    candidates = tuple(
        DeploymentCandidate.from_canonical_deployment(item)
        for item in value["deployments"]
        if isinstance(item, dict) and item.get("enabled") is True
    )
    ids = [item.deployment_id for item in candidates]
    if len(ids) != len(set(ids)):
        raise RoutingError("ECO_ROUTING_DEPLOYMENT_INVALID", "Deployment ids are not unique")
    return candidates


@dataclass(frozen=True)
class RoutingOutcome:
    _decision: dict[str, Any] = field(repr=False)
    _explain: dict[str, Any] = field(repr=False)

    @property
    def decision(self) -> dict[str, Any]:
        return copy.deepcopy(self._decision)

    @property
    def explain(self) -> dict[str, Any]:
        return copy.deepcopy(self._explain)


@dataclass(frozen=True)
class _CandidateEvaluation:
    candidate: DeploymentCandidate
    reasons: tuple[str, ...]
    cost: int | None
    latency: int | None
    evidence_digest: str | None
    evidence_valid_until: datetime | None
    preference: int

    @property
    def eligible(self) -> bool:
        return not self.reasons

    @property
    def rank(self) -> tuple[int, int, int, str]:
        if self.cost is None or self.latency is None:
            raise AssertionError("ineligible candidate has no rank")
        return (self.cost, self.latency, self.preference, self.candidate.candidate_digest)


class DeterministicModelRouter:
    """Pure model router over digest-bound policy, observations and prices.

    It neither resolves endpoints nor invokes providers. The caller must pass the
    selected deployment binding through the existing policy/model bridge, which
    independently re-authorizes the exact call.
    """

    def __init__(self, policy: Mapping[str, Any], price_catalog: Mapping[str, Any]) -> None:
        self._policy = _safe_validate(policy, "ModelRoutingPolicy")
        self._price_catalog = _safe_validate(price_catalog, "TrustedPriceCatalog")
        self._policy_digest = self._policy["metadata"]["recordDigest"]
        self._price_digest = self._price_catalog["metadata"]["recordDigest"]
        self._roles = {item["role"]: copy.deepcopy(item) for item in self._policy["spec"]["roles"]}

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def price_catalog_digest(self) -> str:
        return self._price_digest

    def _observation_map(
        self, observations: Sequence[Mapping[str, Any]]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        result: dict[tuple[str, str], dict[str, Any]] = {}
        for raw in observations:
            observation = _safe_validate(raw, "ObservedModelCapabilities")
            key = (
                observation["spec"]["deploymentId"],
                observation["spec"]["deploymentIdentityDigest"],
            )
            if key in result:
                raise RoutingError(
                    "ECO_ROUTING_EVIDENCE_CONFLICT", "Capability evidence binding is duplicated"
                )
            result[key] = observation
        return result

    def _price_map(self) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (item["deploymentId"], item["deploymentIdentityDigest"]): copy.deepcopy(item)
            for item in self._price_catalog["spec"]["entries"]
        }

    @staticmethod
    def _reservation(price: Mapping[str, Any], request: Mapping[str, Any]) -> int:
        spec = request["spec"]
        aggregate = spec.get("aggregateBudget")
        maximum_calls = aggregate["maximumCalls"] if aggregate is not None else 1
        input_ceiling = (
            aggregate["inputTokenCeiling"] if aggregate is not None else spec["inputTokenCeiling"]
        )
        output_ceiling = (
            aggregate["outputTokenCeiling"]
            if aggregate is not None
            else spec["outputTokenCeiling"]
        )
        variable = (
            input_ceiling * price["inputMicrousdPerMillionTokens"]
            + output_ceiling * price["outputMicrousdPerMillionTokens"]
        )
        return (
            maximum_calls * price["fixedRequestMicrousd"]
            + (variable + 999_999) // 1_000_000
        )

    def _candidate_evaluation(
        self,
        candidate: DeploymentCandidate,
        *,
        request: dict[str, Any],
        role: dict[str, Any],
        observations: dict[tuple[str, str], dict[str, Any]],
        prices: dict[tuple[str, str], dict[str, Any]],
        now: datetime,
        excluded: frozenset[str],
    ) -> _CandidateEvaluation:
        spec = request["spec"]
        reasons: set[str] = set()
        candidate_ids = role["candidateIds"]
        preference = candidate_ids.index(candidate.deployment_id) if candidate.deployment_id in candidate_ids else len(candidate_ids)
        if candidate.candidate_digest in excluded:
            reasons.add("fallback-candidate-excluded")
        if not candidate.enabled:
            reasons.add("deployment-disabled")
        if candidate.deployment_id not in candidate_ids:
            reasons.add("policy-candidate-denied")
        if candidate.zone not in role["allowedZones"] or candidate.zone not in spec["allowedZones"]:
            reasons.add("zone-denied")
        if spec["dataClass"] not in role["allowedDataClasses"] or spec["dataClass"] not in candidate.allowed_data_classes:
            reasons.add("data-class-denied")
        if candidate.retention not in role["allowedRetentions"] or candidate.retention not in spec["allowedRetentions"]:
            reasons.add("retention-denied")
        if not spec["allowCloud"] and candidate.provider_class == "cloud":
            reasons.add("cloud-denied")
        if spec["executionProfile"] == "m6.1-local-zero-cost" and candidate.provider_class != "local":
            reasons.add("local-profile-denied")

        key = (candidate.deployment_id, candidate.identity_digest)
        observation = observations.get(key)
        same_id_observations = [item for item_key, item in observations.items() if item_key[0] == candidate.deployment_id]
        evidence_digest: str | None = None
        evidence_expiry: datetime | None = None
        latency: int | None = None
        if observation is None:
            reasons.add("provider-identity-drift" if same_id_observations else "capability-evidence-missing")
        else:
            evidence_digest = observation["metadata"]["recordDigest"]
            observed = observation["spec"]
            observed_at = _parse_time(observed["observedAt"])
            evidence_expiry = _parse_time(observed["validUntil"])
            if observed_at > now or now >= evidence_expiry:
                reasons.add("capability-evidence-stale")
            required = set(role["requiredCapabilities"]) | set(spec["requiredCapabilities"])
            if not required <= set(observed["capabilities"]):
                reasons.add("capability-missing")
            token_requirement = max(
                spec["requiredContextTokens"],
                spec["inputTokenCeiling"] + spec["outputTokenCeiling"],
            )
            if observed["contextWindowTokens"] < token_requirement:
                reasons.add("context-window-insufficient")
            latency = observed["latencyP95Millis"]
            if now + timedelta(milliseconds=latency) > _parse_time(spec["deadlineAt"]):
                reasons.add("deadline-insufficient")

        price = prices.get(key)
        same_id_prices = [item for price_key, item in prices.items() if price_key[0] == candidate.deployment_id]
        cost: int | None = None
        if price is None:
            reasons.add("provider-identity-drift" if same_id_prices else "price-missing")
        else:
            cost = self._reservation(price, request)
            effective_maximum = min(spec["maximumCostMicrousd"], role["maximumCostMicrousd"])
            if cost > effective_maximum:
                reasons.add("cost-denied")
            if spec["executionProfile"] == "m6.1-local-zero-cost" and cost != 0:
                reasons.add("local-profile-cost-denied")
        return _CandidateEvaluation(
            candidate=candidate,
            reasons=tuple(sorted(reasons)),
            cost=cost,
            latency=latency,
            evidence_digest=evidence_digest,
            evidence_valid_until=evidence_expiry,
            preference=preference,
        )

    def _outcome(
        self,
        *,
        request: dict[str, Any],
        decision_id: str,
        explain_id: str,
        now: datetime,
        reason: str,
        evaluations: Sequence[_CandidateEvaluation],
        selected: _CandidateEvaluation | None,
        route_attempt: int,
        fallback_from: str | None,
        validity_limit: datetime,
    ) -> RoutingOutcome:
        decision_effect = "allowed" if selected is not None else "denied"
        explain_candidates = []
        for evaluation in sorted(evaluations, key=lambda item: item.candidate.candidate_digest):
            excluded = "fallback-candidate-excluded" in evaluation.reasons
            explain_candidates.append(
                {
                    "candidateDigest": evaluation.candidate.candidate_digest,
                    "outcome": "excluded" if excluded else ("eligible" if evaluation.eligible else "rejected"),
                    "reasonCodes": list(evaluation.reasons),
                    "rankDigest": semantic_digest(
                        {
                            "domain": "eco-routing-rank-v1alpha1",
                            "rank": evaluation.rank,
                        }
                    )
                    if evaluation.eligible
                    else None,
                }
            )
        request_digest = request["metadata"]["recordDigest"]
        explain_spec = {
            "requestDigest": request_digest,
            "policyDigest": self._policy_digest,
            "priceCatalogDigest": self._price_digest,
            "decision": decision_effect,
            "reasonCode": reason,
            "selectedCandidateDigest": selected.candidate.candidate_digest if selected else None,
            "candidates": explain_candidates,
        }
        execution_plan_digest = request["spec"].get("executionPlanDigest")
        if execution_plan_digest is not None:
            explain_spec["executionPlanDigest"] = execution_plan_digest
        explain = seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": "RoutingExplain",
                "metadata": {"id": explain_id, "createdAt": _timestamp(now)},
                "spec": explain_spec,
            }
        )
        validate_routing_record(explain)
        safe_until = max(now + timedelta(microseconds=1), validity_limit)
        selected_record = None
        if selected is not None:
            if selected.cost is None or selected.latency is None or selected.evidence_digest is None:
                raise AssertionError("selected route has incomplete trusted inputs")
            selected_record = {
                "deploymentId": selected.candidate.deployment_id,
                "deploymentDigest": selected.candidate.deployment_digest,
                "deploymentIdentityDigest": selected.candidate.identity_digest,
                "observedEvidenceDigest": selected.evidence_digest,
                "candidateDigest": selected.candidate.candidate_digest,
                "reservedCostMicrousd": selected.cost,
                "estimatedLatencyP95Millis": selected.latency,
            }
            aggregate = request["spec"].get("aggregateBudget")
            if aggregate is not None:
                selected_record["aggregateReservation"] = {
                    "maximumCalls": aggregate["maximumCalls"],
                    "inputTokenCeiling": aggregate["inputTokenCeiling"],
                    "outputTokenCeiling": aggregate["outputTokenCeiling"],
                    "reservedCostMicrousd": selected.cost,
                }
        decision_spec = {
            "requestDigest": request_digest,
            "policyDigest": self._policy_digest,
            "priceCatalogDigest": self._price_digest,
            "decision": decision_effect,
            "reasonCode": reason,
            "routeAttempt": route_attempt,
            "selected": selected_record,
            "validUntil": _timestamp(safe_until),
            "fallbackFromDigest": fallback_from,
            "explainDigest": explain["metadata"]["recordDigest"],
        }
        if execution_plan_digest is not None:
            decision_spec["executionPlanDigest"] = execution_plan_digest
        decision = seal_routing_record(
            {
                "apiVersion": ROUTING_API_VERSION,
                "kind": "ModelRouteDecision",
                "metadata": {"id": decision_id, "createdAt": _timestamp(now)},
                "spec": decision_spec,
            }
        )
        validate_routing_record(decision)
        return RoutingOutcome(decision, explain)

    def route(
        self,
        request: Mapping[str, Any],
        candidates: Sequence[DeploymentCandidate],
        observations: Sequence[Mapping[str, Any]],
        *,
        now: datetime,
        decision_id: str,
        explain_id: str,
        _excluded: frozenset[str] = frozenset(),
        _route_attempt: int = 1,
        _fallback_from: str | None = None,
    ) -> RoutingOutcome:
        current = now.astimezone(timezone.utc) if isinstance(now, datetime) and now.tzinfo else None
        if current is None:
            raise RoutingError("ECO_ROUTING_CLOCK_INVALID", "Routing clock must be timezone-aware")
        request_record = _safe_validate(request, "ModelRouteRequest")
        role = self._roles[request_record["spec"]["role"]]
        price_spec = self._price_catalog["spec"]
        deadline = _parse_time(request_record["spec"]["deadlineAt"])
        base_valid_until = min(
            current + timedelta(seconds=self._policy["spec"]["decisionTtlSeconds"]),
            deadline,
        )

        precondition_reason = None
        if request_record["spec"]["policyDigest"] != self._policy_digest:
            precondition_reason = "policy-binding-mismatch"
        elif (
            request_record["spec"]["actionClass"] not in role["allowedActionClasses"]
            or request_record["spec"]["dataClass"] not in role["allowedDataClasses"]
            or deadline <= current
            or (
                request_record["spec"]["executionProfile"] == "m6.1-local-zero-cost"
                and (
                    request_record["spec"]["allowCloud"]
                    or request_record["spec"]["maximumCostMicrousd"] != 0
                )
            )
        ):
            precondition_reason = "request-policy-denied"
        valid_from = _parse_time(price_spec["validFrom"])
        price_valid_until = _parse_time(price_spec["validUntil"])
        if precondition_reason is None and not (valid_from <= current < price_valid_until):
            precondition_reason = "price-catalog-stale"
        base_valid_until = min(base_valid_until, price_valid_until)
        if precondition_reason is not None:
            return self._outcome(
                request=request_record,
                decision_id=decision_id,
                explain_id=explain_id,
                now=current,
                reason=precondition_reason,
                evaluations=(),
                selected=None,
                route_attempt=_route_attempt,
                fallback_from=_fallback_from,
                validity_limit=base_valid_until,
            )

        candidate_ids = [item.deployment_id for item in candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise RoutingError("ECO_ROUTING_CANDIDATE_CONFLICT", "Deployment candidates are duplicated")
        observation_map = self._observation_map(observations)
        prices = self._price_map()
        evaluations = tuple(
            self._candidate_evaluation(
                candidate,
                request=request_record,
                role=role,
                observations=observation_map,
                prices=prices,
                now=current,
                excluded=_excluded,
            )
            for candidate in candidates
        )
        eligible = sorted((item for item in evaluations if item.eligible), key=lambda item: item.rank)
        selected = eligible[0] if eligible else None
        if selected is not None and selected.evidence_valid_until is not None:
            base_valid_until = min(base_valid_until, selected.evidence_valid_until)
        return self._outcome(
            request=request_record,
            decision_id=decision_id,
            explain_id=explain_id,
            now=current,
            reason="eligible" if selected else "no-eligible-candidate",
            evaluations=evaluations,
            selected=selected,
            route_attempt=_route_attempt,
            fallback_from=_fallback_from,
            validity_limit=base_valid_until,
        )

    def fallback(
        self,
        request: Mapping[str, Any],
        previous_decision: Mapping[str, Any],
        failure_class: str,
        candidates: Sequence[DeploymentCandidate],
        observations: Sequence[Mapping[str, Any]],
        *,
        now: datetime,
        decision_id: str,
        explain_id: str,
    ) -> RoutingOutcome:
        current_time = now.astimezone(timezone.utc) if isinstance(now, datetime) and now.tzinfo else None
        if current_time is None:
            raise RoutingError("ECO_ROUTING_CLOCK_INVALID", "Routing clock must be timezone-aware")
        request_record = _safe_validate(request, "ModelRouteRequest")
        previous = _safe_validate(previous_decision, "ModelRouteDecision")
        role = self._roles[request_record["spec"]["role"]]
        previous_digest = previous["metadata"]["recordDigest"]
        selected = previous["spec"]["selected"]
        reason: str | None = None
        if (
            previous["spec"]["decision"] != "allowed"
            or previous["spec"]["requestDigest"] != request_record["metadata"]["recordDigest"]
            or previous["spec"]["policyDigest"] != self._policy_digest
            or previous["spec"]["priceCatalogDigest"] != self._price_digest
            or previous["spec"].get("executionPlanDigest")
            != request_record["spec"].get("executionPlanDigest")
            or selected is None
            or current_time >= _parse_time(previous["spec"]["validUntil"])
        ):
            reason = "fallback-not-authorized"
        elif previous["spec"]["routeAttempt"] >= role["fallback"]["maxRouteAttempts"]:
            reason = "fallback-exhausted"
        elif (
            failure_class in _NON_FALLBACK_FAILURES
            or failure_class not in _RETRYABLE_FAILURES
            or failure_class not in role["fallback"]["retryableFailureClasses"]
        ):
            reason = "fallback-not-authorized"
        else:
            current = next(
                (item for item in candidates if item.deployment_id == selected["deploymentId"]),
                None,
            )
            if current is None or current.identity_digest != selected["deploymentIdentityDigest"]:
                reason = "fallback-identity-drift"
        if reason is not None:
            return self._outcome(
                request=request_record,
                decision_id=decision_id,
                explain_id=explain_id,
                now=current_time,
                reason=reason,
                evaluations=(),
                selected=None,
                route_attempt=2,
                fallback_from=previous_digest,
                validity_limit=current_time + timedelta(microseconds=1),
            )
        return self.route(
            request_record,
            candidates,
            observations,
            now=now,
            decision_id=decision_id,
            explain_id=explain_id,
            _excluded=frozenset({selected["candidateDigest"]}),
            _route_attempt=2,
            _fallback_from=previous_digest,
        )
