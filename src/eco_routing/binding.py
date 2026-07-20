"""Exact workflow/effect binding contracts for governed model routes.

The routing records remain portable, self-digested data.  Authentication is a
separate authority boundary: callers provide a verifier that validates an
external signature/envelope and returns only the bounded attestation below.
This keeps routing independent of any particular PKI or trust-store backend.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, runtime_checkable

from eco_runtime.digests import semantic_digest

from .contracts import validate_routing_record
from .errors import RoutingError


EXECUTION_PLAN_DOMAIN = "eco-route-execution-plan-v1"
ROUTE_CONSUMER_DOMAIN = "eco-route-consumer-binding-v1"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ALGORITHM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _parse_time(value: str) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError as exc:
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority time is invalid") from exc
    if parsed.tzinfo is None:
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority time has no timezone")
    return parsed.astimezone(timezone.utc)


def route_execution_plan_digest(plan: Mapping[str, Any]) -> str:
    """Content-address one complete, secret-free execution plan."""

    if not isinstance(plan, Mapping):
        raise RoutingError("ECO_ROUTE_EXECUTION_PLAN_INVALID", "Execution plan must be an object")
    value = copy.deepcopy(dict(plan))
    if not value:
        raise RoutingError("ECO_ROUTE_EXECUTION_PLAN_INVALID", "Execution plan must not be empty")
    try:
        return semantic_digest({"domain": EXECUTION_PLAN_DOMAIN, "plan": value})
    except Exception as exc:
        raise RoutingError(
            "ECO_ROUTE_EXECUTION_PLAN_INVALID",
            "Execution plan is not canonical JSON",
        ) from exc


@dataclass(frozen=True)
class VerifiedRouteAuthority:
    """Result returned only after an external authority verifier succeeds."""

    issuer_id: str
    key_id: str
    algorithm: str
    evidence_digest: str
    route_decision_digest: str
    route_request_digest: str
    policy_digest: str
    price_catalog_digest: str
    execution_plan_digest: str
    valid_until: str

    def validate(self, *, now: datetime) -> "VerifiedRouteAuthority":
        if (
            not isinstance(self.issuer_id, str)
            or not isinstance(self.key_id, str)
            or not isinstance(self.algorithm, str)
            or _IDENTIFIER_RE.fullmatch(self.issuer_id) is None
            or _IDENTIFIER_RE.fullmatch(self.key_id) is None
            or _ALGORITHM_RE.fullmatch(self.algorithm) is None
            or any(
                not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
                for value in (
                    self.evidence_digest,
                    self.route_decision_digest,
                    self.route_request_digest,
                    self.policy_digest,
                    self.price_catalog_digest,
                    self.execution_plan_digest,
                )
            )
        ):
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority is invalid")
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RoutingError("ECO_ROUTE_CLOCK_INVALID", "Route consumption clock must be timezone-aware")
        if now.astimezone(timezone.utc) >= _parse_time(self.valid_until):
            raise RoutingError("ECO_ROUTE_AUTHORITY_EXPIRED", "Route authority is no longer valid")
        return self


@runtime_checkable
class RouteAuthorityVerifier(Protocol):
    """Trust-boundary hook implemented by an envelope/signature verifier."""

    def verify_route_authority(
        self,
        *,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        now: datetime,
    ) -> VerifiedRouteAuthority:
        """Authenticate the exact records and return bounded verified claims."""


def verify_authenticated_route_authority(
    verifier: RouteAuthorityVerifier,
    decision: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    expected_issuer_id: str,
    expected_key_id: str,
    expected_algorithm: str,
    expected_policy_digest: str,
    expected_price_catalog_digest: str,
    expected_execution_plan_digest: str,
    now: datetime,
) -> VerifiedRouteAuthority:
    """Invoke an external verifier and bind every returned claim exactly."""

    if not isinstance(verifier, RouteAuthorityVerifier):
        raise RoutingError("ECO_ROUTE_AUTHORITY_REQUIRED", "Route authority verifier is required")
    try:
        attestation = verifier.verify_route_authority(
            decision=copy.deepcopy(dict(decision)),
            request=copy.deepcopy(dict(request)),
            now=now,
        )
    except RoutingError:
        raise
    except Exception as exc:
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority verification failed") from exc
    if not isinstance(attestation, VerifiedRouteAuthority):
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority verification failed")
    attestation.validate(now=now)
    decision_digest = decision["metadata"]["recordDigest"]
    request_digest = request["metadata"]["recordDigest"]
    expected = (
        (attestation.issuer_id, expected_issuer_id),
        (attestation.key_id, expected_key_id),
        (attestation.algorithm, expected_algorithm),
        (attestation.route_decision_digest, decision_digest),
        (attestation.route_request_digest, request_digest),
        (attestation.policy_digest, expected_policy_digest),
        (attestation.price_catalog_digest, expected_price_catalog_digest),
        (attestation.execution_plan_digest, expected_execution_plan_digest),
    )
    if any(actual != wanted for actual, wanted in expected):
        raise RoutingError("ECO_ROUTE_AUTHORITY_MISMATCH", "Route authority binding is inconsistent")
    return attestation


def route_consumer_digest(
    decision: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    consumer_kind: str,
    consumer_id: str,
    effect_digest: str,
) -> str:
    """Derive the exact workflow consumer binding shared by fallback attempts.

    The decision digest is deliberately excluded: attempt one and its exact
    fallback must share this same workflow/effect binding.  The journal binds
    each individual route digest separately.
    """

    try:
        decision_record = validate_routing_record(copy.deepcopy(dict(decision)))
        request_record = validate_routing_record(copy.deepcopy(dict(request)))
    except Exception as exc:
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence is invalid") from exc
    if (
        decision_record["kind"] != "ModelRouteDecision"
        or request_record["kind"] != "ModelRouteRequest"
        or not isinstance(consumer_kind, str)
        or _IDENTIFIER_RE.fullmatch(consumer_kind) is None
        or not isinstance(consumer_id, str)
        or _IDENTIFIER_RE.fullmatch(consumer_id) is None
        or not isinstance(effect_digest, str)
        or _DIGEST_RE.fullmatch(effect_digest) is None
    ):
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route consumer binding is invalid")
    request_spec = request_record["spec"]
    decision_spec = decision_record["spec"]
    if decision_spec["decision"] != "allowed" or decision_spec["selected"] is None:
        raise RoutingError("ECO_ROUTE_NOT_ALLOWED", "Only an allowed route can be consumed")
    execution_plan_digest = request_spec.get("executionPlanDigest")
    aggregate_budget = request_spec.get("aggregateBudget")
    if execution_plan_digest is None or aggregate_budget is None:
        raise RoutingError(
            "ECO_ROUTE_EXACT_BINDING_REQUIRED",
            "Exact route binding requires an execution plan and aggregate budget",
        )
    if (
        decision_spec["requestDigest"] != request_record["metadata"]["recordDigest"]
        or decision_spec.get("executionPlanDigest") != execution_plan_digest
    ):
        raise RoutingError("ECO_ROUTE_BINDING_MISMATCH", "Route evidence binding is inconsistent")
    return semantic_digest(
        {
            "domain": ROUTE_CONSUMER_DOMAIN,
            "consumerKind": consumer_kind,
            "consumerId": consumer_id,
            "effectDigest": effect_digest,
            "executionPlanDigest": execution_plan_digest,
            "routeRequestDigest": request_record["metadata"]["recordDigest"],
            "policyDigest": decision_spec["policyDigest"],
            "priceCatalogDigest": decision_spec["priceCatalogDigest"],
            "aggregateBudget": aggregate_budget,
        }
    )


@dataclass(frozen=True)
class RouteAggregateUsage:
    """Durable counters a consumer must persist beside its governed workflow."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_microusd: int = 0


def reserve_route_effect(
    decision: Mapping[str, Any],
    request: Mapping[str, Any],
    current: RouteAggregateUsage,
    *,
    input_tokens: int,
    output_tokens: int,
    cost_microusd: int,
) -> RouteAggregateUsage:
    """Reserve one effect against both per-call and workflow aggregate ceilings.

    This function is pure.  The caller must compare-and-swap the returned
    counters in its durable workflow store before provider egress.
    """

    if not isinstance(current, RouteAggregateUsage) or any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (
            current.calls,
            current.input_tokens,
            current.output_tokens,
            current.cost_microusd,
            input_tokens,
            output_tokens,
            cost_microusd,
        )
    ):
        raise RoutingError("ECO_ROUTE_BUDGET_INVALID", "Route usage counters are invalid")
    try:
        decision_record = validate_routing_record(copy.deepcopy(dict(decision)))
        request_record = validate_routing_record(copy.deepcopy(dict(request)))
    except Exception as exc:
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence is invalid") from exc
    decision_spec = decision_record["spec"]
    request_spec = request_record["spec"]
    selected = decision_spec["selected"]
    aggregate = request_spec.get("aggregateBudget")
    if (
        decision_spec["decision"] != "allowed"
        or selected is None
        or aggregate is None
        or request_spec.get("executionPlanDigest") is None
        or decision_spec.get("executionPlanDigest") != request_spec["executionPlanDigest"]
        or decision_spec["requestDigest"] != request_record["metadata"]["recordDigest"]
        or selected.get("aggregateReservation") is None
    ):
        raise RoutingError(
            "ECO_ROUTE_EXACT_BINDING_REQUIRED",
            "Aggregate usage requires an exact allowed route",
        )
    if input_tokens > request_spec["inputTokenCeiling"] or output_tokens > request_spec[
        "outputTokenCeiling"
    ]:
        raise RoutingError("ECO_ROUTE_CALL_BUDGET_EXCEEDED", "Per-call route budget is exceeded")
    updated = RouteAggregateUsage(
        calls=current.calls + 1,
        input_tokens=current.input_tokens + input_tokens,
        output_tokens=current.output_tokens + output_tokens,
        cost_microusd=current.cost_microusd + cost_microusd,
    )
    reservation = selected["aggregateReservation"]
    if (
        reservation["maximumCalls"] != aggregate["maximumCalls"]
        or reservation["inputTokenCeiling"] != aggregate["inputTokenCeiling"]
        or reservation["outputTokenCeiling"] != aggregate["outputTokenCeiling"]
        or reservation["reservedCostMicrousd"] != selected["reservedCostMicrousd"]
        or reservation["reservedCostMicrousd"] > aggregate["maximumCostMicrousd"]
    ):
        raise RoutingError("ECO_ROUTE_BUDGET_MISMATCH", "Route aggregate reservation is inconsistent")
    if (
        updated.calls > aggregate["maximumCalls"]
        or updated.input_tokens > aggregate["inputTokenCeiling"]
        or updated.output_tokens > aggregate["outputTokenCeiling"]
        or updated.cost_microusd > aggregate["maximumCostMicrousd"]
        or updated.cost_microusd > reservation["reservedCostMicrousd"]
    ):
        raise RoutingError("ECO_ROUTE_AGGREGATE_BUDGET_EXCEEDED", "Aggregate route budget is exceeded")
    return updated
