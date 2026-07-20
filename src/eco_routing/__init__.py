"""Additive M6.4 logical model roles and deterministic routing."""

from .contracts import (
    CANONICAL_MODEL_ROLES,
    ROUTING_API_VERSION,
    ROUTING_CONTRACT_PROFILE,
    ROUTING_SCHEMA_BY_KIND,
    routing_contract_errors,
    routing_record_digest,
    routing_schema_bundle_digest,
    seal_routing_record,
    validate_routing_record,
)
from .binding import (
    EXECUTION_PLAN_DOMAIN,
    ROUTE_CONSUMER_DOMAIN,
    RouteAggregateUsage,
    RouteAuthorityVerifier,
    VerifiedRouteAuthority,
    route_consumer_digest,
    route_execution_plan_digest,
    reserve_route_effect,
    verify_authenticated_route_authority,
)
from .authority import (
    MAX_ROUTE_AUTHORITY_BYTES,
    ROUTE_AUTHORITY_PROTOCOL,
    Ed25519RouteAuthoritySigner,
    Ed25519RouteAuthorityVerifier,
)
from .consumption import (
    DurableRouteConsumptionJournal,
    verify_exact_route_binding,
    verify_route_binding,
)
from .errors import RoutingError
from .router import (
    DeploymentCandidate,
    DeterministicModelRouter,
    RoutingOutcome,
    candidates_from_deployment_catalog,
)
from .usage import DurableRouteUsageJournal

__all__ = [
    "CANONICAL_MODEL_ROLES",
    "ROUTING_API_VERSION",
    "ROUTING_CONTRACT_PROFILE",
    "ROUTING_SCHEMA_BY_KIND",
    "routing_contract_errors",
    "routing_record_digest",
    "routing_schema_bundle_digest",
    "seal_routing_record",
    "validate_routing_record",
    "EXECUTION_PLAN_DOMAIN",
    "ROUTE_CONSUMER_DOMAIN",
    "RouteAggregateUsage",
    "RouteAuthorityVerifier",
    "VerifiedRouteAuthority",
    "route_consumer_digest",
    "route_execution_plan_digest",
    "reserve_route_effect",
    "verify_authenticated_route_authority",
    "MAX_ROUTE_AUTHORITY_BYTES",
    "ROUTE_AUTHORITY_PROTOCOL",
    "Ed25519RouteAuthoritySigner",
    "Ed25519RouteAuthorityVerifier",
    "RoutingError",
    "DurableRouteConsumptionJournal",
    "DurableRouteUsageJournal",
    "DeploymentCandidate",
    "DeterministicModelRouter",
    "RoutingOutcome",
    "candidates_from_deployment_catalog",
    "verify_route_binding",
    "verify_exact_route_binding",
]
