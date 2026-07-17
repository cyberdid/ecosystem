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
from .errors import RoutingError
from .router import (
    DeploymentCandidate,
    DeterministicModelRouter,
    RoutingOutcome,
    candidates_from_deployment_catalog,
)

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
    "RoutingError",
    "DeploymentCandidate",
    "DeterministicModelRouter",
    "RoutingOutcome",
    "candidates_from_deployment_catalog",
]
