from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import RuntimePolicyError

DIGEST_PROFILE = "eco-python-json-v1"


def canonical_json(value: Any) -> str:
    """Serialize JSON-compatible data deterministically and reject non-finite values."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimePolicyError(
            "ECO_CANONICALIZATION_FAILED",
            "Value cannot be represented by the canonical JSON profile",
        ) from exc


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def deployment_identity_payload(deployment: dict[str, Any]) -> dict[str, Any]:
    identity = deployment.get("identity")
    required_identity = {
        "adapterVersion",
        "modelRevision",
        "runtimeEngine",
        "runtimeVersion",
        "quantization",
        "endpointReferenceDigest",
    }
    if not isinstance(identity, dict) or required_identity - set(identity):
        raise RuntimePolicyError(
            "ECO_IDENTITY_INCOMPLETE",
            "Deployment identity is incomplete",
        )
    required = {"id", "provider", "adapter", "model", "endpointRef"}
    if required - set(deployment):
        raise RuntimePolicyError(
            "ECO_IDENTITY_INCOMPLETE",
            "Deployment identity is incomplete",
        )
    endpoint_ref = deployment["endpointRef"]
    if not isinstance(endpoint_ref, str) or not endpoint_ref.startswith(("env:", "config:", "secret://")):
        raise RuntimePolicyError(
            "ECO_IDENTITY_INCOMPLETE",
            "Deployment endpoint must be a typed reference",
        )
    expected_endpoint_digest = semantic_digest({"endpointRef": endpoint_ref})
    if identity["endpointReferenceDigest"] != expected_endpoint_digest:
        raise RuntimePolicyError(
            "ECO_IDENTITY_MISMATCH",
            "Deployment endpoint reference digest does not match its reference",
        )
    return {
        "id": deployment["id"],
        "provider": deployment["provider"],
        "adapter": deployment["adapter"],
        "model": deployment["model"],
        "endpointRef": endpoint_ref,
        "identity": {name: identity[name] for name in sorted(required_identity)},
    }


def deployment_identity_digest(deployment: dict[str, Any]) -> str:
    return semantic_digest(deployment_identity_payload(deployment))
