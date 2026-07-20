"""Ed25519 authority envelopes for exact governed model routes."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from eco_runtime.digests import canonical_json

from .binding import VerifiedRouteAuthority
from .contracts import validate_routing_record
from .errors import RoutingError


ROUTE_AUTHORITY_PROTOCOL = "eco-route-authority-v1"
ROUTE_AUTHORITY_DOMAIN = "eco-route-authority-signature-v1"
MAX_ROUTE_AUTHORITY_BYTES = 262_144
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RoutingError("ECO_ROUTE_CLOCK_INVALID", "Route authority clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except ValueError as exc:
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority time is invalid") from exc
    if parsed.tzinfo is None:
        raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority time has no timezone")
    return parsed.astimezone(timezone.utc)


def _auth_bytes(body: Mapping[str, Any]) -> bytes:
    return canonical_json(
        {"domain": ROUTE_AUTHORITY_DOMAIN, "payload": dict(body)}
    ).encode("utf-8")


def _bindings(decision: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, str]:
    try:
        decision_record = validate_routing_record(copy.deepcopy(dict(decision)))
        request_record = validate_routing_record(copy.deepcopy(dict(request)))
    except Exception as exc:
        raise RoutingError("ECO_ROUTE_EVIDENCE_INVALID", "Route evidence is invalid") from exc
    if (
        decision_record["kind"] != "ModelRouteDecision"
        or request_record["kind"] != "ModelRouteRequest"
        or decision_record["spec"]["requestDigest"]
        != request_record["metadata"]["recordDigest"]
        or decision_record["spec"].get("executionPlanDigest") is None
        or request_record["spec"].get("executionPlanDigest")
        != decision_record["spec"]["executionPlanDigest"]
    ):
        raise RoutingError("ECO_ROUTE_EXACT_BINDING_REQUIRED", "Exact route evidence is required")
    return {
        "routeDecisionDigest": decision_record["metadata"]["recordDigest"],
        "routeRequestDigest": request_record["metadata"]["recordDigest"],
        "policyDigest": decision_record["spec"]["policyDigest"],
        "priceCatalogDigest": decision_record["spec"]["priceCatalogDigest"],
        "executionPlanDigest": decision_record["spec"]["executionPlanDigest"],
    }


class Ed25519RouteAuthoritySigner:
    """Offline/operator signer; private key material never enters route records."""

    def __init__(self, issuer_id: str, key_id: str, private_key: bytes) -> None:
        if (
            not isinstance(issuer_id, str)
            or not isinstance(key_id, str)
            or _IDENTIFIER_RE.fullmatch(issuer_id) is None
            or _IDENTIFIER_RE.fullmatch(key_id) is None
            or not isinstance(private_key, bytes)
            or len(private_key) != 32
        ):
            raise ValueError("route authority signer configuration is invalid")
        self._issuer_id = issuer_id
        self._key_id = key_id
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key)

    def sign(
        self,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        *,
        envelope_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> bytes:
        if not isinstance(envelope_id, str) or _IDENTIFIER_RE.fullmatch(envelope_id) is None:
            raise ValueError("route authority envelope id is invalid")
        issued = _parse_time(_utc(issued_at))
        expiry = _parse_time(_utc(expires_at))
        if expiry <= issued:
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority window is invalid")
        body = {
            "protocol": ROUTE_AUTHORITY_PROTOCOL,
            "envelopeId": envelope_id,
            "issuer": {"id": self._issuer_id, "keyId": self._key_id},
            "issuedAt": _utc(issued),
            "validUntil": _utc(expiry),
            "bindings": _bindings(decision, request),
        }
        signature = self._private_key.sign(_auth_bytes(body))
        return canonical_json(
            {
                **body,
                "signature": {
                    "algorithm": "Ed25519",
                    "value": base64.b64encode(signature).decode("ascii"),
                },
            }
        ).encode("utf-8")


class Ed25519RouteAuthorityVerifier:
    """Public-key verifier implementing the routing authority protocol hook."""

    def __init__(self, encoded: bytes, public_key: bytes) -> None:
        if (
            not isinstance(encoded, bytes)
            or len(encoded) > MAX_ROUTE_AUTHORITY_BYTES
            or not isinstance(public_key, bytes)
            or len(public_key) != 32
        ):
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority input is invalid")
        self._encoded = bytes(encoded)
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)

    def verify_route_authority(
        self,
        *,
        decision: Mapping[str, Any],
        request: Mapping[str, Any],
        now: datetime,
    ) -> VerifiedRouteAuthority:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RoutingError("ECO_ROUTE_CLOCK_INVALID", "Route authority clock must be timezone-aware")
        try:
            envelope = json.loads(self._encoded.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority envelope is unreadable") from exc
        if (
            not isinstance(envelope, dict)
            or canonical_json(envelope).encode("utf-8") != self._encoded
            or set(envelope)
            != {
                "protocol",
                "envelopeId",
                "issuer",
                "issuedAt",
                "validUntil",
                "bindings",
                "signature",
            }
            or envelope.get("protocol") != ROUTE_AUTHORITY_PROTOCOL
        ):
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority envelope is invalid")
        issuer = envelope.get("issuer")
        bindings = envelope.get("bindings")
        signature = envelope.get("signature")
        if (
            not isinstance(envelope.get("envelopeId"), str)
            or _IDENTIFIER_RE.fullmatch(envelope["envelopeId"]) is None
            or not isinstance(issuer, dict)
            or set(issuer) != {"id", "keyId"}
            or any(
                not isinstance(issuer.get(name), str)
                or _IDENTIFIER_RE.fullmatch(issuer[name]) is None
                for name in ("id", "keyId")
            )
            or not isinstance(bindings, dict)
            or set(bindings)
            != {
                "routeDecisionDigest",
                "routeRequestDigest",
                "policyDigest",
                "priceCatalogDigest",
                "executionPlanDigest",
            }
            or not isinstance(signature, dict)
            or set(signature) != {"algorithm", "value"}
            or signature.get("algorithm") != "Ed25519"
            or not isinstance(signature.get("value"), str)
        ):
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority envelope is invalid")
        expected = _bindings(decision, request)
        if bindings != expected:
            raise RoutingError("ECO_ROUTE_AUTHORITY_MISMATCH", "Route authority binding is inconsistent")
        body = {key: value for key, value in envelope.items() if key != "signature"}
        try:
            raw_signature = base64.b64decode(signature["value"], validate=True)
            if base64.b64encode(raw_signature).decode("ascii") != signature["value"]:
                raise ValueError
            self._public_key.verify(raw_signature, _auth_bytes(body))
        except (InvalidSignature, ValueError) as exc:
            raise RoutingError("ECO_ROUTE_AUTHORITY_INVALID", "Route authority signature is invalid") from exc
        issued = _parse_time(envelope["issuedAt"])
        valid_until = _parse_time(envelope["validUntil"])
        current = now.astimezone(timezone.utc)
        if (
            valid_until <= issued
            or issued > current + timedelta(seconds=300)
            or current >= valid_until
        ):
            raise RoutingError("ECO_ROUTE_AUTHORITY_EXPIRED", "Route authority is no longer valid")
        return VerifiedRouteAuthority(
            issuer_id=issuer["id"],
            key_id=issuer["keyId"],
            algorithm="ed25519",
            evidence_digest=hashlib.sha256(self._encoded).hexdigest(),
            route_decision_digest=bindings["routeDecisionDigest"],
            route_request_digest=bindings["routeRequestDigest"],
            policy_digest=bindings["policyDigest"],
            price_catalog_digest=bindings["priceCatalogDigest"],
            execution_plan_digest=bindings["executionPlanDigest"],
            valid_until=envelope["validUntil"],
        ).validate(now=now)
