from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import ContractValidationError


RESEARCH_API_VERSION = "research.ai.ecosystem/v1alpha1"
RESEARCH_CONTRACT_PROFILE = "governed-research-contracts-v1alpha1"
RESEARCH_RECORD_DOMAIN = "eco-governed-research-record-v1alpha1"
RESEARCH_CAPABILITY_DOMAIN = "eco-governed-research-capability-v1alpha1"
RESEARCH_PROVENANCE_DOMAIN = "eco-governed-research-provenance-v1alpha1"
RESEARCH_SCHEMA_BY_KIND = {
    "ResearchPolicy": "research-policy.schema.json",
    "ResearchCapability": "research-capability.schema.json",
    "ResearchRequest": "research-request.schema.json",
    "ResearchArtifact": "research-artifact.schema.json",
}
_COMMON_SCHEMA = "common.schema.json"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _is_canonical_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.microsecond == 0


def _load_schema_file(name: str) -> dict[str, Any]:
    source = resources.files("eco_research").joinpath("schemas", name)
    return json.loads(source.read_text(encoding="utf-8"))


def _registry() -> Registry:
    schemas = [_load_schema_file(_COMMON_SCHEMA)] + [
        _load_schema_file(name) for name in RESEARCH_SCHEMA_BY_KIND.values()
    ]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def research_schema_bundle_digest() -> str:
    return semantic_digest(
        {
            "profile": RESEARCH_CONTRACT_PROFILE,
            "common": _load_schema_file(_COMMON_SCHEMA),
            "records": {
                kind: _load_schema_file(RESEARCH_SCHEMA_BY_KIND[kind])
                for kind in sorted(RESEARCH_SCHEMA_BY_KIND)
            },
        }
    )


def research_record_digest(record: Mapping[str, Any]) -> str:
    projected = copy.deepcopy(dict(record))
    metadata = projected.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("recordDigest", None)
    return semantic_digest(
        {
            "domain": RESEARCH_RECORD_DOMAIN,
            "profile": RESEARCH_CONTRACT_PROFILE,
            "record": projected,
        }
    )


def seal_research_record(record: Mapping[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(dict(record))
    sealed.setdefault("metadata", {})["recordDigest"] = research_record_digest(sealed)
    return sealed


def _path(parts: Iterable[Any]) -> str:
    result = "$"
    for part in parts:
        result += f"[{part}]" if isinstance(part, int) else f".{part}"
    return result


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _canonical_host(value: str) -> bool:
    if not isinstance(value, str) or not value or value != value.lower():
        return False
    if value.endswith(".") or ".." in value:
        return False
    try:
        return value.encode("idna").decode("ascii") == value
    except UnicodeError:
        return False


def research_provenance_digest(
    *,
    request_digest: str,
    policy_digest: str,
    capability_digest: str,
    artifact: Mapping[str, Any],
    media_type: str,
    source_url_digest: str,
    final_url_digest: str,
    redirect_chain_digests: Iterable[str],
    retrieved_at: str,
    provider_identity_digest: str,
) -> str:
    return semantic_digest(
        {
            "domain": RESEARCH_PROVENANCE_DOMAIN,
            "profile": RESEARCH_CONTRACT_PROFILE,
            "requestDigest": request_digest,
            "policyDigest": policy_digest,
            "capabilityDigest": capability_digest,
            "artifact": copy.deepcopy(dict(artifact)),
            "mediaType": media_type,
            "sourceUrlDigest": source_url_digest,
            "finalUrlDigest": final_url_digest,
            "redirectChainDigests": list(redirect_chain_digests),
            "retrievedAt": retrieved_at,
            "providerIdentityDigest": provider_identity_digest,
            "untrusted": True,
        }
    )


def _semantic_errors(kind: str, document: dict[str, Any]) -> list[str]:
    metadata = document["metadata"]
    spec = document["spec"]
    errors: list[str] = []
    if metadata["recordDigest"] != research_record_digest(document):
        errors.append(f"{kind}$.metadata.recordDigest: failed validation")

    if kind == "ResearchPolicy":
        if metadata["runId"] != "definition" or "revision" not in metadata:
            errors.append(f"{kind}$.metadata.runId: failed validation")
        rules = spec["domainRules"]
        if rules != sorted(rules, key=lambda item: (item["host"], item["includeSubdomains"])):
            errors.append(f"{kind}$.spec.domainRules: failed validation")
        if len({item["host"] for item in rules}) != len(rules):
            errors.append(f"{kind}$.spec.domainRules: failed validation")
        if any(not _canonical_host(item["host"]) for item in rules):
            errors.append(f"{kind}$.spec.domainRules: failed validation")
        for field in (
            "allowedMediaTypes",
            "allowedQueryDataClasses",
            "allowedArtifactDataClasses",
            "allowedEgressZones",
            "allowedRetentions",
            "allowedUrlQueryKeys",
        ):
            if spec[field] != sorted(spec[field]):
                errors.append(f"{kind}$.spec.{field}: failed validation")

    elif kind == "ResearchCapability":
        if "revision" in metadata:
            errors.append(f"{kind}$.metadata.revision: failed validation")
        if spec["actions"] != sorted(spec["actions"]):
            errors.append(f"{kind}$.spec.actions: failed validation")
        if _timestamp(spec["validUntil"]) <= _timestamp(spec["validFrom"]):
            errors.append(f"{kind}$.spec.validUntil: failed validation")

    elif kind == "ResearchRequest":
        if "revision" in metadata:
            errors.append(f"{kind}$.metadata.revision: failed validation")
        requested = spec["requestedDomains"]
        if requested != sorted(requested) or len(requested) != len(set(requested)):
            errors.append(f"{kind}$.spec.requestedDomains: failed validation")
        if any(not _canonical_host(host) for host in requested):
            errors.append(f"{kind}$.spec.requestedDomains: failed validation")
        data_rank = {"D0": 0, "D1": 1, "D2": 2, "D3": 3}
        if data_rank[spec["artifactDataClass"]] < data_rank[spec["dataClass"]]:
            errors.append(f"{kind}$.spec.artifactDataClass: failed validation")
        if spec["action"] == "research.search":
            if spec["targetHost"] is not None or not requested:
                errors.append(f"{kind}$.spec.targetHost: failed validation")
        else:
            if not isinstance(spec["targetHost"], str) or requested:
                errors.append(f"{kind}$.spec.targetHost: failed validation")
            elif not _canonical_host(spec["targetHost"]):
                errors.append(f"{kind}$.spec.targetHost: failed validation")

    elif kind == "ResearchArtifact":
        if "revision" in metadata:
            errors.append(f"{kind}$.metadata.revision: failed validation")
        provenance = spec["provenance"]
        redirects = provenance["redirectChainDigests"]
        if len(redirects) != len(set(redirects)):
            errors.append(f"{kind}$.spec.provenance.redirectChainDigests: failed validation")
        expected = research_provenance_digest(
            request_digest=spec["requestDigest"],
            policy_digest=spec["policyDigest"],
            capability_digest=spec["capabilityDigest"],
            artifact=spec["artifact"],
            media_type=spec["mediaType"],
            source_url_digest=provenance["sourceUrlDigest"],
            final_url_digest=provenance["finalUrlDigest"],
            redirect_chain_digests=redirects,
            retrieved_at=provenance["retrievedAt"],
            provider_identity_digest=provenance["providerIdentityDigest"],
        )
        if provenance["provenanceDigest"] != expected:
            errors.append(f"{kind}$.spec.provenance.provenanceDigest: failed validation")
    return errors


def research_contract_errors(document: Any) -> list[str]:
    if not isinstance(document, dict):
        return ["ResearchRecord$: failed validation"]
    kind = document.get("kind")
    if kind not in RESEARCH_SCHEMA_BY_KIND:
        return ["ResearchRecord$.kind: failed validation"]
    schema = _load_schema_file(RESEARCH_SCHEMA_BY_KIND[kind])
    validator = Draft202012Validator(
        schema, registry=_registry(), format_checker=_FORMAT_CHECKER
    )
    errors = [
        f"{kind}{_path(error.absolute_path)}: failed validation"
        for error in sorted(
            validator.iter_errors(document), key=lambda item: list(item.absolute_path)
        )
    ]
    if not errors:
        errors.extend(_semantic_errors(kind, document))
    return errors


def validate_research_record(document: Any) -> dict[str, Any]:
    errors = research_contract_errors(document)
    if errors:
        raise ContractValidationError(errors)
    return copy.deepcopy(document)


def _capability_payload(capability: Mapping[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(dict(capability))
    projected.get("metadata", {}).pop("recordDigest", None)
    projected.get("spec", {}).pop("signature", None)
    return {
        "domain": RESEARCH_CAPABILITY_DOMAIN,
        "profile": RESEARCH_CONTRACT_PROFILE,
        "capability": projected,
    }


def capability_signature(capability: Mapping[str, Any], key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("capability key must contain at least 32 bytes")
    return hmac.new(
        key,
        canonical_json(_capability_payload(capability)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def authenticate_capability(
    capability: Mapping[str, Any], *, key: bytes, key_id: str
) -> dict[str, Any]:
    validated = validate_research_record(dict(capability))
    if validated["kind"] != "ResearchCapability":
        raise ContractValidationError(["ResearchCapability$.kind: failed validation"])
    if validated["spec"]["keyId"] != key_id:
        raise ContractValidationError(["ResearchCapability$.spec.keyId: failed validation"])
    expected = capability_signature(validated, key)
    if not hmac.compare_digest(expected, validated["spec"]["signature"]):
        raise ContractValidationError(["ResearchCapability$.spec.signature: failed validation"])
    return validated


def utc_now_seconds() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None
