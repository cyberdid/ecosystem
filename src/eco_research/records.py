from __future__ import annotations

import copy
import hashlib
from datetime import datetime
from typing import Any, Iterable, Mapping

from eco_runtime.digests import semantic_digest

from .contracts import (
    RESEARCH_API_VERSION,
    capability_signature,
    research_record_digest,
    seal_research_record,
    validate_research_record,
)
from .errors import fail
from .url_policy import canonical_host, normalize_url


def _metadata(
    *, record_id: str, project_id: str, team_id: str, run_id: str, created_at: str
) -> dict[str, Any]:
    return {
        "id": record_id,
        "projectId": project_id,
        "teamId": team_id,
        "runId": run_id,
        "createdAt": created_at,
        "recordDigest": "0" * 64,
    }


def build_research_policy(
    *,
    policy_id: str,
    project_id: str,
    team_id: str,
    revision: int,
    created_at: str,
    domain_rules: Iterable[Mapping[str, Any]],
    search_provider_config_digest: str,
    max_redirects: int = 3,
    max_wire_bytes: int = 2_097_152,
    max_decoded_bytes: int = 4_194_304,
    connect_timeout_ms: int = 5_000,
    read_timeout_ms: int = 15_000,
    allowed_media_types: Iterable[str] = (
        "application/json",
        "text/html",
        "text/markdown",
        "text/plain",
    ),
    allowed_query_data_classes: Iterable[str] = ("D0", "D1"),
    allowed_artifact_data_classes: Iterable[str] = ("D0", "D1", "D2", "D3"),
    allowed_egress_zones: Iterable[str] = ("Z1",),
    allowed_retentions: Iterable[str] = ("no-retention",),
    allowed_url_query_keys: Iterable[str] = (),
    max_search_results: int = 10,
) -> dict[str, Any]:
    rules = [
        {
            "host": canonical_host(str(rule["host"])),
            "includeSubdomains": bool(rule["includeSubdomains"]),
        }
        for rule in domain_rules
    ]
    record = {
        "apiVersion": RESEARCH_API_VERSION,
        "kind": "ResearchPolicy",
        "metadata": {
            **_metadata(
                record_id=policy_id,
                project_id=project_id,
                team_id=team_id,
                run_id="definition",
                created_at=created_at,
            ),
            "revision": revision,
        },
        "spec": {
            "domainRules": sorted(rules, key=lambda item: (item["host"], item["includeSubdomains"])),
            "maxRedirects": max_redirects,
            "maxWireBytes": max_wire_bytes,
            "maxDecodedBytes": max_decoded_bytes,
            "connectTimeoutMs": connect_timeout_ms,
            "readTimeoutMs": read_timeout_ms,
            "allowedMediaTypes": sorted(set(allowed_media_types)),
            "credentials": "none",
            "allowedQueryDataClasses": sorted(set(allowed_query_data_classes)),
            "allowedArtifactDataClasses": sorted(set(allowed_artifact_data_classes)),
            "allowedEgressZones": sorted(set(allowed_egress_zones)),
            "allowedRetentions": sorted(set(allowed_retentions)),
            "allowedUrlQueryKeys": sorted(set(allowed_url_query_keys)),
            "searchProviderConfigDigest": search_provider_config_digest,
            "maxSearchResults": max_search_results,
        },
    }
    return validate_research_record(seal_research_record(record))


def issue_research_capability(
    policy: Mapping[str, Any],
    *,
    capability_id: str,
    run_id: str,
    created_at: str,
    valid_from: str,
    valid_until: str,
    actions: Iterable[str],
    provider_config_digest: str,
    key: bytes,
    key_id: str,
) -> dict[str, Any]:
    trusted_policy = validate_research_record(dict(policy))
    if trusted_policy["kind"] != "ResearchPolicy":
        raise fail("ECO_RESEARCH_POLICY_INVALID", "Research policy is invalid")
    metadata = trusted_policy["metadata"]
    record = {
        "apiVersion": RESEARCH_API_VERSION,
        "kind": "ResearchCapability",
        "metadata": _metadata(
            record_id=capability_id,
            project_id=metadata["projectId"],
            team_id=metadata["teamId"],
            run_id=run_id,
            created_at=created_at,
        ),
        "spec": {
            "policyDigest": trusted_policy["metadata"]["recordDigest"],
            "providerConfigDigest": provider_config_digest,
            "actions": sorted(set(actions)),
            "validFrom": valid_from,
            "validUntil": valid_until,
            "keyId": key_id,
            "signature": "0" * 64,
        },
    }
    record["spec"]["signature"] = capability_signature(record, key)
    return validate_research_record(seal_research_record(record))


def _request(
    policy: Mapping[str, Any],
    capability: Mapping[str, Any],
    *,
    request_id: str,
    created_at: str,
    action: str,
    private_input: bytes,
    data_class: str,
    artifact_data_class: str,
    egress_zone: str,
    retention: str,
    target_host: str | None,
    requested_domains: Iterable[str],
) -> dict[str, Any]:
    trusted_policy = validate_research_record(dict(policy))
    trusted_capability = validate_research_record(dict(capability))
    if trusted_policy["kind"] != "ResearchPolicy" or trusted_capability["kind"] != "ResearchCapability":
        raise fail("ECO_RESEARCH_BINDING_INVALID", "Research request binding is invalid")
    if not isinstance(private_input, bytes) or not private_input:
        raise fail("ECO_RESEARCH_INPUT_INVALID", "Research input is invalid")
    capability_meta = trusted_capability["metadata"]
    record = {
        "apiVersion": RESEARCH_API_VERSION,
        "kind": "ResearchRequest",
        "metadata": _metadata(
            record_id=request_id,
            project_id=capability_meta["projectId"],
            team_id=capability_meta["teamId"],
            run_id=capability_meta["runId"],
            created_at=created_at,
        ),
        "spec": {
            "action": action,
            "policyDigest": trusted_policy["metadata"]["recordDigest"],
            "capabilityDigest": trusted_capability["metadata"]["recordDigest"],
            "inputDigest": hashlib.sha256(private_input).hexdigest(),
            "inputByteLength": len(private_input),
            "dataClass": data_class,
            "artifactDataClass": artifact_data_class,
            "egressZone": egress_zone,
            "retention": retention,
            "targetHost": target_host,
            "requestedDomains": sorted(set(requested_domains)),
        },
    }
    return validate_research_record(seal_research_record(record))


def build_search_request(
    policy: Mapping[str, Any],
    capability: Mapping[str, Any],
    *,
    request_id: str,
    created_at: str,
    query: bytes,
    requested_domains: Iterable[str],
    data_class: str,
    artifact_data_class: str,
    egress_zone: str,
    retention: str,
) -> dict[str, Any]:
    domains = [canonical_host(value) for value in requested_domains]
    return _request(
        policy,
        capability,
        request_id=request_id,
        created_at=created_at,
        action="research.search",
        private_input=query,
        data_class=data_class,
        artifact_data_class=artifact_data_class,
        egress_zone=egress_zone,
        retention=retention,
        target_host=None,
        requested_domains=domains,
    )


def build_fetch_request(
    policy: Mapping[str, Any],
    capability: Mapping[str, Any],
    *,
    request_id: str,
    created_at: str,
    url: str,
    data_class: str,
    artifact_data_class: str,
    egress_zone: str,
    retention: str,
    allow_test_http: bool = False,
) -> dict[str, Any]:
    normalized = normalize_url(url, allow_http=allow_test_http)
    return _request(
        policy,
        capability,
        request_id=request_id,
        created_at=created_at,
        action="research.fetch",
        private_input=normalized.value.encode("ascii"),
        data_class=data_class,
        artifact_data_class=artifact_data_class,
        egress_zone=egress_zone,
        retention=retention,
        target_host=normalized.host,
        requested_domains=(),
    )


def provider_configuration_digest(*, provider_id: str, endpoint: str) -> str:
    normalized = normalize_url(endpoint)
    return semantic_digest(
        {
            "domain": "eco-research-search-provider-config-v1",
            "providerId": provider_id,
            "endpoint": normalized.value,
            "transportProfile": "pinned-public-https-no-credentials-v1",
            "responseProfile": "strict-search-json-v1",
        }
    )


def clone_record(value: Mapping[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(dict(value))
