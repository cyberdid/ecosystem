from __future__ import annotations

import hashlib
import io
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol, Sequence

from eco_runtime.artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import ContractValidationError

from .contracts import (
    RESEARCH_API_VERSION,
    authenticate_capability,
    research_provenance_digest,
    seal_research_record,
    validate_research_record,
)
from .errors import ResearchToolError, fail
from .records import provider_configuration_digest
from .transport import (
    ResearchTransport,
    ResearchTransportPolicy,
    SafeHttpsTransport,
    TransportResponse,
    strict_bounded_json,
)
from .url_policy import host_allowed, normalize_url, validate_url_query


@dataclass(frozen=True)
class SearchHit:
    url: str
    title: str
    snippet: str


@dataclass(frozen=True)
class SearchProviderResponse:
    hits: tuple[SearchHit, ...]
    source_url: str
    final_url: str
    redirect_chain: tuple[str, ...]


class SearchProvider(Protocol):
    configuration_digest: str
    provider_identity_digest: str
    test_only: bool

    def search(
        self,
        query: str,
        *,
        max_results: int,
        policy: ResearchTransportPolicy,
    ) -> SearchProviderResponse: ...


@dataclass(frozen=True)
class ResearchArtifactResult:
    record: dict[str, Any]
    proof: ArtifactAvailabilityProof
    search_hits: tuple[SearchHit, ...] = ()


def _bounded_text(value: Any, *, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid") from exc
    if len(encoded) > maximum_bytes:
        raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
    return value


class JsonSearchProvider:
    """Exact, credential-free JSON search endpoint behind the safe transport.

    The endpoint must accept a POST body ``{"maxResults": n, "query": text}``
    and return exactly ``{"results": [{"url", "title", "snippet"}, ...]}``.
    No environment credentials, cookies, proxy settings, arbitrary headers or
    provider-specific executable adapters are loaded.
    """

    test_only = False

    def __init__(
        self,
        *,
        provider_id: str,
        endpoint: str,
        transport: ResearchTransport | None = None,
    ) -> None:
        self._provider_id = provider_id
        self._endpoint = normalize_url(endpoint).value
        self._transport = transport or SafeHttpsTransport()
        if not isinstance(self._transport, SafeHttpsTransport):
            raise ValueError("production search provider requires the HTTPS transport profile")
        self.configuration_digest = provider_configuration_digest(
            provider_id=provider_id, endpoint=self._endpoint
        )
        self.provider_identity_digest = semantic_digest(
            {
                "domain": "eco-research-provider-identity-v1",
                "providerId": provider_id,
                "configurationDigest": self.configuration_digest,
            }
        )

    def search(
        self,
        query: str,
        *,
        max_results: int,
        policy: ResearchTransportPolicy,
    ) -> SearchProviderResponse:
        request = canonical_json({"maxResults": max_results, "query": query}).encode("utf-8")
        response = self._transport.request(
            method="POST", url=self._endpoint, body=request, policy=policy
        )
        try:
            document = strict_bounded_json(
                response.body,
                maximum_depth=5,
                maximum_items=max_results * 4 + 2,
                maximum_string_bytes=8192,
            )
        except ResearchToolError as exc:
            raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid") from exc
        if not isinstance(document, dict) or set(document) != {"results"}:
            raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
        values = document["results"]
        if not isinstance(values, list) or len(values) > max_results:
            raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
        hits: list[SearchHit] = []
        for value in values:
            if not isinstance(value, dict) or set(value) != {"url", "title", "snippet"}:
                raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
            hits.append(
                SearchHit(
                    url=_bounded_text(value["url"], maximum_bytes=8192),
                    title=_bounded_text(value["title"], maximum_bytes=512),
                    snippet=_bounded_text(value["snippet"], maximum_bytes=4096),
                )
            )
        return SearchProviderResponse(
            hits=tuple(hits),
            source_url=response.source_url,
            final_url=response.final_url,
            redirect_chain=response.redirect_chain,
        )


class GovernedResearchBroker:
    """Trusted search/fetch boundary; returned bytes are immutable untrusted artifacts."""

    def __init__(
        self,
        *,
        policy: Mapping[str, Any],
        capability: Mapping[str, Any],
        capability_key: bytes,
        capability_key_id: str,
        artifact_store: ContentAddressedArtifactStore,
        search_provider: SearchProvider | None = None,
        fetch_transport: ResearchTransport | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        allow_test_adapters: bool = False,
    ) -> None:
        try:
            self._policy = validate_research_record(dict(policy))
            self._capability = authenticate_capability(
                capability, key=capability_key, key_id=capability_key_id
            )
        except ContractValidationError as exc:
            raise fail("ECO_RESEARCH_TRUST_INVALID", "Research trust input is invalid") from exc
        if self._policy["kind"] != "ResearchPolicy":
            raise fail("ECO_RESEARCH_POLICY_INVALID", "Research policy is invalid")
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be ContentAddressedArtifactStore")
        policy_meta = self._policy["metadata"]
        capability_meta = self._capability["metadata"]
        capability_spec = self._capability["spec"]
        if (
            capability_spec["policyDigest"] != policy_meta["recordDigest"]
            or policy_meta["projectId"] != capability_meta["projectId"]
            or policy_meta["teamId"] != capability_meta["teamId"]
            or capability_spec["providerConfigDigest"]
            != self._policy["spec"]["searchProviderConfigDigest"]
        ):
            raise fail("ECO_RESEARCH_BINDING_INVALID", "Research trust binding is invalid")
        if search_provider is not None:
            if search_provider.configuration_digest != capability_spec["providerConfigDigest"]:
                raise fail("ECO_RESEARCH_PROVIDER_MISMATCH", "Research provider binding is invalid")
            if getattr(search_provider, "test_only", True) and not allow_test_adapters:
                raise fail("ECO_RESEARCH_TEST_ADAPTER_DENIED", "Test research adapter is denied")
        self._transport = fetch_transport or SafeHttpsTransport()
        if not allow_test_adapters and not isinstance(self._transport, SafeHttpsTransport):
            raise fail("ECO_RESEARCH_TEST_ADAPTER_DENIED", "Test research adapter is denied")
        if not allow_test_adapters and search_provider is not None and not isinstance(
            search_provider, JsonSearchProvider
        ):
            raise fail("ECO_RESEARCH_TEST_ADAPTER_DENIED", "Test research adapter is denied")
        self._provider = search_provider
        self._store = artifact_store
        self._now = now
        self._allow_test_adapters = allow_test_adapters
        self._lock = threading.RLock()

    def _transport_policy(self) -> ResearchTransportPolicy:
        spec = self._policy["spec"]
        return ResearchTransportPolicy(
            domain_rules=tuple(dict(item) for item in spec["domainRules"]),
            max_redirects=spec["maxRedirects"],
            max_wire_bytes=spec["maxWireBytes"],
            max_decoded_bytes=spec["maxDecodedBytes"],
            connect_timeout_seconds=spec["connectTimeoutMs"] / 1000.0,
            read_timeout_seconds=spec["readTimeoutMs"] / 1000.0,
            allowed_media_types=frozenset(spec["allowedMediaTypes"]),
            allowed_url_query_keys=frozenset(spec["allowedUrlQueryKeys"]),
        )

    def _authorize(
        self, request: Mapping[str, Any], *, action: str, private_input: bytes
    ) -> dict[str, Any]:
        try:
            trusted = validate_research_record(dict(request))
        except ContractValidationError as exc:
            raise fail("ECO_RESEARCH_REQUEST_INVALID", "Research request is invalid") from exc
        if trusted["kind"] != "ResearchRequest" or trusted["spec"]["action"] != action:
            raise fail("ECO_RESEARCH_ACTION_DENIED", "Research action is denied")
        request_meta = trusted["metadata"]
        capability_meta = self._capability["metadata"]
        request_spec = trusted["spec"]
        capability_spec = self._capability["spec"]
        if (
            any(
                request_meta[field] != capability_meta[field]
                for field in ("projectId", "teamId", "runId")
            )
            or request_spec["policyDigest"] != self._policy["metadata"]["recordDigest"]
            or request_spec["capabilityDigest"] != capability_meta["recordDigest"]
        ):
            raise fail("ECO_RESEARCH_BINDING_INVALID", "Research request binding is invalid")
        if action not in capability_spec["actions"]:
            raise fail("ECO_RESEARCH_CAPABILITY_DENIED", "Research capability denies the action")
        now = self._now()
        if now.tzinfo is None:
            raise RuntimeError("owned research clock must be timezone-aware")
        created = datetime.fromisoformat(request_meta["createdAt"][:-1] + "+00:00")
        valid_from = datetime.fromisoformat(capability_spec["validFrom"][:-1] + "+00:00")
        valid_until = datetime.fromisoformat(capability_spec["validUntil"][:-1] + "+00:00")
        if created > now or now < valid_from or now >= valid_until:
            raise fail("ECO_RESEARCH_CAPABILITY_EXPIRED", "Research capability is not currently valid")
        if (
            not isinstance(private_input, bytes)
            or not private_input
            or len(private_input) != request_spec["inputByteLength"]
            or hashlib.sha256(private_input).hexdigest() != request_spec["inputDigest"]
        ):
            raise fail("ECO_RESEARCH_INPUT_MISMATCH", "Research private input does not match")
        policy_spec = self._policy["spec"]
        if request_spec["dataClass"] not in policy_spec["allowedQueryDataClasses"]:
            raise fail("ECO_RESEARCH_DATA_CLASS_DENIED", "Research input data class is denied")
        if request_spec["artifactDataClass"] not in policy_spec["allowedArtifactDataClasses"]:
            raise fail("ECO_RESEARCH_DATA_CLASS_DENIED", "Research artifact data class is denied")
        data_rank = {"D0": 0, "D1": 1, "D2": 2, "D3": 3}
        if data_rank[request_spec["artifactDataClass"]] < data_rank[request_spec["dataClass"]]:
            raise fail("ECO_RESEARCH_DATA_CLASS_DENIED", "Research artifact data class is denied")
        if request_spec["egressZone"] not in policy_spec["allowedEgressZones"]:
            raise fail("ECO_RESEARCH_EGRESS_DENIED", "Research egress zone is denied")
        if request_spec["retention"] not in policy_spec["allowedRetentions"]:
            raise fail("ECO_RESEARCH_RETENTION_DENIED", "Research retention is denied")
        domains = (
            request_spec["requestedDomains"]
            if action == "research.search"
            else [request_spec["targetHost"]]
        )
        if any(not host_allowed(host, policy_spec["domainRules"]) for host in domains):
            raise fail("ECO_RESEARCH_DOMAIN_DENIED", "Research target domain is denied")
        return trusted

    def _validate_response(
        self,
        response: TransportResponse,
        *,
        action: str,
        expected_source_url: str | None = None,
    ) -> TransportResponse:
        policy = self._transport_policy()
        allow_http = self._allow_test_adapters and getattr(
            self._transport, "test_only_allow_http", False
        )
        source = normalize_url(response.source_url, allow_http=allow_http)
        final = normalize_url(response.final_url, allow_http=allow_http)
        redirects = tuple(
            normalize_url(item, allow_http=allow_http).value
            for item in response.redirect_chain
        )
        validate_url_query(
            source.value, allowed_keys=self._policy["spec"]["allowedUrlQueryKeys"]
        )
        validate_url_query(
            final.value, allowed_keys=self._policy["spec"]["allowedUrlQueryKeys"]
        )
        for item in redirects:
            validate_url_query(
                item, allowed_keys=self._policy["spec"]["allowedUrlQueryKeys"]
            )
        if expected_source_url is not None and source.value != expected_source_url:
            raise fail("ECO_RESEARCH_TRANSPORT_INVALID", "Research transport response is invalid")
        if (
            len(redirects) > policy.max_redirects
            or len(set((source.value, *redirects))) != len((source.value, *redirects))
            or (redirects and redirects[-1] != final.value)
            or (not redirects and source.value != final.value)
        ):
            raise fail("ECO_RESEARCH_REDIRECT_INVALID", "Research redirect provenance is invalid")
        if any(
            not host_allowed(item.host, policy.domain_rules)
            for item in (
                source,
                final,
                *(normalize_url(value, allow_http=allow_http) for value in redirects),
            )
        ):
            raise fail("ECO_RESEARCH_DOMAIN_DENIED", "Research response domain is denied")
        if response.media_type not in policy.allowed_media_types:
            raise fail("ECO_RESEARCH_MEDIA_DENIED", "Research response media type is denied")
        if not response.body or len(response.body) > policy.max_decoded_bytes or b"\x00" in response.body:
            raise fail("ECO_RESEARCH_DECODED_LIMIT", "Research response exceeds the decoded limit")
        try:
            response.body.decode("utf-8", errors="strict")
            if response.media_type == "application/json":
                strict_bounded_json(response.body)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError, ResearchToolError) as exc:
            raise fail("ECO_RESEARCH_CONTENT_INVALID", "Research response content is invalid") from exc
        return TransportResponse(
            body=response.body,
            media_type=response.media_type,
            source_url=source.value,
            final_url=final.value,
            redirect_chain=redirects,
        )

    def _publish(
        self,
        request: dict[str, Any],
        *,
        body: bytes,
        media_type: str,
        source_url: str,
        final_url: str,
        redirects: Sequence[str],
        provider_identity_digest: str,
        search_hits: tuple[SearchHit, ...] = (),
    ) -> ResearchArtifactResult:
        request_spec = request["spec"]
        proof = self._store.put(
            io.BytesIO(body),
            expected_sha256=hashlib.sha256(body).hexdigest(),
            expected_byte_length=len(body),
            max_bytes=self._policy["spec"]["maxDecodedBytes"],
        )
        now = self._now()
        retrieved_at = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        artifact = {
            "ref": proof.storage_ref,
            "contentDigest": proof.sha256,
            "byteLength": proof.byte_length,
            "dataClass": request_spec["artifactDataClass"],
        }
        source_digest = hashlib.sha256(source_url.encode("ascii")).hexdigest()
        final_digest = hashlib.sha256(final_url.encode("ascii")).hexdigest()
        redirect_digests = [
            hashlib.sha256(value.encode("ascii")).hexdigest() for value in redirects
        ]
        provenance_digest = research_provenance_digest(
            request_digest=request["metadata"]["recordDigest"],
            policy_digest=request_spec["policyDigest"],
            capability_digest=request_spec["capabilityDigest"],
            artifact=artifact,
            media_type=media_type,
            source_url_digest=source_digest,
            final_url_digest=final_digest,
            redirect_chain_digests=redirect_digests,
            retrieved_at=retrieved_at,
            provider_identity_digest=provider_identity_digest,
        )
        record_id = f"research-artifact-{request['metadata']['recordDigest'][:16]}"
        record = {
            "apiVersion": RESEARCH_API_VERSION,
            "kind": "ResearchArtifact",
            "metadata": {
                "id": record_id,
                "projectId": request["metadata"]["projectId"],
                "teamId": request["metadata"]["teamId"],
                "runId": request["metadata"]["runId"],
                "createdAt": retrieved_at,
                "recordDigest": "0" * 64,
            },
            "spec": {
                "requestDigest": request["metadata"]["recordDigest"],
                "policyDigest": request_spec["policyDigest"],
                "capabilityDigest": request_spec["capabilityDigest"],
                "action": request_spec["action"],
                "artifact": artifact,
                "mediaType": media_type,
                "encoding": "utf-8",
                "untrusted": True,
                "provenance": {
                    "sourceUrlDigest": source_digest,
                    "finalUrlDigest": final_digest,
                    "redirectChainDigests": redirect_digests,
                    "retrievedAt": retrieved_at,
                    "providerIdentityDigest": provider_identity_digest,
                    "provenanceDigest": provenance_digest,
                },
            },
        }
        return ResearchArtifactResult(
            validate_research_record(seal_research_record(record)), proof, search_hits
        )

    def fetch(self, request: Mapping[str, Any], *, url: str) -> ResearchArtifactResult:
        allow_http = self._allow_test_adapters and getattr(
            self._transport, "test_only_allow_http", False
        )
        normalized = normalize_url(url, allow_http=allow_http)
        validate_url_query(
            normalized.value, allowed_keys=self._policy["spec"]["allowedUrlQueryKeys"]
        )
        with self._lock:
            trusted = self._authorize(
                request, action="research.fetch", private_input=normalized.value.encode("ascii")
            )
            if trusted["spec"]["targetHost"] != normalized.host:
                raise fail("ECO_RESEARCH_BINDING_INVALID", "Research request binding is invalid")
            response = self._transport.request(
                method="GET", url=normalized.value, body=None, policy=self._transport_policy()
            )
            response = self._validate_response(
                response,
                action="research.fetch",
                expected_source_url=normalized.value,
            )
            identity = semantic_digest(
                {
                    "domain": "eco-research-fetch-transport-identity-v1",
                    "profile": (
                        "explicit-test-transport-v1"
                        if getattr(self._transport, "test_only_allow_http", False)
                        else "pinned-public-https-no-credentials-v1"
                    ),
                }
            )
            return self._publish(
                trusted,
                body=response.body,
                media_type=response.media_type,
                source_url=response.source_url,
                final_url=response.final_url,
                redirects=response.redirect_chain,
                provider_identity_digest=identity,
            )

    def search(self, request: Mapping[str, Any], *, query: bytes) -> ResearchArtifactResult:
        with self._lock:
            trusted = self._authorize(request, action="research.search", private_input=query)
            if self._provider is None:
                raise fail("ECO_RESEARCH_PROVIDER_UNAVAILABLE", "Research search provider is unavailable")
            if "application/json" not in self._policy["spec"]["allowedMediaTypes"]:
                raise fail("ECO_RESEARCH_MEDIA_DENIED", "Research search media type is denied")
            if len(query) > 16_384 or b"\x00" in query:
                raise fail("ECO_RESEARCH_INPUT_LIMIT", "Research query exceeds the input limit")
            try:
                text = query.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise fail("ECO_RESEARCH_INPUT_INVALID", "Research query is invalid") from exc
            if not text.strip():
                raise fail("ECO_RESEARCH_INPUT_INVALID", "Research query is invalid")
            provider_response = self._provider.search(
                text,
                max_results=self._policy["spec"]["maxSearchResults"],
                policy=self._transport_policy(),
            )
            allow_http = self._allow_test_adapters and self._provider.test_only
            hits: list[SearchHit] = []
            requested = trusted["spec"]["requestedDomains"]
            for hit in provider_response.hits:
                normalized = normalize_url(hit.url, allow_http=allow_http)
                validate_url_query(
                    normalized.value,
                    allowed_keys=self._policy["spec"]["allowedUrlQueryKeys"],
                )
                if not any(
                    normalized.host == domain or normalized.host.endswith("." + domain)
                    for domain in requested
                ):
                    raise fail("ECO_RESEARCH_SEARCH_RESULT_DENIED", "Research search result domain is denied")
                if not host_allowed(normalized.host, self._policy["spec"]["domainRules"]):
                    raise fail("ECO_RESEARCH_SEARCH_RESULT_DENIED", "Research search result domain is denied")
                hits.append(
                    SearchHit(
                        normalized.value,
                        _bounded_text(hit.title, maximum_bytes=512),
                        _bounded_text(hit.snippet, maximum_bytes=4096),
                    )
                )
            if len(hits) > self._policy["spec"]["maxSearchResults"]:
                raise fail("ECO_RESEARCH_PROVIDER_RESPONSE_INVALID", "Research provider response is invalid")
            serialized = canonical_json(
                {
                    "hits": [
                        {"snippet": item.snippet, "title": item.title, "url": item.url}
                        for item in hits
                    ],
                    "untrusted": True,
                }
            ).encode("utf-8")
            transport_response = self._validate_response(
                TransportResponse(
                    body=serialized,
                    media_type="application/json",
                    source_url=provider_response.source_url,
                    final_url=provider_response.final_url,
                    redirect_chain=provider_response.redirect_chain,
                ),
                action="research.search",
            )
            return self._publish(
                trusted,
                body=serialized,
                media_type="application/json",
                source_url=transport_response.source_url,
                final_url=transport_response.final_url,
                redirects=transport_response.redirect_chain,
                provider_identity_digest=self._provider.provider_identity_digest,
                search_hits=tuple(hits),
            )


def source_bundle_entry_from_research_artifact(
    record: Mapping[str, Any], *, source_id: str
) -> dict[str, Any]:
    """Project a fetched text artifact into the existing SourceBundle entry shape.

    HTML intentionally requires a separately governed normalization step. This
    function copies only immutable artifact metadata and web provenance; it
    never loads bytes and never interprets retrieved content as instructions.
    """

    trusted = validate_research_record(dict(record))
    if trusted["kind"] != "ResearchArtifact" or trusted["spec"]["action"] != "research.fetch":
        raise fail("ECO_RESEARCH_SOURCE_ARTIFACT_INVALID", "Research source artifact is invalid")
    if trusted["spec"]["mediaType"] not in {"application/json", "text/markdown", "text/plain"}:
        raise fail("ECO_RESEARCH_SOURCE_MEDIA_UNSUPPORTED", "Research source media requires normalization")
    return {
        "id": source_id,
        "artifact": dict(trusted["spec"]["artifact"]),
        "mediaType": trusted["spec"]["mediaType"],
        "encoding": "utf-8",
        "provenance": {
            "kind": "research-web",
            "provenanceDigest": trusted["spec"]["provenance"]["provenanceDigest"],
            "remoteIdentityDigest": None,
            "commitDigest": None,
        },
    }
