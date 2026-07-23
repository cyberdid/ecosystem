from __future__ import annotations

import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from eco_orchestration.contracts import orchestration_record_digest, validate_orchestration_record
from eco_research import (
    GovernedResearchBroker,
    ResearchToolError,
    SafeHttpsTransport,
    SearchHit,
    SearchProviderResponse,
    TransportResponse,
    build_fetch_request,
    build_research_policy,
    build_search_request,
    decode_bounded_entity,
    issue_research_capability,
    research_schema_bundle_digest,
    seal_research_record,
    source_bundle_entry_from_research_artifact,
)
from eco_research.broker import SearchProvider
from eco_research.errors import fail
from eco_research.transport import ResearchTransportPolicy, strict_bounded_json
from eco_research.url_policy import (
    host_allowed,
    normalize_url,
    resolve_public_addresses,
    validate_url_query,
)
from eco_runtime.artifact_store import ContentAddressedArtifactStore


NOW = datetime(2026, 7, 17, 10, 0, 0, tzinfo=timezone.utc)
NOW_TEXT = "2026-07-17T10:00:00Z"
PROVIDER_DIGEST = "a" * 64
CAPABILITY_KEY = b"research-capability-test-key-value!"


class _FakeTransport:
    test_only_allow_http = True

    def __init__(self, response: TransportResponse | None = None, error: ResearchToolError | None = None):
        self.response = response or TransportResponse(
            body=b"trusted transport, untrusted content",
            media_type="text/plain",
            source_url="https://docs.example.com/source",
            final_url="https://docs.example.com/source",
            redirect_chain=(),
        )
        self.error = error
        self.calls = 0

    def request(self, *, method: str, url: str, body: bytes | None, policy: ResearchTransportPolicy) -> TransportResponse:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.response


class _FakeProvider:
    test_only = True
    configuration_digest = PROVIDER_DIGEST
    provider_identity_digest = "b" * 64

    def __init__(self, hits: tuple[SearchHit, ...] | None = None):
        self.hits = hits or (
            SearchHit("https://docs.example.com/result", "Result", "Untrusted snippet"),
        )
        self.calls = 0

    def search(self, query: str, *, max_results: int, policy: ResearchTransportPolicy) -> SearchProviderResponse:
        self.calls += 1
        return SearchProviderResponse(
            hits=self.hits,
            source_url="https://search.example.com/api",
            final_url="https://search.example.com/api",
            redirect_chain=(),
        )


class _CountingStore(ContentAddressedArtifactStore):
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.put_calls = 0
        super().__init__(*args, **kwargs)

    def put(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        self.put_calls += 1
        return super().put(*args, **kwargs)


class GovernedResearchToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = _CountingStore(
            self.root / "cas",
            proof_key=b"artifact-proof-key-for-research-tests",
            key_id="research-test-cas",
        )
        self.policy = build_research_policy(
            policy_id="research-policy",
            project_id="project",
            team_id="team",
            revision=1,
            created_at=NOW_TEXT,
            domain_rules=(
                {"host": "docs.example.com", "includeSubdomains": True},
                {"host": "search.example.com", "includeSubdomains": False},
            ),
            search_provider_config_digest=PROVIDER_DIGEST,
            max_wire_bytes=1024,
            max_decoded_bytes=2048,
        )
        self.capability = issue_research_capability(
            self.policy,
            capability_id="research-capability",
            run_id="run",
            created_at=NOW_TEXT,
            valid_from="2026-07-17T09:00:00Z",
            valid_until="2026-07-17T11:00:00Z",
            actions=("research.fetch", "research.search"),
            provider_config_digest=PROVIDER_DIGEST,
            key=CAPABILITY_KEY,
            key_id="research-key",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def _broker(
        self,
        *,
        policy=None,
        capability=None,
        transport=None,
        provider=None,
    ) -> GovernedResearchBroker:
        return GovernedResearchBroker(
            policy=policy or self.policy,
            capability=capability or self.capability,
            capability_key=CAPABILITY_KEY,
            capability_key_id="research-key",
            artifact_store=self.store,
            search_provider=provider,
            fetch_transport=transport or _FakeTransport(),
            now=lambda: NOW,
            allow_test_adapters=True,
        )

    def _fetch_request(self, url: str = "https://docs.example.com/source", **overrides: str):
        values = {
            "data_class": "D0",
            "artifact_data_class": "D0",
            "egress_zone": "Z1",
            "retention": "no-retention",
        }
        values.update(overrides)
        return build_fetch_request(
            self.policy,
            self.capability,
            request_id="fetch-request",
            created_at=NOW_TEXT,
            url=url,
            **values,
        )

    def _search_request(self, query: bytes = b"bounded research question", **overrides: str):
        values = {
            "data_class": "D0",
            "artifact_data_class": "D0",
            "egress_zone": "Z1",
            "retention": "no-retention",
        }
        values.update(overrides)
        return build_search_request(
            self.policy,
            self.capability,
            request_id="search-request",
            created_at=NOW_TEXT,
            query=query,
            requested_domains=("docs.example.com",),
            **values,
        )

    def test_schema_bundle_digest_is_pinned(self) -> None:
        self.assertEqual(
            research_schema_bundle_digest(),
            "b7a1d821c8682874336938795e9467486e067e1485f5f8fcee0d598f4f47dd00",
        )

    def test_domain_matching_uses_label_boundary(self) -> None:
        rules = [{"host": "example.com", "includeSubdomains": True}]
        self.assertTrue(host_allowed("a.example.com", rules))
        self.assertFalse(host_allowed("example.com.evil.test", rules))
        self.assertFalse(host_allowed("notexample.com", rules))

    def test_url_denies_userinfo_unicode_and_non_https_but_normalizes_case(self) -> None:
        self.assertEqual(normalize_url("HTTPS://DOCS.EXAMPLE.COM/a").host, "docs.example.com")
        for value in (
            "https://user:password@docs.example.com/a",
            "http://docs.example.com/a",
            "https://döcs.example.com/a",
        ):
            with self.subTest(value=value), self.assertRaises(ResearchToolError):
                normalize_url(value)

    def test_query_policy_is_exact_and_denies_sensitive_keys(self) -> None:
        validate_url_query("https://docs.example.com/a?page=1", allowed_keys=("page",))
        for value, allowed in (
            ("https://docs.example.com/a?token=secret", ("token",)),
            ("https://docs.example.com/a?page=1&page=2", ("page",)),
            ("https://docs.example.com/a?other=1", ("page",)),
        ):
            with self.subTest(value=value), self.assertRaises(ResearchToolError):
                validate_url_query(value, allowed_keys=allowed)

    def test_private_loopback_linklocal_and_mixed_dns_answers_are_denied(self) -> None:
        def answer(*_: object, **__: object):
            return [
                (2, 1, 6, "", ("93.184.216.34", 443)),
                (2, 1, 6, "", ("127.0.0.1", 443)),
            ]

        for host in ("localhost", "127.0.0.1", "169.254.169.254"):
            with self.subTest(host=host), self.assertRaises(ResearchToolError):
                resolve_public_addresses(host)
        with self.assertRaises(ResearchToolError):
            resolve_public_addresses("docs.example.com", resolver=answer)

    def test_wire_and_decompression_limits_are_independent(self) -> None:
        with self.assertRaises(ResearchToolError) as oversized:
            decode_bounded_entity(
                (b"1234", b"5678"),
                content_encoding="identity",
                max_wire_bytes=7,
                max_decoded_bytes=20,
            )
        self.assertEqual(oversized.exception.code, "ECO_RESEARCH_WIRE_LIMIT")
        compressed = gzip.compress(b"x" * 4096)
        with self.assertRaises(ResearchToolError) as bomb:
            decode_bounded_entity(
                (compressed,),
                content_encoding="gzip",
                max_wire_bytes=len(compressed),
                max_decoded_bytes=128,
            )
        self.assertEqual(bomb.exception.code, "ECO_RESEARCH_DECODED_LIMIT")

    def test_json_depth_is_bounded_and_error_is_sanitized(self) -> None:
        nested = ("[" * 80 + "0" + "]" * 80).encode()
        with self.assertRaises(ResearchToolError) as caught:
            strict_bounded_json(nested, maximum_depth=16)
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_JSON_LIMIT")
        self.assertNotIn("[[[[", str(caught.exception))

    def test_absolute_read_deadline_is_checked_before_each_chunk(self) -> None:
        values = iter((0.0, 0.5, 2.0))
        transport = SafeHttpsTransport(monotonic=lambda: next(values))

        class Sock:
            def settimeout(self, _: float) -> None:
                pass

        class Connection:
            sock = Sock()

        class Response:
            calls = 0

            def read(self, _: int) -> bytes:
                self.calls += 1
                return b"a" if self.calls == 1 else b"b"

        with self.assertRaises(ResearchToolError) as caught:
            list(transport._chunks(Response(), connection=Connection(), deadline=1.0))  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_TIMEOUT")

    def test_forged_capability_is_denied_before_transport_or_cas(self) -> None:
        forged = copy.deepcopy(self.capability)
        forged["spec"]["actions"] = ["research.fetch"]
        forged = seal_research_record(forged)
        transport = _FakeTransport()
        with self.assertRaises(ResearchToolError) as caught:
            self._broker(capability=forged, transport=transport)
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_TRUST_INVALID")
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.store.put_calls, 0)

    def test_forged_policy_is_denied_by_signed_binding(self) -> None:
        forged = copy.deepcopy(self.policy)
        forged["spec"]["domainRules"] = [
            {"host": "evil.example", "includeSubdomains": True}
        ]
        forged = seal_research_record(forged)
        with self.assertRaises(ResearchToolError) as caught:
            self._broker(policy=forged)
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_BINDING_INVALID")
        self.assertEqual(self.store.put_calls, 0)

    def test_expired_capability_denies_before_effect(self) -> None:
        broker = GovernedResearchBroker(
            policy=self.policy,
            capability=self.capability,
            capability_key=CAPABILITY_KEY,
            capability_key_id="research-key",
            artifact_store=self.store,
            fetch_transport=_FakeTransport(),
            now=lambda: datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc),
            allow_test_adapters=True,
        )
        with self.assertRaises(ResearchToolError) as caught:
            broker.fetch(self._fetch_request(), url="https://docs.example.com/source")
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_CAPABILITY_EXPIRED")
        self.assertEqual(self.store.put_calls, 0)

    def test_query_and_egress_classification_are_enforced_before_provider(self) -> None:
        provider = _FakeProvider()
        broker = self._broker(provider=provider)
        request = self._search_request(data_class="D2", artifact_data_class="D2")
        with self.assertRaises(ResearchToolError) as caught:
            broker.search(request, query=b"bounded research question")
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_DATA_CLASS_DENIED")
        self.assertEqual(provider.calls, 0)
        self.assertEqual(self.store.put_calls, 0)

    def test_artifact_class_cannot_be_lower_than_private_input(self) -> None:
        with self.assertRaises(Exception):
            self._search_request(data_class="D1", artifact_data_class="D0")
        self.assertEqual(self.store.put_calls, 0)

    def test_fetch_publishes_exactly_one_provenance_bound_untrusted_artifact(self) -> None:
        transport = _FakeTransport()
        result = self._broker(transport=transport).fetch(
            self._fetch_request(), url="https://docs.example.com/source"
        )
        self.assertEqual(transport.calls, 1)
        self.assertEqual(self.store.put_calls, 1)
        self.store.verify_availability(result.proof)
        self.assertTrue(result.record["spec"]["untrusted"])
        self.assertEqual(result.record["spec"]["artifact"]["contentDigest"], result.proof.sha256)
        public = json.dumps(result.record, sort_keys=True)
        self.assertNotIn("trusted transport", public)
        self.assertNotIn("/source", public)

    def test_text_fetch_projects_to_a_valid_source_bundle_entry(self) -> None:
        result = self._broker().fetch(
            self._fetch_request(), url="https://docs.example.com/source"
        )
        entry = source_bundle_entry_from_research_artifact(result.record, source_id="question")
        bundle = {
            "apiVersion": "orchestration.ai.ecosystem/v1alpha1",
            "kind": "SourceBundle",
            "metadata": {
                "id": "web-bundle", "projectId": "project", "teamId": "team",
                "runId": "run", "createdAt": NOW_TEXT, "recordDigest": "0" * 64,
            },
            "spec": {
                "ingestionPolicyDigest": self.policy["metadata"]["recordDigest"],
                "dataClass": "D0", "questionEntryId": "question",
                "totalByteLength": result.proof.byte_length, "entries": [entry],
            },
        }
        bundle["metadata"]["recordDigest"] = orchestration_record_digest(bundle)
        validate_orchestration_record(bundle)

    def test_html_fetch_requires_separate_normalization(self) -> None:
        response = TransportResponse(
            body=b"<html><body>untrusted</body></html>", media_type="text/html",
            source_url="https://docs.example.com/source",
            final_url="https://docs.example.com/source", redirect_chain=(),
        )
        result = self._broker(transport=_FakeTransport(response)).fetch(
            self._fetch_request(), url="https://docs.example.com/source"
        )
        with self.assertRaises(ResearchToolError) as caught:
            source_bundle_entry_from_research_artifact(result.record, source_id="web")
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_SOURCE_MEDIA_UNSUPPORTED")

    def test_wrong_media_invalid_utf8_and_oversize_do_not_write(self) -> None:
        responses = (
            TransportResponse(b"binary", "application/octet-stream", "https://docs.example.com/a", "https://docs.example.com/a", ()),
            TransportResponse(b"\xff", "text/plain", "https://docs.example.com/a", "https://docs.example.com/a", ()),
            TransportResponse(b"x" * 2049, "text/plain", "https://docs.example.com/a", "https://docs.example.com/a", ()),
        )
        for response in responses:
            with self.subTest(media=response.media_type), self.assertRaises(ResearchToolError):
                self._broker(transport=_FakeTransport(response)).fetch(
                    self._fetch_request("https://docs.example.com/a"),
                    url="https://docs.example.com/a",
                )
        self.assertEqual(self.store.put_calls, 0)

    def test_redirect_escape_and_loop_are_denied_before_write(self) -> None:
        responses = (
            TransportResponse(b"x", "text/plain", "https://docs.example.com/a", "https://evil.example/b", ("https://evil.example/b",)),
            TransportResponse(b"x", "text/plain", "https://docs.example.com/a", "https://docs.example.com/a", ("https://docs.example.com/a",)),
        )
        for response in responses:
            with self.subTest(final=response.final_url), self.assertRaises(ResearchToolError):
                self._broker(transport=_FakeTransport(response)).fetch(
                    self._fetch_request("https://docs.example.com/a"),
                    url="https://docs.example.com/a",
                )
        self.assertEqual(self.store.put_calls, 0)

    def test_search_filters_suffix_confusion_and_does_not_publish_hits(self) -> None:
        provider = _FakeProvider(
            (SearchHit("https://docs.example.com.evil.test/result", "Bad", "Bad"),)
        )
        with self.assertRaises(ResearchToolError) as caught:
            self._broker(provider=provider).search(
                self._search_request(), query=b"bounded research question"
            )
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_SEARCH_RESULT_DENIED")
        self.assertEqual(self.store.put_calls, 0)

    def test_search_result_is_private_cas_json_and_typed_hits_remain_untrusted(self) -> None:
        provider = _FakeProvider()
        result = self._broker(provider=provider).search(
            self._search_request(), query=b"bounded research question"
        )
        self.assertEqual(provider.calls, 1)
        self.assertEqual(self.store.put_calls, 1)
        self.assertEqual(result.search_hits[0].snippet, "Untrusted snippet")
        self.assertNotIn("Untrusted snippet", json.dumps(result.record))
        with self.store.open_verified(result.proof) as stream:
            persisted = json.load(stream)
        self.assertTrue(persisted["untrusted"])
        self.assertEqual(persisted["hits"][0]["url"], "https://docs.example.com/result")

    def test_input_path_endpoint_and_transport_failure_are_not_leaked(self) -> None:
        secret_url = "https://docs.example.com/private/customer-42"
        transport = _FakeTransport(error=fail("ECO_RESEARCH_TIMEOUT", "Research request timed out"))
        with self.assertRaises(ResearchToolError) as caught:
            self._broker(transport=transport).fetch(
                self._fetch_request(secret_url), url=secret_url
            )
        self.assertEqual(caught.exception.code, "ECO_RESEARCH_TIMEOUT")
        self.assertNotIn("customer-42", str(caught.exception))
        self.assertNotIn("docs.example.com", str(caught.exception))
        self.assertEqual(self.store.put_calls, 0)

    def test_repository_bytes_and_mtime_are_unchanged(self) -> None:
        repository_file = Path(__file__).resolve().parents[1] / "README.md"
        before = (hashlib.sha256(repository_file.read_bytes()).hexdigest(), repository_file.stat().st_mtime_ns)
        self._broker().fetch(self._fetch_request(), url="https://docs.example.com/source")
        after = (hashlib.sha256(repository_file.read_bytes()).hexdigest(), repository_file.stat().st_mtime_ns)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
