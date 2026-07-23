# M6.7 governed research tools

**Status:** implemented and release-gated as a bounded embedded broker
**Updated:** 2026-07-20
**Contract:** `research.ai.ecosystem/v1alpha1`

## Outcome

M6.7 adds a narrow brokered boundary for public-web search and fetch. It does not
give an agent a browser, socket, credential, arbitrary URL tool or authority to
trust retrieved text. The trusted caller must provide an exact policy, an
HMAC-authenticated capability bound to that policy and provider configuration,
and a content-free request whose digest matches the private query or URL bytes.

The result is always an immutable private-CAS object and a content-free
`ResearchArtifact` record marked `untrusted: true`. A model, role, loop or team
may cite and analyze those bytes later, but the bytes cannot change a role,
route, policy, tool set, gate or terminal state.

```text
operator ResearchPolicy
        │ exact digest
        ▼
HMAC ResearchCapability ── exact namespace/action/provider/validity
        │
        ▼
ResearchRequest + private query/URL bytes
        │ digest, class, zone, retention and domain checks
        ▼
GovernedResearchBroker
        ├── typed exact search provider
        └── pinned public-HTTPS fetch transport
                    │
                    ▼
     bounded UTF-8 bytes → private CAS
                    │
                    ▼
 content-free provenance-bound ResearchArtifact (untrusted)
```

## Additive records

| Kind | Purpose | Content boundary |
|---|---|---|
| `ResearchPolicy` | Exact domains, subdomain rule, redirects, wire/decoded bytes, media, timeouts, query classes, artifact classes, egress zones, retention, URL query keys and search-provider digest | No endpoint, query, path or content |
| `ResearchCapability` | HMAC-authenticated action, namespace, policy, provider, key and validity binding | No credential or private input |
| `ResearchRequest` | Exact action and private-input digest/length plus D/Z/retention scope | Fetch hostname is present; URL path/query and search query are absent |
| `ResearchArtifact` | Immutable CAS binding and digest-only URL/redirect/provider provenance | No source bytes, URL, path, snippet or endpoint |

The research schema registry is independent of the pinned M4/M5 runtime registry.
Its current bundle digest is
`b7a1d821c8682874336938795e9467486e067e1485f5f8fcee0d598f4f47dd00`.

## Domain, URL and credential policy

- Production network operations are HTTPS-only on port 443.
- Userinfo, fragments, controls, backslashes, malformed percent encodings,
  non-canonical host labels and Unicode URL spellings are denied. Canonical
  lower-case A-label hosts may be used explicitly.
- Domain matching is label-aware. `a.example.com` may match an explicit
  subdomain rule; `example.com.evil.test` and `notexample.com` cannot.
- URL query keys use an exact policy allowlist. Duplicate, unlisted and
  credential-like keys (`token`, `secret`, `signature`, `authorization`, and
  related label forms) are denied even if accidentally listed. Query values
  remain private and are represented only by the exact URL digest.
- `credentials` is fixed to `none`. The transport constructs its own headers and
  does not use environment proxies, cookies, authorization headers, browser
  sessions or cloud credential discovery.
- A configured JSON search provider is identified by a digest of its exact HTTPS
  endpoint and provider ID. Production composition accepts only the package-owned
  `JsonSearchProvider`; injected providers/transports require the explicit
  `allow_test_adapters` test boundary.

## Transport boundary

`SafeHttpsTransport` performs a fresh policy check on every redirect. It resolves
each host, rejects the complete answer set if any address is loopback, private,
link-local, multicast, reserved or otherwise non-global, pins one accepted IP for
the TCP connection, and preserves TLS SNI/hostname verification. The implementation
does not consult proxy environment variables.

The response is bounded independently by:

- maximum redirect count and loop detection;
- one owned absolute request deadline plus a connect limit and remaining-deadline
  socket timeout before every read;
- header bytes, declared/chunked transfer bytes and decompressed bytes;
- `identity`, `gzip` or `deflate` only;
- an exact media allowlist, strict UTF-8 and NUL denial;
- duplicate/non-finite JSON denial plus maximum JSON depth, item count and string
  bytes.

Every transport/provider exception becomes a fixed code and generic message. Raw
URLs, paths, queries, endpoints, response bodies and exception text do not enter
control-plane records or errors.

## Search and fetch semantics

Search accepts a bounded UTF-8 query only when its data class, requested domains,
egress zone and retention are all allowed. Output classification can equal or
exceed private-input classification, never downgrade it. The provider returns a
closed JSON shape. Result URLs are canonicalized and rechecked against both the
requested domain set and policy domain rules. Titles, snippets and URLs are
serialized as an untrusted JSON object in private CAS; the public record contains
only its artifact and provenance digests.

Fetch binds the exact private canonical URL bytes to the request digest and target
hostname. The broker rechecks the source URL, every redirect and final URL before
publishing exactly one CAS artifact. `text/plain`, `text/markdown` and
`application/json` artifacts can be projected into the existing `SourceBundle`
entry shape with `provenance.kind=research-web`. `text/html` stays immutable in
CAS but requires a separately governed HTML-to-text normalization step before it
can enter source review.

## Security and test evidence

The focused suite covers contract digests, forged policy/capability bindings,
expiry and namespace/action checks, classification non-downgrade, suffix confusion,
userinfo/IDNA/case handling, query credentials, localhost/private/link-local/
metadata/mixed DNS answers, redirect escape/loops, wire/chunk/decompression limits,
wrong media, invalid UTF-8, deep JSON, absolute read deadlines, P/D/Z/retention
denial, provider mismatch, sanitized failures, exactly one CAS publication and
repository byte/mtime identity.

Deterministic tests use explicit injected transports/providers and perform no live
network access. They prove broker and contract behavior, not the availability,
quality, neutrality or truthfulness of a real search service.

## Exact non-claims

M6.7 does **not** claim unrestricted web access, arbitrary endpoints, authenticated
browser sessions, cookies, OAuth/API keys, browser rendering/JavaScript, file
downloads, binary/PDF parsing, Tor/VPN behavior, universal SSRF prevention,
protection from a compromised DNS/kernel/network/public proxy, distributed replay
protection, durable per-capability use counters, semantic truth, prompt-injection
immunity or safe HTML interpretation. It grants no model, shell, workspace-write,
external-write or memory-promotion authority. Real-provider observations and
M6.8 integrated release evidence remain separate gates.

## Related material

- [Functional orchestration architecture](functional-orchestration.md)
- [M6 threat model](m6-functional-orchestration-threat-model.md)
- [M6 research and implementation plan](../research/2026-07-17-m6.0-functional-orchestration-plan.md)
