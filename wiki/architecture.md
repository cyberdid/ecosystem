# Current architecture

**Updated:** 2026-07-16
**Status:** bounded M1–M5 implemented; enterprise/network authority and native cross-platform security backends remain future boundaries

## TL;DR

The repository implements canonical contracts/compiler plus an embedded default-deny runtime, governed model adapters, durable Linux/WSL reads and exact-approved one-file writes, one fixed no-model loop promoted only through L2, safe project adoption, platform/distribution conformance, and a portable signed team-authority layer. M5 adds exact narrowing team access, private same-host activation/currentness, revocation, emergency recovery, dual-signed rotation and distinct-human quorum permits. It remains independent of a specific AI model or client.

## Implemented

```text
.ai YAML contracts
→ JSON Schema and cross-file validation
→ eco compiler
→ owned vendor projections
→ CI drift and unit tests
→ pure PolicyEngine
→ typed EmbeddedOrchestrator
→ SQLite event/plan/budget/operation authority
→ filesystem-only Linux broker + private artifact CAS
→ separate authenticated write authority + human approval trust store
→ Linux/WSL one-file CAS apply, rollback and restart recovery
→ trusted snapshot/observation ingestion
→ governed local/cloud adapters (observable identity boundary)
→ Linux/WSL network-denied launcher
→ signed cross-deployment evaluation
→ fixed NoModelRunPlan + private HMAC journal
→ deterministic three-page wiki health report
→ five-attempt + zero-read replay L0–L2 promotion gate
→ deterministic adoption preview + ownership receipt + reversible uninstall
→ passive platform doctor + declaration/inventory-only profiles
→ exact offline wheelhouse/lock/schema verifier + installer previews
→ explicit fixed Linux/WSL backend suite + externally signable observation
→ externally anchored signed team identity and access policy
→ private authenticated SQLite activation/revocation authority
→ distinct-human approval quorum + single-use action permits
→ emergency recovery + dual-signed successor-generation rotation
```

## Explicitly not implemented

- endpoint-specific network allowlist backend;
- Windows/macOS executable broker and isolation backends;
- Windows/macOS controlled-write backends;
- autonomous model router;
- durable replay registry for evidence envelopes;
- asymmetric evidence signatures;
- cryptographic remote issuer identity;
- enterprise WebAuthn/OIDC/SSO identity and approval service;
- caller-independent KMS/HSM/Vault anchor and secret custody;
- full-wiki link/staleness lint, scheduler, autonomous retry, and L3–L5 loop authority.
- durable adoption crash journal and hostile filesystem-race proof;
- publisher-authenticated releases, immutable installer CAS handoff and transactional multi-manager rollback;
- native Windows/macOS backend runners and runtime consumption of backend observations.
- PostgreSQL/network authority, HA/consensus and multi-region recovery;
- A3/A4 action profiles and remote transactional effect adapters.

The implemented M2–M4 boundary has negative, concurrency, process-crash, artifact, migration, backup, key-rotation, anchor, adapter, isolation, evidence, parity, exact-approval, CAS-recovery, no-model replay, state-integrity, repository-nonmutation, and promotion tests. See the [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md), [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md), and [M4 report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md).

## Current M4 vertical slice

`eco run wiki-health-check` manually verifies exactly three externally signed D0/P1 wiki pages with zero model/network/write budget. Each broker attempt has a durable `started` ambiguity fence; only pre-start recovery may reauthorize, while an uncertain post-start outcome fails without rereading. The deadline survives recovery and policy freshness advances during the run. `eco eval wiki-health-check` requires five stable independent journals and a zero-read replay, then marks only L0–L2 eligible. Reports/journals contain no raw path or content. See [M4 no-model wiki health](../docs/architecture/no-model-wiki-health.md).

## Current M4.5.1 adoption slice

`eco adopt --dry-run --json` produces a schema-valid content-minimized plan with relative paths, operation classes, digests, discovery counts, and sanitized blockers. `eco adopt --apply PLAN_SHA256` locks, recomputes, validates, preserves existing instruction bytes, and writes `.ai/adoption.json`. Fresh, pre-existing config, and reinstall ownership are distinct. Clean reinstall is a byte/mtime no-op. Full removal requires strict render state and verified backup digest/size, refuses drift/unknown/pre-existing config before mutation, and never trusts marker text alone.

Focused adoption tests run on hosted Linux, macOS, and Windows. This does not port the M2–M4 security backends. See [safe project adoption](../docs/architecture/project-adoption.md).

## Current M4.5.2 platform/adapter slice

`eco platform doctor --json` emits only coarse OS/context, allowlisted executable-name, fixed client-surface, and explicit `not-tested` semantic state. It does not invoke tools, contact adapters, read projection content, resolve credentials, mutate the repository, or create authority. `PlatformProfile` and `AdapterCapabilityProfile` are closed, digest-bound, and structurally forbid proven/effective state; existing signed runtime `AdapterConformanceProfile` remains the proof boundary. Six fixtures cover Linux, WSL, macOS, Windows, container, and hosted CI, while nested contexts and mutable-hint spoofing fail closed.

## Current M4.5.3/M4.6 portability slices

`DistributionManifest` binds a real main wheel, every dependency wheel, `uv.lock`, source revision and schema inventory. Installed and standard-library verifiers stay offline/read-only; manager adapters are preview-only, while Linux CI performs a real clean offline virtual-environment install. The manifest explicitly does not attest publisher origin, and package installation never mutates project adoption state.

`eco conformance run` is separate from passive doctor and accepts only the fixed namespace/Landlock suite in a private external root. Its content-free `PlatformBackendConformanceProfile` records narrow observations bound to platform, distribution, backend instance/implementation, runner and suite. External signing/ingestion is supported, but M4.6 has no policy/runtime consumer. Windows, macOS, container and hosted-CI profiles remain unsupported negatives. See [portable distribution](../docs/architecture/portable-distribution.md) and [backend conformance](../docs/architecture/platform-backend-conformance.md).

## Current M5 team-authority slice

Externally anchored Ed25519 bundles define exact team identities, memberships, public keys, access rules and approval profiles. A private HMAC-authenticated SQLite store establishes monotonic currentness, snapshots, revocation/emergency epochs, permit consumption and immutable audit evidence. Catalog labels alone are not actor authentication: runtime and recovery requests require an exact short-lived Ed25519 `workload-authentication` assertion. Team access is only a narrowing candidate; repository read/write effects additionally require an exact ToolRequest-bound, single-use PolicyEngine claim, optionally persisted in the runtime SQLite store. A2 uses distinct eligible human principals, authenticated requester separation and an authority-issued single-use permit; emergency disable requires a separate recovery quorum. Old+new dual-signed rotation creates a successor generation rather than rewriting history.

Contract behavior is tested on Linux/macOS/Windows; strong private-permission enforcement is POSIX-bounded. Scheduling, autonomous retry, full-wiki lint, publisher provenance, enterprise/network authority, native cross-platform runtime-security backends and every A3/A4 or L3–L5 profile remain separate future gates. See [M5 team authority](../docs/architecture/team-authority.md) and the [completion report](../docs/research/2026-07-16-m5-team-authority-completion-report.md).

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Safe project adoption](../docs/architecture/project-adoption.md)
- [Platform and adapter conformance](../docs/architecture/platform-adapter-conformance.md)
- [Portable distribution](../docs/architecture/portable-distribution.md)
- [Platform backend conformance](../docs/architecture/platform-backend-conformance.md)
- [M5 team authority](../docs/architecture/team-authority.md)
- [M5 operations runbook](../docs/operations/team-authority-runbook.md)
- [Roadmap](roadmap.md)
