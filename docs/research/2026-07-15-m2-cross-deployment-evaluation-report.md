# M2 cross-deployment evaluation report

**Status:** deterministic runner and one live governed local/cloud proof implemented

**Date:** 2026-07-15

## Outcome

The ecosystem runs one immutable evaluation suite through governed deployments using a narrow vendor-neutral protocol. It emits schema-valid `AdapterConformanceProfile` observations and canonical HMAC-authenticated evidence containing suite identity, declared/observable deployment identity digests, normalized output digests, normalized usage, pairwise comparison, and observation digests.

The live reference run passed on:

- local: Ollama 0.32.0, `qwen3:0.6b`, manifest `sha256:7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`;
- cloud: broker-owned Claude Code CLI 2.1.202, recorded executable `sha256:7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6`, primary routing alias `claude-sonnet-5`.

Before invocation, the local adapter queries Ollama's loopback `/api/tags` inventory and requires the exact configured manifest digest. The script hashes the Claude CLI executable, compares it with the operator-pinned digest, and the adapter hashes it again immediately before invocation. The cloud model value remains a provider routing alias: the evidence does not attest immutable Claude weights, tokenizer, serving stack, auxiliary models, or backend build. The identity digest proves stability of the observable retained identity record, not independent provider attestation of every provider-internal value.

The suite digest is `08d7ee84c62d53c3ae08419623b48cfb6d645fe8c127ddcd090295e194826dd6`. The passing aggregate evidence digest is `1c7e8d1a08006c6606cc734b83f94d5a2df7082a0985a48a820a1fb8c9e46927`. The authenticated publication-manifest digest is `fabdb4d726139cf01a821648182c99bd38437efac2e3c8c7f9076095de48d624`.

Closure evidence is retained under `.ai/evals/live/2026-07-15-m2-closure-pass/`. Publication is staged and uses OS-level atomic no-replace semantics. `publication-manifest.json` authenticates the exact bytes of all other files, including the sanitized RunRequest, RunPlan, PolicyDecision, trust receipt, and policy-gate receipt. Files remain administratively mutable on disk, but any change is detectable with the externally retained HMAC key. Earlier sibling directories are historical or superseded attempts and have no current promotion authority. The signing key is not stored in Git.

## Identical-run contract

For each deployment, the runner hands the adapter the same frozen `EvaluationRequest`: suite digest, case ID, input text, zero-temperature request, and seed. Ollama applies temperature and seed directly. Claude CLI does not expose equivalent seed/temperature controls, so the proof establishes identical suite input and exact-output conformance, not deterministic provider inference. The suite identity binds an input digest, expected normalized-output digest, and explicit usage tolerance. Raw input is never written to observations or signed evidence.

Output normalization is deliberately narrow: CRLF/CR becomes LF and Unicode becomes NFC. Case, whitespace, punctuation, line count, and other text differences remain visible. Usage is normalized to non-negative integer input, output, total tokens, and request count. Any tolerance is explicit in the suite.

## Adapter boundary

The mock-independent runtime adapters cover:

- one pinned loopback OpenAI-compatible profile;
- one pinned direct-cloud HTTPS profile;
- credential-free model invocation objects;
- transport-owned cloud credentials;
- exact model, adapter, endpoint-reference, and resolved-endpoint binding;
- bounded timeout, output, response, and usage handling;
- one-shot invocation with no automatic fallback.

Live evaluation uses two reference adapters:

- `OllamaEvaluationAdapter`, restricted to a literal loopback endpoint;
- `ClaudeCliEvaluationAdapter`, which sends the prompt over stdin, disables tools, browser integration, slash commands, and session persistence, pins the model, limits budget, and passes only an allowlisted environment without API-key/token variables.

The Claude CLI is used as a trusted provider transport process, not as an autonomous agent. Its OS-managed authentication remains inside that provider client. User/project/local setting sources are disabled, MCP configuration is forced empty and strict, tools/hooks from those sources are excluded, and the executable is hashed both before and after invocation. Admin-managed provider policy and OS authentication remain part of the trusted client boundary.

## Sanitized signed evidence

Evidence excludes raw prompt and response bodies, endpoint URLs, provider bodies, exceptions, credentials, paths, usernames, session IDs, and UUIDs. A post-run scan found none of these values. It still contains D0 metadata and deterministic output digests, so the precise claim is **raw-content-free D0 evidence**, not information-free evidence. A plain digest of a low-entropy value can be guessed; non-public suites require a keyed digest or an explicit disclosure policy. HMAC-SHA256 authenticates canonical JSON with a locally retained 32-byte key.

HMAC provides embedded authentication, not third-party non-repudiation. Aggregate evaluation, derived-key trusted observations, and the final publication manifest use separate authentication domains. The manifest retains the full sanitized policy-gate records, so their digests and decision/plan binding can be replayed independently when the external key is available. Team or remote verification will require asymmetric signatures or an authenticated verification service in a later milestone.

## Verification

Automated tests cover identical request delivery, deterministic reproduction, output/usage parity and divergence, timeout, identity mismatch, invalid protocol data, output bounds, signature tampering, observation reconciliation, loopback enforcement, prompt-over-stdin, clean environment, and provider failure sanitization.

The live run additionally proved:

- both pinned deployments returned the exact expected normalized output;
- explicit usage tolerance was enforced;
- evaluation records and returned adapter bindings matched the retained identity records;
- signed evidence reconciled with both observations;
- each observation was emitted as a canonical trusted-evidence envelope and re-ingested against issuer, key, deployment identity, suite, and validity policy;
- the local observation authorized a real production `PolicyEngine` D0 allow-plan whose digest binds the envelope provenance; the cloud observation remains routing-disabled because provider policy fields are not yet attested;
- no raw prompt/output/provider/session material entered retained evidence.

## Exact proof boundary

- The live suite is a small M2 conformance probe, not a quality benchmark or general semantic-equivalence claim.
- Claude provider retention, region, auxiliary internal model use, and training behavior remain provider-managed/unknown; only D0 public probe text was sent.
- The evaluation signer key is local and symmetric.
- The provider transport is trusted. Untrusted agent processes are separately proven network-denied and credential-clean by the Linux/WSL isolation tests.
- Physical cancellation depends on the concrete HTTP/subprocess boundary; the runner itself rejects late results but cannot kill arbitrary Python threads.
- Exact live identities are evidence records, not portable default deployments. Canonical project deployments remain disabled templates until a target machine explicitly enables them.
- The cloud model alias is observable and governed but does not identify immutable provider weights.
- These observations are valid for 24 hours (`testedAt` to `validUntil`). After expiry they remain historical run evidence but must be renewed before current routing or promotion.
