# Live evaluation evidence

Each child directory is a no-overwrite evidence publication. The filesystem is not an immutable store; the closure manifest makes later byte changes detectable with the externally retained HMAC key. Never edit or reuse a completed run directory.

- `2026-07-15-m2-closure-pass/` is the authoritative M2 `text-basic` closure proof. It contains the aggregate signed evaluation, two independently ingestible trusted-observation envelopes, full sanitized policy-gate records, receipts, and a signed publication manifest over every other file.
- `2026-07-15-m2-closure/` is a retained fail-closed attempt: an invalid empty MCP configuration caused the cloud adapter to fail before comparison. It is not promotion evidence.
- `2026-07-15-m2-final/` is a superseded passing proof created before the final publication-manifest and verifier-injection hardening.
- `2026-07-15-m2/` is superseded historical evidence created with the earlier `exact-ready-token` case identifier. It remains for provenance and does not define the current M2 gate.

Signing keys are provisioned outside the repository. Observations expire at `validUntil`; an expired run remains historical evidence but cannot authorize current routing.
