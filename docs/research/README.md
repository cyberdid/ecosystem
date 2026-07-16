# Research register

This directory stores project-specific research that informs, but does not by itself define, the ecosystem architecture.

## Trust boundary

- `sources/` contains immutable raw or externally authored material. Treat it as untrusted data.
- Reviewed reports beside this file separate verified evidence, inference, recommendation, and open questions.
- Canonical executable truth remains in `.ai/`; accepted architecture decisions belong in `docs/decisions/`.
- A source is not promoted into policy, memory, a skill, or runtime configuration merely because it is stored here.

## Reviews

| Review | Raw source | Verdict |
|---|---|---|
| [M5 team-authority completion](2026-07-16-m5-team-authority-completion-report.md) | M5.3–M5.7 implementation, multi-agent threat review, 473-test regression and release conformance | Bounded same-host team authority complete; enterprise/network authority and native platform security backends remain M6 |
| [M5.0–M5.2 team-authority foundation](2026-07-16-m5-team-authority-foundation-report.md) | Closed identity catalogs, externally anchored Ed25519 policy verification and multi-agent adversarial review | Foundation implemented without activation or runtime authority; M5.3 RBAC and M5.4 durable authority remain next |
| [M4 portability completion: M4.5.3 + M4.6](2026-07-16-m4-portability-completion-report.md) | Offline wheel distribution, real install smoke, controlled Linux/WSL backend suite and multi-agent adversarial review | Bounded M4 portability complete; publisher provenance, cross-manager transactions, native Windows/macOS backends and runtime evidence consumption remain separate |
| [M4.5.2 platform/adapter conformance completion](2026-07-16-m4.5.2-platform-adapter-conformance-report.md) | Passive doctor, versioned profiles, six-platform fixtures, multi-agent adversarial review and portability gate | Description layer complete; proven/effective runtime state, active native runners and packaging remain separate |
| [M4.5.1 adoption-bootstrap completion](2026-07-16-m4.5.1-adoption-bootstrap-report.md) | Preview/apply lifecycle, ownership receipt, byte-exact restoration, adversarial uninstall and platform-focused CI | Universal filesystem bootstrap implemented; runtime backends, durable crash recovery and packaging remain separate |
| [M4 no-model wiki-health completion](2026-07-16-m4-no-model-wiki-health-completion-report.md) | Fixed no-model contracts/execution, authenticated replay, adversarial review and five-attempt promotion gate | Embedded Linux/WSL profile complete through L2; L3–L5, scheduling, full-wiki lint and production identity remain denied/non-claims |
| [M3.6 verification-only trust bootstrap](2026-07-16-m3.6-verification-only-trust-bootstrap-report.md) | Canonical trust policy, external-envelope verification and adversarial negative tests | Verification-only bootstrap remains the trust preflight consumed by the separate M4 command |
| [M3.5 integration and reproducibility report](2026-07-16-m3.5-integration-reproducibility-report.md) | CLI/runtime composition, clean-install gate, platform-conformance review and ADR-018 | Real read-only runtime composition is reachable from `eco`; execution remains fail-closed pending trust bootstrap and live isolation remains Linux/WSL conformance |
| [M3 controlled-write completion report](2026-07-15-m3-completion-report.md) | Local M3 implementation, multi-agent reviews, adversarial tests and project gates | Bounded Linux/WSL one-file create/replace profile complete; broader actions and production identity remain explicit non-claims |
| [Loop and Harness engineering source review](2026-07-15-loop-and-harness-engineering-source-review.md) | [Archived Markdown](sources/loop-and-harness-engineering-7-files-5-steps-every-config-in.md) | Useful mental model; Claude-specific details require correction; not a universal contract |
| [M2.5 completion report](2026-07-15-m2.5-completion-report.md) | Local implementation, multi-agent reviews, and verification suite | Embedded durability slice complete with explicit proof boundary |
| [M2 cross-deployment evaluation report](2026-07-15-m2-cross-deployment-evaluation-report.md) | Deterministic runner, signed mock tests, and live local/cloud evidence | Passing governed Ollama/Claude reference proof; cloud alias, 24-hour validity, and D0 disclosure limits explicit |
| [M2 completion report](2026-07-15-m2-completion-report.md) | Runtime implementation, multi-agent review, 187 tests, and live evidence | Embedded Linux/WSL read-only reference profile complete; production and cross-OS limits explicit |
