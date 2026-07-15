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
| [Loop and Harness engineering source review](2026-07-15-loop-and-harness-engineering-source-review.md) | [Archived Markdown](sources/loop-and-harness-engineering-7-files-5-steps-every-config-in.md) | Useful mental model; Claude-specific details require correction; not a universal contract |
| [M2.5 completion report](2026-07-15-m2.5-completion-report.md) | Local implementation, multi-agent reviews, and verification suite | Embedded durability slice complete with explicit proof boundary |
| [M2 cross-deployment evaluation report](2026-07-15-m2-cross-deployment-evaluation-report.md) | Deterministic runner, signed mock tests, and live local/cloud evidence | Passing governed Ollama/Claude reference proof; cloud alias, 24-hour validity, and D0 disclosure limits explicit |
| [M2 completion report](2026-07-15-m2-completion-report.md) | Runtime implementation, multi-agent review, 187 tests, and live evidence | Embedded Linux/WSL read-only reference profile complete; production and cross-OS limits explicit |
