# Wiki Log

Append-only хронологічний лог операцій. Формат: `## [YYYY-MM-DD] тип | назва`

---

## [2026-07-14] docs | Loop engineering contract

- Distinguished execution, automation, and learning loops.
- Defined the bounded LoopDefinition contract, independent gate, state trust layers, budgets, hard stops, approval, and audit requirements.
- Added L0–L5 maturity levels and fail-closed promotion rules.
- Selected `wiki-health-check` as the first L2 observe/report-only candidate; kept `ml-autoresearch` second behind experiment and DGX resource safeguards.
- Recorded that candidates are not runtime services until M2–M4 enforcement and evaluation boundaries exist.

## [2026-07-14] implementation | M1 contracts/compiler foundation

- Added `ai.ecosystem/v1alpha1` canonical `.ai/` contracts and JSON Schemas.
- Implemented `eco init/validate/audit/diff/render/doctor/lock/uninstall`.
- Added safe projection ownership, explicit adopt/force, backups, drift check, and rollback-aware uninstall.
- Added sanitized secret-reference validation, cross-contract checks, unit tests, and CI.
- Reframed LiteLLM/DGX as optional adapters/profiles; central service and multi-agent runtime remain deferred.
- M2 read-only PEP/broker is the next milestone; no production-enforcement claim is made.

## [2026-07-14] chore | Ініціалізація екосистеми (Phase 0)

- Створено hub-репо: AGENTS.md (конституція), MAP.md (карта вузлів), каркаси skills/ mcp/ agents/ loops/ wiki/
- Рішення: хаб — окремий репо; dgx_spark лишається вузлом «машина DGX»
- Кандидати перших loops: wiki-health-check (🟢), ml-autoresearch (🟢)
