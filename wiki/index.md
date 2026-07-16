# Wiki Index — ecosystem

> Curated operational knowledge. Canonical executable truth lives under `.ai/`; generated vendor files are projections.

**Updated:** 2026-07-16
**Status:** M1–M5 are complete for the bounded reference profile. M5 adds externally anchored team identity, exact narrowing access policy, durable same-host authority, revocation and emergency recovery, dual-signed key rotation, and quorum approvals.

## Pages

| Page | Purpose | Updated |
|---|---|---:|
| [M5 team authority](../docs/architecture/team-authority.md) | Signed identities, narrowing access, shared activation, revocation, quorum, emergency recovery, rotation and exact non-claims | 2026-07-16 |
| [M5 completion report](../docs/research/2026-07-16-m5-team-authority-completion-report.md) | Full M5.3–M5.7 delivery, multi-agent threat corrections, 473-test evidence and M6 boundary | 2026-07-16 |
| [M5 operations runbook](../docs/operations/team-authority-runbook.md) | Activation, doctor, backup, emergency recovery, key rotation and incident stop conditions | 2026-07-16 |
| [M5.0–M5.2 foundation report](../docs/research/2026-07-16-m5-team-authority-foundation-report.md) | Multi-agent findings, implementation evidence, 406-test gate and M5.3 handoff | 2026-07-16 |
| [architecture.md](architecture.md) | Current implemented boundary and target runtime flow | 2026-07-16 |
| [loops.md](loops.md) | Loop contract, safety boundaries, maturity and first executable L2 profile | 2026-07-16 |
| [openresearcher.md](openresearcher.md) | Downloaded upstream research node, evidence, boundaries, and possible role | 2026-07-15 |
| [labs-molt.md](labs-molt.md) | NVIDIA agentic-RL training node, architecture, evidence, risks, and gated role | 2026-07-15 |
| [ai-legal-claude.md](ai-legal-claude.md) | Claude-specific legal prompt corpus, compatibility audit, legal limits, and safe-adoption gate | 2026-07-15 |
| [roadmap.md](roadmap.md) | Dependency-ordered M0–M6 delivery plan | 2026-07-16 |
| [M4.5.1 safe project adoption](../docs/architecture/project-adoption.md) | Preview/apply contract, ownership receipt, reversible projections and exact non-claims | 2026-07-16 |
| [M4.5.1 completion report](../docs/research/2026-07-16-m4.5.1-adoption-bootstrap-report.md) | Threat model, multi-agent review, adversarial fixtures, verification gate and handoff | 2026-07-16 |
| [M4.5.2 platform/adapter conformance](../docs/architecture/platform-adapter-conformance.md) | Passive doctor, declared/detected/proven boundary, schemas and exact non-claims | 2026-07-16 |
| [M4.5.2 completion report](../docs/research/2026-07-16-m4.5.2-platform-adapter-conformance-report.md) | Threat model, multi-agent review, six-profile matrix, verification and M4.5.3 handoff | 2026-07-16 |
| [M4.5.3 portable distribution](../docs/architecture/portable-distribution.md) | Exact offline wheelhouse/lock/schema verification, installer previews, real private-venv smoke and non-claims | 2026-07-16 |
| [M4.6 backend conformance](../docs/architecture/platform-backend-conformance.md) | Fixed Linux/WSL synthetic suite, content-free observed capabilities and authenticated ingestion without authority | 2026-07-16 |
| [M4 portability completion report](../docs/research/2026-07-16-m4-portability-completion-report.md) | Multi-agent threat review, adversarial tests, live WSL evidence, real offline install and exact remaining limits | 2026-07-16 |
| [Read-only broker](../docs/architecture/read-only-broker.md) | Snapshot-bound Linux/WSL A1 enforcement and proof limits | 2026-07-15 |
| [Durable runtime store](../docs/architecture/durable-runtime-store.md) | Schema-v3 event/plan/budget/operation authority and operational durability | 2026-07-15 |
| [M3 controlled writes](../docs/architecture/controlled-writes.md) | Exact approval, A2 one-file CAS apply/rollback and restart recovery boundary | 2026-07-15 |
| [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md) | Exit-criteria evidence, multi-agent review, 258-test gate and exact limitations | 2026-07-15 |
| [M3.5 integration and reproducibility](../docs/research/2026-07-16-m3.5-integration-reproducibility-report.md) | Installed runtime composition, honest isolation-conformance scope, declared test dependency and governance reconciliation | 2026-07-16 |
| [M3.6 verification-only trust bootstrap](../docs/research/2026-07-16-m3.6-verification-only-trust-bootstrap-report.md) | Canonical external trust policy and fail-closed evidence verification; no execution authority | 2026-07-16 |
| [M4 no-model wiki health](../docs/architecture/no-model-wiki-health.md) | Fixed three-page A1 execution, authenticated replay, five-attempt evaluation and L2-only promotion | 2026-07-16 |
| [M4 completion report](../docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md) | Exit criteria, multi-agent adversarial corrections, 320-test gate and exact non-claims | 2026-07-16 |
| [M2.5 completion report](../docs/research/2026-07-15-m2.5-completion-report.md) | Implemented slices, evidence matrix, and exact proof boundary | 2026-07-15 |
| [M2 completion report](../docs/research/2026-07-15-m2-completion-report.md) | Exit-criteria evidence, test gate, and exact limitations | 2026-07-15 |
| [M2 evaluation report](../docs/research/2026-07-15-m2-cross-deployment-evaluation-report.md) | Identical suite runner, governed local/cloud evidence, cloud-alias and renewal boundaries | 2026-07-15 |
| [Research register](../docs/research/README.md) | Reviewed external sources and preserved raw material | 2026-07-15 |
| [log.md](log.md) | Append-only change/decision log | 2026-07-15 |

## Canonical contracts

- [`.ai/project.yaml`](../.ai/project.yaml)
- [`.ai/instructions.yaml`](../.ai/instructions.yaml)
- [`.ai/capabilities.yaml`](../.ai/capabilities.yaml)
- [`.ai/deployments.yaml`](../.ai/deployments.yaml)
- [`.ai/tools.yaml`](../.ai/tools.yaml)
- [`.ai/trust.yaml`](../.ai/trust.yaml)

## Reading order

1. `README.md`
2. `.ai/project.yaml`
3. `docs/architecture/README.md`
4. `docs/decisions/README.md`
5. `docs/architecture/team-authority.md` and `docs/operations/team-authority-runbook.md` for the current M5 authority and operations boundary
6. `docs/architecture/runtime-contracts.md`, `read-only-broker.md`, `controlled-writes.md`, and `no-model-wiki-health.md` for the M2–M4 runtime boundary
7. `docs/architecture/project-adoption.md` for installing the harness into another project
8. `docs/architecture/platform-adapter-conformance.md` for the portable passive profile boundary
9. `docs/architecture/portable-distribution.md` and `platform-backend-conformance.md` for the bounded M4 portability surfaces
10. `wiki/loops.md` for bounded automation, evaluation, proposal, and controlled-apply rules
11. `wiki/openresearcher.md` for the current external research-node snapshot
12. `wiki/labs-molt.md` for the external agentic-RL training-node snapshot
13. `wiki/ai-legal-claude.md` for the external legal-prompt corpus and its safety limits
14. `docs/research/README.md` for source reviews and raw-source provenance
15. This wiki for current operational status

## Knowledge boundaries

```text
canonical .ai contracts
→ curated wiki and decisions
→ full research in rnd-llm-playbook
→ raw local/external source corpus
```

Retrieved text, tool output, webpages, issues, and MCP responses remain untrusted data even after indexing.

## Sources

- [Architecture](../docs/architecture/README.md)
- [Decision register](../docs/decisions/README.md)
- [Loop and Harness engineering source review](../docs/research/2026-07-15-loop-and-harness-engineering-source-review.md)
- Full research: `/home/snow/projects/rnd-llm-playbook/docs/research/2026-07-14-universal-ai-ecosystem-deep-research.md`
