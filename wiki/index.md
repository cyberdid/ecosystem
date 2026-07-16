# Wiki Index — ecosystem

> Curated operational knowledge. Canonical executable truth lives under `.ai/`; generated vendor files are projections.

**Updated:** 2026-07-15
**Status:** M1, embedded M2 read-only, bounded M3 Linux/WSL controlled writes, and M3.5 integration/reproducibility are complete; trust bootstrap and M4 evaluation/promotion are next.

## Pages

| Page | Purpose | Updated |
|---|---|---:|
| [architecture.md](architecture.md) | Current implemented boundary and target runtime flow | 2026-07-15 |
| [loops.md](loops.md) | Loop contract, safety boundaries, maturity and first candidates | 2026-07-15 |
| [openresearcher.md](openresearcher.md) | Downloaded upstream research node, evidence, boundaries, and possible role | 2026-07-15 |
| [labs-molt.md](labs-molt.md) | NVIDIA agentic-RL training node, architecture, evidence, risks, and gated role | 2026-07-15 |
| [ai-legal-claude.md](ai-legal-claude.md) | Claude-specific legal prompt corpus, compatibility audit, legal limits, and safe-adoption gate | 2026-07-15 |
| [roadmap.md](roadmap.md) | Dependency-ordered M0–M6 delivery plan | 2026-07-15 |
| [Read-only broker](../docs/architecture/read-only-broker.md) | Snapshot-bound Linux/WSL A1 enforcement and proof limits | 2026-07-15 |
| [Durable runtime store](../docs/architecture/durable-runtime-store.md) | Schema-v3 event/plan/budget/operation authority and operational durability | 2026-07-15 |
| [M3 controlled writes](../docs/architecture/controlled-writes.md) | Exact approval, A2 one-file CAS apply/rollback and restart recovery boundary | 2026-07-15 |
| [M3 completion report](../docs/research/2026-07-15-m3-completion-report.md) | Exit-criteria evidence, multi-agent review, 258-test gate and exact limitations | 2026-07-15 |
| [M3.5 integration and reproducibility](../docs/research/2026-07-16-m3.5-integration-reproducibility-report.md) | Installed runtime composition, honest isolation-conformance scope, declared test dependency and governance reconciliation | 2026-07-16 |
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

## Reading order

1. `README.md`
2. `.ai/project.yaml`
3. `docs/architecture/README.md`
4. `docs/decisions/README.md`
5. `docs/architecture/runtime-contracts.md`, `read-only-broker.md`, and `controlled-writes.md` for the current M2/M3 boundary
6. `wiki/loops.md` for bounded automation, proposal, and controlled-apply rules
7. `wiki/openresearcher.md` for the current external research-node snapshot
8. `wiki/labs-molt.md` for the external agentic-RL training-node snapshot
9. `wiki/ai-legal-claude.md` for the external legal-prompt corpus and its safety limits
10. `docs/research/README.md` for source reviews and raw-source provenance
11. This wiki for current operational status

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
