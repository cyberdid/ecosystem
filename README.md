# ecosystem

Embedded-first, vendor- and model-neutral AI engineering harness.

The project owns stable contracts, deterministic instruction projections, validation, audit metadata, and evaluation boundaries. Models, IDE agents, gateways, MCP servers, and inference runtimes remain replaceable adapters.

## Current status

**Implemented M1 foundation:**

- `ai.ecosystem/v1alpha1` canonical manifests;
- JSON Schema 2020-12 validation;
- cross-file capability and action-class checks;
- secret-reference validation without echoing rejected values;
- read-only repository audit;
- deterministic Codex/Claude/Copilot/Gemini/Cursor projections;
- unmanaged-file refusal, explicit adoption, replacement backups, drift checks, and reversible uninstall;
- deterministic configuration lock;
- automated unit tests and CI.

**M2 embedded read-only reference profile complete:**

- separate `runtime.ai.ecosystem/v1alpha1` records for requests, immutable plans, decisions, events, artifacts, typed errors, and adapter observations;
- strict broker-owned `repository.read` argument contract;
- enabled deployments require exact identity fields and an observed-capability reference;
- cross-contract validation rejects candidate zone, data-class, and artifact-trust incompatibility;
- runtime contract validation is fail-closed and does not echo untrusted values;
- embedded default-deny planning/tool PEP with immutable plans and single-use decisions;
- capability-scoped run state machine backed by a shared pure replay reducer, plus one runtime-owned atomic budget ledger per active plan;
- snapshot-bound Linux/WSL `repository.read` broker with `openat2`, symlink/hardlink defense, D/P gates, and content-digest verification.
- SQLite schema-v3 authority for the full native run-event lifecycle, plan activation, absolute deadlines, exact policy provenance, atomic decision nonces, durable tool/input budgets, repository-read PREPARE/COMMIT, explicit no-retry recovery, terminal checkpoints, canonical immutable records, and HMAC-linked authority revisions;
- filesystem-only broker plus typed orchestrator, private content-addressed artifact storage with availability proofs, authenticated v2→v3 migration, online backup/restore, historical-key rotation, and external anchor protocols;
- privacy-preserving store boundary: no raw path/content, store-scoped keyed path references, code-owned failure records, coherent-snapshot verification, and relational result reconciliation.
- pinned local-loopback and direct-cloud model adapter contracts with credential-free requests, exact endpoint/model identity, strict response limits, sanitized failures, and no automatic fallback;
- signed trusted snapshot/observation ingestion; unsigned runtime evidence is rejected by `PolicyEngine` by default;
- Linux/WSL untrusted-process isolation using user/net/pid namespaces, Landlock filesystem/TCP denial, a clean environment, zero credential bindings, executable allowlisting, closed stdin, bounded output, and fail-closed preflight;
- exact-output local/cloud conformance evaluation with signed raw-content-free D0 evidence and one passing live Ollama/Qwen plus broker-owned Claude/Sonnet reference run.

**M3 bounded controlled-write profile complete:**

- exact A2 `repository.write` proposals in a dedicated write-only plan for one UTF-8 regular-file `create` or `replace` on Linux/WSL;
- separate authenticated human approval and policy allow, both parameter-bound and atomically single-use;
- exact active-plan, repository-snapshot, broker-root, candidate, before-state, limit and display bindings;
- private CAS candidate/before-image/recovery bundles plus a content-free authenticated SQLite write authority;
- descriptor-anchored compare-and-swap apply, atomic install, postcondition validation and compare-and-swap rollback;
- fenced leases, idempotent historical replay after authority expiry, restart reconciliation and conservative rollback;
- negative coverage for substitution, traversal, protected paths, symlink/hardlink races, tampering, process loss and unrelated edits.

See [M3 controlled writes](docs/architecture/controlled-writes.md) and the [M3 completion report](docs/research/2026-07-15-m3-completion-report.md).

**Not implemented and not claimed:** endpoint-specific network allowlists, Windows/macOS executable isolation/write backends, descendant-exec/seccomp/cgroup/device containment, asymmetric evidence or approval signatures, durable evidence replay IDs, delete/rename/mkdir/batch/arbitrary-command writes, A3/A4 external actions, a bundled database-plus-CAS disaster-recovery package, caller-independent external anchoring, or production autonomy.

## Architecture in one sentence

```text
canonical contracts → compiler/projections → policy boundary → adapters → audit/evaluations
```

`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `GEMINI.md`, and Cursor rules are generated projections. Their canonical source is [`.ai/instructions.yaml`](.ai/instructions.yaml).

## Quick start

```bash
cd /path/to/ecosystem
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[test]"

eco validate
eco render --check
eco doctor
python -m unittest discover -s tests -v
```

Initialize another repository:

```bash
eco --repo /path/to/project audit
eco --repo /path/to/project init --name example-project
eco --repo /path/to/project diff
eco --repo /path/to/project render
```

If an instruction surface already exists, `render` refuses to overwrite it:

```bash
# Preserve the existing file and append an owned block.
eco --repo /path/to/project render --adopt

# Replace it only with an ignored backup recorded under .ai/.state/.
eco --repo /path/to/project render --force
```

Remove generated projections while preserving canonical configuration:

```bash
eco --repo /path/to/project uninstall
```

Deleting `.ai/` additionally requires explicit confirmation:

```bash
eco --repo /path/to/project uninstall --remove-config --yes
```

## Commands

| Command | Purpose | Writes? |
|---|---|---:|
| `eco init` | Create `.ai/` starter contracts | Yes |
| `eco validate` | Validate schemas, references, capabilities, and secret fields | No |
| `eco audit` | Discover repository conventions and potential secret locations | No |
| `eco diff` | Preview projection changes | No |
| `eco render` | Apply owned vendor projections | Yes |
| `eco render --check` | Detect projection drift for CI | No |
| `eco doctor` | Validate configuration and projection health | No |
| `eco runtime doctor` | Probe the embedded runtime composition; does not enable execution | No |
| `eco lock` | Record deterministic input hashes and deployment identities | Yes |
| `eco uninstall` | Remove/restore only eco-owned projections | Yes |

## Repository layout

```text
.ai/                    canonical project contracts
src/eco_cli/            CLI, compiler, audit, validator
src/eco_cli/schemas/    normative JSON Schemas
tests/                  contract/projection/security tests
docs/architecture/      logical architecture and boundaries
docs/decisions/         architecture decisions
wiki/                   curated operational knowledge
skills/                 future canonical skill packages
mcp/                    adapter inventory; not authorization
agents/                 optional role patterns
loops/                  evaluated automation candidates
MAP.md                  deployment inventory, not architecture truth
```

## Project roles

```text
rnd-llm-playbook = methodology and research
ecosystem        = executable contracts/compiler/harness
dgx_spark        = historical example/corpus; retired host, not a dependency
odysseus         = brownfield conformance benchmark
```

## Design boundaries

- OpenAI-compatible transport does not imply semantic compatibility.
- LiteLLM is optional and replaceable; direct provider adapters remain possible.
- MCP is a tool/resource protocol, not a policy engine or trust certificate.
- Local execution is not automatically private.
- SQLite is the local M2.5 transaction authority for the embedded read-only lifecycle. External immutability exists only when the caller publishes anchors to an independent append-only/WORM sink.
- Multi-agent execution is opt-in and must outperform a single-agent baseline.
- A central control service, A2A, Temporal, Kubernetes, Vault, and SPIFFE are deferred until a measured need exists.

Read [the architecture](docs/architecture/README.md), [the decisions](docs/decisions/README.md), and [the wiki](wiki/index.md) for detail.

## Safety

- No literal secrets in canonical configuration; use `env:`, `config:`, or `secret://` references.
- Audit output reports secret-like keys and locations but intentionally does not display values.
- Generated files carry ownership markers and source digests.
- Unmanaged files are never overwritten by default.
- Runtime authorization exists in the embedded M2 read-only slice; instruction files are never authorization boundaries.
- Broker results remain untrusted content and require plan-bound classification and downstream authorization.

## License

[MIT](LICENSE).
