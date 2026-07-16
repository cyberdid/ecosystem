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

**M3.6 verification-only trust bootstrap complete:**

- canonical `.ai/trust.yaml` declares only external verification-key/evidence references and fixed repository scope;
- `eco runtime trust doctor --json` verifies externally signed snapshot/conformance evidence without creating a run, store, broker, model request, network egress, or write authority;
- the embedded HMAC profile is explicitly local-shared-key, not remote/provider provenance or third-party non-repudiation.

See the [M3.6 trust-bootstrap report](docs/research/2026-07-16-m3.6-verification-only-trust-bootstrap-report.md).

**M4 fixed no-model loop and promotion profile complete:**

- `eco run wiki-health-check --json` executes one code-owned A1 workflow over exactly three signed D0/P1 wiki entries;
- the separate `NoModelRunPlan` has no route, deployment, adapter, endpoint, model request, network request, or write authority;
- every read receives a fresh single-use expiring policy decision evaluated against advancing runtime time and passes only through the Linux/WSL snapshot broker;
- private external SQLite journals are path/content-free, HMAC-authenticated, exclusively process-owned, replay-safe, symlink/hardlink resistant, and never written below the governed repository;
- a durable pre-I/O `started` event fences each broker attempt: pre-start recovery reauthorizes, while an ambiguous post-start crash fails closed without rereading;
- the deterministic report checks signed-snapshot integrity, one primary heading per document, and distinct document contents without emitting document text or paths;
- `eco eval wiki-health-check --json` evaluates five independent fixed journals plus a zero-read replay proof and can promote this workflow only through L2;
- L3, L4, and L5 are explicit ineligible results for this no-model read-only profile, not implied write or autonomy rights.

See [M4 no-model wiki health](docs/architecture/no-model-wiki-health.md) and the [M4 completion report](docs/research/2026-07-16-m4-no-model-wiki-health-completion-report.md).

**M4.5.1 safe project-adoption bootstrap complete:**

- `eco adopt --dry-run --json` emits a deterministic, content-minimized plan without writing;
- apply requires the exact recomputed plan digest under a per-repository lock;
- fresh, explicitly adopted existing-config, and no-op reinstall modes have separate ownership semantics;
- existing instruction surfaces use byte-exact before-image backups and managed blocks;
- `.ai/adoption.json` records exact ownership; full removal is receipt-enumerated and complete-preflight;
- stale state, path escape, symlink/hardlink/non-UTF-8 targets, backup tampering, forged markers, drift, unknown config, and concurrent rollback edits fail closed;
- focused adoption behavior runs in hosted Linux, macOS, and Windows CI without broadening the Linux/WSL runtime proof.

See [M4.5.1 project adoption](docs/architecture/project-adoption.md) and the [M4.5.1 completion report](docs/research/2026-07-16-m4.5.1-adoption-bootstrap-report.md).

**M4.5.2 platform and adapter conformance boundary complete:**

- closed `platform.ai.ecosystem/v1alpha1` `PlatformProfile` and `AdapterCapabilityProfile` contracts;
- `eco platform doctor --json` emits deterministic categorical inventory without invoking executables, contacting adapters, reading projection contents, writing files, or creating authority;
- operator declaration, passive detection, authenticated proof, and effective capability state remain separate;
- passive platform and adapter profiles structurally forbid proven/effective runtime capabilities;
- Linux, WSL, macOS, Windows, container, and hosted-CI fixtures cover spoofing, nested ambiguity, schema closure, privacy, and zero-side-effect behavior;
- focused platform/adoption portability gates run on hosted Linux, macOS, and Windows.

See [M4.5.2 platform and adapter conformance](docs/architecture/platform-adapter-conformance.md) and the [M4.5.2 completion report](docs/research/2026-07-16-m4.5.2-platform-adapter-conformance-report.md).

**M4.5.3 portable distribution complete for the wheel-only integrity profile:**

- closed deterministic manifest binds the real main wheel, every dependency wheel, `uv.lock`, source revision and packaged schema inventory;
- installed and standard-library verifiers are offline, read-only and reject artifact/lock/schema/archive/alias tampering;
- main and dependency artifacts must be structurally valid wheels; the main wheel additionally binds `Requires-Python`, package modules and the `eco` entry point;
- installer adapters emit non-executable `venv-pip`, `pipx` and `uv tool` previews;
- hosted Linux builds, independently verifies and installs the real wheelhouse into a clean offline virtual environment;
- Python package installation remains separate from preview-bound project adoption and from all runtime authority.

**M4.6 controlled Linux/WSL backend conformance complete:**

- `eco conformance run` is an explicit active surface separate from passive `platform doctor`;
- one fixed synthetic suite tests the existing namespace/Landlock backend's environment, filesystem, network, read-only, stdin, output and deadline boundaries;
- the closed `PlatformBackendConformanceProfile` binds platform, distribution, backend instance/implementation, runner and suite digests without raw output or paths;
- external HMAC envelope ingestion re-verifies exact bindings but has no policy/runtime consumer and creates no effective capability;
- Windows, macOS, containers and hosted CI remain unsupported negative profiles, never fallback passes.

See [M4.5.3 portable distribution](docs/architecture/portable-distribution.md), [M4.6 platform backend conformance](docs/architecture/platform-backend-conformance.md), and the [combined completion report](docs/research/2026-07-16-m4-portability-completion-report.md).

**Not implemented and not claimed:** durable adoption crash recovery, hostile parent-swap/reparse/case-fold security on every filesystem, publisher-authenticated distribution provenance, immutable verified-byte installer staging, transactional cross-manager rollback, standalone/OS-native packages, Windows/macOS M4 read-broker conformance or executable isolation/write backends, endpoint-specific network allowlists, descendant-exec/seccomp/cgroup/device containment, asymmetric evidence or approval signatures, delete/rename/mkdir/batch/arbitrary-command writes, A3/A4 external actions, a bundled database-plus-CAS disaster-recovery package, caller-independent external anchoring, scheduled/autonomous loops, full wiki link/staleness lint, or production autonomy.

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
eco platform doctor --json
eco runtime trust doctor --json
python -m unittest discover -s tests -v
```

The live M4 commands additionally require operator-provisioned external state and trust inputs. The runtime never creates or signs its own snapshot:

```bash
export ECO_SNAPSHOT_EVIDENCE_KEY='operator-provisioned verification material'
export ECO_WIKI_SNAPSHOT_ENVELOPE_FILE='/private/external/snapshot.envelope'
export ECO_RUNTIME_STATE_DIR='/private/external/runtime-state' # existing mode 0700
export ECO_RUNTIME_JOURNAL_HMAC_KEY='separate journal key with at least 32 bytes'

eco run wiki-health-check --json
eco eval wiki-health-check --json
```

Do not commit those values or the external evidence/state files. The example shows required interfaces, not reusable credentials.

Initialize another repository:

```bash
eco --repo /path/to/project audit
eco --repo /path/to/project adopt --dry-run --json
eco --repo /path/to/project adopt --apply <planDigest> --json
```

`adopt` is the recommended project-bootstrap path after the Python package is installed. It preserves existing instruction surfaces and requires a fresh preview digest before mutation. If valid canonical `.ai` contracts already exist, repeat both commands with `--adopt-existing-config`; those canonical files remain user-owned.

`eco init`, `diff`, and `render` remain lower-level compiler commands for explicitly managed repositories.

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

Removing adoption-owned `.ai/` additionally requires explicit confirmation and a valid ownership receipt. Drift, unknown entries, or pre-existing canonical config block the entire operation before any mutation:

```bash
eco --repo /path/to/project uninstall --remove-config --yes
```

## Commands

| Command | Purpose | Writes? |
|---|---|---:|
| `eco init` | Create `.ai/` starter contracts | Yes |
| `eco validate` | Validate schemas, references, capabilities, and secret fields | No |
| `eco audit` | Discover repository conventions and potential secret locations | No |
| `eco adopt --dry-run` | Build a deterministic, content-minimized project-adoption plan | No |
| `eco adopt --apply` | Apply one exact previewed adoption plan and write its ownership receipt | Yes |
| `eco diff` | Preview projection changes | No |
| `eco render` | Apply owned vendor projections | Yes |
| `eco render --check` | Detect projection drift for CI | No |
| `eco doctor` | Validate configuration and projection health | No |
| `eco runtime doctor` | Probe the embedded runtime composition; does not enable execution | No |
| `eco runtime trust doctor` | Verify externally signed trust inputs; does not start execution | No |
| `eco distribution verify` | Verify one exact local offline wheelhouse and lock | No |
| `eco distribution plan` | Emit a non-executable package-manager argv preview | No |
| `eco conformance run` | Run the explicit fixed synthetic Linux/WSL backend suite in an external test root | External synthetic root only |
| `eco run wiki-health-check` | Run the fixed signed-snapshot, no-model A1 health profile | No repository write* |
| `eco eval wiki-health-check` | Run the fixed five-attempt plus replay L0–L2 promotion gate | No repository write* |
| `eco lock` | Record deterministic input hashes and deployment identities | Yes |
| `eco uninstall` | Remove/restore only eco-owned projections | Yes |

`*` The M4 commands write only HMAC-authenticated SQLite state below the separately provisioned external `ECO_RUNTIME_STATE_DIR`.

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
