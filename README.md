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

**Not implemented and not claimed:** runtime PEP/broker, model routing, sandbox execution, approvals, immutable audit, or production autonomy.

## Architecture in one sentence

```text
canonical contracts → compiler/projections → policy boundary → adapters → audit/evaluations
```

`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `GEMINI.md`, and Cursor rules are generated projections. Their canonical source is [`.ai/instructions.yaml`](.ai/instructions.yaml).

## Quick start

```bash
cd /home/snow/projects/ecosystem
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .

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
dgx_spark        = local execution and evaluation lab
odysseus         = brownfield conformance benchmark
```

## Design boundaries

- OpenAI-compatible transport does not imply semantic compatibility.
- LiteLLM is optional and replaceable; direct provider adapters remain possible.
- MCP is a tool/resource protocol, not a policy engine or trust certificate.
- Local execution is not automatically private.
- SQLite is a local audit trail, not an immutable production ledger.
- Multi-agent execution is opt-in and must outperform a single-agent baseline.
- A central control service, A2A, Temporal, Kubernetes, Vault, and SPIFFE are deferred until a measured need exists.

Read [the architecture](docs/architecture/README.md), [the decisions](docs/decisions/README.md), and [the wiki](wiki/index.md) for detail.

## Safety

- No literal secrets in canonical configuration; use `env:`, `config:`, or `secret://` references.
- Audit output reports secret-like keys and locations but intentionally does not display values.
- Generated files carry ownership markers and source digests.
- Unmanaged files are never overwritten by default.
- Runtime enforcement remains a future milestone; instruction files are not authorization boundaries.

## License

[MIT](LICENSE).
