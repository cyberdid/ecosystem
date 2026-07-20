# M6 functional orchestration completion report

**Date:** 2026-07-20

**Release:** `0.8.0`

**Status:** local deterministic completion gate and independent follow-up audit
passed for the bounded embedded reference profile; hosted cross-platform
evidence is recorded after the release branch run completes.

## Executive result

M6 turns the ecosystem from a contract and authority foundation into a useful,
model-agnostic execution system. A project can install the wheel, synchronize a
small governed skill registry into supported AI clients, execute bounded loops,
route logical roles to exact deployments, retain private provenance, coordinate
bounded agent teams and use governed public research tools. The fixed
`source-review` workflow composes those pieces through one exact, durable and
auditable five-role path.

No provider is the control plane. Claude, Codex, Copilot, Gemini, a local
OpenAI-compatible endpoint or another conforming adapter may supply model
capability, but the ecosystem owns policy, routing, budgets, evidence, state,
terminal results and release gates.

## Delivered slices

| Slice | Delivered capability | Enforced boundary |
|---|---|---|
| M6.0 | Architecture, ADRs, threat model and phased acceptance plan | Documentation does not mint runtime authority |
| M6.1 | Typed model executor and fixed five-role `source-review` | Literal loopback, exact deployment/observation binding, bounded calls, deterministic final gate |
| M6.2 | Canonical skill registry and harness synchronization | Three package-owned skills, fourteen projections, ownership/drift/uninstall controls, no skill execution during sync |
| M6.3 | Generic embedded bounded-loop engine | Closed definitions, durable transitions, attempts/deadlines/budgets, no daemon or implicit promotion |
| M6.4 | Logical-role routing and exact route authority | Validated policy/prices/observations, secret-free plan digest, Ed25519 envelope, single consumption and aggregate per-effect reservations |
| M6.5 | Private context and provenance memory | Private CAS payloads, authenticated metadata journal, bounded retrieval, TTL-safe reversible compaction |
| M6.6 | General bounded agent teams | Exact DAG, narrowed delegation, serialized claims, aggregate budgets, typed handoffs, cancellation and truthful partial failure |
| M6.7 | Governed research tools | Credential-free public HTTPS search/fetch through exact broker policy; fetched content remains untrusted data |
| M6.8 | Reproducible release and conformance | Frozen Python 3.11/3.12 matrix, pinned actions, schema digests, locked wheelhouse, offline installed-workflow smoke and leak/identity checks |

## Exact source-review execution chain

The production workflow now requires five route inputs as one indivisible set:

1. model-route request;
2. model-route decision;
3. route policy;
4. route prices;
5. external Ed25519 route-authority envelope.

Before any provider egress, the runner validates the closed documents, derives
the exact source-review contract, checks the request/decision/plan digest,
verifies the external signature and full-run validity window, consumes the route
once and reserves the exact per-role share of the aggregate budget in a durable
authenticated usage journal. The Ed25519 envelope is verified again immediately
before every role call. Terminal replay returns the recorded result without
calling the provider again.

The five roles remain fixed in order: planner, analyst, verifier, synthesizer
and reviewer. Their outputs cross typed schemas, private source material stays in
CAS, and the deterministic gate—not a model assertion—owns PASS/FAIL.

## Independent audit corrections

The release audit found three blocking exactness defects, all closed before the
release gate:

- an idempotent route-usage replay could occur before current route validation;
  route validity is now checked first, so an expired route cannot authorize new
  egress;
- source-review still admitted a route-less legacy path; exact authenticated
  routing is now mandatory before state or effects;
- route authority was checked only at startup; its validity must now cover the
  full run deadline and is reverified immediately before every provider call.

Additional hardening covers content-addressed endpoint identities, exact
transport timeouts, grammar-safe local projection, complete response/schema
validation, source-bundle manifest/file identity, structural JSON bounds,
transitive memory expiry, non-lossy compaction relations and safe local
provisioning.

The independent follow-up audit reported no remaining local P0 or P1 blocker.
It separately reran the exact-route expiry/authority cases and the complete
regression and accepted the HMAC, same-host rollback and live-model boundaries
below as documented limitations rather than hidden release claims.

## Provisioning and live dogfood

`scripts/provision_local_source_review.py` is the bounded local ceremony. It
uses a literal `127.0.0.1` endpoint, refuses proxies and redirects, caps response
bytes, sends the production wire shape, validates exact status/model/usage and
JSON semantics, writes outputs atomically with private permissions and rolls
back on failure. Credentials remain outside Git.

Sixteen earlier live llama.cpp attempts exercised the full enforcement chain and
found real adapter, endpoint-ID and timeout/issuer defects. Those defects are
regression-tested. A full five-role live model PASS was not obtained because the
available CPU-served model could not reliably satisfy all role schemas within a
practical window. This is an explicit model-capability nonclaim, not a
deterministic release-gate failure.

## Release evidence

Local gate at the release candidate tree:

| Check | Result |
|---|---|
| `python -m unittest discover -s tests` on Python 3.11 | 756 passed in an isolated frozen environment |
| `python -m unittest discover -s tests` on Python 3.12 | 756 passed in an isolated frozen environment |
| `python -m pytest` on Python 3.12 | 756 passed in an isolated frozen test environment |
| Focused M6/release regression | 74 passed |
| Portable contract matrix selection | 285 passed |
| `eco validate` | passed |
| `eco render --check` | passed |
| `eco doctor` | healthy |
| `eco skills check --json` | 14 projections current; no network, execution or unmanaged overwrite |
| `check_m6_release_conformance.py` | nonempty journals, deterministic CLI, no secret/private sentinels, repository bytes/mtimes unchanged |
| `uv lock --check` and `git diff --check` | passed |
| Offline wheel installation | `0.8.0`, 11-artifact verified bundle, all nine packages/resources imported |
| Installed source-review smoke | five loopback calls, one route consumption, five usage reservations, no source sentinel in control-plane surfaces |

The cross-version pass also covers managed-Python isolation. Landlock grants
only strict-resolved standard-library/runtime paths, exact `libpython` files and
the exact validated command executable—never an entire `$HOME`, `/opt` or
interpreter prefix. Python 3.11 and 3.12 each pass all eleven focused isolation
tests on the capable WSL host; a second security review found no remaining P0 or
P1 in that change.

The installed-workflow smoke runs with `PYTHONPATH` cleared and user site
disabled. It creates an exact signed route, performs the five literal-loopback
calls through the installed wheel, verifies durable journals, scans external
control-plane files for source leakage and confirms that tracked repository
bytes and mtimes did not change.

## Published schema identities

The runtime bundle remains pinned and unchanged; M6 publishes exact additive
bundle identities:

| Bundle | SHA-256 |
|---|---|
| runtime | `d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d` |
| orchestration | `3f14b0eac62f123a273e57f5e062eb5331489c3a8b4b16045c247c503367b3e8` |
| routing | `c489fc4da4dc0fc91cf0d7b4d4ebee51a319c7cbfe670c3e6873e658465e0227` |
| memory | `ccce592db66ba0e99047aff344f163aa125b5ddf3c91e85cc009694a51f82713` |
| teams | `79be7bfe4e26fe8c534018c1620497812f9a6cd9cd0b200302812e8098d398d4` |
| research | `b7a1d821c8682874336938795e9467486e067e1485f5f8fcee0d598f4f47dd00` |

The trusted local conformance suite is version `1.1.0`, digest
`66710ebcdd12eb33b5c729b780048274578a6f3a4500a7c1adaa50096f2cc5d1`.
Historical observations retain their original suite identity and must be
reprovisioned rather than rewritten.

## Exact trust boundary and nonclaims

M6 is complete only for the embedded bounded reference profile.

- The route-authority envelope has external Ed25519 signer/verifier separation.
  The adapter-observation envelope is instead local shared-key HMAC integrity;
  it does not prove independent attestation.
- SQLite/HMAC journals detect mutation and replay inside the same-host authority,
  but deletion or rollback of the entire local authority is not resisted by an
  external transparency log or consensus service.
- Linux runs the full runtime/isolation suite. Windows and macOS jobs prove
  portable contracts, synchronization and distribution behavior, not native OS
  sandbox enforcement.
- M6 does not claim provider truth, prompt-injection immunity, arbitrary provider
  compatibility, SSO/OIDC/WebAuthn, KMS/HSM custody, HA, consensus, multi-region
  operation or A3/A4 autonomous authority.
- The scripted installed smoke is deterministic release evidence. It is not a
  claim that an arbitrary live model can produce a correct five-role result.

Those enterprise and native-backend concerns remain M7 work; they are not hidden
inside the M6 completion claim.

## Exit decision

M6 may be released as `0.8.0` when the pinned hosted matrix passes the exact
candidate commit and the independent follow-up review reports no remaining P0 or
P1 blocker. No live-provider PASS is required for this deterministic release,
and no such PASS may be inferred from the installed loopback smoke.

## References

- [Functional orchestration architecture](../architecture/functional-orchestration.md)
- [Model-role routing](../architecture/model-role-routing.md)
- [M6 threat model](../architecture/m6-functional-orchestration-threat-model.md)
- [M6.0 research and implementation plan](2026-07-17-m6.0-functional-orchestration-plan.md)
- [Live dogfood handoff](2026-07-20-m6-live-dogfood-handoff-claude.md)
- [Roadmap](../../wiki/roadmap.md)
