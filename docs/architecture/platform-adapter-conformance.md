# M4.5.2 platform and adapter conformance

**Status:** implemented for passive inventory and non-authorizing profile contracts

**Updated:** 2026-07-16

## Outcome

M4.5.2 gives the ecosystem a portable vocabulary for describing a host and an adapter without pretending that description is a security proof. It adds two closed `platform.ai.ecosystem/v1alpha1` contracts, a deterministic `eco platform doctor --json`, six portable fixture profiles, and a focused Linux/macOS/Windows CI gate.

The implementation is deliberately passive. It can report bounded categorical facts, but it cannot install a package, invoke a discovered executable, contact an endpoint, resolve a credential, initialize CUDA or a model runtime, create a broker, start a loop, mutate the repository, or grant runtime authority.

## Why three states are necessary

| State | Meaning | Can grant authority? |
|---|---|---|
| `declared` | An operator or adapter says that a profile or capability is intended | No |
| `detected` | A passive bounded observation found a categorical condition | No |
| `proven` | An independent trusted conformance suite produced fresh, exact-bound, authenticated evidence | Only after the consuming runtime re-verifies that evidence |

Presence is not proof. Linux does not imply `openat2` policy correctness; WSL does not imply DrvFS safety; a container marker does not imply isolation; `nvidia-smi` on a search path does not imply usable CUDA; a client instruction file does not imply that a client loaded or obeyed it.

The current doctor therefore always returns `profile.proven: null`, marks every runtime-security capability `not-tested`, and returns an empty `effectiveCapabilities` list. It exposes no caller-supplied evidence parameter. An unsigned dictionary cannot elevate a capability.

## Versioned contracts

### `PlatformProfile`

`src/eco_cli/schemas/platform-profile.schema.json` describes a content-minimized host profile:

- declared, detected, and proven platform classification remain separate;
- operating-system family and nested context observations use bounded enums;
- executable and client inventories expose only allowlisted logical identifiers and categorical state;
- filesystem, environment, process, executable, and projection semantics remain explicit `detected` or `not-tested` facts;
- runtime-security capability records carry separate declared/detected/proven fields, while this passive profile forbids `proven` and `effective` values;
- effective capabilities are structurally fixed empty in this version;
- safety flags require no execution readiness, authority creation, mutation, or network access.

The semantic `profileDigest` excludes its own value. The validator additionally rejects unsorted or duplicate capability ids, digest drift, unknown fields, every non-null platform proof, and every effective capability claim. Proven capability state belongs only to the separately authenticated runtime `AdapterConformanceProfile` and its consuming policy boundary.

### `AdapterCapabilityProfile`

`src/eco_cli/schemas/adapter-capability-profile.schema.json` is a declaration-and-inventory contract. It binds an adapter id, deployment identity digest, and platform-profile digest to a sorted capability list. In this version:

- `authority` is fixed to `declaration-and-inventory-only`;
- `effectiveCapabilities` must be empty;
- each capability has `effective: false`;
- `proven` cannot be set to `proven`;
- safety fixes `authorityCreated` and `executionReady` to false.

This contract does not duplicate the existing runtime `AdapterConformanceProfile`. The new profile describes claims and observations; the existing runtime record is the authenticated, freshness-bounded result of an independently governed suite. Only the runtime trust path may verify the latter and use it in a policy decision.

## Passive doctor

```bash
eco platform doctor --json
```

The public command performs only these operations:

1. derives a coarse OS family through Python runtime metadata;
2. categorizes WSL from the kernel release and a container from a fixed filesystem marker;
3. checks ten allowlisted executable names with path resolution but never opens or invokes the executable;
4. uses `lstat` to report the regular-file presence of five fixed client projection locations without reading their contents;
5. emits one deterministic, sanitized JSON document.

The doctor does not enumerate arbitrary environment variables. Hosted-CI and environment hints exist in the normalized fixture interface so the classification rules can be tested, but mutable hints cannot prove a context. A hint without its independent categorical marker is blocked. Multiple simultaneous strong contexts, such as WSL inside a container or a hosted runner inside a container, are `ambiguous` and blocked rather than collapsed into whichever profile appears strongest.

The allowlists are intentionally small:

- executables: `claude`, `codex`, `cursor`, `docker`, `gemini`, `git`, `node`, `nvidia-smi`, `ollama`, `python`;
- clients: Claude, Codex, Copilot, Cursor, and Gemini projection locations.

Only names and states are emitted. `shutil.which` consults the current process search-path rules as a narrowly bounded exception to the no-environment-enumeration rule; the path values and resolved locations are neither emitted nor included in the report digest. Absolute paths, search-path contents, command output, file contents, host/user ids, endpoints, model ids, tokens, device names, package inventories, and raw exceptions are excluded. An unexpected probe failure becomes the fixed `ECO_PLATFORM_PROBE_FAILED` code.

## Classification behavior

| Input condition | Result |
|---|---|
| Linux with no nested marker | `linux-native` |
| Linux kernel categorized as WSL | `wsl` |
| Darwin | `macos` |
| Windows | `windows-native` |
| Corroborated container marker | `container` |
| Corroborated hosted-CI fixture marker | `hosted-ci` |
| Mutable hint without corroboration | blocked |
| More than one strong nested context | `ambiguous`, blocked |
| Declared and detected profile mismatch | blocked |
| Unsupported or internally inconsistent OS | blocked |

Detection success means only that the inventory completed. It does not mean execution is ready.

## Conformance fixtures and adversarial gate

Six deterministic JSON fixtures cover Linux native, WSL, macOS, Windows native, container, and hosted CI. They contain categorical booleans only; no path, environment value, endpoint, device, or credential is stored.

The focused tests verify:

- byte-stable results and semantic digests;
- strict separation of declared, detected, proven, and effective state;
- no unsigned evidence input channel;
- closed schema validation, digest binding, capability order, and duplicate rejection;
- fail-closed OS inconsistency, mutable-marker spoofing, unknown fields, duplicate inventory entries, unsupported platforms, and nested contexts;
- changed observations change digests but never create authority;
- exactly one JSON result with no repository path or secret canary;
- no subprocess, shell, socket, HTTP, write, rename, delete, or executable invocation;
- unchanged repository bytes and mtimes after the CLI probe.

The hosted portability job runs this focused test module together with the M4.5.1 adoption suite on Linux, macOS, and Windows. Those jobs prove deterministic Python contract behavior on the three operating systems; they do not prove native read brokers, isolation, controlled writes, CUDA, NIM, model routing, or loops.

## Explicit non-claims

M4.5.2 does not prove:

- that an executable starts, is the expected binary, is safe, or has a compatible version;
- endpoint reachability, authentication, model identity, model quality, privacy, retention, or provider provenance;
- CUDA, GPU, NIM, Docker, local-model, or cloud-model functionality;
- shell quoting, descendant-process containment, sandboxing, network denial, credential access, or package-manager safety;
- Windows reparse/case-fold behavior, macOS sandbox semantics, WSL DrvFS semantics, container escape resistance, or NFS/CIFS/FUSE behavior;
- repository read-broker, write-broker, approval, recovery, routing, or loop availability on a new backend;
- evidence freshness after the doctor completes;
- authorization. A doctor report and its digest are inventory metadata, not a capability token.

## Handoff to M4.5.3

M4.5.3 may package and install the harness only against this frozen boundary:

1. installation remains separate from passive detection;
2. an installer cannot convert declared/detected facts into proven capabilities;
3. packaging must preserve the M4.5.1 preview, ownership, and reversible-uninstall rules;
4. every native runtime backend needs its own controlled conformance runner and authenticated evidence;
5. unsupported security controls remain unavailable without fallback.
