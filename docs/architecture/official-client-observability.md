# Official assistant clients, private traces and reviewed learning

**Status:** accepted product-adapter boundary; first Nordrassil slice implemented
**Updated:** 2026-07-26
**Product revision:** `cyberdid/nordrassil@101a321`

## Decision

Nordrassil may invoke the locally installed official Claude Code, OpenAI Codex
and GitHub Copilot clients as bounded subprocess adapters. The official client,
not Nordrassil, owns account login, token refresh, Keychain access and cached
credentials.

These clients are **not** entries in the ecosystem canonical
`DeploymentCatalog`. A successful CLI login or one successful response proves
only that this product adapter can invoke that client in the observed local
environment. It does not establish a model identity, semantic capability,
conformance envelope, cost contract or governed deployment authority.

No canonical `.ai/deployments.yaml` entry was added for this slice. That is
intentional, not an omitted registration.

## Adapter boundary

| Client | Bounded invocation | Machine-readable output | Login owner |
|---|---|---|---|
| Claude Code | `claude -p`, fixed permission mode, turn budget and no session persistence | `stream-json` | Claude Code |
| OpenAI Codex | `codex exec`, fixed workspace, ephemeral session, sandbox/approval mode | JSONL | Codex |
| GitHub Copilot CLI | documented one-shot programmatic mode; ACP remains the preferred persistent follow-up | JSON/JSONL | Copilot CLI |

The adapter:

- selects only a fixed discovered executable;
- constructs an argv vector without a shell;
- pins the active project as the working directory;
- validates model identifiers, mode and prompt size;
- applies turn and wall-clock budgets;
- passes only a client-specific environment allowlist;
- captures bounded stdout, stderr, structured events, exit status and usage;
- returns a sanitized public error while keeping private diagnostic evidence.

The adapter does not:

- scrape browser sessions, cookies, Keychain entries or another client's token
  files;
- accept an arbitrary executable or command line from a browser request;
- convert client authentication into canonical ecosystem authority;
- claim that API-compatible transport implies semantic compatibility;
- let a trace, skill, model response or learned lesson grant permission.

## Superuser

Nordrassil Superuser is an explicit single-operator testing override. For an
official client it selects the client's own unrestricted flag. This deliberately
removes that client's local approval/sandbox guard for the run.

The trace still records:

- requested mode;
- exact fixed argv shape, with an argv-carried prompt replaced by `[PROMPT]`;
- the product capability path;
- client events and exit state;
- `authority: none` for the trace itself.

Superuser does not rewrite the ecosystem core verdict and is not a deployment,
team or production authorization.

## Private execution trace contract

Every Nordrassil Chat turn and official-client invocation creates one
project-scoped trace. A complete private trace contains:

- trace/project identity and operation kind;
- client/provider/model and execution mode;
- bounded input or prompt;
- fixed argv shape and prompt transport;
- model/client event stream and tool decisions;
- output, stdout and bounded stderr;
- status, stable error code, duration, exit code, event and byte counts;
- learning state and optional memory digest;
- explicit hard limits and `authority: none`.

Private traces are:

- stored outside Git in product runtime state;
- mode `0700` per project and `0600` per record/key;
- sealed with HMAC-SHA256 and bound to exact project and trace identifiers;
- rejected on tampering, symlinks, hardlinks, oversize or invalid lifecycle;
- redacted before persistence for known environment-secret values, bearer
  credentials and common credential assignments.

Hard limits in the first version:

| Boundary | Limit |
|---|---:|
| input | 256 KiB |
| output/stdout | 8 MiB |
| stderr | 1 MiB |
| structured events | 2,048 |
| complete trace envelope | 16 MiB |
| traces per project | 10,000 |
| client wall clock | 10–3,600 seconds |
| client turn budget | 1–64 |

The list projection is content-free: it exposes identity, status, metrics,
error code, integrity and learning state, but no prompt, output, stderr or event
payload. Private content requires the separate `audit.read` capability.

Existing specialized evidence remains valid rather than being silently
flattened:

| Surface | Durable evidence |
|---|---|
| Chat and official assistant clients | private HMAC execution traces |
| bounded Agents | authenticated manifests, checkpoints and runtime event chains |
| Deep Research | project-private trajectory, source CAS and citation evidence |
| Eval Lab | private transcripts plus sanitized reports |
| Cookbook jobs | typed plans, progress and bounded job logs |
| Memory | provenance-bound HMAC records and explicit review state |

Trace Lab is the first unified analysis surface for Chat/client traces. A
cross-surface index over every specialized evidence store is still a separate
future projection; absence of that projection must not be described as absence
of the underlying logs.

## Error analysis and learning loop

Learning is a bounded, review-gated loop:

```text
terminal private trace
→ operator requests analysis
→ one selected model receives one bounded UNTRUSTED trace
→ structured lesson proposal
→ provenance-bound memory item in state proposed
→ human review: reviewed | rejected
→ only reviewed memory may be retrieved by later runs
```

The analysis prompt requires separate observed facts, hypotheses, failed
approach, prevention, next verification and open uncertainties. It has no tools
and cannot infer permissions. Oversize evidence is reduced to a deterministic
bounded tail and that coverage loss is recorded.

Analysis requires four independent grants:

- `audit.read`;
- `learning.analyze`;
- `memory.write`;
- `models.invoke`.

A generated lesson starts as `proposed`. It cannot approve itself, modify
policy, widen a team manifest, enable Superuser or become retrievable verified
memory without a separate human review. This preserves VERIFIED-STATE,
POLICY-OUTSIDE-PROMPTS and BOUNDED-LOOPS while still letting the product learn
from real failures.

## Verification evidence

Nordrassil revision `101a321`:

- full product suite: 139/139;
- focused trace/client/security suite: 18/18;
- Python compilation, inline JavaScript parsing and `git diff --check`: clean;
- live Codex profile: installed and authenticated through the official client;
- live Superuser smoke: exact bounded response returned, four JSONL events
  captured, exit code zero and private HMAC trace persisted;
- public trace list contained no prompt/output; private retrieval returned the
  exact bounded trajectory.

Claude Code and Copilot CLI were not installed on the observed Mac, so their
argv, gate, redaction and failure paths are covered deterministically but no
live upstream invocation is claimed.

