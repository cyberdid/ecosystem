# M2 completion report

**Status:** complete for the embedded read-only reference profile

**Date:** 2026-07-15

## Outcome

M2 delivers a read-only, default-deny execution slice with governed deployment identities, trusted repository and capability evidence, broker-owned authority, sanitized durable events, OS-enforced direct-egress denial for untrusted processes, and one passing live local/cloud evaluation.

This is not a production-autonomy claim. The executable filesystem, snapshot, and isolation proof is Linux/WSL-specific; Windows and macOS retain contract-only portability until their backends pass the same conformance suite.

## Exit criteria

| Criterion | Result | Evidence |
|---|---|---|
| Agent processes have no provider/tool credentials | Pass for the reference profile | The untrusted-agent launcher rejects every credential binding before execution; the separate trusted provider transport owns its OS-managed authentication |
| Direct egress bypass is denied | Pass for Linux/WSL deny profile | user/net/pid namespace plus Landlock TCP deny; host loopback bypass test cannot connect |
| One local and one cloud deployment have governed identity records | Pass at the observable-identity level | `.ai/evals/live/2026-07-15-m2-closure-pass/deployment-identities.json`; local manifest/transport are recorded, while the cloud model is explicitly a provider alias rather than immutable weights |
| Unsupported capability returns typed failure | Pass | policy and adapter negative tests |
| Read-only access remains inside repository boundary | Pass for Linux/WSL | `openat2` snapshot generator and repository broker symlink, hardlink, mount, protected-path, binary, and mutation tests |
| Sensitive content is absent from default evidence/audit | Pass | safe-record journal scans, sanitized adapter/evaluation records, live evidence scan |
| The same evaluation runs on both deployments | Pass | suite `08d7ee...26dd6`, signed evidence `1c7e8d...e46927`, publication manifest `fabdb4...d624`; both observations were independently ingested and the local envelope passed the production PolicyEngine gate |

## Implemented boundary

- immutable runtime contracts and exact digests of governed deployment identity records;
- trusted HMAC evidence envelopes with issuer/kind/project/deployment/suite/time binding;
- canonical signed evidence-envelope bytes plus exact immutable issuer policies; `PolicyEngine` constructs its own verifier, binds provenance into plans, re-verifies at construction/planning/activation/tool authorization, and caps allow-decision expiry to supporting evidence; the installed runtime has no unsigned constructor or injectable verifier;
- descriptor-anchored Linux repository snapshot generation;
- pure policy engine, immutable plans, single-use decisions, and no automatic fallback;
- filesystem-only read broker and typed orchestrator;
- durable SQLite plan/event/budget/operation authority and private artifact CAS;
- governed local/cloud adapter contracts with strongest-observable identity and sanitized model result records;
- Linux/WSL untrusted-agent launcher with clean environment, zero credential bindings, executable allowlist, namespaces, Landlock filesystem/TCP deny, closed stdin, bounded output, timeout, and fail-closed preflight;
- deterministic cross-deployment runner, digest-bound observations, signed aggregate evidence, and live local/cloud proof.

## Test evidence

The final repository gate passes:

- `python -m unittest discover -s tests -v`;
- `pytest`;
- `compileall` for `src`, `tests`, and `scripts`;
- `eco validate`;
- `eco render --check`;
- `eco doctor`;
- `git diff --check`.

The suite contains 187 automated tests at closure, plus the live local/cloud evaluation.

## Explicit limitations beyond M2

- Endpoint-specific network allowlists are not implemented by the Linux launcher; its executable proof supports network deny and rejects allowlist mode before resolving credentials.
- The executable isolation proof is Linux/WSL only. Windows/macOS implementations are future platform adapters.
- Initial executable allowlisting does not prevent arbitrary descendant `exec`; stricter process control requires seccomp/container/OS backends.
- No cgroup, GPU/device, seccomp, or host-admin containment is claimed.
- Evidence replay-ID tracking is process-local; durable replay authority is future work.
- HMAC keys require secure provisioning and rotation and do not provide third-party non-repudiation.
- Provider retention, region, auxiliary model use, and training behavior require contractual/provider evidence before non-public data can be routed.
- The cloud model name is an observable routing alias, not provider attestation of immutable weights or serving revision.
- M2 live observations expire after 24 hours. Expired records remain historical evidence but cannot authorize current routing; renewal requires a fresh run, signature verification, and trusted ingestion.
- Retained evaluation evidence is raw-content-free for the D0 probe, not information-free: deterministic digests of low-entropy values may be guessable.
- Controlled writes, approvals, rollback, and A2+ actions remain M3.

## M3 gate

M3 may now begin with controlled workspace writes and approvals, while preserving M2 as the regression baseline. Any new platform/backend must pass the same contracts, isolation negatives, trusted-evidence ingestion, and parity-evaluation mechanism before promotion.
