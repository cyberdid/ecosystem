# Read-only repository broker

**Status:** integrated into the durable M2 Linux/WSL read-only reference profile

**Updated:** 2026-07-15

## Purpose

`RepositoryReadBroker` is the filesystem-only reader inside the first A1 tool boundary. It accepts only a validated repository-relative path and a byte bound. `EmbeddedOrchestrator` and the SQLite authority validate the active `RunPlan`, `ToolRequest`, single-use decision, snapshot binding, lease, and budget before broker I/O.

The returned field is deliberately named `untrusted_content`. Reading a file does not make its instructions trustworthy and does not authorize another tool, a model route, or an external side effect.

## Required chain

```text
trusted RepositorySnapshot
        ↓ digest + root identity + D/P entry metadata
immutable RunPlan + SQLite-owned budget/lease authority
        ↓
ToolRequest(path)
        ↓
PolicyEngine: known path, not protected, class ≤ run class
        ↓ single-use allow
EmbeddedOrchestrator → Linux openat2 broker(path, byte bound)
        ↓ size/digest/UTF-8 checks
RepositoryReadResult(untrusted_content, D, P, snapshot digest)
```

Unknown paths fail closed. D4 entries are never released. An entry above the run's effective data class requires a newly planned run; the broker does not silently escalate or reroute.

## Filesystem enforcement

The current backend supports tested Linux `x86_64` and `aarch64` profiles and uses:

- an operator-selected root opened once as a directory descriptor;
- `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`;
- an `O_PATH` inspection before a regular file is reopened through its pinned `/proc/self/fd` handle;
- regular-file, single-hardlink, byte-limit, UTF-8, NUL, before/after stat, manifest size, and SHA-256 checks;
- lifecycle locking and a duplicated root descriptor so concurrent `close()` cannot retarget a reused file descriptor;
- a runtime-owned, atomic input-byte reservation before content is read.

There is no permissive fallback when `openat2` or the tested architecture profile is unavailable.

The single-hardlink rule is defense in depth and may reject legitimate repositories. A high-assurance deployment should broker an isolated, read-only snapshot/export with fresh inodes instead of a mutable brownfield working tree.

## Snapshot trust boundary

`RepositorySnapshot` records bind project and root identity, issuer label and snapshot trust, and every readable path's expected length, content digest, data class, trust, and classification authority.

`LinuxRepositorySnapshotGenerator` creates descriptor-anchored snapshots from explicit per-path classifications. `HmacEvidenceSigner` authenticates issuer, project, root identity, validity, and exact record digest. In production, `PolicyEngine` accepts canonical signed snapshot-envelope bytes plus exact immutable `EvidenceIssuerPolicy` trust anchors and constructs its own verifier; it re-verifies at construction, run planning, plan activation, and tool authorization. No unsigned constructor exists in the installed runtime package. HMAC remains an embedded shared-key identity, not third-party non-repudiation. A filename denylist remains an extra guard, not the classification mechanism.

## What current tests prove

Negative tests cover absolute/traversal/ambiguous paths, final and intermediate symlinks, hardlink aliases, protected and unsnapshotted paths, D2/D4 escalation, missing files, directories, FIFO files, binary/NUL and invalid UTF-8 data, oversized files, post-snapshot mutation, decision replay, plan/snapshot binding, shared budget state, and idempotent concurrent close.

These tests run under WSL/Linux. Separate isolation tests prove network denial and a clean environment for the Linux launcher. They do not prove Windows reparse-point safety, macOS behavior, DrvFS/NFS/CIFS/FUSE semantics, endpoint-specific allowlists, host-admin containment, or safety against a malicious process that already owns the trusted broker process.

## Integrated M2.5 boundary

`RepositoryReadBroker` is now a filesystem-only reader. `EmbeddedOrchestrator` owns the trusted policy/store capabilities and executes `PREPARE → read → artifact fsync/proof → SUCCESS/FAILURE`; SQLite is the sole budget, nonce, lease, and lifecycle authority. Broker exceptions are mapped to fixed safe messages, and terminal idempotent replay never repeats filesystem I/O.

## Remaining beyond M2

- add Windows and other filesystem backends with their own conformance suites;
- add endpoint-specific network allowlist and stronger descendant-process controls;
- add asymmetric/durable evidence identity for team or remote topologies;
- extend the bound runtime step to controlled writes only after M3 approvals and rollback exist.
