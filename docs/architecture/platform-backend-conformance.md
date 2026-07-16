# M4.6 controlled platform-backend conformance

**Status:** implemented for the fixed Linux/WSL namespace + Landlock profile

**Updated:** 2026-07-16

## Purpose

M4.5.2 describes a platform without running it. M4.6 adds a separate, explicitly active runner that can test one already implemented backend without allowing the backend to certify itself into runtime authority.

`eco platform doctor` remains passive and unchanged. It never imports or calls the runner. The active surface is `eco conformance run`, requires `--active`, an exact suite ID/digest, an absolute external test root, a passive `PlatformProfile`, the distribution-manifest digest and an operator-provisioned backend-instance digest.

## Fixed suite

The `linux-namespace-boundary` v1 suite accepts no arbitrary command, module, plugin, environment or endpoint. It uses packaged Python probes against synthetic data only:

1. clean environment and Landlock denial of a sibling synthetic canary;
2. network-namespace denial of a parent-owned literal-loopback sentinel;
3. stdout and deadline bounds;
4. read-only work-directory enforcement;
5. closed stdin.

The runner allows zero credentials, zero DNS/public network targets, fixed executable identity, bounded output and a two-second per-launch deadline. The environment probe seeds a fixed parent-only canary and requires the exact five-variable child environment (`PATH`, locale, `HOME` and `TMPDIR`) with home/temp bound to the synthetic work directory. Raw output, exception text, paths, ports, process identifiers, host/user names and canary bytes are not retained in the profile.

## Controlled test root

The operator must create an empty, private, canonical absolute directory outside the governed repository, package source and home tree. On POSIX it must be owned by the current user with mode `0700`. Symlink/reparse aliases, unsafe ownership/mode, non-empty roots and repository overlap fail before backend preflight or mutation.

After the backend preflight passes, the runner creates one random child containing only the synthetic work directory and canary. Cleanup is limited to that runner-owned child; the external root is left empty. Unsupported platforms and unavailable kernel controls return `unsupported` with every probe `not-run` and no observed capabilities.

## Evidence contract

The closed runtime `PlatformBackendConformanceProfile` binds:

- passive PlatformProfile ID and digest;
- platform family, architecture and native/WSL context;
- distribution-manifest digest;
- backend ID/version, implementation digest and random backend-instance digest;
- runner digest;
- exact suite ID/version/digest and ordered probe inventory;
- tested/valid-until timestamps, content-free probe results and deviations.

Successful records use `observedCapabilities`, never `effectiveCapabilities`. A partial or failed suite has an empty observation set. The record is an unsigned candidate (`authenticated: false`) and never enters policy, store, broker, model, adapter or loop construction.

An external trusted controller may sign the exact record with the existing evidence envelope. `TrustedEvidenceIngestor.ingest_platform_backend_conformance` then re-verifies issuer/key authentication, freshness, suite, platform profile, distribution, backend-instance, backend-implementation and runner bindings. HMAC remains a configured local-shared-key boundary, not third-party provenance or non-repudiation. Ingestion returns verified evidence only; M4.6 deliberately has no runtime consumer and creates no capability token.

For a live run, the runner independently classifies native Linux, WSL, container and hosted-CI signals. A declared profile/context mismatch produces `unsupported` before backend preflight; injected launchers used by unit tests do not form production evidence.

## Platform matrix

| Platform/context | Result |
|---|---|
| Linux native x86_64/aarch64 with namespaces + Landlock | Live suite supported |
| WSL x86_64/aarch64 with namespaces + Landlock | Live suite supported |
| Linux/WSL missing a required kernel control | Signed/unsigned negative record may say `unsupported`; never pass |
| Container or hosted CI profile | `unsupported` / all probes `not-run` |
| Windows native | Schema/negative fixture only |
| macOS | Schema/negative fixture only |

Linux and WSL profiles are not interchangeable. This suite does not claim endpoint allowlisting, credentials, descendant-exec/seccomp/cgroup/device containment, repository-read broker conformance, controlled-write conformance, model routing or loop safety.

## Verification

The focused suite covers exact schema semantics, confirmation/suite/root zero-effect rejection, unsupported-platform zero-effect behavior, deterministic fake-backend pass/fail, six controlled backend launches for five logical probes, raw-output/path/secret exclusion, envelope authentication, exact ingestion, replay and cross-binding mismatch/conflict rejection. Existing live isolation tests and a local WSL run pass all six observed capability checks.
