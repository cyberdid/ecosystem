# M4 portability completion report: M4.5.3 and M4.6

**Date:** 2026-07-16

**Scope:** portable offline wheel distribution plus controlled Linux/WSL backend conformance

## Result

The remaining bounded M4 portability slices are implemented.

- M4.5.3 adds a closed distribution manifest, exact local wheelhouse/lock/schema integrity verification, a standard-library pre-install verifier, deterministic non-executable installer previews and a real private-venv offline installation smoke gate.
- M4.6 adds a separate explicit active conformance command, a fixed synthetic Linux/WSL namespace + Landlock suite, a closed content-free backend evidence record and exact external envelope ingestion with no policy/runtime consumer.

Version `0.6.0` marks both additions. Neither turns platform detection, checksum integrity or a signed observation into runtime authority.

## Multi-agent method

Three parallel roles were used while the main implementation continued:

1. a distribution test agent built deterministic wheel fixtures and offline/no-process/no-write adversarial coverage;
2. a threat-model agent audited distribution bootstrap, archive, installer, active-runner, test-root and evidence boundaries;
3. a contract reviewer independently inspected packaging honesty, cross-platform behavior and race/alias gaps.

The reviews produced material corrections before completion:

- `uv.lock` was initially bound into the manifest but not re-read by verification; tampering now blocks both verifiers;
- early fixtures allowed arbitrary bytes named `.whl`; main and dependency artifacts now require wheel metadata and `RECORD`, while the main wheel additionally requires its package modules, schemas, `Requires-Python` and `eco` entry point;
- wheel hashing and internal inspection initially reopened the path; they now operate on the same bounded regular-file bytes;
- file aliases, ZIP special members, normalized-name collisions and cumulative expansion limits were strengthened;
- the standalone verifier initially accepted some manifests rejected by the normative schema; version/revision/digest/path/support/provenance and archive checks were aligned and exercised directly;
- Python numeric aliases (`0`/`1` for booleans and integral floats for integer sizes), oversized manifest identities and non-PEP-427 wheel names are now rejected equivalently by the library and standalone verifier;
- M4.6 capabilities were narrowed to what the existing launcher actually proves; no descendant-exec, seccomp, cgroup, device, endpoint-allowlist or credential claim was added;
- live context is detected independently of the supplied passive profile, the clean-environment probe seeds a parent canary and checks the exact child environment, and non-object profile JSON fails closed through the CLI;
- signed backend evidence ingestion now pins the exact runner and backend implementation digests in addition to platform, distribution, backend instance and suite;
- active runner evidence was kept out of policy/store composition, and the probe child never receives a signing key.

## M4.5.3 evidence

The distribution test profile covers:

- deterministic manifest and plan digests;
- exact main/dependency/lock/schema binding;
- malformed/duplicate/unknown manifest data;
- wheel, dependency, schema and lock tampering;
- missing/extra/truncated/oversized artifacts;
- symlink, hardlink and FIFO rejection;
- paths with spaces and Unicode;
- offline, read-only, no-process, no-installer and no-secret-access traps;
- sanitized CLI failures and a standard-library verifier pass/fail pair.

A real local packaging smoke built `ai_ecosystem_harness-0.6.0-py3-none-any.whl` plus seven dependency wheels, created and verified the exact eight-artifact offline manifest, installed into a clean virtual environment with `--no-index --find-links`, and returned `eco 0.6.0`.

The workflow now repeats that smoke on hosted Linux. Focused manifest/adoption/profile tests run on hosted Linux, macOS and Windows. The latter jobs are contract portability evidence, not native runtime-security proof.

## M4.6 evidence

Seven focused adversarial tests cover:

- exact sorted suite/probe/capability inventory and semantic schema invariants;
- `--active`, suite digest and safe-root checks before process or mutation;
- Windows/macOS/container/hosted-CI unsupported records with zero launches/writes;
- deterministic pass/fail behavior through a fake launcher, including inherited-environment and output/deadline error paths;
- absence of raw root, secret canary and backend output from records;
- sanitized rejection of valid JSON values that are not profile objects;
- exact HMAC envelope signing/ingestion, replay, runner/implementation binding mismatch and envelope-ID conflict.

The existing seven isolation tests pass on the local WSL host. A live fixed-suite run against the real `LinuxNamespaceLauncher` passed and observed only:

- `backend.clean-environment`;
- `backend.landlock-workdir-boundary`;
- `backend.network-namespace-deny`;
- `backend.output-deadline-bounded`;
- `backend.read-only-workdir`;
- `backend.stdin-closed`.

The test root was empty after the run.

## Verification snapshot

At the implementation checkpoint:

- complete pytest suite: 381 tests passed on Python 3.12;
- distribution focused suite: 17 passed;
- backend-conformance focused suite: 7 passed;
- live isolation suite: 7 passed;
- real wheel build, stdlib verification, offline install and installed CLI version smoke: passed;
- Python compilation, JSON Schema checks and `git diff --check`: passed.

Remote hosted results are recorded separately after the pushed commit finishes CI; a configured workflow is not itself passing evidence.

## Explicit non-claims

M4.5.3 does not provide publisher authentication, asymmetric signatures, transparency, SBOM, online acquisition, immutable CAS handoff, package-manager rollback transactions, standalone binaries or OS-native installers. `pipx` and `uv tool` are preview adapters only in this slice.

M4.6 does not make Windows/macOS/container/hosted CI a supported enforcement backend, and its signed records are not capability tokens. It has no policy consumer and does not authorize M2 reads, M3 writes, models, adapters, credentials, scheduling, retry or loops.

M4 as a whole remains the fixed manual no-model L0–L2 reference profile plus its bounded adoption, passive-platform, packaging and Linux/WSL backend-conformance surfaces. M5 team identity, signed policy distribution, RBAC, revocation and shared-state authority remain next.
