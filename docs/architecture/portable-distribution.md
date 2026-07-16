# M4.5.3 portable offline distribution

**Status:** implemented for the bounded wheel-only integrity profile

**Updated:** 2026-07-16

## Purpose

M4.5.3 makes the Python harness distributable without tying project adoption to a model, IDE, provider, GPU, or runtime backend. It solves two separate problems:

1. prove that one local offline wheelhouse exactly matches deterministic integrity metadata;
2. describe standard package-manager operations without silently executing them.

Installing the `eco` command and adopting `.ai/` into a repository remain separate lifecycles. Package installation never grants repository-write, model, network, broker, adapter, loop, or conformance authority.

## Distribution contract

`DistributionManifest` is a closed `distribution.ai.ecosystem/v1alpha1` document. Its semantic digest binds:

- package name, version, entry point and Python requirement;
- one main wheel and the exact sorted dependency-wheel inventory;
- SHA-256 and byte size for every wheel;
- the exact `uv.lock` SHA-256;
- source revision;
- every packaged CLI/runtime JSON Schema path, SHA-256 and size;
- the installer-preview inventory and explicit support/non-support flags;
- safety flags fixed to no installation, mutation, network access or authority creation.

The manifest intentionally states `originAuthentication: not-attested`. Its digest and artifact checks prove byte integrity and internal consistency, not publisher identity, source provenance, non-repudiation, revocation freshness, or reproducible-build identity. A first installer cannot authenticate itself; a future public provenance layer requires an out-of-band trust anchor and separately authenticated release policy.

## Offline verifier

Two verifiers implement the same bounded profile:

- `eco distribution verify` uses the installed contract implementation;
- `scripts/verify_distribution.py` is a standard-library-only pre-install verifier.

Both require absolute local paths and perform no network, subprocess, package-manager or write operation. Verification rejects:

- missing, extra, renamed, truncated, oversized or changed wheels or `uv.lock`;
- symlink, hardlink, FIFO and supported reparse aliases;
- manifest duplicates, unknown fields, invalid ordering or digest drift;
- invalid ZIP paths, duplicate/case-fold/NFC aliases, encrypted entries, special-file members, entry/count/expanded-size excess, missing or inventory-inconsistent `RECORD`, or inconsistent wheel metadata;
- a main wheel without the `eco` console entry point, `Requires-Python: >=3.11`, required package modules, schemas, `METADATA`, `WHEEL` and `RECORD`;

`RECORD` is checked for a complete, unique member inventory. Per-entry `RECORD`
hashes are not treated as a separate trust anchor because the closed manifest
already pins the SHA-256 digest of every complete wheel byte stream.
- a dependency artifact that is merely named `.whl`, lacks a PEP-427-shaped filename, disagrees with its `METADATA` identity, or is not a structurally valid wheel.

Hashing and ZIP inspection use the same bounded bytes. This removes the earlier verified-path/inspected-path split inside the verifier. The verifier still does not pin verified artifacts into an immutable content-addressed installation stage; standard package-manager execution is therefore a separate operator boundary.

## Installer previews and real smoke gate

`eco distribution plan` emits deterministic argv-token previews for `venv-pip`, `pipx` and `uv tool`. Every plan has `executionReady: false`; no shell or package manager is invoked. The preview requires an already verified bundle, an isolated user environment, no administrator privileges and separate project adoption.

The hosted Linux packaging gate exercises the supported reference path rather than treating a preview as installation proof:

1. build the real `0.6.0` main wheel plus all dependency wheels;
2. copy the locked dependency input into the wheelhouse;
3. create and independently verify the manifest;
4. create a fresh virtual environment;
5. install with `pip --no-index --find-links`;
6. run `eco --version` from the installed environment.

The fixture/contract suites run on Linux, macOS and Windows. They prove portable manifest, verifier and preview behavior; they do not prove native package-manager transactions for every manager on every OS.

## Relationship to project adoption

After installing the CLI, the only supported repository bootstrap remains:

```text
eco --repo PROJECT adopt --dry-run --json
eco --repo PROJECT adopt --apply PLAN_DIGEST --json
```

Package upgrade/uninstall must not edit `.ai`, projection backups or adoption receipts. Conversely, `eco uninstall` removes only receipt-owned project projections/configuration and never uninstalls the Python package.

## Exact support boundary

| Surface | Status |
|---|---|
| Pure-Python main wheel contract | Implemented and built in CI |
| Exact local dependency wheelhouse + `uv.lock` integrity | Implemented |
| Standard-library pre-install verification | Implemented |
| Linux fresh private-venv offline install smoke | Implemented |
| Linux/macOS/Windows contract and negative fixtures | Implemented |
| `pipx` / `uv tool` argv preview | Implemented, non-executable |
| Publisher signature, transparency log, SBOM, revocation | Not implemented |
| Immutable verified-byte CAS handoff to package manager | Not implemented |
| Transactional manager-owned upgrade/rollback/uninstall matrix | Not implemented |
| zipapp, standalone binary, OS package managers/installers | Not implemented |

Those non-claims do not weaken M4.5.1 adoption ownership or M4.5.2 detection/proof separation.
