# M4.5.1 safe project-adoption bootstrap

**Status:** implemented for canonical `.ai` bootstrap and instruction-surface projection on Linux, macOS, and Windows

**Updated:** 2026-07-16

## Purpose

M4.5.1 makes the harness installable into an arbitrary existing repository without binding that repository to a model, provider, IDE, gateway, or machine. It solves one narrow problem: establish the canonical ecosystem contracts and reversible client projections while preserving every pre-existing byte unless the operator explicitly accepts a previewed plan.

It does not port the Linux/WSL runtime broker, isolation launcher, or controlled-write backend to other operating systems. Those remain separate conformance profiles.

## Operator flow

```text
repository
  → read-only discovery
  → deterministic raw-content-free ProjectAdoptionPlan
  → operator reviews planDigest and operations
  → eco adopt --apply <planDigest>
  → exact preconditions are recomputed under an exclusive lock
  → canonical contracts + managed projections + receipt are installed
  → validation succeeds or every touched file is rolled back
```

Preview is mandatory:

```bash
eco --repo /path/to/project adopt --dry-run --json
eco --repo /path/to/project adopt --apply <planDigest> --json
```

If a valid `.ai` directory already exists, adoption is blocked until the operator adds `--adopt-existing-config`. This records the canonical files as `preexisting`; it never converts them into ecosystem-owned files.

## Versioned contracts

`ProjectAdoptionPlan` and `ProjectAdoptionReceipt` use `adoption.ai.ecosystem/v1alpha1` and have packaged JSON Schema 2020-12 definitions.

The plan contains only:

- repository-relative paths;
- before/after digests and file/absence states;
- operation and ownership classes;
- counts for discovered languages, build files, instruction surfaces, and potential secret locations;
- sanitized warnings/blockers;
- one digest over the canonical plan body.

It never contains repository absolute paths, source contents, secret-like values, endpoints, credentials, or inferred executable commands. `planDigest` detects a stale preview; it is not authentication, approval, or runtime authorization.

The portable receipt at `.ai/adoption.json` records exact file roles and ownership:

| Role | Ownership | Removal rule |
|---|---|---|
| Canonical | `created` | removable only while its exact created digest still matches |
| Canonical | `preexisting` | never removed by adoption uninstall |
| Projection | `created` | deleted only through managed projection state |
| Projection | `managed-block` | original bytes restored from the exact before-image backup |
| Generated | `generated` | removable only while its exact digest still matches |

Private render state and before-images remain under `.ai/.state/`; `.ai/.state/.gitignore` keeps them out of Git while preserving that ignore rule itself.

## Modes

### Fresh

No `.ai` directory exists. The command builds a starter bundle in memory, validates it before the first write, discovers only descriptive metadata, and previews creation of canonical contracts, projections, the deterministic lock, state ignore rule, and receipt.

### Existing config

A valid `.ai` directory exists without an adoption receipt. The default result is `ECO_ADOPTION_CONFIG_EXISTS`. With explicit `--adopt-existing-config`, canonical files remain pre-existing, projections are adopted reversibly, and only ecosystem-generated state is owned.

### Reinstall

A valid receipt exists. The current repository is compared with the receipt and canonical contracts. A clean reinstall is a byte- and mtime-preserving no-op. Drift produces a new plan or a blocker; it is never silently overwritten.

## Safety invariants

1. `--dry-run` performs no repository write.
2. Apply recomputes the complete plan and requires the exact preview digest.
3. All projection preconditions are checked before the first projection mutation.
4. Existing instruction surfaces are preserved byte-for-byte in content-addressed backups before a managed block is appended.
5. Symlinks, non-regular targets, hard-linked regular files on supported POSIX hosts, path escape, non-UTF-8 projections, invalid canonical config, and unsafe receipt/state are rejected.
6. Apply is serialized per resolved repository by a process-external lock and performs transactional best-effort rollback of every planned file and newly created backup on failure.
7. Full removal performs a complete read-only preflight before projection cleanup. Canonical drift, projection drift, unknown `.ai` entries, missing ownership evidence, unsafe state, or pre-existing config blocks the operation with zero mutation.
8. Removal enumerates receipt-owned files; it never recursively deletes an unverified `.ai` tree.

## Portability boundary

The bootstrap uses Python filesystem primitives and is covered by focused CI on Linux, macOS, and Windows. This proves the adoption CLI and contract behavior on those hosted filesystems only. It does not prove hostile concurrent-directory-swap resistance, Windows reparse-point security, case-fold collision safety on every filesystem, platform package-manager installation, executable isolation, network denial, repository-read brokering, or controlled writes.

The receipt and render state are strict local ownership metadata, not a cryptographically authenticated identity. The implementation rejects malformed, aliased, incomplete, drifted, and digest-inconsistent metadata. An actor already able to coherently rewrite the receipt, state, backups, and repository targets is outside this bootstrap proof; team-authenticated ownership belongs to the future M5 identity boundary.

Custom config roots are intentionally blocked in `v1alpha1`. A second root would change receipt ownership, ignore, projection-source, and uninstall semantics and therefore needs a separately versioned contract.

## Failure codes

The command emits stable `ECO_ADOPTION_*` codes, including:

- `ECO_ADOPTION_CONFIG_EXISTS`;
- `ECO_ADOPTION_PLAN_CHANGED`;
- `ECO_ADOPTION_PATH_UNSAFE`;
- `ECO_ADOPTION_BUSY`;
- `ECO_ADOPTION_CONFIG_DRIFT`;
- `ECO_ADOPTION_UNKNOWN_CONFIG_ENTRY`;
- `ECO_ADOPTION_PREEXISTING_CONFIG`;
- `ECO_ADOPTION_RECEIPT_REQUIRED`.

Errors are sanitized. The JSON result does not echo file contents or absolute repository paths.

## Next slice

M4.5.2 should define versioned `PlatformProfile` and adapter-capability contracts, then execute a conformance matrix for Windows native, macOS, Linux, WSL, container, and CI profiles. A platform receives a capability only after a backend-specific test proves it; unsupported runtime security controls must remain unavailable rather than falling back to a weaker implementation.
