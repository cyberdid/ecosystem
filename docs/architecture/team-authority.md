# M5 team authority

**Status:** M5.0–M5.2 foundation implemented; activation, RBAC, shared authority, revocation and quorum are not yet implemented.

**Updated:** 2026-07-16

## Purpose

M5 replaces machine-local identity labels with a portable team-authority contract while preserving the existing embedded runtime safety boundary. The first slice is deliberately non-authorizing:

```text
closed identity declarations
→ Ed25519 signature verification relative to a supplied external anchor
→ immutable verification result
→ no activation, permission, runtime or write authority
```

A valid signature proves only that the holder of the externally trusted private key signed the exact canonical bytes. It does not prove that the declaration is the newest revision, that the named human is present, that revocation state is fresh, or that an operation is permitted.

## Threat model

| Threat | M5.0–M5.2 control | Remaining control |
|---|---|---|
| Bundle supplies a key that authenticates itself | Verification key comes only from a caller-supplied external `PolicyTrustAnchor`; the same key must also be exactly represented in the signed catalog | Independently provisioned anchor resolver, rotation ceremony and durable key heads in M5.5 |
| Algorithm downgrade or confusion | Envelope accepts only exact `Ed25519`; raw key and signature lengths are fixed and base64url is canonical | Hardware-backed/KMS signers remain outside this repository |
| Field, subject or project substitution | Signature covers a domain-separated canonical envelope; subject, team, project, key and record digest are re-bound after verification | Durable activation head in M5.4 |
| Duplicate keys or ambiguous serialization | Canonical UTF-8 JSON only; duplicate keys, BOM, whitespace variants, invalid UTF-8 and oversized inputs fail closed | Alternative encodings are not supported |
| Identity declaration silently grants access | Every record structurally fixes `permissionsGranted: false` and `runtimeAuthorityCreated: false`; policy profile is `deny-all` | RBAC intersection in M5.3 |
| Old valid bundle replay | CLI reports `currentness: not-established` and `activationEligible: false` | Monotonic revision/CAS authority in M5.4 |
| Project replaces its own root of trust | `eco policy verify` rejects an anchor inside the repository and labels success as relative to the caller-supplied anchor | M5.2 does not establish anchor provenance; an independently provisioned resolver/OS trust-store adapter requires later conformance |
| Unsafe input file | Descriptor-based bounded read rejects relative paths, symlinks, hardlinks, reparse points, mutation during read and non-regular files | Cross-platform file-safety claims remain bounded by hosted tests |
| M5 change invalidates M4 durable state | Runtime schemas and `schema_bundle_digest()` remain unchanged; authority schemas use a separate registry and digest | Future migrations must keep the profiles explicit |

## Authority contracts

All new records use `authority.ai.ecosystem/v1alpha1` and closed JSON Schemas.

| Kind | Meaning | Explicitly not granted |
|---|---|---|
| `TeamIdentity` | Versioned team declaration and validity claim | Membership, permission, ownership |
| `PrincipalIdentity` | Human/service/agent/CI declaration with controller rule | Authentication, role, runtime access |
| `MembershipBinding` | Exact digest-bound team/principal relationship claim | Role or permission |
| `IdentityKey` | Public Ed25519 key, purpose, lifecycle and exact subject claim | Private key custody or effective trust |
| `TeamPolicyBundle` | Revisioned, signed identity catalog for exact projects | Activation or runtime policy |

Authority record digests use a domain-separated projection that excludes `metadata.recordDigest`. Membership IDs derive deterministically from exact team and principal IDs. Key IDs are `ed25519:` plus the SHA-256 digest of the raw 32-byte public key. IDs are lowercase ASCII and timestamps are UTC seconds ending in `Z`.

The initial policy profile is intentionally fixed:

```text
profile: identity-catalog-only
authorityMode: deny-all
permissionsGranted: false
runtimeAuthorityCreated: false
policyActivated: false
privateKeyPresent: false
```

Embedded teams, principals, memberships and keys are recursively validated, sorted, unique and digest-bound. The bundle must contain the exact active team and an exact active team-owned policy-signing key. A structural predecessor link is required for revisions after revision 1, but it is not described as replay protection.

## Signature envelope

`TeamPolicyVerifier` accepts canonical bytes for `eco-team-policy-envelope-v1`. It verifies a signature over:

```text
"eco-team-policy-signature-v1\0" + canonical_json(envelope_without_signature)
```

The immutable `PolicyTrustAnchor` binds:

- exact team ID;
- exact deterministic key ID and raw public key;
- exact sorted project allowlist;
- external validity interval.

The verified result retains signature provenance relative to that supplied anchor and a deeply immutable policy view. Its fixed safety state is:

```text
signature_verified = true
activation_eligible = false
authority_created = false
currentness = "not-established"
```

There is no production signing API or CLI command. Private-key custody and signing ceremony remain external boundaries.

## Diagnostic CLI

```text
eco identity inspect --record /absolute/identity.json --json
eco policy inspect --record /absolute/policy.json --json
eco policy verify \
  --envelope /absolute/policy-envelope.json \
  --trust-anchor /absolute/external/trust-anchor.json \
  --project exact-project-id \
  --json
```

`inspect` proves only structural/semantic validity. `verify` proves a cryptographic signature relative to the supplied external anchor; it does not establish who provisioned that anchor. Neither command writes files, contacts a network, creates a store, constructs `PolicyEngine`, activates a revision, or emits private/public key bytes or raw payloads in diagnostics.

## Compatibility

M4 runtime schemas remain in `RUNTIME_SCHEMA_BY_KIND`, and the legacy `SCHEMA_BY_KIND` alias still exposes that exact set. Authority records live in `AUTHORITY_SCHEMA_BY_KIND`. Therefore the existing M4 runtime schema digest remains:

```text
d7ab8041c8d42b51ff0cfe7996254fc91c3ec0555df0491328673949db316d9d
```

`.ai/trust.yaml`, the existing HMAC evidence profile, `PolicyEngine`, runtime decisions, stores, brokers and loop authority are unchanged in this slice.

## Next slices

1. **M5.3 RBAC/ABAC:** signed exact actions/resources/constraints that can only narrow the current `PolicyEngine` decision.
2. **M5.4 shared authority:** local same-host multiprocess SQLite activation heads, authority epochs and atomic compare-and-swap.
3. **M5.5 lifecycle:** revocation, key rotation and emergency deny with effect-boundary rechecks.
4. **M5.6 approval:** distinct-principal quorum and separation of duties bound to exact action permits.
5. **M5.7 conformance:** migration, contention/recovery, cross-platform contract behavior, distribution and operational runbooks.

PostgreSQL, a network authority service, SSO/OIDC/WebAuthn, KMS/HSM/Vault, HA consensus, multi-region operation and enterprise A3/A4 profiles remain M6 concerns.
