# D/A/Z/P policy semantics

**Status:** normative for `ai.ecosystem/v1alpha1` and `runtime.ai.ecosystem/v1alpha1`

**Updated:** 2026-07-15

These vocabularies classify different dimensions. They are not interchangeable, and a model cannot assign, lower, or override them at runtime.

## Data classes (D)

Higher values are more restrictive.

| Class | Meaning | Default handling |
|---|---|---|
| D0 | Public, intentionally publishable information | Eligible for explicitly allowed deployments |
| D1 | Internal project code, documentation, or routine metadata | Approved project deployments only |
| D2 | Confidential business, personal, or unreleased material | Private/contractually approved deployments only |
| D3 | Restricted or regulated data requiring a specific control profile | Deny unless a dedicated policy explicitly authorizes the exact deployment |
| D4 | Credentials, private keys, raw secrets, or data forbidden from model context | Never route to a model; use opaque references and broker-owned resolution |

Rules:

- unknown classification becomes the canonical `policy.unknownDataClass` and is never silently lowered;
- aggregate context inherits its highest data class;
- an automated classifier may raise a class or request review, but cannot declassify;
- D4 is intentionally absent from deployment and logical-role allowlists in v1alpha1.

## Action classes (A)

Higher values have greater external consequence.

| Class | Meaning | Examples |
|---|---|---|
| A0 | Model computation without an external side effect | text generation, structured output proposal |
| A1 | Read-only access inside an approved boundary | repository file read |
| A2 | Reversible workspace change or project execution | patch, build, unit test |
| A3 | External write or publication | push, issue update, email, artifact publish |
| A4 | Production, destructive, IAM, financial, or safety-critical change | deployment, permission change, purchase, device actuation |

An operation is allowed only when its catalog action class is at or below both the run ceiling and logical-role ceiling. M2 supports only A0/A1.

## Execution zones (Z)

Zones are explicit trust/topology labels, not a numeric security ranking. A logical role lists every zone it permits.

| Zone | Meaning |
|---|---|
| Z0 | Isolated/offline execution boundary |
| Z1 | Personally controlled local machine or DGX lab |
| Z2 | Organization-controlled shared environment |
| Z3 | Contractually approved external cloud environment |
| Z4 | Unknown or unclassified environment; not routable by v1alpha1 roles |

Transport compatibility does not move a deployment between zones. Region, retention, training use, endpoint binding, and exact identity remain separate required evidence.

## Provenance/artifact trust (P)

Higher values require stronger evidence. A deployment's `artifactTrust` is the maximum default trust its unverified output may claim; task-specific verification may produce a new artifact with stronger provenance.

| Level | Meaning |
|---|---|
| P0 | Untrusted or origin unknown |
| P1 | Origin and deployment identity recorded; result not task-verified |
| P2 | Passed a versioned capability/task evaluation with recorded evidence |
| P3 | Repeated or independent verification with reproducible evidence |
| P4 | Explicitly governed high-assurance evidence, such as signed release or authorized human acceptance |

Trust is never inferred from model reputation, provider name, API compatibility, or local execution alone.

## Eligibility intersection

A route is eligible only if all conditions hold:

```text
deployment enabled
AND deployment is a candidate for the logical role
AND run data class is allowed by the role and deployment
AND deployment zone is explicitly allowed by the role
AND deployment artifact trust meets the role minimum
AND requested action ceiling does not exceed the role ceiling
AND every required capability is declared and freshly observed
AND exact deployment identity matches the observation
```

Any unknown, stale, missing, or contradictory value fails closed. Policy, capability, data, or identity denial never triggers automatic fallback.
