# M6.6 general agent-team orchestration

## Outcome

M6.6 adds an embedded `eco_teams` scheduling plane for bounded workload-agent
teams. It composes with M5 identity/access authority, M6.3 loop semantics, M6.4
route decisions and M6.5 context artifacts; it does not reinterpret any of them.
A team manifest and a router decision are descriptions, not permission.

The contract namespace is `teams.ai.ecosystem/v1alpha1` and contains four sealed,
content-free record kinds:

- `AgentTeamManifest`: exact project and current M5 authority snapshot/bundle/
  access-policy binding, role envelopes, delegation edges, deadline and aggregate
  budgets;
- `TeamTask`: exact team/project/run/role/action/resource/input, dependency,
  route, time and per-task budget binding;
- `TeamHandoff`: one typed `task-input` edge with exact source, target, roles and
  immutable artifact binding;
- `TeamRunResult`: immutable truthful terminal outcomes and aggregate charged
  usage.

## Authority intersection

`M5AuthorityGuard` verifies the manifest against one current signed M5 authority,
including store/team/project, snapshot, active bundle, access-policy digest,
emergency state, principal and membership. It re-evaluates exact M5 access on
every claim. This result is narrowing-only.

An effect additionally needs an opaque `ExecutionAuthorization` minted by a
trusted runtime authorizer for the exact task and lease. `M5ExecutionAuthorizer`
adapts the existing single-use `TeamAuthorizationGate`; it rechecks currentness at
the effect boundary and executes through that gate. An M6.4 route is consumed
exactly once at effect start but never grants execution by itself.

`model.invoke` now uses an action-specific M5 binding: the runtime decision binds
the exact `ModelRequest`, while team access binds `resource.kind=deployment`, the
request's `deploymentId`, its `deploymentIdentityDigest`, and the input data
class. Repository request/resource equality is not reused for model calls.

## Durable task semantics

The private single-host SQLite coordinator uses serialized claims and bounded
leases. Its path must be absolute, outside the governed repository, non-symlinked
and private on POSIX. A caller-owned HMAC key authenticates the complete mutable
state, metadata and an append-only revision/hash chain, including leases, status,
budgets, cancellations, consumed routes and terminal result bytes. Claiming
atomically reserves the complete per-task token and cost ceiling
against the run aggregate. A lease that expires before effect start releases its
reservation and may be reclaimed. After effect start, expiry or an exception is
`ambiguous`, charges the conservative reservation, and is never automatically
retried.

Children may only use a manifest delegation edge whose target role is already a
subset of the parent role. Each concrete child task must further narrow action,
data class, tool, zone, environment, resource, deadline, duration, tokens and
cost. Cross-team, cross-project and cross-run references fail closed.

Dependencies become claimable only after exact predecessor success and an exact
typed handoff matching the target input artifact. Cancellation immediately stops
pending/leased work, propagates to started work, and requires explicit
acknowledgement. Successful/failed completion is idempotent only for the exact
same outcome and usage; conflicting terminal writes are rejected. Finalization
reports `succeeded`, `failed`, `partial-failure`, `cancelled` or `ambiguous`
directly from every durable task row.

Time authority is broker-owned. The coordinator samples its injected trusted
clock at claim, authorization, effect start and settlement. A caller timestamp is
only a lower-bound anti-rollback assertion: an old value cannot revive an expired
M5 identity, task, lease or route, and a value ahead of the trusted clock is
rejected before accounting changes.

For `model.invoke`, route consumption accepts the full validated M6.4
`ModelRouteRequest` and `ModelRouteDecision`, not a caller-named digest. The exact
record binding, trusted policy/price digests, allowed effect, validity, attempt/
fallback predecessor, selected deployment identity, route cost ceiling and exact
`ModelRequest` input/run/deployment are rechecked inside the same transaction that
consumes the route. The decision digest must also be pinned by the trusted
composition root; a caller cannot mint an allowed route merely by copying trusted
policy or price identifiers.

## Explicit non-claims

This slice is an API-first embedded reference runtime. It does not claim a
distributed scheduler, remote worker authentication transport, consensus,
provider independence, provider pricing authority, automatic recovery of an
ambiguous external effect, arbitrary DAG workflow semantics, or a new source of
permissions. HMAC authentication does not provide encryption, remote identity,
KMS custody or detection of a complete offline rollback without an external
monotonic anchor. Strong private-mode enforcement is POSIX-only; Windows ACL
hardening remains a conformance backend. The SQLite file is external local
coordination state; M5 and the existing runtime/broker boundaries remain
authoritative.

## Verification

Focused tests cover contract narrowing, team/project/run substitution, concurrent
claims, lease expiry on both sides of the effect boundary, aggregate-budget races,
typed handoff substitution, child escalation, stale/revoked/emergency authority,
route-only denial and one-time route consumption, cancellation, truthful partial
failure, terminal replay, caller-clock manipulation, repository non-mutation,
database tampering and action-specific `model.invoke` binding.
