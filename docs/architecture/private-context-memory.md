# M6.5 private context and memory graph

**Status:** implemented as an embedded, content-private library; integrated M6 release evidence remains pending  
**Updated:** 2026-07-17

## Purpose

M6.5 gives a project a durable way to remember facts, claims, decisions,
constraints, open questions, failed approaches and summaries without turning
memory into policy. A remembered statement can help a later role find context. It
cannot grant a role, route, model, tool, capability, budget or permission.

```text
raw/private memory bytes ──> private content-addressed artifact store
                                  │ exact digest/length binding
                                  ▼
sealed MemoryRecord ───────> private authenticated SQLite journal/index
                                  │ exact namespace + TTL + policy + budgets
                                  ▼
bounded deterministic retrieval ──> private bytes + content-free public binding
```

## Record contract

`memory.ai.ecosystem/v1alpha1` is separate from runtime, orchestration and team-
authority contracts. A sealed `MemoryRecord` contains:

- exact project/team/run namespace;
- one of seven memory types;
- data class `D0`–`D3`, privacy level `P0`–`P3`, author and UTC timestamp;
- optional expiry time;
- exact CAS reference, SHA-256 and byte length for the memory body;
- at least one exact source-artifact binding;
- sorted `supersedes`, `refutes` and `conflicts` links;
- for summaries, the complete source-record set, source-artifact union and all
  preserved source relations.

The schema is closed. Authority-shaped additions such as capabilities or tools
are rejected rather than ignored. Links must already exist in the same exact
namespace, so a forged digest or cross-project/team/run edge fails closed.

## Private store and integrity

The memory body never enters SQLite. The database contains canonical sealed
metadata, content-free artifact bindings, an HMAC for every record and an HMAC-
authenticated append chain with an authenticated head. It uses a private local
directory, `BEGIN IMMEDIATE`, full SQLite synchronization and idempotent exact
replay. Reusing an ID for different bytes is a conflict.

Opening or verifying the store rechecks the database profile, metadata HMAC,
every record seal/HMAC, the complete journal chain, referential links and
compaction completeness. Selected content is reopened through the private CAS,
rehashes every byte and checks exact length before release. Missing or modified
CAS objects fail closed with fixed public errors.

The HMAC key and CAS proof key remain caller-owned composition secrets. Neither
key is serialized. This is same-host private durability, not independent audit
anchoring or remote consensus.

## Retrieval rules

Retrieval always requires all of the following:

1. an exact project/team/run namespace;
2. explicit allowed data classes, privacy levels and memory types;
3. a trusted caller-owned read-policy decision;
4. a caller-supplied timezone-aware current time for TTL enforcement;
5. non-negative item, byte and deterministic token-estimate ceilings.

Ordering is deterministic: newest timestamp first, then record digest. No
semantic relevance score is invented. Bytes use the exact artifact length;
tokens use the documented portable ceiling of one token per stored byte.
A `refutes`/`conflicts` connected component is selected atomically. If all
visible sides do not fit, none is returned and the result is marked truncated. A
policy-filtered or expired counterpart also suppresses the visible side,
preventing a partial “uncontested” presentation.

The private result may contain verified content bytes. Its public diagnostic form
contains only record/artifact digests, lengths, classes and explicit relations.

## Reversible compaction

Compaction adds a summary; it never deletes or rewrites source records. The store
derives, rather than trusts, the exact source-artifact union and relation set. A
summary that omits a source conflict/refutation is rejected. `expand_summary`
returns the original sealed records, exact artifact bindings and preserved edges,
and re-verifies every referenced CAS object.

Summary text remains a claim. Compaction does not promote truth, remove expiry,
change data class, lower privacy, or authorize an action. The summary inherits the
most restrictive source data class and privacy level.

## Tests and failure cases

The focused suite covers cross-project/team/run isolation, expiry, data-class and
privacy filters, fail-closed policy, forged and cross-namespace links, conflict-
atomic budgets, exact item/byte/token boundaries, deterministic ordering, public
content minimization, reversible compaction, omitted-relation rejection, missing
CAS content, database tampering, exact concurrent replay and conflicting replay.

## Explicit non-claims

M6.5 does **not** implement or claim:

- vector search, embeddings, semantic ranking or retrieval accuracy;
- a distributed database, HA, replication, consensus or multi-host locking;
- encryption at rest beyond the caller's filesystem/CAS deployment controls;
- independent audit anchoring, KMS/HSM custody or key rotation ceremony;
- automatic truth verification, trust promotion or policy inference;
- autonomous learning, deletion/retention jobs or background compaction;
- a capability, tool, model, route, role, budget or team-authority grant;
- a complete M6.6 workload-agent team runtime.
