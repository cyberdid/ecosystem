# Current architecture

**Updated:** 2026-07-14  
**Status:** compiler foundation implemented

## TL;DR

The repository currently implements canonical contracts, validation, audit, deterministic projections, lock generation, drift checks, backups, and uninstall. It does not yet enforce runtime model/tool permissions.

## Implemented

```text
.ai YAML contracts
→ JSON Schema and cross-file validation
→ eco compiler
→ owned vendor projections
→ CI drift and unit tests
```

## Explicitly not implemented

- provider or tool credential broker;
- data/action PEP;
- network egress control;
- sandbox execution;
- model router;
- capability probes;
- SQLite run events;
- approvals;
- signed audit checkpoints.

The project must not claim these boundaries until negative tests prove them.

## Next vertical slice

Integrate one external repository in `observe` mode, then build a read-only broker with one local DGX adapter and one approved cloud adapter. Both must run the same evaluation task, and a bypass test must fail closed.

The first automation loop remains `wiki-health-check` in L2 observe/report-only mode. Scheduling and autonomous retries are added only after the manual command, deterministic gate, bounded state, and repeated-run evaluation are reliable. See [Loop engineering](loops.md).

## Sources

- [Detailed architecture](../docs/architecture/README.md)
- [Decisions](../docs/decisions/README.md)
- [Loop engineering](loops.md)
- [Roadmap](roadmap.md)
