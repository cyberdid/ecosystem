# Team authority operations runbook

**Scope:** M5 same-host SQLite authority.

**Updated:** 2026-07-16

## Before activation

- Provision the Ed25519 trust anchor and an empty `SQLiteTeamAuthority` database outside the governed repository; CLI activation refuses a missing database because no exact snapshot CAS can be supplied for an uncreated store.
- Restrict the containing directory to the operator account on POSIX systems.
- Inject a 32-byte HMAC secret as `ECO_TEAM_AUTHORITY_HMAC_HEX`; do not put it in shell history, Git, `.env`, CLI arguments or logs.
- Inspect and verify the signed bundle before activation.
- Record the expected predecessor revision, predecessor digest and exact authority snapshot digest from `eco team doctor --json`.

## Activate and verify

Run `eco team activate ... --expected-snapshot-digest EXACT_DIGEST --apply --json` with exact predecessor values. Then run `eco team doctor ... --json`. Do not retry a failed activation with guessed values; reread the current snapshot and investigate the typed failure.

## Routine checks

- Run doctor after deployment, restore, rotation or incident recovery.
- Monitor activation, revocation, emergency and permit-consumption events.
- Confirm that policy validity windows and external anchors are renewed before expiry.
- Periodically create a coherent backup and verify that it reopens to the expected snapshot.
- Keep approval identities independent from requesters and operators where possible.

## Emergency deny

Enable emergency deny when active authority may be unsafe. While enabled, normal authorization and effect execution stay blocked. It cannot be disabled by the generic state API.

Recovery requires a current signed `emergency-recovery` profile, an exact request bound to the emergency head, authority snapshot, policy digest and revocation epoch, and a short-lived Ed25519 requester assertion for that exact request. Collect the configured quorum from distinct eligible human approvers; the authenticated requester cannot vote. The recovery API verifies evidence and disables the deny in one transaction.

## Key rotation

Prepare a new external anchor and a canonical rotation envelope. Obtain signatures from both old and new private keys. The migration reserves one exact successor target, fences the predecessor, imports the exact revocation set into a pending successor, atomically publishes it, finalizes it active, and retires the predecessor. Retry only the same target and inputs after a crash. Verify lineage and retain the retired predecessor plus rotation evidence. Never overwrite or relabel the old generation.

## Backup and restore

Use the exported `SQLiteTeamAuthority.backup_to(destination, expected_snapshot_digest=..., now=..., forbidden_root=...)` API rather than copying a live SQLite file. It can preserve active, emergency, rotation-pending or retired evidence and returns the exact expected snapshot. Restore only into a private external path and reopen it using the same anchor, store identity, audit key ID and HMAC secret. A mismatch is corruption or the wrong backup. Before making a restored active authority operational, fence or decommission the original; the backup is not safe active-active replication.

## Incident stop conditions

Stop authorization and preserve evidence on any HMAC, signature, canonical digest, snapshot, epoch, lineage, unsafe-path, unsafe-permission, link-topology or SQLite-integrity error. Do not edit the database manually. Prefer an emergency deny, a verified backup, or a dual-signed successor generation.

## Non-claims

This runbook does not provide HA, distributed consensus, remote database safety, cloud secret management, SSO, native Windows ACL enforcement or multi-region disaster recovery. Those require M6 backends and their own conformance evidence.
