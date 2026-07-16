from __future__ import annotations

"""M5 authority-generation migration for dual-signed trust-anchor rotation."""

from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import RuntimePolicyError, RuntimeStoreError
from .policy_bundle import PolicyTrustAnchor, TeamPolicyVerifier
from .team_authority import (
    GENESIS_DIGEST,
    SQLiteTeamAuthority,
    _path_identity,
    _preflight_successor_authority_path,
    _private_staging_path,
    _publish_no_replace,
    _require_id,
    _successor_location_digest,
    _unlink_owned,
    _validate_authority_constructor_inputs,
)
from .team_rotation import TeamKeyRotationVerifier


def rotate_authority_generation(
    current: SQLiteTeamAuthority,
    *,
    expected_current_snapshot_digest: str,
    raw_rotation: bytes,
    new_anchor: PolicyTrustAnchor,
    raw_successor_policy: bytes,
    successor_database: str | Path,
    successor_hmac_key: bytes,
    successor_audit_key_id: str,
    successor_store_id: str,
    activation_id: str,
    now: datetime,
    forbidden_root: str | Path | None = None,
) -> dict[str, Any]:
    """Create a new linked store generation; never rewrite old signed history."""

    if not isinstance(current, SQLiteTeamAuthority):
        raise TypeError("current must be SQLiteTeamAuthority")
    initial = current.snapshot()
    _validate_authority_constructor_inputs(
        hmac_key=successor_hmac_key,
        key_id=successor_audit_key_id,
        trust_anchor=new_anchor,
        project_id=initial["projectId"],
        store_id=successor_store_id,
        generation_profile="successor",
    )
    _require_id(activation_id)
    target = _preflight_successor_authority_path(
        successor_database,
        forbidden_root=forbidden_root,
        allow_existing=initial["generationStatus"]
        in {"rotation-pending", "retired"},
    )
    successor_location_digest = _successor_location_digest(target)
    try:
        rotation = TeamKeyRotationVerifier(
            current.trust_anchor, new_anchor
        ).verify(
            bytes(raw_rotation),
            expected_project_id=initial["projectId"],
            now=now,
        )
        successor_policy = TeamPolicyVerifier(new_anchor).verify(
            bytes(raw_successor_policy),
            expected_project_id=initial["projectId"],
            now=now,
        )
    except RuntimePolicyError as exc:
        raise RuntimeStoreError(
            exc.code, "Team authority rotation failed closed"
        ) from exc
    if successor_policy.revision != 1 or successor_policy.bundle[
        "spec"
    ]["previous"] is not None:
        raise RuntimeStoreError(
            "ECO_TEAM_ROTATION_SUCCESSOR_POLICY_INVALID",
            "Team authority rotation failed closed",
        )
    reservation = current.reserve_rotation(
        raw_rotation=bytes(raw_rotation),
        new_anchor=new_anchor,
        successor_store_id=successor_store_id,
        successor_location_digest=successor_location_digest,
        successor_policy_digest=successor_policy.bundle_digest,
        expected_snapshot_digest=expected_current_snapshot_digest,
        now=now,
    )
    commitment = reservation["rotationCommitmentDigest"]
    staging: Path | None = None
    staging_identity: tuple[int, int] | None = None
    try:
        if not target.exists():
            staging = _private_staging_path(target)
            with SQLiteTeamAuthority(
                staging,
                hmac_key=successor_hmac_key,
                key_id=successor_audit_key_id,
                trust_anchor=new_anchor,
                project_id=initial["projectId"],
                forbidden_root=forbidden_root,
                store_id=successor_store_id,
                generation_profile="successor",
            ) as successor:
                staging_identity = _path_identity(staging)
                if staging_identity is None:
                    raise RuntimeStoreError(
                        "ECO_TEAM_AUTHORITY_STAGING_UNSAFE",
                        "Team authority rotation failed closed",
                    )
                successor_genesis = successor.snapshot()[
                    "authoritySnapshotDigest"
                ]
                lineage = successor.record_rotated_predecessor(
                    raw_rotation=bytes(raw_rotation),
                    predecessor_anchor=current.trust_anchor,
                    predecessor_store_id=current.store_id,
                    predecessor_snapshot_digest=expected_current_snapshot_digest,
                    rotation_commitment_digest=commitment,
                    successor_location_digest=successor_location_digest,
                    inherited_revocation_epoch=reservation[
                        "revocationEpoch"
                    ],
                    inherited_revocation_head_digest=reservation[
                        "revocationHeadDigest"
                    ],
                    inherited_revocation_set_digest=reservation[
                        "revocationSetDigest"
                    ],
                    inherited_revocations=reservation["revocations"],
                    expected_snapshot_digest=successor_genesis,
                    now=now,
                )
                activated = successor.activate_policy(
                    bytes(raw_successor_policy),
                    activation_id=activation_id,
                    expected_previous=(0, GENESIS_DIGEST),
                    expected_snapshot_digest=lineage[
                        "successorSnapshotDigest"
                    ],
                    now=now,
                )
                if activated["generationStatus"] != "pending-successor":
                    raise RuntimeStoreError(
                        "ECO_TEAM_ROTATION_SUCCESSOR_STATE_INVALID",
                        "Team authority rotation failed closed",
                    )
                successor.verify()
            _publish_no_replace(
                staging,
                target,
                staging_identity,
                conflict_code="ECO_TEAM_ROTATION_SUCCESSOR_PATH_INVALID",
            )
            staging_identity = None

        with SQLiteTeamAuthority(
            target,
            hmac_key=successor_hmac_key,
            key_id=successor_audit_key_id,
            trust_anchor=new_anchor,
            project_id=initial["projectId"],
            forbidden_root=forbidden_root,
            store_id=successor_store_id,
        ) as successor:
            successor_state = successor.snapshot()
            if (
                successor_state["rotationCommitmentDigest"] != commitment
                or successor_state["activePolicy"]["revision"] != 1
                or successor_state["activePolicy"]["digest"]
                != successor_policy.bundle_digest
                or successor_state["generationStatus"]
                not in {"pending-successor", "active"}
            ):
                raise RuntimeStoreError(
                    "ECO_TEAM_ROTATION_SUCCESSOR_STATE_INVALID",
                    "Team authority rotation failed closed",
                )
            finalized = successor.finalize_successor_generation(
                rotation_commitment_digest=commitment,
                expected_snapshot_digest=successor_state[
                    "authoritySnapshotDigest"
                ],
                now=now,
            )
            successor.verify()
        current.finalize_rotation(
            rotation_id=rotation.rotation_id,
            rotation_commitment_digest=commitment,
            successor_store_id=successor_store_id,
            successor_location_digest=successor_location_digest,
            successor_snapshot_digest=finalized["authoritySnapshotDigest"],
            now=now,
        )
        return {
            "predecessorStoreId": current.store_id,
            "predecessorSnapshotDigest": expected_current_snapshot_digest,
            "successorStoreId": successor_store_id,
            "successorSnapshotDigest": finalized[
                "authoritySnapshotDigest"
            ],
            "successorPolicyDigest": successor_policy.bundle_digest,
            "successorPolicyRevision": 1,
            "rotationId": rotation.rotation_id,
            "rotationCommitmentDigest": commitment,
            "successorLocationDigest": successor_location_digest,
            "verified": True,
            "migrationProfile": "new-authority-generation-v1",
            "predecessorHistoryRewritten": False,
        }
    except Exception:
        if staging is not None:
            _unlink_owned(staging, staging_identity)
        raise


__all__ = ["rotate_authority_generation"]
