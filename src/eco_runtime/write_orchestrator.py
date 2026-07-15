from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .approval import ApprovalTrustStore, build_approval_grant
from .artifact_store import ArtifactAvailabilityProof, ContentAddressedArtifactStore
from .change_store import SQLiteChangeAuthority
from .contracts import API_VERSION, validate_record, validate_tool_arguments
from .digests import canonical_json, semantic_digest
from .errors import BrokerError, RuntimeStoreError
from .policy import PolicyEngine
from .store import SQLiteRuntimeStore
from .write_broker import (
    FileState,
    LinuxWorkspaceWriteBroker,
    WorkspaceRollbackResult,
    WorkspaceWriteResult,
)


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Write orchestrator clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RuntimeStoreError("ECO_TIME_INVALID", "Runtime timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimeStoreError("ECO_TIME_INVALID", "Runtime timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ControlledWriteProposal:
    """Validated proposal plus transient execution handles kept out of SQLite."""

    plan: dict[str, Any]
    snapshot: dict[str, Any]
    tool_request: dict[str, Any]
    policy_decision: dict[str, Any]
    proposal: dict[str, Any]
    approval_request: dict[str, Any]
    authority_subject_digest: str
    candidate_artifact: dict[str, Any]
    candidate_proof: ArtifactAvailabilityProof
    path: str


@dataclass(frozen=True)
class ControlledWriteExecution:
    operation_id: str
    state: str
    replayed: bool
    approval_grant: dict[str, Any] | None = None
    intent: dict[str, Any] | None = None
    receipt: dict[str, Any] | None = None
    rollback_receipt: dict[str, Any] | None = None
    broker_result: WorkspaceWriteResult | None = None
    error_code: str | None = None


class ControlledWriteOrchestrator:
    """Compose A2 policy, exact human approval, durable PREPARE and filesystem CAS."""

    def __init__(
        self,
        authority: SQLiteChangeAuthority,
        broker: LinuxWorkspaceWriteBroker,
        artifact_store: ContentAddressedArtifactStore,
        policy: PolicyEngine,
        approval_trust_store: ApprovalTrustStore,
        runtime_store: SQLiteRuntimeStore,
        *,
        path_hmac_key: bytes,
        owner_id: str,
        lease_seconds: int = 30,
    ) -> None:
        if not isinstance(authority, SQLiteChangeAuthority):
            raise TypeError("authority must be SQLiteChangeAuthority")
        if not isinstance(broker, LinuxWorkspaceWriteBroker):
            raise TypeError("broker must be LinuxWorkspaceWriteBroker")
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be ContentAddressedArtifactStore")
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        if not isinstance(approval_trust_store, ApprovalTrustStore):
            raise TypeError("approval_trust_store must be ApprovalTrustStore")
        if not isinstance(runtime_store, SQLiteRuntimeStore):
            raise TypeError("runtime_store must be the active SQLiteRuntimeStore authority")
        if not isinstance(path_hmac_key, bytes) or len(path_hmac_key) < 32:
            raise ValueError("path_hmac_key must contain at least 32 bytes")
        if not isinstance(owner_id, str) or _ID.fullmatch(owner_id) is None:
            raise ValueError("owner_id must be a bounded identifier")
        if not isinstance(lease_seconds, int) or not 1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 1 and 3600")
        self._authority = authority
        self._broker = broker
        self._artifacts = artifact_store
        self._policy = policy
        self._approval_trust_store = approval_trust_store
        self._runtime_store = runtime_store
        self._path_hmac_key = path_hmac_key
        self._owner_id = owner_id
        self._lease_seconds = lease_seconds

    @staticmethod
    def _operation_id(run_id: str, idempotency_key: str) -> str:
        return f"operation-{semantic_digest({'run': run_id, 'key': idempotency_key})}"

    def _require_active_plan(self, plan: Mapping[str, Any]) -> None:
        run_status = self._runtime_store.run_status(plan["metadata"]["runId"])
        if (
            run_status["state"] != "RUNNING"
            or run_status["active_plan_digest"] != semantic_digest(plan)
        ):
            raise RuntimeStoreError(
                "ECO_PLAN_NOT_ACTIVE", "Controlled write requires the exact active running plan"
            )

    def _persist_recovery_bundle(
        self, bundle: Mapping[str, Any]
    ) -> ArtifactAvailabilityProof:
        encoded = canonical_json(dict(bundle)).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        return self._artifacts.put(
            [encoded],
            expected_sha256=digest,
            expected_byte_length=len(encoded),
            max_bytes=1_048_576,
        )

    def _load_recovery_bundle(self, status: Mapping[str, Any]) -> dict[str, Any]:
        try:
            proof = self._artifacts.proof_for_record(
                storage_ref=status["recovery_storage_ref"],
                sha256=status["recovery_sha256"],
                byte_length=status["recovery_byte_length"],
            )
            with self._artifacts.open_verified(proof) as source:
                encoded = source.read(1_048_577)
            if len(encoded) > 1_048_576:
                raise ValueError("recovery bundle is too large")
            bundle = json.loads(encoded.decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Durable recovery bundle is invalid"
            ) from exc
        if (
            not isinstance(bundle, dict)
            or canonical_json(bundle).encode("utf-8") != encoded
            or semantic_digest(bundle) != status["recovery_metadata_digest"]
        ):
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Durable recovery bundle binding differs"
            )
        return bundle

    def path_reference_digest(self, path: str) -> str:
        payload = {"domain": "eco-workspace-path-reference-v1", "path": path}
        return hmac.new(
            self._path_hmac_key,
            canonical_json(payload).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _artifact_descriptor(record: Mapping[str, Any], proof: ArtifactAvailabilityProof) -> dict[str, Any]:
        spec = record["spec"]
        return {
            "artifactRecordDigest": semantic_digest(record),
            "contentDigest": spec["sha256"],
            "byteLength": spec["byteLength"],
            "dataClass": spec["dataClass"],
            "trust": spec["trust"],
            "availabilityProofDigest": semantic_digest(proof.as_dict()),
            "fileType": "regular",
            "encoding": "UTF-8",
            "mode": spec.get("mode", 0o644),
        }

    @staticmethod
    def _file_state(value: Mapping[str, Any]) -> FileState:
        if value["state"] == "absent":
            return FileState.absent()
        return FileState.present(value["contentDigest"], value["byteLength"], value["mode"])

    @staticmethod
    def _expected_record(value: FileState) -> dict[str, Any]:
        if value.state == "absent":
            return {"state": "absent"}
        return {
            "state": "present",
            "fileType": "regular",
            "encoding": "UTF-8",
            "contentDigest": value.sha256,
            "byteLength": value.byte_length,
            "mode": value.mode,
        }

    def create_proposal(
        self,
        plan: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        tool_request: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
        candidate_artifact: Mapping[str, Any],
        candidate_proof: ArtifactAvailabilityProof,
        *,
        display_digest: str,
        now: datetime,
        approval_ttl_seconds: int = 300,
    ) -> ControlledWriteProposal:
        """Validate and register one exact proposal without mutating the workspace."""

        _utc(now)
        if not isinstance(approval_ttl_seconds, int) or not 1 <= approval_ttl_seconds <= 3600:
            raise ValueError("approval_ttl_seconds must be between 1 and 3600")
        plan = copy.deepcopy(validate_record(dict(plan)))
        snapshot = copy.deepcopy(validate_record(dict(snapshot)))
        request = copy.deepcopy(validate_record(dict(tool_request)))
        decision = copy.deepcopy(validate_record(dict(policy_decision)))
        artifact = copy.deepcopy(validate_record(dict(candidate_artifact)))
        if (
            plan["kind"] != "RunPlan"
            or snapshot["kind"] != "RepositorySnapshot"
            or request["kind"] != "ToolRequest"
            or request["spec"]["toolId"] != "repository.write"
            or decision["kind"] != "PolicyDecision"
            or artifact["kind"] != "ArtifactRecord"
        ):
            raise RuntimeStoreError("ECO_WRITE_INPUT_INVALID", "Controlled write input kind is invalid")
        if {tool["id"] for tool in plan["spec"]["tools"]} != {"repository.write"}:
            raise RuntimeStoreError(
                "ECO_WRITE_PLAN_SCOPE",
                "The bounded M3 profile requires a dedicated write-only plan",
            )
        arguments = validate_tool_arguments("repository.write", request["spec"]["arguments"])
        planned_snapshot = plan["spec"].get("repositorySnapshot")
        expected_snapshot = {
            "id": snapshot["metadata"]["id"],
            "digest": semantic_digest(snapshot),
            "rootIdentityDigest": snapshot["spec"]["rootIdentityDigest"],
        }
        if (
            not isinstance(planned_snapshot, dict)
            or any(planned_snapshot.get(key) != value for key, value in expected_snapshot.items())
            or self._broker.root_identity_digest != snapshot["spec"]["rootIdentityDigest"]
        ):
            raise RuntimeStoreError(
                "ECO_ROOT_IDENTITY_MISMATCH",
                "Plan, snapshot and write broker are not bound to the same workspace root",
            )
        run_status = self._runtime_store.run_status(plan["metadata"]["runId"])
        if (
            run_status["state"] != "RUNNING"
            or run_status["active_plan_digest"] != semantic_digest(plan)
        ):
            raise RuntimeStoreError(
                "ECO_PLAN_NOT_ACTIVE", "Controlled write requires the exact active running plan"
            )
        trusted = self._policy.authorize_tool(
            plan,
            request,
            decision_id=decision["metadata"]["id"],
            now=now,
            require_in_memory_activation=False,
        )
        if semantic_digest(trusted) != semantic_digest(decision) or decision["spec"]["effect"] != "allow":
            raise RuntimeStoreError("ECO_DECISION_UNTRUSTED", "Write decision is not an exact policy allow")
        self._artifacts.verify_availability(candidate_proof)
        descriptor = self._artifact_descriptor(artifact, candidate_proof)
        if descriptor != arguments["candidateArtifact"]:
            raise RuntimeStoreError("ECO_CANDIDATE_MISMATCH", "Candidate artifact binding differs")
        if artifact["metadata"]["runId"] != plan["metadata"]["runId"]:
            raise RuntimeStoreError("ECO_RUN_MISMATCH", "Candidate belongs to another run")
        if artifact["spec"]["storageRef"] != candidate_proof.storage_ref:
            raise RuntimeStoreError("ECO_CANDIDATE_MISMATCH", "Candidate storage binding differs")

        path = arguments["path"]
        path_digest = self.path_reference_digest(path)
        expires_at = min(
            now.astimezone(timezone.utc) + timedelta(seconds=approval_ttl_seconds),
            _parse(decision["spec"]["constraints"]["expiresAt"]),
        )
        expires_at_text = _utc(expires_at)
        proposal_id = f"proposal-{semantic_digest({'run': plan['metadata']['runId'], 'request': semantic_digest(request)})}"
        proposal = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "WorkspaceChangeProposal",
                "metadata": {
                    "id": proposal_id,
                    "runId": plan["metadata"]["runId"],
                    "createdAt": _utc(now),
                },
                "spec": {
                    "planDigest": semantic_digest(plan),
                    "toolRequest": {"id": request["metadata"]["id"], "digest": semantic_digest(request)},
                    "policyAllowDecision": {
                        "id": decision["metadata"]["id"],
                        "digest": semantic_digest(decision),
                    },
                    "operation": arguments["operation"],
                    "pathDigest": path_digest,
                    "expectedBefore": copy.deepcopy(arguments["expectedBefore"]),
                    "candidateArtifact": descriptor,
                    "displayDigest": display_digest,
                    "approvalExpiresAt": expires_at_text,
                    "rollbackProfile": "single-file-cas-restore-v1",
                },
            }
        )
        authority_binding = self._authority.register_proposal(
            {
                "proposalId": proposal_id,
                "projectId": plan["spec"]["project"]["id"],
                "runId": plan["metadata"]["runId"],
                "planDigest": semantic_digest(plan),
                "policyDecisionDigest": semantic_digest(decision),
                "actionClass": "A2",
                "operationKind": arguments["operation"],
                "rootIdentityDigest": snapshot["spec"]["rootIdentityDigest"],
                "baseDigest": semantic_digest(snapshot),
                "targetRefDigest": path_digest,
                "desiredDigest": semantic_digest(descriptor),
                "rollbackDigest": semantic_digest(arguments["expectedBefore"]),
                "displayDigest": display_digest,
                "limits": {
                    "maxBytes": descriptor["byteLength"],
                    "maxFiles": 1,
                    "maxOperations": plan["spec"]["budget"]["maxToolRequests"],
                    "approvalExpiresAt": expires_at_text,
                },
            },
            now=now,
        )
        proposal_digest = semantic_digest(proposal)
        approval_request = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ApprovalRequest",
                "metadata": {
                    "id": f"approval-request-{proposal_digest}",
                    "runId": plan["metadata"]["runId"],
                    "createdAt": _utc(now),
                },
                "spec": {
                    "proposal": {"id": proposal_id, "digest": proposal_digest},
                    "toolRequest": {"id": request["metadata"]["id"], "digest": semantic_digest(request)},
                    "subject": {"kind": "WorkspaceChangeProposal", "id": proposal_id, "digest": proposal_digest},
                    "authoritySubjectDigest": authority_binding["subjectDigest"],
                    "displayDigest": display_digest,
                    "requestedActionClass": "A2",
                    "humanRequired": True,
                    "expiresAt": expires_at_text,
                },
            }
        )
        return ControlledWriteProposal(
            plan=plan,
            snapshot=snapshot,
            tool_request=request,
            policy_decision=decision,
            proposal=proposal,
            approval_request=approval_request,
            authority_subject_digest=authority_binding["subjectDigest"],
            candidate_artifact=artifact,
            candidate_proof=candidate_proof,
            path=path,
        )

    def _backup_artifact(
        self,
        proposal: ControlledWriteProposal,
        proof: ArtifactAvailabilityProof,
        *,
        operation_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        candidate = proposal.candidate_artifact["spec"]
        return validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ArtifactRecord",
                "metadata": {
                    "id": f"backup-{operation_id}",
                    "runId": proposal.plan["metadata"]["runId"],
                    "createdAt": _utc(now),
                },
                "spec": {
                    "role": "evidence",
                    "mediaType": "text/plain",
                    "byteLength": proof.byte_length,
                    "sha256": proof.sha256,
                    "dataClass": candidate["dataClass"],
                    "trust": "P1",
                    "producer": {"type": "runtime", "id": self._owner_id},
                    "parentRefs": [],
                    "storageRef": proof.storage_ref,
                    "retention": "run",
                },
            }
        )

    def execute(
        self,
        proposal: ControlledWriteProposal,
        approval_envelope: Mapping[str, Any],
        *,
        idempotency_key: str,
        now: datetime,
        post_apply_validator: Callable[[dict[str, Any]], bool] | None = None,
    ) -> ControlledWriteExecution:
        """Apply and commit, or CAS-rollback when the post-apply gate rejects."""

        if not isinstance(proposal, ControlledWriteProposal):
            raise TypeError("proposal must be ControlledWriteProposal")
        if not isinstance(idempotency_key, str) or _ID.fullmatch(idempotency_key) is None:
            raise ValueError("idempotency_key must be a bounded identifier")
        if post_apply_validator is not None and not callable(post_apply_validator):
            raise TypeError("post_apply_validator must be callable")
        _utc(now)
        operation_id = self._operation_id(proposal.plan["metadata"]["runId"], idempotency_key)
        for record in (
            proposal.plan,
            proposal.snapshot,
            proposal.tool_request,
            proposal.policy_decision,
            proposal.proposal,
            proposal.approval_request,
            proposal.candidate_artifact,
        ):
            validate_record(record)
        arguments = validate_tool_arguments(
            "repository.write", proposal.tool_request["spec"]["arguments"]
        )
        proposal_digest = semantic_digest(proposal.proposal)
        request_digest = semantic_digest(proposal.tool_request)
        decision_digest = semantic_digest(proposal.policy_decision)
        approval_spec = proposal.approval_request["spec"]
        proposal_spec = proposal.proposal["spec"]
        planned_snapshot = proposal.plan["spec"].get("repositorySnapshot")
        expected_snapshot = {
            "id": proposal.snapshot["metadata"]["id"],
            "digest": semantic_digest(proposal.snapshot),
            "rootIdentityDigest": proposal.snapshot["spec"]["rootIdentityDigest"],
        }
        if (
            proposal.path != arguments["path"]
            or proposal.tool_request["spec"]["planDigest"] != semantic_digest(proposal.plan)
            or proposal_spec["planDigest"] != semantic_digest(proposal.plan)
            or proposal_spec["pathDigest"] != self.path_reference_digest(proposal.path)
            or proposal_spec["toolRequest"]
            != {"id": proposal.tool_request["metadata"]["id"], "digest": request_digest}
            or proposal_spec["policyAllowDecision"]
            != {"id": proposal.policy_decision["metadata"]["id"], "digest": decision_digest}
            or proposal_spec["candidateArtifact"] != arguments["candidateArtifact"]
            or approval_spec["proposal"]
            != {"id": proposal.proposal["metadata"]["id"], "digest": proposal_digest}
            or approval_spec["toolRequest"]
            != {"id": proposal.tool_request["metadata"]["id"], "digest": request_digest}
            or approval_spec["authoritySubjectDigest"] != proposal.authority_subject_digest
            or approval_spec["displayDigest"] != proposal_spec["displayDigest"]
            or approval_spec["expiresAt"] != proposal_spec["approvalExpiresAt"]
            or not isinstance(planned_snapshot, dict)
            or any(planned_snapshot.get(key) != value for key, value in expected_snapshot.items())
            or self._broker.root_identity_digest
            != proposal.snapshot["spec"]["rootIdentityDigest"]
        ):
            raise RuntimeStoreError("ECO_CHANGE_AUTHORITY_MISMATCH", "Proposal bundle binding differs")
        if self._artifact_descriptor(
            proposal.candidate_artifact, proposal.candidate_proof
        ) != arguments["candidateArtifact"]:
            raise RuntimeStoreError("ECO_CANDIDATE_MISMATCH", "Candidate artifact binding differs")
        limits = {
            "maxBytes": arguments["candidateArtifact"]["byteLength"],
            "maxFiles": 1,
            "maxOperations": proposal.plan["spec"]["budget"]["maxToolRequests"],
            "approvalExpiresAt": proposal_spec["approvalExpiresAt"],
        }
        expected_authority = {
            "proposalId": proposal.proposal["metadata"]["id"],
            "projectId": proposal.plan["spec"]["project"]["id"],
            "runId": proposal.plan["metadata"]["runId"],
            "planDigest": semantic_digest(proposal.plan),
            "policyDecisionDigest": decision_digest,
            "actionClass": "A2",
            "operationKind": arguments["operation"],
            "rootIdentityDigest": proposal.snapshot["spec"]["rootIdentityDigest"],
            "baseDigest": semantic_digest(proposal.snapshot),
            "targetRefDigest": proposal_spec["pathDigest"],
            "desiredDigest": semantic_digest(arguments["candidateArtifact"]),
            "rollbackDigest": semantic_digest(arguments["expectedBefore"]),
            "displayDigest": proposal_spec["displayDigest"],
            "limits": limits,
        }
        stored_authority = self._authority.proposal_status(
            proposal.proposal["metadata"]["id"]
        )
        if (
            any(stored_authority.get(key) != value for key, value in expected_authority.items())
            or stored_authority.get("subjectDigest") != proposal.authority_subject_digest
        ):
            raise RuntimeStoreError(
                "ECO_CHANGE_AUTHORITY_MISMATCH",
                "Live write bundle differs from the exact approved authority proposal",
            )

        # Exact retries are historical evidence checks, not new authorizations.
        # This lookup deliberately precedes current expiry checks so a committed,
        # rolled-back, failed, or recovery-required operation remains observable
        # after its one-shot decision and approval windows have closed.
        try:
            existing = self._authority.operation_status(operation_id)
        except RuntimeStoreError as exc:
            if exc.code != "ECO_CHANGE_OPERATION_UNKNOWN":
                raise
            existing = None
        if existing is not None:
            idem_digest = semantic_digest(
                {"domain": "eco-change-idempotency-v1", "key": idempotency_key}
            )
            historical = self._approval_trust_store.verify_historical(
                approval_envelope,
                expected_subject_digest=proposal.authority_subject_digest,
            )
            stored_approval = self._authority.approval_status(existing["approval_id"])
            if (
                existing["proposal_id"] != proposal.proposal["metadata"]["id"]
                or existing["approval_id"] != historical.envelope["approvalId"]
                or existing["idempotency_key_digest"] != idem_digest
                or existing["policy_decision_digest"] != decision_digest
                or stored_approval["envelope_digest"] != historical.envelope_digest
                or stored_approval["consumed_operation_id"] != operation_id
            ):
                raise RuntimeStoreError(
                    "ECO_CHANGE_IDEMPOTENCY_CONFLICT",
                    "Operation id is already bound to another exact authority",
                )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state=existing["state"],
                replayed=True,
            )

        self._artifacts.verify_availability(proposal.candidate_proof)
        if _parse(proposal.policy_decision["spec"]["constraints"]["expiresAt"]) <= now.astimezone(
            timezone.utc
        ):
            raise RuntimeStoreError("ECO_DECISION_EXPIRED", "Write policy decision has expired")
        verified = self._approval_trust_store.verify(
            approval_envelope,
            expected_subject_digest=proposal.authority_subject_digest,
            now=now,
        )
        if (
            _parse(verified.envelope["issuedAt"])
            < _parse(proposal.approval_request["metadata"]["createdAt"])
            or _parse(verified.envelope["expiresAt"])
            > _parse(proposal.approval_request["spec"]["expiresAt"])
        ):
            raise RuntimeStoreError(
                "ECO_APPROVAL_SCOPE",
                "Approval validity is outside the exact request window",
            )
        approval_grant = validate_record(
            build_approval_grant(
                verified,
                run_id=proposal.plan["metadata"]["runId"],
                approval_request_id=proposal.approval_request["metadata"]["id"],
                approval_request_digest=semantic_digest(proposal.approval_request),
                proposal_id=proposal.proposal["metadata"]["id"],
                proposal_digest=semantic_digest(proposal.proposal),
                display_digest=proposal.proposal["spec"]["displayDigest"],
            )
        )
        self._authority.record_verified_grant(approval_envelope, now=now)
        temporary_name = self._broker.issue_temporary_name()
        recovery_bundle: dict[str, Any] = {
            "domain": "eco-workspace-recovery-bundle-v1",
            "version": 1,
            "operationId": operation_id,
            "runId": proposal.plan["metadata"]["runId"],
            "proposalId": proposal.proposal["metadata"]["id"],
            "proposalDigest": semantic_digest(proposal.proposal),
            "approvalId": approval_grant["metadata"]["id"],
            "policyDecisionDigest": decision_digest,
            "rootIdentityDigest": proposal.snapshot["spec"]["rootIdentityDigest"],
            "path": proposal.path,
            "pathDigest": proposal.proposal["spec"]["pathDigest"],
            "operation": arguments["operation"],
            "expectedBefore": copy.deepcopy(arguments["expectedBefore"]),
            "candidate": {
                "storageRef": proposal.candidate_proof.storage_ref,
                "sha256": proposal.candidate_proof.sha256,
                "byteLength": proposal.candidate_proof.byte_length,
                "mode": arguments["candidateArtifact"]["mode"],
            },
            "temporaryName": temporary_name,
            "backup": None,
            "intentDigest": None,
            "phase": "prepared",
        }
        recovery_proof = self._persist_recovery_bundle(recovery_bundle)
        recovery_digest = semantic_digest(recovery_bundle)
        prepared = self._authority.prepare_operation(
            operation_id=operation_id,
            proposal_id=proposal.proposal["metadata"]["id"],
            approval_id=approval_grant["metadata"]["id"],
            idempotency_key=idempotency_key,
            recovery_metadata_digest=recovery_digest,
            recovery_storage_ref=recovery_proof.storage_ref,
            recovery_sha256=recovery_proof.sha256,
            recovery_byte_length=recovery_proof.byte_length,
            owner_id=self._owner_id,
            now=now,
            lease_seconds=self._lease_seconds,
        )
        if prepared.get("replayed"):
            status = self._authority.operation_status(operation_id)
            return ControlledWriteExecution(
                operation_id=operation_id,
                state=status["state"],
                replayed=True,
                approval_grant=approval_grant,
            )
        lease_started = time.monotonic()

        def current_lease() -> dict[str, Any]:
            # Advance the caller's trusted wall time by local monotonic elapsed
            # time so slow validators cannot keep using the PREPARE timestamp.
            transition_now = now + timedelta(seconds=max(0.0, time.monotonic() - lease_started))
            return {
                "owner_id": self._owner_id,
                "lease_token": prepared["leaseToken"],
                "lease_epoch": prepared["leaseEpoch"],
                "now": transition_now,
            }
        expected = self._file_state(arguments["expectedBefore"])
        intent: dict[str, Any] | None = None
        receipt: dict[str, Any] | None = None

        def rollback_ready(before: FileState, proof: ArtifactAvailabilityProof | None) -> None:
            nonlocal intent, recovery_bundle
            self._require_active_plan(proposal.plan)
            rollback: dict[str, Any] = {
                "profile": "single-file-cas-restore-v1",
                "expectedAppliedDigest": proposal.candidate_proof.sha256,
            }
            before_proof: dict[str, Any] = {"state": before.state}
            if proof is not None:
                backup = self._backup_artifact(proposal, proof, operation_id=operation_id, now=now)
                rollback["backupArtifact"] = self._artifact_descriptor(backup, proof)
                before_proof["availabilityProofDigest"] = semantic_digest(proof.as_dict())
                before_proof["artifactRecordDigest"] = semantic_digest(backup)
            intent = validate_record(
                {
                    "apiVersion": API_VERSION,
                    "kind": "WorkspaceWriteIntent",
                    "metadata": {
                        "id": operation_id,
                        "runId": proposal.plan["metadata"]["runId"],
                        "createdAt": _utc(now),
                    },
                    "spec": {
                        "idempotencyKeyDigest": semantic_digest(
                            {"domain": "eco-change-idempotency-v1", "key": idempotency_key}
                        ),
                        "planDigest": semantic_digest(proposal.plan),
                        "toolRequest": {
                            "id": proposal.tool_request["metadata"]["id"],
                            "digest": semantic_digest(proposal.tool_request),
                        },
                        "policyAllowDecision": {
                            "id": proposal.policy_decision["metadata"]["id"],
                            "digest": semantic_digest(proposal.policy_decision),
                        },
                        "approvalGrant": {
                            "id": approval_grant["metadata"]["id"],
                            "digest": semantic_digest(approval_grant),
                        },
                        "proposal": {
                            "id": proposal.proposal["metadata"]["id"],
                            "digest": semantic_digest(proposal.proposal),
                        },
                        "toolCatalogDigest": next(
                            tool["catalogDigest"]
                            for tool in proposal.plan["spec"]["tools"]
                            if tool["id"] == "repository.write"
                        ),
                        "operation": arguments["operation"],
                        "pathDigest": proposal.proposal["spec"]["pathDigest"],
                        "expectedBefore": copy.deepcopy(arguments["expectedBefore"]),
                        "candidateArtifact": copy.deepcopy(arguments["candidateArtifact"]),
                        "rollback": rollback,
                    },
                }
            )
            recovery_bundle = {
                **recovery_bundle,
                "backup": (
                    None
                    if proof is None
                    else {
                        "storageRef": proof.storage_ref,
                        "sha256": proof.sha256,
                        "byteLength": proof.byte_length,
                    }
                ),
                "intentDigest": semantic_digest(intent),
                "phase": "rollback-ready",
            }
            durable_recovery = self._persist_recovery_bundle(recovery_bundle)
            self._authority.mark_rollback_ready(
                operation_id,
                before_proof_digest=semantic_digest(before_proof),
                execution_intent_digest=semantic_digest(intent),
                recovery_metadata_digest=semantic_digest(recovery_bundle),
                recovery_storage_ref=durable_recovery.storage_ref,
                recovery_sha256=durable_recovery.sha256,
                recovery_byte_length=durable_recovery.byte_length,
                **current_lease(),
            )
            self._require_active_plan(proposal.plan)
            self._authority.mark_applying(operation_id, **current_lease())

        def commit_authority() -> None:
            with self._runtime_store.active_plan_guard(
                proposal.plan["metadata"]["runId"], semantic_digest(proposal.plan)
            ):
                self._authority.mark_commit_ready(operation_id, **current_lease())

        try:
            broker_result = self._broker.apply(
                proposal.path,
                operation=arguments["operation"],
                expected_before=expected,
                candidate_proof=proposal.candidate_proof,
                candidate_mode=arguments["candidateArtifact"]["mode"],
                temporary_name=temporary_name,
                rollback_ready_hook=rollback_ready,
                commit_authority_hook=commit_authority,
            )
            if intent is None:
                raise RuntimeStoreError("ECO_CHANGE_ROLLBACK_UNREADY", "Execution intent was not durable")
            applied = {
                "fileType": "regular",
                "encoding": "UTF-8",
                "contentDigest": broker_result.after.sha256,
                "byteLength": broker_result.after.byte_length,
                "mode": broker_result.after.mode,
                "filesystemProfile": "linux-openat2-v1",
                "atomicReplace": True,
                "directoryFsync": True,
            }
            receipt = validate_record(
                {
                    "apiVersion": API_VERSION,
                    "kind": "WorkspaceWriteReceipt",
                    "metadata": {
                        "id": f"receipt-{operation_id}",
                        "runId": proposal.plan["metadata"]["runId"],
                        "operationId": operation_id,
                        "createdAt": _utc(now),
                    },
                    "spec": {
                        "intentDigest": semantic_digest(intent),
                        "proposalDigest": semantic_digest(proposal.proposal),
                        "toolRequestDigest": semantic_digest(proposal.tool_request),
                        "policyDecisionDigest": semantic_digest(proposal.policy_decision),
                        "approvalGrantDigest": semantic_digest(approval_grant),
                        "idempotencyKeyDigest": intent["spec"]["idempotencyKeyDigest"],
                        "operation": arguments["operation"],
                        "pathDigest": proposal.proposal["spec"]["pathDigest"],
                        "expectedBefore": copy.deepcopy(arguments["expectedBefore"]),
                        "applied": applied,
                        "postconditionDigest": semantic_digest(applied),
                    },
                }
            )
            self._authority.mark_applied(
                operation_id, receipt_digest=semantic_digest(receipt), **current_lease()
            )
            accepted = True
            if post_apply_validator is not None:
                try:
                    accepted = post_apply_validator(copy.deepcopy(receipt)) is True
                except Exception:
                    accepted = False
            if accepted:
                self._authority.mark_committed(operation_id, **current_lease())
                return ControlledWriteExecution(
                    operation_id=operation_id,
                    state="committed",
                    replayed=False,
                    approval_grant=approval_grant,
                    intent=intent,
                    receipt=receipt,
                    broker_result=broker_result,
                )

            self._authority.mark_rolling_back(operation_id, **current_lease())
            rollback_result = self._broker.rollback(
                broker_result,
                temporary_name=temporary_name,
                commit_authority_hook=lambda: self._authority.assert_operation_lease(
                    operation_id,
                    required_state="rolling_back",
                    **current_lease(),
                ),
            )
            rollback_receipt = self._rollback_receipt(
                proposal,
                operation_id=operation_id,
                intent=intent,
                receipt=receipt,
                result=rollback_result,
                now=now,
                status="rolled-back",
            )
            self._authority.mark_rolled_back(
                operation_id, receipt_digest=semantic_digest(rollback_receipt), **current_lease()
            )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state="rolled_back",
                replayed=False,
                approval_grant=approval_grant,
                intent=intent,
                receipt=receipt,
                rollback_receipt=rollback_receipt,
                broker_result=broker_result,
                error_code="ECO_POST_APPLY_VALIDATION_FAILED",
            )
        except BrokerError as exc:
            state = self._authority.operation_status(operation_id)["state"]
            observed: FileState | None = None
            try:
                observed = self._broker.observe(proposal.path)
            except BrokerError:
                pass
            failure_digest = semantic_digest({"domain": "eco-write-failure-v1", "code": exc.code})
            if state in {"prepared", "rollback_ready", "applying", "commit_ready"} and observed == expected:
                self._authority.mark_failed(
                    operation_id, failure_digest=failure_digest, **current_lease()
                )
                terminal = "failed"
            else:
                self._authority.mark_recovery_required(
                    operation_id, reason_digest=failure_digest, **current_lease()
                )
                terminal = "recovery_required"
            return ControlledWriteExecution(
                operation_id=operation_id,
                state=terminal,
                replayed=False,
                approval_grant=approval_grant,
                intent=intent,
                receipt=receipt,
                error_code=exc.code,
            )

    def recover(self, operation_id: str, *, now: datetime) -> ControlledWriteExecution:
        """Conservatively reconcile and compensate one expired in-flight write.

        Recovery never converts filesystem ambiguity into success.  If the
        exact approved after-state is present it performs the pre-authorized
        CAS rollback; if the exact before-state is present it records failure;
        any third state remains recovery-required for operator inspection.
        """

        if not isinstance(operation_id, str) or _ID.fullmatch(operation_id) is None:
            raise ValueError("operation_id must be a bounded identifier")
        _utc(now)
        status = self._authority.operation_status(operation_id)
        if status["state"] in {"committed", "rolled_back", "failed"}:
            return ControlledWriteExecution(
                operation_id=operation_id, state=status["state"], replayed=True
            )
        stored_proposal = self._authority.proposal_status(status["proposal_id"])
        if stored_proposal.get("rootIdentityDigest") != self._broker.root_identity_digest:
            raise RuntimeStoreError(
                "ECO_ROOT_IDENTITY_MISMATCH",
                "Recovery broker is not pinned to the approved workspace root",
            )

        claimed = self._authority.claim_operation(
            operation_id,
            owner_id=self._owner_id,
            now=now,
            lease_seconds=self._lease_seconds,
        )
        if claimed.get("state") != "recovery_required" or "leaseToken" not in claimed:
            return ControlledWriteExecution(
                operation_id=operation_id,
                state=claimed["state"],
                replayed=True,
            )
        status = self._authority.operation_status(operation_id)
        bundle = self._load_recovery_bundle(status)
        required = {
            "domain", "version", "operationId", "runId", "proposalId", "proposalDigest",
            "approvalId", "policyDecisionDigest", "rootIdentityDigest", "path", "pathDigest", "operation",
            "expectedBefore", "candidate", "temporaryName", "backup", "intentDigest", "phase",
        }
        candidate = bundle.get("candidate")
        if (
            set(bundle) != required
            or bundle.get("domain") != "eco-workspace-recovery-bundle-v1"
            or bundle.get("version") != 1
            or bundle.get("operationId") != operation_id
            or bundle.get("runId") != status["run_id"]
            or bundle.get("proposalId") != status["proposal_id"]
            or bundle.get("approvalId") != status["approval_id"]
            or bundle.get("policyDecisionDigest") != status["policy_decision_digest"]
            or bundle.get("rootIdentityDigest") != stored_proposal.get("rootIdentityDigest")
            or bundle.get("rootIdentityDigest") != self._broker.root_identity_digest
            or bundle.get("pathDigest") != status["target_ref_digest"]
            or self.path_reference_digest(bundle.get("path")) != bundle.get("pathDigest")
            or bundle.get("operation") not in {"create", "replace"}
            or not isinstance(bundle.get("temporaryName"), str)
            or not isinstance(candidate, dict)
            or set(candidate) != {"storageRef", "sha256", "byteLength", "mode"}
        ):
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Recovery bundle authority differs"
            )

        try:
            before = self._file_state(bundle["expectedBefore"])
            candidate_proof = self._artifacts.proof_for_record(
                storage_ref=candidate["storageRef"],
                sha256=candidate["sha256"],
                byte_length=candidate["byteLength"],
            )
            after = FileState.present(
                candidate_proof.sha256, candidate_proof.byte_length, candidate["mode"]
            )
            backup_value = bundle["backup"]
            rollback_proof = (
                None
                if backup_value is None
                else self._artifacts.proof_for_record(
                    storage_ref=backup_value["storageRef"],
                    sha256=backup_value["sha256"],
                    byte_length=backup_value["byteLength"],
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Recovery artifact descriptor is invalid"
            ) from exc
        if (
            (bundle["operation"] == "create" and (before.state != "absent" or rollback_proof is not None))
            or (
                bundle["operation"] == "replace"
                and (
                    before.state != "present"
                    or rollback_proof is None
                    or rollback_proof.sha256 != before.sha256
                    or rollback_proof.byte_length != before.byte_length
                )
            )
        ):
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Recovery before-state proof differs"
            )

        lease_started = time.monotonic()

        def current_lease() -> dict[str, Any]:
            return {
                "owner_id": self._owner_id,
                "lease_token": claimed["leaseToken"],
                "lease_epoch": claimed["leaseEpoch"],
                "now": now + timedelta(seconds=max(0.0, time.monotonic() - lease_started)),
            }

        self._broker.cleanup_temporary(bundle["path"], bundle["temporaryName"])
        observed = self._broker.observe(bundle["path"])
        if observed == before:
            if claimed.get("recoveryPhase") == "rollback":
                self._authority.mark_rolling_back(operation_id, **current_lease())
                recovered_receipt = semantic_digest(
                    {
                        "domain": "eco-workspace-recovery-receipt-v1",
                        "operationId": operation_id,
                        "intentDigest": bundle["intentDigest"],
                        "restoredState": self._expected_record(before),
                        "changed": True,
                        "reconciledAfterProcessLoss": True,
                    }
                )
                self._authority.mark_rolled_back(
                    operation_id,
                    receipt_digest=recovered_receipt,
                    **current_lease(),
                )
                return ControlledWriteExecution(
                    operation_id=operation_id,
                    state="rolled_back",
                    replayed=False,
                    error_code="ECO_CRASH_RECOVERY_ROLLBACK",
                )
            failure = semantic_digest(
                {"domain": "eco-write-recovery-v1", "result": "before-state-observed"}
            )
            self._authority.mark_failed(
                operation_id, failure_digest=failure, **current_lease()
            )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state="failed",
                replayed=False,
                error_code="ECO_WRITE_NOT_COMMITTED",
            )
        if observed != after:
            conflict_reason = semantic_digest(
                {
                    "domain": "eco-write-recovery-conflict-v1",
                    "observedState": self._expected_record(observed),
                }
            )
            self._authority.record_recovery_conflict(
                operation_id,
                reason_digest=conflict_reason,
                **current_lease(),
            )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state="recovery_required",
                replayed=False,
                error_code="ECO_RECOVERY_CONFLICT",
            )
        if bundle["phase"] != "rollback-ready" or not isinstance(bundle["intentDigest"], str):
            raise RuntimeStoreError(
                "ECO_CHANGE_RECOVERY_INVALID", "Rollback authority was not durable"
            )

        broker_result = WorkspaceWriteResult(
            path=bundle["path"],
            operation=bundle["operation"],
            before=before,
            after=after,
            candidate_proof=candidate_proof,
            rollback_proof=rollback_proof,
        )
        try:
            self._authority.mark_rolling_back(operation_id, **current_lease())
            rollback_result = self._broker.rollback(
                broker_result,
                temporary_name=bundle["temporaryName"],
                commit_authority_hook=lambda: self._authority.assert_operation_lease(
                    operation_id,
                    required_state="rolling_back",
                    **current_lease(),
                ),
            )
            recovery_receipt_digest = semantic_digest(
                {
                    "domain": "eco-workspace-recovery-receipt-v1",
                    "operationId": operation_id,
                    "intentDigest": bundle["intentDigest"],
                    "restoredState": self._expected_record(rollback_result.state),
                    "changed": rollback_result.changed,
                }
            )
            self._authority.mark_rolled_back(
                operation_id,
                receipt_digest=recovery_receipt_digest,
                **current_lease(),
            )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state="rolled_back",
                replayed=False,
                broker_result=broker_result,
                error_code="ECO_CRASH_RECOVERY_ROLLBACK",
            )
        except BrokerError as exc:
            reason = semantic_digest(
                {"domain": "eco-write-recovery-failure-v1", "code": exc.code}
            )
            self._authority.mark_recovery_required(
                operation_id, reason_digest=reason, **current_lease()
            )
            return ControlledWriteExecution(
                operation_id=operation_id,
                state="recovery_required",
                replayed=False,
                broker_result=broker_result,
                error_code=exc.code,
            )

    def _rollback_receipt(
        self,
        proposal: ControlledWriteProposal,
        *,
        operation_id: str,
        intent: dict[str, Any],
        receipt: dict[str, Any],
        result: WorkspaceRollbackResult,
        now: datetime,
        status: str,
    ) -> dict[str, Any]:
        restored = self._expected_record(result.state)
        return validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "WorkspaceRollbackReceipt",
                "metadata": {
                    "id": f"rollback-{operation_id}",
                    "runId": proposal.plan["metadata"]["runId"],
                    "operationId": operation_id,
                    "createdAt": _utc(now),
                },
                "spec": {
                    "writeIntentDigest": semantic_digest(intent),
                    "writeReceiptDigest": semantic_digest(receipt),
                    "reasonCode": "ECO_POST_APPLY_VALIDATION_FAILED",
                    "pathDigest": proposal.proposal["spec"]["pathDigest"],
                    "status": status,
                    "expectedAppliedDigest": proposal.candidate_proof.sha256,
                    "beforeRestored": restored,
                    "rollbackProfile": "single-file-cas-restore-v1",
                    "restoredStateDigest": semantic_digest(restored),
                },
            }
        )
