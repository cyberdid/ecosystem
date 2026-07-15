from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from .artifact_store import ContentAddressedArtifactStore
from .broker import RepositoryReadResult
from .contracts import API_VERSION, validate_record, validate_tool_arguments
from .digests import semantic_digest
from .errors import BrokerError, ContractValidationError, RuntimeStoreError
from .policy import PolicyEngine
from .store import SAFE_BROKER_ERROR_MESSAGES, SQLiteRuntimeStore


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Runtime clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class RuntimeCapabilities:
    """Opaque issuer capabilities held by the embedded trusted composition root."""

    policy: object
    broker: object
    runtime: object
    adapter: object

    def __post_init__(self) -> None:
        values = (self.policy, self.broker, self.runtime, self.adapter)
        if any(value is None for value in values) or len({id(value) for value in values}) != 4:
            raise ValueError("runtime capabilities must be four distinct non-null objects")


@dataclass(frozen=True)
class RepositoryReadExecution:
    """Typed logical result; terminal replay does not rehydrate content from SQL."""

    operation_id: str
    state: str
    outcome_digest: str | None
    untrusted_content: str | None
    content_digest: str | None
    byte_length: int | None
    replayed: bool


class RepositoryReader(Protocol):
    def read(self, path: str, *, maximum_bytes: int | None = None) -> RepositoryReadResult: ...


class EmbeddedOrchestrator:
    """Compose durable authority with the filesystem-only repository reader."""

    def __init__(
        self,
        store: SQLiteRuntimeStore,
        broker: RepositoryReader,
        artifact_store: ContentAddressedArtifactStore,
        policy: PolicyEngine,
        *,
        capabilities: RuntimeCapabilities,
        owner_id: str,
        lease_seconds: int = 30,
    ) -> None:
        if not isinstance(owner_id, str) or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", owner_id
        ) is None:
            raise ValueError("owner_id must be a bounded safe identifier")
        if not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive integer")
        self._store = store
        self._broker = broker
        self._artifact_store = artifact_store
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be the trusted PolicyEngine")
        self._policy = policy
        self._capabilities = capabilities
        self._owner_id = owner_id
        self._lease_seconds = lease_seconds

    def activate_plan(
        self,
        plan: dict[str, Any],
        decision: dict[str, Any],
        *,
        nonce: str,
        now: datetime,
    ) -> dict[str, Any]:
        """Durably issue/activate a plan and transition its adapter to RUNNING."""

        self._store.issue_plan(
            plan,
            decision,
            policy_capability=self._capabilities.policy,
            runtime_capability=self._capabilities.runtime,
        )
        budget = self._store.activate_plan(
            plan,
            decision,
            nonce=nonce,
            now=now,
            policy_capability=self._capabilities.policy,
        )
        status = self._store.run_status(plan["metadata"]["runId"])
        if status["state"] == "AUTHORIZED":
            self._store.start_adapter(
                plan["metadata"]["runId"],
                now=now,
                adapter_capability=self._capabilities.adapter,
            )
        return budget

    @staticmethod
    def _operation_id(run_id: str, idempotency_key_digest: str) -> str:
        digest = semantic_digest(
            {
                "domain": "eco-repository-operation-id-v1",
                "runId": run_id,
                "idempotencyKeyDigest": idempotency_key_digest,
            }
        )
        return f"operation-{digest}"

    def _intent(
        self,
        plan: dict[str, Any],
        snapshot: dict[str, Any],
        request: dict[str, Any],
        decision: dict[str, Any],
        *,
        idempotency_key_digest: str,
    ) -> dict[str, Any]:
        path = validate_tool_arguments(
            "repository.read", request["spec"]["arguments"]
        )["path"]
        entry = next(
            (candidate for candidate in snapshot["spec"]["entries"] if candidate["path"] == path),
            None,
        )
        if entry is None:
            raise RuntimeStoreError(
                "ECO_PATH_NOT_IN_SNAPSHOT", "Requested path is not in the approved snapshot"
            )
        run_id = plan["metadata"]["runId"]
        operation_id = self._operation_id(run_id, idempotency_key_digest)
        tool = next(
            (candidate for candidate in plan["spec"]["tools"] if candidate["id"] == "repository.read"),
            None,
        )
        if tool is None:
            raise RuntimeStoreError("ECO_TOOL_NOT_APPROVED", "Repository read is absent from the plan")
        return validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ToolExecutionIntent",
                "metadata": {
                    "id": operation_id,
                    "runId": run_id,
                    # Stable across retries of the same immutable ToolRequest.
                    "createdAt": request["metadata"]["createdAt"],
                },
                "spec": {
                    "idempotencyKeyDigest": idempotency_key_digest,
                    "planDigest": semantic_digest(plan),
                    "toolRequest": {
                        "id": request["metadata"]["id"],
                        "digest": semantic_digest(request),
                    },
                    "allowDecision": {
                        "id": decision["metadata"]["id"],
                        "digest": semantic_digest(decision),
                    },
                    "toolCatalogDigest": tool["catalogDigest"],
                    "reservation": {
                        "toolRequests": 1,
                        "inputBytes": entry["byteLength"],
                    },
                    "repositoryEntry": {
                        "snapshotDigest": semantic_digest(snapshot),
                        "pathDigest": self._store.path_reference_digest(path),
                        "contentDigest": entry["contentDigest"],
                        "byteLength": entry["byteLength"],
                        "dataClass": entry["dataClass"],
                        "trust": entry["trust"],
                    },
                },
            }
        )

    @staticmethod
    def _replayed(operation: dict[str, Any]) -> RepositoryReadExecution:
        return RepositoryReadExecution(
            operation_id=operation["operation_id"],
            state=operation["state"],
            outcome_digest=operation.get("outcome_digest"),
            untrusted_content=None,
            content_digest=None,
            byte_length=None,
            replayed=True,
        )

    def execute_repository_read(
        self,
        plan: dict[str, Any],
        snapshot: dict[str, Any],
        request: dict[str, Any],
        decision: dict[str, Any],
        *,
        idempotency_key_digest: str,
        now: datetime,
    ) -> RepositoryReadExecution:
        """Execute one durable read without placing raw path/content in SQLite.

        Successful bytes are installed in the separate private artifact store
        before their content-free metadata is committed to the runtime journal.
        """

        if not isinstance(idempotency_key_digest, str) or _SHA256.fullmatch(
            idempotency_key_digest
        ) is None:
            raise ValueError("idempotency_key_digest must be an opaque SHA-256 value")
        try:
            plan = copy.deepcopy(validate_record(plan))
            snapshot = copy.deepcopy(validate_record(snapshot))
            request = copy.deepcopy(validate_record(request))
            decision = copy.deepcopy(validate_record(decision))
            trusted_decision = self._policy.authorize_tool(
                plan,
                request,
                decision_id=decision["metadata"]["id"],
                now=now,
                require_in_memory_activation=False,
            )
            if semantic_digest(trusted_decision) != semantic_digest(decision):
                raise RuntimeStoreError(
                    "ECO_DECISION_UNTRUSTED",
                    "Tool decision was not issued by the configured policy engine",
                )
            decision = trusted_decision
            intent = self._intent(
                plan,
                snapshot,
                request,
                decision,
                idempotency_key_digest=idempotency_key_digest,
            )
        except ContractValidationError as exc:
            raise RuntimeStoreError(
                "ECO_STORE_RECORD_INVALID", "Repository operation input is invalid"
            ) from exc
        prepared = self._store.prepare_repository_read(
            plan,
            snapshot,
            request,
            decision,
            intent,
            owner_id=self._owner_id,
            now=now,
            policy_capability=self._capabilities.policy,
            broker_capability=self._capabilities.broker,
            runtime_capability=self._capabilities.runtime,
            lease_seconds=self._lease_seconds,
        )
        if prepared["state"] != "prepared":
            return self._replayed(prepared)
        return self._execute_prepared(
            intent,
            request,
            operation_id=prepared["operationId"],
            lease_token=prepared["leaseToken"],
            now=now,
        )

    def _execute_prepared(
        self,
        intent: dict[str, Any],
        request: dict[str, Any],
        *,
        operation_id: str,
        lease_token: str,
        now: datetime,
    ) -> RepositoryReadExecution:
        entry = intent["spec"]["repositoryEntry"]
        path = request["spec"]["arguments"]["path"]
        try:
            read_result = self._broker.read(path, maximum_bytes=entry["byteLength"])
        except BrokerError as exc:
            code = exc.code if exc.code in SAFE_BROKER_ERROR_MESSAGES else "ECO_FILE_OPEN_FAILED"
            return self._fail(
                intent,
                operation_id=operation_id,
                lease_token=lease_token,
                code=code,
                now=now,
            )
        return self._complete(
            intent,
            read_result,
            operation_id=operation_id,
            lease_token=lease_token,
            now=now,
        )

    def _complete(
        self,
        intent: dict[str, Any],
        read_result: RepositoryReadResult,
        *,
        operation_id: str,
        lease_token: str,
        now: datetime,
    ) -> RepositoryReadExecution:
        run_id = intent["metadata"]["runId"]
        created_at = _utc(now)
        storage_ref = f"artifact://runs/{run_id}/artifact-{operation_id}"
        proof = self._artifact_store.put(
            [read_result.untrusted_content.encode("utf-8")],
            storage_ref=storage_ref,
            expected_sha256=read_result.sha256,
            expected_byte_length=read_result.byte_length,
            max_bytes=read_result.byte_length,
        )
        self._artifact_store.verify_availability(proof)
        receipt = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "RepositoryReadReceipt",
                "metadata": {
                    "id": f"receipt-{operation_id}",
                    "runId": run_id,
                    "operationId": operation_id,
                    "createdAt": created_at,
                },
                "spec": {
                    "intentDigest": semantic_digest(intent),
                    "toolRequestDigest": intent["spec"]["toolRequest"]["digest"],
                    "repositorySnapshotDigest": read_result.repository_snapshot_digest,
                    "contentDigest": read_result.sha256,
                    "byteLength": read_result.byte_length,
                    "dataClass": read_result.data_class,
                    "trust": read_result.trust,
                },
            }
        )
        artifact = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ArtifactRecord",
                "metadata": {
                    "id": f"artifact-{operation_id}",
                    "runId": run_id,
                    "createdAt": created_at,
                },
                "spec": {
                    "role": "output",
                    "mediaType": "text/plain",
                    "byteLength": read_result.byte_length,
                    "sha256": read_result.sha256,
                    "dataClass": read_result.data_class,
                    "trust": read_result.trust,
                    "producer": {"type": "tool", "id": "repository.read"},
                    "parentRefs": [],
                    "storageRef": proof.storage_ref,
                    "retention": "ephemeral",
                },
            }
        )
        outcome = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ToolExecutionOutcome",
                "metadata": {
                    "id": f"outcome-{operation_id}",
                    "runId": run_id,
                    "operationId": operation_id,
                    "createdAt": created_at,
                },
                "spec": {
                    "intentDigest": semantic_digest(intent),
                    "status": "succeeded",
                    "receiptDigest": semantic_digest(receipt),
                    "artifactRecordDigest": semantic_digest(artifact),
                },
            }
        )
        operation = self._store.complete_repository_read(
            operation_id,
            lease_token=lease_token,
            receipt=receipt,
            artifact=artifact,
            outcome=outcome,
            availability_proof=proof,
            now=now,
            broker_capability=self._capabilities.broker,
        )
        return RepositoryReadExecution(
            operation_id=operation_id,
            state=operation["state"],
            outcome_digest=operation["outcome_digest"],
            untrusted_content=read_result.untrusted_content,
            content_digest=read_result.sha256,
            byte_length=read_result.byte_length,
            replayed=False,
        )

    def _fail(
        self,
        intent: dict[str, Any],
        *,
        operation_id: str,
        lease_token: str,
        code: str,
        now: datetime,
    ) -> RepositoryReadExecution:
        run_id = intent["metadata"]["runId"]
        created_at = _utc(now)
        error = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ErrorRecord",
                "metadata": {
                    "id": f"error-{operation_id}",
                    "runId": run_id,
                    "requestId": intent["spec"]["toolRequest"]["id"],
                    "createdAt": created_at,
                },
                "spec": {
                    "code": code,
                    "category": "broker",
                    "stage": "tool",
                    "retryable": False,
                    "safeMessage": SAFE_BROKER_ERROR_MESSAGES[code],
                    "details": {"toolId": "repository.read"},
                },
            }
        )
        outcome = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ToolExecutionOutcome",
                "metadata": {
                    "id": f"outcome-{operation_id}",
                    "runId": run_id,
                    "operationId": operation_id,
                    "createdAt": created_at,
                },
                "spec": {
                    "intentDigest": semantic_digest(intent),
                    "status": "failed",
                    "errorRecordDigest": semantic_digest(error),
                },
            }
        )
        operation = self._store.fail_repository_read(
            operation_id,
            lease_token=lease_token,
            error=error,
            outcome=outcome,
            now=now,
            broker_capability=self._capabilities.broker,
        )
        return RepositoryReadExecution(
            operation_id=operation_id,
            state=operation["state"],
            outcome_digest=operation["outcome_digest"],
            untrusted_content=None,
            content_digest=None,
            byte_length=None,
            replayed=False,
        )
