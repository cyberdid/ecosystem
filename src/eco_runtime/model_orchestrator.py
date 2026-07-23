from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from .adapters import AdapterInvocationResult
from .artifact_store import ContentAddressedArtifactStore
from .contracts import API_VERSION, validate_record
from .digests import semantic_digest
from .errors import ContractValidationError, RuntimeAdapterError, RuntimeStoreError
from .orchestrator import RuntimeCapabilities
from .policy import PolicyEngine
from .store import SAFE_MODEL_ERROR_MESSAGES, SQLiteRuntimeStore


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise RuntimeStoreError("ECO_CLOCK_INVALID", "Runtime clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ModelAdapter(Protocol):
    def invoke(
        self, request: dict[str, Any], input_text: str, *, now: datetime
    ) -> AdapterInvocationResult: ...


@dataclass(frozen=True)
class ModelInvocationExecution:
    request_id: str
    state: str
    model_result_digest: str | None
    output_artifact_record_digest: str | None
    error_record_digest: str | None
    untrusted_output: str | None = field(repr=False)
    replayed: bool = False


@dataclass(frozen=True)
class RecoveredModelOutput:
    """Verified replay bytes plus their authenticated, content-free record."""

    artifact_record: dict[str, Any]
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_record", copy.deepcopy(self.artifact_record))
        if not isinstance(self.content, bytes):
            raise TypeError("content must be bytes")


class GovernedModelOrchestrator:
    """The only safe composition path from policy authority to model egress.

    PREPARE and STARTED are distinct durable fences.  A PREPARED call may be
    resumed because no adapter egress was authorized yet.  A STARTED call is
    permanently ambiguous until an explicit terminal settlement is present and
    is never invoked automatically again.
    """

    def __init__(
        self,
        store: SQLiteRuntimeStore,
        artifact_store: ContentAddressedArtifactStore,
        policy: PolicyEngine,
        adapter: ModelAdapter,
        *,
        capabilities: RuntimeCapabilities,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, SQLiteRuntimeStore):
            raise TypeError("store must be SQLiteRuntimeStore")
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be ContentAddressedArtifactStore")
        if not isinstance(policy, PolicyEngine):
            raise TypeError("policy must be PolicyEngine")
        self._store = store
        self._artifact_store = artifact_store
        self._policy = policy
        self._adapter = adapter
        self._capabilities = capabilities
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def recover_succeeded_output(self, request_id: str) -> RecoveredModelOutput:
        """Recover terminal output without provider egress or journal raw bytes."""

        artifact = self._store.recover_succeeded_model_output_record(
            request_id, runtime_capability=self._capabilities.runtime
        )
        spec = artifact["spec"]
        proof = self._artifact_store.proof_for_record(
            storage_ref=spec["storageRef"],
            sha256=spec["sha256"],
            byte_length=spec["byteLength"],
        )
        with self._artifact_store.open_verified(proof) as stream:
            content = stream.read(spec["byteLength"] + 1)
        if (
            len(content) != spec["byteLength"]
            or hashlib.sha256(content).hexdigest() != spec["sha256"]
        ):
            raise RuntimeStoreError(
                "ECO_ARTIFACT_STORE_CORRUPT", "Recovered model output is invalid"
            )
        return RecoveredModelOutput(artifact_record=artifact, content=content)

    def exact_replay_state(
        self,
        request: dict[str, Any],
        endpoint_binding: dict[str, Any],
        input_artifact: dict[str, Any],
        decision: dict[str, Any],
        *,
        idempotency_key: str,
        cost_reservation_microusd: int,
    ) -> str | None:
        """Return content-free state for an exact call, without CAS access."""

        operation = self._store.exact_model_replay_status(
            request,
            endpoint_binding,
            input_artifact,
            decision,
            idempotency_key=idempotency_key,
            cost_reservation_microusd=cost_reservation_microusd,
        )
        return None if operation is None else operation["state"]

    @staticmethod
    def _replay(operation: dict[str, Any]) -> ModelInvocationExecution:
        state = operation["state"]
        if state == "started":
            raise RuntimeStoreError(
                "ECO_MODEL_INVOCATION_AMBIGUOUS",
                "Started model invocation cannot be retried automatically",
            )
        if state not in {"succeeded", "failed", "ambiguous"}:
            raise RuntimeStoreError(
                "ECO_MODEL_OPERATION_IN_PROGRESS",
                "Prepared model invocation has not reached its egress fence",
            )
        return ModelInvocationExecution(
            request_id=operation["request_id"],
            state=state,
            model_result_digest=operation["model_result_digest"],
            output_artifact_record_digest=operation[
                "output_artifact_record_digest"
            ],
            error_record_digest=operation["error_record_digest"],
            untrusted_output=None,
            replayed=True,
        )

    def execute(
        self,
        plan: dict[str, Any],
        request: dict[str, Any],
        endpoint_binding: dict[str, Any],
        input_artifact: dict[str, Any],
        decision: dict[str, Any],
        input_text: str,
        *,
        idempotency_key: str,
        cost_reservation_microusd: int,
        now: datetime,
    ) -> ModelInvocationExecution:
        """Authorize, prepare, invoke once, persist CAS output, and settle."""

        try:
            plan = copy.deepcopy(validate_record(plan))
            request = copy.deepcopy(validate_record(request))
            endpoint_binding = copy.deepcopy(validate_record(endpoint_binding))
            input_artifact = copy.deepcopy(validate_record(input_artifact))
            decision = copy.deepcopy(validate_record(decision))
        except ContractValidationError as exc:
            raise RuntimeStoreError(
                "ECO_STORE_RECORD_INVALID", "Model invocation input is invalid"
            ) from exc
        if cost_reservation_microusd != 0:
            raise RuntimeStoreError(
                "ECO_PRICING_AUTHORITY_REQUIRED",
                "M6.1 accepts only an exact zero-cost local model profile",
            )

        existing = self._store.exact_model_replay_status(
            request,
            endpoint_binding,
            input_artifact,
            decision,
            idempotency_key=idempotency_key,
            cost_reservation_microusd=cost_reservation_microusd,
        )
        if existing is not None and existing["state"] != "prepared":
            return self._replay(existing)
        if not isinstance(input_text, str):
            raise RuntimeStoreError("ECO_MODEL_INPUT_MISMATCH", "Model input must be text")
        encoded_input = input_text.encode("utf-8")
        if (
            len(encoded_input) != input_artifact["spec"]["byteLength"]
            or hashlib.sha256(encoded_input).hexdigest()
            != input_artifact["spec"]["sha256"]
            or request["spec"]["input"]["contentDigest"]
            != input_artifact["spec"]["sha256"]
        ):
            raise RuntimeStoreError(
                "ECO_MODEL_INPUT_MISMATCH", "Model input does not match its artifact"
            )
        # Caller time is only a lower-bound anti-rollback assertion.  Fresh
        # authority, durable STARTED fencing, and adapter egress all use the
        # broker-owned clock sampled immediately before those operations.
        execution_now = self._completion_time(now)
        fresh_resume_decision: dict[str, Any] | None = None
        if existing is None:
            self._policy.assert_decision_current(
                decision, request, now=execution_now
            )
            start_gate = self._policy.authorize_model(
                plan,
                request,
                endpoint_binding,
                input_artifact,
                decision_id=f"model-start-{semantic_digest({'requestId': request['metadata']['id'], 'now': _utc(execution_now)})[:32]}",
                now=execution_now,
                require_in_memory_activation=False,
            )
            if start_gate["spec"]["effect"] != "allow":
                raise RuntimeStoreError(
                    start_gate["spec"]["reasonCodes"][0],
                    "Policy denied the exact model invocation",
                )
        else:
            resume_id = f"model-resume-{semantic_digest({'requestId': request['metadata']['id'], 'now': _utc(execution_now)})[:32]}"
            fresh_resume_decision = self._policy.authorize_model(
                plan,
                request,
                endpoint_binding,
                input_artifact,
                decision_id=resume_id,
                now=execution_now,
                require_in_memory_activation=False,
            )
            if fresh_resume_decision["spec"]["effect"] != "allow":
                raise RuntimeStoreError(
                    fresh_resume_decision["spec"]["reasonCodes"][0],
                    "Policy denied resuming the prepared model invocation",
                )

        input_proof = self._artifact_store.proof_for_record(
            storage_ref=input_artifact["spec"]["storageRef"],
            sha256=input_artifact["spec"]["sha256"],
            byte_length=input_artifact["spec"]["byteLength"],
        )

        prepared = self._store.prepare_model_invocation(
            plan,
            request,
            endpoint_binding,
            input_artifact,
            decision,
            input_availability_proof=input_proof,
            idempotency_key=idempotency_key,
            cost_reservation_microusd=cost_reservation_microusd,
            now=execution_now,
            policy_capability=self._capabilities.policy,
            runtime_capability=self._capabilities.runtime,
            adapter_capability=self._capabilities.adapter,
        )
        if prepared["state"] in {"succeeded", "failed", "ambiguous", "started"}:
            return self._replay(prepared)
        if prepared["replayed"]:
            if fresh_resume_decision is None:
                raise RuntimeStoreError(
                    "ECO_MODEL_RESUME_AUTHORITY_REQUIRED",
                    "Prepared model invocation requires fresh authority",
                )
            started = self._store.resume_prepared_model_invocation(
                request,
                fresh_resume_decision,
                now=execution_now,
                policy_capability=self._capabilities.policy,
                adapter_capability=self._capabilities.adapter,
            )
        else:
            started = self._store.start_model_invocation(
                request["metadata"]["id"],
                now=execution_now,
                adapter_capability=self._capabilities.adapter,
            )
        if started.get("replayed") or started["state"] != "started":
            return self._replay(started)
        try:
            invocation = self._adapter.invoke(request, input_text, now=execution_now)
        except RuntimeAdapterError as exc:
            completion_now = self._completion_time(execution_now)
            code = exc.code if exc.code in SAFE_MODEL_ERROR_MESSAGES else "ECO_ADAPTER_TRANSPORT"
            return self._fail(request, code=code, now=completion_now)
        except Exception:
            # An adapter is an untrusted egress boundary.  Never expose a
            # provider/library exception or leave its reservation open merely
            # because the implementation failed to translate that exception.
            completion_now = self._completion_time(execution_now)
            return self._fail(
                request, code="ECO_ADAPTER_TRANSPORT", now=completion_now
            )
        completion_now = self._completion_time(execution_now)
        try:
            normalized_record = copy.deepcopy(invocation.record)
            normalized_record["metadata"]["createdAt"] = _utc(completion_now)
            if not isinstance(invocation.untrusted_output, str):
                raise TypeError("adapter output must be text")
            invocation = AdapterInvocationResult(
                record=validate_record(normalized_record),
                untrusted_output=invocation.untrusted_output,
            )
        except (AttributeError, ContractValidationError, KeyError, TypeError):
            return self._fail(
                request, code="ECO_ADAPTER_RESPONSE_INVALID", now=completion_now
            )
        deadline = self._store.budget_status(request["metadata"]["runId"])["deadline_at"]
        deadline_at = datetime.fromisoformat(
            deadline[:-1] + "+00:00" if deadline.endswith("Z") else deadline
        ).astimezone(timezone.utc)
        if completion_now.astimezone(timezone.utc) >= deadline_at:
            return self._fail(request, code="ECO_DEADLINE_EXCEEDED", now=completion_now)
        finalization_decision = self._policy.authorize_model(
            plan,
            request,
            endpoint_binding,
            input_artifact,
            decision_id=f"model-finalize-{semantic_digest({'requestId': request['metadata']['id'], 'now': _utc(completion_now)})[:32]}",
            now=completion_now,
            require_in_memory_activation=False,
        )
        if finalization_decision["spec"]["effect"] != "allow":
            self._store.issue_decision(
                finalization_decision,
                semantic_config_digest=plan["spec"]["project"]["semanticConfigDigest"],
                policy_capability=self._capabilities.policy,
            )
            return self._fail(
                request,
                code="ECO_MODEL_FINALIZATION_DENIED",
                policy_rule=finalization_decision["spec"]["reasonCodes"][0],
                now=completion_now,
            )
        return self._complete(
            request,
            input_artifact,
            invocation,
            finalization_decision=finalization_decision,
            now=completion_now,
        )

    def _completion_time(self, started_at: datetime) -> datetime:
        completed_at = self._clock()
        if completed_at.tzinfo is None:
            raise RuntimeStoreError("ECO_CLOCK_INVALID", "Completion clock must be timezone-aware")
        if completed_at.astimezone(timezone.utc) < started_at.astimezone(timezone.utc):
            raise RuntimeStoreError("ECO_CLOCK_ROLLBACK", "Completion clock moved backwards")
        return completed_at

    def _complete(
        self,
        request: dict[str, Any],
        input_artifact: dict[str, Any],
        invocation: AdapterInvocationResult,
        *,
        finalization_decision: dict[str, Any],
        now: datetime,
    ) -> ModelInvocationExecution:
        output = invocation.record["spec"]["output"]
        request_id = request["metadata"]["id"]
        run_id = request["metadata"]["runId"]
        artifact_id = f"model-output-{semantic_digest({'requestId': request_id})}"
        storage_ref = f"artifact://runs/{run_id}/{artifact_id}"
        encoded_output = invocation.untrusted_output.encode("utf-8")
        proof = self._artifact_store.put(
            [encoded_output],
            storage_ref=storage_ref,
            expected_sha256=output["contentDigest"],
            expected_byte_length=output["byteLength"],
            max_bytes=request["spec"]["parameters"]["maxOutputBytes"],
        )
        artifact = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ArtifactRecord",
                "metadata": {
                    "id": artifact_id,
                    "runId": run_id,
                    "createdAt": _utc(now),
                },
                "spec": {
                    "role": "output",
                    "mediaType": "text/plain",
                    "byteLength": output["byteLength"],
                    "sha256": output["contentDigest"],
                    "dataClass": output["dataClass"],
                    "trust": "P0",
                    "producer": {
                        "type": "model",
                        "id": request["spec"]["deploymentId"],
                    },
                    "parentRefs": [input_artifact["spec"]["storageRef"]],
                    "storageRef": storage_ref,
                    "retention": "run",
                },
            }
        )
        operation = self._store.complete_model_invocation(
            request_id,
            result=invocation.record,
            output_artifact=artifact,
            finalization_decision=finalization_decision,
            availability_proof=proof,
            now=now,
            adapter_capability=self._capabilities.adapter,
        )
        return ModelInvocationExecution(
            request_id=request_id,
            state=operation["state"],
            model_result_digest=operation["model_result_digest"],
            output_artifact_record_digest=operation[
                "output_artifact_record_digest"
            ],
            error_record_digest=None,
            untrusted_output=invocation.untrusted_output,
            replayed=False,
        )

    def _fail(
        self,
        request: dict[str, Any],
        *,
        code: str,
        now: datetime,
        policy_rule: str | None = None,
    ) -> ModelInvocationExecution:
        request_id = request["metadata"]["id"]
        error = validate_record(
            {
                "apiVersion": API_VERSION,
                "kind": "ErrorRecord",
                "metadata": {
                    "id": f"error-{semantic_digest({'requestId': request_id})}",
                    "runId": request["metadata"]["runId"],
                    "requestId": request_id,
                    "createdAt": _utc(now),
                },
                "spec": {
                    "code": code,
                    "category": (
                        "policy"
                        if code == "ECO_MODEL_FINALIZATION_DENIED"
                        else "budget"
                        if code == "ECO_DEADLINE_EXCEEDED"
                        else "adapter"
                    ),
                    "stage": "model",
                    "retryable": False,
                    "safeMessage": SAFE_MODEL_ERROR_MESSAGES[code],
                    "details": (
                        {"policyRule": policy_rule}
                        if code == "ECO_MODEL_FINALIZATION_DENIED"
                        else {"deploymentId": request["spec"]["deploymentId"]}
                    ),
                },
            }
        )
        operation = self._store.fail_model_invocation(
            request_id,
            error=error,
            now=now,
            adapter_capability=self._capabilities.adapter,
        )
        return ModelInvocationExecution(
            request_id=request_id,
            state=operation["state"],
            model_result_digest=None,
            output_artifact_record_digest=None,
            error_record_digest=operation["error_record_digest"],
            untrusted_output=None,
            replayed=False,
        )
