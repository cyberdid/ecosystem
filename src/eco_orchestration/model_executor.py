from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.contracts import validate_record
from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimeStoreError
from eco_runtime.model_orchestrator import GovernedModelOrchestrator

from .context import (
    RoleExecution,
    RoleExecutorFailure,
    RoleInvocation,
    RoleUsage,
    UntrustedArtifact,
)


TYPED_INPUT_ENVELOPE_FORMAT = "eco.openai-typed-messages/v1"


def _payload(item: UntrustedArtifact) -> dict[str, Any]:
    return {
        "binding": copy.deepcopy(dict(item.binding)),
        "contentBase64": base64.b64encode(item.content).decode("ascii"),
        "mediaType": item.media_type,
        "sourceEntryId": item.source_entry_id,
        "trust": "P0",
    }


def canonical_role_input_envelope(invocation: RoleInvocation) -> bytes:
    """Return the only byte representation accepted by the typed adapter.

    Trusted instructions, structured state, sources, and prior artifacts stay
    in distinct fields.  Content bytes are base64 values inside data fields;
    they never participate in choosing a provider message role.
    """

    if not isinstance(invocation, RoleInvocation):
        raise TypeError("invocation must be RoleInvocation")
    value = {
        "attempt": invocation.attempt,
        "format": TYPED_INPUT_ENVELOPE_FORMAT,
        "roleId": invocation.role_id,
        "runtimeState": copy.deepcopy(dict(invocation.runtime_state)),
        "trustedInstruction": invocation.trusted_instruction,
        "trustedOutputSchema": copy.deepcopy(
            dict(invocation.trusted_output_schema)
        ),
        "untrustedArtifacts": [
            _payload(item) for item in invocation.untrusted_artifacts
        ],
        "untrustedSources": [
            _payload(item) for item in invocation.untrusted_sources
        ],
    }
    return canonical_json(value).encode("utf-8")


@dataclass(frozen=True)
class TypedEnvelopeBinding:
    """Content-free information exposed to the authority resolver."""

    content_digest: str
    byte_length: int


@dataclass(frozen=True)
class GovernedRoleCall:
    """Exact pre-authorized runtime records for one role attempt."""

    plan: Mapping[str, Any]
    request: Mapping[str, Any]
    endpoint_binding: Mapping[str, Any]
    input_artifact: Mapping[str, Any]
    decision: Mapping[str, Any]
    idempotency_key: str
    cost_reservation_microusd: int
    now: datetime

    def __post_init__(self) -> None:
        for name in (
            "plan",
            "request",
            "endpoint_binding",
            "input_artifact",
            "decision",
        ):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise TypeError(f"{name} must be a mapping")
            object.__setattr__(self, name, copy.deepcopy(dict(value)))
        if not isinstance(self.idempotency_key, str) or not self.idempotency_key:
            raise ValueError("idempotency_key must be a non-empty string")
        if (
            not isinstance(self.cost_reservation_microusd, int)
            or isinstance(self.cost_reservation_microusd, bool)
            or self.cost_reservation_microusd < 0
        ):
            raise ValueError("cost_reservation_microusd must be non-negative")
        if not isinstance(self.now, datetime) or self.now.tzinfo is None:
            raise ValueError("now must be timezone-aware")


class RoleCallResolver(Protocol):
    """Resolve authority using only role identity and an envelope digest."""

    def resolve(
        self, role_id: str, attempt: int, envelope: TypedEnvelopeBinding
    ) -> GovernedRoleCall: ...


class GovernedRoleExecutor:
    """RoleExecutor backed exclusively by GovernedModelOrchestrator.

    The resolver never receives source bytes.  It returns records bound to the
    canonical envelope digest, then this executor installs those exact bytes in
    private CAS before the orchestrator performs its own proof, policy, durable
    egress-fence, and terminal-settlement checks.
    """

    def __init__(
        self,
        orchestrator: GovernedModelOrchestrator,
        artifact_store: ContentAddressedArtifactStore,
        resolver: RoleCallResolver,
    ) -> None:
        if not isinstance(orchestrator, GovernedModelOrchestrator):
            raise TypeError("orchestrator must be GovernedModelOrchestrator")
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be ContentAddressedArtifactStore")
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("resolver must implement RoleCallResolver")
        self._orchestrator = orchestrator
        self._artifact_store = artifact_store
        self._resolver = resolver

    @staticmethod
    def _validate_binding(
        call: GovernedRoleCall, envelope: TypedEnvelopeBinding
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            artifact = copy.deepcopy(validate_record(dict(call.input_artifact)))
            request = copy.deepcopy(validate_record(dict(call.request)))
        except ContractValidationError as exc:
            raise RuntimeStoreError(
                "ECO_MODEL_INPUT_MISMATCH", "Typed model input binding is invalid"
            ) from exc
        spec = artifact["spec"]
        request_input = request["spec"]["input"]
        if (
            artifact["kind"] != "ArtifactRecord"
            or spec["role"] != "input"
            or spec["mediaType"] != "application/json"
            or spec["producer"]["type"] != "runtime"
            or spec["sha256"] != envelope.content_digest
            or spec["byteLength"] != envelope.byte_length
            or request_input["artifactRecordDigest"] != semantic_digest(artifact)
            or request_input["contentDigest"] != envelope.content_digest
            or request_input["byteLength"] != envelope.byte_length
            or request_input["dataClass"] != spec["dataClass"]
            or request_input["trust"] != spec["trust"]
        ):
            raise RuntimeStoreError(
                "ECO_MODEL_INPUT_MISMATCH",
                "Typed model input does not match its artifact binding",
            )
        return request, artifact

    def execute(self, invocation: RoleInvocation) -> RoleExecution:
        envelope_bytes = canonical_role_input_envelope(invocation)
        envelope = TypedEnvelopeBinding(
            content_digest=hashlib.sha256(envelope_bytes).hexdigest(),
            byte_length=len(envelope_bytes),
        )
        call = self._resolver.resolve(invocation.role_id, invocation.attempt, envelope)
        if not isinstance(call, GovernedRoleCall):
            raise RuntimeStoreError(
                "ECO_MODEL_ROUTE_MISMATCH", "Role route resolver returned an invalid call"
            )
        request, artifact = self._validate_binding(call, envelope)
        parameters = request["spec"]["parameters"]
        budget = invocation.runtime_state.get("budget")
        if not isinstance(budget, Mapping):
            raise RuntimeStoreError(
                "ECO_MODEL_BUDGET_INVALID", "Role invocation budget is unavailable"
            )
        budget_names = (
            "maxInputBytes",
            "maxTotalTokens",
            "maxOutputBytes",
            "maxCostMicrousd",
            "maxDurationSeconds",
            "maxModelRequests",
            "maxAttempts",
        )
        if any(
            not isinstance(budget.get(name), int)
            or isinstance(budget.get(name), bool)
            or budget[name] < 0
            for name in budget_names
        ):
            raise RuntimeStoreError(
                "ECO_MODEL_BUDGET_INVALID", "Role invocation budget is invalid"
            )
        reservation_exceeds_role_budget = (
            envelope.byte_length > budget["maxInputBytes"]
            or envelope.byte_length + parameters["maxOutputTokens"]
            > budget["maxTotalTokens"]
            or parameters["maxOutputBytes"] > budget["maxOutputBytes"]
            or call.cost_reservation_microusd
            > budget["maxCostMicrousd"]
            or request["spec"]["timeoutMs"]
            > budget["maxDurationSeconds"] * 1000
            or budget["maxModelRequests"] < 1
            or budget["maxAttempts"] < 1
        )
        if reservation_exceeds_role_budget:
            raise RoleExecutorFailure(
                status="failed",
                error_code="budget-exceeded",
                usage=RoleUsage(
                    duration_seconds=0,
                    input_bytes=0,
                    output_bytes=0,
                    total_tokens=0,
                    cost_microusd=0,
                ),
            )
        replay_state = self._orchestrator.exact_replay_state(
            request,
            dict(call.endpoint_binding),
            artifact,
            dict(call.decision),
            idempotency_key=call.idempotency_key,
            cost_reservation_microusd=call.cost_reservation_microusd,
        )
        if replay_state is None:
            self._artifact_store.put(
                [envelope_bytes],
                storage_ref=artifact["spec"]["storageRef"],
                expected_sha256=envelope.content_digest,
                expected_byte_length=envelope.byte_length,
                max_bytes=envelope.byte_length,
            )
        reserved_usage = RoleUsage(
            duration_seconds=0,
            input_bytes=envelope.byte_length,
            output_bytes=0,
            total_tokens=envelope.byte_length + parameters["maxOutputTokens"],
            cost_microusd=call.cost_reservation_microusd,
        )
        try:
            execution = self._orchestrator.execute(
                dict(call.plan),
                request,
                dict(call.endpoint_binding),
                artifact,
                dict(call.decision),
                envelope_bytes.decode("utf-8"),
                idempotency_key=call.idempotency_key,
                cost_reservation_microusd=call.cost_reservation_microusd,
                now=call.now,
            )
        except RuntimeStoreError as exc:
            if exc.code == "ECO_MODEL_INVOCATION_AMBIGUOUS":
                raise RoleExecutorFailure(
                    status="ambiguous",
                    error_code="provider-ambiguous",
                    usage=reserved_usage,
                ) from exc
            raise
        if execution.state != "succeeded":
            raise RoleExecutorFailure(
                status="ambiguous" if execution.state == "ambiguous" else "failed",
                error_code=(
                    "provider-ambiguous"
                    if execution.state == "ambiguous"
                    else "adapter-failed"
                ),
                usage=reserved_usage,
            )
        if execution.untrusted_output is None:
            if not execution.replayed:
                raise RuntimeStoreError(
                    "ECO_MODEL_RECOVERY_UNAVAILABLE",
                    "Succeeded model output is unavailable",
                )
            try:
                raw_output = self._orchestrator.recover_succeeded_output(
                    execution.request_id
                ).content
            except RuntimeStoreError as exc:
                raise RoleExecutorFailure(
                    status="ambiguous",
                    error_code="provider-ambiguous",
                    usage=reserved_usage,
                ) from exc
        else:
            raw_output = execution.untrusted_output.encode("utf-8")
        return RoleExecution(
            raw_output=raw_output,
            usage=RoleUsage(
                duration_seconds=0,
                input_bytes=envelope.byte_length,
                output_bytes=len(raw_output),
                # Provider-reported token usage is informational.  The
                # durable bridge charges this exact authorized ceiling.
                total_tokens=envelope.byte_length
                + parameters["maxOutputTokens"],
                cost_microusd=call.cost_reservation_microusd,
            ),
        )
