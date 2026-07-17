from __future__ import annotations

import copy
import io
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.digests import canonical_json, semantic_digest
from eco_runtime.errors import ContractValidationError, RuntimeStoreError

from .context import (
    RoleExecution,
    RoleExecutor,
    RoleExecutorFailure,
    RoleInvocation,
    UntrustedArtifact,
)
from .contracts import (
    ORCHESTRATION_API_VERSION,
    orchestration_record_digest,
    validate_orchestration_record,
    validate_orchestration_record_set,
)
from .profiles import (
    SOURCE_REVIEW_ROLES,
    SourceReviewDefinitions,
    load_packaged_role_profile,
    load_source_review_rubric,
)


EXECUTION_SLOTS = (
    ("planner", 1),
    ("analyst", 1),
    ("verifier", 1),
    ("synthesizer", 1),
    ("reviewer", 1),
    ("synthesizer", 2),
    ("reviewer", 2),
)
HANDOFF_SLOTS = (
    (0, "planner", 1, "analyst", 1),
    (0, "analyst", 1, "verifier", 1),
    (0, "verifier", 1, "synthesizer", 1),
    (0, "synthesizer", 1, "reviewer", 1),
    (1, "reviewer", 1, "synthesizer", 2),
    (1, "synthesizer", 2, "reviewer", 2),
)
_USAGE_TO_BUDGET = {
    "durationSeconds": "maxDurationSeconds",
    "attempts": "maxAttempts",
    "modelRequests": "maxModelRequests",
    "inputBytes": "maxInputBytes",
    "outputBytes": "maxOutputBytes",
    "totalTokens": "maxTotalTokens",
    "costMicrousd": "maxCostMicrousd",
}
_ZERO_USAGE = {
    "durationSeconds": 0,
    "attempts": 0,
    "modelRequests": 0,
    "inputBytes": 0,
    "outputBytes": 0,
    "totalTokens": 0,
    "costMicrousd": 0,
}
_MAX_ROLE_OUTPUT_BYTES = 1_048_576
_MAX_JSON_DEPTH = 24
_MAX_JSON_ITEMS = 100_000
_MAX_SOURCE_CONTEXT_BYTES = 8_388_608


class SourceReviewError(RuntimeError):
    """Sanitized workflow failure that never contains source/model bytes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateKey(ValueError):
    pass


class _Terminal(RuntimeError):
    def __init__(self, status: str, reason_code: str) -> None:
        super().__init__(reason_code)
        self.status = status
        self.reason_code = reason_code


@dataclass(frozen=True)
class SourceReviewInputs:
    definitions: SourceReviewDefinitions
    source_bundle: Mapping[str, Any]
    request: Mapping[str, Any]
    plan: Mapping[str, Any]
    route_decisions: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.definitions, SourceReviewDefinitions):
            raise TypeError("definitions must be SourceReviewDefinitions")
        object.__setattr__(
            self,
            "definitions",
            SourceReviewDefinitions(
                tuple(copy.deepcopy(item) for item in self.definitions.profiles),
                copy.deepcopy(self.definitions.team_manifest),
                copy.deepcopy(self.definitions.loop_definition),
            ),
        )
        object.__setattr__(self, "source_bundle", copy.deepcopy(dict(self.source_bundle)))
        object.__setattr__(self, "request", copy.deepcopy(dict(self.request)))
        object.__setattr__(self, "plan", copy.deepcopy(dict(self.plan)))
        object.__setattr__(
            self,
            "route_decisions",
            tuple(copy.deepcopy(dict(item)) for item in self.route_decisions),
        )

    def base_records(self) -> tuple[dict[str, Any], ...]:
        return (
            *(copy.deepcopy(item) for item in self.definitions.records()),
            copy.deepcopy(dict(self.source_bundle)),
            copy.deepcopy(dict(self.request)),
            copy.deepcopy(dict(self.plan)),
            *(copy.deepcopy(dict(item)) for item in self.route_decisions),
        )


@dataclass(frozen=True)
class SourceReviewExecution:
    records: tuple[dict[str, Any], ...]
    result: dict[str, Any]
    replayed: bool = False


@dataclass
class _RunState:
    attempts: list[dict[str, Any]] = field(default_factory=list)
    handoffs: list[dict[str, Any]] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    verifications: list[dict[str, Any]] = field(default_factory=list)
    reviews: list[dict[str, Any]] = field(default_factory=list)
    used_routes: list[dict[str, Any]] = field(default_factory=list)
    output_artifacts: dict[tuple[str, int], UntrustedArtifact] = field(default_factory=dict)
    parsed_outputs: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)

    def usage(self) -> dict[str, int]:
        return {
            name: sum(item["spec"]["usage"][name] for item in self.attempts)
            for name in _ZERO_USAGE
        }


def _binding(record: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": record["kind"],
        "id": record["metadata"]["id"],
        "digest": record["metadata"]["recordDigest"],
    }


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SourceReviewError("ECO_CLOCK_INVALID", "Workflow clock must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey("duplicate")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite")


def _bounded_shape(value: Any, *, depth: int = 0) -> int:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("depth")
    if isinstance(value, dict):
        total = len(value)
        for item in value.values():
            total += _bounded_shape(item, depth=depth + 1)
    elif isinstance(value, list):
        total = len(value)
        for item in value:
            total += _bounded_shape(item, depth=depth + 1)
    else:
        total = 0
    if total > _MAX_JSON_ITEMS:
        raise ValueError("items")
    return total


def parse_role_output(raw: bytes, schema: Mapping[str, Any], *, maximum_bytes: int) -> dict[str, Any]:
    """Parse one exact JSON object; no fence stripping or repair is permitted."""

    if not isinstance(raw, bytes) or len(raw) > min(maximum_bytes, _MAX_ROLE_OUTPUT_BYTES):
        raise SourceReviewError("ECO_ROLE_OUTPUT_MALFORMED", "Role output is malformed")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("shape")
        _bounded_shape(value)
        if next(Draft202012Validator(dict(schema)).iter_errors(value), None) is not None:
            raise ValueError("schema")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise SourceReviewError(
            "ECO_ROLE_OUTPUT_MALFORMED", "Role output is malformed"
        ) from exc
    return value


class SourceReviewWorkflow:
    """Fixed, bounded source-review state machine over already-authorized routes."""

    def __init__(
        self,
        artifact_store: ContentAddressedArtifactStore,
        executor: RoleExecutor,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(artifact_store, ContentAddressedArtifactStore):
            raise TypeError("artifact_store must be ContentAddressedArtifactStore")
        if not callable(getattr(executor, "execute", None)):
            raise TypeError("executor must implement RoleExecutor")
        self._store = artifact_store
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._completed: dict[str, tuple[str, SourceReviewExecution]] = {}
        self._running: set[str] = set()

    def run(self, inputs: SourceReviewInputs) -> SourceReviewExecution:
        if not isinstance(inputs, SourceReviewInputs):
            raise TypeError("inputs must be SourceReviewInputs")
        plan_id = inputs.plan["metadata"]["id"]
        fingerprint = semantic_digest(
            [item["metadata"]["recordDigest"] for item in inputs.base_records()]
        )
        with self._lock:
            cached = self._completed.get(plan_id)
            if cached is not None:
                if cached[0] != fingerprint:
                    raise SourceReviewError(
                        "ECO_SOURCE_REVIEW_REPLAY_CONFLICT",
                        "Plan identifier was reused with different immutable inputs",
                    )
                return self._clone_execution(cached[1], replayed=True)
            if plan_id in self._running:
                raise SourceReviewError(
                    "ECO_SOURCE_REVIEW_IN_PROGRESS", "Source review is already running"
                )
            self._running.add(plan_id)
        try:
            result = self._execute(inputs)
        except BaseException:
            with self._lock:
                self._running.discard(plan_id)
            raise
        with self._lock:
            self._completed[plan_id] = (fingerprint, self._clone_execution(result))
            self._running.discard(plan_id)
        return result

    @staticmethod
    def _clone_execution(
        execution: SourceReviewExecution, *, replayed: bool | None = None
    ) -> SourceReviewExecution:
        return SourceReviewExecution(
            records=tuple(copy.deepcopy(item) for item in execution.records),
            result=copy.deepcopy(execution.result),
            replayed=execution.replayed if replayed is None else replayed,
        )

    def _execute(self, inputs: SourceReviewInputs) -> SourceReviewExecution:
        self._validate_base_graph(inputs)
        packaged = self._validate_trusted_profiles(inputs.definitions)
        source_artifacts = self._load_sources(inputs.source_bundle)
        route_by_slot = {
            (item["spec"]["roleId"], item["spec"]["attempt"]): item
            for item in inputs.route_decisions
        }
        state = _RunState()
        final_report: dict[str, Any] | None = None
        try:
            planner = self._invoke(
                inputs, state, route_by_slot, packaged, source_artifacts, "planner", 1, ()
            )
            self._semantic_planner(planner[0], inputs.source_bundle)
            self._handoff(inputs, state, 1, planner[1], planner[0])

            analyst = self._invoke(
                inputs, state, route_by_slot, packaged, source_artifacts, "analyst", 1,
                (planner[2],),
            )
            self._publish_claim_graph(inputs, state, analyst[0])
            self._handoff(inputs, state, 2, analyst[1], analyst[0])

            verifier = self._invoke(
                inputs, state, route_by_slot, packaged, source_artifacts, "verifier", 1,
                (analyst[2],),
            )
            self._publish_verifications(inputs, state, verifier[0])
            self._handoff(inputs, state, 3, verifier[1], verifier[0])

            synth = self._invoke(
                inputs, state, route_by_slot, packaged, (), "synthesizer", 1,
                (analyst[2], verifier[2]),
            )
            self._semantic_synthesis(state, synth[0])
            final_report = dict(synth[2].binding)
            self._handoff(inputs, state, 4, synth[1], synth[0])

            reviewer = self._invoke(
                inputs, state, route_by_slot, packaged, (), "reviewer", 1,
                (verifier[2], synth[2]),
            )
            self._semantic_reviewer(state, reviewer[0])
            review = self._publish_review(inputs, state, reviewer[1], synth[2], reviewer[0], 0)

            if reviewer[0]["verdict"] == "revision-required":
                self._handoff(inputs, state, 5, reviewer[1], reviewer[0])
                synth2 = self._invoke(
                    inputs, state, route_by_slot, packaged, (), "synthesizer", 2,
                    (verifier[2], synth[2], reviewer[2]),
                )
                self._semantic_synthesis(state, synth2[0])
                final_report = dict(synth2[2].binding)
                self._handoff(inputs, state, 6, synth2[1], synth2[0])
                reviewer2 = self._invoke(
                    inputs, state, route_by_slot, packaged, (), "reviewer", 2,
                    (verifier[2], synth2[2]),
                )
                self._semantic_reviewer(state, reviewer2[0])
                review2 = self._publish_review(
                    inputs, state, reviewer2[1], synth2[2], reviewer2[0], 1
                )
                same_report = synth[2].binding == synth2[2].binding
                if reviewer2[0]["verdict"] == "revision-required":
                    raise _Terminal(
                        "exhausted", "no-progress" if same_report else "revision-exhausted"
                    )
                if reviewer2[0]["verdict"] != "accepted":
                    raise _Terminal("incomplete", "gate-rejected")
                if same_report:
                    raise _Terminal("exhausted", "gate-rejected")
                review = review2
            elif reviewer[0]["verdict"] != "accepted":
                raise _Terminal("incomplete", "gate-rejected")

            if self._unsupported_claim_ids(state):
                raise _Terminal("incomplete", "verification-failed")
            if review["spec"]["subject"] != final_report:
                raise _Terminal("incomplete", "gate-rejected")
            status, reason = "succeeded", "accepted"
        except _Terminal as terminal:
            status, reason = terminal.status, terminal.reason_code
        except RuntimeStoreError:
            # A model result or prior handoff may already be durable. Preserve
            # that exact prefix and terminate; never promote a partial artifact.
            status, reason = "failed", "role-failed"

        return self._finish(inputs, state, status, reason, final_report)

    def _validate_base_graph(self, inputs: SourceReviewInputs) -> None:
        base = list(inputs.base_records())
        try:
            for record in base:
                validate_orchestration_record(record)
        except ContractValidationError as exc:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_INPUT_INVALID", "Source review input graph is invalid"
            ) from exc
        if len(inputs.route_decisions) != 7:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_INPUT_INVALID", "Source review route inventory is invalid"
            )
        placeholder_event = self._record(
            inputs,
            "OrchestrationEvent",
            "preflight-terminal",
            {
                "planId": inputs.plan["metadata"]["id"],
                "planDigest": inputs.plan["metadata"]["recordDigest"],
                "sequence": 1,
                "occurredAt": inputs.plan["metadata"]["createdAt"],
                "eventType": "run-denied",
                "subject": _binding(inputs.plan),
                "previousEventDigest": None,
                "reasonCode": "policy-denied",
            },
        )
        placeholder = self._record(
            inputs,
            "TeamRunResult",
            "preflight-result",
            {
                "plan": _binding(inputs.plan),
                "request": _binding(inputs.request),
                "sourceBundle": _binding(inputs.source_bundle),
                "status": "denied",
                "reasonCode": "policy-denied",
                "finalReport": None,
                "reviews": [],
                "claims": [],
                "evidence": [],
                "verifications": [],
                "routeDecisions": [
                    _binding(
                        next(
                            item
                            for item in inputs.route_decisions
                            if (item["spec"]["roleId"], item["spec"]["attempt"])
                            == EXECUTION_SLOTS[0]
                        )
                    )
                ],
                "roleAttempts": [],
                "handoffs": [],
                "usage": copy.deepcopy(_ZERO_USAGE),
                "terminalEvent": _binding(placeholder_event),
            },
        )
        try:
            validate_orchestration_record_set([*base, placeholder_event, placeholder])
        except ContractValidationError as exc:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_INPUT_INVALID", "Source review input graph is invalid"
            ) from exc

    def _validate_trusted_profiles(
        self, definitions: SourceReviewDefinitions
    ) -> dict[str, Any]:
        packaged_by_role = {
            role: load_packaged_role_profile(role) for role in SOURCE_REVIEW_ROLES
        }
        profiles = {item["spec"]["roleId"]: item for item in definitions.profiles}
        if tuple(sorted(profiles)) != tuple(sorted(SOURCE_REVIEW_ROLES)):
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_PROFILE_INVALID", "Source review profiles are invalid"
            )
        for role, packaged in packaged_by_role.items():
            profile = profiles[role]
            instruction = self._read_binding(profile["spec"]["instruction"])
            output_schema = self._read_binding(profile["spec"]["outputSchema"])
            expected_schema = canonical_json(dict(packaged.output_schema)).encode("utf-8")
            expected_fields = {
                "inputKinds": list(packaged.input_kinds),
                "outputKinds": list(packaged.output_kinds),
                "allowedCapabilities": list(packaged.allowed_capabilities),
                "allowedDataClasses": list(packaged.allowed_data_classes),
                "modelRequirements": dict(packaged.model_requirements),
            }
            if (
                instruction != packaged.instruction.encode("utf-8")
                or output_schema != expected_schema
                or any(profile["spec"][name] != value for name, value in expected_fields.items())
                or profile["spec"]["tools"] != []
            ):
                raise SourceReviewError(
                    "ECO_SOURCE_REVIEW_PROFILE_INVALID", "Source review profiles are invalid"
                )
        rubric = self._read_binding(definitions.team_manifest["spec"]["gate"]["rubric"])
        if rubric != canonical_json(load_source_review_rubric()).encode("utf-8"):
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_PROFILE_INVALID", "Source review rubric is invalid"
            )
        return packaged_by_role

    def _read_binding(self, binding: Mapping[str, Any]) -> bytes:
        try:
            proof = self._store.proof_for_record(
                storage_ref=binding["ref"],
                sha256=binding["contentDigest"],
                byte_length=binding["byteLength"],
            )
            with self._store.open_verified(proof) as stream:
                payload = stream.read(binding["byteLength"] + 1)
        except (KeyError, RuntimeStoreError, OSError) as exc:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_ARTIFACT_INVALID", "Source review artifact is unavailable"
            ) from exc
        if len(payload) != binding["byteLength"]:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_ARTIFACT_INVALID", "Source review artifact is unavailable"
            )
        return payload

    def _load_sources(
        self, source_bundle: Mapping[str, Any]
    ) -> tuple[UntrustedArtifact, ...]:
        if source_bundle["spec"]["totalByteLength"] > _MAX_SOURCE_CONTEXT_BYTES:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_CONTEXT_TOO_LARGE", "Source review context is too large"
            )
        artifacts = []
        for entry in source_bundle["spec"]["entries"]:
            binding = entry["artifact"]
            artifacts.append(
                UntrustedArtifact(
                    binding=binding,
                    content=self._read_binding(binding),
                    media_type=entry["mediaType"],
                    source_entry_id=entry["id"],
                )
            )
        return tuple(artifacts)

    def _invoke(
        self,
        inputs: SourceReviewInputs,
        state: _RunState,
        routes: Mapping[tuple[str, int], dict[str, Any]],
        profiles: Mapping[str, Any],
        sources: tuple[UntrustedArtifact, ...],
        role: str,
        attempt: int,
        prior: tuple[UntrustedArtifact, ...],
    ) -> tuple[dict[str, Any], dict[str, Any], UntrustedArtifact]:
        route = routes[(role, attempt)]
        state.used_routes.append(route)
        if (
            route["spec"]["decision"] != "allowed"
            or self._now() >= route["spec"]["validUntil"]
        ):
            raise _Terminal("denied", "policy-denied")
        step = next(item for item in inputs.plan["spec"]["steps"] if item["roleId"] == role)
        current_usage = state.usage()
        context_bytes = (
            len(profiles[role].instruction.encode("utf-8"))
            + len(canonical_json(dict(profiles[role].output_schema)).encode("utf-8"))
            + sum(len(item.content) for item in (*sources, *prior))
        )
        if (
            context_bytes > step["budget"]["maxInputBytes"]
            or current_usage["attempts"] + 1 > inputs.plan["spec"]["aggregateBudget"]["maxAttempts"]
            or current_usage["modelRequests"] + 1
            > inputs.plan["spec"]["aggregateBudget"]["maxModelRequests"]
            or current_usage["inputBytes"] + context_bytes
            > inputs.plan["spec"]["aggregateBudget"]["maxInputBytes"]
            or self._now() > inputs.plan["spec"]["deadlineAt"]
        ):
            raise _Terminal("exhausted", "budget-exhausted")
        invocation = RoleInvocation(
            role_id=role,
            attempt=attempt,
            trusted_instruction=profiles[role].instruction,
            trusted_output_schema=profiles[role].output_schema,
            runtime_state={
                "workflow": "source-review",
                "plan": _binding(inputs.plan),
                "sourceBundle": _binding(inputs.source_bundle),
                "routeDecision": _binding(route),
                "cycle": attempt - 1 if role in {"synthesizer", "reviewer"} else 0,
                "budget": copy.deepcopy(step["budget"]),
                "claimIds": [item["metadata"]["id"] for item in state.claims],
                "evidenceIds": [item["metadata"]["id"] for item in state.evidence],
            },
            untrusted_sources=sources,
            untrusted_artifacts=prior,
        )
        started = self._now()
        try:
            execution = self._executor.execute(invocation)
            if not isinstance(execution, RoleExecution):
                raise TypeError("invalid executor result")
        except RoleExecutorFailure as exc:
            usage = exc.usage.as_contract_usage()
            aggregate = {
                name: current_usage[name] + usage[name] for name in current_usage
            }
            out_of_bounds = any(
                usage[name] > step["budget"][budget]
                or aggregate[name]
                > inputs.plan["spec"]["aggregateBudget"][budget]
                for name, budget in _USAGE_TO_BUDGET.items()
            )
            if out_of_bounds:
                # The record contract cannot represent usage above its exact
                # approved ceiling.  Preserve the largest representable charged
                # prefix and terminate exhausted; never lose the TeamRunResult.
                usage = {
                    name: min(
                        usage[name],
                        step["budget"][budget],
                        max(
                            0,
                            inputs.plan["spec"]["aggregateBudget"][budget]
                            - current_usage[name],
                        ),
                    )
                    for name, budget in _USAGE_TO_BUDGET.items()
                }
            attempt_record = self._attempt_record(
                inputs,
                route,
                role,
                attempt,
                started,
                self._now(),
                None,
                "failed" if out_of_bounds else exc.status,
                "budget-exceeded" if out_of_bounds else exc.error_code,
                usage,
            )
            state.attempts.append(attempt_record)
            if out_of_bounds or exc.error_code == "budget-exceeded":
                raise _Terminal("exhausted", "budget-exhausted") from exc
            raise _Terminal("failed", "role-failed") from exc
        except Exception as exc:
            usage = {
                **_ZERO_USAGE,
                "attempts": 1,
                "modelRequests": 1,
                "inputBytes": context_bytes,
            }
            attempt_record = self._attempt_record(
                inputs, route, role, attempt, started, self._now(), None,
                "ambiguous", "provider-ambiguous", usage,
            )
            state.attempts.append(attempt_record)
            raise _Terminal("failed", "role-failed") from exc
        finished = self._now()
        usage = execution.usage.as_contract_usage()
        role_overage = any(
            usage[name] > step["budget"][budget]
            for name, budget in _USAGE_TO_BUDGET.items()
        )
        aggregate = {
            name: current_usage[name] + usage[name] for name in current_usage
        }
        aggregate_overage = any(
            aggregate[name] > inputs.plan["spec"]["aggregateBudget"][budget]
            for name, budget in _USAGE_TO_BUDGET.items()
        )
        if role_overage or aggregate_overage:
            # The executor crossed an already-authorized ceiling. The durable
            # charge is the conservative reservation ceiling that the contract
            # can represent; no over-budget output is published or accepted.
            charged = {
                name: min(
                    usage[name],
                    step["budget"][_USAGE_TO_BUDGET[name]],
                    max(
                        0,
                        inputs.plan["spec"]["aggregateBudget"][_USAGE_TO_BUDGET[name]]
                        - current_usage[name],
                    ),
                )
                for name in usage
            }
            attempt_record = self._attempt_record(
                inputs,
                route,
                role,
                attempt,
                started,
                finished,
                None,
                "failed",
                "budget-exceeded",
                charged,
            )
            state.attempts.append(attempt_record)
            raise _Terminal("exhausted", "budget-exhausted")
        try:
            parsed = parse_role_output(
                execution.raw_output,
                profiles[role].output_schema,
                maximum_bytes=step["budget"]["maxOutputBytes"],
            )
        except SourceReviewError as exc:
            attempt_record = self._attempt_record(
                inputs, route, role, attempt, started, finished, None,
                "failed", "malformed-output", usage,
            )
            state.attempts.append(attempt_record)
            raise _Terminal("failed", "role-failed") from exc
        try:
            output_binding = self._put_artifact(
                inputs, execution.raw_output, f"role-{role}-{attempt}"
            )
        except RuntimeStoreError as exc:
            attempt_record = self._attempt_record(
                inputs,
                route,
                role,
                attempt,
                started,
                finished,
                None,
                "ambiguous",
                "provider-ambiguous",
                usage,
            )
            state.attempts.append(attempt_record)
            raise _Terminal("failed", "role-failed") from exc
        attempt_record = self._attempt_record(
            inputs, route, role, attempt, started, finished, output_binding,
            "succeeded", None, usage,
        )
        state.attempts.append(attempt_record)
        artifact = UntrustedArtifact(
            binding=output_binding,
            content=execution.raw_output,
            media_type="application/json",
        )
        state.output_artifacts[(role, attempt)] = artifact
        state.parsed_outputs[(role, attempt)] = parsed
        return parsed, attempt_record, artifact

    def _attempt_record(
        self,
        inputs: SourceReviewInputs,
        route: Mapping[str, Any],
        role: str,
        attempt: int,
        started: str,
        finished: str,
        output: Mapping[str, Any] | None,
        status: str,
        error_code: str | None,
        usage: Mapping[str, int],
    ) -> dict[str, Any]:
        return self._record(
            inputs,
            "RoleAttemptResult",
            f"attempt-{role}-{attempt}",
            {
                "planId": inputs.plan["metadata"]["id"],
                "planDigest": inputs.plan["metadata"]["recordDigest"],
                "roleId": role,
                "attempt": attempt,
                "routeDecision": _binding(route),
                "status": status,
                "startedAt": started,
                "finishedAt": finished,
                "output": copy.deepcopy(dict(output)) if output is not None else None,
                "errorCode": error_code,
                "usage": copy.deepcopy(dict(usage)),
            },
        )

    def _semantic_planner(self, value: Mapping[str, Any], source: Mapping[str, Any]) -> None:
        entry_ids = {item["id"] for item in source["spec"]["entries"]}
        if set(value["sourceEntryIds"]) - entry_ids:
            raise _Terminal("failed", "role-failed")

    def _publish_claim_graph(
        self, inputs: SourceReviewInputs, state: _RunState, value: Mapping[str, Any]
    ) -> None:
        claims = value["claims"]
        claim_ids = [item["id"] for item in claims]
        evidence_ids = [evidence["id"] for item in claims for evidence in item["evidence"]]
        entries = {item["id"]: item for item in inputs.source_bundle["spec"]["entries"]}
        question_id = inputs.source_bundle["spec"]["questionEntryId"]
        if (
            len(claim_ids) != len(set(claim_ids))
            or len(evidence_ids) != len(set(evidence_ids))
            or any(
                evidence["sourceEntryId"] not in entries
                or evidence["sourceEntryId"] == question_id
                for item in claims
                for evidence in item["evidence"]
            )
        ):
            raise _Terminal("failed", "role-failed")
        for item in claims:
            statement = self._put_artifact(
                inputs, item["statement"].encode("utf-8"), f"claim-{item['id']}"
            )
            state.claims.append(
                self._record(
                    inputs,
                    "ClaimRecord",
                    item["id"],
                    {
                        "planId": inputs.plan["metadata"]["id"],
                        "planDigest": inputs.plan["metadata"]["recordDigest"],
                        "sourceBundle": _binding(inputs.source_bundle),
                        "producedByRole": "analyst",
                        "statement": statement,
                        "classification": item["classification"],
                        "state": "proposed",
                    },
                )
            )
            for evidence in item["evidence"]:
                source_entry = entries[evidence["sourceEntryId"]]
                exact_passage = evidence["observation"].encode("utf-8")
                if exact_passage not in self._read_binding(source_entry["artifact"]):
                    raise _Terminal("failed", "role-failed")
                observation = self._put_artifact(
                    inputs,
                    exact_passage,
                    f"evidence-{evidence['id']}",
                )
                state.evidence.append(
                    self._record(
                        inputs,
                        "EvidenceRecord",
                        evidence["id"],
                        {
                            "planId": inputs.plan["metadata"]["id"],
                            "planDigest": inputs.plan["metadata"]["recordDigest"],
                            "sourceBundle": _binding(inputs.source_bundle),
                            "sourceEntryId": evidence["sourceEntryId"],
                            "observation": observation,
                            "provenanceDigest": source_entry["provenance"]["provenanceDigest"],
                            "trust": "P0",
                            "relation": evidence["relation"],
                            "claimIds": [item["id"]],
                        },
                    )
                )

    def _publish_verifications(
        self, inputs: SourceReviewInputs, state: _RunState, value: Mapping[str, Any]
    ) -> None:
        claim_by_id = {item["metadata"]["id"]: item for item in state.claims}
        evidence_by_id = {item["metadata"]["id"]: item for item in state.evidence}
        items = value["verifications"]
        if {item["claimId"] for item in items} != set(claim_by_id) or len(items) != len(claim_by_id):
            raise _Terminal("failed", "role-failed")
        for item in items:
            selected = []
            for evidence_id in item["evidenceIds"]:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None or item["claimId"] not in evidence["spec"]["claimIds"]:
                    raise _Terminal("failed", "role-failed")
                selected.append(evidence)
            if item["status"] == "verified" and not any(
                evidence["spec"]["relation"] == "supports" for evidence in selected
            ):
                raise _Terminal("failed", "role-failed")
            state.verifications.append(
                self._record(
                    inputs,
                    "VerificationRecord",
                    f"verification-{semantic_digest({'claim': item['claimId']})[:24]}",
                    {
                        "planId": inputs.plan["metadata"]["id"],
                        "planDigest": inputs.plan["metadata"]["recordDigest"],
                        "claim": _binding(claim_by_id[item["claimId"]]),
                        "verifiedByRole": "verifier",
                        "rubricDigest": inputs.plan["spec"]["gate"]["rubricDigest"],
                        "evidence": [_binding(item) for item in selected],
                        "status": item["status"],
                    },
                )
            )

    def _unsupported_claim_ids(self, state: _RunState) -> set[str]:
        return {
            item["spec"]["claim"]["id"]
            for item in state.verifications
            if item["spec"]["status"] != "verified"
        }

    def _semantic_synthesis(self, state: _RunState, value: Mapping[str, Any]) -> None:
        claim_ids = {item["metadata"]["id"] for item in state.claims}
        if set(value["claimIds"]) != claim_ids or set(value["unsupportedClaimIds"]) != self._unsupported_claim_ids(state):
            raise _Terminal("failed", "role-failed")

    def _semantic_reviewer(self, state: _RunState, value: Mapping[str, Any]) -> None:
        if set(value["reviewedClaimIds"]) != {
            item["metadata"]["id"] for item in state.claims
        }:
            raise _Terminal("failed", "role-failed")

    def _publish_review(
        self,
        inputs: SourceReviewInputs,
        state: _RunState,
        reviewer_attempt: Mapping[str, Any],
        subject: UntrustedArtifact,
        value: Mapping[str, Any],
        cycle: int,
    ) -> dict[str, Any]:
        findings = (
            self._put_artifact(
                inputs,
                canonical_json(value["findings"]).encode("utf-8"),
                f"review-findings-{cycle}",
            )
            if value["findings"]
            else None
        )
        review = self._record(
            inputs,
            "ReviewRecord",
            f"review-{cycle + 1}",
            {
                "planId": inputs.plan["metadata"]["id"],
                "planDigest": inputs.plan["metadata"]["recordDigest"],
                "subject": copy.deepcopy(dict(subject.binding)),
                "producerRole": "synthesizer",
                "reviewerRole": "reviewer",
                "reviewerAttempt": _binding(reviewer_attempt),
                "rubricDigest": inputs.plan["spec"]["gate"]["rubricDigest"],
                "cycle": cycle,
                "verdict": value["verdict"],
                "findings": findings,
            },
        )
        state.reviews.append(review)
        return review

    def _handoff(
        self,
        inputs: SourceReviewInputs,
        state: _RunState,
        ordinal: int,
        attempt_record: Mapping[str, Any],
        value: Mapping[str, Any],
    ) -> None:
        cycle, source, _, target, to_attempt = HANDOFF_SLOTS[ordinal - 1]
        output = attempt_record["spec"]["output"]
        open_questions = value.get("openQuestions", [])
        questions = (
            self._put_artifact(
                inputs,
                canonical_json(open_questions).encode("utf-8"),
                f"handoff-open-questions-{ordinal}",
            )
            if open_questions
            else None
        )
        state.handoffs.append(
            self._record(
                inputs,
                "HandoffRecord",
                f"handoff-{ordinal}",
                {
                    "planId": inputs.plan["metadata"]["id"],
                    "planDigest": inputs.plan["metadata"]["recordDigest"],
                    "ordinal": ordinal,
                    "cycle": cycle,
                    "fromRoleId": source,
                    "toRoleId": target,
                    "toAttempt": to_attempt,
                    "roleAttemptResult": _binding(attempt_record),
                    "status": "ready",
                    "artifacts": [copy.deepcopy(output)] if output is not None else [],
                    "claims": [_binding(item) for item in state.claims],
                    "evidence": [_binding(item) for item in state.evidence],
                    "verifications": [_binding(item) for item in state.verifications],
                    "uncertainty": value.get("uncertainty", "none"),
                    "openQuestions": questions,
                },
            )
        )

    def _finish(
        self,
        inputs: SourceReviewInputs,
        state: _RunState,
        status: str,
        reason_code: str,
        final_report: Mapping[str, Any] | None,
    ) -> SourceReviewExecution:
        event_type = {
            "succeeded": "run-succeeded",
            "incomplete": "run-incomplete",
            "failed": "run-failed",
            "denied": "run-denied",
            "exhausted": "run-exhausted",
            "cancelled": "run-cancelled",
        }[status]
        event = self._record(
            inputs,
            "OrchestrationEvent",
            "terminal-event",
            {
                "planId": inputs.plan["metadata"]["id"],
                "planDigest": inputs.plan["metadata"]["recordDigest"],
                "sequence": 1,
                "occurredAt": self._now(),
                "eventType": event_type,
                "subject": _binding(inputs.plan),
                "previousEventDigest": None,
                "reasonCode": reason_code,
            },
        )
        result = self._record(
            inputs,
            "TeamRunResult",
            "source-review-result",
            {
                "plan": _binding(inputs.plan),
                "request": _binding(inputs.request),
                "sourceBundle": _binding(inputs.source_bundle),
                "status": status,
                "reasonCode": reason_code,
                "finalReport": copy.deepcopy(dict(final_report)) if final_report is not None else None,
                "reviews": [_binding(item) for item in state.reviews],
                "claims": [_binding(item) for item in state.claims],
                "evidence": [_binding(item) for item in state.evidence],
                "verifications": [_binding(item) for item in state.verifications],
                "routeDecisions": [_binding(item) for item in state.used_routes],
                "roleAttempts": [_binding(item) for item in state.attempts],
                "handoffs": [_binding(item) for item in state.handoffs],
                "usage": state.usage(),
                "terminalEvent": _binding(event),
            },
        )
        records = (
            *inputs.base_records(),
            *state.attempts,
            *state.claims,
            *state.evidence,
            *state.verifications,
            *state.handoffs,
            *state.reviews,
            event,
            result,
        )
        try:
            validate_orchestration_record_set(list(records))
        except ContractValidationError as exc:
            raise SourceReviewError(
                "ECO_SOURCE_REVIEW_RESULT_INVALID", "Source review result graph is invalid"
            ) from exc
        return SourceReviewExecution(tuple(records), result)

    def _put_artifact(
        self, inputs: SourceReviewInputs, payload: bytes, label: str
    ) -> dict[str, Any]:
        del label
        proof = self._store.put(io.BytesIO(payload), max_bytes=len(payload))
        self._store.verify_availability(proof)
        return {
            "ref": proof.storage_ref,
            "contentDigest": proof.sha256,
            "byteLength": proof.byte_length,
            "dataClass": inputs.source_bundle["spec"]["dataClass"],
        }

    def _record(
        self,
        inputs: SourceReviewInputs,
        kind: str,
        identifier: str,
        spec: Mapping[str, Any],
    ) -> dict[str, Any]:
        value = {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": kind,
            "metadata": {
                "id": identifier,
                "projectId": inputs.plan["metadata"]["projectId"],
                "teamId": inputs.plan["metadata"]["teamId"],
                "runId": inputs.plan["metadata"]["runId"],
                "createdAt": self._now(),
                "recordDigest": "0" * 64,
            },
            "spec": copy.deepcopy(dict(spec)),
        }
        value["metadata"]["recordDigest"] = orchestration_record_digest(value)
        return validate_orchestration_record(value)

    def _now(self) -> str:
        return _utc(self._clock())
