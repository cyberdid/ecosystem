from __future__ import annotations

import copy
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from eco_orchestration.contracts import (
    ORCHESTRATION_API_VERSION,
    orchestration_record_digest,
    orchestration_route_digest,
    validate_orchestration_record,
)
from eco_orchestration.context import RoleExecution, RoleInvocation
from eco_orchestration.model_executor import (
    GovernedRoleCall,
    GovernedRoleExecutor,
    TypedEnvelopeBinding,
)
from eco_orchestration.profiles import (
    SOURCE_REVIEW_ROLES,
    install_source_review_definitions,
    load_packaged_role_profile,
    load_source_review_rubric,
)
from eco_orchestration.source_bundle import (
    SourceBundleLimits,
    ingest_source_bundle_manifest_file,
    load_source_bundle_manifest,
)
from eco_orchestration.source_review import (
    EXECUTION_SLOTS,
    SourceReviewInputs,
    SourceReviewWorkflow,
)
from eco_runtime.adapters import (
    ADAPTER_VERSION,
    LoopbackOpenAITypedHTTPInvoker,
    PinnedOpenAICompatibleDeployment,
    TypedOpenAICompatibleAdapter,
)
from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.contracts import API_VERSION
from eco_runtime.digests import deployment_identity_digest, semantic_digest
from eco_runtime.evidence import EvidenceTrustStore, TrustedEvidenceIngestor
from eco_runtime.errors import RuntimePolicyError, RuntimeStoreError
from eco_runtime.model_orchestrator import GovernedModelOrchestrator
from eco_runtime.orchestrator import RuntimeCapabilities
from eco_runtime.policy import PolicyEngine
from eco_runtime.store import SQLiteRuntimeStore
from eco_runtime.trust_diagnostics import _external_evidence, _issuer_policies
from eco_routing.consumption import DurableRouteConsumptionJournal, verify_route_binding
from eco_routing.errors import RoutingError


_ENV_NAME = re.compile(r"^ECO_[A-Z0-9_]{1,120}$")
_ROUTE_FILE_LIMIT_BYTES = 262_144
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ORCHESTRATION_IDENTIFIER = re.compile(
    r"^[a-z0-9](?:[a-z0-9._:-]{0,126}[a-z0-9])?$"
)
_SOURCE_LIMITS = SourceBundleLimits(
    maximum_file_bytes=1_048_576,
    maximum_source_count=64,
    maximum_total_bytes=4_000_000,
    maximum_manifest_bytes=262_144,
)
_MAX_OUTPUT_BYTES = 262_144
_MAX_OUTPUT_TOKENS = 32_768
_MAX_RUNTIME_INPUT_BYTES = 9_500_000
_MAX_RUNTIME_TOTAL_TOKENS = 10_000_000
_LOGICAL_ROLE = "review.private"


class SourceReviewCLIError(RuntimeError):
    """Stable, content-free CLI composition failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> SourceReviewCLIError:
    return SourceReviewCLIError(code, message)


def _parse_time(value: str, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise _fail("ECO_SOURCE_REVIEW_TIME_INVALID", f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _fail("ECO_SOURCE_REVIEW_TIME_INVALID", f"{field} is invalid") from exc
    if parsed.microsecond:
        raise _fail("ECO_SOURCE_REVIEW_TIME_INVALID", f"{field} is invalid")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identifier(value: str, *, orchestration: bool = False) -> str:
    pattern = _ORCHESTRATION_IDENTIFIER if orchestration else _IDENTIFIER
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail("ECO_SOURCE_REVIEW_IDENTIFIER_INVALID", "Run identity is invalid")
    return value


def _secret(name: str) -> bytes:
    if not isinstance(name, str) or _ENV_NAME.fullmatch(name) is None:
        raise _fail("ECO_SOURCE_REVIEW_SECRET_REFERENCE_INVALID", "Secret reference is invalid")
    value = os.environ.get(name)
    if value is None:
        raise _fail("ECO_SOURCE_REVIEW_SECRET_UNAVAILABLE", "Required secret is unavailable")
    if len(value) == 64 and re.fullmatch(r"[a-fA-F0-9]{64}", value):
        encoded = bytes.fromhex(value)
    else:
        encoded = value.encode("utf-8")
    if len(encoded) < 32:
        raise _fail("ECO_SOURCE_REVIEW_SECRET_INVALID", "Required secret is invalid")
    return encoded


def _load_route_records(
    route_decision_path: Path | None, route_request_path: Path | None
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if route_decision_path is None and route_request_path is None:
        return None
    if route_decision_path is None or route_request_path is None:
        raise _fail(
            "ECO_SOURCE_REVIEW_ROUTE_INVALID",
            "Route decision and request files are required together",
        )
    records: list[dict[str, Any]] = []
    for path in (route_decision_path, route_request_path):
        try:
            resolved = Path(path)
            if (
                not resolved.is_file()
                or resolved.is_symlink()
                or resolved.stat().st_size > _ROUTE_FILE_LIMIT_BYTES
            ):
                raise _fail(
                    "ECO_SOURCE_REVIEW_ROUTE_INVALID",
                    "Route evidence file is missing or exceeds the input limit",
                )
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except SourceReviewCLIError:
            raise
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise _fail(
                "ECO_SOURCE_REVIEW_ROUTE_INVALID", "Route evidence file is not bounded UTF-8 JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise _fail(
                "ECO_SOURCE_REVIEW_ROUTE_INVALID", "Route evidence file must contain one JSON object"
            )
        records.append(payload)
    return records[0], records[1]


def _outside_repository(path: Path, repository: Path, *, directory: bool) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise _fail("ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED", "Runtime state location is invalid")
    resolved = path.resolve(strict=False)
    root = repository.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError:
        pass
    else:
        raise _fail(
            "ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED",
            "Runtime state must remain outside the governed repository",
        )
    parent = resolved if directory and resolved.exists() else resolved.parent
    try:
        info = parent.resolve(strict=True).lstat()
    except OSError as exc:
        raise _fail("ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED", "Runtime state parent is invalid") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise _fail("ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED", "Runtime state parent is invalid")
    if os.name == "posix" and info.st_mode & 0o077:
        raise _fail("ECO_SOURCE_REVIEW_STATE_PERMISSIONS", "Runtime state parent is not private")
    if resolved.exists():
        current = resolved.lstat()
        expected = stat.S_ISDIR(current.st_mode) if directory else stat.S_ISREG(current.st_mode)
        if stat.S_ISLNK(current.st_mode) or not expected:
            raise _fail("ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED", "Runtime state location is invalid")
    return resolved


def _binding(record: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": record["kind"],
        "id": record["metadata"]["id"],
        "digest": record["metadata"]["recordDigest"],
    }


def _metadata(identifier: str, context: "CompositionContext") -> dict[str, Any]:
    return {
        "id": identifier,
        "projectId": context.project_id,
        "teamId": context.team_id,
        "runId": context.run_id,
        "createdAt": context.created_at_text,
        "recordDigest": "0" * 64,
    }


def _seal(kind: str, identifier: str, spec: Mapping[str, Any], context: "CompositionContext") -> dict[str, Any]:
    record = {
        "apiVersion": ORCHESTRATION_API_VERSION,
        "kind": kind,
        "metadata": _metadata(identifier, context),
        "spec": copy.deepcopy(dict(spec)),
    }
    record["metadata"]["recordDigest"] = orchestration_record_digest(record)
    return validate_orchestration_record(record)


@dataclass(frozen=True)
class VerifiedDeployment:
    deployment: dict[str, Any]
    endpoint_url: str
    observation_envelope: bytes
    observation: dict[str, Any]
    evidence_policies: tuple[Any, ...]
    trusted_suite_digests: frozenset[str]
    authority_valid_until: datetime


@dataclass(frozen=True)
class CompositionContext:
    repository: Path
    bundle: dict[str, dict[str, Any]]
    project_id: str
    team_id: str
    run_id: str
    store_id: str
    data_class: str
    created_at: datetime
    deadline_at: datetime
    verified: VerifiedDeployment
    capabilities: RuntimeCapabilities
    runtime_store: SQLiteRuntimeStore
    artifact_store: ContentAddressedArtifactStore

    @property
    def created_at_text(self) -> str:
        return _utc(self.created_at)

    @property
    def deadline_at_text(self) -> str:
        return _utc(self.deadline_at)

    @property
    def route_valid_until(self) -> datetime:
        return min(self.deadline_at, self.verified.authority_valid_until)


def _verify_deployment(
    repository: Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime,
) -> VerifiedDeployment:
    deployments = bundle["deployments"].get("deployments", [])
    enabled = [item for item in deployments if isinstance(item, dict) and item.get("enabled") is True]
    if len(enabled) != 1:
        raise _fail(
            "ECO_SOURCE_REVIEW_DEPLOYMENT_COUNT",
            "Exactly one enabled deployment is required",
        )
    deployment = copy.deepcopy(enabled[0])
    if (
        deployment.get("provider") != "local"
        or deployment.get("adapter") != "openai-compatible"
        or deployment.get("identity", {}).get("adapterVersion") != ADAPTER_VERSION
        or not {"model.text", "model.structured-output"}.issubset(
            set(deployment.get("declaredCapabilities", []))
        )
        or deployment.get("trainingUse") != "prohibited"
        or deployment.get("region") != "local"
    ):
        raise _fail("ECO_SOURCE_REVIEW_DEPLOYMENT_INVALID", "Local deployment is not eligible")
    try:
        deployment_identity_digest(deployment)
    except RuntimePolicyError as exc:
        raise _fail(exc.code, "Local deployment identity is invalid") from exc

    role = bundle["deployments"].get("logicalRoles", {}).get(_LOGICAL_ROLE)
    if (
        not isinstance(role, dict)
        or role.get("candidates") != [deployment["id"]]
        or not {"model.text", "model.structured-output"}.issubset(
            set(role.get("requiredCapabilities", []))
        )
        or role.get("maximumActionClass") != "A0"
        or role.get("minimumArtifactTrust") not in {"P0", "P1"}
    ):
        raise _fail("ECO_SOURCE_REVIEW_ROLE_INVALID", "Private review role is not exactly configured")

    endpoint_ref = deployment.get("endpointRef")
    if not isinstance(endpoint_ref, str) or not endpoint_ref.startswith("env:"):
        raise _fail("ECO_SOURCE_REVIEW_ENDPOINT_REFERENCE_INVALID", "Endpoint reference is invalid")
    endpoint_name = endpoint_ref[4:]
    if _ENV_NAME.fullmatch(endpoint_name) is None or not os.environ.get(endpoint_name):
        raise _fail("ECO_SOURCE_REVIEW_ENDPOINT_UNAVAILABLE", "Local endpoint is unavailable")
    endpoint_url = os.environ[endpoint_name]

    trust = bundle.get("trust")
    if not isinstance(trust, dict):
        raise _fail("ECO_SOURCE_REVIEW_EVIDENCE_CONFIG_INVALID", "Evidence configuration is invalid")
    policies = _issuer_policies(trust)
    conformance = trust.get("conformance", {})
    observations = [
        item
        for item in conformance.get("requiredObservations", [])
        if item.get("deploymentId") == deployment["id"]
    ] if isinstance(conformance, dict) else []
    if len(observations) != 1:
        raise _fail("ECO_SOURCE_REVIEW_EVIDENCE_MISSING", "Deployment evidence is missing")
    observation_spec = observations[0]
    suite_digest = observation_spec.get("suiteDigest")
    trusted_suites = {
        item.get("digest")
        for item in conformance.get("trustedSuites", [])
        if isinstance(item, dict)
    }
    if suite_digest not in trusted_suites:
        raise _fail("ECO_SOURCE_REVIEW_EVIDENCE_UNTRUSTED", "Deployment suite is not trusted")
    envelope = _external_evidence(observation_spec.get("envelopeRef"), repository_root=repository)
    verified = TrustedEvidenceIngestor(EvidenceTrustStore(policies)).ingest_observed_capabilities(
        envelope,
        expected_deployment_id=deployment["id"],
        expected_deployment_identity_digest=deployment_identity_digest(deployment),
        trusted_suite_digests={suite_digest},
        now=now,
    )
    observation = verified.as_dict()
    try:
        observation_valid_until = datetime.fromisoformat(
            observation["metadata"]["validUntil"].replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        envelope_valid_until = datetime.fromisoformat(
            verified.provenance.expires_at.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError) as exc:
        raise _fail("ECO_SOURCE_REVIEW_EVIDENCE_UNTRUSTED", "Evidence lifetime is invalid") from exc
    authority_valid_until = min(observation_valid_until, envelope_valid_until)
    if authority_valid_until <= now:
        raise _fail("ECO_SOURCE_REVIEW_EVIDENCE_STALE", "Deployment evidence is stale")
    required = {"model.text", "model.structured-output"}
    probes = {item.get("id"): item for item in observation["spec"].get("probes", [])}
    if (
        observation["spec"].get("status") != "pass"
        or not required.issubset(set(observation["spec"].get("effectiveCapabilities", [])))
        or any(
            probes.get(probe, {}).get("status") != "pass"
            or probes.get(probe, {}).get("successes", 0) < 1
            for probe in ("text-basic", "structured-output-strict")
        )
    ):
        raise _fail("ECO_SOURCE_REVIEW_CAPABILITY_UNVERIFIED", "Structured output is not verified")
    # Constructor performs the concrete literal-loopback endpoint check without
    # egress and binds its preflight lifetime to signed evidence authority.
    PinnedOpenAICompatibleDeployment(
        deployment,
        endpoint_url=endpoint_url,
        transport_profile="local-loopback-http",
        resolved_at=now,
        valid_until=authority_valid_until,
    )
    return VerifiedDeployment(
        deployment=deployment,
        endpoint_url=endpoint_url,
        observation_envelope=envelope,
        observation=observation,
        evidence_policies=policies,
        trusted_suite_digests=frozenset({suite_digest}),
        authority_valid_until=authority_valid_until,
    )


def _aggregate_budget(context: CompositionContext) -> dict[str, int]:
    duration = int((context.deadline_at - context.created_at).total_seconds())
    return {
        "maxDurationSeconds": duration,
        "maxAttempts": 7,
        "maxModelRequests": 7,
        "maxInputBytes": 70_000_000,
        "maxOutputBytes": 7 * _MAX_OUTPUT_BYTES,
        "maxTotalTokens": 70_000_000,
        "maxCostMicrousd": 0,
    }


def _step_budget(context: CompositionContext) -> dict[str, int]:
    duration = min(int((context.deadline_at - context.created_at).total_seconds()), 3_600)
    return {
        "maxDurationSeconds": duration,
        "maxAttempts": 2,
        "maxModelRequests": 2,
        "maxInputBytes": _MAX_RUNTIME_INPUT_BYTES,
        "maxOutputBytes": _MAX_OUTPUT_BYTES,
        "maxTotalTokens": _MAX_RUNTIME_TOTAL_TOKENS,
        "maxCostMicrousd": 0,
    }


def _build_orchestration_inputs(
    context: CompositionContext,
    source_bundle: dict[str, Any],
) -> SourceReviewInputs:
    aggregate = _aggregate_budget(context)
    definitions = install_source_review_definitions(
        context.artifact_store,
        project_id=context.project_id,
        team_id=context.team_id,
        created_at=context.created_at_text,
        budget=aggregate,
    )
    request = _seal(
        "TeamRunRequest",
        f"request-{context.run_id}",
        {
            "workflow": "source-review",
            "sourceBundle": _binding(source_bundle),
            "teamManifest": _binding(definitions.team_manifest),
            "loopDefinition": _binding(definitions.loop_definition),
            "requestedRoles": list(SOURCE_REVIEW_ROLES),
            "policySnapshotDigest": semantic_digest(context.bundle),
            "budget": aggregate,
            "deadlineAt": context.deadline_at_text,
        },
        context,
    )
    target = PinnedOpenAICompatibleDeployment(
        context.verified.deployment,
        endpoint_url=context.verified.endpoint_url,
        transport_profile="local-loopback-http",
        resolved_at=context.created_at,
        valid_until=context.route_valid_until,
    )
    routes: list[dict[str, Any]] = []
    for role_id, attempt in EXECUTION_SLOTS:
        route = {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": "RouteDecision",
            "metadata": _metadata(f"route-{role_id}-{attempt}", context),
            "spec": {
                "planId": f"plan-{context.run_id}",
                "planDigest": "0" * 64,
                "roleId": role_id,
                "attempt": attempt,
                "routeDigest": "0" * 64,
                "decision": "allowed",
                "reasonCode": "eligible",
                "deployment": {
                    "id": target.deployment_id,
                    "digest": semantic_digest(context.verified.deployment),
                    "endpointBindingDigest": target.endpoint_binding_digest,
                    "capabilityEvidenceDigest": semantic_digest(context.verified.observation),
                },
                "validUntil": _utc(context.route_valid_until),
                "fallbackPolicy": "none",
            },
        }
        route["spec"]["routeDigest"] = orchestration_route_digest(route)
        routes.append(route)
    profile_by_role = {item["spec"]["roleId"]: item for item in definitions.profiles}
    steps = []
    for ordinal, role_id in enumerate(SOURCE_REVIEW_ROLES, start=1):
        selected = [item for item in routes if item["spec"]["roleId"] == role_id]
        steps.append(
            {
                "ordinal": ordinal,
                "roleId": role_id,
                "profile": _binding(profile_by_role[role_id]),
                "predecessors": [] if ordinal == 1 else [SOURCE_REVIEW_ROLES[ordinal - 2]],
                "childPlanDigest": semantic_digest(
                    {"domain": "eco-source-review-child-plan-commitment-v1", "runId": context.run_id, "roleId": role_id}
                ),
                "routes": [
                    {
                        "attempt": item["spec"]["attempt"],
                        "decisionId": item["metadata"]["id"],
                        "routeDigest": item["spec"]["routeDigest"],
                    }
                    for item in selected
                ],
                "budget": _step_budget(context),
            }
        )
    plan = _seal(
        "TeamRunPlan",
        f"plan-{context.run_id}",
        {
            "request": _binding(request),
            "sourceBundle": _binding(source_bundle),
            "teamManifest": _binding(definitions.team_manifest),
            "loopDefinition": _binding(definitions.loop_definition),
            "policySnapshotDigest": semantic_digest(context.bundle),
            "deadlineAt": context.deadline_at_text,
            "aggregateBudget": aggregate,
            "steps": steps,
            "gate": {
                "owner": "runtime",
                "reviewRole": "reviewer",
                "rubricDigest": definitions.team_manifest["spec"]["gate"]["rubric"]["contentDigest"],
                "maxRevisionCycles": 1,
            },
        },
        context,
    )
    for route in routes:
        route["spec"]["planDigest"] = plan["metadata"]["recordDigest"]
        route["metadata"]["recordDigest"] = orchestration_record_digest(route)
        validate_orchestration_record(route)
    return SourceReviewInputs(definitions, source_bundle, request, plan, tuple(routes))


class _DynamicGovernedExecutor:
    """Construct one exact policy engine and governed bridge for every role slot."""

    def __init__(self, context: CompositionContext) -> None:
        self._context = context

    def execute(self, invocation: RoleInvocation) -> RoleExecution:
        from eco_orchestration.model_executor import canonical_role_input_envelope

        envelope_bytes = canonical_role_input_envelope(invocation)
        envelope_digest = __import__("hashlib").sha256(envelope_bytes).hexdigest()
        child = semantic_digest(
            {"domain": "eco-source-review-runtime-child-v1", "runId": self._context.run_id, "role": invocation.role_id, "attempt": invocation.attempt}
        )[:32]
        runtime_run_id = f"sr-{child}"
        request_id = f"model:{invocation.role_id}:{invocation.attempt}:{child}"
        artifact = {
            "apiVersion": API_VERSION,
            "kind": "ArtifactRecord",
            "metadata": {
                "id": f"input-{child}",
                "runId": runtime_run_id,
                "createdAt": self._context.created_at_text,
            },
            "spec": {
                "role": "input",
                "mediaType": "application/json",
                "byteLength": len(envelope_bytes),
                "sha256": envelope_digest,
                "dataClass": self._context.data_class,
                "trust": "P1",
                "producer": {"type": "runtime", "id": "source-review-composer-v1"},
                "parentRefs": [],
                "storageRef": f"artifact://runs/{runtime_run_id}/input",
                "retention": "run",
            },
        }
        if len(envelope_bytes) > _MAX_RUNTIME_INPUT_BYTES or len(envelope_bytes) + _MAX_OUTPUT_TOKENS > _MAX_RUNTIME_TOTAL_TOKENS:
            raise _fail("ECO_SOURCE_REVIEW_INPUT_LIMIT", "Typed role input exceeds the runtime limit")
        engine = PolicyEngine(
            self._context.bundle,
            {self._context.verified.deployment["id"]: self._context.verified.observation_envelope},
            {artifact["spec"]["storageRef"]: artifact},
            evidence_policies=self._context.verified.evidence_policies,
            evidence_now=self._context.created_at,
            trusted_suite_digests=set(self._context.verified.trusted_suite_digests),
            decision_ttl_seconds=3_600,
        )
        runtime_budget = {
            "maxDurationSeconds": min(int((self._context.deadline_at - self._context.created_at).total_seconds()), 3_600),
            "maxModelRequests": 1,
            "maxToolRequests": 0,
            "maxInputBytes": len(envelope_bytes),
            "maxOutputBytes": _MAX_OUTPUT_BYTES,
            "maxTotalTokens": len(envelope_bytes) + _MAX_OUTPUT_TOKENS,
            "maxCostMicrousd": 0,
        }
        run_request = {
            "apiVersion": API_VERSION,
            "kind": "RunRequest",
            "metadata": {
                "id": f"run-request-{child}",
                "createdAt": self._context.created_at_text,
                "actor": {"type": "human", "id": "source-review-operator"},
            },
            "spec": {
                "projectId": self._context.project_id,
                "logicalRole": _LOGICAL_ROLE,
                "dataClass": artifact["spec"]["dataClass"],
                "classificationAuthority": "operator",
                "deploymentPin": self._context.verified.deployment["id"],
                "task": {
                    "type": "source.review",
                    "instructionRef": artifact["spec"]["storageRef"],
                    "inputRefs": [],
                },
                "requestedTools": [],
                "constraints": {
                    "maximumActionClass": "A0",
                    "sandbox": "inspect",
                    "agentNetwork": "deny",
                    "toolNetwork": "deny",
                },
                "budget": runtime_budget,
                "fallbackPolicy": "none",
            },
        }
        planned = engine.plan_run(
            run_request,
            run_id=runtime_run_id,
            plan_id=f"run-plan-{child}",
            decision_id=f"plan-decision-{child}",
            now=self._context.created_at,
        )
        if planned.plan is None or planned.decision["spec"]["effect"] != "allow":
            raise _fail(planned.decision["spec"]["reasonCodes"][0], "Role plan was denied")
        plan = planned.plan
        engine.activate_plan(plan, planned.decision, now=self._context.created_at)
        target = PinnedOpenAICompatibleDeployment(
            self._context.verified.deployment,
            endpoint_url=self._context.verified.endpoint_url,
            transport_profile="local-loopback-http",
            resolved_at=self._context.created_at,
            valid_until=self._context.route_valid_until,
        )
        endpoint = target.endpoint_binding()
        model_request = {
            "apiVersion": API_VERSION,
            "kind": "ModelRequest",
            "metadata": {
                "id": request_id,
                "runId": runtime_run_id,
                "createdAt": self._context.created_at_text,
            },
            "spec": {
                "planDigest": semantic_digest(plan),
                "deploymentId": target.deployment_id,
                "deploymentIdentityDigest": target.identity_digest,
                "endpointBindingDigest": target.endpoint_binding_digest,
                "input": {
                    "artifactRecordDigest": semantic_digest(artifact),
                    "contentDigest": envelope_digest,
                    "byteLength": len(envelope_bytes),
                    "dataClass": artifact["spec"]["dataClass"],
                    "trust": artifact["spec"]["trust"],
                },
                "parameters": {
                    "maxOutputTokens": _MAX_OUTPUT_TOKENS,
                    "maxOutputBytes": _MAX_OUTPUT_BYTES,
                    "temperatureMillis": 0,
                },
                "timeoutMs": min(runtime_budget["maxDurationSeconds"] * 1000, 120_000),
                "fallbackPolicy": "none",
            },
        }
        model_decision = engine.authorize_model(
            plan,
            model_request,
            endpoint,
            artifact,
            decision_id=f"model-decision-{child}",
            now=self._context.created_at,
        )
        if model_decision["spec"]["effect"] != "allow":
            raise _fail(model_decision["spec"]["reasonCodes"][0], "Model call was denied")
        self._initialize_store(plan, planned.decision)
        orchestrator = GovernedModelOrchestrator(
            self._context.runtime_store,
            self._context.artifact_store,
            engine,
            TypedOpenAICompatibleAdapter(
                target,
                LoopbackOpenAITypedHTTPInvoker(maximum_response_bytes=524_288),
            ),
            capabilities=self._context.capabilities,
        )
        call = GovernedRoleCall(
            plan=plan,
            request=model_request,
            endpoint_binding=endpoint,
            input_artifact=artifact,
            decision=model_decision,
            idempotency_key=(
                f"source-review:{self._context.store_id}:{self._context.run_id}:"
                f"{invocation.role_id}:{invocation.attempt}"
            ),
            cost_reservation_microusd=0,
            now=self._context.created_at,
        )

        class Resolver:
            def resolve(inner_self, role_id: str, attempt: int, envelope: TypedEnvelopeBinding) -> GovernedRoleCall:
                if (
                    role_id != invocation.role_id
                    or attempt != invocation.attempt
                    or envelope.content_digest != envelope_digest
                    or envelope.byte_length != len(envelope_bytes)
                ):
                    raise RuntimeStoreError("ECO_MODEL_ROUTE_MISMATCH", "Role route is not exact")
                return call

        try:
            result = GovernedRoleExecutor(
                orchestrator,
                self._context.artifact_store,
                Resolver(),
            ).execute(invocation)
        except Exception:
            self._settle_child(runtime_run_id, succeeded=False)
            raise
        self._settle_child(runtime_run_id, succeeded=True)
        return result

    def _settle_child(self, run_id: str, *, succeeded: bool) -> None:
        store = self._context.runtime_store
        capabilities = self._context.capabilities
        now = datetime.now(timezone.utc)
        status = store.run_status(run_id)["state"]
        if status != "RUNNING":
            return
        if succeeded:
            store.complete_adapter(
                run_id, now=now, adapter_capability=capabilities.adapter
            )
            store.finish_run(
                run_id,
                outcome="succeeded",
                now=now,
                runtime_capability=capabilities.runtime,
            )
        else:
            store.fail_adapter(
                run_id, now=now, adapter_capability=capabilities.adapter
            )
            store.finish_run(
                run_id,
                outcome="failed",
                now=now,
                runtime_capability=capabilities.runtime,
            )

    def _initialize_store(self, plan: dict[str, Any], decision: dict[str, Any]) -> None:
        store = self._context.runtime_store
        capabilities = self._context.capabilities
        try:
            status = store.run_status(plan["metadata"]["runId"])
        except RuntimeStoreError as exc:
            if exc.code != "ECO_RUN_UNKNOWN":
                raise
            store.issue_plan(plan, decision, policy_capability=capabilities.policy)
            store.activate_plan(
                plan,
                decision,
                nonce=f"activate:{plan['metadata']['id']}",
                now=self._context.created_at,
                policy_capability=capabilities.policy,
            )
            status = store.run_status(plan["metadata"]["runId"])
        if status["state"] == "AUTHORIZED":
            store.start_adapter(
                plan["metadata"]["runId"],
                now=self._context.created_at,
                adapter_capability=capabilities.adapter,
            )
        elif status["state"] not in {
            "RUNNING", "SUCCEEDED", "FAILED", "DENIED", "CANCELLED", "EXHAUSTED"
        }:
            raise _fail("ECO_SOURCE_REVIEW_RUNTIME_STATE", "Role runtime is not resumable")


def preflight_source_review(
    repository: Path,
    bundle: dict[str, dict[str, Any]],
    *,
    manifest_path: str,
    database_path: Path,
    artifact_store_path: Path,
    hmac_env: str,
    proof_env: str,
    team_id: str,
    run_id: str,
    created_at: str,
    deadline_at: str,
    route_decision_path: Path | None = None,
    route_request_path: Path | None = None,
) -> dict[str, Any]:
    repository = repository.resolve(strict=True)
    _identifier(team_id, orchestration=True)
    _identifier(run_id, orchestration=True)
    if len(run_id) > 96:
        raise _fail("ECO_SOURCE_REVIEW_IDENTIFIER_INVALID", "Run identity is too long")
    created = _parse_time(created_at, field="created-at")
    deadline = _parse_time(deadline_at, field="deadline-at")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    duration = int((deadline - created).total_seconds())
    created_age = (now - created).total_seconds()
    if (
        duration < 1
        or duration > 3_600
        or deadline <= now
        or created_age < -300
        or created_age > 300
    ):
        raise _fail("ECO_SOURCE_REVIEW_TIME_INVALID", "Run time window is invalid")
    database = _outside_repository(database_path, repository, directory=False)
    artifacts = _outside_repository(artifact_store_path, repository, directory=True)
    try:
        database.relative_to(artifacts)
    except ValueError:
        pass
    else:
        raise _fail("ECO_SOURCE_REVIEW_STATE_LOCATION_DENIED", "Runtime stores must not overlap")
    _secret(hmac_env)
    _secret(proof_env)
    if not isinstance(manifest_path, str) or Path(manifest_path).is_absolute():
        raise _fail("ECO_SOURCE_MANIFEST_INVALID", "Manifest path must be repository-relative")
    manifest = load_source_bundle_manifest(repository, manifest_path, limits=_SOURCE_LIMITS)
    verified = _verify_deployment(repository, bundle, now=now)
    if deadline > verified.authority_valid_until:
        raise _fail(
            "ECO_SOURCE_REVIEW_EVIDENCE_WINDOW",
            "Run deadline exceeds signed deployment authority",
        )
    role = bundle["deployments"]["logicalRoles"][_LOGICAL_ROLE]
    if (
        manifest.data_class not in verified.deployment["allowedDataClasses"]
        or manifest.data_class not in role["allowedDataClasses"]
    ):
        raise _fail("ECO_DATA_CLASS_DENIED", "Source data class is not eligible")
    for role_id in SOURCE_REVIEW_ROLES:
        load_packaged_role_profile(role_id)
    load_source_review_rubric()
    route_records = _load_route_records(route_decision_path, route_request_path)
    route_decision_digest = None
    if route_records is not None:
        try:
            verified_decision, _verified_request = verify_route_binding(
                route_records[0],
                route_records[1],
                expected_deployment_id=verified.deployment["id"],
                expected_deployment_identity_digest=deployment_identity_digest(
                    verified.deployment
                ),
                now=now,
            )
        except RoutingError as exc:
            raise _fail(exc.code, "Route evidence is not acceptable") from exc
        route_decision_digest = verified_decision["metadata"]["recordDigest"]
    return {
        "available": True,
        "operation": "team-run-source-review-check",
        "status": "ready",
        "code": "ECO_SOURCE_REVIEW_READY",
        "projectId": bundle["project"]["metadata"]["name"],
        "teamId": team_id,
        "runId": run_id,
        "deploymentId": verified.deployment["id"],
        "routeDecisionDigest": route_decision_digest,
        "sourceCount": len(manifest.sources),
        "safety": {
            "credentials": "none",
            "network": "literal-loopback-model-only",
            "redirects": "denied",
            "proxies": "denied",
            "tools": "denied",
            "workspaceWrites": "denied",
            "repositoryMutation": False,
            "contentEmitted": False,
        },
    }


def run_source_review(
    repository: Path,
    bundle: dict[str, dict[str, Any]],
    *,
    manifest_path: str,
    database_path: Path,
    artifact_store_path: Path,
    hmac_env: str,
    proof_env: str,
    team_id: str,
    run_id: str,
    created_at: str,
    deadline_at: str,
    store_id: str,
    route_decision_path: Path | None = None,
    route_request_path: Path | None = None,
) -> dict[str, Any]:
    _identifier(store_id)
    preflight_source_review(
        repository,
        bundle,
        manifest_path=manifest_path,
        database_path=database_path,
        artifact_store_path=artifact_store_path,
        hmac_env=hmac_env,
        proof_env=proof_env,
        team_id=team_id,
        run_id=run_id,
        created_at=created_at,
        deadline_at=deadline_at,
        route_decision_path=route_decision_path,
        route_request_path=route_request_path,
    )
    created = _parse_time(created_at, field="created-at")
    deadline = _parse_time(deadline_at, field="deadline-at")
    repository = repository.resolve(strict=True)
    database = database_path.resolve(strict=False)
    artifact_root = artifact_store_path.resolve(strict=False)
    project_id = bundle["project"]["metadata"]["name"]
    verified = _verify_deployment(repository, bundle, now=datetime.now(timezone.utc))
    capabilities = RuntimeCapabilities(object(), object(), object(), object())
    proof_key = _secret(proof_env)
    hmac_key = _secret(hmac_env)
    route_records = _load_route_records(route_decision_path, route_request_path)
    route_receipt: dict[str, Any] | None = None
    if route_records is not None:
        route_journal_path = database.parent / (database.name + ".routes")
        consumer_digest = semantic_digest(
            {
                "domain": "eco-source-review-route-consumer-v1",
                "storeId": store_id,
                "teamId": team_id,
                "runId": run_id,
            }
        )
        try:
            with DurableRouteConsumptionJournal(
                route_journal_path,
                hmac_key=hmac_key,
                key_id="source-review-route-v1",
            ) as route_journal:
                route_receipt = route_journal.consume(
                    route_records[0],
                    route_records[1],
                    expected_deployment_id=verified.deployment["id"],
                    expected_deployment_identity_digest=deployment_identity_digest(
                        verified.deployment
                    ),
                    consumer_kind="source-review",
                    consumer_id=run_id,
                    consumer_digest=consumer_digest,
                    now=datetime.now(timezone.utc),
                )
        except RoutingError as exc:
            raise _fail(exc.code, "Route evidence is not acceptable") from exc
    with ContentAddressedArtifactStore(
        artifact_root,
        proof_key=proof_key,
        key_id="source-review-proof-v1",
        forbidden_root=repository,
    ) as artifacts:
        with SQLiteRuntimeStore(
            database,
            hmac_key=hmac_key,
            key_id="source-review-runtime-v1",
            policy_capability=capabilities.policy,
            broker_capability=capabilities.broker,
            runtime_capability=capabilities.runtime,
            adapter_capability=capabilities.adapter,
            producer_issuers={
                "runtime": "source-review-runtime-v1",
                "policy": "source-review-policy-v1",
                "broker": "source-review-broker-v1",
                "adapter": "source-review-adapter-v1",
            },
            forbidden_root=repository,
            artifact_store=artifacts,
            path_hmac_key=hmac_key,
        ) as runtime_store:
            source_bundle = ingest_source_bundle_manifest_file(
                repository,
                manifest_path,
                artifacts,
                project_id=project_id,
                team_id=team_id,
                run_id=run_id,
                created_at=_utc(created),
                limits=_SOURCE_LIMITS,
            )
            context = CompositionContext(
                repository=repository,
                bundle=copy.deepcopy(bundle),
                project_id=project_id,
                team_id=team_id,
                run_id=run_id,
                store_id=store_id,
                data_class=source_bundle["spec"]["dataClass"],
                created_at=created,
                deadline_at=deadline,
                verified=verified,
                capabilities=capabilities,
                runtime_store=runtime_store,
                artifact_store=artifacts,
            )
            inputs = _build_orchestration_inputs(context, source_bundle)
            execution = SourceReviewWorkflow(
                artifacts,
                _DynamicGovernedExecutor(context),
            ).run(inputs)
            runtime_store.verify()
    result = execution.result
    return {
        "available": result["spec"]["status"] == "succeeded",
        "operation": "team-run-source-review",
        "status": result["spec"]["status"],
        "code": result["spec"]["reasonCode"],
        "runId": run_id,
        "result": result,
        "reportArtifact": result["spec"]["finalReport"],
        "replayed": execution.replayed,
        "routeConsumption": route_receipt,
        "safety": {
            "contentEmitted": False,
            "providerCalls": "durably-fenced",
            "tools": "denied",
            "workspaceWrites": "denied",
            "network": "literal-loopback-model-only",
        },
    }


__all__ = [
    "SourceReviewCLIError",
    "preflight_source_review",
    "run_source_review",
]
