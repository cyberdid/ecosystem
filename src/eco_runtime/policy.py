from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from importlib import resources

from jsonschema import Draft202012Validator
from eco_cli.constants import SCHEMA_FILES
from .contracts import (
    API_VERSION,
    CONTRACT_PROFILE,
    TOOL_ARGUMENT_SCHEMAS,
    schema_bundle_digest,
    tool_argument_errors,
    validate_record,
)
from .budget import BudgetLedger
from .digests import DIGEST_PROFILE, deployment_identity_digest, semantic_digest
from .errors import ContractValidationError, RuntimePolicyError
from .evidence import (
    EvidenceIssuerPolicy,
    EvidenceProvenance,
    EvidenceTrustStore,
    TrustedEvidenceIngestor,
)
from .repository import protected_repository_path, repository_snapshot_entries

ACTION_ORDER = {f"A{level}": level for level in range(5)}
DATA_ORDER = {f"D{level}": level for level in range(5)}
TRUST_ORDER = {f"P{level}": level for level in range(5)}
ARGUMENT_CONTRACTS = {
    "repository.read": "eco://tools/repository-read/v1alpha1",
}
POLICY_ENGINE_VERSION = "0.1.0"


@dataclass(frozen=True)
class PlanningResult:
    plan: dict[str, Any] | None
    decision: dict[str, Any]


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise RuntimePolicyError("ECO_CLOCK_INVALID", "Runtime clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError) as exc:
        raise RuntimePolicyError("ECO_TIME_INVALID", "Runtime timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise RuntimePolicyError("ECO_TIME_INVALID", "Runtime timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


class PolicyEngine:
    """Pure, default-deny M2 planner and tool policy evaluator.

    The engine performs no network, filesystem, credential, audit, or model operation.
    """

    def __init__(
        self,
        bundle: dict[str, dict[str, Any]],
        observations: dict[str, bytes],
        artifacts: dict[str, dict[str, Any]] | None = None,
        *,
        repository_snapshot: bytes | None = None,
        evidence_policies: tuple[EvidenceIssuerPolicy, ...] | None = None,
        evidence_now: datetime | None = None,
        repository_root_identity_digest: str | None = None,
        trusted_suite_digests: set[str] | None = None,
        decision_ttl_seconds: int = 300,
        maximum_snapshot_age_seconds: int = 3600,
        maximum_observation_age_seconds: int = 2_764_800,
        maximum_clock_skew_seconds: int = 300,
    ) -> None:
        required = {"project", "capabilities", "deployments", "tools", "instructions"}
        if required - set(bundle):
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "Canonical bundle is incomplete")
        policy = bundle["project"].get("policy", {})
        if policy.get("defaultDecision") != "deny" or policy.get("allowDirectEgress") is not False:
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "M2 requires default deny and no direct egress")
        if decision_ttl_seconds < 1 or decision_ttl_seconds > 3600:
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "Decision TTL is outside the M2 boundary")
        if (
            maximum_snapshot_age_seconds < 1
            or maximum_observation_age_seconds < 1
            or maximum_clock_skew_seconds < 0
        ):
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "Runtime time bounds are invalid")

        self._bundle = copy.deepcopy(bundle)
        self._observations: dict[str, dict[str, Any]] = {}
        self._observation_provenance: dict[str, EvidenceProvenance] = {}
        self._artifacts = copy.deepcopy(artifacts or {})
        self._repository_snapshot: dict[str, Any] | None = None
        self._repository_snapshot_provenance: EvidenceProvenance | None = None
        self._encoded_observations = copy.deepcopy(observations)
        self._encoded_repository_snapshot = repository_snapshot
        if evidence_policies is not None and (
            not isinstance(evidence_policies, tuple)
            or not evidence_policies
            or any(type(policy) is not EvidenceIssuerPolicy for policy in evidence_policies)
        ):
            raise RuntimePolicyError("ECO_EVIDENCE_UNTRUSTED", "Evidence trust policy is invalid")
        self._evidence_ingestor = (
            TrustedEvidenceIngestor(
                EvidenceTrustStore(evidence_policies),
                maximum_snapshot_age_seconds=maximum_snapshot_age_seconds,
                maximum_observation_age_seconds=maximum_observation_age_seconds,
                maximum_clock_skew_seconds=maximum_clock_skew_seconds,
            )
            if evidence_policies is not None
            else None
        )
        self._repository_root_identity_digest = repository_root_identity_digest
        self._trusted_suite_digests = frozenset(trusted_suite_digests or set())
        self._config_digest = semantic_digest(self._bundle)
        self._schema_bundle_digest = schema_bundle_digest()
        self._source_digests = {
            name: semantic_digest(self._bundle[name]) for name in sorted(required)
        }
        self._decision_ttl_seconds = decision_ttl_seconds
        self._maximum_snapshot_age_seconds = maximum_snapshot_age_seconds
        self._maximum_observation_age_seconds = maximum_observation_age_seconds
        self._maximum_clock_skew_seconds = maximum_clock_skew_seconds
        self._lock = threading.Lock()
        self._issued_decisions: dict[str, dict[str, Any]] = {}
        self._issued_plans: dict[str, str] = {}
        self._active_plans: dict[str, str] = {}
        self._budget_ledgers: dict[str, BudgetLedger] = {}

        self._validate_canonical_schemas()
        self._deployments = self._unique_map(
            self._bundle["deployments"].get("deployments", []), "ECO_CONFIG_INVALID"
        )
        self._tools = self._unique_map(self._bundle["tools"].get("tools", []), "ECO_CONFIG_INVALID")
        self._capabilities = self._unique_map(
            self._bundle["capabilities"].get("capabilities", []), "ECO_CONFIG_INVALID"
        )
        self._validate_canonical_snapshot()
        if observations or repository_snapshot is not None:
            if self._evidence_ingestor is None or evidence_now is None:
                raise RuntimePolicyError(
                    "ECO_EVIDENCE_UNTRUSTED",
                    "Signed evidence and an explicit trust context are required",
                )
            self._refresh_trusted_evidence(evidence_now)
        self._repository_entries: dict[str, dict[str, Any]] = {}
        if self._repository_snapshot is not None:
            self._repository_entries = repository_snapshot_entries(
                self._repository_snapshot,
                project_id=self._bundle["project"].get("metadata", {}).get("name"),
            )

    def _refresh_trusted_evidence(self, now: datetime) -> None:
        if now.tzinfo is None:
            raise RuntimePolicyError("ECO_CLOCK_INVALID", "Runtime clock must be timezone-aware")
        if self._evidence_ingestor is None:
            return
        verified_observations: dict[str, dict[str, Any]] = {}
        observation_provenance: dict[str, EvidenceProvenance] = {}
        for deployment_id, encoded in self._encoded_observations.items():
            deployment = self._deployments.get(deployment_id)
            if deployment is None or not isinstance(encoded, bytes):
                raise RuntimePolicyError("ECO_EVIDENCE_UNTRUSTED", "Observation trust context is invalid")
            verified = self._evidence_ingestor.ingest_observed_capabilities(
                encoded,
                expected_deployment_id=deployment_id,
                expected_deployment_identity_digest=deployment_identity_digest(deployment),
                trusted_suite_digests=self._trusted_suite_digests,
                now=now,
            )
            verified_observations[deployment_id] = verified.as_dict()
            observation_provenance[deployment_id] = verified.provenance
        verified_snapshot = None
        snapshot_provenance = None
        if self._encoded_repository_snapshot is not None:
            if not isinstance(self._encoded_repository_snapshot, bytes) or not isinstance(
                self._repository_root_identity_digest, str
            ):
                raise RuntimePolicyError("ECO_EVIDENCE_UNTRUSTED", "Snapshot trust context is invalid")
            verified = self._evidence_ingestor.ingest_repository_snapshot(
                self._encoded_repository_snapshot,
                expected_project_id=self._bundle["project"]["metadata"]["name"],
                expected_root_identity_digest=self._repository_root_identity_digest,
                now=now,
            )
            verified_snapshot = verified.as_dict()
            snapshot_provenance = verified.provenance
        self._observations = verified_observations
        self._observation_provenance = observation_provenance
        self._repository_snapshot = verified_snapshot
        self._repository_snapshot_provenance = snapshot_provenance
        self._repository_entries = {}
        if verified_snapshot is not None:
            self._repository_entries = repository_snapshot_entries(
                verified_snapshot,
                project_id=self._bundle["project"]["metadata"]["name"],
            )

    def _validate_canonical_schemas(self) -> None:
        for name in ("project", "instructions", "capabilities", "deployments", "tools"):
            document = self._bundle.get(name)
            if not isinstance(document, dict):
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Canonical record is not an object")
            source = resources.files("eco_cli").joinpath("schemas", SCHEMA_FILES[name])
            schema = json.loads(source.read_text(encoding="utf-8"))
            if next(Draft202012Validator(schema).iter_errors(document), None) is not None:
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Canonical record failed schema validation")

    def _validate_canonical_snapshot(self) -> None:
        api_version = self._bundle["project"].get("apiVersion")
        if api_version != "ai.ecosystem/v1alpha1":
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "Canonical API version is unsupported")
        for name in ("instructions", "capabilities", "deployments", "tools"):
            if self._bundle[name].get("apiVersion") != api_version:
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Canonical API versions do not match")
        for tool in self._tools.values():
            capability = self._capabilities.get(tool.get("capability"))
            if capability is None or capability.get("actionClass") != tool.get("actionClass"):
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Tool capability binding is invalid")
        roles = self._bundle["deployments"].get("logicalRoles", {})
        if not isinstance(roles, dict):
            raise RuntimePolicyError("ECO_CONFIG_INVALID", "Logical role catalog is invalid")
        for role in roles.values():
            if role.get("maximumActionClass") not in ACTION_ORDER:
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Logical role action class is invalid")
            if role.get("minimumArtifactTrust") not in TRUST_ORDER:
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Logical role artifact trust is invalid")
            if not set(role.get("requiredCapabilities", [])) <= set(self._capabilities):
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Logical role capability is invalid")
            if not set(role.get("candidates", [])) <= set(self._deployments):
                raise RuntimePolicyError("ECO_CONFIG_INVALID", "Logical role deployment candidate is invalid")

    @staticmethod
    def _unique_map(items: list[dict[str, Any]], error_code: str) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in items:
            identifier = item.get("id")
            if not isinstance(identifier, str) or identifier in result:
                raise RuntimePolicyError(error_code, "Canonical catalog contains an invalid or duplicate id")
            result[identifier] = item
        return result

    @property
    def config_digest(self) -> str:
        return self._config_digest

    def _register_decision(self, decision: dict[str, Any]) -> None:
        decision_id = decision["metadata"]["id"]
        digest = semantic_digest(decision)
        with self._lock:
            existing = self._issued_decisions.get(decision_id)
            if existing is not None and existing["digest"] != digest:
                raise RuntimePolicyError(
                    "ECO_DECISION_ID_CONFLICT",
                    "Decision id was already issued for different content",
                )
            self._issued_decisions[decision_id] = {
                "digest": digest,
                "consumed": existing["consumed"] if existing else False,
            }

    def _register_plan(self, plan: dict[str, Any]) -> None:
        plan_id = plan["metadata"]["id"]
        digest = semantic_digest(plan)
        with self._lock:
            existing = self._issued_plans.get(plan_id)
            if existing is not None and existing != digest:
                raise RuntimePolicyError(
                    "ECO_PLAN_ID_CONFLICT",
                    "Plan id was already issued for different content",
                )
            self._issued_plans[plan_id] = digest

    def _decision(
        self,
        *,
        decision_id: str,
        run_id: str,
        now: datetime,
        subject_kind: str,
        subject_id: str,
        subject_digest: str,
        effect: str,
        reason_codes: list[str],
        maximum_expiry: datetime | None = None,
    ) -> dict[str, Any]:
        expiry = now + timedelta(seconds=self._decision_ttl_seconds)
        if maximum_expiry is not None:
            if maximum_expiry.tzinfo is None:
                raise RuntimePolicyError("ECO_TIME_INVALID", "Decision expiry bound is invalid")
            expiry = min(expiry, maximum_expiry.astimezone(timezone.utc))
        decision = {
            "apiVersion": API_VERSION,
            "kind": "PolicyDecision",
            "metadata": {
                "id": decision_id,
                "runId": run_id,
                "createdAt": _timestamp(now),
            },
            "spec": {
                "subject": {
                    "kind": subject_kind,
                    "id": subject_id,
                    "digest": subject_digest,
                },
                "effect": effect,
                "reasonCodes": reason_codes,
                "policySnapshot": {
                    "apiVersion": self._bundle["project"]["apiVersion"],
                    "semanticConfigDigest": self._config_digest,
                    "digestProfile": DIGEST_PROFILE,
                    "contractProfile": CONTRACT_PROFILE,
                    "schemaBundleDigest": self._schema_bundle_digest,
                    "policyEngineVersion": POLICY_ENGINE_VERSION,
                },
                "constraints": {
                    "singleUse": True,
                    "expiresAt": _timestamp(expiry),
                },
            },
        }
        validate_record(decision)
        self._register_decision(decision)
        return copy.deepcopy(decision)

    def _evidence_deadline(self, deployment_id: str, *, include_snapshot: bool) -> datetime:
        observation = self._observations[deployment_id]
        provenance = self._observation_provenance[deployment_id]
        deadlines = [
            _parse_timestamp(observation["metadata"]["validUntil"]),
            _parse_timestamp(provenance.expires_at),
        ]
        if include_snapshot:
            if self._repository_snapshot is None or self._repository_snapshot_provenance is None:
                raise RuntimePolicyError("ECO_REPOSITORY_SNAPSHOT_MISSING", "Snapshot evidence is missing")
            deadlines.extend(
                (
                    _parse_timestamp(self._repository_snapshot_provenance.expires_at),
                    _parse_timestamp(self._repository_snapshot["metadata"]["createdAt"])
                    + timedelta(seconds=self._maximum_snapshot_age_seconds),
                )
            )
        return min(deadlines)

    def _deny_run(
        self,
        request: dict[str, Any],
        *,
        run_id: str,
        decision_id: str,
        now: datetime,
        code: str,
    ) -> PlanningResult:
        return PlanningResult(
            plan=None,
            decision=self._decision(
                decision_id=decision_id,
                run_id=run_id,
                now=now,
                subject_kind="RunRequest",
                subject_id=request["metadata"]["id"],
                subject_digest=semantic_digest(request),
                effect="deny",
                reason_codes=[code],
            ),
        )

    def plan_run(
        self,
        request: dict[str, Any],
        *,
        run_id: str,
        plan_id: str,
        decision_id: str,
        now: datetime,
    ) -> PlanningResult:
        _timestamp(now)
        self._refresh_trusted_evidence(now)
        request = copy.deepcopy(validate_record(request))
        spec = request["spec"]
        request_created_at = _parse_timestamp(request["metadata"]["createdAt"])
        if request_created_at > now.astimezone(timezone.utc) + timedelta(
            seconds=self._maximum_clock_skew_seconds
        ):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_REQUEST_TIME_INVALID"
            )
        project = self._bundle["project"]
        project_id = project.get("metadata", {}).get("name")
        if spec["projectId"] != project_id:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_PROJECT_MISMATCH"
            )
        if (
            request["metadata"]["actor"]["type"] == "automation"
            and spec["classificationAuthority"] == "operator"
        ):
            return self._deny_run(
                request,
                run_id=run_id,
                decision_id=decision_id,
                now=now,
                code="ECO_CLASSIFICATION_AUTHORITY_DENIED",
            )

        roles = self._bundle["deployments"].get("logicalRoles", {})
        role = roles.get(spec["logicalRole"])
        if not isinstance(role, dict):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_UNKNOWN_ROLE"
            )

        artifact_refs = [spec["task"]["instructionRef"], *spec["task"]["inputRefs"]]
        effective_data_class = spec["dataClass"]
        plan_inputs: list[dict[str, Any]] = []
        for artifact_ref in artifact_refs:
            artifact = self._artifacts.get(artifact_ref)
            if not isinstance(artifact, dict):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ARTIFACT_MISSING"
                )
            try:
                validate_record(artifact)
            except ContractValidationError:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ARTIFACT_INVALID"
                )
            if artifact["metadata"]["runId"] != run_id or artifact["spec"]["storageRef"] != artifact_ref:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ARTIFACT_MISMATCH"
                )
            artifact_class = artifact["spec"]["dataClass"]
            plan_inputs.append(
                {
                    "ref": artifact_ref,
                    "artifactRecordDigest": semantic_digest(artifact),
                    "contentDigest": artifact["spec"]["sha256"],
                    "dataClass": artifact_class,
                    "byteLength": artifact["spec"]["byteLength"],
                }
            )
            if DATA_ORDER[artifact_class] > DATA_ORDER[effective_data_class]:
                effective_data_class = artifact_class

        if sum(item["byteLength"] for item in plan_inputs) > spec["budget"]["maxInputBytes"]:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_BUDGET_INVALID"
            )

        data_class = effective_data_class
        if data_class == "D4" or data_class not in role.get("allowedDataClasses", []):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_DATA_CLASS_DENIED"
            )

        requested_action = spec["constraints"]["maximumActionClass"]
        if ACTION_ORDER[requested_action] > ACTION_ORDER.get(role.get("maximumActionClass"), -1):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ACTION_CLASS_DENIED"
            )

        candidates = role.get("candidates", [])
        pin = spec.get("deploymentPin")
        if pin is None:
            if not candidates:
                code = "ECO_NO_ELIGIBLE_DEPLOYMENT"
            elif len(candidates) > 1:
                code = "ECO_ROUTE_AMBIGUOUS"
            else:
                code = ""
                pin = candidates[0]
            if code:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code=code
                )
        elif pin not in candidates:
            return self._deny_run(
                request,
                run_id=run_id,
                decision_id=decision_id,
                now=now,
                code="ECO_DEPLOYMENT_NOT_CANDIDATE",
            )

        deployment = self._deployments.get(pin)
        if deployment is None:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_UNKNOWN_DEPLOYMENT"
            )
        if not deployment.get("enabled"):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_DEPLOYMENT_DISABLED"
            )
        if deployment.get("provider") == "configured-at-runtime" or deployment.get("model") == "configured-at-runtime":
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_IDENTITY_INCOMPLETE"
            )
        try:
            identity_digest = deployment_identity_digest(deployment)
        except RuntimePolicyError as exc:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code=exc.code
            )
        if (
            deployment.get("retention") in {None, "unknown", "contract-required"}
            or deployment.get("trainingUse") in {None, "unknown"}
            or deployment.get("region") in {None, "unknown", "contract-required"}
        ):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_DEPLOYMENT_POLICY_INCOMPLETE"
            )
        if deployment.get("zone") not in role.get("allowedZones", []):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ZONE_DENIED"
            )
        if data_class not in deployment.get("allowedDataClasses", []):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_DATA_CLASS_DENIED"
            )
        if TRUST_ORDER.get(deployment.get("artifactTrust"), -1) < TRUST_ORDER.get(
            role.get("minimumArtifactTrust"), -1
        ):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ARTIFACT_TRUST_INSUFFICIENT"
            )

        observation = self._observations.get(pin)
        if not isinstance(observation, dict):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_MISSING"
            )
        try:
            validate_record(observation)
        except ContractValidationError:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_INVALID"
            )
        if observation["metadata"]["deploymentId"] != pin:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_MISMATCH"
            )
        if observation["spec"]["deploymentIdentityDigest"] != identity_digest:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_MISMATCH"
            )
        if observation["spec"]["adapterVersion"] != deployment["identity"]["adapterVersion"]:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_MISMATCH"
            )
        if observation["spec"]["status"] != "pass":
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_CAPABILITY_UNVERIFIED"
            )
        try:
            tested_at = _parse_timestamp(observation["metadata"]["testedAt"])
            valid_until = _parse_timestamp(observation["metadata"]["validUntil"])
        except RuntimePolicyError:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_INVALID"
            )
        effective_now = now.astimezone(timezone.utc)
        if valid_until <= tested_at:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_INVALID"
            )
        if tested_at > effective_now or valid_until <= effective_now:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_STALE"
            )

        suite = observation["spec"].get("suite", {})
        if suite.get("digest") not in self._trusted_suite_digests:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_EVALUATION_SUITE_UNTRUSTED"
            )
        if (
            valid_until - tested_at > timedelta(seconds=self._maximum_observation_age_seconds)
            or effective_now - tested_at > timedelta(seconds=self._maximum_observation_age_seconds)
        ):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_STALE"
            )

        probes = observation["spec"].get("probes", [])
        probe_by_id: dict[str, dict[str, Any]] = {}
        for probe in probes:
            probe_id = probe.get("id")
            if probe_id in probe_by_id or probe.get("successes", 0) > probe.get("attempts", 0):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_OBSERVATION_INVALID"
                )
            probe_by_id[probe_id] = probe

        required_capabilities = set(role.get("requiredCapabilities", []))
        if spec["requestedTools"]:
            required_capabilities.add("model.tool-calling")
        if not required_capabilities <= set(self._capabilities):
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_CAPABILITY_UNAVAILABLE"
            )
        declared = set(deployment.get("declaredCapabilities", []))
        observed = set(observation["spec"].get("effectiveCapabilities", []))
        if not required_capabilities <= declared or not required_capabilities <= observed:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_CAPABILITY_UNAVAILABLE"
            )
        required_probe_by_capability = {
            "model.text": "text-basic",
            "model.tool-calling": "tool-call-normalization",
            "model.structured-output": "structured-output-strict",
        }
        for capability in required_capabilities:
            probe_id = required_probe_by_capability.get(capability)
            if probe_id is None:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_CAPABILITY_UNVERIFIED"
                )
            probe = probe_by_id.get(probe_id)
            if probe is None or probe.get("status") != "pass" or probe.get("successes", 0) < 1:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_CAPABILITY_UNVERIFIED"
                )

        if len(spec["requestedTools"]) > spec["budget"]["maxToolRequests"]:
            return self._deny_run(
                request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_BUDGET_INVALID"
            )

        if "repository.read" in spec["requestedTools"] and self._repository_snapshot is None:
            return self._deny_run(
                request,
                run_id=run_id,
                decision_id=decision_id,
                now=now,
                code="ECO_REPOSITORY_SNAPSHOT_MISSING",
            )

        plan_tools: list[dict[str, Any]] = []
        for tool_id in spec["requestedTools"]:
            tool = self._tools.get(tool_id)
            if tool is None or tool_id not in TOOL_ARGUMENT_SCHEMAS:
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_TOOL_NOT_ALLOWED"
                )
            if not tool.get("enabled"):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_TOOL_DISABLED"
                )
            if tool_id == "repository.read" and (
                tool.get("transport") != "builtin"
                or tool.get("binding") != "workspace-filesystem"
                or tool.get("capability") != "filesystem.read"
                or tool.get("actionClass") != "A1"
            ):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_TOOL_BINDING_MISMATCH"
                )
            tool_action = tool.get("actionClass")
            if ACTION_ORDER.get(tool_action, 99) > ACTION_ORDER[requested_action] or ACTION_ORDER.get(
                tool_action, 99
            ) > ACTION_ORDER.get(role.get("maximumActionClass"), -1):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_ACTION_CLASS_DENIED"
                )
            if "inspect" not in tool.get("allowedSandboxes", []):
                return self._deny_run(
                    request, run_id=run_id, decision_id=decision_id, now=now, code="ECO_SANDBOX_DENIED"
                )
            plan_tools.append(
                {
                    "id": tool_id,
                    "catalogDigest": semantic_digest(tool),
                    "capability": tool["capability"],
                    "actionClass": tool_action,
                    "argumentContract": ARGUMENT_CONTRACTS[tool_id],
                }
            )

        identity = deployment["identity"]
        plan = {
            "apiVersion": API_VERSION,
            "kind": "RunPlan",
            "metadata": {"id": plan_id, "runId": run_id, "createdAt": _timestamp(now)},
            "spec": {
                "requestDigest": semantic_digest(request),
                "project": {
                    "id": project_id,
                    "semanticConfigDigest": self._config_digest,
                    "sourceDigests": self._source_digests,
                    "digestProfile": DIGEST_PROFILE,
                    "contractProfile": CONTRACT_PROFILE,
                    "schemaBundleDigest": self._schema_bundle_digest,
                    "policyEngineVersion": POLICY_ENGINE_VERSION,
                },
                "effectivePolicy": {
                    "dataClass": data_class,
                    "maximumActionClass": requested_action,
                    "sandbox": "inspect",
                    "agentNetwork": "deny",
                    "toolNetwork": "deny",
                },
                "inputs": plan_inputs,
                **(
                    {
                        "repositorySnapshot": {
                            "id": self._repository_snapshot["metadata"]["id"],
                            "digest": semantic_digest(self._repository_snapshot),
                            "rootIdentityDigest": self._repository_snapshot["spec"]["rootIdentityDigest"],
                            "trust": self._repository_snapshot["spec"]["trust"],
                            "evidence": self._repository_snapshot_provenance.as_dict(),
                        }
                    }
                    if self._repository_snapshot is not None and "repository.read" in spec["requestedTools"]
                    else {}
                ),
                "route": {
                    "logicalRole": spec["logicalRole"],
                    "deploymentId": pin,
                    "deploymentDigest": semantic_digest(deployment),
                    "deploymentIdentityDigest": identity_digest,
                    "observedCapabilitiesDigest": semantic_digest(observation),
                    "observedCapabilitiesEvidence": self._observation_provenance[pin].as_dict(),
                    "brokerModelEgress": {
                        "allowed": True,
                        "adapter": deployment["adapter"],
                        "endpointReferenceDigest": identity["endpointReferenceDigest"],
                    },
                    "identity": {
                        "provider": deployment["provider"],
                        "adapter": deployment["adapter"],
                        "adapterVersion": identity["adapterVersion"],
                        "model": deployment["model"],
                        "modelRevision": identity["modelRevision"],
                        "runtimeEngine": identity["runtimeEngine"],
                        "runtimeVersion": identity["runtimeVersion"],
                        "quantization": identity["quantization"],
                        "endpointReferenceDigest": identity["endpointReferenceDigest"],
                    },
                },
                "tools": plan_tools,
                "budget": copy.deepcopy(spec["budget"]),
            },
        }
        validate_record(plan)
        self._register_plan(plan)
        decision = self._decision(
            decision_id=decision_id,
            run_id=run_id,
            now=now,
            subject_kind="RunPlan",
            subject_id=plan_id,
            subject_digest=semantic_digest(plan),
            effect="allow",
            reason_codes=["ECO_RUN_ALLOWED"],
            maximum_expiry=self._evidence_deadline(
                pin, include_snapshot="repository.read" in spec["requestedTools"]
            ),
        )
        return PlanningResult(plan=plan, decision=decision)

    def authorize_tool(
        self,
        plan: dict[str, Any],
        request: dict[str, Any],
        *,
        decision_id: str,
        now: datetime,
        require_in_memory_activation: bool = True,
    ) -> dict[str, Any]:
        _timestamp(now)
        self._refresh_trusted_evidence(now)
        plan = copy.deepcopy(validate_record(plan))
        request = copy.deepcopy(validate_record(request))
        run_id = plan["metadata"]["runId"]
        subject_digest = semantic_digest(request)
        with self._lock:
            active_plan_digest = self._active_plans.get(run_id)

        code: str | None = None
        try:
            request_created_at = _parse_timestamp(request["metadata"]["createdAt"])
            plan_created_at = _parse_timestamp(plan["metadata"]["createdAt"])
        except RuntimePolicyError:
            request_created_at = None
            plan_created_at = None
            code = "ECO_TOOL_REQUEST_TIME_INVALID"
        if code is None and (
            request_created_at < plan_created_at
            or request_created_at
            > now.astimezone(timezone.utc) + timedelta(seconds=self._maximum_clock_skew_seconds)
        ):
            code = "ECO_TOOL_REQUEST_TIME_INVALID"
        elif request["metadata"]["runId"] != run_id:
            code = "ECO_RUN_MISMATCH"
        elif require_in_memory_activation and active_plan_digest != semantic_digest(plan):
            code = "ECO_PLAN_NOT_ACTIVE"
        elif plan["spec"]["project"]["semanticConfigDigest"] != self._config_digest:
            code = "ECO_CONFIG_DRIFT"
        elif request["spec"]["planDigest"] != semantic_digest(plan):
            code = "ECO_PLAN_MISMATCH"
        else:
            planned_tools = {item["id"]: item for item in plan["spec"]["tools"]}
            tool_id = request["spec"]["toolId"]
            if tool_id not in planned_tools:
                code = "ECO_TOOL_NOT_ALLOWED"
            elif tool_argument_errors(tool_id, request["spec"]["arguments"]):
                code = "ECO_TOOL_ARGUMENTS_INVALID"
            elif tool_id == "repository.read":
                path = request["spec"]["arguments"]["path"]
                entry = self._repository_entries.get(path)
                if protected_repository_path(path):
                    code = "ECO_PROTECTED_PATH"
                elif entry is None:
                    code = "ECO_REPOSITORY_PATH_UNSNAPSHOTTED"
                elif entry["dataClass"] == "D4" or DATA_ORDER[entry["dataClass"]] > DATA_ORDER[
                    plan["spec"]["effectivePolicy"]["dataClass"]
                ]:
                    code = "ECO_DATA_CLASS_DENIED"

        return self._decision(
            decision_id=decision_id,
            run_id=run_id,
            now=now,
            subject_kind="ToolRequest",
            subject_id=request["metadata"]["id"],
            subject_digest=subject_digest,
            effect="deny" if code else "allow",
            reason_codes=[code or "ECO_TOOL_ALLOWED"],
            maximum_expiry=(
                self._evidence_deadline(
                    plan["spec"]["route"]["deploymentId"],
                    include_snapshot="repositorySnapshot" in plan["spec"],
                )
                if code is None
                else None
            ),
        )

    def consume_decision(
        self,
        decision: dict[str, Any],
        subject: dict[str, Any],
        *,
        now: datetime,
    ) -> None:
        _timestamp(now)
        decision = copy.deepcopy(validate_record(decision))
        subject = copy.deepcopy(validate_record(subject))
        spec = decision["spec"]
        decision_id = decision["metadata"]["id"]
        decision_digest = semantic_digest(decision)
        subject_run_id = subject["metadata"].get("runId")
        now_utc = now.astimezone(timezone.utc)

        if spec["effect"] != "allow":
            raise RuntimePolicyError("ECO_DECISION_DENIED", "Denied decision cannot authorize execution")
        if decision["metadata"]["runId"] != subject_run_id:
            raise RuntimePolicyError("ECO_DECISION_MISMATCH", "Decision belongs to another run")
        if spec["policySnapshot"]["semanticConfigDigest"] != self._config_digest:
            raise RuntimePolicyError("ECO_CONFIG_DRIFT", "Decision uses another policy snapshot")
        if (
            spec["subject"]["kind"] != subject["kind"]
            or spec["subject"]["id"] != subject["metadata"]["id"]
            or spec["subject"]["digest"] != semantic_digest(subject)
        ):
            raise RuntimePolicyError("ECO_DECISION_MISMATCH", "Decision subject does not match")
        if _parse_timestamp(decision["metadata"]["createdAt"]) > now_utc:
            raise RuntimePolicyError("ECO_DECISION_TIME_INVALID", "Decision was created in the future")
        if _parse_timestamp(spec["constraints"]["expiresAt"]) <= now_utc:
            raise RuntimePolicyError("ECO_DECISION_EXPIRED", "Decision has expired")

        with self._lock:
            issued = self._issued_decisions.get(decision_id)
            if issued is None or issued["digest"] != decision_digest:
                raise RuntimePolicyError("ECO_DECISION_UNTRUSTED", "Decision was not issued by this policy engine")
            if issued["consumed"]:
                raise RuntimePolicyError("ECO_DECISION_REPLAYED", "Decision was already consumed")
            issued["consumed"] = True

    def activate_plan(
        self,
        plan: dict[str, Any],
        decision: dict[str, Any],
        *,
        now: datetime,
    ) -> None:
        _timestamp(now)
        self._refresh_trusted_evidence(now)
        plan = copy.deepcopy(validate_record(plan))
        plan_id = plan["metadata"]["id"]
        plan_digest = semantic_digest(plan)
        with self._lock:
            if self._issued_plans.get(plan_id) != plan_digest:
                raise RuntimePolicyError("ECO_PLAN_UNTRUSTED", "Plan was not issued by this policy engine")
        self.consume_decision(decision, plan, now=now)
        run_id = plan["metadata"]["runId"]
        with self._lock:
            existing = self._active_plans.get(run_id)
            if existing is not None and existing != plan_digest:
                raise RuntimePolicyError("ECO_PLAN_ID_CONFLICT", "Another plan is active for this run")
            self._active_plans[run_id] = plan_digest
            if run_id not in self._budget_ledgers:
                self._budget_ledgers[run_id] = BudgetLedger(plan)

    def budget_ledger(self, plan: dict[str, Any]) -> BudgetLedger:
        """Return the one runtime-owned ledger for an exact active plan."""

        plan = copy.deepcopy(validate_record(plan))
        run_id = plan["metadata"]["runId"]
        plan_digest = semantic_digest(plan)
        with self._lock:
            if self._active_plans.get(run_id) != plan_digest:
                raise RuntimePolicyError("ECO_PLAN_NOT_ACTIVE", "Plan is not active")
            ledger = self._budget_ledgers.get(run_id)
            if ledger is None or ledger.plan_digest != plan_digest:
                raise RuntimePolicyError("ECO_BUDGET_UNAVAILABLE", "Active plan has no trusted budget ledger")
            return ledger
