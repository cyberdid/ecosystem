from __future__ import annotations

import copy
import hashlib
import hmac
import json
import queue
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import combinations
from typing import Any, Mapping, Protocol

from .contracts import API_VERSION, validate_record
from .digests import canonical_json, semantic_digest
from .errors import RuntimeStoreError


EVALUATION_EVIDENCE_VERSION = 1
_SAFE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_DEPLOYMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("evaluation time must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_output(value: str) -> str:
    """Normalize protocol-level Unicode/newline variance without hiding text changes."""

    if not isinstance(value, str):
        raise TypeError("model output must be text")
    return unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))


def normalized_output_digest(value: str) -> str:
    return hashlib.sha256(normalize_output(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvaluationUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    model_requests: int = 1

    def __post_init__(self) -> None:
        for value in (
            self.input_tokens,
            self.output_tokens,
            self.total_tokens,
            self.model_requests,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("evaluation usage must contain non-negative integers")
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        if self.model_requests < 1:
            raise ValueError("model_requests must be positive")

    def as_evidence(self) -> dict[str, int]:
        return {
            "inputTokens": self.input_tokens,
            "outputTokens": self.output_tokens,
            "totalTokens": self.total_tokens,
            "modelRequests": self.model_requests,
        }


@dataclass(frozen=True)
class UsageTolerance:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    model_requests: int = 0

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in (
                self.input_tokens,
                self.output_tokens,
                self.total_tokens,
                self.model_requests,
            )
        ):
            raise ValueError("usage tolerances must be non-negative integers")

    def as_evidence(self) -> dict[str, int]:
        return {
            "inputTokens": self.input_tokens,
            "outputTokens": self.output_tokens,
            "totalTokens": self.total_tokens,
            "modelRequests": self.model_requests,
        }


@dataclass(frozen=True)
class EvaluationCase:
    id: str
    input_text: str = field(repr=False)
    expected_output_digest: str | None = None
    usage_tolerance: UsageTolerance = field(default_factory=UsageTolerance)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or _SAFE_ID_RE.fullmatch(self.id) is None:
            raise ValueError("evaluation case id is invalid")
        if not isinstance(self.input_text, str) or not self.input_text:
            raise ValueError("evaluation input must be non-empty text")
        if len(self.input_text.encode("utf-8")) > 1_000_000:
            raise ValueError("evaluation input exceeds the bounded suite profile")
        if self.expected_output_digest is not None and (
            not isinstance(self.expected_output_digest, str)
            or _DIGEST_RE.fullmatch(self.expected_output_digest) is None
        ):
            raise ValueError("expected output digest is invalid")

    def identity_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "inputDigest": hashlib.sha256(self.input_text.encode("utf-8")).hexdigest(),
            "expectedOutputDigest": self.expected_output_digest,
            "usageTolerance": self.usage_tolerance.as_evidence(),
        }


@dataclass(frozen=True)
class EvaluationSuite:
    id: str
    version: str
    cases: tuple[EvaluationCase, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or _SAFE_ID_RE.fullmatch(self.id) is None:
            raise ValueError("evaluation suite id is invalid")
        if not isinstance(self.version, str) or _VERSION_RE.fullmatch(self.version) is None:
            raise ValueError("evaluation suite version is invalid")
        if not 1 <= len(self.cases) <= 256:
            raise ValueError("evaluation suite must contain between 1 and 256 cases")
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("evaluation case ids must be unique")

    @property
    def digest(self) -> str:
        return semantic_digest(
            {
                "domain": "eco-cross-deployment-suite-v1",
                "id": self.id,
                "version": self.version,
                "cases": [case.identity_payload() for case in self.cases],
            }
        )

    def reference(self) -> dict[str, str]:
        return {"id": self.id, "version": self.version, "digest": self.digest}


@dataclass(frozen=True)
class PinnedEvaluationDeployment:
    id: str
    deployment_identity_digest: str
    adapter_version: str
    effective_capabilities: tuple[str, ...] = ("model.text",)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or _DEPLOYMENT_ID_RE.fullmatch(self.id) is None:
            raise ValueError("deployment id is invalid")
        if (
            not isinstance(self.deployment_identity_digest, str)
            or _DIGEST_RE.fullmatch(self.deployment_identity_digest) is None
        ):
            raise ValueError("deployment identity digest is invalid")
        if (
            not isinstance(self.adapter_version, str)
            or _VERSION_RE.fullmatch(self.adapter_version) is None
        ):
            raise ValueError("adapter version is required")
        if not self.effective_capabilities or len(set(self.effective_capabilities)) != len(
            self.effective_capabilities
        ):
            raise ValueError("effective capabilities must be unique and non-empty")
        if any(_SAFE_ID_RE.fullmatch(item) is None for item in self.effective_capabilities):
            raise ValueError("effective capability is invalid")


@dataclass(frozen=True)
class EvaluationRequest:
    suite_digest: str
    case_id: str
    input_text: str = field(repr=False)
    temperature_milli: int = 0
    seed: int = 0


@dataclass(frozen=True)
class EvaluationInvocation:
    deployment_identity_digest: str
    output_text: str = field(repr=False)
    usage: EvaluationUsage


class EvaluationAdapter(Protocol):
    deployment_id: str
    adapter_version: str

    def invoke(
        self, request: EvaluationRequest, *, timeout_seconds: float
    ) -> EvaluationInvocation: ...


@dataclass(frozen=True)
class SignedEvaluationEvidence:
    canonical_payload: bytes = field(repr=False)
    key_id: str
    signature: str = field(repr=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_payload).hexdigest()

    @property
    def payload(self) -> dict[str, Any]:
        return json.loads(self.canonical_payload.decode("utf-8"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence": self.payload,
            "evidenceDigest": self.digest,
            "signature": {
                "algorithm": "HMAC-SHA256",
                "keyId": self.key_id,
                "value": self.signature,
            },
        }


@dataclass(frozen=True)
class EvaluationRun:
    observations: tuple[dict[str, Any], ...]
    evidence: SignedEvaluationEvidence


@dataclass(frozen=True)
class _ProbeResult:
    case_id: str
    status: str
    deviation_code: str | None
    output_digest: str | None
    usage: EvaluationUsage | None

    def evidence_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "caseId": self.case_id,
            "status": self.status,
            "deviationCode": self.deviation_code,
        }
        if self.output_digest is not None:
            payload["normalizedOutputDigest"] = self.output_digest
        if self.usage is not None:
            payload["usage"] = self.usage.as_evidence()
        return payload


class EvaluationEvidenceSigner:
    def __init__(self, *, key: bytes, key_id: str) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("evaluation signing key must contain at least 32 bytes")
        if not isinstance(key_id, str) or _DEPLOYMENT_ID_RE.fullmatch(key_id) is None:
            raise ValueError("evaluation signing key id is required")
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: Mapping[str, Any]) -> SignedEvaluationEvidence:
        self._validate_payload(payload)
        encoded = canonical_json(dict(payload)).encode("utf-8")
        signature = hmac.new(self._key, encoded, hashlib.sha256).hexdigest()
        return SignedEvaluationEvidence(encoded, self._key_id, signature)

    @staticmethod
    def _validate_payload(payload: Mapping[str, Any]) -> None:
        invalid = not isinstance(payload, Mapping) or set(payload) != {
            "domain",
            "version",
            "suite",
            "evaluatedAt",
            "status",
            "deployments",
            "comparisons",
        }
        if invalid:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence has an invalid shape"
            )
        suite = payload["suite"]
        deployments = payload["deployments"]
        comparisons = payload["comparisons"]
        if (
            payload["domain"] != "eco-cross-deployment-evidence-v1"
            or payload["version"] != EVALUATION_EVIDENCE_VERSION
            or payload["status"] not in {"pass", "fail"}
            or not isinstance(payload["evaluatedAt"], str)
            or not isinstance(suite, dict)
            or set(suite) != {"id", "version", "digest"}
            or not isinstance(suite["id"], str)
            or _SAFE_ID_RE.fullmatch(suite["id"]) is None
            or not isinstance(suite["version"], str)
            or _VERSION_RE.fullmatch(suite["version"]) is None
            or not isinstance(suite["digest"], str)
            or _DIGEST_RE.fullmatch(suite["digest"]) is None
            or not isinstance(deployments, list)
            or len(deployments) < 2
            or not isinstance(comparisons, list)
        ):
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence has invalid metadata"
            )
        deployment_ids: set[str] = set()
        probes_by_deployment: dict[str, dict[str, dict[str, Any]]] = {}
        expected_deviations: dict[str, set[str]] = {}
        for deployment in deployments:
            if not isinstance(deployment, dict) or set(deployment) != {
                "deploymentId",
                "pinnedIdentityDigest",
                "adapterVersion",
                "status",
                "observationDigest",
                "probes",
                "deviationCodes",
            }:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation deployment evidence is invalid"
                )
            deployment_id = deployment["deploymentId"]
            if (
                not isinstance(deployment_id, str)
                or _DEPLOYMENT_ID_RE.fullmatch(deployment_id) is None
                or deployment_id in deployment_ids
                or deployment["status"] not in {"pass", "fail"}
                or not isinstance(deployment["pinnedIdentityDigest"], str)
                or _DIGEST_RE.fullmatch(deployment["pinnedIdentityDigest"]) is None
                or not isinstance(deployment["observationDigest"], str)
                or _DIGEST_RE.fullmatch(deployment["observationDigest"]) is None
                or not isinstance(deployment["adapterVersion"], str)
                or _VERSION_RE.fullmatch(deployment["adapterVersion"]) is None
                or not isinstance(deployment["probes"], list)
                or not isinstance(deployment["deviationCodes"], list)
                or any(
                    not isinstance(code, str)
                    or re.fullmatch(r"ECO_[A-Z0-9_]+", code) is None
                    for code in deployment["deviationCodes"]
                )
                or len(deployment["deviationCodes"])
                != len(set(deployment["deviationCodes"]))
                or deployment["deviationCodes"] != sorted(deployment["deviationCodes"])
            ):
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation deployment evidence is invalid"
                )
            probes: dict[str, dict[str, Any]] = {}
            probe_deviations: set[str] = set()
            for probe in deployment["probes"]:
                if (
                    not isinstance(probe, dict)
                    or not {"caseId", "status", "deviationCode"}.issubset(probe)
                    or set(probe)
                    - {
                        "caseId",
                        "status",
                        "deviationCode",
                        "normalizedOutputDigest",
                        "usage",
                    }
                ):
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Evaluation probe evidence is invalid"
                    )
                case_id = probe["caseId"]
                status = probe["status"]
                deviation_code = probe["deviationCode"]
                output_digest = probe.get("normalizedOutputDigest")
                usage = probe.get("usage")
                if (
                    not isinstance(case_id, str)
                    or _SAFE_ID_RE.fullmatch(case_id) is None
                    or case_id in probes
                    or status not in {"pass", "fail"}
                    or (status == "pass" and deviation_code is not None)
                    or (
                        status == "fail"
                        and (
                            not isinstance(deviation_code, str)
                            or re.fullmatch(r"ECO_[A-Z0-9_]+", deviation_code) is None
                        )
                    )
                    or (output_digest is None) != (usage is None)
                    or (
                        output_digest is not None
                        and (
                            not isinstance(output_digest, str)
                            or _DIGEST_RE.fullmatch(output_digest) is None
                        )
                    )
                ):
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Evaluation probe evidence is invalid"
                    )
                if status == "pass" and output_digest is None:
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Passing evaluation probe has no result"
                    )
                if usage is not None:
                    if (
                        not isinstance(usage, dict)
                        or set(usage)
                        != {"inputTokens", "outputTokens", "totalTokens", "modelRequests"}
                        or any(
                            not isinstance(value, int)
                            or isinstance(value, bool)
                            or value < 0
                            for value in usage.values()
                        )
                        or usage["totalTokens"]
                        != usage["inputTokens"] + usage["outputTokens"]
                        or usage["modelRequests"] < 1
                    ):
                        raise RuntimeStoreError(
                            "ECO_EVAL_EVIDENCE_INVALID", "Evaluation probe usage is invalid"
                        )
                probes[case_id] = probe
                if deviation_code is not None:
                    probe_deviations.add(deviation_code)
            if not probes:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation probe inventory is empty"
                )
            probes_by_deployment[deployment_id] = probes
            expected_deviations[deployment_id] = probe_deviations
            deployment_ids.add(deployment_id)
        case_inventory = {tuple(sorted(probes)) for probes in probes_by_deployment.values()}
        if len(case_inventory) != 1:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation probe inventories do not match"
            )
        if len(comparisons) != len(deployments) * (len(deployments) - 1) // 2:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison inventory is incomplete"
            )
        expected_pairs = {
            frozenset(pair) for pair in combinations(sorted(deployment_ids), 2)
        }
        actual_pairs: set[frozenset[str]] = set()
        expected_cases = next(iter(case_inventory))
        for comparison in comparisons:
            if not isinstance(comparison, dict) or set(comparison) != {
                "leftDeploymentId",
                "rightDeploymentId",
                "status",
                "cases",
            }:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison is invalid"
                )
            left_id = comparison["leftDeploymentId"]
            right_id = comparison["rightDeploymentId"]
            if not isinstance(left_id, str) or not isinstance(right_id, str):
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison is invalid"
                )
            pair = frozenset((left_id, right_id))
            if (
                left_id not in deployment_ids
                or right_id not in deployment_ids
                or left_id == right_id
                or pair in actual_pairs
                or not isinstance(comparison["cases"], list)
            ):
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison is invalid"
                )
            actual_pairs.add(pair)
            case_statuses: dict[str, str] = {}
            for case in comparison["cases"]:
                if (
                    not isinstance(case, dict)
                    or set(case) != {"caseId", "status"}
                    or not isinstance(case["caseId"], str)
                    or case["caseId"] in case_statuses
                    or case["status"]
                    not in {
                        "parity",
                        "output-divergence",
                        "usage-divergence",
                        "not-comparable",
                    }
                ):
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Evaluation case comparison is invalid"
                    )
                case_id = case["caseId"]
                left_probe = probes_by_deployment[left_id].get(case_id)
                right_probe = probes_by_deployment[right_id].get(case_id)
                if left_probe is None or right_probe is None:
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Evaluation case inventory is incomplete"
                    )
                if left_probe["status"] != "pass" or right_probe["status"] != "pass":
                    expected_status = {"not-comparable"}
                elif left_probe["normalizedOutputDigest"] != right_probe["normalizedOutputDigest"]:
                    expected_status = {"output-divergence"}
                elif left_probe["usage"] == right_probe["usage"]:
                    expected_status = {"parity"}
                else:
                    # Tolerances are bound by the suite digest but omitted from
                    # content-free evidence, so either result can be valid here.
                    expected_status = {"parity", "usage-divergence"}
                if case["status"] not in expected_status:
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Evaluation case comparison is inconsistent"
                    )
                if case["status"] == "output-divergence":
                    expected_deviations[left_id].add("ECO_EVAL_OUTPUT_DIVERGENCE")
                    expected_deviations[right_id].add("ECO_EVAL_OUTPUT_DIVERGENCE")
                elif case["status"] == "usage-divergence":
                    expected_deviations[left_id].add("ECO_EVAL_USAGE_DIVERGENCE")
                    expected_deviations[right_id].add("ECO_EVAL_USAGE_DIVERGENCE")
                case_statuses[case_id] = case["status"]
            if tuple(sorted(case_statuses)) != expected_cases:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation case inventory is incomplete"
                )
            derived_status = (
                "divergence"
                if any(
                    status in {"output-divergence", "usage-divergence"}
                    for status in case_statuses.values()
                )
                else "not-comparable"
                if "not-comparable" in case_statuses.values()
                else "parity"
            )
            if comparison["status"] != derived_status:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison status is inconsistent"
                )
        if actual_pairs != expected_pairs:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation comparison inventory is incomplete"
            )
        for deployment in deployments:
            deployment_id = deployment["deploymentId"]
            derived_status = (
                "pass"
                if not expected_deviations[deployment_id]
                and all(
                    probe["status"] == "pass"
                    for probe in probes_by_deployment[deployment_id].values()
                )
                else "fail"
            )
            if (
                deployment["deviationCodes"]
                != sorted(expected_deviations[deployment_id])
                or deployment["status"] != derived_status
            ):
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID", "Evaluation deployment status is inconsistent"
                )
        derived_overall = (
            "pass"
            if all(deployment["status"] == "pass" for deployment in deployments)
            and all(comparison["status"] == "parity" for comparison in comparisons)
            else "fail"
        )
        if payload["status"] != derived_overall:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence status is inconsistent"
            )
        if _RFC3339_RE.fullmatch(payload["evaluatedAt"]) is None:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence time is invalid"
            )
        try:
            evaluated_at = datetime.fromisoformat(
                payload["evaluatedAt"][:-1] + "+00:00"
                if payload["evaluatedAt"].endswith("Z")
                else payload["evaluatedAt"]
            )
        except ValueError as exc:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence time is invalid"
            ) from exc
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence time is invalid"
            )

    def verify(
        self,
        evidence: SignedEvaluationEvidence,
        *,
        observations: tuple[dict[str, Any], ...] | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(evidence, SignedEvaluationEvidence)
            or evidence.key_id != self._key_id
            or not isinstance(evidence.signature, str)
            or _DIGEST_RE.fullmatch(evidence.signature) is None
        ):
            raise RuntimeStoreError(
                "ECO_EVAL_SIGNATURE_INVALID", "Evaluation evidence signature is invalid"
            )
        expected = hmac.new(self._key, evidence.canonical_payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, evidence.signature):
            raise RuntimeStoreError(
                "ECO_EVAL_SIGNATURE_INVALID", "Evaluation evidence authentication failed"
            )
        try:
            payload = evidence.payload
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence is invalid"
            ) from exc
        if canonical_json(payload).encode("utf-8") != evidence.canonical_payload:
            raise RuntimeStoreError(
                "ECO_EVAL_EVIDENCE_INVALID", "Evaluation evidence is not canonical"
            )
        self._validate_payload(payload)
        if observations is not None:
            expected_observations = {
                item["deploymentId"]: item["observationDigest"]
                for item in payload.get("deployments", [])
            }
            actual_observations: dict[str, str] = {}
            for observation in observations:
                validate_record(observation)
                deployment_id = observation["metadata"]["deploymentId"]
                if deployment_id in actual_observations:
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID", "Observation inventory contains duplicates"
                    )
                actual_observations[deployment_id] = semantic_digest(observation)
            if expected_observations != actual_observations:
                raise RuntimeStoreError(
                    "ECO_EVAL_EVIDENCE_INVALID",
                    "Evaluation observations do not match signed evidence",
                )
            evidence_deployments = {
                item["deploymentId"]: item for item in payload["deployments"]
            }
            for observation in observations:
                deployment_id = observation["metadata"]["deploymentId"]
                deployment = evidence_deployments[deployment_id]
                spec = observation["spec"]
                evidence_probes = {
                    item["caseId"]: item for item in deployment["probes"]
                }
                observation_probes = {item["id"]: item for item in spec["probes"]}
                consistent = (
                    observation["metadata"]["testedAt"] == payload["evaluatedAt"]
                    and spec["deploymentIdentityDigest"]
                    == deployment["pinnedIdentityDigest"]
                    and spec["adapterVersion"] == deployment["adapterVersion"]
                    and spec["suite"] == payload["suite"]
                    and spec["status"] == deployment["status"]
                    and spec["deviationCodes"] == deployment["deviationCodes"]
                    and set(observation_probes) == set(evidence_probes)
                    and len(observation_probes) == len(spec["probes"])
                )
                if consistent:
                    for case_id, probe in evidence_probes.items():
                        observed = observation_probes[case_id]
                        expected_metrics = None
                        if "usage" in probe:
                            expected_metrics = {
                                "inputTokens": probe["usage"]["inputTokens"],
                                "outputTokens": probe["usage"]["outputTokens"],
                            }
                        if (
                            observed["status"] != probe["status"]
                            or observed["attempts"] != 1
                            or observed["successes"]
                            != (1 if probe["status"] == "pass" else 0)
                            or observed["evidenceDigest"] != semantic_digest(probe)
                            or observed.get("metrics") != expected_metrics
                        ):
                            consistent = False
                            break
                if not consistent:
                    raise RuntimeStoreError(
                        "ECO_EVAL_EVIDENCE_INVALID",
                        "Evaluation observation is inconsistent with signed evidence",
                    )
        return copy.deepcopy(payload)


class CrossDeploymentEvaluationRunner:
    """Run one deterministic suite through pinned adapters and sign sanitized evidence."""

    def __init__(
        self,
        *,
        signer: EvaluationEvidenceSigner,
        timeout_seconds: float = 30.0,
        max_output_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(max_output_bytes, int) or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self._signer = signer
        self._timeout_seconds = float(timeout_seconds)
        self._max_output_bytes = max_output_bytes

    def _invoke_with_timeout(
        self, adapter: EvaluationAdapter, request: EvaluationRequest
    ) -> tuple[str, EvaluationInvocation | None]:
        result_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

        def invoke() -> None:
            try:
                result_queue.put(
                    (
                        "result",
                        adapter.invoke(request, timeout_seconds=self._timeout_seconds),
                    )
                )
            except BaseException:
                result_queue.put(("error", None))

        worker = threading.Thread(target=invoke, daemon=True, name="eco-evaluation-invoke")
        worker.start()
        worker.join(self._timeout_seconds)
        if worker.is_alive():
            return "ECO_EVAL_TIMEOUT", None
        try:
            status, value = result_queue.get_nowait()
        except queue.Empty:
            return "ECO_EVAL_ADAPTER_FAILURE", None
        if status != "result" or not isinstance(value, EvaluationInvocation):
            return "ECO_EVAL_ADAPTER_FAILURE", None
        return "success", value

    def _run_probe(
        self,
        suite: EvaluationSuite,
        case: EvaluationCase,
        deployment: PinnedEvaluationDeployment,
        adapter: EvaluationAdapter,
    ) -> _ProbeResult:
        if (
            getattr(adapter, "deployment_id", None) != deployment.id
            or getattr(adapter, "adapter_version", None) != deployment.adapter_version
        ):
            return _ProbeResult(
                case.id, "fail", "ECO_DEPLOYMENT_IDENTITY_MISMATCH", None, None
            )
        request = EvaluationRequest(suite.digest, case.id, case.input_text)
        status, invocation = self._invoke_with_timeout(adapter, request)
        if invocation is None:
            return _ProbeResult(case.id, "fail", status, None, None)
        if invocation.deployment_identity_digest != deployment.deployment_identity_digest:
            return _ProbeResult(
                case.id, "fail", "ECO_DEPLOYMENT_IDENTITY_MISMATCH", None, None
            )
        try:
            normalized = normalize_output(invocation.output_text)
            encoded = normalized.encode("utf-8")
            if len(encoded) > self._max_output_bytes:
                return _ProbeResult(case.id, "fail", "ECO_EVAL_OUTPUT_TOO_LARGE", None, None)
            output_digest = hashlib.sha256(encoded).hexdigest()
            if not isinstance(invocation.usage, EvaluationUsage):
                return _ProbeResult(case.id, "fail", "ECO_EVAL_PROTOCOL_INVALID", None, None)
        except (TypeError, UnicodeError):
            return _ProbeResult(case.id, "fail", "ECO_EVAL_PROTOCOL_INVALID", None, None)
        if (
            case.expected_output_digest is not None
            and output_digest != case.expected_output_digest
        ):
            return _ProbeResult(
                case.id,
                "fail",
                "ECO_EVAL_EXPECTATION_MISMATCH",
                output_digest,
                invocation.usage,
            )
        return _ProbeResult(case.id, "pass", None, output_digest, invocation.usage)

    @staticmethod
    def _usage_diverges(
        left: EvaluationUsage, right: EvaluationUsage, tolerance: UsageTolerance
    ) -> bool:
        return any(
            delta > allowed
            for delta, allowed in (
                (abs(left.input_tokens - right.input_tokens), tolerance.input_tokens),
                (abs(left.output_tokens - right.output_tokens), tolerance.output_tokens),
                (abs(left.total_tokens - right.total_tokens), tolerance.total_tokens),
                (abs(left.model_requests - right.model_requests), tolerance.model_requests),
            )
        )

    def run(
        self,
        suite: EvaluationSuite,
        deployments: tuple[PinnedEvaluationDeployment, ...],
        adapters: Mapping[str, EvaluationAdapter],
        *,
        evaluated_at: datetime,
        valid_for: timedelta = timedelta(hours=24),
    ) -> EvaluationRun:
        if not isinstance(suite, EvaluationSuite):
            raise TypeError("suite must be an EvaluationSuite")
        if len(deployments) < 2 or len({item.id for item in deployments}) != len(deployments):
            raise ValueError("cross-deployment evaluation needs at least two unique deployments")
        if set(adapters) != {item.id for item in deployments}:
            raise ValueError("adapter inventory must exactly match pinned deployments")
        if evaluated_at.tzinfo is None or valid_for <= timedelta(0):
            raise ValueError("evaluation validity window is invalid")
        evaluated_at_text = _utc(evaluated_at)
        valid_until_text = _utc(evaluated_at + valid_for)

        ordered_deployments = tuple(sorted(deployments, key=lambda item: item.id))
        results: dict[str, tuple[_ProbeResult, ...]] = {
            deployment.id: tuple(
                self._run_probe(suite, case, deployment, adapters[deployment.id])
                for case in suite.cases
            )
            for deployment in ordered_deployments
        }
        deviations: dict[str, set[str]] = {
            deployment.id: {
                result.deviation_code
                for result in results[deployment.id]
                if result.deviation_code is not None
            }
            for deployment in ordered_deployments
        }

        comparisons: list[dict[str, Any]] = []
        cases_by_id = {case.id: case for case in suite.cases}
        for left, right in combinations(ordered_deployments, 2):
            case_comparisons: list[dict[str, str]] = []
            pair_status = "parity"
            for left_result, right_result in zip(results[left.id], results[right.id], strict=True):
                if left_result.status != "pass" or right_result.status != "pass":
                    case_status = "not-comparable"
                    pair_status = "not-comparable" if pair_status == "parity" else pair_status
                elif left_result.output_digest != right_result.output_digest:
                    case_status = "output-divergence"
                    pair_status = "divergence"
                    deviations[left.id].add("ECO_EVAL_OUTPUT_DIVERGENCE")
                    deviations[right.id].add("ECO_EVAL_OUTPUT_DIVERGENCE")
                elif self._usage_diverges(
                    left_result.usage,
                    right_result.usage,
                    cases_by_id[left_result.case_id].usage_tolerance,
                ):
                    case_status = "usage-divergence"
                    pair_status = "divergence"
                    deviations[left.id].add("ECO_EVAL_USAGE_DIVERGENCE")
                    deviations[right.id].add("ECO_EVAL_USAGE_DIVERGENCE")
                else:
                    case_status = "parity"
                case_comparisons.append({"caseId": left_result.case_id, "status": case_status})
            comparisons.append(
                {
                    "leftDeploymentId": left.id,
                    "rightDeploymentId": right.id,
                    "status": pair_status,
                    "cases": case_comparisons,
                }
            )

        observations: list[dict[str, Any]] = []
        deployment_evidence: list[dict[str, Any]] = []
        for deployment in ordered_deployments:
            probe_records: list[dict[str, Any]] = []
            for result in results[deployment.id]:
                probe: dict[str, Any] = {
                    "id": result.case_id,
                    "status": result.status,
                    "attempts": 1,
                    "successes": 1 if result.status == "pass" else 0,
                    "evidenceDigest": semantic_digest(result.evidence_payload()),
                }
                if result.usage is not None:
                    probe["metrics"] = {
                        "inputTokens": result.usage.input_tokens,
                        "outputTokens": result.usage.output_tokens,
                    }
                probe_records.append(probe)
            profile_passes = not deviations[deployment.id] and all(
                result.status == "pass" for result in results[deployment.id]
            )
            observation_id = "eval-" + semantic_digest(
                {
                    "deploymentId": deployment.id,
                    "suiteDigest": suite.digest,
                    "evaluatedAt": evaluated_at_text,
                }
            )[:24]
            observation = validate_record(
                {
                    "apiVersion": API_VERSION,
                    "kind": "AdapterConformanceProfile",
                    "metadata": {
                        "id": observation_id,
                        "deploymentId": deployment.id,
                        "testedAt": evaluated_at_text,
                        "validUntil": valid_until_text,
                    },
                    "spec": {
                        "deploymentIdentityDigest": deployment.deployment_identity_digest,
                        "adapterVersion": deployment.adapter_version,
                        "suite": suite.reference(),
                        "status": "pass" if profile_passes else "fail",
                        "effectiveCapabilities": (
                            sorted(deployment.effective_capabilities) if profile_passes else []
                        ),
                        "probes": probe_records,
                        "deviationCodes": sorted(deviations[deployment.id]),
                    },
                }
            )
            observation = copy.deepcopy(observation)
            observations.append(observation)
            deployment_evidence.append(
                {
                    "deploymentId": deployment.id,
                    "pinnedIdentityDigest": deployment.deployment_identity_digest,
                    "adapterVersion": deployment.adapter_version,
                    "status": observation["spec"]["status"],
                    "observationDigest": semantic_digest(observation),
                    "probes": [result.evidence_payload() for result in results[deployment.id]],
                    "deviationCodes": sorted(deviations[deployment.id]),
                }
            )

        overall_pass = all(item["status"] == "pass" for item in deployment_evidence) and all(
            item["status"] == "parity" for item in comparisons
        )
        payload = {
            "domain": "eco-cross-deployment-evidence-v1",
            "version": EVALUATION_EVIDENCE_VERSION,
            "suite": suite.reference(),
            "evaluatedAt": evaluated_at_text,
            "status": "pass" if overall_pass else "fail",
            "deployments": deployment_evidence,
            "comparisons": comparisons,
        }
        signed = self._signer.sign(payload)
        run = EvaluationRun(tuple(observations), signed)
        self._signer.verify(run.evidence, observations=run.observations)
        return run
