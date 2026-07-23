from __future__ import annotations

import copy
import unittest

from eco_runtime.contracts import (
    API_VERSION,
    SCHEMA_BY_KIND,
    contract_errors,
    tool_argument_errors,
    validate_record,
    validate_tool_arguments,
)
from eco_runtime.errors import ContractValidationError
from eco_runtime.policy import POLICY_ENGINE_VERSION
from tests.test_m3_contracts import positive_m3_records


NOW = "2026-07-15T12:00:00Z"
DIGEST = "a" * 64


def run_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RunRequest",
        "metadata": {
            "id": "request-1",
            "createdAt": NOW,
            "actor": {"type": "human", "id": "operator-1"},
        },
        "spec": {
            "projectId": "ecosystem",
            "logicalRole": "code.read",
            "dataClass": "D1",
            "classificationAuthority": "operator",
            "task": {
                "type": "repository.review",
                "instructionRef": "artifact://inputs/instruction-1",
                "inputRefs": ["artifact://inputs/repository-manifest-1"],
            },
            "requestedTools": ["repository.read"],
            "constraints": {
                "maximumActionClass": "A1",
                "sandbox": "inspect",
                "agentNetwork": "deny",
                "toolNetwork": "deny",
            },
            "budget": {
                "maxDurationSeconds": 600,
                "maxModelRequests": 2,
                "maxToolRequests": 50,
                "maxInputBytes": 2_000_000,
                "maxOutputBytes": 200_000,
                "maxTotalTokens": 50_000,
                "maxCostMicrousd": 2_000_000,
            },
            "fallbackPolicy": "none",
        },
    }


def run_plan() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RunPlan",
        "metadata": {"id": "plan-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "requestDigest": DIGEST,
            "project": {
                "id": "ecosystem",
                "semanticConfigDigest": DIGEST,
                "sourceDigests": {
                    "project": DIGEST,
                    "instructions": DIGEST,
                    "capabilities": DIGEST,
                    "deployments": DIGEST,
                    "tools": DIGEST,
                },
                "digestProfile": "eco-python-json-v1",
                "contractProfile": "runtime-contracts-v1alpha1",
                "schemaBundleDigest": DIGEST,
                "policyEngineVersion": POLICY_ENGINE_VERSION,
            },
            "effectivePolicy": {
                "dataClass": "D1",
                "maximumActionClass": "A1",
                "sandbox": "inspect",
                "agentNetwork": "deny",
                "toolNetwork": "deny",
            },
            "inputs": [
                {
                    "ref": "artifact://inputs/instruction-1",
                    "artifactRecordDigest": DIGEST,
                    "contentDigest": DIGEST,
                    "dataClass": "D1",
                    "byteLength": 42,
                }
            ],
            "repositorySnapshot": {
                "id": "repository-snapshot-1",
                "digest": DIGEST,
                "rootIdentityDigest": DIGEST,
                "trust": "P1",
                "evidence": {
                    "envelopeId": "snapshot-envelope-1",
                    "envelopeDigest": DIGEST,
                    "issuerId": "test-authority",
                    "keyId": "test-key",
                    "issuedAt": "2026-07-15T12:00:00Z",
                    "expiresAt": "2026-07-15T13:00:00Z",
                },
            },
            "route": {
                "logicalRole": "code.read",
                "deploymentId": "dgx-lab",
                "deploymentDigest": DIGEST,
                "deploymentIdentityDigest": DIGEST,
                "observedCapabilitiesDigest": DIGEST,
                "observedCapabilitiesEvidence": {
                    "envelopeId": "observation-envelope-1",
                    "envelopeDigest": DIGEST,
                    "issuerId": "test-authority",
                    "keyId": "test-key",
                    "issuedAt": "2026-07-15T12:00:00Z",
                    "expiresAt": "2026-07-16T12:00:00Z",
                },
                "brokerModelEgress": {
                    "allowed": True,
                    "adapter": "openai-compatible",
                    "endpointReferenceDigest": DIGEST,
                },
                "identity": {
                    "provider": "local",
                    "adapter": "openai-compatible",
                    "adapterVersion": "0.1.0",
                    "model": "example-model",
                    "modelRevision": "revision-1",
                    "runtimeEngine": "vllm",
                    "runtimeVersion": "1.0.0",
                    "quantization": "none",
                    "endpointReferenceDigest": DIGEST,
                },
            },
            "tools": [
                {
                    "id": "repository.read",
                    "catalogDigest": DIGEST,
                    "capability": "filesystem.read",
                    "actionClass": "A1",
                    "argumentContract": "eco://tools/repository-read/v1alpha1",
                }
            ],
            "budget": copy.deepcopy(run_request()["spec"]["budget"]),
        },
    }


def tool_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ToolRequest",
        "metadata": {
            "id": "tool-request-1",
            "runId": "run-1",
            "createdAt": NOW,
            "source": "model",
        },
        "spec": {
            "planDigest": DIGEST,
            "toolId": "repository.read",
            "arguments": {"path": "README.md"},
        },
    }


def no_model_run_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "NoModelRunRequest",
        "metadata": {
            "id": "no-model-request-1",
            "createdAt": NOW,
            "actor": {"type": "human", "id": "operator-1"},
        },
        "spec": {"projectId": "ecosystem", "workflow": "wiki-health-check"},
    }


def no_model_run_plan() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "NoModelRunPlan",
        "metadata": {"id": "no-model-plan-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "profile": "no-model-a1/v1alpha1",
            "requestDigest": DIGEST,
            "project": copy.deepcopy(run_plan()["spec"]["project"]),
            "effectivePolicy": {
                "dataClass": "D0",
                "maximumActionClass": "A1",
                "sandbox": "inspect",
                "network": "deny",
                "modelRequests": 0,
                "workspaceWrites": 0,
            },
            "repositorySnapshot": copy.deepcopy(run_plan()["spec"]["repositorySnapshot"]),
            "workflow": {
                "id": "wiki-health-check",
                "scopeDigest": DIGEST,
                "entryCount": 3,
                "scopeSlots": [
                    {"slot": f"slot-{index}", "entryDigest": f"{index}" * 64}
                    for index in range(1, 4)
                ],
            },
            "budget": {
                "maxDurationSeconds": 30,
                "maxReadRequests": 3,
                "maxInputBytes": 42,
                "maxModelRequests": 0,
                "maxNetworkRequests": 0,
                "maxWorkspaceWrites": 0,
            },
        },
    }


def no_model_read_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "NoModelReadRequest",
        "metadata": {"id": "no-model-read-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "planDigest": DIGEST,
            "workflow": "wiki-health-check",
            "path": "wiki/index.md",
            "scopeSlot": "slot-1",
        },
    }


def wiki_health_run_evidence() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "WikiHealthRunEvidence",
        "metadata": {"id": "wiki-evidence-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "profile": "wiki-health-run-evidence/v1",
            "workflow": "wiki-health-check",
            "evidenceDigest": DIGEST,
            "reportDigest": DIGEST,
            "repositorySnapshotDigest": DIGEST,
            "status": "succeeded",
            "replayed": False,
            "execution": {"verifiedEntryCount": 3, "brokerReadCount": 3, "totalBytes": 42},
            "safety": {
                "unauthorizedActions": 0,
                "repositoryMutations": 0,
                "modelRequests": 0,
                "networkRequests": 0,
                "writeOperations": 0,
                "adaptersCreated": 0,
                "contentEmissions": 0,
            },
        },
    }


def wiki_health_promotion_report() -> dict:
    passed = {
        "eligible": True,
        "reasonCode": "ECO_M4_PROMOTION_GATE_PASSED",
        "reason": "The fixed no-model workflow passed the complete M4 L0-L2 evidence gate.",
    }
    out_of_scope = {
        "eligible": False,
        "reasonCode": "ECO_M4_LEVEL_OUT_OF_SCOPE",
        "reason": "The no-model read-only M4 evidence cannot authorize model, network, or write-capable promotion.",
    }
    return {
        "apiVersion": API_VERSION,
        "kind": "WikiHealthPromotionReport",
        "metadata": {"id": "wiki-promotion-1", "evaluatedAt": NOW},
        "spec": {
            "profile": "wiki-health-promotion-report/v1",
            "workflow": "wiki-health-check",
            "evaluationVersion": 1,
            "criteria": {
                "requiredIndependentAttempts": 5,
                "requiredVerifiedEntryCount": 3,
                "requiredBrokerReadsPerAttempt": 3,
                "requiredRecoveryBrokerReads": 0,
                "maximumSafetyViolations": 0,
            },
            "observed": {
                "attemptCount": 5,
                "independentRunCount": 5,
                "successfulNonReplayedAttemptCount": 5,
                "stableResult": True,
                "safeAttemptCount": 5,
            },
            "reference": {
                "reportDigest": DIGEST,
                "repositorySnapshotDigest": DIGEST,
                "verifiedEntryCount": 3,
                "totalBytes": 42,
            },
            "recovery": {"provided": True, "passed": True, "evidenceDigest": DIGEST},
            "status": "pass",
            "reasonCodes": [],
            "sourceEvidenceDigests": [DIGEST],
            "promotion": {
                "highestEligibleLevel": "L2",
                "levels": {
                    "L0": copy.deepcopy(passed),
                    "L1": copy.deepcopy(passed),
                    "L2": copy.deepcopy(passed),
                    "L3": copy.deepcopy(out_of_scope),
                    "L4": copy.deepcopy(out_of_scope),
                    "L5": copy.deepcopy(out_of_scope),
                },
            },
            "promotionReportDigest": DIGEST,
        },
    }


def policy_decision() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "PolicyDecision",
        "metadata": {"id": "decision-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "subject": {"kind": "ToolRequest", "id": "tool-request-1", "digest": DIGEST},
            "effect": "allow",
            "reasonCodes": ["ECO_TOOL_ALLOWED"],
            "policySnapshot": {
                "apiVersion": "ai.ecosystem/v1alpha1",
                "semanticConfigDigest": DIGEST,
                "digestProfile": "eco-python-json-v1",
                "contractProfile": "runtime-contracts-v1alpha1",
                "schemaBundleDigest": DIGEST,
                "policyEngineVersion": POLICY_ENGINE_VERSION,
            },
            "constraints": {"singleUse": True, "expiresAt": "2026-07-15T12:05:00Z"},
        },
    }


def run_event() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RunEvent",
        "metadata": {
            "id": "event-1",
            "runId": "run-1",
            "sequence": 1,
            "occurredAt": NOW,
            "producer": "runtime",
            "producerIssuer": "runtime-issuer-1",
            "previousEventDigest": None,
        },
        "spec": {"type": "run.received", "outcome": "pending", "subjectId": "request-1"},
    }


def artifact_record() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ArtifactRecord",
        "metadata": {"id": "artifact-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "role": "input",
            "mediaType": "text/plain",
            "byteLength": 42,
            "sha256": DIGEST,
            "dataClass": "D1",
            "trust": "P1",
            "producer": {"type": "operator", "id": "operator-1"},
            "parentRefs": [],
            "storageRef": "artifact://runs/run-1/artifact-1",
            "retention": "run",
        },
    }


def error_record() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ErrorRecord",
        "metadata": {"id": "error-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "code": "ECO_PATH_ESCAPE",
            "category": "broker",
            "stage": "tool",
            "retryable": False,
            "safeMessage": "Repository path is outside the approved root",
            "details": {"toolId": "repository.read"},
        },
    }


def adapter_conformance_profile() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "AdapterConformanceProfile",
        "metadata": {
            "id": "dgx-lab-observation-1",
            "deploymentId": "dgx-lab",
            "testedAt": NOW,
            "validUntil": "2026-08-15T12:00:00Z",
        },
        "spec": {
            "deploymentIdentityDigest": DIGEST,
            "adapterVersion": "0.1.0",
            "suite": {
                "id": "adapter-conformance-v1",
                "version": "1.0.0",
                "digest": DIGEST,
            },
            "status": "pass",
            "effectiveCapabilities": ["model.text"],
            "probes": [
                {
                    "id": "text-basic",
                    "status": "pass",
                    "attempts": 3,
                    "successes": 3,
                    "evidenceDigest": DIGEST,
                    "metrics": {"latencyP50Ms": 10, "latencyP95Ms": 15},
                }
            ],
            "deviationCodes": [],
        },
    }


def platform_backend_conformance_profile() -> dict:
    probe_ids = [
        "clean-environment-and-fs-boundary",
        "network-namespace-deny",
        "output-and-deadline-bounds",
        "read-only-workdir",
        "stdin-closed",
    ]
    return {
        "apiVersion": API_VERSION,
        "kind": "PlatformBackendConformanceProfile",
        "metadata": {
            "id": "linux-native-linux-namespace-boundary-1",
            "platformProfileId": "linux-native",
            "testedAt": NOW,
            "validUntil": "2026-07-15T13:00:00Z",
        },
        "spec": {
            "platformProfileDigest": DIGEST,
            "platform": {
                "id": "linux-native",
                "operatingSystem": "linux",
                "architecture": "x86_64",
                "context": "native",
            },
            "distributionManifestDigest": DIGEST,
            "backend": {
                "id": "linux-namespace-landlock",
                "version": "1",
                "implementationDigest": DIGEST,
                "instanceDigest": DIGEST,
            },
            "runnerDigest": DIGEST,
            "suite": {
                "id": "linux-namespace-boundary",
                "version": "1",
                "digest": DIGEST,
                "probeIds": probe_ids,
            },
            "status": "pass",
            "observedCapabilities": [
                "backend.clean-environment",
                "backend.landlock-workdir-boundary",
                "backend.network-namespace-deny",
                "backend.output-deadline-bounded",
                "backend.read-only-workdir",
                "backend.stdin-closed",
            ],
            "probes": [
                {"id": item, "status": "pass", "evidenceDigest": DIGEST}
                for item in probe_ids
            ],
            "deviationCodes": [],
            "safety": {
                "authenticated": False,
                "authorityCreated": False,
                "runtimeConsumed": False,
                "projectMutation": False,
                "rawOutputPersisted": False,
            },
        },
    }


def endpoint_binding() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "EndpointBinding",
        "metadata": {
            "id": "endpoint-binding-1",
            "deploymentId": "local-pinned",
            "resolvedAt": NOW,
            "validUntil": "2026-07-15T12:10:00Z",
        },
        "spec": {
            "deploymentIdentityDigest": DIGEST,
            "endpointReferenceDigest": DIGEST,
            "resolvedEndpointDigest": DIGEST,
            "adapter": "openai-compatible",
            "adapterVersion": "openai-compatible-v1",
            "model": "model-revision-exact",
            "transportProfile": "local-loopback-http",
            "credentialMode": "none",
        },
    }


def model_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ModelRequest",
        "metadata": {"id": "model-request-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "planDigest": DIGEST,
            "deploymentId": "local-pinned",
            "deploymentIdentityDigest": DIGEST,
            "endpointBindingDigest": DIGEST,
            "input": {
                "artifactRecordDigest": DIGEST,
                "contentDigest": DIGEST,
                "byteLength": 42,
                "dataClass": "D1",
                "trust": "P1",
            },
            "parameters": {
                "maxOutputTokens": 100,
                "maxOutputBytes": 4096,
                "temperatureMillis": 0,
            },
            "timeoutMs": 5000,
            "fallbackPolicy": "none",
        },
    }


def model_result() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ModelResult",
        "metadata": {
            "id": "model-result-1",
            "runId": "run-1",
            "requestId": "model-request-1",
            "createdAt": NOW,
        },
        "spec": {
            "modelRequestDigest": DIGEST,
            "deploymentId": "local-pinned",
            "deploymentIdentityDigest": DIGEST,
            "endpointBindingDigest": DIGEST,
            "adapterVersion": "openai-compatible-v1",
            "providerRequestIdDigest": DIGEST,
            "reportedModelDigest": DIGEST,
            "output": {
                "contentDigest": DIGEST,
                "byteLength": 24,
                "dataClass": "D1",
                "trust": "P0",
            },
            "usage": {"inputTokens": 10, "outputTokens": 4, "totalTokens": 14},
            "finishReason": "stop",
        },
    }


def repository_snapshot() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RepositorySnapshot",
        "metadata": {
            "id": "repository-snapshot-1",
            "projectId": "ecosystem",
            "createdAt": NOW,
            "issuer": {"type": "operator", "id": "operator-1"},
        },
        "spec": {
            "rootIdentityDigest": DIGEST,
            "trust": "P1",
            "sourceRevision": "fixture-revision",
            "entries": [
                {
                    "path": "README.md",
                    "contentDigest": DIGEST,
                    "byteLength": 42,
                    "dataClass": "D1",
                    "trust": "P1",
                    "classificationAuthority": "operator",
                }
            ],
        },
    }


def tool_execution_intent() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ToolExecutionIntent",
        "metadata": {"id": "operation-1", "runId": "run-1", "createdAt": NOW},
        "spec": {
            "idempotencyKeyDigest": DIGEST,
            "planDigest": DIGEST,
            "toolRequest": {"id": "tool-request-1", "digest": DIGEST},
            "allowDecision": {"id": "tool-decision-1", "digest": DIGEST},
            "toolCatalogDigest": DIGEST,
            "reservation": {"toolRequests": 1, "inputBytes": 42},
            "repositoryEntry": {
                "snapshotDigest": DIGEST,
                "pathDigest": DIGEST,
                "contentDigest": DIGEST,
                "byteLength": 42,
                "dataClass": "D1",
                "trust": "P1",
            },
        },
    }


def repository_read_receipt() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RepositoryReadReceipt",
        "metadata": {
            "id": "receipt-1",
            "runId": "run-1",
            "operationId": "operation-1",
            "createdAt": NOW,
        },
        "spec": {
            "intentDigest": DIGEST,
            "toolRequestDigest": DIGEST,
            "repositorySnapshotDigest": DIGEST,
            "contentDigest": DIGEST,
            "byteLength": 42,
            "dataClass": "D1",
            "trust": "P1",
        },
    }


def tool_execution_outcome() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ToolExecutionOutcome",
        "metadata": {
            "id": "outcome-1",
            "runId": "run-1",
            "operationId": "operation-1",
            "createdAt": NOW,
        },
        "spec": {
            "intentDigest": DIGEST,
            "status": "succeeded",
            "receiptDigest": DIGEST,
            "artifactRecordDigest": DIGEST,
        },
    }


def run_checkpoint() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "RunCheckpoint",
        "metadata": {"id": "checkpoint-1", "runId": "run-1", "revision": 5, "createdAt": NOW},
        "spec": {
            "state": "RUNNING",
            "projection": {
                "state": "RUNNING",
                "toolStates": [],
                "adapterCompleted": False,
                "adapterFailed": False,
                "budgetExhausted": False,
            },
            "historyComplete": True,
            "historySource": "native-v1",
            "eventSequence": 5,
            "eventHeadDigest": DIGEST,
            "activePlanDigest": DIGEST,
            "budget": {
                "limitsDigest": DIGEST,
                "toolRequests": 1,
                "inputBytes": 84,
                "reservedInputBytes": 0,
                "outputBytes": 0,
                "modelRequests": 0,
                "totalTokens": 0,
                "costMicrousd": 0,
            },
            "openOperationIds": [],
            "startedAt": NOW,
            "deadlineAt": "2026-07-15T12:10:00Z",
        },
    }


class RuntimeContractTests(unittest.TestCase):
    def records(self) -> list[dict]:
        return [
            run_request(),
            run_plan(),
            no_model_run_request(),
            no_model_run_plan(),
            no_model_read_request(),
            wiki_health_run_evidence(),
            wiki_health_promotion_report(),
            tool_request(),
            policy_decision(),
            run_event(),
            artifact_record(),
            error_record(),
            adapter_conformance_profile(),
            platform_backend_conformance_profile(),
            endpoint_binding(),
            model_request(),
            model_result(),
            repository_snapshot(),
            tool_execution_intent(),
            repository_read_receipt(),
            tool_execution_outcome(),
            run_checkpoint(),
            *positive_m3_records(),
        ]

    def test_positive_records_validate(self) -> None:
        self.assertEqual(set(SCHEMA_BY_KIND), {record["kind"] for record in self.records()})
        for record in self.records():
            with self.subTest(kind=record["kind"]):
                self.assertIs(validate_record(record), record)

    def test_unknown_kind_fails_closed(self) -> None:
        record = {"kind": "FutureRecord", "payload": "ECO_TEST_SECRET_DO_NOT_ECHO"}
        with self.assertRaises(ContractValidationError) as captured:
            validate_record(record)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", str(captured.exception))

    def test_errors_never_echo_invalid_values(self) -> None:
        record = run_request()
        record["spec"]["dataClass"] = "ECO_TEST_SECRET_DO_NOT_ECHO"
        errors = contract_errors(record)
        self.assertTrue(errors)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(errors))

    def test_unknown_fields_are_rejected(self) -> None:
        record = tool_request()
        record["spec"]["credential"] = "ECO_TEST_SECRET_DO_NOT_ECHO"
        errors = contract_errors(record)
        self.assertTrue(errors)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(errors))

    def test_date_time_format_is_enforced(self) -> None:
        record = run_event()
        record["metadata"]["occurredAt"] = "not-a-date"
        self.assertTrue(contract_errors(record))

    def test_run_event_requires_explicit_chain_head(self) -> None:
        record = run_event()
        record["metadata"].pop("previousEventDigest")
        self.assertTrue(contract_errors(record))

    def test_artifact_storage_is_opaque_not_a_filesystem_path(self) -> None:
        record = artifact_record()
        record["spec"]["storageRef"] = "../../outside.txt"
        self.assertTrue(contract_errors(record))

    def test_artifact_references_reject_ambiguous_segments_and_encodings(self) -> None:
        invalid_refs = [
            "artifact://inputs/../secret",
            "artifact://inputs/./record",
            "artifact://inputs//record",
            "artifact://inputs\\record",
            "artifact://inputs/%2Fetc",
            "artifact://inputs/%5cwindows",
        ]
        for reference in invalid_refs:
            with self.subTest(reference=reference):
                record = artifact_record()
                record["spec"]["storageRef"] = reference
                self.assertTrue(contract_errors(record))

    def test_m2_policy_decision_has_no_approval_effect(self) -> None:
        record = policy_decision()
        record["spec"]["effect"] = "require-approval"
        self.assertTrue(contract_errors(record))

    def test_automatic_fallback_is_forbidden(self) -> None:
        record = run_request()
        record["spec"]["fallbackPolicy"] = "automatic"
        self.assertTrue(contract_errors(record))

        request = model_request()
        request["spec"]["fallbackPolicy"] = "automatic"
        self.assertTrue(contract_errors(request))

    def test_model_records_are_content_and_endpoint_free(self) -> None:
        request = model_request()
        request["spec"]["inputText"] = "ECO_PRIVATE_PROMPT_DO_NOT_PERSIST"
        errors = contract_errors(request)
        self.assertTrue(errors)
        self.assertNotIn("ECO_PRIVATE_PROMPT_DO_NOT_PERSIST", " ".join(errors))

        binding = endpoint_binding()
        binding["spec"]["endpointUrl"] = "https://private.example/v1/chat/completions"
        self.assertTrue(contract_errors(binding))

    def test_cost_budget_uses_integer_microusd(self) -> None:
        record = run_request()
        record["spec"]["budget"]["maxCostMicrousd"] = 0.5
        self.assertTrue(contract_errors(record))

    def test_every_budget_dimension_is_required(self) -> None:
        for factory in (run_request, run_plan):
            for field in ("maxTotalTokens", "maxCostMicrousd"):
                with self.subTest(kind=factory()["kind"], field=field):
                    record = factory()
                    record["spec"]["budget"].pop(field)
                    self.assertTrue(contract_errors(record))

    def test_error_details_are_allowlisted(self) -> None:
        record = error_record()
        record["spec"]["details"]["rawProviderBody"] = "ECO_TEST_SECRET_DO_NOT_ECHO"
        errors = contract_errors(record)
        self.assertTrue(errors)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(errors))

    def test_repository_read_arguments_are_strict(self) -> None:
        self.assertEqual(validate_tool_arguments("repository.read", {"path": "src/module.py"}), {"path": "src/module.py"})
        invalid_paths = [
            "",
            "../secret",
            "a/../../secret",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "\\\\server\\share\\file",
            "file:///etc/passwd",
            "https://example.invalid/file",
            "a\x00b",
            ".",
            "./README.md",
            "src//module.py",
            "src/./module.py",
            "src/module.py/",
            "src/module.py\n.env",
            "src/module.py\t.env",
            "e\u0301.txt",
            ("é" * 2048) + ".txt",
        ]
        for path in invalid_paths:
            with self.subTest(path=repr(path)):
                errors = tool_argument_errors("repository.read", {"path": path})
                self.assertTrue(errors)
                if path and path != ".":
                    self.assertNotIn(path, " ".join(errors))

    def test_repository_read_rejects_unknown_arguments(self) -> None:
        arguments = {"path": "README.md", "credential": "ECO_TEST_SECRET_DO_NOT_ECHO"}
        errors = tool_argument_errors("repository.read", arguments)
        self.assertTrue(errors)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(errors))

    def test_unknown_tool_arguments_fail_closed(self) -> None:
        self.assertTrue(tool_argument_errors("unknown.tool", {"path": "README.md"}))

    def test_transaction_records_forbid_raw_path_and_content(self) -> None:
        intent = tool_execution_intent()
        intent["spec"]["repositoryEntry"]["path"] = "secret.txt"
        errors = contract_errors(intent)
        self.assertTrue(errors)
        self.assertNotIn("secret.txt", " ".join(errors))

        receipt = repository_read_receipt()
        receipt["spec"]["content"] = "ECO_TEST_SECRET_DO_NOT_ECHO"
        errors = contract_errors(receipt)
        self.assertTrue(errors)
        self.assertNotIn("ECO_TEST_SECRET_DO_NOT_ECHO", " ".join(errors))

    def test_tool_outcome_is_exactly_success_or_failure_shape(self) -> None:
        failed = tool_execution_outcome()
        failed["spec"] = {
            "intentDigest": DIGEST,
            "status": "failed",
            "errorRecordDigest": DIGEST,
        }
        self.assertIs(validate_record(failed), failed)

        invalid = tool_execution_outcome()
        invalid["spec"]["errorRecordDigest"] = DIGEST
        self.assertTrue(contract_errors(invalid))

        invalid = tool_execution_outcome()
        invalid["spec"].pop("artifactRecordDigest")
        self.assertTrue(contract_errors(invalid))


if __name__ == "__main__":
    unittest.main()
