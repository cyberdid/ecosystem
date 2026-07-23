from __future__ import annotations

import copy
import unittest

from eco_runtime.contracts import (
    API_VERSION,
    contract_errors,
    schema_bundle_digest,
    tool_argument_errors,
    validate_record,
    validate_tool_arguments,
)


NOW = "2026-07-15T12:00:00Z"
DIGEST = "a" * 64


def _metadata(identifier: str, *, operation_id: str | None = None) -> dict:
    value = {"id": identifier, "runId": "run-1", "createdAt": NOW}
    if operation_id is not None:
        value["operationId"] = operation_id
    return value


def _binding(identifier: str) -> dict:
    return {"id": identifier, "digest": DIGEST}


def _candidate() -> dict:
    return {
        "artifactRecordDigest": DIGEST,
        "contentDigest": DIGEST,
        "byteLength": 42,
        "dataClass": "D1",
        "trust": "P1",
        "availabilityProofDigest": DIGEST,
        "fileType": "regular",
        "encoding": "UTF-8",
        "mode": 420,
    }


def _present_before() -> dict:
    return {
        "state": "present",
        "fileType": "regular",
        "encoding": "UTF-8",
        "contentDigest": DIGEST,
        "byteLength": 21,
        "mode": 420,
    }


def workspace_change_proposal() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "WorkspaceChangeProposal",
        "metadata": _metadata("proposal-1"),
        "spec": {
            "planDigest": DIGEST,
            "toolRequest": _binding("write-request-1"),
            "policyAllowDecision": _binding("write-policy-1"),
            "operation": "create",
            "pathDigest": DIGEST,
            "expectedBefore": {"state": "absent"},
            "candidateArtifact": _candidate(),
            "displayDigest": DIGEST,
            "approvalExpiresAt": "2026-07-15T12:05:00Z",
            "rollbackProfile": "single-file-cas-restore-v1",
        },
    }


def approval_request() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ApprovalRequest",
        "metadata": _metadata("approval-request-1"),
        "spec": {
            "proposal": _binding("proposal-1"),
            "toolRequest": _binding("write-request-1"),
            "subject": {
                "kind": "WorkspaceChangeProposal",
                "id": "proposal-1",
                "digest": DIGEST,
            },
            "authoritySubjectDigest": DIGEST,
            "displayDigest": DIGEST,
            "requestedActionClass": "A2",
            "humanRequired": True,
            "expiresAt": "2026-07-15T12:05:00Z",
        },
    }


def approval_grant() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "ApprovalGrant",
        "metadata": _metadata("approval-grant-1"),
        "spec": {
            "approvalRequest": _binding("approval-request-1"),
            "proposal": _binding("proposal-1"),
            "subject": {
                "kind": "WorkspaceChangeProposal",
                "id": "proposal-1",
                "digest": DIGEST,
            },
            "authoritySubjectDigest": DIGEST,
            "displayDigest": DIGEST,
            "decision": "approve",
            "approver": {
                "type": "human",
                "issuerId": "local-approval-authority",
                "subjectId": "operator-1",
                "assurance": "local-os-session",
                "challengeDigest": DIGEST,
            },
            "constraints": {
                "singleUse": True,
                "expiresAt": "2026-07-15T12:05:00Z",
            },
            "signedEnvelope": {
                "protocol": "eco-approval-envelope-v1",
                "envelopeId": "approval-envelope-1",
                "issuer": {
                    "id": "local-approval-authority",
                    "keyId": "approval-key-1",
                },
                "subjectDigest": DIGEST,
                "issuedAt": NOW,
                "expiresAt": "2026-07-15T12:05:00Z",
                "signature": {"algorithm": "HMAC-SHA256", "tag": DIGEST},
            },
        },
    }


def workspace_write_intent() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "WorkspaceWriteIntent",
        "metadata": _metadata("write-operation-1"),
        "spec": {
            "idempotencyKeyDigest": DIGEST,
            "planDigest": DIGEST,
            "toolRequest": _binding("write-request-1"),
            "policyAllowDecision": _binding("write-policy-1"),
            "approvalGrant": _binding("approval-grant-1"),
            "proposal": _binding("proposal-1"),
            "toolCatalogDigest": DIGEST,
            "operation": "create",
            "pathDigest": DIGEST,
            "expectedBefore": {"state": "absent"},
            "candidateArtifact": _candidate(),
            "rollback": {
                "profile": "single-file-cas-restore-v1",
                "expectedAppliedDigest": DIGEST,
            },
        },
    }


def workspace_write_receipt() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "WorkspaceWriteReceipt",
        "metadata": _metadata("write-receipt-1", operation_id="write-operation-1"),
        "spec": {
            "intentDigest": DIGEST,
            "proposalDigest": DIGEST,
            "toolRequestDigest": DIGEST,
            "policyDecisionDigest": DIGEST,
            "approvalGrantDigest": DIGEST,
            "idempotencyKeyDigest": DIGEST,
            "operation": "create",
            "pathDigest": DIGEST,
            "expectedBefore": {"state": "absent"},
            "applied": {
                "fileType": "regular",
                "encoding": "UTF-8",
                "contentDigest": DIGEST,
                "byteLength": 42,
                "mode": 420,
                "filesystemProfile": "linux-openat2-v1",
                "atomicReplace": True,
                "directoryFsync": True,
            },
            "postconditionDigest": DIGEST,
        },
    }


def workspace_rollback_receipt() -> dict:
    return {
        "apiVersion": API_VERSION,
        "kind": "WorkspaceRollbackReceipt",
        "metadata": _metadata("rollback-receipt-1", operation_id="write-operation-1"),
        "spec": {
            "writeIntentDigest": DIGEST,
            "writeReceiptDigest": DIGEST,
            "reasonCode": "ECO_WRITE_VERIFICATION_FAILED",
            "pathDigest": DIGEST,
            "status": "rolled-back",
            "expectedAppliedDigest": DIGEST,
            "beforeRestored": {"state": "absent"},
            "rollbackProfile": "single-file-cas-restore-v1",
            "restoredStateDigest": DIGEST,
        },
    }


def positive_m3_records() -> list[dict]:
    return [
        workspace_change_proposal(),
        approval_request(),
        approval_grant(),
        workspace_write_intent(),
        workspace_write_receipt(),
        workspace_rollback_receipt(),
    ]


class M3ContractTests(unittest.TestCase):
    def test_positive_m3_records_validate(self) -> None:
        for record in positive_m3_records():
            with self.subTest(kind=record["kind"]):
                self.assertIs(validate_record(record), record)

    def test_repository_write_is_one_exact_create_or_replace(self) -> None:
        create = {
            "path": "src/new_module.py",
            "operation": "create",
            "expectedBefore": {"state": "absent"},
            "candidateArtifact": _candidate(),
        }
        self.assertIs(validate_tool_arguments("repository.write", create), create)

        replace = copy.deepcopy(create)
        replace["operation"] = "replace"
        replace["expectedBefore"] = _present_before()
        self.assertIs(validate_tool_arguments("repository.write", replace), replace)

        for mutation in (
            {"operation": "delete"},
            {"operation": "create", "expectedBefore": _present_before()},
            {"operation": "replace", "expectedBefore": {"state": "absent"}},
        ):
            invalid = copy.deepcopy(create)
            invalid.update(mutation)
            self.assertTrue(tool_argument_errors("repository.write", invalid))

    def test_read_and_write_share_canonical_path_semantics(self) -> None:
        invalid_paths = [
            "../secret",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "file:///etc/passwd",
            ".",
            "./README.md",
            "src//module.py",
            "src/./module.py",
            "src/module.py/",
            "e\u0301.txt",
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                self.assertTrue(tool_argument_errors("repository.read", {"path": path}))
                arguments = {
                    "path": path,
                    "operation": "create",
                    "expectedBefore": {"state": "absent"},
                    "candidateArtifact": _candidate(),
                }
                self.assertTrue(tool_argument_errors("repository.write", arguments))

    def test_durable_records_reject_raw_path_and_content(self) -> None:
        for factory in (
            workspace_change_proposal,
            workspace_write_intent,
            workspace_write_receipt,
            workspace_rollback_receipt,
        ):
            for field in ("path", "content"):
                with self.subTest(kind=factory()["kind"], field=field):
                    record = factory()
                    record["spec"][field] = "ECO_PRIVATE_VALUE_DO_NOT_PERSIST"
                    errors = contract_errors(record)
                    self.assertTrue(errors)
                    self.assertNotIn("ECO_PRIVATE_VALUE_DO_NOT_PERSIST", " ".join(errors))

    def test_approval_is_human_exact_single_use_and_signed(self) -> None:
        mutations = [
            ("approver", "type", "automation"),
            ("constraints", "singleUse", False),
            (None, "decision", "delegate"),
            ("signedEnvelope", "protocol", "unsigned"),
        ]
        for container, field, value in mutations:
            with self.subTest(field=field, value=value):
                record = approval_grant()
                target = record["spec"] if container is None else record["spec"][container]
                target[field] = value
                self.assertTrue(contract_errors(record))

        for field in ("approvalRequest", "proposal", "subject", "displayDigest"):
            record = approval_grant()
            record["spec"].pop(field)
            self.assertTrue(contract_errors(record))

        record = approval_grant()
        record["spec"]["approver"].pop("challengeDigest")
        self.assertTrue(contract_errors(record))

    def test_replace_intent_requires_backup_and_create_forbids_it(self) -> None:
        replace = workspace_write_intent()
        replace["spec"]["operation"] = "replace"
        replace["spec"]["expectedBefore"] = _present_before()
        self.assertTrue(contract_errors(replace))
        replace["spec"]["rollback"]["backupArtifact"] = _candidate()
        self.assertFalse(contract_errors(replace))

        create = workspace_write_intent()
        create["spec"]["rollback"]["backupArtifact"] = _candidate()
        self.assertTrue(contract_errors(create))

    def test_rollback_receipt_has_exact_terminal_shape(self) -> None:
        recovery = workspace_rollback_receipt()
        recovery["spec"]["status"] = "recovery-required"
        recovery["spec"].pop("restoredStateDigest")
        recovery["spec"]["errorRecordDigest"] = DIGEST
        self.assertFalse(contract_errors(recovery))

        invalid = workspace_rollback_receipt()
        invalid["spec"]["errorRecordDigest"] = DIGEST
        self.assertTrue(contract_errors(invalid))

    def test_schema_bundle_digest_includes_additive_m3_contracts(self) -> None:
        digest = schema_bundle_digest()
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, DIGEST)


if __name__ == "__main__":
    unittest.main()
