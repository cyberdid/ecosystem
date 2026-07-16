from __future__ import annotations

import os
import re
import sqlite3
import stat
import hashlib
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .broker import RepositoryReadBroker
from .digests import semantic_digest
from .errors import BrokerError, EcoRuntimeError, RuntimePolicyError, RuntimeStoreError
from .no_model_journal import NoModelJournal
from .policy import NO_MODEL_A1_PROFILE, NO_MODEL_WORKFLOWS, PolicyEngine
from .state_reducer import RunState
from .trust_diagnostics import verified_trust_bootstrap


_SAFE_CODE = re.compile(r"^ECO_[A-Z0-9_]{1,96}$")
_WORKFLOW = "wiki-health-check"


def _safe_code(exc: BaseException) -> str:
    code = getattr(exc, "code", "ECO_NO_MODEL_EXECUTION_FAILED")
    return code if isinstance(code, str) and _SAFE_CODE.fullmatch(code) else "ECO_NO_MODEL_EXECUTION_FAILED"


def _single_h1_outside_fences(content: str) -> bool:
    in_fence = False
    fence_marker: str | None = None
    headings = 0
    for line in content.splitlines():
        stripped = line.lstrip()
        marker = "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        if marker is not None:
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = None
            continue
        if not in_fence and line.startswith("# "):
            headings += 1
    return not in_fence and headings == 1


def _private_state_directory(root: Path) -> Path:
    configured = os.environ.get("ECO_RUNTIME_STATE_DIR")
    if not configured:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable")
    state_root = Path(configured)
    if not state_root.is_absolute():
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
    try:
        resolved = state_root.resolve(strict=True)
        resolved.relative_to(root)
    except ValueError:
        pass
    except OSError as exc:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable") from exc
    else:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
    if resolved != state_root:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
    try:
        status = state_root.lstat()
    except OSError as exc:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_UNAVAILABLE", "No-model state is unavailable") from exc
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
    if os.name == "posix" and (
        status.st_mode & 0o077
        or (hasattr(os, "geteuid") and status.st_uid != os.geteuid())
    ):
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_LOCATION_DENIED", "No-model state location is invalid")
    return state_root


def _state_integrity_key() -> bytes:
    value = os.environ.get("ECO_RUNTIME_JOURNAL_HMAC_KEY")
    if not value or len(value.encode("utf-8")) < 32:
        raise RuntimeStoreError("ECO_NO_MODEL_STATE_KEY_UNAVAILABLE", "No-model state key is unavailable")
    return value.encode("utf-8")


def _identifiers(
    snapshot_digest: str,
    config_digest: str,
    evidence_envelope_digest: str,
    execution_profile: str,
) -> dict[str, str]:
    seed = semantic_digest(
        {
            "profile": NO_MODEL_A1_PROFILE,
            "workflow": _WORKFLOW,
            "repositorySnapshot": snapshot_digest,
            "evidenceEnvelope": evidence_envelope_digest,
            "config": config_digest,
            "executionProfile": execution_profile,
        }
    )
    return {
        "run": f"wiki-health-{seed[:32]}",
        "request": f"wiki-health-request-{seed[:24]}",
        "plan": f"wiki-health-plan-{seed[:24]}",
        "decision": f"wiki-health-decision-{seed[:20]}",
    }


def _result(
    *,
    status: str,
    code: str,
    replayed: bool = False,
    read_count: int = 0,
    total_bytes: int = 0,
    snapshot_digest: str | None = None,
    broker_read_count: int = 0,
    run_id: str | None = None,
    checks: dict[str, str] | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"verifiedSnapshotEntries": read_count}
    if snapshot_digest is not None:
        evidence["repositorySnapshotDigest"] = snapshot_digest
    if run_id is not None:
        evidence["runId"] = run_id
    stable_report = {
        "profile": "wiki-health-integrity-report/v1",
        "workflow": _WORKFLOW,
        "status": status,
        "verifiedSnapshotEntries": read_count,
        "totalBytes": total_bytes,
        "repositorySnapshotDigest": snapshot_digest,
        "checks": checks
        or {
            "signedSnapshotIntegrity": "pass" if status == "succeeded" else "not-passed",
            "singleDocumentHeading": "pass" if status == "succeeded" else "not-passed",
            "distinctDocuments": "pass" if status == "succeeded" else "not-passed",
        },
    }
    return {
        "available": status == "succeeded",
        "workflow": _WORKFLOW,
        "profile": NO_MODEL_A1_PROFILE,
        "status": status,
        "code": code,
        "replayed": replayed,
        "execution": {
            "readCount": read_count,
            "brokerReadCount": broker_read_count,
            "totalBytes": total_bytes,
        },
        "report": {
            "profile": stable_report["profile"],
            "digest": semantic_digest(stable_report),
            "integrity": "pass" if status == "succeeded" else "not-passed",
            "checks": stable_report["checks"],
        },
        "evidence": evidence,
        "safety": {
            "repositoryMutation": "denied",
            "modelEgress": "not-used",
            "network": "not-used",
            "writeAuthority": "not-created",
            "adapter": "not-created",
            "content": "not-emitted",
        },
    }


def _execute_wiki_health_check(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
    evaluation_slot: int | None = None,
) -> dict[str, Any]:
    """Execute the one M4 no-model A1 workflow through policy, journal and broker.

    This API intentionally has no workflow/path/provider/adapter parameter.  It
    never persists or returns the untrusted document text received from the
    broker; only verified digest/length metadata is retained in its external
    private journal.
    """

    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if evaluation_slot is not None and evaluation_slot not in range(1, 6):
        raise ValueError("evaluation_slot must be one of the five fixed M4 slots")
    execution_profile = (
        "manual" if evaluation_slot is None else f"m4-evaluation-slot-{evaluation_slot}"
    )
    database_name = (
        "no-model-a1.sqlite3"
        if evaluation_slot is None
        else f"no-model-a1-evaluation-{evaluation_slot}.sqlite3"
    )
    broker_read_count = 0
    heading_structure_valid = True
    content_digests: set[str] = set()
    started_at = time.monotonic()
    try:
        root = Path(repository).resolve(strict=True)
        bootstrap = verified_trust_bootstrap(root, bundle, now=instant)
        policy = PolicyEngine(
            bundle,
            {},
            repository_snapshot=bootstrap.repository_snapshot_envelope,
            evidence_policies=bootstrap.evidence_policies,
            evidence_now=instant,
            repository_root_identity_digest=bootstrap.repository_root_identity_digest,
        )
        snapshot_digest = semantic_digest(bootstrap.repository_snapshot)
        identifiers = _identifiers(
            snapshot_digest,
            policy.config_digest,
            hashlib.sha256(bootstrap.repository_snapshot_envelope).hexdigest(),
            execution_profile,
        )
        run_request = {
            "apiVersion": "runtime.ai.ecosystem/v1alpha1",
            "kind": "NoModelRunRequest",
            "metadata": {
                "id": identifiers["request"],
                "createdAt": bootstrap.repository_snapshot["metadata"]["createdAt"],
                "actor": {"type": "automation", "id": "eco-cli"},
            },
            "spec": {"projectId": bundle["project"]["metadata"]["name"], "workflow": _WORKFLOW},
        }
        planning = policy.plan_no_model_run(
            run_request,
            run_id=identifiers["run"], plan_id=identifiers["plan"],
            decision_id=identifiers["decision"], now=instant,
        )
        if planning.plan is None or planning.decision["spec"]["effect"] != "allow":
            return _result(status="blocked", code=planning.decision["spec"]["reasonCodes"][0])
        duration_limit = planning.plan["spec"]["budget"]["maxDurationSeconds"]
        deadline_at = instant + timedelta(seconds=duration_limit)

        def observed_time() -> datetime:
            elapsed = max(0.0, time.monotonic() - started_at)
            return instant + timedelta(seconds=elapsed)

        def current_time() -> datetime:
            elapsed = max(0.0, time.monotonic() - started_at)
            candidate = instant + timedelta(seconds=elapsed)
            if candidate >= deadline_at:
                raise RuntimePolicyError(
                    "ECO_NO_MODEL_DEADLINE_EXCEEDED", "No-model deadline elapsed"
                )
            return candidate

        policy.activate_no_model_plan(planning.plan, planning.decision, now=current_time())
        state_root = _private_state_directory(root)
        with NoModelJournal(
            state_root / database_name, integrity_key=_state_integrity_key()
        ) as journal:
            current_time()
            # The first durable event records the immutable attempt origin,
            # not the later journal-open instant, so recovery cannot extend
            # a partially spent deadline.
            chain, replayed = journal.begin(planning.plan, now=instant)
            if replayed:
                first_event_time = chain.events()[0]["metadata"]["occurredAt"]
                deadline_at = datetime.fromisoformat(
                    first_event_time[:-1] + "+00:00"
                    if first_event_time.endswith("Z")
                    else first_event_time
                ) + timedelta(seconds=duration_limit)
            completed, total_bytes = journal.completed_summary(chain)
            completed_observations = journal.completed_observations(chain)
            content_digests = {digest for digest, _ in completed_observations}
            heading_structure_valid = all(
                heading_check == "pass" for _, heading_check in completed_observations
            )
            if chain.state == RunState.SUCCEEDED:
                return _result(
                    status="succeeded", code="ECO_NO_MODEL_WORKFLOW_SUCCEEDED", replayed=True,
                    read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                    broker_read_count=0, run_id=identifiers["run"],
                )
            if chain.state in {RunState.FAILED, RunState.DENIED, RunState.CANCELLED, RunState.EXHAUSTED}:
                return _result(
                    status="failed", code="ECO_NO_MODEL_REPLAY_TERMINAL", replayed=True,
                    read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                    broker_read_count=0, run_id=identifiers["run"],
                )
            with RepositoryReadBroker(
                root, bootstrap.repository_snapshot, maximum_file_bytes=bootstrap.maximum_file_bytes
            ) as broker:
                for index, path in enumerate(NO_MODEL_WORKFLOWS[_WORKFLOW], start=1):
                    request = {
                        "apiVersion": "runtime.ai.ecosystem/v1alpha1",
                        "kind": "NoModelReadRequest",
                        "metadata": {
                            "id": f"wiki-health-read-{identifiers['run'][-24:]}-{index}",
                            "runId": identifiers["run"],
                            "createdAt": bootstrap.repository_snapshot["metadata"]["createdAt"],
                        },
                        "spec": {
                            "planDigest": semantic_digest(planning.plan),
                            "workflow": _WORKFLOW,
                            "path": path,
                            "scopeSlot": f"slot-{index}",
                        },
                    }
                    request_digest = semantic_digest(request)
                    scope_marker = planning.plan["spec"]["workflow"]["scopeSlots"][index - 1]
                    phase = journal.read_phase(chain, request["metadata"]["id"])
                    if phase == "completed":
                        continue
                    if phase == "started":
                        code = "ECO_NO_MODEL_READ_OUTCOME_AMBIGUOUS"
                        journal.append(
                            chain,
                            "no-model.read.failed",
                            "runtime",
                            now=observed_time(),
                            subject_id=request["metadata"]["id"],
                            subject_digest=request_digest,
                            result_digest=semantic_digest({"code": code}),
                            reason_code=code,
                            scope_slot=scope_marker["slot"],
                            entry_digest=scope_marker["entryDigest"],
                        )
                        journal.append(chain, "run.failed", "runtime", now=observed_time())
                        completed, total_bytes = journal.completed_summary(chain)
                        return _result(
                            status="failed",
                            code=code,
                            replayed=True,
                            read_count=completed,
                            total_bytes=total_bytes,
                            snapshot_digest=snapshot_digest,
                            broker_read_count=0,
                            run_id=identifiers["run"],
                        )
                    if phase in {"failed", "denied"}:
                        journal.append(chain, "run.failed", "runtime", now=observed_time())
                        completed, total_bytes = journal.completed_summary(chain)
                        terminal_code = (
                            "ECO_NO_MODEL_READ_DENIED"
                            if phase == "denied"
                            else "ECO_NO_MODEL_READ_FAILED"
                        )
                        return _result(status="failed", code=terminal_code, replayed=replayed,
                                       read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                                       broker_read_count=broker_read_count, run_id=identifiers["run"])
                    if phase is None:
                        try:
                            current_time()
                        except RuntimePolicyError as exc:
                            code = _safe_code(exc)
                            journal.append(
                                chain,
                                "run.failed",
                                "runtime",
                                now=observed_time(),
                                result_digest=semantic_digest({"code": code}),
                                reason_code=code,
                            )
                            completed, total_bytes = journal.completed_summary(chain)
                            return _result(
                                status="failed",
                                code=code,
                                replayed=replayed,
                                read_count=completed,
                                total_bytes=total_bytes,
                                snapshot_digest=snapshot_digest,
                                broker_read_count=broker_read_count,
                                run_id=identifiers["run"],
                            )
                        journal.append(chain, "no-model.read.requested", "runtime", now=observed_time(),
                                       subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                       scope_slot=scope_marker["slot"],
                                       entry_digest=scope_marker["entryDigest"])
                        phase = "requested"
                    if phase in {"requested", "allowed"}:
                        try:
                            authority_time = current_time()
                            decision = policy.authorize_no_model_read(
                                planning.plan, request,
                                decision_id=f"wiki-health-read-decision-{identifiers['run'][-18:]}-{index}",
                                now=authority_time,
                            )
                        except RuntimePolicyError as exc:
                            code = _safe_code(exc)
                            journal.append(
                                chain,
                                "no-model.read.denied",
                                "policy",
                                now=observed_time(),
                                subject_id=request["metadata"]["id"],
                                subject_digest=request_digest,
                                result_digest=semantic_digest({"code": code}),
                                reason_code=code,
                                scope_slot=scope_marker["slot"],
                                entry_digest=scope_marker["entryDigest"],
                            )
                            journal.append(chain, "run.failed", "runtime", now=observed_time())
                            completed, total_bytes = journal.completed_summary(chain)
                            return _result(
                                status="blocked",
                                code=code,
                                replayed=replayed,
                                read_count=completed,
                                total_bytes=total_bytes,
                                snapshot_digest=snapshot_digest,
                                broker_read_count=broker_read_count,
                                run_id=identifiers["run"],
                            )
                        if decision["spec"]["effect"] != "allow":
                            journal.append(chain, "no-model.read.denied", "policy", now=observed_time(),
                                           subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                           result_digest=semantic_digest(decision),
                                           reason_code=decision["spec"]["reasonCodes"][0],
                                           scope_slot=scope_marker["slot"],
                                           entry_digest=scope_marker["entryDigest"])
                            journal.append(chain, "run.failed", "runtime", now=observed_time())
                            completed, total_bytes = journal.completed_summary(chain)
                            return _result(status="blocked", code=decision["spec"]["reasonCodes"][0], replayed=replayed,
                                           read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                                           broker_read_count=broker_read_count, run_id=identifiers["run"])
                        try:
                            policy.consume_decision(decision, request, now=current_time())
                        except RuntimePolicyError as exc:
                            code = _safe_code(exc)
                            journal.append(
                                chain,
                                "no-model.read.denied",
                                "policy",
                                now=observed_time(),
                                subject_id=request["metadata"]["id"],
                                subject_digest=request_digest,
                                result_digest=semantic_digest({"code": code}),
                                reason_code=code,
                                scope_slot=scope_marker["slot"],
                                entry_digest=scope_marker["entryDigest"],
                            )
                            journal.append(chain, "run.failed", "runtime", now=observed_time())
                            completed, total_bytes = journal.completed_summary(chain)
                            return _result(
                                status="blocked",
                                code=code,
                                replayed=replayed,
                                read_count=completed,
                                total_bytes=total_bytes,
                                snapshot_digest=snapshot_digest,
                                broker_read_count=broker_read_count,
                                run_id=identifiers["run"],
                            )
                        if phase == "requested":
                            journal.append(chain, "no-model.read.allowed", "policy", now=observed_time(),
                                           subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                           scope_slot=scope_marker["slot"],
                                           entry_digest=scope_marker["entryDigest"])
                    try:
                        current_time()
                        journal.append(
                            chain,
                            "no-model.read.started",
                            "runtime",
                            now=observed_time(),
                            subject_id=request["metadata"]["id"],
                            subject_digest=request_digest,
                            scope_slot=scope_marker["slot"],
                            entry_digest=scope_marker["entryDigest"],
                        )
                        current_time()
                        broker_read_count += 1
                        read = broker.read(path, maximum_bytes=bootstrap.maximum_file_bytes)
                        current_time()
                        heading_valid = read.byte_length > 0 and _single_h1_outside_fences(
                            read.untrusted_content
                        )
                        authority_time = current_time()
                        policy.assert_no_model_plan_current(
                            planning.plan, now=authority_time
                        )
                    except (BrokerError, RuntimePolicyError) as exc:
                        code = _safe_code(exc)
                        failure_producer = "broker" if isinstance(exc, BrokerError) else "runtime"
                        journal.append(chain, "no-model.read.failed", failure_producer, now=observed_time(),
                                       subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                       result_digest=semantic_digest({"code": code}), reason_code=code,
                                       scope_slot=scope_marker["slot"],
                                       entry_digest=scope_marker["entryDigest"])
                        journal.append(chain, "run.failed", "runtime", now=observed_time())
                        completed, total_bytes = journal.completed_summary(chain)
                        return _result(status="failed", code=code, replayed=replayed,
                                       read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                                       broker_read_count=broker_read_count, run_id=identifiers["run"])
                    heading_structure_valid = heading_structure_valid and heading_valid
                    content_digests.add(read.sha256)
                    if total_bytes + read.byte_length > planning.plan["spec"]["budget"]["maxInputBytes"]:
                        code = "ECO_NO_MODEL_INPUT_BUDGET_EXCEEDED"
                        journal.append(chain, "no-model.read.failed", "runtime", now=observed_time(),
                                       subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                       result_digest=semantic_digest({"code": code}), reason_code=code,
                                       scope_slot=scope_marker["slot"],
                                       entry_digest=scope_marker["entryDigest"])
                        journal.append(chain, "run.failed", "runtime", now=observed_time())
                        completed, total_bytes = journal.completed_summary(chain)
                        return _result(status="failed", code=code, replayed=replayed,
                                       read_count=completed, total_bytes=total_bytes,
                                       snapshot_digest=snapshot_digest,
                                       broker_read_count=broker_read_count,
                                       run_id=identifiers["run"])
                    current_time()
                    journal.append(chain, "no-model.read.completed", "broker", now=observed_time(),
                                   subject_id=request["metadata"]["id"], subject_digest=request_digest,
                                   result_digest=semantic_digest({"sha256": read.sha256, "byteLength": read.byte_length}),
                                   byte_count=read.byte_length,
                                   scope_slot=scope_marker["slot"],
                                   entry_digest=scope_marker["entryDigest"],
                                   content_digest=read.sha256,
                                   heading_check="pass" if heading_valid else "fail")
            try:
                current_time()
            except RuntimePolicyError as exc:
                code = _safe_code(exc)
                journal.append(
                    chain,
                    "run.failed",
                    "runtime",
                    now=observed_time(),
                    result_digest=semantic_digest({"code": code}),
                    reason_code=code,
                )
                completed, total_bytes = journal.completed_summary(chain)
                return _result(
                    status="failed",
                    code=code,
                    replayed=replayed,
                    read_count=completed,
                    total_bytes=total_bytes,
                    snapshot_digest=snapshot_digest,
                    broker_read_count=broker_read_count,
                    run_id=identifiers["run"],
                )
            checks = {
                "signedSnapshotIntegrity": "pass",
                "singleDocumentHeading": "pass" if heading_structure_valid else "fail",
                "distinctDocuments": "pass" if len(content_digests) == 3 else "fail",
            }
            if "fail" in checks.values():
                code = "ECO_WIKI_HEALTH_STRUCTURE_INVALID"
                journal.append(
                    chain,
                    "run.failed",
                    "runtime",
                    now=observed_time(),
                    result_digest=semantic_digest(checks),
                    reason_code=code,
                )
                completed, total_bytes = journal.completed_summary(chain)
                return _result(
                    status="failed",
                    code=code,
                    replayed=replayed,
                    read_count=completed,
                    total_bytes=total_bytes,
                    snapshot_digest=snapshot_digest,
                    broker_read_count=broker_read_count,
                    run_id=identifiers["run"],
                    checks=checks,
                )
            try:
                policy.assert_no_model_plan_current(planning.plan, now=current_time())
                success_time = current_time()
            except RuntimePolicyError as exc:
                code = _safe_code(exc)
                journal.append(
                    chain,
                    "run.failed",
                    "runtime",
                    now=observed_time(),
                    result_digest=semantic_digest({"code": code}),
                    reason_code=code,
                )
                completed, total_bytes = journal.completed_summary(chain)
                return _result(
                    status="failed",
                    code=code,
                    replayed=replayed,
                    read_count=completed,
                    total_bytes=total_bytes,
                    snapshot_digest=snapshot_digest,
                    broker_read_count=broker_read_count,
                    run_id=identifiers["run"],
                )
            journal.append(
                chain, "no-model.workflow.succeeded", "runtime", now=success_time
            )
            completed, total_bytes = journal.completed_summary(chain)
            return _result(status="succeeded", code="ECO_NO_MODEL_WORKFLOW_SUCCEEDED", replayed=replayed,
                           read_count=completed, total_bytes=total_bytes, snapshot_digest=snapshot_digest,
                           broker_read_count=broker_read_count, run_id=identifiers["run"])
    except (EcoRuntimeError, OSError, sqlite3.Error) as exc:
        return _result(status="blocked", code=_safe_code(exc))


def execute_wiki_health_check(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Public fixed manual command with no caller-controlled workflow or state slot."""

    return _execute_wiki_health_check(repository, bundle, now=now)
