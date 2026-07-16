from __future__ import annotations

import re
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifact_store import ContentAddressedArtifactStore
from .broker import RepositoryReadBroker
from .errors import ContractValidationError, EcoRuntimeError
from .evidence import LinuxRepositorySnapshotGenerator, SnapshotEntryClassification
from .orchestrator import EmbeddedOrchestrator, RuntimeCapabilities
from .policy import PolicyEngine
from .store import SQLiteRuntimeStore


_ISSUERS = {
    "policy": "runtime-doctor-policy",
    "broker": "runtime-doctor-broker",
    "runtime": "runtime-doctor-runtime",
    "adapter": "runtime-doctor-adapter",
}
_SAFE_CODE = re.compile(r"^ECO_[A-Z0-9_]{1,96}$")


def _ready(component: str, code: str) -> dict[str, str]:
    return {"component": component, "status": "ready", "code": code}


def _failed(component: str, exc: BaseException) -> dict[str, str]:
    if isinstance(exc, ContractValidationError):
        code = "ECO_RUNTIME_CONTRACT_INVALID"
    elif isinstance(exc, EcoRuntimeError):
        code = getattr(exc, "code", "ECO_RUNTIME_PROBE_FAILED")
    else:
        code = "ECO_RUNTIME_PROBE_FAILED"
    if not isinstance(code, str) or _SAFE_CODE.fullmatch(code) is None:
        code = "ECO_RUNTIME_PROBE_FAILED"
    return {"component": component, "status": "blocked", "code": code}


def runtime_diagnostics(
    repository: str | Path,
    bundle: dict[str, dict[str, Any]],
    *,
    probe_path: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Probe the installed embedded composition root without enabling a run.

    The probe creates only short-lived private state outside the governed
    repository. Keys are generated in memory, no provider is contacted, and no
    model or write authority is created. Exception messages are intentionally
    excluded from the result because they may contain repository-controlled
    text or platform details.
    """

    root = Path(repository).resolve(strict=True)
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    checks: list[dict[str, str]] = []

    try:
        policy = PolicyEngine(bundle, {})
    except Exception as exc:
        checks.append(_failed("policy", exc))
        return _result(checks)
    checks.append(_ready("policy", "ECO_RUNTIME_POLICY_READY"))

    capabilities = RuntimeCapabilities(
        policy=object(), broker=object(), runtime=object(), adapter=object()
    )
    try:
        with tempfile.TemporaryDirectory(prefix="eco-runtime-doctor-") as temporary:
            private_root = Path(temporary)
            artifacts = ContentAddressedArtifactStore(
                private_root / "artifacts",
                proof_key=secrets.token_bytes(32),
                key_id="runtime-doctor-artifact-key",
                forbidden_root=root,
            )
            try:
                store = SQLiteRuntimeStore(
                    private_root / "state" / "runtime.db",
                    hmac_key=secrets.token_bytes(32),
                    path_hmac_key=secrets.token_bytes(32),
                    key_id="runtime-doctor-store-key",
                    policy_capability=capabilities.policy,
                    broker_capability=capabilities.broker,
                    runtime_capability=capabilities.runtime,
                    adapter_capability=capabilities.adapter,
                    producer_issuers=_ISSUERS,
                    forbidden_root=root,
                    artifact_store=artifacts,
                )
                try:
                    store.verify()
                    checks.append(_ready("store", "ECO_RUNTIME_STORE_READY"))

                    classification = SnapshotEntryClassification(
                        data_class="D0",
                        trust="P1",
                        classification_authority="operator",
                    )
                    with LinuxRepositorySnapshotGenerator(root) as generator:
                        snapshot = generator.generate(
                            snapshot_id="runtime-doctor-snapshot",
                            project_id=bundle["project"]["metadata"]["name"],
                            issuer_type="runtime",
                            issuer_id="runtime-doctor",
                            snapshot_trust="P1",
                            classifications={probe_path: classification},
                            now=instant,
                        )
                    checks.append(_ready("snapshot", "ECO_RUNTIME_SNAPSHOT_READY"))

                    with RepositoryReadBroker(root, snapshot) as broker:
                        checks.append(_ready("broker", "ECO_RUNTIME_BROKER_READY"))
                        EmbeddedOrchestrator(
                            store,
                            broker,
                            artifacts,
                            policy,
                            capabilities=capabilities,
                            owner_id="runtime-doctor",
                        )
                        checks.append(
                            _ready("orchestrator", "ECO_RUNTIME_ORCHESTRATOR_READY")
                        )
                finally:
                    store.close()
            finally:
                artifacts.close()
    except Exception as exc:
        completed = {item["component"] for item in checks}
        component = next(
            name
            for name in ("store", "snapshot", "broker", "orchestrator")
            if name not in completed
        )
        checks.append(_failed(component, exc))

    return _result(checks)


def _result(checks: list[dict[str, str]]) -> dict[str, Any]:
    available = (
        {item["component"] for item in checks if item["status"] == "ready"}
        == {"policy", "store", "snapshot", "broker", "orchestrator"}
    )
    return {
        "available": available,
        "executionReady": False,
        "mode": "embedded-read-only-preflight",
        "checks": checks,
        "execution": {
            "status": "blocked",
            "code": "ECO_RUNTIME_TRUST_BOOTSTRAP_REQUIRED",
        },
        "safety": {
            "repositoryMutation": "denied",
            "modelEgress": "not-used",
            "writeAuthority": "not-created",
            "probeKeys": "ephemeral",
        },
    }
