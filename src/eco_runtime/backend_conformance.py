from __future__ import annotations

import hashlib
import os
import platform as host_platform
import secrets
import shutil
import socket
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from eco_cli.platform_profiles import profile_document_digest, validate_platform_profile

from .contracts import API_VERSION, validate_record
from .digests import semantic_digest
from .errors import RuntimePolicyError
from .isolation import (
    IsolationContract,
    LaunchRequest,
    LinuxNamespaceLauncher,
    MappingCredentialResolver,
)


SUITE_ID = "linux-namespace-boundary"
SUITE_VERSION = "1"
PROBE_IDS = (
    "clean-environment-and-fs-boundary",
    "network-namespace-deny",
    "output-and-deadline-bounds",
    "read-only-workdir",
    "stdin-closed",
)
OBSERVED_CAPABILITIES = (
    "backend.clean-environment",
    "backend.landlock-workdir-boundary",
    "backend.network-namespace-deny",
    "backend.output-deadline-bounded",
    "backend.read-only-workdir",
    "backend.stdin-closed",
)
SUITE_DIGEST = semantic_digest(
    {
        "id": SUITE_ID,
        "version": SUITE_VERSION,
        "probeIds": list(PROBE_IDS),
        "capabilities": list(OBSERVED_CAPABILITIES),
        "network": "literal-loopback-sentinel-only",
        "credentials": "none",
        "output": "content-free-results-only",
    }
)
_DIGEST_CHARS = frozenset("0123456789abcdef")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _implementation_digests() -> tuple[str, str]:
    runner = Path(__file__).resolve(strict=True)
    isolation = runner.with_name("isolation.py")
    worker = runner.with_name("_isolation_worker.py")
    return _file_digest(runner), semantic_digest(
        {
            "isolation": _file_digest(isolation),
            "worker": _file_digest(worker),
        }
    )


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimePolicyError("ECO_CLOCK_INVALID", "Conformance clock is invalid")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_digest(value: str, code: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _DIGEST_CHARS for character in value)
    ):
        raise RuntimePolicyError(code, "Conformance binding is invalid")


def _platform_facts(
    profile: Mapping[str, Any], system: str, machine: str, live_context: str
) -> tuple[str, str, str, str, bool, str | None]:
    profile_id = str(profile["metadata"]["id"])
    family = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(
        system, "unsupported"
    )
    architecture = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(
        machine.lower(), "other"
    )
    context = {
        "wsl": "wsl",
        "container": "container",
        "hosted-ci": "hosted-ci",
    }.get(profile_id, "native")
    detected = profile["spec"]["classification"]["detected"]
    supported = (
        profile_id in {"linux-native", "wsl"}
        and detected == profile_id
        and profile["spec"]["operatingSystem"]["family"] == "linux"
        and family == "linux"
        and architecture in {"x86_64", "aarch64"}
        and context == live_context
    )
    code = (
        None
        if supported
        else (
            "ECO_BACKEND_CONTEXT_MISMATCH"
            if family == "linux" and context != live_context
            else "ECO_BACKEND_PLATFORM_UNSUPPORTED"
        )
    )
    return profile_id, family, architecture, context, supported, code


def _live_context(system: str) -> str:
    if system != "Linux":
        return "native"
    release = host_platform.release().lower()
    signals: list[str] = []
    if "microsoft" in release or "wsl" in release:
        signals.append("wsl")
    if Path("/.dockerenv").is_file() or Path("/run/.containerenv").is_file():
        signals.append("container")
    if any(
        os.environ.get(name)
        for name in (
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "BUILDKITE",
            "CIRCLECI",
            "TF_BUILD",
        )
    ):
        signals.append("hosted-ci")
    return signals[0] if len(signals) == 1 else ("native" if not signals else "ambiguous")


def _probe_result(probe_id: str, status: str, code: str) -> dict[str, str]:
    return {
        "id": probe_id,
        "status": status,
        "evidenceDigest": semantic_digest(
            {"probeId": probe_id, "status": status, "code": code}
        ),
    }


def _record(
    *,
    profile: Mapping[str, Any],
    profile_id: str,
    family: str,
    architecture: str,
    context: str,
    distribution_manifest_digest: str,
    backend_instance_digest: str,
    runner_digest: str,
    implementation_digest: str,
    now: datetime,
    status: str,
    probes: list[dict[str, str]],
    deviation_codes: list[str],
) -> dict[str, Any]:
    document = {
        "apiVersion": API_VERSION,
        "kind": "PlatformBackendConformanceProfile",
        "metadata": {
            "id": f"{profile_id}-{SUITE_ID}-{SUITE_DIGEST[:16]}",
            "platformProfileId": profile_id,
            "testedAt": _timestamp(now),
            "validUntil": _timestamp(now + timedelta(hours=1)),
        },
        "spec": {
            "platformProfileDigest": profile["metadata"]["profileDigest"],
            "platform": {
                "id": profile_id,
                "operatingSystem": family,
                "architecture": architecture,
                "context": context,
            },
            "distributionManifestDigest": distribution_manifest_digest,
            "backend": {
                "id": "linux-namespace-landlock",
                "version": "1",
                "implementationDigest": implementation_digest,
                "instanceDigest": backend_instance_digest,
            },
            "runnerDigest": runner_digest,
            "suite": {
                "id": SUITE_ID,
                "version": SUITE_VERSION,
                "digest": SUITE_DIGEST,
                "probeIds": list(PROBE_IDS),
            },
            "status": status,
            "observedCapabilities": (
                list(OBSERVED_CAPABILITIES) if status == "pass" else []
            ),
            "probes": probes,
            "deviationCodes": sorted(set(deviation_codes)),
            "safety": {
                "authenticated": False,
                "authorityCreated": False,
                "runtimeConsumed": False,
                "projectMutation": False,
                "rawOutputPersisted": False,
            },
        },
    }
    return validate_record(document)


def _validate_test_root(root: Path, repository: Path) -> Path:
    if not root.is_absolute():
        raise RuntimePolicyError("ECO_CONFORMANCE_ROOT_INVALID", "Test root is invalid")
    try:
        status = root.lstat()
        resolved = root.resolve(strict=True)
        repo = repository.resolve(strict=True)
        home = Path.home().resolve(strict=True)
        package = Path(__file__).resolve(strict=True).parents[2]
    except OSError as exc:
        raise RuntimePolicyError("ECO_CONFORMANCE_ROOT_INVALID", "Test root is invalid") from exc
    protected = (repo, package, *((home,) if os.name == "posix" else ()))
    overlap = any(
        resolved == item or resolved in item.parents or item in resolved.parents
        for item in protected
    )
    if (
        not stat.S_ISDIR(status.st_mode)
        or resolved != root
        or overlap
        or any(root.iterdir())
        or (os.name == "posix" and (status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) != 0o700))
        or getattr(status, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ):
        raise RuntimePolicyError("ECO_CONFORMANCE_ROOT_INVALID", "Test root is invalid")
    return resolved


def run_backend_conformance(
    platform_profile: Mapping[str, Any],
    *,
    test_root: Path,
    repository: Path,
    distribution_manifest_digest: str,
    backend_instance_digest: str,
    suite_digest: str,
    active: bool,
    now: datetime,
    launcher: LinuxNamespaceLauncher | None = None,
    host_system: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    """Run the fixed synthetic suite; return an unsigned, non-authorizing record."""

    if active is not True:
        raise RuntimePolicyError("ECO_CONFORMANCE_CONFIRMATION_REQUIRED", "Active confirmation is required")
    if not isinstance(platform_profile, dict):
        raise RuntimePolicyError(
            "ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID", "Platform profile is invalid"
        )
    if suite_digest != SUITE_DIGEST:
        raise RuntimePolicyError("ECO_CONFORMANCE_SUITE_MISMATCH", "Conformance suite is invalid")
    _require_digest(distribution_manifest_digest, "ECO_CONFORMANCE_DISTRIBUTION_INVALID")
    _require_digest(backend_instance_digest, "ECO_CONFORMANCE_BACKEND_INSTANCE_INVALID")
    profile = dict(platform_profile)
    if validate_platform_profile(profile):
        raise RuntimePolicyError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID", "Platform profile is invalid")
    if profile["metadata"]["profileDigest"] != profile_document_digest(profile):
        raise RuntimePolicyError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID", "Platform profile is invalid")
    current = now.astimezone(timezone.utc) if now.tzinfo is not None else None
    if current is None:
        raise RuntimePolicyError("ECO_CLOCK_INVALID", "Conformance clock is invalid")

    runner_digest, implementation_digest = _implementation_digests()
    system = host_system or host_platform.system()
    declared_context = {
        "wsl": "wsl",
        "container": "container",
        "hosted-ci": "hosted-ci",
    }.get(profile["metadata"]["id"], "native")
    observed_context = declared_context if launcher is not None else _live_context(system)
    profile_id, family, architecture, context, supported, unsupported_code = _platform_facts(
        profile,
        system,
        machine or host_platform.machine(),
        observed_context,
    )
    if not supported:
        return _record(
            profile=profile,
            profile_id=profile_id,
            family=family,
            architecture=architecture,
            context=context,
            distribution_manifest_digest=distribution_manifest_digest,
            backend_instance_digest=backend_instance_digest,
            runner_digest=runner_digest,
            implementation_digest=implementation_digest,
            now=current,
            status="unsupported",
            probes=[_probe_result(item, "not-run", unsupported_code or "ECO_BACKEND_PLATFORM_UNSUPPORTED") for item in PROBE_IDS],
            deviation_codes=[unsupported_code or "ECO_BACKEND_PLATFORM_UNSUPPORTED"],
        )

    root = _validate_test_root(Path(test_root), Path(repository))
    backend = launcher or LinuxNamespaceLauncher()
    try:
        backend._preflight()
    except RuntimePolicyError:
        return _record(
            profile=profile,
            profile_id=profile_id,
            family=family,
            architecture=architecture,
            context=context,
            distribution_manifest_digest=distribution_manifest_digest,
            backend_instance_digest=backend_instance_digest,
            runner_digest=runner_digest,
            implementation_digest=implementation_digest,
            now=current,
            status="unsupported",
            probes=[_probe_result(item, "not-run", "ECO_BACKEND_CONTROL_UNAVAILABLE") for item in PROBE_IDS],
            deviation_codes=["ECO_BACKEND_CONTROL_UNAVAILABLE"],
        )

    child = root / f"eco-conformance-{secrets.token_hex(16)}"
    work = child / "work"
    outside = child / "outside-canary"
    try:
        child.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        outside.write_bytes(b"synthetic-conformance-canary")
        os.chmod(outside, 0o600)
    except Exception:
        try:
            if child.exists():
                shutil.rmtree(child)
        except Exception:
            pass
        raise RuntimePolicyError(
            "ECO_CONFORMANCE_SETUP_FAILED", "Synthetic test root setup failed"
        ) from None
    python = str(Path(getattr(backend, "_python", sys.executable)).resolve(strict=True))

    def launch(source: str, *, access: str = "read-write", arguments: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
        contract = IsolationContract(
            network_mode="deny",
            allowed_network_endpoints=(),
            credential_bindings=(),
            executable_allowlist=(python,),
            working_directory_access=access,
            timeout_seconds=2,
            maximum_stdout_bytes=64,
            maximum_stderr_bytes=64,
        )
        return backend.launch(
            LaunchRequest(python, ("-c", source, *arguments), str(work)),
            contract,
            credential_resolver=MappingCredentialResolver({}),
        )

    outcomes: list[dict[str, str]] = []
    deviations: list[str] = []

    def record(probe_id: str, passed: bool, code: str) -> None:
        status = "pass" if passed else "fail"
        outcomes.append(_probe_result(probe_id, status, code))
        if not passed:
            deviations.append(code)

    try:
        try:
            canary_name = "ECO_CONFORMANCE_HOST_CANARY"
            previous_canary = os.environ.get(canary_name)
            os.environ[canary_name] = "must-not-cross"
            try:
                result = launch(
                    "# ECO_PROBE:clean-environment-and-fs-boundary\n"
                    "import os,pathlib,sys\n"
                    "try:\n pathlib.Path(sys.argv[1]).read_bytes(); outside=True\n"
                    "except (PermissionError,FileNotFoundError):\n outside=False\n"
                    "expected={'PATH','LANG','LC_ALL','HOME','TMPDIR'}\n"
                    "clean=set(os.environ)==expected and os.environ.get('ECO_CONFORMANCE_HOST_CANARY') is None and os.environ.get('HOME')==os.getcwd() and os.environ.get('TMPDIR')==os.getcwd()\n"
                    "pathlib.Path('created').write_bytes(b'ok')\n"
                    "print('ECO_BACKEND_PROBE_PASS' if clean and not outside else 'ECO_BACKEND_PROBE_FAIL')\n",
                    arguments=(str(outside),),
                )
            finally:
                if previous_canary is None:
                    os.environ.pop(canary_name, None)
                else:
                    os.environ[canary_name] = previous_canary
            record("clean-environment-and-fs-boundary", result.returncode == 0 and result.stdout.strip() == b"ECO_BACKEND_PROBE_PASS", "ECO_PROBE_CLEAN_FS_FAILED")
        except Exception:
            record("clean-environment-and-fs-boundary", False, "ECO_PROBE_CLEAN_FS_FAILED")

        try:
            result = launch(
                "# ECO_PROBE:read-only-workdir\n"
                "from pathlib import Path\n"
                "try:\n Path('denied').write_bytes(b'no'); print('ECO_BACKEND_PROBE_FAIL')\n"
                "except PermissionError:\n print('ECO_BACKEND_PROBE_PASS')\n",
                access="read-only",
            )
            record("read-only-workdir", result.returncode == 0 and result.stdout.strip() == b"ECO_BACKEND_PROBE_PASS", "ECO_PROBE_READ_ONLY_FAILED")
        except Exception:
            record("read-only-workdir", False, "ECO_PROBE_READ_ONLY_FAILED")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            result = launch(
                "# ECO_PROBE:network-namespace-deny\n"
                "import socket,sys\n"
                "s=socket.socket();s.settimeout(.5)\n"
                "try:\n s.connect(('127.0.0.1',int(sys.argv[1])));print('ECO_BACKEND_PROBE_FAIL')\n"
                "except OSError:\n print('ECO_BACKEND_PROBE_PASS')\n",
                arguments=(str(port),),
            )
            record("network-namespace-deny", result.returncode == 0 and result.stdout.strip() == b"ECO_BACKEND_PROBE_PASS", "ECO_PROBE_NETWORK_FAILED")
        except Exception:
            record("network-namespace-deny", False, "ECO_PROBE_NETWORK_FAILED")
        finally:
            listener.close()

        try:
            result = launch(
                "# ECO_PROBE:stdin-closed\nimport sys\nprint('ECO_BACKEND_PROBE_PASS' if not sys.stdin.buffer.read() else 'ECO_BACKEND_PROBE_FAIL')\n"
            )
            record("stdin-closed", result.returncode == 0 and result.stdout.strip() == b"ECO_BACKEND_PROBE_PASS", "ECO_PROBE_STDIN_FAILED")
        except Exception:
            record("stdin-closed", False, "ECO_PROBE_STDIN_FAILED")

        bounded = False
        timed = False
        try:
            launch("# ECO_PROBE:output-limit\nimport sys\nsys.stdout.write('x'*65)\n")
        except RuntimePolicyError as exc:
            bounded = exc.code == "ECO_ISOLATION_OUTPUT_LIMIT"
        except Exception:
            bounded = False
        try:
            launch("# ECO_PROBE:deadline\nimport time\ntime.sleep(5)\n")
        except RuntimePolicyError as exc:
            timed = exc.code == "ECO_ISOLATION_TIMEOUT"
        except Exception:
            timed = False
        record("output-and-deadline-bounds", bounded and timed, "ECO_PROBE_BOUNDS_FAILED")
    finally:
        try:
            shutil.rmtree(child)
        except Exception:
            raise RuntimePolicyError(
                "ECO_CONFORMANCE_CLEANUP_FAILED", "Synthetic test cleanup failed"
            ) from None

    outcomes.sort(key=lambda item: PROBE_IDS.index(item["id"]))
    status = "pass" if all(item["status"] == "pass" for item in outcomes) else "fail"
    return _record(
        profile=profile,
        profile_id=profile_id,
        family=family,
        architecture=architecture,
        context=context,
        distribution_manifest_digest=distribution_manifest_digest,
        backend_instance_digest=backend_instance_digest,
        runner_digest=runner_digest,
        implementation_digest=implementation_digest,
        now=current,
        status=status,
        probes=outcomes,
        deviation_codes=deviations,
    )


__all__ = [
    "OBSERVED_CAPABILITIES",
    "PROBE_IDS",
    "SUITE_DIGEST",
    "SUITE_ID",
    "run_backend_conformance",
]
