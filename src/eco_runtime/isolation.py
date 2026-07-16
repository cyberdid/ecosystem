from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from .digests import canonical_json
from .errors import RuntimePolicyError


ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
REFERENCE_RE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])$")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_SECRET_BYTES = 65_536
MAX_ARGUMENT_BYTES = 65_536
DEFAULT_CAPTURE_BYTES = 1_048_576
MAX_CAPTURE_BYTES = 16_777_216


@dataclass(frozen=True)
class NetworkEndpoint:
    host: str
    port: int
    protocol: str = "tcp"

    def __post_init__(self) -> None:
        if HOST_RE.fullmatch(self.host) is None or not 1 <= self.port <= 65_535:
            raise ValueError("network endpoint is invalid")
        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("network endpoint protocol is invalid")


@dataclass(frozen=True)
class CredentialBinding:
    environment_name: str
    reference: str

    def __post_init__(self) -> None:
        if ENVIRONMENT_NAME_RE.fullmatch(self.environment_name) is None:
            raise ValueError("credential environment name is invalid")
        if REFERENCE_RE.fullmatch(self.reference) is None:
            raise ValueError("credential reference must be an opaque secret:// reference")


@dataclass(frozen=True)
class IsolationContract:
    network_mode: str
    allowed_network_endpoints: tuple[NetworkEndpoint, ...]
    credential_bindings: tuple[CredentialBinding, ...]
    executable_allowlist: tuple[str, ...]
    working_directory_access: str = "read-only"
    timeout_seconds: int = 30
    maximum_stdout_bytes: int = DEFAULT_CAPTURE_BYTES
    maximum_stderr_bytes: int = DEFAULT_CAPTURE_BYTES

    def __post_init__(self) -> None:
        if self.network_mode not in {"deny", "allowlist"}:
            raise ValueError("network mode is invalid")
        if self.network_mode == "deny" and self.allowed_network_endpoints:
            raise ValueError("deny network mode cannot contain endpoints")
        if self.network_mode == "allowlist" and not self.allowed_network_endpoints:
            raise ValueError("allowlist network mode requires endpoints")
        if len(set(self.allowed_network_endpoints)) != len(self.allowed_network_endpoints):
            raise ValueError("network endpoint allowlist contains duplicates")
        names = [item.environment_name for item in self.credential_bindings]
        references = [item.reference for item in self.credential_bindings]
        if len(set(names)) != len(names) or len(set(references)) != len(references):
            raise ValueError("credential allowlist contains duplicates")
        if not self.executable_allowlist:
            raise ValueError("executable allowlist cannot be empty")
        resolved: list[str] = []
        for executable in self.executable_allowlist:
            path = Path(executable)
            if not path.is_absolute():
                raise ValueError("allowlisted executable must be absolute")
            resolved.append(str(path.resolve(strict=False)))
        if len(set(resolved)) != len(resolved):
            raise ValueError("executable allowlist contains aliases or duplicates")
        if self.working_directory_access not in {"read-only", "read-write"}:
            raise ValueError("working directory access is invalid")
        if not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("isolation timeout is invalid")
        if any(
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 0 <= limit <= MAX_CAPTURE_BYTES
            for limit in (self.maximum_stdout_bytes, self.maximum_stderr_bytes)
        ):
            raise ValueError("isolation output limit is invalid")


@dataclass(frozen=True)
class LaunchRequest:
    executable: str
    arguments: tuple[str, ...]
    working_directory: str

    def __post_init__(self) -> None:
        executable = Path(self.executable)
        workdir = Path(self.working_directory)
        if not executable.is_absolute() or not workdir.is_absolute():
            raise ValueError("launch paths must be absolute")
        if any(
            not isinstance(argument, str)
            or "\x00" in argument
            or len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES
            for argument in self.arguments
        ):
            raise ValueError("launch argument is invalid")


@dataclass(frozen=True)
class LaunchResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CredentialResolver(Protocol):
    def resolve(self, reference: str) -> str:
        ...


class MappingCredentialResolver:
    """Test/local resolver. Mapping values must not be persisted or logged."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = copy.deepcopy(dict(values))

    def resolve(self, reference: str) -> str:
        if reference not in self._values:
            raise RuntimePolicyError(
                "ECO_CREDENTIAL_UNAVAILABLE", "Allowlisted credential is unavailable"
            ) from None
        return self._values[reference]


class LinuxNamespaceLauncher:
    """Linux/WSL untrusted-agent backend: namespaces + Landlock + clean env.

    This backend intentionally supports network deny only. Endpoint allowlists
    and credential-bearing processes require separately proven backends and
    fail closed here.
    """

    def __init__(
        self,
        *,
        unshare_executable: str = "/usr/bin/unshare",
        python_executable: str | None = None,
    ) -> None:
        self._unshare = str(Path(unshare_executable).resolve(strict=False))
        self._python = str(Path(python_executable or sys.executable).resolve(strict=True))
        self._worker = str(Path(__file__).with_name("_isolation_worker.py").resolve(strict=True))

    def _preflight(self) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimePolicyError("ECO_ISOLATION_UNSUPPORTED", "Linux isolation backend is required")
        if not Path(self._unshare).is_file() or not os.access(self._unshare, os.X_OK):
            raise RuntimePolicyError("ECO_ISOLATION_UNSUPPORTED", "unshare backend is unavailable")
        probe = subprocess.run(
            [
                self._unshare,
                "--user",
                "--map-root-user",
                "--net",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--mount-proc",
                "--",
                self._python,
                self._worker,
                "--probe",
            ],
            env={"PATH": SAFE_PATH, "LANG": "C.UTF-8"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        if probe.returncode != 0:
            raise RuntimePolicyError(
                "ECO_ISOLATION_UNSUPPORTED", "Required namespace or Landlock control is unavailable"
            )

    @staticmethod
    def _resolve_credentials(
        bindings: tuple[CredentialBinding, ...], resolver: CredentialResolver
    ) -> dict[str, str]:
        values: dict[str, str] = {}
        for binding in bindings:
            unavailable = False
            try:
                value = resolver.resolve(binding.reference)
            except Exception:
                unavailable = True
                value = None
            if unavailable:
                raise RuntimePolicyError(
                    "ECO_CREDENTIAL_UNAVAILABLE", "Allowlisted credential could not be resolved"
                ) from None
            if (
                not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > MAX_SECRET_BYTES
            ):
                raise RuntimePolicyError(
                    "ECO_CREDENTIAL_INVALID", "Resolved credential has an invalid value shape"
                )
            values[binding.environment_name] = value
        return values

    @staticmethod
    def _bounded_reader(
        stream: object,
        *,
        limit: int,
        chunks: list[bytes],
        exceeded: threading.Event,
    ) -> None:
        descriptor = stream.fileno()  # type: ignore[attr-defined]
        total = 0
        try:
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    return
                remaining = limit - total
                if len(chunk) > remaining:
                    if remaining > 0:
                        chunks.append(chunk[:remaining])
                    exceeded.set()
                    return
                chunks.append(chunk)
                total += len(chunk)
        except OSError:
            return

    @staticmethod
    def _stop(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def launch(
        self,
        request: LaunchRequest,
        contract: IsolationContract,
        *,
        credential_resolver: CredentialResolver,
    ) -> LaunchResult:
        if contract.credential_bindings:
            raise RuntimePolicyError(
                "ECO_CREDENTIAL_BINDINGS_DENIED",
                "Untrusted-agent processes cannot receive credentials",
            )
        if contract.network_mode != "deny" or contract.allowed_network_endpoints:
            raise RuntimePolicyError(
                "ECO_NETWORK_ALLOWLIST_UNSUPPORTED",
                "This backend cannot enforce endpoint network allowlists",
            )
        executable = str(Path(request.executable).resolve(strict=True))
        allowlist = {str(Path(item).resolve(strict=True)) for item in contract.executable_allowlist}
        if executable not in allowlist or not os.access(executable, os.X_OK):
            raise RuntimePolicyError("ECO_EXECUTABLE_DENIED", "Executable is not allowlisted")
        workdir = Path(request.working_directory).resolve(strict=True)
        if not workdir.is_dir():
            raise RuntimePolicyError("ECO_WORKDIR_INVALID", "Working directory is invalid")
        # Reject invalid/unimplemented requests before probing optional kernel
        # controls.  This makes the policy error deterministic on every host;
        # a valid launch still fails closed when the isolation profile is absent.
        self._preflight()
        configuration = canonical_json(
            {
                "command": [executable, *request.arguments],
                "workingDirectory": str(workdir),
                "workingDirectoryAccess": contract.working_directory_access,
            }
        )
        environment = {
            "PATH": SAFE_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(workdir),
            "TMPDIR": str(workdir),
            "ECO_ISOLATION_CONFIG": configuration,
        }
        command = [
            self._unshare,
            "--user",
            "--map-root-user",
            "--net",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--mount-proc",
            "--",
            self._python,
            self._worker,
            "--run",
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=workdir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, ValueError):
            raise RuntimePolicyError(
                "ECO_ISOLATION_SETUP_FAILED", "OS isolation process could not start"
            ) from None
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen invariant
            self._stop(process)
            raise RuntimePolicyError("ECO_ISOLATION_SETUP_FAILED", "OS isolation setup failed closed")

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_exceeded = threading.Event()
        stderr_exceeded = threading.Event()
        readers = (
            threading.Thread(
                target=self._bounded_reader,
                kwargs={
                    "stream": process.stdout,
                    "limit": contract.maximum_stdout_bytes,
                    "chunks": stdout_chunks,
                    "exceeded": stdout_exceeded,
                },
                daemon=True,
            ),
            threading.Thread(
                target=self._bounded_reader,
                kwargs={
                    "stream": process.stderr,
                    "limit": contract.maximum_stderr_bytes,
                    "chunks": stderr_chunks,
                    "exceeded": stderr_exceeded,
                },
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + contract.timeout_seconds
        timed_out = False
        while process.poll() is None:
            if stdout_exceeded.is_set() or stderr_exceeded.is_set():
                self._stop(process)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                self._stop(process)
                break
            time.sleep(0.01)
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):  # pragma: no cover - defensive pipe guard
            self._stop(process)
            process.stdout.close()
            process.stderr.close()
            raise RuntimePolicyError("ECO_ISOLATION_SETUP_FAILED", "OS isolation output pipe failed")
        process.stdout.close()
        process.stderr.close()
        if stdout_exceeded.is_set() or stderr_exceeded.is_set():
            raise RuntimePolicyError(
                "ECO_ISOLATION_OUTPUT_LIMIT", "Isolated process exceeded output limit"
            )
        if timed_out:
            raise RuntimePolicyError(
                "ECO_ISOLATION_TIMEOUT", "Isolated process exceeded deadline"
            )
        stdout = b"".join(stdout_chunks)
        stderr = b"".join(stderr_chunks)
        if process.returncode == 125 and stderr.startswith(b"ECO_ISOLATION_SETUP_FAILED"):
            raise RuntimePolicyError("ECO_ISOLATION_SETUP_FAILED", "OS isolation setup failed closed")
        return LaunchResult(process.returncode, stdout, stderr)
