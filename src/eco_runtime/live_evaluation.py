from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from .evaluation import EvaluationInvocation, EvaluationRequest, EvaluationUsage


_MAX_PROVIDER_RESPONSE_BYTES = 4 * 1024 * 1024
_SAFE_ENVIRONMENT_NAMES = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
        "WSL_DISTRO_NAME",
        "WSL_INTEROP",
        "WSLENV",
    }
)


def _safe_json(payload: bytes) -> dict[str, Any]:
    if len(payload) > _MAX_PROVIDER_RESPONSE_BYTES:
        raise RuntimeError("provider response exceeds the bounded evaluation profile")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("provider response is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("provider response is invalid")
    return value


def executable_sha256(path: str | Path) -> str:
    """Hash the executable bytes used by a live provider transport."""

    executable = Path(path)
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("Provider executable must be an existing absolute path")
    digest = hashlib.sha256()
    try:
        with executable.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeError("Provider executable identity could not be read") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class OllamaEvaluationAdapter:
    """Bounded loopback-only Ollama adapter for M2 conformance evidence."""

    deployment_id: str
    adapter_version: str
    deployment_identity_digest: str
    model: str
    model_digest: str
    endpoint_url: str = "http://127.0.0.1:11434/api/generate"
    _urlopen: Callable[..., Any] = urllib.request.urlopen

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint_url)
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise ValueError("Ollama endpoint must use a literal loopback address") from exc
        if (
            parsed.scheme != "http"
            or not address.is_loopback
            or parsed.path != "/api/generate"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Ollama endpoint is outside the loopback evaluation profile")
        if len(self.model_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.model_digest
        ):
            raise ValueError("Ollama model digest must be an exact SHA-256 digest")

    def _assert_model_identity(self, *, timeout_seconds: float) -> None:
        parsed = urlsplit(self.endpoint_url)
        tags_url = urlunsplit((parsed.scheme, parsed.netloc, "/api/tags", "", ""))
        try:
            with self._urlopen(tags_url, timeout=timeout_seconds) as response:
                value = _safe_json(response.read(_MAX_PROVIDER_RESPONSE_BYTES + 1))
        except TimeoutError:
            raise
        except Exception as exc:
            raise RuntimeError("Ollama model identity check failed") from exc
        models = value.get("models")
        if not isinstance(models, list) or not any(
            isinstance(item, dict)
            and item.get("name") == self.model
            and item.get("digest") == self.model_digest
            for item in models
        ):
            raise RuntimeError("Ollama model identity does not match the pinned digest")

    def invoke(
        self, request: EvaluationRequest, *, timeout_seconds: float
    ) -> EvaluationInvocation:
        self._assert_model_identity(timeout_seconds=timeout_seconds)
        body = json.dumps(
            {
                "model": self.model,
                "prompt": request.input_text,
                "stream": False,
                "think": False,
                "keep_alive": "5m",
                "options": {
                    "temperature": request.temperature_milli / 1000,
                    "seed": request.seed,
                    "num_predict": 32,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        http_request = urllib.request.Request(
            self.endpoint_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._urlopen(http_request, timeout=timeout_seconds) as response:
                payload = response.read(_MAX_PROVIDER_RESPONSE_BYTES + 1)
        except TimeoutError:
            raise
        except Exception as exc:
            raise RuntimeError("Ollama evaluation transport failed") from exc
        value = _safe_json(payload)
        self._assert_model_identity(timeout_seconds=timeout_seconds)
        output = value.get("response")
        input_tokens = value.get("prompt_eval_count")
        output_tokens = value.get("eval_count")
        if (
            value.get("model") != self.model
            or value.get("done") is not True
            or not isinstance(output, str)
            or not isinstance(input_tokens, int)
            or isinstance(input_tokens, bool)
            or input_tokens < 0
            or not isinstance(output_tokens, int)
            or isinstance(output_tokens, bool)
            or output_tokens < 0
        ):
            raise RuntimeError("Ollama evaluation response is invalid")
        usage = EvaluationUsage(input_tokens, output_tokens, input_tokens + output_tokens)
        return EvaluationInvocation(self.deployment_identity_digest, output, usage)


@dataclass(frozen=True)
class ClaudeCliEvaluationAdapter:
    """Broker-owned Claude CLI adapter with prompt-over-stdin and a clean environment."""

    deployment_id: str
    adapter_version: str
    deployment_identity_digest: str
    model: str
    executable: str
    executable_sha256: str
    maximum_budget_usd: str = "0.05"
    _runner: Callable[..., Any] = subprocess.run

    def __post_init__(self) -> None:
        executable = Path(self.executable)
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError("Claude CLI executable must be an existing absolute path")
        if not self.model or not self.maximum_budget_usd:
            raise ValueError("Claude CLI evaluation identity is incomplete")
        if len(self.executable_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.executable_sha256
        ):
            raise ValueError("Claude CLI executable digest must be an exact SHA-256 digest")

    def _assert_executable_identity(self) -> None:
        if executable_sha256(self.executable) != self.executable_sha256:
            raise RuntimeError("Claude CLI executable identity does not match the pinned digest")

    @staticmethod
    def _clean_environment() -> dict[str, str]:
        return {
            name: value
            for name, value in os.environ.items()
            if name.upper() in _SAFE_ENVIRONMENT_NAMES
        }

    def invoke(
        self, request: EvaluationRequest, *, timeout_seconds: float
    ) -> EvaluationInvocation:
        self._assert_executable_identity()
        command = [
            self.executable,
            "-p",
            "--output-format",
            "json",
            "--tools",
            "",
            "--disable-slash-commands",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--no-chrome",
            "--no-session-persistence",
            "--permission-mode",
            "manual",
            "--model",
            self.model,
            "--max-budget-usd",
            self.maximum_budget_usd,
        ]
        try:
            with tempfile.TemporaryDirectory(prefix="eco-claude-eval-") as workdir:
                completed = self._runner(
                    command,
                    input=request.input_text.encode("utf-8"),
                    cwd=workdir,
                    env=self._clean_environment(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Claude CLI evaluation timed out") from exc
        except Exception as exc:
            raise RuntimeError("Claude CLI evaluation transport failed") from exc
        if completed.returncode != 0:
            raise RuntimeError("Claude CLI evaluation failed")
        self._assert_executable_identity()
        value = _safe_json(completed.stdout)
        output = value.get("result")
        usage_value = value.get("usage")
        model_usage = value.get("modelUsage")
        if (
            value.get("type") != "result"
            or value.get("subtype") != "success"
            or value.get("is_error") is not False
            or value.get("terminal_reason") != "completed"
            or not isinstance(output, str)
            or not isinstance(usage_value, dict)
            or not isinstance(model_usage, dict)
            or self.model not in model_usage
        ):
            raise RuntimeError("Claude CLI evaluation response is invalid")
        counts = (
            usage_value.get("input_tokens", 0),
            usage_value.get("cache_creation_input_tokens", 0),
            usage_value.get("cache_read_input_tokens", 0),
            usage_value.get("output_tokens", 0),
        )
        if any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts
        ):
            raise RuntimeError("Claude CLI evaluation usage is invalid")
        input_tokens = counts[0] + counts[1] + counts[2]
        output_tokens = counts[3]
        usage = EvaluationUsage(input_tokens, output_tokens, input_tokens + output_tokens)
        return EvaluationInvocation(self.deployment_identity_digest, output, usage)
