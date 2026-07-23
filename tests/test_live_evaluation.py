from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from eco_runtime.evaluation import EvaluationRequest
from eco_runtime.live_evaluation import ClaudeCliEvaluationAdapter, OllamaEvaluationAdapter


IDENTITY = "a" * 64
MODEL_DIGEST = "c" * 64
REQUEST = EvaluationRequest("b" * 64, "deterministic", "private prompt", 0, 42)


class _Response:
    def __init__(self, payload: dict) -> None:
        self._stream = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size: int) -> bytes:
        return self._stream.read(size)


class LiveEvaluationAdapterTests(unittest.TestCase):
    def test_ollama_is_loopback_only_and_normalizes_usage(self) -> None:
        seen = []

        def urlopen(request, *, timeout):
            seen.append((request, timeout))
            if isinstance(request, str) and request.endswith("/api/tags"):
                return _Response(
                    {"models": [{"name": "qwen-exact", "digest": MODEL_DIGEST}]}
                )
            return _Response(
                {
                    "model": "qwen-exact",
                    "response": "READY",
                    "done": True,
                    "prompt_eval_count": 11,
                    "eval_count": 2,
                }
            )

        adapter = OllamaEvaluationAdapter(
            "local-pinned",
            "ollama-eval-v1",
            IDENTITY,
            "qwen-exact",
            MODEL_DIGEST,
            _urlopen=urlopen,
        )
        result = adapter.invoke(REQUEST, timeout_seconds=2)
        self.assertEqual(result.output_text, "READY")
        self.assertEqual(result.usage.total_tokens, 13)
        payload = json.loads(seen[1][0].data)
        self.assertEqual(payload["prompt"], "private prompt")
        self.assertFalse(payload["stream"])
        with self.assertRaises(ValueError):
            OllamaEvaluationAdapter(
                "local-pinned",
                "ollama-eval-v1",
                IDENTITY,
                "qwen-exact",
                MODEL_DIGEST,
                endpoint_url="http://example.com/api/generate",
            )
        mismatched = OllamaEvaluationAdapter(
            "local-pinned",
            "ollama-eval-v1",
            IDENTITY,
            "qwen-exact",
            "d" * 64,
            _urlopen=urlopen,
        )
        with self.assertRaises(RuntimeError):
            mismatched.invoke(REQUEST, timeout_seconds=2)

    def test_claude_uses_stdin_clean_env_exact_model_and_sanitized_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "claude"
            executable.write_bytes(b"fixture")
            executable_digest = __import__("hashlib").sha256(b"fixture").hexdigest()
            calls = []

            def runner(command, **kwargs):
                calls.append((command, kwargs))
                payload = {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": "READY",
                    "terminal_reason": "completed",
                    "usage": {
                        "input_tokens": 2,
                        "cache_creation_input_tokens": 3,
                        "cache_read_input_tokens": 4,
                        "output_tokens": 1,
                    },
                    "modelUsage": {"claude-exact": {}},
                }
                return SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode(), stderr=b"")

            previous = os.environ.get("ANTHROPIC_API_KEY")
            os.environ["ANTHROPIC_API_KEY"] = "must-not-cross"
            try:
                adapter = ClaudeCliEvaluationAdapter(
                    "cloud-pinned",
                    "claude-cli-eval-v1",
                    IDENTITY,
                    "claude-exact",
                    str(executable),
                    executable_digest,
                    _runner=runner,
                )
                result = adapter.invoke(REQUEST, timeout_seconds=3)
            finally:
                if previous is None:
                    os.environ.pop("ANTHROPIC_API_KEY", None)
                else:
                    os.environ["ANTHROPIC_API_KEY"] = previous
            self.assertEqual(result.output_text, "READY")
            self.assertEqual(result.usage.input_tokens, 9)
            command, kwargs = calls[0]
            self.assertNotIn("private prompt", command)
            self.assertEqual(kwargs["input"], b"private prompt")
            self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
            self.assertIn("--no-session-persistence", command)
            self.assertEqual(command[command.index("--setting-sources") + 1], "")
            self.assertIn("--strict-mcp-config", command)
            self.assertEqual(
                command[command.index("--mcp-config") + 1], '{"mcpServers":{}}'
            )
            self.assertEqual(command[command.index("--model") + 1], "claude-exact")

            executable.write_bytes(b"changed-after-pinning")
            with self.assertRaises(RuntimeError) as changed:
                adapter.invoke(REQUEST, timeout_seconds=3)
            self.assertNotIn("changed-after-pinning", str(changed.exception))
            executable.write_bytes(b"fixture")

            def timeout_runner(*_args, **_kwargs):
                raise subprocess.TimeoutExpired("private command", 1, stderr=b"private body")

            timed = ClaudeCliEvaluationAdapter(
                "cloud-pinned",
                "claude-cli-eval-v1",
                IDENTITY,
                "claude-exact",
                str(executable),
                executable_digest,
                _runner=timeout_runner,
            )
            with self.assertRaises(TimeoutError) as caught:
                timed.invoke(REQUEST, timeout_seconds=1)
            self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
