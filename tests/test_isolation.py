from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import traceback
import unittest
from pathlib import Path
from unittest import mock

from eco_runtime.errors import RuntimePolicyError
from eco_runtime.isolation import (
    CredentialBinding,
    IsolationContract,
    LaunchRequest,
    LinuxNamespaceLauncher,
    MappingCredentialResolver,
    NetworkEndpoint,
)


def _live_isolation_available() -> bool:
    """Whether this host can execute, rather than merely unit-test, the profile."""
    try:
        LinuxNamespaceLauncher()._preflight()
    except RuntimePolicyError:
        return False
    return True


LIVE_ISOLATION_AVAILABLE = _live_isolation_available()


class _ExplodingResolver:
    def __init__(self) -> None:
        self.called = False

    def resolve(self, reference: str) -> str:
        self.called = True
        raise AssertionError("resolver must not run for an untrusted-agent process")


class _LeakingResolver:
    def resolve(self, reference: str) -> str:
        raise RuntimeError("ECO_CREDENTIAL_VALUE_SENTINEL")


class IsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        self.secret = self.root / "outside-secret.txt"
        self.secret.write_text("host-file-secret", encoding="utf-8")
        self.python = str(Path(sys.executable).resolve())
        self.launcher = LinuxNamespaceLauncher()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def contract(
        self,
        *,
        access: str = "read-write",
        bindings: tuple[CredentialBinding, ...] = (),
        stdout_limit: int = 1_048_576,
        stderr_limit: int = 1_048_576,
    ) -> IsolationContract:
        return IsolationContract(
            network_mode="deny",
            allowed_network_endpoints=(),
            credential_bindings=bindings,
            executable_allowlist=(self.python,),
            working_directory_access=access,
            timeout_seconds=10,
            maximum_stdout_bytes=stdout_limit,
            maximum_stderr_bytes=stderr_limit,
        )

    def request(self, source: str, *arguments: str) -> LaunchRequest:
        return LaunchRequest(self.python, ("-c", source, *arguments), str(self.work))

    def assert_code(self, code: str, operation) -> RuntimePolicyError:
        with self.assertRaises(RuntimePolicyError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    @unittest.skipUnless(
        LIVE_ISOLATION_AVAILABLE,
        "requires a Linux host with user/net/pid namespaces and Landlock",
    )
    def test_environment_is_clean_and_host_files_are_landlock_denied(self) -> None:
        host_name = "ECO_HOST_ONLY_SECRET"
        previous = os.environ.get(host_name)
        os.environ[host_name] = "must-not-cross"
        source = """
import json, os, pathlib, sys
outside = sys.argv[1]
def readable(path):
    try:
        pathlib.Path(path).read_text()
        return True
    except (PermissionError, FileNotFoundError):
        return False
pathlib.Path('created.txt').write_text('ok')
print(json.dumps({
    'host': os.environ.get('ECO_HOST_ONLY_SECRET'),
    'extra': os.environ.get('EXTRA_TOKEN'),
    'outside': readable(outside),
    'proc_root_bypass': readable('/proc/self/root' + outside),
    'home': os.environ.get('HOME'),
}))
"""
        try:
            result = self.launcher.launch(
                self.request(source, str(self.secret)),
                self.contract(),
                credential_resolver=MappingCredentialResolver({}),
            )
        finally:
            if previous is None:
                os.environ.pop(host_name, None)
            else:
                os.environ[host_name] = previous
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIsNone(payload["host"])
        self.assertIsNone(payload["extra"])
        self.assertFalse(payload["outside"])
        self.assertFalse(payload["proc_root_bypass"])
        self.assertEqual(payload["home"], str(self.work))
        self.assertEqual((self.work / "created.txt").read_text(), "ok")

    @unittest.skipUnless(
        LIVE_ISOLATION_AVAILABLE,
        "requires a Linux host with user/net/pid namespaces and Landlock",
    )
    def test_network_namespace_and_landlock_deny_host_tcp_connection(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(1)
        port = server.getsockname()[1]
        accepted: list[bool] = []

        def accept() -> None:
            try:
                connection, _ = server.accept()
                accepted.append(True)
                connection.close()
            except TimeoutError:
                pass

        thread = threading.Thread(target=accept)
        thread.start()
        result = self.launcher.launch(
            self.request(
                """
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(('127.0.0.1', int(sys.argv[1])))
    print('connected')
except OSError:
    print('blocked')
""",
                str(port),
            ),
            self.contract(),
            credential_resolver=MappingCredentialResolver({}),
        )
        thread.join()
        server.close()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"blocked")
        self.assertEqual(accepted, [])

    @unittest.skipUnless(
        LIVE_ISOLATION_AVAILABLE,
        "requires a Linux host with user/net/pid namespaces and Landlock",
    )
    def test_read_only_workdir_denies_mutation(self) -> None:
        result = self.launcher.launch(
            self.request(
                """
from pathlib import Path
try:
    Path('denied.txt').write_text('no')
    print('wrote')
except PermissionError:
    print('blocked')
"""
            ),
            self.contract(access="read-only"),
            credential_resolver=MappingCredentialResolver({}),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"blocked")
        self.assertFalse((self.work / "denied.txt").exists())

    def test_credentials_endpoint_allowlist_and_executable_bypass_fail_closed(self) -> None:
        resolver = _ExplodingResolver()
        self.assert_code(
            "ECO_CREDENTIAL_BINDINGS_DENIED",
            lambda: self.launcher.launch(
                self.request("print('never')"),
                self.contract(bindings=(CredentialBinding("TOKEN", "secret://sensitive/ref"),)),
                credential_resolver=resolver,
            ),
        )
        self.assertFalse(resolver.called)

    def test_static_contract_rejections_precede_optional_kernel_preflight(self) -> None:
        """An unsupported host must not obscure an invalid launch contract."""
        resolver = _ExplodingResolver()
        allowlist = IsolationContract(
            network_mode="allowlist",
            allowed_network_endpoints=(NetworkEndpoint("api.example.com", 443),),
            credential_bindings=(),
            executable_allowlist=(self.python,),
        )
        with mock.patch.object(
            self.launcher,
            "_preflight",
            side_effect=AssertionError("kernel probe must not run"),
        ):
            self.assert_code(
                "ECO_NETWORK_ALLOWLIST_UNSUPPORTED",
                lambda: self.launcher.launch(
                    self.request("print('never')"),
                    allowlist,
                    credential_resolver=resolver,
                ),
            )
            self.assert_code(
                "ECO_EXECUTABLE_DENIED",
                lambda: self.launcher.launch(
                    LaunchRequest("/usr/bin/true", (), str(self.work)),
                    self.contract(),
                    credential_resolver=resolver,
                ),
            )
        self.assertFalse(resolver.called)

        allowlist = IsolationContract(
            network_mode="allowlist",
            allowed_network_endpoints=(NetworkEndpoint("api.example.com", 443),),
            credential_bindings=(),
            executable_allowlist=(self.python,),
        )
        self.assert_code(
            "ECO_NETWORK_ALLOWLIST_UNSUPPORTED",
            lambda: self.launcher.launch(
                self.request("print('never')"), allowlist, credential_resolver=resolver
            ),
        )
        self.assertFalse(resolver.called)

        denied_request = LaunchRequest("/usr/bin/true", (), str(self.work))
        self.assert_code(
            "ECO_EXECUTABLE_DENIED",
            lambda: self.launcher.launch(
                denied_request,
                self.contract(),
                credential_resolver=resolver,
            ),
        )
        self.assertFalse(resolver.called)

    def test_missing_os_backend_and_resolver_failures_are_sanitized(self) -> None:
        resolver = _ExplodingResolver()
        unavailable = LinuxNamespaceLauncher(unshare_executable="/does/not/exist/unshare")
        self.assert_code(
            "ECO_ISOLATION_UNSUPPORTED",
            lambda: unavailable.launch(
                self.request("print('never')"),
                self.contract(),
                credential_resolver=resolver,
            ),
        )
        self.assertFalse(resolver.called)
        binding = (CredentialBinding("TOKEN", "secret://sensitive/ref"),)
        for resolver, sentinel in (
            (MappingCredentialResolver({}), "sensitive/ref"),
            (_LeakingResolver(), "ECO_CREDENTIAL_VALUE_SENTINEL"),
        ):
            with self.subTest(resolver=type(resolver).__name__):
                error = self.assert_code(
                    "ECO_CREDENTIAL_UNAVAILABLE",
                    lambda resolver=resolver: LinuxNamespaceLauncher._resolve_credentials(
                        binding, resolver
                    ),
                )
                rendered = "".join(traceback.format_exception(error))
                self.assertNotIn(sentinel, rendered)
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    @unittest.skipUnless(
        LIVE_ISOLATION_AVAILABLE,
        "requires a Linux host with user/net/pid namespaces and Landlock",
    )
    def test_stdin_is_closed_and_output_is_bounded(self) -> None:
        result = self.launcher.launch(
            self.request("import sys; print(len(sys.stdin.buffer.read()))"),
            self.contract(),
            credential_resolver=MappingCredentialResolver({}),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"0")

        cases = (
            ("import sys; sys.stdout.write('x' * 65)", 64, 1_048_576),
            ("import sys; sys.stderr.write('x' * 65)", 1_048_576, 64),
        )
        for source, stdout_limit, stderr_limit in cases:
            with self.subTest(source=source):
                self.assert_code(
                    "ECO_ISOLATION_OUTPUT_LIMIT",
                    lambda source=source, stdout_limit=stdout_limit, stderr_limit=stderr_limit: self.launcher.launch(
                        self.request(source),
                        self.contract(
                            stdout_limit=stdout_limit,
                            stderr_limit=stderr_limit,
                        ),
                        credential_resolver=MappingCredentialResolver({}),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
