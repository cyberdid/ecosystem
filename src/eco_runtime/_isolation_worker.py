from __future__ import annotations

import ctypes
import json
import os
import sys
import sysconfig
from pathlib import Path


_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13
_FS_TRUNCATE = 1 << 14
_FS_IOCTL_DEV = 1 << 15
_NET_BIND_TCP = 1 << 0
_NET_CONNECT_TCP = 1 << 1


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


def _abi() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return int(
        libc.syscall(
            ctypes.c_long(_LANDLOCK_CREATE_RULESET),
            ctypes.c_void_p(),
            ctypes.c_size_t(0),
            ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION),
        )
    )


def _handled_fs(abi: int) -> int:
    access = (
        _FS_EXECUTE
        | _FS_WRITE_FILE
        | _FS_READ_FILE
        | _FS_READ_DIR
        | _FS_REMOVE_DIR
        | _FS_REMOVE_FILE
        | _FS_MAKE_CHAR
        | _FS_MAKE_DIR
        | _FS_MAKE_REG
        | _FS_MAKE_SOCK
        | _FS_MAKE_FIFO
        | _FS_MAKE_BLOCK
        | _FS_MAKE_SYM
    )
    if abi >= 2:
        access |= _FS_REFER
    if abi >= 3:
        access |= _FS_TRUNCATE
    if abi >= 5:
        access |= _FS_IOCTL_DEV
    return access


def _runtime_read_paths() -> tuple[Path, ...]:
    """Return narrow interpreter paths needed after Landlock is active.

    Distribution-provided Python normally lives below ``/usr``, which is part
    of the static runtime allowlist.  Managed interpreters (for example uv and
    actions/setup-python) use dedicated prefixes below a user or tool-cache
    directory.  The requested Python process cannot restart there unless its
    standard library and private shared library are explicitly readable.

    Whole prefixes are deliberately never returned: a valid Python prefix may
    itself be ``$HOME`` or ``/opt``, and recursively allowing it would expose
    unrelated host data.  Invalid or non-contained runtime metadata fails
    closed instead of widening the filesystem grant.
    """

    base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    prefixes: list[Path] = []
    for raw in (sys.base_prefix, sys.base_exec_prefix):
        prefix = Path(raw).resolve(strict=True)
        if prefix == Path(prefix.anchor):
            raise OSError("Python runtime prefix is unsafe")
        if prefix not in prefixes:
            prefixes.append(prefix)
    if not any(base_executable.is_relative_to(prefix) for prefix in prefixes):
        raise OSError("Python runtime executable is outside its prefixes")

    variables = dict(sysconfig.get_config_vars())
    variables.update(
        {
            "base": str(prefixes[0]),
            "installed_base": str(prefixes[0]),
            "platbase": str(prefixes[-1]),
            "installed_platbase": str(prefixes[-1]),
        }
    )
    paths: list[Path] = []

    def add_directory(raw: str | None) -> None:
        if not raw:
            raise OSError("Python runtime directory is unavailable")
        path = Path(raw).resolve(strict=True)
        if (
            not path.is_dir()
            or path in prefixes
            or not any(path.is_relative_to(prefix) for prefix in prefixes)
        ):
            raise OSError("Python runtime directory is unsafe")
        if path not in paths:
            paths.append(path)

    add_directory(sysconfig.get_path("stdlib", vars=variables))
    add_directory(sysconfig.get_path("platstdlib", vars=variables))

    shared = sysconfig.get_config_var("DESTSHARED")
    if shared:
        add_directory(str(shared))

    library_directory = sysconfig.get_config_var("LIBDIR")
    if library_directory:
        libdir = Path(str(library_directory)).resolve(strict=True)
        if libdir.is_dir() and any(libdir.is_relative_to(prefix) for prefix in prefixes):
            for variable in ("LDLIBRARY", "INSTSONAME"):
                name = sysconfig.get_config_var(variable)
                if not isinstance(name, str) or not name or Path(name).name != name:
                    continue
                unresolved = libdir / name
                if not unresolved.is_file():
                    continue
                candidate = unresolved.resolve(strict=True)
                if not any(candidate.is_relative_to(prefix) for prefix in prefixes):
                    raise OSError("Python runtime library is unsafe")
                if candidate not in paths:
                    paths.append(candidate)
    return tuple(paths)


def _restrict(working_directory: Path, *, writable: bool, executable: Path) -> None:
    abi = _abi()
    if abi < 4:
        raise OSError("Landlock ABI 4 or newer is required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    handled_fs = _handled_fs(abi)
    ruleset_attr = _RulesetAttr(handled_fs, _NET_BIND_TCP | _NET_CONNECT_TCP)
    ruleset_fd = int(
        libc.syscall(
            ctypes.c_long(_LANDLOCK_CREATE_RULESET),
            ctypes.byref(ruleset_attr),
            ctypes.c_size_t(ctypes.sizeof(ruleset_attr)),
            ctypes.c_uint(0),
        )
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")

    read_access = _FS_EXECUTE | _FS_READ_FILE | _FS_READ_DIR
    write_access = handled_fs

    def allow(path: Path, access: int) -> None:
        if not path.exists():
            return
        descriptor = os.open(path, getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC)
        try:
            rule = _PathBeneathAttr(access & handled_fs, descriptor, 0)
            result = libc.syscall(
                ctypes.c_long(_LANDLOCK_ADD_RULE),
                ctypes.c_int(ruleset_fd),
                ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
                ctypes.byref(rule),
                ctypes.c_uint(0),
            )
            if result != 0:
                raise OSError(ctypes.get_errno(), "landlock_add_rule failed")
        finally:
            os.close(descriptor)

    try:
        allowed: set[Path] = set()
        static_roots = tuple(
            Path(raw).resolve(strict=False)
            for raw in ("/usr", "/bin", "/sbin", "/lib", "/lib64")
        )
        for path in static_roots:
            if path not in allowed:
                allow(path, read_access)
                allowed.add(path)
        for path in _runtime_read_paths():
            if path not in allowed:
                allow(path, read_access if path.is_dir() else _FS_READ_FILE)
                allowed.add(path)
        allow(executable, _FS_EXECUTE | _FS_READ_FILE)
        for raw in (
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/localtime",
            "/etc/nsswitch.conf",
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/dev/urandom",
        ):
            path = Path(raw).resolve(strict=False)
            file_access = _FS_READ_FILE | (_FS_WRITE_FILE if raw.startswith("/dev/") else 0)
            allow(path, file_access)
        allow(Path("/proc"), read_access)
        allow(working_directory, write_access if writable else read_access)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
        if libc.syscall(ctypes.c_long(_LANDLOCK_RESTRICT_SELF), ctypes.c_int(ruleset_fd), 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(ruleset_fd)


def _fail() -> None:
    os.write(2, b"ECO_ISOLATION_SETUP_FAILED\n")
    raise SystemExit(125)


def main() -> None:
    if sys.argv[1:] == ["--probe"]:
        if _abi() < 4:
            _fail()
        return
    if sys.argv[1:] != ["--run"]:
        _fail()
    raw = os.environ.pop("ECO_ISOLATION_CONFIG", None)
    try:
        config = json.loads(raw) if raw is not None else None
        if (
            not isinstance(config, dict)
            or set(config) != {"command", "workingDirectory", "workingDirectoryAccess"}
            or not isinstance(config["command"], list)
            or not config["command"]
            or not all(isinstance(item, str) and "\x00" not in item for item in config["command"])
            or config["workingDirectoryAccess"] not in {"read-only", "read-write"}
        ):
            _fail()
        workdir = Path(config["workingDirectory"]).resolve(strict=True)
        executable = Path(config["command"][0]).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            _fail()
        config["command"][0] = str(executable)
        os.chdir(workdir)
        _restrict(
            workdir,
            writable=config["workingDirectoryAccess"] == "read-write",
            executable=executable,
        )
        os.execve(config["command"][0], config["command"], dict(os.environ))
    except SystemExit:
        raise
    except Exception:
        _fail()


if __name__ == "__main__":
    main()
