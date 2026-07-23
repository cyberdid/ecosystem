#!/usr/bin/env python3
"""Create deterministic M4.5.3 integrity metadata for an offline wheelhouse."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

from eco_cli.distribution import (
    MAX_LOCK_BYTES,
    build_distribution_manifest,
    distribution_file_digest,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="create_distribution_manifest.py")
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--main-wheel", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    requested_root = args.bundle_root.expanduser()
    if not requested_root.is_absolute():
        parser.error("bundle root must be absolute")
    root_status = requested_root.lstat()
    root = requested_root.resolve(strict=True)
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or root != requested_root
        or getattr(root_status, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        or Path(args.main_wheel).name != args.main_wheel
    ):
        parser.error("bundle root and main wheel must identify a local wheelhouse")
    output = args.output.resolve()
    if output.exists() or output.parent != output.parent.resolve(strict=True):
        parser.error("output must be a new file below an existing directory")
    main_wheel = root / args.main_wheel
    lock = root / "uv.lock"
    dependencies = sorted(
        path for path in root.glob("*.whl") if path.name != main_wheel.name
    )
    manifest = build_distribution_manifest(
        main_wheel,
        dependency_wheels=dependencies,
        version=args.version,
        lock_digest=distribution_file_digest(lock, maximum_size=MAX_LOCK_BYTES),
        source_revision=args.source_revision,
    )
    encoded = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_name, output)
        os.unlink(temporary_name)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise
    print(manifest["metadata"]["manifestDigest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
