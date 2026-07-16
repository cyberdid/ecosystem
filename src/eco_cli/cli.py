from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from . import VERSION
from .audit import audit_repository
from .compiler import apply_projections, plan_projections, uninstall_projections
from .config import (
    atomic_write,
    config_directory,
    dump_yaml,
    sha256_file,
    stable_json,
    validate_repository,
)
from .constants import CONFIG_FILES
from .errors import EcoError
from .templates import starter_bundle


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eco", description="Vendor-neutral AI project contracts and compiler")
    parser.add_argument("--version", action="version", version=f"eco {VERSION}")
    parser.add_argument("--repo", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--config-root", default=".ai", help="Canonical config directory relative to repo")

    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a canonical starter configuration")
    init.add_argument("--name", help="Project identifier (default: repository name)")
    init.add_argument("--render", action="store_true", help="Render vendor projections after initialization")

    validate = commands.add_parser("validate", help="Validate schemas and cross-file invariants")
    validate.add_argument("--json", action="store_true", dest="json_output")

    audit = commands.add_parser("audit", help="Read-only repository discovery and hygiene audit")
    audit.add_argument("--json", action="store_true", dest="json_output")

    render = commands.add_parser("render", help="Render deterministic vendor instruction projections")
    mode = render.add_mutually_exclusive_group()
    mode.add_argument("--adopt", action="store_true", help="Preserve unmanaged content and append an eco block")
    mode.add_argument("--force", action="store_true", help="Replace unmanaged files after creating backups")
    render.add_argument("--check", action="store_true", help="Exit non-zero on drift without writing")

    commands.add_parser("diff", help="Show proposed vendor projection changes")

    doctor = commands.add_parser("doctor", help="Validate configuration and projection health")
    doctor.add_argument("--json", action="store_true", dest="json_output")

    runtime = commands.add_parser("runtime", help="Inspect the embedded runtime composition")
    runtime_commands = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_doctor = runtime_commands.add_parser(
        "doctor", help="Probe runtime boundaries without enabling execution"
    )
    runtime_doctor.add_argument("--json", action="store_true", dest="json_output")

    runtime_trust = runtime_commands.add_parser(
        "trust", help="Verify external runtime trust evidence without enabling execution"
    )
    runtime_trust_commands = runtime_trust.add_subparsers(dest="runtime_trust_command", required=True)
    runtime_trust_doctor = runtime_trust_commands.add_parser(
        "doctor", help="Verify the externally signed repository snapshot bootstrap"
    )
    runtime_trust_doctor.add_argument("--json", action="store_true", dest="json_output")

    commands.add_parser("lock", help="Write a deterministic lock of canonical configuration inputs")

    uninstall = commands.add_parser("uninstall", help="Remove only eco-managed vendor projections")
    uninstall.add_argument("--remove-config", action="store_true", help="Also delete canonical configuration")
    uninstall.add_argument("--yes", action="store_true", help="Confirm destructive config removal")

    return parser


def _repo(args: argparse.Namespace) -> Path:
    repo = Path(args.repo).expanduser().resolve()
    if not repo.is_dir():
        raise EcoError(f"Repository directory does not exist: {repo}")
    return repo


def _print_errors(errors: list[str]) -> None:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)


def _validate(repo: Path, config_root: str) -> tuple[list[str], dict[str, Any], dict[str, Path]]:
    errors, bundle, paths = validate_repository(repo, config_root)
    return errors, bundle, paths


def command_init(args: argparse.Namespace) -> int:
    repo = _repo(args)
    directory = config_directory(repo, args.config_root)
    if directory.exists():
        raise EcoError(f"Canonical config already exists: {directory}")
    bundle = starter_bundle(args.name or repo.name.lower().replace(" ", "-"))
    for name, document in bundle.items():
        atomic_write(directory / CONFIG_FILES[name], dump_yaml(document))
    print(f"Initialized {directory.relative_to(repo)}")
    if args.render:
        errors, loaded, paths = _validate(repo, args.config_root)
        if errors:
            _print_errors(errors)
            return 1
        plans = plan_projections(repo, directory, loaded, paths["instructions"])
        apply_projections(repo, directory, plans)
        print("Rendered vendor projections")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    repo = _repo(args)
    errors, _, _ = _validate(repo, args.config_root)
    result = {"valid": not errors, "errors": errors}
    if args.json_output:
        print(stable_json(result), end="")
    elif errors:
        _print_errors(errors)
    else:
        print("Configuration is valid")
    return 0 if not errors else 1


def command_audit(args: argparse.Namespace) -> int:
    result = audit_repository(_repo(args), args.config_root)
    if args.json_output:
        print(stable_json(result), end="")
        return 0
    print(f"Repository: {result['repository']}")
    print(f"Git: head={result['git']['head']} dirty={result['git']['dirty']}")
    print(f"Languages: {', '.join(result['languages']) or 'not detected'}")
    print(f"Build files: {', '.join(result['buildFiles']) or 'none'}")
    print("Instruction surfaces:")
    for item in result["instructionSurfaces"]:
        print(f"  - {item['path']}: managed={item['managed']}")
    findings = result["potentialSecretLocations"]
    print(f"Potential secret locations: {len(findings)} (values were not displayed)")
    for item in findings:
        location = f"{item['path']}:{item['line']}" if item.get("line") else item["path"]
        print(f"  - {location}: {item['reason']}")
    return 0


def _plans(repo: Path, config_root: str, *, adopt: bool = False, force: bool = False):
    errors, bundle, paths = _validate(repo, config_root)
    if errors:
        _print_errors(errors)
        raise EcoError("Configuration validation failed")
    directory = config_directory(repo, config_root)
    return directory, plan_projections(
        repo,
        directory,
        bundle,
        paths["instructions"],
        adopt=adopt,
        force=force,
    )


def command_render(args: argparse.Namespace) -> int:
    repo = _repo(args)
    directory, plans = _plans(repo, args.config_root, adopt=args.adopt, force=args.force)
    changes = [plan for plan in plans if plan.status != "clean"]
    if args.check:
        for plan in changes:
            print(f"{plan.status.upper()}: {plan.path.relative_to(repo)}")
        return 1 if changes else 0
    outputs = apply_projections(repo, directory, plans)
    for output in outputs:
        print(f"{output['mode']}: {output['path']}")
    return 0


def command_diff(args: argparse.Namespace) -> int:
    repo = _repo(args)
    _, plans = _plans(repo, args.config_root)
    changed = False
    for plan in plans:
        if plan.status != "clean":
            changed = True
            if plan.mode == "conflict":
                print(f"# CONFLICT: unmanaged surface {plan.path.relative_to(repo)}")
            print(plan.diff, end="")
    if not changed:
        print("No projection changes")
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    repo = _repo(args)
    errors, bundle, paths = _validate(repo, args.config_root)
    projection_status: list[dict[str, str]] = []
    if not errors:
        directory = config_directory(repo, args.config_root)
        plans = plan_projections(repo, directory, bundle, paths["instructions"])
        projection_status = [
            {"client": plan.client, "path": str(plan.path.relative_to(repo)), "status": plan.status}
            for plan in plans
        ]
    healthy = not errors and all(item["status"] == "clean" for item in projection_status)
    result = {"healthy": healthy, "validationErrors": errors, "projections": projection_status}
    if args.json_output:
        print(stable_json(result), end="")
    else:
        _print_errors(errors)
        for item in projection_status:
            print(f"{item['status'].upper()}: {item['client']} -> {item['path']}")
        print("Doctor: healthy" if healthy else "Doctor: attention required")
    return 0 if healthy else 1


def command_lock(args: argparse.Namespace) -> int:
    repo = _repo(args)
    errors, bundle, paths = _validate(repo, args.config_root)
    if errors:
        _print_errors(errors)
        return 1
    directory = config_directory(repo, args.config_root)
    inputs = {
        name: {
            "path": path.relative_to(directory).as_posix(),
            "sha256": sha256_file(path),
        }
        for name, path in sorted(paths.items())
    }
    deployments = [
        {
            "id": item["id"],
            "provider": item["provider"],
            "adapter": item["adapter"],
            "model": item["model"],
            "enabled": item["enabled"],
        }
        for item in bundle["deployments"].get("deployments", [])
    ]
    output = directory / "locks" / "ecosystem.lock.json"
    atomic_write(output, stable_json({"apiVersion": bundle["project"]["apiVersion"], "inputs": inputs, "deployments": deployments}))
    print(f"Wrote {output.relative_to(repo)}")
    return 0


def command_runtime(args: argparse.Namespace) -> int:
    if args.runtime_command not in {"doctor", "trust"}:
        raise EcoError(f"Unknown runtime command: {args.runtime_command}")
    repo = _repo(args)
    try:
        errors, bundle, paths = _validate(repo, args.config_root)
    except EcoError:
        errors, bundle, paths = ["configuration unavailable"], {}, {}
    if args.runtime_command == "trust":
        if args.runtime_trust_command != "doctor":
            raise EcoError(f"Unknown runtime trust command: {args.runtime_trust_command}")
        if errors:
            result = {
                "available": False,
                "executionReady": False,
                "mode": "embedded-trust-bootstrap-verification",
                "checks": [
                    {
                        "component": "trust-config",
                        "status": "blocked",
                        "code": "ECO_CONFIG_INVALID",
                    }
                ],
                "evidence": {"verifiedSnapshotEntries": 0},
                "execution": {
                    "status": "blocked",
                    "code": "ECO_RUNTIME_NO_MODEL_PLAN_CONTRACT_REQUIRED",
                },
                "safety": {
                    "repositoryRead": "not-started",
                    "repositoryMutation": "denied",
                    "modelEgress": "not-used",
                    "writeAuthority": "not-created",
                    "runtimeState": "not-created",
                },
            }
        else:
            from eco_runtime.trust_diagnostics import runtime_trust_diagnostics

            result = runtime_trust_diagnostics(repo, bundle)
        if args.json_output:
            print(stable_json(result), end="")
        else:
            for item in result["checks"]:
                print(f"{item['status'].upper()}: {item['component']} ({item['code']})")
            print("Trust bootstrap: ready" if result["available"] else "Trust bootstrap: blocked")
            print("Execution: blocked until an explicit no-model A1 plan contract exists")
        return 0 if result["available"] else 1

    if errors:
        result = {
            "available": False,
            "executionReady": False,
            "mode": "embedded-read-only-preflight",
            "checks": [
                {
                    "component": "configuration",
                    "status": "blocked",
                    "code": "ECO_CONFIG_INVALID",
                }
            ],
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
    else:
        from eco_runtime.integration import runtime_diagnostics

        probe_path = paths["project"].relative_to(repo).as_posix()
        result = runtime_diagnostics(repo, bundle, probe_path=probe_path)
    if args.json_output:
        print(stable_json(result), end="")
    else:
        for item in result["checks"]:
            print(
                f"{item['status'].upper()}: {item['component']} ({item['code']})"
            )
        readiness = "available" if result["available"] else "unavailable"
        print(f"Runtime composition: {readiness}")
        print(
            "Execution: blocked until trusted evidence and key provisioning are configured"
        )
    return 0 if result["available"] else 1


def command_uninstall(args: argparse.Namespace) -> int:
    repo = _repo(args)
    directory = config_directory(repo, args.config_root)
    removed = uninstall_projections(repo, directory)
    for item in removed:
        print(item)
    if args.remove_config:
        if not args.yes:
            raise EcoError("--remove-config requires --yes")
        if directory.exists():
            shutil.rmtree(directory)
            print(f"deleted {directory.relative_to(repo)}")
    return 0


COMMANDS = {
    "init": command_init,
    "validate": command_validate,
    "audit": command_audit,
    "render": command_render,
    "diff": command_diff,
    "doctor": command_doctor,
    "runtime": command_runtime,
    "lock": command_lock,
    "uninstall": command_uninstall,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except EcoError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
