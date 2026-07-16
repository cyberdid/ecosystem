from __future__ import annotations

import argparse
import json
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
    validate_bundle,
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

    adopt = commands.add_parser(
        "adopt", help="Preview or apply the bounded project-adoption bootstrap"
    )
    adopt_mode = adopt.add_mutually_exclusive_group(required=True)
    adopt_mode.add_argument(
        "--dry-run", action="store_true", help="Build a deterministic zero-write adoption plan"
    )
    adopt_mode.add_argument(
        "--apply", metavar="PLAN_SHA256", help="Apply exactly a previously previewed plan digest"
    )
    adopt.add_argument("--name", help="Canonical project identifier for a fresh adoption")
    adopt.add_argument(
        "--adopt-existing-config",
        action="store_true",
        help="Explicitly retain and register an already valid canonical configuration",
    )
    adopt.add_argument("--json", action="store_true", dest="json_output")

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

    platform_command = commands.add_parser(
        "platform", help="Inspect passive platform and adapter-capability inventory"
    )
    platform_commands = platform_command.add_subparsers(
        dest="platform_command", required=True
    )
    platform_doctor_command = platform_commands.add_parser(
        "doctor", help="Report sanitized platform facts without creating authority"
    )
    platform_doctor_command.add_argument(
        "--json", action="store_true", dest="json_output"
    )
    platform_doctor_command.add_argument(
        "--declared-profile",
        choices=(
            "linux-native",
            "wsl",
            "macos",
            "windows-native",
            "container",
            "hosted-ci",
        ),
        help="Operator-declared profile to compare with passive detection",
    )

    runtime_trust = runtime_commands.add_parser(
        "trust", help="Verify external runtime trust evidence without enabling execution"
    )
    runtime_trust_commands = runtime_trust.add_subparsers(dest="runtime_trust_command", required=True)
    runtime_trust_doctor = runtime_trust_commands.add_parser(
        "doctor", help="Verify the externally signed repository snapshot bootstrap"
    )
    runtime_trust_doctor.add_argument("--json", action="store_true", dest="json_output")

    run = commands.add_parser("run", help="Run one fixed, policy-bound workflow")
    run_commands = run.add_subparsers(dest="run_command", required=True)
    wiki_health = run_commands.add_parser(
        "wiki-health-check", help="Verify the fixed trusted D0 wiki scope without a model"
    )
    wiki_health.add_argument("--json", action="store_true", dest="json_output")

    evaluate = commands.add_parser("eval", help="Evaluate one fixed workflow promotion gate")
    evaluate_commands = evaluate.add_subparsers(dest="eval_command", required=True)
    wiki_health_eval = evaluate_commands.add_parser(
        "wiki-health-check", help="Run the fixed five-attempt no-model L0-L2 gate"
    )
    wiki_health_eval.add_argument("--json", action="store_true", dest="json_output")

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
    errors = validate_bundle(repo, directory, bundle)
    if errors:
        _print_errors(errors)
        raise EcoError("Starter configuration is invalid")
    written: list[Path] = []
    try:
        for name, document in bundle.items():
            path = directory / CONFIG_FILES[name]
            atomic_write(path, dump_yaml(document))
            written.append(path)
    except OSError as exc:
        for path in reversed(written):
            path.unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError:
            pass
        raise EcoError("Unable to initialize canonical configuration") from exc
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


def command_adopt(args: argparse.Namespace) -> int:
    from .adoption import apply_adoption, plan_adoption

    def failure_code(error: Exception) -> str:
        if isinstance(error, EcoError):
            code = str(error)
            if code.startswith("ECO_ADOPTION_") and code.replace("_", "").isalnum():
                return code
        return "ECO_ADOPTION_FAILED"

    if args.dry_run:
        try:
            repo = _repo(args)
            plan = plan_adoption(
                repo,
                args.config_root,
                args.name,
                args.adopt_existing_config,
            )
        except Exception as exc:
            code = failure_code(exc)
            result = {
                "available": False,
                "operation": "adopt",
                "status": "blocked",
                "code": code,
                "planDigest": None,
                "plan": None,
            }
            if args.json_output:
                print(stable_json(result), end="")
                return 1
            raise EcoError(code) from exc
        available = plan["status"]["state"] != "blocked"
        result = {
            "available": available,
            "operation": "adopt",
            "status": "planned" if available else "blocked",
            "planDigest": plan["planDigest"],
            "plan": plan,
        }
        if not available:
            result["code"] = plan["status"]["blockers"][0]
        if args.json_output:
            print(stable_json(result), end="")
        else:
            print(f"Adoption: {result['status']}")
            print(f"Plan digest: {plan['planDigest']}")
            for item in plan["status"]["warnings"]:
                print(f"WARNING: {item}")
            for item in plan["status"]["blockers"]:
                print(f"BLOCKED: {item}")
            for item in plan["spec"]["operations"]:
                print(f"{item['action']}: {item['path']}")
        return 0 if available else 1

    try:
        repo = _repo(args)
        applied = apply_adoption(
            repo,
            expected_plan_digest=args.apply,
            config_root=args.config_root,
            name=args.name,
            adopt_existing_config=args.adopt_existing_config,
        )
    except Exception as exc:
        code = failure_code(exc)
        result = {
            "available": False,
            "operation": "adopt",
            "status": "blocked",
            "code": code,
            "planDigest": args.apply,
            "changed": False,
        }
        if args.json_output:
            print(stable_json(result), end="")
            return 1
        raise EcoError(code) from exc

    changed = bool(applied["applied"])
    result = {
        "available": True,
        "operation": "adopt",
        "status": "applied" if changed else "no-op",
        "planDigest": applied["planDigest"],
        "changed": changed,
    }
    if args.json_output:
        print(stable_json(result), end="")
    else:
        print(f"Adoption: {result['status']}")
        print(f"Plan digest: {result['planDigest']}")
        print(f"Operations: {applied['operationCount']}")
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
                    "status": "not-started",
                    "code": "ECO_RUNTIME_TRUST_VERIFICATION_ONLY",
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
            print("Execution: not started; run wiki-health-check through the separate fixed command")
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


def command_platform(args: argparse.Namespace) -> int:
    if args.platform_command != "doctor":
        raise EcoError(f"Unknown platform command: {args.platform_command}")
    from .platform_profiles import platform_doctor

    result = platform_doctor(args.declared_profile, repository=_repo(args))
    if args.json_output:
        print(stable_json(result), end="")
    else:
        print(f"Platform inventory: {result['status']} ({result['code']})")
        print(
            "Profile: "
            f"declared={result['profile']['declared']} "
            f"detected={result['profile']['detected']} proven=none"
        )
        print("Execution: not ready; no authority, mutation, or network access was created")
    return 0 if result["available"] else 1


def command_run(args: argparse.Namespace) -> int:
    if args.run_command != "wiki-health-check":
        raise EcoError(f"Unknown fixed workflow: {args.run_command}")
    repo = _repo(args)
    errors, bundle, _ = _validate(repo, args.config_root)
    if errors:
        result = {
            "available": False,
            "workflow": "wiki-health-check",
            "status": "blocked",
            "code": "ECO_CONFIG_INVALID",
            "safety": {
                "repositoryMutation": "denied",
                "modelEgress": "not-used",
                "network": "not-used",
                "writeAuthority": "not-created",
                "adapter": "not-created",
                "content": "not-emitted",
            },
        }
    else:
        from eco_runtime.no_model_execution import execute_wiki_health_check

        result = execute_wiki_health_check(repo, bundle)
    if args.json_output:
        print(stable_json(result), end="")
    else:
        print(f"Workflow: {result['workflow']}")
        print(f"Status: {result['status']} ({result['code']})")
        print("Safety: no model, network, write authority, adapter, or document content")
    return 0 if result["available"] else 1


def command_eval(args: argparse.Namespace) -> int:
    if args.eval_command != "wiki-health-check":
        raise EcoError(f"Unknown fixed evaluation: {args.eval_command}")
    repo = _repo(args)
    errors, bundle, _ = _validate(repo, args.config_root)
    if errors:
        result = {
            "available": False,
            "workflow": "wiki-health-check",
            "status": "blocked",
            "code": "ECO_CONFIG_INVALID",
        }
    else:
        from eco_runtime.wiki_health_evaluation import execute_wiki_health_evaluation

        result = execute_wiki_health_evaluation(repo, bundle)
    if args.json_output:
        print(stable_json(result), end="")
    else:
        print(f"Workflow: {result['workflow']}")
        print(f"Evaluation: {result['status']} ({result['code']})")
        if "evaluation" in result:
            print(
                "Highest eligible level: "
                f"{result['evaluation'].get('highestEligibleLevel') or 'none'}"
            )
    return 0 if result["available"] else 1


def command_uninstall(args: argparse.Namespace) -> int:
    repo = _repo(args)
    directory = config_directory(repo, args.config_root)
    if not args.remove_config:
        from .adoption import _exclusive_adoption_lock

        with _exclusive_adoption_lock(repo):
            removed = uninstall_projections(repo, directory)
        for item in removed:
            print(item)
        return 0
    if not args.yes:
        raise EcoError("--remove-config requires --yes")

    from .adoption import _exclusive_adoption_lock, remove_owned_adoption_config

    with _exclusive_adoption_lock(repo):
        removal = remove_owned_adoption_config(
            repo,
            args.config_root,
            dry_run=True,
            allow_projection_state=True,
        )
        if removal["status"] != "ready":
            raise EcoError(removal["blockers"][0])
        removed = uninstall_projections(repo, directory)
        removal = remove_owned_adoption_config(repo, args.config_root)
        if removal["status"] != "removed":
            raise EcoError(removal["blockers"][0])

    for item in removed:
        print(item)
    print(f"deleted {directory.relative_to(repo)} ({removal['removedCount']} owned files)")
    return 0


COMMANDS = {
    "init": command_init,
    "validate": command_validate,
    "audit": command_audit,
    "adopt": command_adopt,
    "render": command_render,
    "diff": command_diff,
    "doctor": command_doctor,
    "runtime": command_runtime,
    "platform": command_platform,
    "run": command_run,
    "eval": command_eval,
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
