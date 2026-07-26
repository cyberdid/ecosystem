from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timezone
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

    skills = commands.add_parser(
        "skills", help="Plan and synchronize package-owned portable skills"
    )
    skills_commands = skills.add_subparsers(dest="skills_command", required=True)
    for name, help_text in (
        ("plan", "Preview deterministic skill projections without writing"),
        ("sync", "Synchronize only eco-owned skill projections"),
        ("check", "Detect projection, ownership, and lock drift"),
        ("uninstall", "Remove only unchanged eco-owned skill projections"),
    ):
        skill_command = skills_commands.add_parser(name, help=help_text)
        skill_command.add_argument("--json", action="store_true", dest="json_output")
    gsc_propose = skills_commands.add_parser(
        "propose", help="Gate a proposed SKILL.md through the GSC gate (does not promote)"
    )
    gsc_propose.add_argument("proposal_file", help="Path to a proposed SKILL.md")
    gsc_propose.add_argument("--capabilities", default="", help="Comma-separated declared capabilities")
    gsc_propose.add_argument("--allowed", default="", help="Comma-separated allowed capabilities")
    gsc_propose.add_argument("--json", action="store_true", dest="json_output")
    gsc_promote = skills_commands.add_parser(
        "promote", help="Promote an approved admissible proposal into a skills root (L0)"
    )
    gsc_promote.add_argument("proposal_file", help="Path to a proposed SKILL.md")
    gsc_promote.add_argument("--into", required=True, help="Existing skills root directory to write into")
    gsc_promote.add_argument("--approve", required=True, metavar="APPROVER", help="Approver id (explicit human approval)")
    gsc_promote.add_argument("--capabilities", default="")
    gsc_promote.add_argument("--allowed", default="")
    gsc_promote.add_argument("--json", action="store_true", dest="json_output")
    import_plan = skills_commands.add_parser(
        "import-plan",
        help="Inspect one pinned local Git tree without importing or executing skills",
    )
    import_plan.add_argument(
        "source_root", help="Local Git repository containing the pinned commit object"
    )
    import_plan.add_argument(
        "--source-uri",
        required=True,
        help="Credential-free HTTPS identity of the upstream repository",
    )
    import_plan.add_argument(
        "--commit", required=True, help="Exact full 40-character Git commit id"
    )
    import_plan.add_argument(
        "--skill",
        action="append",
        default=[],
        help="Inspect only this skill id (repeatable); repository signals remain global",
    )
    import_plan.add_argument("--json", action="store_true", dest="json_output")

    loops = commands.add_parser(
        "loops", help="Validate or run an M6.3 deterministic no-effect loop profile"
    )
    loops_commands = loops.add_subparsers(dest="loops_command", required=True)
    for name, help_text in (
        ("validate", "Validate a package-owned deterministic loop profile"),
        ("run", "Run a deterministic report-only loop through its existing boundary"),
    ):
        loop_command = loops_commands.add_parser(name, help=help_text)
        loop_command.add_argument("profile", choices=("wiki-health-check",))
        loop_command.add_argument("--json", action="store_true", dest="json_output")

    route_command = commands.add_parser(
        "route", help="Compute one deterministic, non-authorizing model route"
    )
    route_commands = route_command.add_subparsers(dest="route_command", required=True)
    route_plan = route_commands.add_parser(
        "plan",
        help="Route one request over canonical deployments; computes a decision, grants nothing",
    )
    route_plan.add_argument(
        "--policy", required=True, type=Path, help="ModelRoutingPolicy JSON record"
    )
    route_plan.add_argument(
        "--prices", required=True, type=Path, help="TrustedPriceCatalog JSON record"
    )
    route_plan.add_argument(
        "--request", required=True, type=Path, help="ModelRouteRequest JSON record"
    )
    route_plan.add_argument(
        "--observation", action="append", type=Path, default=[],
        help="ObservedModelCapabilities JSON record (repeatable)",
    )
    route_plan.add_argument(
        "--at", help="Deterministic UTC routing time (YYYY-MM-DDTHH:MM:SSZ); default: now"
    )
    route_plan.add_argument("--decision-id", default="route-plan-decision")
    route_plan.add_argument("--explain-id", default="route-plan-explain")
    route_plan.add_argument("--json", action="store_true", dest="json_output")

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

    distribution = commands.add_parser(
        "distribution", help="Verify or preview a portable offline distribution"
    )
    distribution_commands = distribution.add_subparsers(
        dest="distribution_command", required=True
    )
    distribution_verify = distribution_commands.add_parser(
        "verify", help="Verify a complete local wheelhouse without installing it"
    )
    distribution_verify.add_argument("--manifest", required=True, type=Path)
    distribution_verify.add_argument("--bundle-root", required=True, type=Path)
    distribution_verify.add_argument("--json", action="store_true", dest="json_output")
    distribution_plan = distribution_commands.add_parser(
        "plan", help="Emit a deterministic non-executable installer preview"
    )
    distribution_plan.add_argument("--manifest", required=True, type=Path)
    distribution_plan.add_argument(
        "--adapter", required=True, choices=("pipx", "uv-tool", "venv-pip")
    )
    distribution_plan.add_argument(
        "--operation", default="install", choices=("install", "upgrade", "uninstall")
    )
    distribution_plan.add_argument("--json", action="store_true", dest="json_output")

    conformance = commands.add_parser(
        "conformance", help="Run an explicit active platform-backend conformance suite"
    )
    conformance_commands = conformance.add_subparsers(
        dest="conformance_command", required=True
    )
    conformance_run = conformance_commands.add_parser(
        "run", help="Run the fixed synthetic Linux/WSL namespace suite"
    )
    conformance_run.add_argument("--active", action="store_true", required=True)
    conformance_run.add_argument("--platform-profile", required=True, type=Path)
    conformance_run.add_argument("--test-root", required=True, type=Path)
    conformance_run.add_argument("--suite", required=True, choices=("linux-namespace-boundary",))
    conformance_run.add_argument("--suite-digest", required=True)
    conformance_run.add_argument("--distribution-manifest-digest", required=True)
    conformance_run.add_argument("--backend-instance-digest", required=True)
    conformance_run.add_argument("--json", action="store_true", dest="json_output")

    policy_command = commands.add_parser(
        "policy", help="Inspect or authenticate a deny-all team policy declaration"
    )
    policy_commands = policy_command.add_subparsers(
        dest="policy_command", required=True
    )
    policy_verify = policy_commands.add_parser(
        "verify", help="Authenticate a signed team policy without activating it"
    )
    policy_verify.add_argument("--envelope", required=True, type=Path)
    policy_verify.add_argument("--trust-anchor", required=True, type=Path)
    policy_verify.add_argument("--project", required=True)
    policy_verify.add_argument("--json", action="store_true", dest="json_output")
    policy_inspect = policy_commands.add_parser(
        "inspect", help="Validate an unsigned team policy declaration"
    )
    policy_inspect.add_argument("--record", required=True, type=Path)
    policy_inspect.add_argument("--json", action="store_true", dest="json_output")

    identity_command = commands.add_parser(
        "identity", help="Inspect a non-authorizing identity declaration"
    )
    identity_commands = identity_command.add_subparsers(
        dest="identity_command", required=True
    )
    identity_inspect = identity_commands.add_parser(
        "inspect", help="Validate one identity declaration without authenticating it"
    )
    identity_inspect.add_argument("--record", required=True, type=Path)
    identity_inspect.add_argument("--json", action="store_true", dest="json_output")

    team_command = commands.add_parser(
        "team", help="Operate one externally anchored local team authority"
    )
    team_commands = team_command.add_subparsers(dest="team_command", required=True)

    def add_team_authority_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--database", required=True, type=Path)
        command.add_argument("--trust-anchor", required=True, type=Path)
        command.add_argument("--project", required=True)
        command.add_argument("--audit-key-id", required=True)
        command.add_argument(
            "--hmac-env", default="ECO_TEAM_AUTHORITY_HMAC_HEX"
        )
        command.add_argument("--store-id")
        command.add_argument("--json", action="store_true", dest="json_output")

    team_doctor = team_commands.add_parser(
        "doctor", help="Verify the external authority state and audit chain"
    )
    add_team_authority_arguments(team_doctor)
    team_activate = team_commands.add_parser(
        "activate", help="Activate one exact externally signed policy revision"
    )
    add_team_authority_arguments(team_activate)
    team_activate.add_argument("--envelope", required=True, type=Path)
    team_activate.add_argument("--activation-id", required=True)
    team_activate.add_argument("--expected-revision", required=True, type=int)
    team_activate.add_argument("--expected-digest", required=True)
    team_activate.add_argument("--expected-snapshot-digest", required=True)
    team_activate.add_argument("--apply", action="store_true", required=True)
    team_run = team_commands.add_parser(
        "run", help="Run one package-owned, policy-bound AI team workflow"
    )
    team_run_commands = team_run.add_subparsers(
        dest="team_run_command", required=True
    )
    source_review = team_run_commands.add_parser(
        "source-review",
        help="Run the fixed five-role source-review workflow through a local model",
    )
    source_review.add_argument(
        "--manifest", required=True, type=Path,
        help="Strict repository-relative source manifest",
    )
    source_review.add_argument("--database", required=True, type=Path)
    source_review.add_argument("--artifact-store", required=True, type=Path)
    source_review.add_argument(
        "--hmac-env", default="ECO_SOURCE_REVIEW_HMAC_KEY"
    )
    source_review.add_argument(
        "--proof-env", default="ECO_SOURCE_REVIEW_PROOF_KEY"
    )
    source_review.add_argument("--team-id", default="research-team")
    source_review.add_argument("--run-id", required=True)
    source_review.add_argument("--store-id", required=True)
    source_review.add_argument(
        "--created-at", required=True, help="Stable UTC run time (YYYY-MM-DDTHH:MM:SSZ)"
    )
    source_review.add_argument(
        "--deadline-at", required=True, help="Absolute UTC deadline (YYYY-MM-DDTHH:MM:SSZ)"
    )
    source_review.add_argument(
        "--check", action="store_true",
        help="Verify configuration, evidence and external state locations without writing",
    )
    source_review.add_argument(
        "--route-decision", type=Path, default=None,
        help="Required exact ModelRouteDecision JSON to consume durably for this run",
    )
    source_review.add_argument(
        "--route-request", type=Path, default=None,
        help="ModelRouteRequest JSON bound to --route-decision",
    )
    source_review.add_argument(
        "--route-policy", type=Path, default=None,
        help="Exact ModelRoutingPolicy JSON authenticated by the route authority",
    )
    source_review.add_argument(
        "--route-prices", type=Path, default=None,
        help="Exact TrustedPriceCatalog JSON authenticated by the route authority",
    )
    source_review.add_argument(
        "--route-authority", type=Path, default=None,
        help="Ed25519 route-authority envelope for the exact execution plan",
    )
    source_review.add_argument("--json", action="store_true", dest="json_output")

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
    eval_suite = evaluate_commands.add_parser(
        "suite", help="Run a deterministic eval suite file with judge validation"
    )
    eval_suite.add_argument("suite_file", help="Path to an EvalSuite JSON file")
    eval_suite.add_argument("--json", action="store_true", dest="json_output")

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


def command_distribution(args: argparse.Namespace) -> int:
    from .distribution import (
        installer_plan,
        load_distribution_manifest,
        verify_distribution,
    )

    def error_code(error: Exception) -> str:
        code = getattr(error, "code", "")
        return (
            code
            if isinstance(code, str) and code.startswith("ECO_DISTRIBUTION_")
            else "ECO_DISTRIBUTION_FAILED"
        )

    try:
        manifest = load_distribution_manifest(args.manifest)
        if args.distribution_command == "verify":
            if not args.bundle_root.is_absolute():
                raise EcoError("ECO_DISTRIBUTION_PATH_INVALID")
            result = verify_distribution(manifest, args.bundle_root)
            available = bool(result["available"])
        elif args.distribution_command == "plan":
            result = installer_plan(manifest, args.adapter, args.operation)
            available = True
        else:
            raise EcoError("ECO_DISTRIBUTION_COMMAND_INVALID")
    except Exception as exc:
        code = str(exc) if isinstance(exc, EcoError) else error_code(exc)
        result = {
            "available": False,
            "status": "blocked",
            "code": code,
            "safety": {
                "authorityCreated": False,
                "installationPerformed": False,
                "projectMutation": False,
                "networkAccessed": False,
            },
        }
        available = False

    if args.json_output:
        print(stable_json(result), end="")
    elif available:
        print(
            "Distribution verified"
            if args.distribution_command == "verify"
            else "Installer preview created; nothing was executed"
        )
    else:
        print(f"Distribution blocked ({result['code']})", file=sys.stderr)
    return 0 if available else 1


def command_conformance(args: argparse.Namespace) -> int:
    if args.conformance_command != "run":
        raise EcoError("ECO_CONFORMANCE_COMMAND_INVALID")
    from eco_runtime.backend_conformance import run_backend_conformance
    from eco_runtime.errors import RuntimePolicyError

    def load_profile(path: Path) -> dict[str, Any]:
        def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
                result[key] = value
            return result

        if not path.is_absolute():
            raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
        descriptor = -1
        try:
            before = path.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or not 1 <= before.st_size <= 2 * 1024 * 1024
                or path.resolve(strict=True) != path
                or getattr(before, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            opened = os.fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
            if any(getattr(before, field) != getattr(opened, field) for field in fields):
                raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
            raw = b""
            while len(raw) <= 2 * 1024 * 1024:
                block = os.read(descriptor, 65_536)
                if not block:
                    break
                raw += block
            after = os.fstat(descriptor)
            if len(raw) != after.st_size or any(
                getattr(opened, field) != getattr(after, field) for field in fields
            ):
                raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
            document = json.loads(
                raw.decode("utf-8"), object_pairs_hook=no_duplicates
            )
            if not isinstance(document, dict):
                raise EcoError("ECO_CONFORMANCE_PLATFORM_PROFILE_INVALID")
            return document
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    try:
        profile = load_profile(args.platform_profile)
        result = run_backend_conformance(
            profile,
            test_root=args.test_root,
            repository=_repo(args),
            distribution_manifest_digest=args.distribution_manifest_digest,
            backend_instance_digest=args.backend_instance_digest,
            suite_digest=args.suite_digest,
            active=args.active,
            now=datetime.now(timezone.utc),
        )
    except (EcoError, RuntimePolicyError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        code = getattr(
            exc,
            "code",
            str(exc)
            if isinstance(exc, EcoError) and str(exc).startswith("ECO_")
            else "ECO_CONFORMANCE_FAILED",
        )
        result = {
            "available": False,
            "status": "blocked",
            "code": code,
            "safety": {
                "authenticated": False,
                "authorityCreated": False,
                "runtimeConsumed": False,
                "projectMutation": False,
                "rawOutputPersisted": False,
            },
        }
    available = result.get("spec", {}).get("status") == "pass"
    if args.json_output:
        print(stable_json(result), end="")
    elif available:
        print("Backend conformance passed; unsigned evidence candidate emitted")
    else:
        code = result.get("code") or result.get("spec", {}).get(
            "deviationCodes", ["ECO_CONFORMANCE_FAILED"]
        )[0]
        print(f"Backend conformance unavailable ({code})", file=sys.stderr)
    return 0 if available else 1


def _authority_failure(operation: str, code: str) -> dict[str, Any]:
    return {
        "available": False,
        "operation": operation,
        "status": "blocked",
        "code": code if code.startswith("ECO_") else "ECO_AUTHORITY_FAILED",
        "currentness": "not-established",
        "activationEligible": False,
        "safety": {
            "permissionsGranted": False,
            "runtimeAuthorityCreated": False,
            "policyActivated": False,
            "repositoryMutation": False,
            "networkAccessed": False,
        },
    }


def command_policy(args: argparse.Namespace) -> int:
    from eco_runtime.errors import ContractValidationError, RuntimePolicyError
    from eco_runtime.policy_bundle import TeamPolicyVerifier
    from eco_runtime.team_identity import validate_authority_record

    from .authority import (
        load_trust_anchor,
        observed_at,
        parse_canonical_json,
        read_regular_file,
    )

    operation = f"policy-{args.policy_command}"
    try:
        repo = _repo(args)
        if args.policy_command == "inspect":
            document = parse_canonical_json(read_regular_file(args.record))
            validate_authority_record(document)
            if document["kind"] != "TeamPolicyBundle":
                raise EcoError("ECO_TEAM_POLICY_BUNDLE_INVALID")
            result = {
                "available": True,
                "operation": operation,
                "status": "structurally-valid",
                "bundleId": document["metadata"]["id"],
                "revision": document["metadata"]["revision"],
                "authenticity": "not-established",
                "currentness": "not-established",
                "activationEligible": False,
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": False,
                    "policyActivated": False,
                    "repositoryMutation": False,
                    "networkAccessed": False,
                },
            }
        elif args.policy_command == "verify":
            envelope = read_regular_file(args.envelope)
            anchor = load_trust_anchor(
                read_regular_file(args.trust_anchor, forbidden_root=repo)
            )
            verified = TeamPolicyVerifier(anchor).verify(
                envelope,
                expected_project_id=args.project,
                now=observed_at(),
            )
            result = {
                "available": True,
                "operation": operation,
                "status": "signature-verified",
                "bundleId": verified.bundle_id,
                "bundleDigest": verified.bundle_digest,
                "revision": verified.revision,
                "issuerTeamId": verified.issuer_team_id,
                "issuerKeyId": verified.issuer_key_id,
                "authenticity": "relative-to-supplied-anchor",
                "trustBasis": "caller-supplied-external-anchor",
                "currentness": verified.currentness,
                "activationEligible": verified.activation_eligible,
                "safety": {
                    "permissionsGranted": False,
                    "runtimeAuthorityCreated": verified.authority_created,
                    "policyActivated": False,
                    "repositoryMutation": False,
                    "networkAccessed": False,
                },
            }
        else:
            raise EcoError("ECO_AUTHORITY_COMMAND_INVALID")
    except (EcoError, ContractValidationError, RuntimePolicyError, OSError) as exc:
        code = getattr(exc, "code", str(exc))
        result = _authority_failure(operation, code)
    if args.json_output:
        print(stable_json(result), end="")
    elif result["available"]:
        print(
            "Policy signature verified relative to the supplied anchor; activation and runtime authority were not created"
            if args.policy_command == "verify"
            else "Policy declaration is structurally valid; authenticity is not established"
        )
    else:
        print(f"Policy operation blocked ({result['code']})", file=sys.stderr)
    return 0 if result["available"] else 1


def command_identity(args: argparse.Namespace) -> int:
    from eco_runtime.errors import ContractValidationError
    from eco_runtime.team_identity import validate_authority_record

    from .authority import parse_canonical_json, read_regular_file

    operation = "identity-inspect"
    try:
        if args.identity_command != "inspect":
            raise EcoError("ECO_AUTHORITY_COMMAND_INVALID")
        _repo(args)
        document = parse_canonical_json(read_regular_file(args.record))
        validate_authority_record(document)
        if document["kind"] not in {
            "PrincipalIdentity",
            "TeamIdentity",
            "MembershipBinding",
            "IdentityKey",
        }:
            raise EcoError("ECO_AUTHORITY_IDENTITY_KIND_INVALID")
        result = {
            "available": True,
            "operation": operation,
            "status": "structurally-valid",
            "kind": document["kind"],
            "id": document["metadata"]["id"],
            "statusClaim": document["spec"]["status"],
            "authenticity": "not-established",
            "currentness": "not-established",
            "activationEligible": False,
            "safety": {
                "permissionsGranted": False,
                "runtimeAuthorityCreated": False,
                "policyActivated": False,
                "repositoryMutation": False,
                "networkAccessed": False,
            },
        }
    except (EcoError, ContractValidationError, OSError) as exc:
        code = getattr(exc, "code", str(exc))
        result = _authority_failure(operation, code)
    if args.json_output:
        print(stable_json(result), end="")
    elif result["available"]:
        print("Identity declaration is structurally valid; authority was not created")
    else:
        print(f"Identity inspection blocked ({result['code']})", file=sys.stderr)
    return 0 if result["available"] else 1


def _caps(value: str) -> list[str]:
    return [c.strip() for c in value.split(",") if c.strip()]


def _command_skills_gsc(args: argparse.Namespace) -> int:
    import hashlib

    from eco_gsc import HumanApproval, PromotionError, gate_skill_proposal, promote_skill

    try:
        text = Path(args.proposal_file).read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, OSError):
        result = {"available": False, "status": "blocked", "code": "ECO_GSC_FILE_UNREADABLE"}
        print(stable_json(result) if args.json_output else f"Proposal: blocked ({result['code']})", end="" if args.json_output else "\n")
        return 1

    if args.skills_command == "propose":
        verdict = gate_skill_proposal(
            text, declared_capabilities=_caps(args.capabilities), allowed_capabilities=_caps(args.allowed)
        )
        if args.json_output:
            print(stable_json({"available": verdict.admissible, "status": "gated", **verdict.as_record()}), end="")
        else:
            state = "ADMISSIBLE (ready for human approval)" if verdict.admissible else "REJECTED"
            print(f"Proposal: {state} ({verdict.code})")
            if verdict.reasons:
                print("  reasons: " + "; ".join(verdict.reasons))
        return 0 if verdict.admissible else 1

    # promote (L0): explicit approval bound to the exact content digest
    approval = HumanApproval(approver_id=args.approve, approved_digest=hashlib.sha256(text.encode("utf-8")).hexdigest())
    try:
        receipt = promote_skill(
            text, declared_capabilities=_caps(args.capabilities), allowed_capabilities=_caps(args.allowed),
            approval=approval, skills_root=args.into,
        )
    except PromotionError as exc:
        if args.json_output:
            print(stable_json({"available": False, "status": "blocked", "code": exc.code}), end="")
        else:
            print(f"Promotion: blocked ({exc.code})")
        return 1
    if args.json_output:
        print(stable_json({"available": True, "status": "promoted", **receipt.as_record()}), end="")
    else:
        print(f"Promotion: {receipt.skill_id} promoted by {receipt.approver_id}")
        print(f"  written: {receipt.path}")
    return 0


def command_skills(args: argparse.Namespace) -> int:
    if args.skills_command in ("propose", "promote"):
        return _command_skills_gsc(args)
    if args.skills_command == "import-plan":
        from eco_skills import UpstreamSkillImportError, inspect_upstream_skills

        try:
            result = inspect_upstream_skills(
                args.source_root,
                source_uri=args.source_uri,
                commit=args.commit,
                selection=tuple(args.skill),
            )
        except UpstreamSkillImportError as exc:
            result = {
                "available": False,
                "operation": "import-plan",
                "status": "blocked",
                "code": exc.code,
                "safety": {
                    "networkAccessed": False,
                    "skillCodeExecuted": False,
                    "hooksLoaded": False,
                    "dependenciesInstalled": False,
                    "filesWritten": False,
                    "credentialsConsumed": False,
                    "runtimeAuthorityCreated": False,
                },
            }
            if args.json_output:
                print(stable_json(result), end="")
            else:
                print(f"Upstream skill import plan: blocked ({exc.code})", file=sys.stderr)
            return 1
        if args.json_output:
            print(stable_json(result), end="")
        else:
            summary = result["summary"]
            print(
                "Upstream skill import plan: reviewed "
                f"({summary['selectedCandidates']} candidates; "
                f"{summary['blockedCandidates']} blocked; "
                f"{summary['brokenSymlinks']} broken symlinks)"
            )
            print("Promotion: not eligible; run the separate proposal gate after review")
        return 0
    from eco_skills import (
        SkillSyncError,
        check_skills,
        plan_skills,
        sync_skills,
        uninstall_skills,
    )

    operations = {
        "plan": plan_skills,
        "sync": sync_skills,
        "check": check_skills,
        "uninstall": uninstall_skills,
    }
    operation = args.skills_command
    try:
        result = operations[operation](_repo(args))
    except SkillSyncError as exc:
        if not args.json_output:
            raise
        result = {
            "available": False,
            "operation": operation,
            "status": "blocked",
            "code": exc.code,
            "safety": {
                "skillCodeExecuted": False,
                "networkAccessed": False,
                "unmanagedFilesOverwritten": False,
                "runtimeAuthorityCreated": False,
            },
        }
    if args.json_output:
        print(stable_json(result), end="")
    elif operation == "plan":
        state = "ready" if result["available"] else "blocked"
        print(f"Skill synchronization plan: {state} ({result['projectionCount']} projections)")
    elif operation == "sync" and result["available"]:
        print(f"Skill projections synchronized ({result['changed']} changes)")
    elif operation == "check" and result["available"]:
        print("Skill projections are synchronized")
    elif operation == "uninstall" and result["available"]:
        print(f"Skill projections removed ({result['removed']} files)")
    else:
        print(f"Skill operation blocked ({result.get('code', 'ECO_SKILL_DRIFT')})", file=sys.stderr)
    if operation == "plan":
        return 0
    return 0 if result["available"] else 1


def command_team(args: argparse.Namespace) -> int:
    from .team import activate_team_policy_file, doctor_team_authority

    operation = (
        "team-run-source-review-check"
        if args.team_command == "run" and args.check
        else "team-run-source-review"
        if args.team_command == "run"
        else f"team-{args.team_command}"
    )
    try:
        repo = _repo(args)
        if args.team_command == "run":
            if args.team_run_command != "source-review":
                raise EcoError("ECO_SOURCE_REVIEW_COMMAND_INVALID")
            errors, bundle, _ = _validate(repo, args.config_root)
            if errors:
                raise EcoError("ECO_CONFIG_INVALID")
            from .source_review import preflight_source_review, run_source_review

            common = {
                "repository": repo,
                "bundle": bundle,
                "manifest_path": str(args.manifest),
                "database_path": args.database,
                "artifact_store_path": args.artifact_store,
                "hmac_env": args.hmac_env,
                "proof_env": args.proof_env,
                "team_id": args.team_id,
                "run_id": args.run_id,
                "store_id": args.store_id,
                "created_at": args.created_at,
                "deadline_at": args.deadline_at,
                "route_decision_path": args.route_decision,
                "route_request_path": args.route_request,
                "route_policy_path": args.route_policy,
                "route_price_catalog_path": args.route_prices,
                "route_authority_path": args.route_authority,
            }
            result = (
                preflight_source_review(**common)
                if args.check
                else run_source_review(**common)
            )
        else:
            common = {
                "database_path": args.database,
                "trust_anchor_path": args.trust_anchor,
                "forbidden_root": repo,
                "project_id": args.project,
                "audit_key_id": args.audit_key_id,
                "hmac_env": args.hmac_env,
                "store_id": args.store_id,
            }
            if args.team_command == "doctor":
                result = doctor_team_authority(**common)
            elif args.team_command != "activate":
                raise EcoError("ECO_AUTHORITY_COMMAND_INVALID")
            else:
                if not args.apply:
                    raise EcoError("ECO_TEAM_ACTIVATION_CONFIRMATION_REQUIRED")
                result = activate_team_policy_file(
                    **common,
                    envelope_path=args.envelope,
                    activation_id=args.activation_id,
                    expected_previous=(
                        args.expected_revision,
                        args.expected_digest,
                    ),
                    expected_snapshot_digest=args.expected_snapshot_digest,
                )
    except Exception as exc:
        code = getattr(exc, "code", str(exc))
        result = {
            "available": False,
            "operation": operation,
            "status": "blocked",
            "code": code if str(code).startswith("ECO_") else "ECO_TEAM_FAILED",
            "safety": {
                "secretExposed": False,
                "pathExposed": False,
                "rawEnvelopeExposed": False,
                "repositoryMutation": False,
                "networkAccessed": False,
            },
        }
    if args.json_output:
        print(stable_json(result), end="")
    elif result["available"]:
        if args.team_command == "run":
            print(
                "Source-review preflight is ready"
                if args.check
                else f"Source-review {result['status']}"
            )
        else:
            print(
                "Team authority verified"
                if args.team_command == "doctor"
                else f"Team policy {result['status']}"
            )
    else:
        print(f"Team operation blocked ({result['code']})", file=sys.stderr)
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


_ROUTE_INPUT_LIMIT_BYTES = 1_048_576


def _read_routing_json(path: Path, *, field: str) -> dict[str, Any]:
    try:
        resolved = Path(path)
        if not resolved.is_file() or resolved.stat().st_size > _ROUTE_INPUT_LIMIT_BYTES:
            raise EcoError(f"Route {field} file is missing or exceeds the input limit")
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except EcoError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EcoError(f"Route {field} file is not bounded UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise EcoError(f"Route {field} file must contain one JSON object")
    return payload


def command_route(args: argparse.Namespace) -> int:
    from eco_routing import (
        DeterministicModelRouter,
        RoutingError,
        candidates_from_deployment_catalog,
    )

    repo = _repo(args)
    errors, bundle, _paths = _validate(repo, args.config_root)
    if errors:
        _print_errors(errors)
        return 1
    policy = _read_routing_json(args.policy, field="policy")
    prices = _read_routing_json(args.prices, field="price-catalog")
    request = _read_routing_json(args.request, field="request")
    observations = [
        _read_routing_json(item, field="observation") for item in args.observation
    ]
    if args.at is None:
        routed_at = datetime.now(timezone.utc)
    else:
        try:
            routed_at = datetime.fromisoformat(str(args.at).replace("Z", "+00:00"))
        except ValueError as exc:
            raise EcoError("Route time is invalid") from exc
        if routed_at.tzinfo is None:
            raise EcoError("Route time is invalid")
    try:
        router = DeterministicModelRouter(policy, prices)
        candidates = candidates_from_deployment_catalog(bundle["deployments"])
        outcome = router.route(
            request,
            candidates,
            observations,
            now=routed_at,
            decision_id=args.decision_id,
            explain_id=args.explain_id,
        )
    except RoutingError as exc:
        raise EcoError(exc.code) from exc
    decision = outcome.decision
    result = {"decision": decision, "explain": outcome.explain}
    allowed = decision["spec"]["decision"] == "allowed"
    if args.json_output:
        print(stable_json(result), end="")
    else:
        verdict = decision["spec"]["decision"]
        reason = decision["spec"]["reasonCode"]
        print(f"Route: {verdict} ({reason})")
        if allowed:
            selected = decision["spec"]["selected"]
            print(f"Selected deployment: {selected['deploymentId']}")
            print(f"Reserved cost (microUSD): {selected['reservedCostMicrousd']}")
    return 0 if allowed else 1


def command_loops(args: argparse.Namespace) -> int:
    from datetime import timedelta

    from eco_loops import BoundedLoopEngine, InMemoryLoopJournal, LoopEngineError
    from eco_loops.compatibility import wiki_health_executor
    from eco_loops.profiles import profile, validate_profile
    from eco_runtime.digests import semantic_digest

    try:
        definition = profile(
            args.profile,
            deadline=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
    except KeyError as exc:
        raise EcoError("ECO_LOOP_PROFILE_UNKNOWN") from exc

    if args.loops_command == "validate":
        result = validate_profile(definition)
    elif args.loops_command == "run":
        repo = _repo(args)
        errors, bundle, _ = _validate(repo, args.config_root)
        if errors:
            result = {
                "available": False,
                "loop": definition.loop_id,
                "profile": definition.profile,
                "state": "failed",
                "code": "ECO_CONFIG_INVALID",
                "safety": {
                    "repositoryMutation": "denied",
                    "modelEgress": "not-used",
                    "network": "not-used",
                    "writeAuthority": "not-created",
                    "content": "not-emitted",
                },
            }
        else:
            executor, gate, holder = wiki_health_executor(repo, bundle)
            run_seed = semantic_digest(
                {
                    "definition": definition.digest,
                    "config": semantic_digest(bundle),
                    "profile": definition.profile,
                }
            )
            journal = InMemoryLoopJournal()
            try:
                checkpoint = BoundedLoopEngine(definition, journal).run(
                    f"loop-wiki-{run_seed[:24]}", executor, gate
                )
            except LoopEngineError as exc:
                raise EcoError(exc.code) from exc
            delegated = holder.get("result", {})
            result = {
                "available": checkpoint.state == "succeeded",
                "loop": definition.loop_id,
                "profile": definition.profile,
                "definitionDigest": definition.digest,
                "state": checkpoint.state,
                "code": checkpoint.terminal_reason,
                "usage": checkpoint.usage.record(),
                "evidence": {
                    "eventCount": len(journal.events(checkpoint.run_id)),
                    "headDigest": checkpoint.head_digest,
                    "delegatedReportDigest": delegated.get("report", {}).get("digest"),
                },
                "safety": {
                    "repositoryMutation": "denied",
                    "modelEgress": "not-used",
                    "network": "not-used",
                    "writeAuthority": "not-created",
                    "content": "not-emitted",
                },
            }
    else:
        raise EcoError("ECO_LOOP_COMMAND_INVALID")

    if args.json_output:
        print(stable_json(result), end="")
    else:
        print(f"Loop: {result['loop']} ({result['profile']})")
        if "state" in result:
            print(f"State: {result['state']} ({result['code']})")
        else:
            print("Profile: valid")
        print("Safety: deterministic no-model/report-only boundary")
    return 0 if result["available"] else 1


def _command_eval_suite(args: argparse.Namespace) -> int:
    from eco_eval import EvalError, load_eval_suite, run_eval_suite

    path = Path(args.suite_file)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        verdict = run_eval_suite(load_eval_suite(document))
    except (FileNotFoundError, IsADirectoryError):
        result: dict[str, Any] = {"available": False, "status": "blocked", "code": "ECO_EVAL_FILE_UNREADABLE"}
    except json.JSONDecodeError:
        result = {"available": False, "status": "blocked", "code": "ECO_EVAL_FILE_INVALID"}
    except EvalError as exc:
        result = {"available": False, "status": "blocked", "code": exc.code}
    else:
        result = {"available": verdict.available, "status": "evaluated", **verdict.as_record()}
    if args.json_output:
        print(stable_json(result), end="")
    elif result["status"] == "blocked":
        print(f"Eval suite: blocked ({result['code']})")
    else:
        print(f"Eval suite: {result['suiteId']} ({'PASS' if result['available'] else 'FAIL'})")
        print(f"Judge validated: {result['judgeValidated']}")
        print(f"Passed {result['passed']}/{result['total']} (threshold {result['threshold']})")
    return 0 if result["available"] else 1


def command_eval(args: argparse.Namespace) -> int:
    if args.eval_command == "suite":
        return _command_eval_suite(args)
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
    "distribution": command_distribution,
    "conformance": command_conformance,
    "policy": command_policy,
    "identity": command_identity,
    "skills": command_skills,
    "loops": command_loops,
    "route": command_route,
    "team": command_team,
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
