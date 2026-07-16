from __future__ import annotations

from typing import Any

from .constants import API_VERSION


def starter_bundle(name: str) -> dict[str, dict[str, Any]]:
    return {
        "project": {
            "apiVersion": API_VERSION,
            "kind": "ProjectAIConfig",
            "metadata": {"name": name, "owners": ["project-maintainers"], "riskProfile": "standard"},
            "project": {"languages": [], "build": [], "test": [], "protectedPaths": [".git/**"]},
            "references": {
                "instructions": "instructions.yaml",
                "capabilities": "capabilities.yaml",
                "deployments": "deployments.yaml",
                "tools": "tools.yaml",
                "trust": "trust.yaml",
            },
            "policy": {
                "defaultDecision": "deny",
                "unknownDataClass": "D2",
                "allowDirectEgress": False,
            },
            "runtime": {
                "profile": "embedded",
                "auditTrail": "sqlite",
                "sandboxProfile": "inspect",
                "telemetry": {"enabled": False, "includeSensitiveContent": False},
            },
        },
        "instructions": {
            "apiVersion": API_VERSION,
            "kind": "InstructionGraph",
            "metadata": {"name": name},
            "language": "uk",
            "purpose": f"Maintain {name} with verifiable, reversible changes and explicit security boundaries.",
            "principles": [
                "Canonical contracts are the source; vendor files are deterministic projections.",
                "A model may propose actions, but policy and the execution broker grant permissions.",
                "No capability is trusted until it passes a versioned conformance evaluation.",
            ],
            "rules": [
                {
                    "id": "VERIFY-DONE",
                    "priority": "must",
                    "text": "Verify completion with tests, validators, or another objective artifact.",
                },
                {
                    "id": "PRESERVE-USER-WORK",
                    "priority": "must",
                    "text": "Preserve unrelated user changes and never destructively reset a dirty worktree.",
                },
                {
                    "id": "NO-SECRETS",
                    "priority": "must",
                    "text": "Never write credentials, tokens, passwords, or raw secret values to the repository.",
                },
            ],
            "commands": {"validate": "eco validate", "test": "python -m unittest discover -s tests"},
            "conventions": {"responseLanguage": "Ukrainian", "commitStyle": "<type>: <description>"},
            "projections": {
                "codex": "AGENTS.md",
                "claude": "CLAUDE.md",
                "copilot": ".github/copilot-instructions.md",
                "gemini": "GEMINI.md",
                "cursor": ".cursor/rules/eco.mdc",
            },
        },
        "capabilities": {
            "apiVersion": API_VERSION,
            "kind": "CapabilityCatalog",
            "capabilities": [
                {
                    "id": "model.text",
                    "description": "Generate or analyze text without an external side effect.",
                    "actionClass": "A0",
                    "sideEffect": False,
                    "defaultSandbox": "inspect",
                },
                {
                    "id": "model.tool-calling",
                    "description": "Propose typed tool calls for independent validation and authorization.",
                    "actionClass": "A0",
                    "sideEffect": False,
                    "defaultSandbox": "inspect",
                },
                {
                    "id": "filesystem.read",
                    "description": "Read project files inside the approved repository boundary.",
                    "actionClass": "A1",
                    "sideEffect": False,
                    "defaultSandbox": "inspect",
                },
                {
                    "id": "workspace.write",
                    "description": "Create or modify files inside the approved workspace sandbox.",
                    "actionClass": "A2",
                    "sideEffect": True,
                    "defaultSandbox": "workspace-change",
                },
                {
                    "id": "external.write",
                    "description": "Write to an external service or publish an artifact.",
                    "actionClass": "A3",
                    "sideEffect": True,
                    "defaultSandbox": "staging",
                },
            ],
        },
        "deployments": {
            "apiVersion": API_VERSION,
            "kind": "DeploymentCatalog",
            "deployments": [],
            "logicalRoles": {
                "code.read": {
                    "requiredCapabilities": ["model.text"],
                    "allowedDataClasses": ["D0", "D1"],
                    "allowedZones": ["Z1", "Z2", "Z3"],
                    "minimumArtifactTrust": "P1",
                    "maximumActionClass": "A1",
                    "candidates": [],
                },
                "code.write": {
                    "requiredCapabilities": ["model.text"],
                    "allowedDataClasses": ["D0", "D1"],
                    "allowedZones": ["Z0", "Z1", "Z2", "Z3"],
                    "minimumArtifactTrust": "P1",
                    "maximumActionClass": "A2",
                    "candidates": [],
                }
            },
        },
        "tools": {
            "apiVersion": API_VERSION,
            "kind": "ToolCatalog",
            "tools": [
                {
                    "id": "repository.read",
                    "transport": "builtin",
                    "binding": "workspace-filesystem",
                    "capability": "filesystem.read",
                    "actionClass": "A1",
                    "allowedSandboxes": ["inspect", "workspace-change", "build-test"],
                    "enabled": True,
                },
                {
                    "id": "repository.write",
                    "transport": "builtin",
                    "binding": "workspace-filesystem",
                    "capability": "workspace.write",
                    "actionClass": "A2",
                    "allowedSandboxes": ["workspace-change"],
                    "enabled": False,
                }
            ],
        },
        "trust": {
            "apiVersion": API_VERSION,
            "kind": "RuntimeTrustBootstrap",
            "evidence": {
                "algorithm": "HMAC-SHA256",
                "profile": "local-shared-key",
                "issuers": [
                    {
                        "id": "local-snapshot-authority",
                        "keyId": "local-snapshot-v1",
                        "verificationKeyRef": "env:ECO_SNAPSHOT_EVIDENCE_KEY",
                        "allowedKinds": ["RepositorySnapshot"],
                        "allowedProjects": [name],
                        "allowedDeployments": [],
                        "allowedSuiteDigests": [],
                    }
                ],
            },
            "repositorySnapshot": {
                "issuer": {
                    "id": "local-snapshot-authority",
                    "keyId": "local-snapshot-v1",
                    "recordIssuerType": "operator",
                },
                "envelopeRef": "env:ECO_REPOSITORY_SNAPSHOT_ENVELOPE_FILE",
                "trust": "P1",
                "maximumFileBytes": 16777216,
                "entries": [],
            },
            "conformance": {"trustedSuites": [], "requiredObservations": []},
        },
    }
