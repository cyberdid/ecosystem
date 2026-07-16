from __future__ import annotations

API_VERSION = "ai.ecosystem/v1alpha1"
VERSION = "0.1.0"

CONFIG_FILES = {
    "project": "project.yaml",
    "instructions": "instructions.yaml",
    "capabilities": "capabilities.yaml",
    "deployments": "deployments.yaml",
    "tools": "tools.yaml",
    "trust": "trust.yaml",
}

SCHEMA_FILES = {
    "project": "project.schema.json",
    "instructions": "instructions.schema.json",
    "capabilities": "capabilities.schema.json",
    "deployments": "deployments.schema.json",
    "tools": "tools.schema.json",
    "trust": "trust.schema.json",
}

PROJECTION_CLIENTS = ("codex", "claude", "copilot", "gemini", "cursor")

MANAGED_START_PREFIX = "<!-- eco:managed:start"
MANAGED_END = "<!-- eco:managed:end -->"

DATA_CLASSES = ("D0", "D1", "D2", "D3", "D4")
ACTION_CLASSES = ("A0", "A1", "A2", "A3", "A4")
ZONES = ("Z0", "Z1", "Z2", "Z3", "Z4")
ARTIFACT_TRUST = ("P0", "P1", "P2", "P3", "P4")
