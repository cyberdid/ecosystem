from __future__ import annotations

import copy
import io
import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, Mapping

from eco_runtime.artifact_store import ContentAddressedArtifactStore
from eco_runtime.digests import canonical_json

from .contracts import (
    ORCHESTRATION_API_VERSION,
    orchestration_record_digest,
    validate_orchestration_record,
)


SOURCE_REVIEW_PROFILE_VERSION = "source-review.v1"
SOURCE_REVIEW_ROLES = ("planner", "analyst", "verifier", "synthesizer", "reviewer")
_PROFILE_KEYS = frozenset(
    {
        "roleId",
        "instruction",
        "inputKinds",
        "outputKinds",
        "allowedCapabilities",
        "allowedDataClasses",
        "modelRequirements",
        "outputSchema",
    }
)


@dataclass(frozen=True)
class PackagedRoleProfile:
    role_id: str
    instruction: str
    input_kinds: tuple[str, ...]
    output_kinds: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]
    allowed_data_classes: tuple[str, ...]
    model_requirements: Mapping[str, Any]
    output_schema: Mapping[str, Any]


@dataclass(frozen=True)
class SourceReviewDefinitions:
    profiles: tuple[dict[str, Any], ...]
    team_manifest: dict[str, Any]
    loop_definition: dict[str, Any]

    def records(self) -> tuple[dict[str, Any], ...]:
        return (*self.profiles, self.team_manifest, self.loop_definition)


def _load_json_resource(name: str) -> dict[str, Any]:
    source = resources.files("eco_orchestration").joinpath(
        "profiles", SOURCE_REVIEW_PROFILE_VERSION, name
    )
    return json.loads(source.read_text(encoding="utf-8"))


def load_packaged_role_profile(role_id: str) -> PackagedRoleProfile:
    if role_id not in SOURCE_REVIEW_ROLES:
        raise ValueError("role_id is not part of source-review.v1")
    value = _load_json_resource(f"{role_id}.json")
    if not isinstance(value, dict) or set(value) != _PROFILE_KEYS:
        raise RuntimeError("Packaged source-review profile has invalid fields")
    if value["roleId"] != role_id:
        raise RuntimeError("Packaged source-review profile role does not match")
    instruction = value["instruction"]
    if not isinstance(instruction, str) or not instruction:
        raise RuntimeError("Packaged source-review instruction is invalid")
    for field in ("inputKinds", "outputKinds", "allowedCapabilities", "allowedDataClasses"):
        if not isinstance(value[field], list) or not all(
            isinstance(item, str) for item in value[field]
        ):
            raise RuntimeError("Packaged source-review profile list is invalid")
    if not isinstance(value["modelRequirements"], dict) or not isinstance(
        value["outputSchema"], dict
    ):
        raise RuntimeError("Packaged source-review profile structure is invalid")
    return PackagedRoleProfile(
        role_id=role_id,
        instruction=instruction,
        input_kinds=tuple(value["inputKinds"]),
        output_kinds=tuple(value["outputKinds"]),
        allowed_capabilities=tuple(value["allowedCapabilities"]),
        allowed_data_classes=tuple(value["allowedDataClasses"]),
        model_requirements=copy.deepcopy(value["modelRequirements"]),
        output_schema=copy.deepcopy(value["outputSchema"]),
    )


def load_source_review_rubric() -> dict[str, Any]:
    value = _load_json_resource("rubric.json")
    if not isinstance(value, dict):
        raise RuntimeError("Packaged source-review rubric is invalid")
    return value


def _metadata(
    identifier: str, *, project_id: str, team_id: str, created_at: str
) -> dict[str, Any]:
    return {
        "id": identifier,
        "projectId": project_id,
        "teamId": team_id,
        "runId": "definition",
        "revision": 1,
        "createdAt": created_at,
        "recordDigest": "0" * 64,
    }


def _seal(value: dict[str, Any]) -> dict[str, Any]:
    value["metadata"]["recordDigest"] = orchestration_record_digest(value)
    return validate_orchestration_record(value)


def _binding(value: Mapping[str, Any]) -> dict[str, str]:
    return {
        "kind": value["kind"],
        "id": value["metadata"]["id"],
        "digest": value["metadata"]["recordDigest"],
    }


def _install_artifact(
    store: ContentAddressedArtifactStore,
    payload: bytes,
    *,
    storage_ref: str,
    data_class: str,
) -> dict[str, Any]:
    proof = store.put(io.BytesIO(payload), storage_ref=storage_ref, max_bytes=len(payload))
    store.verify_availability(proof)
    return {
        "ref": proof.storage_ref,
        "contentDigest": proof.sha256,
        "byteLength": proof.byte_length,
        "dataClass": data_class,
    }


def install_source_review_definitions(
    store: ContentAddressedArtifactStore,
    *,
    project_id: str,
    team_id: str,
    created_at: str,
    budget: Mapping[str, int],
) -> SourceReviewDefinitions:
    """Install package-owned authority artifacts and build fixed definitions."""

    if not isinstance(store, ContentAddressedArtifactStore):
        raise TypeError("store must be ContentAddressedArtifactStore")
    profiles: list[dict[str, Any]] = []
    for role_id in SOURCE_REVIEW_ROLES:
        packaged = load_packaged_role_profile(role_id)
        instruction = _install_artifact(
            store,
            packaged.instruction.encode("utf-8"),
            storage_ref=(
                f"artifact://orchestration/profiles/{SOURCE_REVIEW_PROFILE_VERSION}/"
                f"{role_id}"
            ),
            data_class="D0",
        )
        output_schema = _install_artifact(
            store,
            canonical_json(dict(packaged.output_schema)).encode("utf-8"),
            storage_ref=(
                f"artifact://orchestration/profiles/{SOURCE_REVIEW_PROFILE_VERSION}/"
                f"{role_id}-output-schema"
            ),
            data_class="D0",
        )
        profile = {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": "RoleProfile",
            "metadata": _metadata(
                f"source-review-{role_id}-v1",
                project_id=project_id,
                team_id=team_id,
                created_at=created_at,
            ),
            "spec": {
                "roleId": role_id,
                "instruction": instruction,
                "outputSchema": output_schema,
                "inputKinds": list(packaged.input_kinds),
                "outputKinds": list(packaged.output_kinds),
                "allowedCapabilities": list(packaged.allowed_capabilities),
                "allowedDataClasses": list(packaged.allowed_data_classes),
                "tools": [],
                "modelRequirements": copy.deepcopy(dict(packaged.model_requirements)),
            },
        }
        profiles.append(_seal(profile))

    rubric_bytes = canonical_json(load_source_review_rubric()).encode("utf-8")
    rubric = _install_artifact(
        store,
        rubric_bytes,
        storage_ref=f"artifact://orchestration/profiles/{SOURCE_REVIEW_PROFILE_VERSION}/rubric",
        data_class="D0",
    )
    team = _seal(
        {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": "TeamManifest",
            "metadata": _metadata(
                "source-review-team-v1",
                project_id=project_id,
                team_id=team_id,
                created_at=created_at,
            ),
            "spec": {
                "workflow": "source-review",
                "roles": [
                    {"roleId": role, "profile": _binding(profile)}
                    for role, profile in zip(SOURCE_REVIEW_ROLES, profiles)
                ],
                "edges": [
                    {"from": source, "to": target}
                    for source, target in zip(
                        SOURCE_REVIEW_ROLES, SOURCE_REVIEW_ROLES[1:]
                    )
                ],
                "maxRevisionCycles": 1,
                "gate": {
                    "owner": "runtime",
                    "rubric": rubric,
                    "acceptedVerdict": "accepted",
                },
            },
        }
    )
    loop = _seal(
        {
            "apiVersion": ORCHESTRATION_API_VERSION,
            "kind": "LoopDefinition",
            "metadata": _metadata(
                "source-review-loop-v1",
                project_id=project_id,
                team_id=team_id,
                created_at=created_at,
            ),
            "spec": {
                "workflow": "source-review",
                "teamManifest": _binding(team),
                "trigger": "manual",
                "maxIterations": 2,
                "budget": copy.deepcopy(dict(budget)),
                "gate": {
                    "owner": "runtime",
                    "reviewRole": "reviewer",
                    "rubricDigest": rubric["contentDigest"],
                    "acceptedVerdict": "accepted",
                },
                "hardStops": [
                    "budget-exhausted",
                    "cancelled",
                    "deadline",
                    "policy-denied",
                    "revision-exhausted",
                    "verification-failed",
                ],
            },
        }
    )
    return SourceReviewDefinitions(tuple(profiles), team, loop)
