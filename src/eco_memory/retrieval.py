from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence

from eco_runtime.errors import RuntimePolicyError, RuntimeStoreError

from .contracts import DATA_CLASSES, LINK_RELATIONS, MEMORY_TYPES, PRIVACY_LEVELS
from .store import PrivateMemoryStore


class MemoryReadPolicy(Protocol):
    """Trusted caller-owned filter. Memory content cannot implement this policy."""

    def allows(self, record: Mapping[str, Any]) -> bool:
        ...


@dataclass(frozen=True)
class ExplicitMemoryReadPolicy:
    """Small fail-closed policy useful at an embedded composition boundary."""

    allowed_data_classes: tuple[str, ...]
    allowed_privacy_levels: tuple[str, ...]
    allowed_authors: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not self.allowed_data_classes or any(item not in DATA_CLASSES for item in self.allowed_data_classes):
            raise ValueError("allowed_data_classes must be an explicit non-empty subset")
        if not self.allowed_privacy_levels or any(item not in PRIVACY_LEVELS for item in self.allowed_privacy_levels):
            raise ValueError("allowed_privacy_levels must be an explicit non-empty subset")

    def allows(self, record: Mapping[str, Any]) -> bool:
        spec = record["spec"]
        return (
            spec["dataClass"] in self.allowed_data_classes
            and spec["privacyLevel"] in self.allowed_privacy_levels
            and (self.allowed_authors is None or spec["author"] in self.allowed_authors)
        )


@dataclass(frozen=True)
class MemoryQuery:
    namespace: Mapping[str, Any]
    data_classes: tuple[str, ...]
    privacy_levels: tuple[str, ...]
    memory_types: tuple[str, ...] = MEMORY_TYPES
    max_items: int = 16
    max_bytes: int = 64 * 1024
    max_tokens: int = 16 * 1024

    def __post_init__(self) -> None:
        if set(self.namespace) != {"projectId", "teamId", "runId"}:
            raise ValueError("namespace must be exact")
        if not self.data_classes or any(item not in DATA_CLASSES for item in self.data_classes):
            raise ValueError("data_classes must be an explicit non-empty subset")
        if not self.privacy_levels or any(item not in PRIVACY_LEVELS for item in self.privacy_levels):
            raise ValueError("privacy_levels must be an explicit non-empty subset")
        if not self.memory_types or any(item not in MEMORY_TYPES for item in self.memory_types):
            raise ValueError("memory_types must be an explicit non-empty subset")
        for name, value in (
            ("max_items", self.max_items),
            ("max_bytes", self.max_bytes),
            ("max_tokens", self.max_tokens),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True)
class MemoryHit:
    record: dict[str, Any]
    content: bytes

    @property
    def record_digest(self) -> str:
        return self.record["metadata"]["recordDigest"]

    def public_binding(self) -> dict[str, Any]:
        spec = self.record["spec"]
        return {
            "recordDigest": self.record_digest,
            "memoryType": spec["memoryType"],
            "dataClass": spec["dataClass"],
            "privacyLevel": spec["privacyLevel"],
            "contentArtifact": dict(spec["contentArtifact"]),
            "sourceArtifacts": list(spec["sourceArtifacts"]),
        }


@dataclass(frozen=True)
class MemoryRetrievalResult:
    hits: tuple[MemoryHit, ...]
    relations: tuple[dict[str, Any], ...]
    used_bytes: int
    estimated_tokens: int
    truncated: bool

    def as_public_dict(self) -> dict[str, Any]:
        """Return a content-free diagnostic; raw memory bytes are deliberately absent."""

        return {
            "hits": [item.public_binding() for item in self.hits],
            "relations": [dict(item) for item in self.relations],
            "usedItems": len(self.hits),
            "usedBytes": self.used_bytes,
            "estimatedTokens": self.estimated_tokens,
            "truncated": self.truncated,
        }


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def _relations(record: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    digest = record["metadata"]["recordDigest"]
    values = {
        (digest, relation, target)
        for relation in LINK_RELATIONS
        for target in record["spec"]["links"][relation]
    }
    compaction = record["spec"]["compaction"]
    if compaction is not None:
        values.update(
            (item["from"], item["relation"], item["to"])
            for item in compaction["preservedRelations"]
        )
    return values


def _policy_allows(policy: MemoryReadPolicy, record: Mapping[str, Any]) -> bool:
    try:
        decision = policy.allows(record)
    except Exception as exc:
        raise RuntimePolicyError("ECO_MEMORY_POLICY_FAILED", "Memory read policy failed closed") from exc
    if not isinstance(decision, bool):
        raise RuntimePolicyError("ECO_MEMORY_POLICY_FAILED", "Memory read policy returned an invalid decision")
    return decision


def retrieve_memory(
    store: PrivateMemoryStore,
    query: MemoryQuery,
    *,
    policy: MemoryReadPolicy,
    now: datetime,
) -> MemoryRetrievalResult:
    """Retrieve deterministic exact-namespace context under three hard budgets.

    No semantic or vector relevance is claimed. Ordering is timestamp-descending
    with digest tie-breaking. Conflict/refutation-connected records are selected
    atomically, so truncation cannot silently keep only one visible side.
    """

    if not isinstance(now, datetime) or now.tzinfo is None:
        raise RuntimeStoreError("ECO_MEMORY_CLOCK_INVALID", "Memory retrieval clock must be timezone-aware")
    current = now.astimezone(timezone.utc)
    records = store.namespace_records(query.namespace)
    by_digest = {record["metadata"]["recordDigest"]: record for record in records}

    policy_allowed = {
        digest: _policy_allows(policy, record)
        for digest, record in by_digest.items()
    }
    eligible: dict[str, dict[str, Any]] = {}
    for digest, record in by_digest.items():
        spec = record["spec"]
        expires_at = spec["expiresAt"]
        if (
            spec["dataClass"] in query.data_classes
            and spec["privacyLevel"] in query.privacy_levels
            and spec["memoryType"] in query.memory_types
            and policy_allowed[digest]
            and (expires_at is None or _parse_time(expires_at) > current)
        ):
            compaction = spec["compaction"]
            if compaction is not None:
                bound_digests = set(compaction["sourceRecordDigests"])
                bound_digests.update(item["to"] for item in compaction["preservedRelations"])
                if any(
                    target not in by_digest
                    or not policy_allowed[target]
                    or by_digest[target]["spec"]["dataClass"] not in query.data_classes
                    or by_digest[target]["spec"]["privacyLevel"] not in query.privacy_levels
                    for target in bound_digests
                ):
                    continue
            eligible[digest] = record

    all_relations = set().union(*(_relations(record) for record in records)) if records else set()
    graph: dict[str, set[str]] = {digest: set() for digest in eligible}
    blocked: set[str] = set()
    for source, relation, target in all_relations:
        if relation not in {"refutes", "conflicts"}:
            continue
        source_visible = source in eligible
        target_visible = target in eligible
        if source_visible and target_visible:
            graph[source].add(target)
            graph[target].add(source)
        elif source_visible:
            blocked.add(source)
        elif target_visible:
            blocked.add(target)
    # A filtered or expired counterpart must not leak through a digest, and the
    # visible side must not be presented as uncontested.
    stack = list(blocked)
    while stack:
        digest = stack.pop()
        for neighbor in graph.get(digest, ()):
            if neighbor not in blocked:
                blocked.add(neighbor)
                stack.append(neighbor)
    for digest in blocked:
        graph.pop(digest, None)
        eligible.pop(digest, None)
    for neighbors in graph.values():
        neighbors.difference_update(blocked)

    components: list[list[str]] = []
    unseen = set(eligible)
    while unseen:
        seed = min(unseen)
        stack = [seed]
        component: set[str] = set()
        while stack:
            digest = stack.pop()
            if digest in component:
                continue
            component.add(digest)
            stack.extend(sorted(graph.get(digest, ()), reverse=True))
        unseen.difference_update(component)
        components.append(sorted(component))

    def component_key(component: Sequence[str]) -> tuple[float, str]:
        newest = max(_parse_time(eligible[digest]["metadata"]["createdAt"]).timestamp() for digest in component)
        return (-newest, component[0])

    components.sort(key=component_key)
    selected: list[str] = []
    used_bytes = 0
    used_tokens = 0
    truncated = bool(blocked)
    for component in components:
        component_bytes = sum(eligible[digest]["spec"]["contentArtifact"]["byteLength"] for digest in component)
        component_tokens = component_bytes
        if (
            len(selected) + len(component) > query.max_items
            or used_bytes + component_bytes > query.max_bytes
            or used_tokens + component_tokens > query.max_tokens
        ):
            truncated = True
            continue
        selected.extend(component)
        used_bytes += component_bytes
        used_tokens += component_tokens

    selected.sort(
        key=lambda digest: (
            -_parse_time(eligible[digest]["metadata"]["createdAt"]).timestamp(),
            digest,
        )
    )
    hits = tuple(MemoryHit(record=eligible[digest], content=store.read_content(eligible[digest])) for digest in selected)
    selected_set = set(selected)
    relation_items: list[dict[str, Any]] = [
        {"from": source, "relation": relation, "to": target}
        for source, relation, target in sorted(all_relations)
        if source in selected_set and target in selected_set
    ]
    for digest in selected:
        compaction = eligible[digest]["spec"]["compaction"]
        if compaction is not None:
            relation_items.extend(
                {**item, "preservedBy": digest}
                for item in compaction["preservedRelations"]
            )
    relation_items.sort(
        key=lambda item: (
            item["from"], item["relation"], item["to"], item.get("preservedBy", "")
        )
    )
    explicit_relations = tuple(relation_items)
    return MemoryRetrievalResult(
        hits=hits,
        relations=explicit_relations,
        used_bytes=used_bytes,
        estimated_tokens=used_tokens,
        truncated=truncated,
    )
