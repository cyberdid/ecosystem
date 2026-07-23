from __future__ import annotations

"""Content-free, cap-enforcing telemetry ledger."""

import re
from dataclasses import dataclass, field
from typing import Any

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}\Z")


class TelemetryError(Exception):
    """Typed, fail-closed telemetry error. Carries a stable code only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise TelemetryError("ECO_TELEMETRY_INVALID")
    return value


def _non_negative(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise TelemetryError("ECO_TELEMETRY_INVALID")
    return value


@dataclass(frozen=True)
class CostRecord:
    """One content-free spend event: ids and numbers only."""

    run_id: str
    role_id: str
    tokens: int
    cost_microusd: int
    elapsed_ms: int

    def __post_init__(self) -> None:
        _identifier(self.run_id)
        _identifier(self.role_id)
        _non_negative(self.tokens)
        _non_negative(self.cost_microusd)
        _non_negative(self.elapsed_ms)

    def as_record(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            "roleId": self.role_id,
            "tokens": self.tokens,
            "costMicrousd": self.cost_microusd,
            "elapsedMs": self.elapsed_ms,
        }


@dataclass(frozen=True)
class TelemetrySummary:
    total_tokens: int
    total_cost_microusd: int
    total_elapsed_ms: int
    per_role: dict[str, dict[str, int]]
    cost_cap_microusd: int | None
    token_cap: int | None

    def as_record(self) -> dict[str, Any]:
        return {
            "totalTokens": self.total_tokens,
            "totalCostMicrousd": self.total_cost_microusd,
            "totalElapsedMs": self.total_elapsed_ms,
            "perRole": {k: dict(v) for k, v in sorted(self.per_role.items())},
            "costCapMicrousd": self.cost_cap_microusd,
            "tokenCap": self.token_cap,
            "costHeadroomMicrousd": (
                None if self.cost_cap_microusd is None else self.cost_cap_microusd - self.total_cost_microusd
            ),
            "tokenHeadroom": (None if self.token_cap is None else self.token_cap - self.total_tokens),
        }


class TelemetryLedger:
    """Accumulates content-free cost records and enforces caps fail-closed.

    A record that would push total cost or tokens past a configured cap is
    rejected with ``ECO_TELEMETRY_CAP_EXCEEDED`` and is *not* recorded. Caps are
    enforced before spend is admitted, never reconciled afterwards.
    """

    def __init__(self, *, cost_cap_microusd: int | None = None, token_cap: int | None = None):
        if cost_cap_microusd is not None:
            _non_negative(cost_cap_microusd)
        if token_cap is not None:
            _non_negative(token_cap)
        self._cost_cap = cost_cap_microusd
        self._token_cap = token_cap
        self._records: list[CostRecord] = []
        self._total_tokens = 0
        self._total_cost = 0
        self._total_elapsed = 0
        self._per_role: dict[str, dict[str, int]] = {}

    def record(self, event: CostRecord) -> None:
        if not isinstance(event, CostRecord):
            raise TelemetryError("ECO_TELEMETRY_INVALID")
        if self._cost_cap is not None and self._total_cost + event.cost_microusd > self._cost_cap:
            raise TelemetryError("ECO_TELEMETRY_CAP_EXCEEDED")
        if self._token_cap is not None and self._total_tokens + event.tokens > self._token_cap:
            raise TelemetryError("ECO_TELEMETRY_CAP_EXCEEDED")
        self._records.append(event)
        self._total_tokens += event.tokens
        self._total_cost += event.cost_microusd
        self._total_elapsed += event.elapsed_ms
        role = self._per_role.setdefault(
            event.role_id, {"tokens": 0, "costMicrousd": 0, "elapsedMs": 0, "events": 0}
        )
        role["tokens"] += event.tokens
        role["costMicrousd"] += event.cost_microusd
        role["elapsedMs"] += event.elapsed_ms
        role["events"] += 1

    @property
    def within_caps(self) -> bool:
        return (self._cost_cap is None or self._total_cost <= self._cost_cap) and (
            self._token_cap is None or self._total_tokens <= self._token_cap
        )

    def summary(self) -> TelemetrySummary:
        return TelemetrySummary(
            total_tokens=self._total_tokens,
            total_cost_microusd=self._total_cost,
            total_elapsed_ms=self._total_elapsed,
            per_role={k: dict(v) for k, v in self._per_role.items()},
            cost_cap_microusd=self._cost_cap,
            token_cap=self._token_cap,
        )
