from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .contracts import validate_record
from .digests import semantic_digest
from .errors import RuntimeBudgetError


@dataclass(frozen=True)
class BudgetSnapshot:
    run_id: str
    plan_digest: str
    tool_requests: int
    input_bytes: int
    reserved_input_bytes: int
    output_bytes: int
    model_requests: int
    total_tokens: int
    cost_microusd: int


class InputByteReservation:
    def __init__(self, ledger: BudgetLedger, reservation_id: int, byte_count: int):
        self._ledger = ledger
        self._reservation_id = reservation_id
        self.byte_count = byte_count
        self._finished = False

    def commit(self, actual_byte_count: int) -> None:
        if self._finished:
            raise RuntimeBudgetError("ECO_BUDGET_RESERVATION_USED", "Budget reservation is already closed")
        self._ledger._commit_input_reservation(self._reservation_id, actual_byte_count)
        self._finished = True

    def release(self) -> None:
        if not self._finished:
            self._ledger._release_input_reservation(self._reservation_id)
            self._finished = True

    def __enter__(self) -> InputByteReservation:
        return self

    def __exit__(self, *_: object) -> None:
        self.release()


class BudgetLedger:
    """In-process, monotonic, atomic accounting bound to one immutable RunPlan."""

    def __init__(self, plan: dict[str, Any], *, clock: Callable[[], float] = time.monotonic):
        plan = copy.deepcopy(validate_record(plan))
        self._run_id = plan["metadata"]["runId"]
        self._plan_digest = semantic_digest(plan)
        self._limits = copy.deepcopy(plan["spec"]["budget"])
        self._clock = clock
        self._started_at = clock()
        self._tool_requests = 0
        self._input_bytes = sum(item["byteLength"] for item in plan["spec"]["inputs"])
        self._reserved_input_bytes = 0
        self._next_reservation_id = 1
        self._input_reservations: dict[int, int] = {}
        self._output_bytes = 0
        self._model_requests = 0
        self._total_tokens = 0
        self._cost_microusd = 0
        self._lock = threading.Lock()
        if self._input_bytes > self._limits["maxInputBytes"]:
            raise RuntimeBudgetError("ECO_BUDGET_EXHAUSTED", "Initial inputs exceed the run budget")

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def plan_digest(self) -> str:
        return self._plan_digest

    def _check_duration_locked(self) -> None:
        if self._clock() - self._started_at > self._limits["maxDurationSeconds"]:
            raise RuntimeBudgetError("ECO_DURATION_EXHAUSTED", "Run duration budget is exhausted")

    def reserve_tool_request(self) -> int:
        """Spend one request and return the remaining input-byte allowance."""

        with self._lock:
            self._check_duration_locked()
            if self._tool_requests >= self._limits["maxToolRequests"]:
                raise RuntimeBudgetError("ECO_TOOL_BUDGET_EXHAUSTED", "Tool request budget is exhausted")
            self._tool_requests += 1
            return self._limits["maxInputBytes"] - self._input_bytes - self._reserved_input_bytes

    def reserve_input_bytes(self, byte_count: int) -> InputByteReservation:
        if not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("byte_count must be a non-negative integer")
        with self._lock:
            self._check_duration_locked()
            if self._input_bytes + self._reserved_input_bytes + byte_count > self._limits["maxInputBytes"]:
                raise RuntimeBudgetError("ECO_INPUT_BUDGET_EXHAUSTED", "Input byte budget is exhausted")
            reservation_id = self._next_reservation_id
            self._next_reservation_id += 1
            self._input_reservations[reservation_id] = byte_count
            self._reserved_input_bytes += byte_count
            return InputByteReservation(self, reservation_id, byte_count)

    def _release_input_reservation(self, reservation_id: int) -> None:
        with self._lock:
            byte_count = self._input_reservations.pop(reservation_id, None)
            if byte_count is None:
                raise RuntimeBudgetError("ECO_BUDGET_RESERVATION_INVALID", "Budget reservation is unknown")
            self._reserved_input_bytes -= byte_count

    def _commit_input_reservation(self, reservation_id: int, actual_byte_count: int) -> None:
        if not isinstance(actual_byte_count, int) or actual_byte_count < 0:
            raise ValueError("actual_byte_count must be a non-negative integer")
        with self._lock:
            reserved = self._input_reservations.get(reservation_id)
            if reserved is None:
                raise RuntimeBudgetError("ECO_BUDGET_RESERVATION_INVALID", "Budget reservation is unknown")
            if actual_byte_count > reserved:
                raise RuntimeBudgetError(
                    "ECO_INPUT_BUDGET_EXHAUSTED",
                    "Actual input exceeds its byte reservation",
                )
            self._input_reservations.pop(reservation_id)
            self._reserved_input_bytes -= reserved
            self._input_bytes += actual_byte_count

    def consume_input_bytes(self, byte_count: int) -> None:
        if not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("byte_count must be a non-negative integer")
        with self._lock:
            self._check_duration_locked()
            if self._input_bytes + self._reserved_input_bytes + byte_count > self._limits["maxInputBytes"]:
                raise RuntimeBudgetError("ECO_INPUT_BUDGET_EXHAUSTED", "Input byte budget is exhausted")
            self._input_bytes += byte_count

    def consume_model_usage(
        self,
        *,
        output_bytes: int,
        tokens: int,
        cost_microusd: int,
    ) -> None:
        values = (output_bytes, tokens, cost_microusd)
        if any(not isinstance(value, int) or value < 0 for value in values):
            raise ValueError("usage values must be non-negative integers")
        with self._lock:
            self._check_duration_locked()
            proposed = {
                "model": self._model_requests + 1,
                "output": self._output_bytes + output_bytes,
                "tokens": self._total_tokens + tokens,
                "cost": self._cost_microusd + cost_microusd,
            }
            if proposed["model"] > self._limits["maxModelRequests"]:
                raise RuntimeBudgetError("ECO_MODEL_BUDGET_EXHAUSTED", "Model request budget is exhausted")
            if proposed["output"] > self._limits["maxOutputBytes"]:
                raise RuntimeBudgetError("ECO_OUTPUT_BUDGET_EXHAUSTED", "Output byte budget is exhausted")
            if proposed["tokens"] > self._limits["maxTotalTokens"]:
                raise RuntimeBudgetError("ECO_TOKEN_BUDGET_EXHAUSTED", "Token budget is exhausted")
            if proposed["cost"] > self._limits["maxCostMicrousd"]:
                raise RuntimeBudgetError("ECO_COST_BUDGET_EXHAUSTED", "Cost budget is exhausted")
            self._model_requests = proposed["model"]
            self._output_bytes = proposed["output"]
            self._total_tokens = proposed["tokens"]
            self._cost_microusd = proposed["cost"]

    def snapshot(self) -> BudgetSnapshot:
        with self._lock:
            return BudgetSnapshot(
                run_id=self._run_id,
                plan_digest=self._plan_digest,
                tool_requests=self._tool_requests,
                input_bytes=self._input_bytes,
                reserved_input_bytes=self._reserved_input_bytes,
                output_bytes=self._output_bytes,
                model_requests=self._model_requests,
                total_tokens=self._total_tokens,
                cost_microusd=self._cost_microusd,
            )
