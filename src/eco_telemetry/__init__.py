"""P5 cost/observability telemetry.

A telemetry ledger separate from the audit chain and from per-run budget
enforcement (``eco_runtime.budget``). It records content-free per-run and
per-role token/cost/time and enforces explicit caps *before* spend is accepted:
a record that would breach a cap is rejected fail-closed (stop-on-breach), it is
never admitted and reported after the fact. Records carry ids and numbers only,
never raw prompts, outputs, or paths — the Hermes "surprise bill" lesson made a
contract.
"""

from .ledger import (
    CostRecord,
    TelemetryError,
    TelemetryLedger,
    TelemetrySummary,
)

__all__ = ["CostRecord", "TelemetryError", "TelemetryLedger", "TelemetrySummary"]
