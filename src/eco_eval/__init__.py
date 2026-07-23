"""P1 general deterministic evaluation harness.

A vendor-neutral eval harness in the shape the vendor cookbooks converge on
(``claude/tool_evaluation``): an eval suite file → N independent grader runs →
metrics → a signed-free verdict. Its distinguishing property is *validate the
judge*: before any task is graded, the grader must pass a known-good
calibration case and fail a known-broken one; a grader that cannot catch a
deliberately broken case fails the suite closed. Graders in this slice are
deterministic functions (no live model), so the whole harness is reproducible
and testable offline.
"""

from .harness import (
    EvalError,
    EvalSuite,
    EvalTask,
    EvalVerdict,
    GraderCalibration,
    available_graders,
    load_eval_suite,
    run_eval_suite,
)

__all__ = [
    "EvalError",
    "EvalSuite",
    "EvalTask",
    "EvalVerdict",
    "GraderCalibration",
    "available_graders",
    "load_eval_suite",
    "run_eval_suite",
]
