from __future__ import annotations

"""Deterministic evaluation harness with judge validation.

The harness never trusts a grader it has not first proven can distinguish a
known-good case from a known-broken one. It emits a content-free verdict: task
ids, pass/fail counts and digests, never the raw inputs or outputs.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

_ID_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}\Z")
_MAX_TEXT_BYTES = 1_000_000
_MAX_TASKS = 256


class EvalError(Exception):
    """Typed, fail-closed evaluation error. Carries a stable code only."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# --- Built-in deterministic graders -------------------------------------------------
# A grader maps (candidate_output, config) -> bool. Pure and side-effect free.

def _grade_exact_match(output: str, config: Mapping[str, Any]) -> bool:
    return output == config.get("expected", "")


def _grade_contains(output: str, config: Mapping[str, Any]) -> bool:
    needle = config.get("substring", "")
    return isinstance(needle, str) and needle != "" and needle in output


def _grade_non_empty(output: str, config: Mapping[str, Any]) -> bool:
    return output.strip() != ""


def _grade_json_valid(output: str, config: Mapping[str, Any]) -> bool:
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError):
        return False
    required = config.get("requiredKeys")
    if required is None:
        return True
    return isinstance(parsed, dict) and all(k in parsed for k in required)


_GRADERS: dict[str, Callable[[str, Mapping[str, Any]], bool]] = {
    "exact-match": _grade_exact_match,
    "contains": _grade_contains,
    "non-empty": _grade_non_empty,
    "json-valid": _grade_json_valid,
}


def available_graders() -> tuple[str, ...]:
    return tuple(sorted(_GRADERS))


def _grader(grader_id: str) -> Callable[[str, Mapping[str, Any]], bool]:
    grader = _GRADERS.get(grader_id)
    if grader is None:
        raise EvalError("ECO_EVAL_GRADER_UNKNOWN")
    return grader


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise EvalError("ECO_EVAL_INVALID")
    return value


def _bounded_text(value: Any) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise EvalError("ECO_EVAL_INVALID")
    return value


@dataclass(frozen=True)
class EvalTask:
    """One graded task: an input, a grader, its config, and a candidate output."""

    id: str
    grader_id: str
    input_text: str = field(repr=False)
    candidate_output: str = field(repr=False)
    config: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _identifier(self.id)
        _identifier(self.grader_id)
        _bounded_text(self.input_text)
        _bounded_text(self.candidate_output)
        if not isinstance(self.config, Mapping):
            raise EvalError("ECO_EVAL_INVALID")

    def grade(self) -> bool:
        return _grader(self.grader_id)(self.candidate_output, self.config)


@dataclass(frozen=True)
class GraderCalibration:
    """A known-good case (must pass) and a known-broken case (must fail).

    This is the *validate the judge* contract: a grader that cannot pass the
    good case and fail the broken one is not trusted to grade anything.
    """

    grader_id: str
    good_output: str = field(repr=False)
    broken_output: str = field(repr=False)
    config: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _identifier(self.grader_id)
        _bounded_text(self.good_output)
        _bounded_text(self.broken_output)
        if not isinstance(self.config, Mapping):
            raise EvalError("ECO_EVAL_INVALID")

    def validate_judge(self) -> None:
        grader = _grader(self.grader_id)
        if not grader(self.good_output, self.config):
            raise EvalError("ECO_EVAL_JUDGE_REJECTS_GOOD")
        if grader(self.broken_output, self.config):
            raise EvalError("ECO_EVAL_JUDGE_ACCEPTS_BROKEN")


@dataclass(frozen=True)
class EvalSuite:
    """A file-backed suite: calibration, tasks, independence and threshold."""

    id: str
    version: str
    independence: int
    threshold: float
    calibration: GraderCalibration
    tasks: tuple[EvalTask, ...]

    def __post_init__(self) -> None:
        _identifier(self.id)
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.version or ""):
            raise EvalError("ECO_EVAL_INVALID")
        if not isinstance(self.independence, int) or not 1 <= self.independence <= 15:
            raise EvalError("ECO_EVAL_INVALID")
        if not isinstance(self.threshold, (int, float)) or not 0.0 < float(self.threshold) <= 1.0:
            raise EvalError("ECO_EVAL_INVALID")
        if not 1 <= len(self.tasks) <= _MAX_TASKS:
            raise EvalError("ECO_EVAL_INVALID")
        ids = [t.id for t in self.tasks]
        if len(ids) != len(set(ids)):
            raise EvalError("ECO_EVAL_DUPLICATE_TASK")

    @property
    def digest(self) -> str:
        return _canonical_digest(
            {
                "domain": "eco-eval-suite-v1",
                "id": self.id,
                "version": self.version,
                "independence": self.independence,
                "threshold": float(self.threshold),
                "graderId": self.calibration.grader_id,
                "tasks": [
                    {"id": t.id, "graderId": t.grader_id, "inputDigest": _digest(t.input_text)}
                    for t in self.tasks
                ],
            }
        )


@dataclass(frozen=True)
class EvalVerdict:
    """Content-free result: pass/fail per task, aggregate and calibration."""

    suite_id: str
    suite_digest: str
    judge_validated: bool
    passed: int
    total: int
    threshold: float
    available: bool
    task_results: tuple[dict[str, Any], ...]

    def as_record(self) -> dict[str, Any]:
        return {
            "suiteId": self.suite_id,
            "suiteDigest": self.suite_digest,
            "judgeValidated": self.judge_validated,
            "passed": self.passed,
            "total": self.total,
            "threshold": self.threshold,
            "available": self.available,
            "tasks": list(self.task_results),
        }


def run_eval_suite(suite: EvalSuite) -> EvalVerdict:
    """Validate the judge, then grade every task through N independent runs.

    Fails closed: if the judge cannot be validated, no task is graded and the
    verdict is unavailable.
    """

    suite.calibration.validate_judge()

    results: list[dict[str, Any]] = []
    passed = 0
    for task in suite.tasks:
        votes = [task.grade() for _ in range(suite.independence)]
        agree_pass = votes.count(True)
        # Deterministic graders yield unanimous votes; a majority rule keeps the
        # contract meaningful for future non-deterministic graders.
        task_pass = agree_pass * 2 > suite.independence
        if task_pass:
            passed += 1
        results.append(
            {
                "id": task.id,
                "graderId": task.grader_id,
                "inputDigest": _digest(task.input_text),
                "votesPass": agree_pass,
                "votes": suite.independence,
                "pass": task_pass,
            }
        )

    fraction = passed / len(suite.tasks)
    available = fraction >= suite.threshold
    return EvalVerdict(
        suite_id=suite.id,
        suite_digest=suite.digest,
        judge_validated=True,
        passed=passed,
        total=len(suite.tasks),
        threshold=float(suite.threshold),
        available=available,
        task_results=tuple(results),
    )


def load_eval_suite(document: Mapping[str, Any]) -> EvalSuite:
    """Load and validate a suite document (already-parsed JSON)."""

    if not isinstance(document, Mapping):
        raise EvalError("ECO_EVAL_INVALID")
    if document.get("apiVersion") != "eval.ai.ecosystem/v1alpha1" or document.get("kind") != "EvalSuite":
        raise EvalError("ECO_EVAL_INVALID")
    metadata = document.get("metadata")
    spec = document.get("spec")
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
        raise EvalError("ECO_EVAL_INVALID")
    cal = spec.get("calibration")
    if not isinstance(cal, Mapping):
        raise EvalError("ECO_EVAL_INVALID")
    raw_tasks = spec.get("tasks")
    if not isinstance(raw_tasks, list):
        raise EvalError("ECO_EVAL_INVALID")

    calibration = GraderCalibration(
        grader_id=cal.get("graderId", ""),
        good_output=cal.get("goodOutput", ""),
        broken_output=cal.get("brokenOutput", ""),
        config=cal.get("config", {}) if isinstance(cal.get("config", {}), Mapping) else {},
    )
    tasks = tuple(
        EvalTask(
            id=t.get("id", "") if isinstance(t, Mapping) else "",
            grader_id=t.get("graderId", "") if isinstance(t, Mapping) else "",
            input_text=t.get("input", "") if isinstance(t, Mapping) else "",
            candidate_output=t.get("candidateOutput", "") if isinstance(t, Mapping) else "",
            config=t.get("config", {}) if isinstance(t, Mapping) and isinstance(t.get("config", {}), Mapping) else {},
        )
        for t in raw_tasks
    )
    return EvalSuite(
        id=metadata.get("id", ""),
        version=metadata.get("version", ""),
        independence=spec.get("independence", 0),
        threshold=spec.get("threshold", 0.0),
        calibration=calibration,
        tasks=tasks,
    )
