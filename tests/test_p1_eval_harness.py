from __future__ import annotations

import json
import unittest

from eco_eval import (
    EvalError,
    GraderCalibration,
    available_graders,
    load_eval_suite,
    run_eval_suite,
)


def _suite_doc(*, good="ok", broken="", tasks=None):
    return {
        "apiVersion": "eval.ai.ecosystem/v1alpha1",
        "kind": "EvalSuite",
        "metadata": {"id": "sample-suite", "version": "1.0.0"},
        "spec": {
            "independence": 3,
            "threshold": 1.0,
            "calibration": {"graderId": "non-empty", "goodOutput": good, "brokenOutput": broken},
            "tasks": tasks
            or [
                {"id": "t1", "graderId": "non-empty", "input": "q1", "candidateOutput": "answer"},
                {"id": "t2", "graderId": "contains", "input": "q2", "candidateOutput": "hello world", "config": {"substring": "world"}},
            ],
        },
    }


class EvalHarnessTests(unittest.TestCase):
    def test_valid_suite_passes_with_validated_judge(self) -> None:
        verdict = run_eval_suite(load_eval_suite(_suite_doc()))
        self.assertTrue(verdict.available)
        self.assertTrue(verdict.judge_validated)
        self.assertEqual((verdict.passed, verdict.total), (2, 2))

    def test_judge_that_rejects_good_case_fails_closed(self) -> None:
        # non-empty grader will reject an empty "good" output.
        with self.assertRaises(EvalError) as ctx:
            run_eval_suite(load_eval_suite(_suite_doc(good="")))
        self.assertEqual(ctx.exception.code, "ECO_EVAL_JUDGE_REJECTS_GOOD")

    def test_judge_that_accepts_broken_case_fails_closed(self) -> None:
        # non-empty grader will accept a non-empty "broken" output -> not a judge.
        with self.assertRaises(EvalError) as ctx:
            run_eval_suite(load_eval_suite(_suite_doc(broken="still not empty")))
        self.assertEqual(ctx.exception.code, "ECO_EVAL_JUDGE_ACCEPTS_BROKEN")

    def test_failing_task_makes_suite_unavailable(self) -> None:
        tasks = [
            {"id": "t1", "graderId": "non-empty", "input": "q1", "candidateOutput": "answer"},
            {"id": "t2", "graderId": "contains", "input": "q2", "candidateOutput": "hello", "config": {"substring": "world"}},
        ]
        verdict = run_eval_suite(load_eval_suite(_suite_doc(tasks=tasks)))
        self.assertFalse(verdict.available)
        self.assertEqual(verdict.passed, 1)

    def test_duplicate_task_ids_rejected(self) -> None:
        tasks = [
            {"id": "dup", "graderId": "non-empty", "input": "a", "candidateOutput": "x"},
            {"id": "dup", "graderId": "non-empty", "input": "b", "candidateOutput": "y"},
        ]
        with self.assertRaises(EvalError) as ctx:
            load_eval_suite(_suite_doc(tasks=tasks))
        self.assertEqual(ctx.exception.code, "ECO_EVAL_DUPLICATE_TASK")

    def test_unknown_grader_rejected(self) -> None:
        tasks = [{"id": "t1", "graderId": "no-such-grader", "input": "a", "candidateOutput": "x"}]
        suite = load_eval_suite(_suite_doc(tasks=tasks))
        with self.assertRaises(EvalError) as ctx:
            run_eval_suite(suite)
        self.assertEqual(ctx.exception.code, "ECO_EVAL_GRADER_UNKNOWN")

    def test_verdict_is_content_free(self) -> None:
        verdict = run_eval_suite(load_eval_suite(_suite_doc()))
        blob = json.dumps(verdict.as_record())
        self.assertNotIn("answer", blob)
        self.assertNotIn("hello world", blob)
        self.assertNotIn("q1", blob)
        # digests are present instead of raw text
        self.assertTrue(all("inputDigest" in t for t in verdict.as_record()["tasks"]))

    def test_json_valid_grader_and_available_graders(self) -> None:
        self.assertEqual(
            available_graders(), ("contains", "exact-match", "json-valid", "non-empty")
        )
        tasks = [
            {"id": "t1", "graderId": "json-valid", "input": "q", "candidateOutput": '{"a": 1}', "config": {"requiredKeys": ["a"]}},
        ]
        doc = _suite_doc(good='{"a":1}', broken="not json", tasks=tasks)
        doc["spec"]["calibration"] = {"graderId": "json-valid", "goodOutput": '{"a":1}', "brokenOutput": "not json"}
        verdict = run_eval_suite(load_eval_suite(doc))
        self.assertTrue(verdict.available)

    def test_malformed_document_rejected(self) -> None:
        with self.assertRaises(EvalError):
            load_eval_suite({"apiVersion": "wrong", "kind": "EvalSuite"})


if __name__ == "__main__":
    unittest.main()
