from __future__ import annotations

import unittest

from eco_runtime.model_reliability import classify_completion, recommend_transport


class ClassifyCompletionTests(unittest.TestCase):
    def test_length_with_empty_body_is_truncated_and_retryable(self) -> None:
        out = classify_completion("", "length")
        self.assertEqual(out.kind, "truncated")
        self.assertTrue(out.should_retry_with_more_tokens)

    def test_length_with_partial_body_is_truncated_and_retryable(self) -> None:
        out = classify_completion("partial answer that got cut", "length")
        self.assertEqual(out.kind, "truncated")
        self.assertTrue(out.should_retry_with_more_tokens)

    def test_clean_stop_with_no_content_is_empty_no_retry(self) -> None:
        out = classify_completion("   ", "stop")
        self.assertEqual(out.kind, "empty")
        self.assertFalse(out.should_retry_with_more_tokens)

    def test_clean_stop_with_content_is_complete(self) -> None:
        out = classify_completion('{"answer": "yes"}', "stop")
        self.assertEqual(out.kind, "complete")
        self.assertFalse(out.should_retry_with_more_tokens)

    def test_none_content_is_empty(self) -> None:
        self.assertEqual(classify_completion(None, "stop").kind, "empty")

    def test_record_shape(self) -> None:
        self.assertEqual(
            classify_completion("x", "stop").as_record(),
            {"kind": "complete", "shouldRetryWithMoreTokens": False},
        )


class RecommendTransportTests(unittest.TestCase):
    def test_strict_grammar_model_uses_json_schema(self) -> None:
        self.assertEqual(recommend_transport(honors_strict_grammar=True), "strict-json-schema")

    def test_prose_model_uses_prompt_and_extraction(self) -> None:
        # gemma4:12b-mlx observed behaviour: ignores strict grammar, emits prose
        self.assertEqual(recommend_transport(honors_strict_grammar=False), "prompt-json-extract")


if __name__ == "__main__":
    unittest.main()
