from __future__ import annotations

import json
import unittest

from eco_runtime.structured_admission import (
    AdmissionVerdict,
    extract_json_candidate,
    probe_structured_output,
    wire_schema,
)

SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["answer", "confidence"],
    "properties": {
        "answer": {"type": "string", "minLength": 1, "maxLength": 200},
        "confidence": {"type": "number"},
    },
}

CLEAN = '{"answer": "yes", "confidence": 0.9}'


class StructuredAdmissionTests(unittest.TestCase):
    def test_clean_typed_output_is_admitted_without_normalization(self) -> None:
        v = probe_structured_output(CLEAN, SCHEMA)
        self.assertTrue(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_OK")
        self.assertFalse(v.normalized)

    def test_markdown_fenced_json_is_admitted_after_normalization(self) -> None:
        fenced = "```json\n" + CLEAN + "\n```"
        v = probe_structured_output(fenced, SCHEMA)
        self.assertTrue(v.admitted)
        self.assertTrue(v.normalized)

    def test_plain_fence_without_language_is_admitted(self) -> None:
        v = probe_structured_output("```\n" + CLEAN + "\n```", SCHEMA)
        self.assertTrue(v.admitted)
        self.assertTrue(v.normalized)

    def test_prose_wrapped_json_is_admitted(self) -> None:
        v = probe_structured_output("Sure! Here is the object: " + CLEAN + " Hope that helps.", SCHEMA)
        self.assertTrue(v.admitted)
        self.assertTrue(v.normalized)

    def test_thinking_block_then_json_is_admitted(self) -> None:
        v = probe_structured_output("<think>Earth vs Moon, Earth is bigger.</think>\n" + CLEAN, SCHEMA)
        self.assertTrue(v.admitted)
        self.assertTrue(v.normalized)

    def test_no_json_anywhere_is_denied(self) -> None:
        v = probe_structured_output("I think the answer is yes, quite confidently.", SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_NO_JSON")

    def test_wrapper_object_is_a_real_schema_violation(self) -> None:
        # valid JSON, extracted cleanly, but the wrong shape -> strictly denied
        v = probe_structured_output('{"response": {"answer": "yes", "confidence": 0.9}}', SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_SCHEMA_MISMATCH")

    def test_missing_required_key_is_denied(self) -> None:
        v = probe_structured_output('{"answer": "yes"}', SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_SCHEMA_MISMATCH")

    def test_full_schema_is_the_validation_authority(self) -> None:
        wire = wire_schema(SCHEMA)
        answer = wire["properties"]["answer"]
        self.assertNotIn("minLength", answer)
        self.assertNotIn("maxLength", answer)
        # an over-long answer the wire grammar would allow is still denied by the full schema
        too_long = '{"answer": "' + "x" * 300 + '", "confidence": 0.5}'
        self.assertFalse(probe_structured_output(too_long, SCHEMA).admitted)

    def test_extractor_respects_braces_inside_strings(self) -> None:
        candidate, normalized = extract_json_candidate('```json\n{"answer": "a } b", "confidence": 1}\n```')
        self.assertEqual(candidate, '{"answer": "a } b", "confidence": 1}')
        self.assertTrue(normalized)

    def test_markdown_escaped_underscore_is_repaired(self) -> None:
        # gemma markdown-escapes underscores, emitting invalid JSON escape ``\_``.
        candidate, normalized = extract_json_candidate('{"answer": "func\\_checked", "confidence": 1}')
        self.assertIsNotNone(candidate)
        self.assertEqual(json.loads(candidate)["answer"], "func_checked")
        # a valid escape is left intact
        c2, _ = extract_json_candidate('```\n{"answer": "line\\nbreak", "confidence": 1}\n```')
        self.assertEqual(json.loads(c2)["answer"], "line\nbreak")

    def test_record_shape_includes_normalized(self) -> None:
        self.assertEqual(
            AdmissionVerdict(True, "ECO_ADMISSION_OK", normalized=True).as_record(),
            {"admitted": True, "code": "ECO_ADMISSION_OK", "normalized": True},
        )


if __name__ == "__main__":
    unittest.main()
