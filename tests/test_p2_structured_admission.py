from __future__ import annotations

import unittest

from eco_runtime.structured_admission import (
    AdmissionVerdict,
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


class StructuredAdmissionTests(unittest.TestCase):
    def test_valid_typed_output_is_admitted(self) -> None:
        v = probe_structured_output('{"answer": "yes", "confidence": 0.9}', SCHEMA)
        self.assertTrue(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_OK")

    def test_prose_is_not_json_and_denied(self) -> None:
        v = probe_structured_output("Sure! Here is my answer: yes.", SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_NOT_JSON")

    def test_wrapper_object_is_denied(self) -> None:
        # a common small-model failure: wrapping the real object
        v = probe_structured_output('{"response": {"answer": "yes", "confidence": 0.9}}', SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_SCHEMA_MISMATCH")

    def test_missing_required_key_is_denied(self) -> None:
        v = probe_structured_output('{"answer": "yes"}', SCHEMA)
        self.assertFalse(v.admitted)
        self.assertEqual(v.code, "ECO_ADMISSION_SCHEMA_MISMATCH")

    def test_wire_schema_drops_unexpressible_keywords_but_full_schema_validates(self) -> None:
        wire = wire_schema(SCHEMA)
        answer = wire["properties"]["answer"]
        # grammar-safe projection drops minLength/maxLength on the wire
        self.assertNotIn("minLength", answer)
        self.assertNotIn("maxLength", answer)
        # but the authoritative admission still validates against the full schema:
        # an over-long answer that the wire grammar would allow is denied here only
        # if it violates the full schema. Confirm the full schema is the authority.
        too_long = '{"answer": "' + "x" * 300 + '", "confidence": 0.5}'
        self.assertFalse(probe_structured_output(too_long, SCHEMA).admitted)

    def test_record_shape(self) -> None:
        self.assertEqual(
            AdmissionVerdict(True, "ECO_ADMISSION_OK").as_record(),
            {"admitted": True, "code": "ECO_ADMISSION_OK"},
        )


if __name__ == "__main__":
    unittest.main()
