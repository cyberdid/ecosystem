from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
import unicodedata
from pathlib import Path
from unittest import mock

from eco_orchestration.contracts import validate_orchestration_record
from eco_orchestration.source_bundle import (
    FILESYSTEM_PROFILE,
    SourceBundleError,
    SourceBundleLimits,
    ingest_source_bundle,
    ingest_source_bundle_manifest_file,
    load_source_bundle_manifest,
    validate_source_bundle_manifest,
)
from eco_runtime.artifact_store import ContentAddressedArtifactStore


KEY = b"m6-source-bundle-test-proof-key-0000000000000000"
CREATED_AT = "2026-07-17T00:00:00Z"


def declaration(
    source_id: str,
    path: str,
    content: bytes,
    *,
    media_type: str = "text/markdown",
    data_class: str = "D1",
) -> dict[str, object]:
    return {
        "id": source_id,
        "path": path,
        "mediaType": media_type,
        "dataClass": data_class,
        "sha256": hashlib.sha256(content).hexdigest(),
        "byteLength": len(content),
    }


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux openat2 proof")
class SourceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        self.repository.mkdir()
        self.store = ContentAddressedArtifactStore(
            self.base / "private-store",
            proof_key=KEY,
            key_id="m6-source-test-key",
            forbidden_root=self.repository,
        )
        self.question = b"What claims are supported?\n"
        self.source = b"# Evidence\n\nAn inert untrusted source.\n"
        (self.repository / "question.md").write_bytes(self.question)
        (self.repository / "source.md").write_bytes(self.source)

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def manifest(
        self,
        *,
        question: dict[str, object] | None = None,
        sources: list[dict[str, object]] | None = None,
        data_class: str = "D1",
    ) -> dict[str, object]:
        return {
            "bundleId": "source-review-input",
            "dataClass": data_class,
            "question": question
            or declaration("question", "question.md", self.question, data_class=data_class),
            "sources": sources
            if sources is not None
            else [declaration("source-1", "source.md", self.source, data_class=data_class)],
        }

    def ingest(self, manifest: dict[str, object], **kwargs: object) -> dict[str, object]:
        return ingest_source_bundle(
            self.repository,
            manifest,
            self.store,
            project_id="ecosystem",
            team_id="research-team",
            run_id="source-review-run-1",
            created_at=CREATED_AT,
            **kwargs,
        )

    def test_success_is_content_free_sorted_sealed_and_cas_backed(self) -> None:
        record = self.ingest(self.manifest())

        self.assertEqual(record, validate_orchestration_record(record))
        self.assertEqual(record["kind"], "SourceBundle")
        self.assertEqual(record["metadata"]["runId"], "source-review-run-1")
        self.assertEqual(record["spec"]["questionEntryId"], "question")
        self.assertEqual(
            [entry["id"] for entry in record["spec"]["entries"]],
            ["question", "source-1"],
        )
        self.assertEqual(
            record["spec"]["totalByteLength"], len(self.question) + len(self.source)
        )
        self.assertEqual(record["spec"]["ingestionPolicyDigest"], SourceBundleLimits().policy_digest())
        serialized = json.dumps(record, sort_keys=True)
        self.assertNotIn("question.md", serialized)
        self.assertNotIn("source.md", serialized)
        self.assertNotIn("What claims are supported?", serialized)
        self.assertNotIn("An inert untrusted source", serialized)
        for entry in record["spec"]["entries"]:
            artifact = entry["artifact"]
            proof = self.store.proof_for_record(
                storage_ref=artifact["ref"],
                sha256=artifact["contentDigest"],
                byte_length=artifact["byteLength"],
            )
            self.store.verify_availability(proof)

    def test_ingestion_policy_digest_is_derived_from_the_exact_enforced_limits(self) -> None:
        limits = SourceBundleLimits()
        record = self.ingest(
            self.manifest(),
            limits=limits,
            ingestion_policy_digest=limits.policy_digest(),
        )
        self.assertEqual(
            record["spec"]["ingestionPolicyDigest"], limits.policy_digest()
        )

        for supplied, expected_code in (
            ("b" * 64, "ECO_SOURCE_POLICY_MISMATCH"),
            ("not-a-digest", "ECO_SOURCE_POLICY_INVALID"),
        ):
            with self.subTest(code=expected_code):
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(
                        self.manifest(),
                        limits=limits,
                        ingestion_policy_digest=supplied,
                    )
                self.assertEqual(caught.exception.code, expected_code)
                self.assertNotIn(supplied, str(caught.exception))

    def test_cli_facing_manifest_file_is_descriptor_safely_loaded(self) -> None:
        manifest_path = self.repository / "bundle.json"
        manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")

        parsed = load_source_bundle_manifest(self.repository, "bundle.json")
        self.assertEqual(parsed.question.id, "question")
        record = ingest_source_bundle_manifest_file(
            self.repository,
            "bundle.json",
            self.store,
            project_id="ecosystem",
            team_id="research-team",
            run_id="source-review-run-1",
            created_at=CREATED_AT,
        )
        self.assertEqual(record["spec"]["questionEntryId"], "question")

    def test_exact_manifest_bytes_are_bound_between_preflight_and_ingestion(self) -> None:
        manifest_path = self.repository / "bundle-bound.json"
        manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")
        parsed = load_source_bundle_manifest(self.repository, manifest_path.name)
        self.assertIsNotNone(parsed.manifest_digest)
        manifest_path.write_text(
            json.dumps(self.manifest(), indent=2),
            encoding="utf-8",
        )
        with self.assertRaises(SourceBundleError) as caught:
            ingest_source_bundle_manifest_file(
                self.repository,
                manifest_path.name,
                self.store,
                project_id="ecosystem",
                team_id="research-team",
                run_id="source-review-run-1",
                created_at=CREATED_AT,
                expected_manifest_digest=parsed.manifest_digest,
            )
        self.assertEqual(caught.exception.code, "ECO_SOURCE_MANIFEST_CHANGED")

    def test_manifest_json_duplicate_keys_non_utf8_and_nul_fail_closed(self) -> None:
        valid_tail = (
            ',"dataClass":"D1","question":{},"sources":[]}'
        ).encode("utf-8")
        cases = {
            "duplicate": b'{"bundleId":"one","bundleId":"two"' + valid_tail,
            "non-utf8": b"\xff",
            "nul": b"{}\x00",
        }
        expected = {
            "duplicate": "ECO_SOURCE_JSON_DUPLICATE_KEY",
            "non-utf8": "ECO_SOURCE_MANIFEST_ENCODING",
            "nul": "ECO_SOURCE_MANIFEST_ENCODING",
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.repository / f"{name}.json"
                path.write_bytes(content)
                with self.assertRaises(SourceBundleError) as caught:
                    load_source_bundle_manifest(self.repository, path.name)
                self.assertEqual(caught.exception.code, expected[name])

    def test_manifest_json_depth_and_parser_recursion_fail_with_stable_limits(self) -> None:
        limits = SourceBundleLimits(maximum_json_depth=8)
        cases = (
            (b'{"x":' * 9 + b"0" + b"}" * 9, "bounded-depth.json"),
            (b'[' * 1_500 + b"0" + b"]" * 1_500, "parser-depth.json"),
        )
        for content, name in cases:
            with self.subTest(name=name):
                (self.repository / name).write_bytes(content)
                with self.assertRaises(SourceBundleError) as caught:
                    load_source_bundle_manifest(self.repository, name, limits=limits)
                self.assertEqual(caught.exception.code, "ECO_SOURCE_MANIFEST_JSON_LIMIT")

    def test_application_json_depth_and_item_limits_are_broker_owned(self) -> None:
        cases = (
            (
                b'{"x":' * 9 + b"0" + b"}" * 9,
                SourceBundleLimits(maximum_json_depth=8),
            ),
            (
                b"[0,1,2,3,4,5,6,7,8,9]",
                SourceBundleLimits(maximum_json_items=8),
            ),
        )
        for index, (content, limits) in enumerate(cases):
            with self.subTest(index=index):
                path = self.repository / f"bounded-{index}.json"
                path.write_bytes(content)
                item = declaration(
                    f"source-{index}",
                    path.name,
                    content,
                    media_type="application/json",
                )
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest(sources=[item]), limits=limits)
                self.assertEqual(caught.exception.code, "ECO_SOURCE_JSON_LIMIT")

    def test_absolute_traversal_backslash_percent_control_and_non_nfc_paths_are_denied(self) -> None:
        decomposed = unicodedata.normalize("NFD", "café.md")
        paths = [
            "/tmp/source.md",
            "../source.md",
            "nested/../source.md",
            r"nested\source.md",
            "source%2fescape.md",
            "source\nname.md",
            decomposed,
        ]
        for path in paths:
            with self.subTest(path=repr(path)):
                item = declaration("source-1", path, self.source)
                with self.assertRaises(SourceBundleError) as caught:
                    validate_source_bundle_manifest(self.manifest(sources=[item]))
                self.assertEqual(caught.exception.code, "ECO_SOURCE_PATH_INVALID")

    def test_duplicate_paths_and_identifiers_are_denied(self) -> None:
        duplicate_path = declaration("other", "question.md", self.question)
        duplicate_id = declaration("question", "source.md", self.source)
        for source, code in (
            (duplicate_path, "ECO_SOURCE_DUPLICATE_PATH"),
            (duplicate_id, "ECO_SOURCE_DUPLICATE_ID"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(SourceBundleError) as caught:
                    validate_source_bundle_manifest(self.manifest(sources=[source]))
                self.assertEqual(caught.exception.code, code)

    def test_media_type_data_class_and_question_role_are_fail_closed(self) -> None:
        cases = []
        denied_media = declaration("source-1", "source.md", self.source)
        denied_media["mediaType"] = "text/html"
        cases.append((self.manifest(sources=[denied_media]), "ECO_SOURCE_MEDIA_TYPE_DENIED"))
        mismatched = declaration("source-1", "source.md", self.source, data_class="D2")
        cases.append((self.manifest(sources=[mismatched]), "ECO_SOURCE_DATA_CLASS_MISMATCH"))
        question = declaration(
            "question", "question.md", self.question, media_type="application/json"
        )
        cases.append((self.manifest(question=question), "ECO_SOURCE_QUESTION_INVALID"))
        cases.append((self.manifest(data_class="D4"), "ECO_SOURCE_DATA_CLASS_DENIED"))
        for manifest, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(SourceBundleError) as caught:
                    validate_source_bundle_manifest(manifest)
                self.assertEqual(caught.exception.code, code)

    def test_per_file_count_and_aggregate_limits_are_enforced_before_read(self) -> None:
        cases = (
            (
                SourceBundleLimits(
                    maximum_file_bytes=10,
                    maximum_source_count=1,
                    maximum_total_bytes=20,
                ),
                "ECO_SOURCE_COUNT_EXCEEDED",
            ),
            (
                SourceBundleLimits(
                    maximum_file_bytes=8,
                    maximum_source_count=4,
                    maximum_total_bytes=16,
                ),
                "ECO_SOURCE_FILE_TOO_LARGE",
            ),
            (
                SourceBundleLimits(
                    maximum_file_bytes=64,
                    maximum_source_count=4,
                    maximum_total_bytes=64,
                ),
                "ECO_SOURCE_TOTAL_TOO_LARGE",
            ),
        )
        for limits, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(SourceBundleError) as caught:
                    validate_source_bundle_manifest(self.manifest(), limits=limits)
                self.assertEqual(caught.exception.code, code)

    def test_exact_length_and_digest_are_required(self) -> None:
        wrong_length = declaration("source-1", "source.md", self.source)
        wrong_length["byteLength"] = len(self.source) - 1
        wrong_digest = declaration("source-1", "source.md", self.source)
        wrong_digest["sha256"] = "0" * 64
        for item, code in (
            (wrong_length, "ECO_SOURCE_LENGTH_MISMATCH"),
            (wrong_digest, "ECO_SOURCE_DIGEST_MISMATCH"),
        ):
            with self.subTest(code=code):
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest(sources=[item]))
                self.assertEqual(caught.exception.code, code)

    def test_non_utf8_nul_and_malformed_json_sources_are_denied(self) -> None:
        cases = (
            (b"\xff", "text/plain", "ECO_SOURCE_ENCODING_DENIED"),
            (b"before\x00after", "text/plain", "ECO_SOURCE_BINARY_DENIED"),
            (b'{"open":', "application/json", "ECO_SOURCE_JSON_INVALID"),
            (b'{"value":NaN}', "application/json", "ECO_SOURCE_JSON_INVALID"),
        )
        for index, (content, media_type, code) in enumerate(cases):
            with self.subTest(code=code):
                path = self.repository / f"invalid-{index}.txt"
                path.write_bytes(content)
                item = declaration(
                    f"source-{index}", path.name, content, media_type=media_type
                )
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest(sources=[item]))
                self.assertEqual(caught.exception.code, code)

    def test_symlink_hardlink_and_special_files_are_denied(self) -> None:
        (self.repository / "target.md").write_bytes(self.source)
        os.symlink("target.md", self.repository / "symlink.md")
        os.link(self.repository / "target.md", self.repository / "hardlink.md")
        os.mkfifo(self.repository / "source.fifo")
        cases = (
            ("symlink.md", "ECO_SOURCE_PATH_ESCAPE"),
            ("hardlink.md", "ECO_SOURCE_HARDLINK_DENIED"),
            ("source.fifo", "ECO_SOURCE_NOT_REGULAR"),
        )
        for index, (path, code) in enumerate(cases):
            with self.subTest(code=code):
                item = declaration(f"source-{index}", path, self.source)
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest(sources=[item]))
                self.assertEqual(caught.exception.code, code)

    def test_intermediate_symlink_escape_is_denied_by_openat2(self) -> None:
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "evidence.md").write_bytes(self.source)
        os.symlink(outside, self.repository / "linked")
        item = declaration("source-1", "linked/evidence.md", self.source)
        with self.assertRaises(SourceBundleError) as caught:
            self.ingest(self.manifest(sources=[item]))
        self.assertEqual(caught.exception.code, "ECO_SOURCE_PATH_ESCAPE")

    def test_content_and_hardlink_races_are_detected(self) -> None:
        for race in ("content", "hardlink"):
            with self.subTest(race=race):
                source_path = self.repository / "race.md"
                source_path.write_bytes(self.source)
                item = declaration("source-1", "race.md", self.source)
                triggered = False

                def fault(phase: str, path: str) -> None:
                    nonlocal triggered
                    if triggered or phase != "read" or path != "race.md":
                        return
                    triggered = True
                    if race == "content":
                        source_path.write_bytes(self.source + b"changed\n")
                    else:
                        os.link(source_path, self.repository / "race-peer.md")

                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest(sources=[item]), fault_hook=fault)
                self.assertEqual(caught.exception.code, "ECO_SOURCE_CHANGED")
                if (self.repository / "race-peer.md").exists():
                    (self.repository / "race-peer.md").unlink()

    def test_low_level_reopen_read_and_fstat_errors_are_stable_and_sanitized(self) -> None:
        secret = "ECO_TEST_LOW_LEVEL_SECRET"
        original_open = os.open
        original_fstat = os.fstat

        def failing_reopen(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if isinstance(path, str) and path.startswith("/proc/self/fd/"):
                raise OSError(secret)
            return original_open(path, flags, *args, **kwargs)

        fstat_calls = 0

        def failing_fstat(descriptor: int) -> os.stat_result:
            nonlocal fstat_calls
            fstat_calls += 1
            if fstat_calls == 2:
                raise OSError(secret)
            return original_fstat(descriptor)

        cases = (
            (
                mock.patch("eco_orchestration.source_bundle.os.open", side_effect=failing_reopen),
                "ECO_SOURCE_REOPEN_FAILED",
            ),
            (
                mock.patch(
                    "eco_orchestration.source_bundle.os.read",
                    side_effect=OSError(secret),
                ),
                "ECO_SOURCE_READ_FAILED",
            ),
            (
                mock.patch(
                    "eco_orchestration.source_bundle.os.fstat",
                    side_effect=failing_fstat,
                ),
                "ECO_SOURCE_STAT_FAILED",
            ),
        )
        for patcher, expected_code in cases:
            fstat_calls = 0
            with self.subTest(code=expected_code), patcher:
                with self.assertRaises(SourceBundleError) as caught:
                    self.ingest(self.manifest())
                self.assertEqual(caught.exception.code, expected_code)
                self.assertNotIn(secret, str(caught.exception))

    def test_late_validation_failure_does_not_partially_mutate_cas(self) -> None:
        second_content = b"second source\n"
        (self.repository / "second.md").write_bytes(second_content)
        first = declaration("source-1", "source.md", self.source)
        second = declaration("source-2", "second.md", second_content)
        second["sha256"] = "f" * 64

        with self.assertRaises(SourceBundleError) as caught:
            self.ingest(self.manifest(sources=[first, second]))
        self.assertEqual(caught.exception.code, "ECO_SOURCE_DIGEST_MISMATCH")
        object_files = [path for path in (self.base / "private-store" / "objects").rglob("*") if path.is_file()]
        self.assertEqual(object_files, [])

    def test_executable_text_is_never_executed(self) -> None:
        canary = self.base / "execution-canary"
        script = f"#!/bin/sh\ntouch {canary}\n".encode("utf-8")
        script_path = self.repository / "untrusted.sh"
        script_path.write_bytes(script)
        script_path.chmod(0o755)
        item = declaration("source-1", "untrusted.sh", script, media_type="text/plain")

        record = self.ingest(self.manifest(sources=[item]))
        self.assertEqual(record["kind"], "SourceBundle")
        self.assertFalse(canary.exists())

    def test_platform_fails_closed_without_claiming_portability(self) -> None:
        self.assertEqual(FILESYSTEM_PROFILE, "linux-openat2-v1")
        with mock.patch("eco_orchestration.source_bundle.sys.platform", "win32"):
            with self.assertRaises(SourceBundleError) as caught:
                self.ingest(self.manifest())
        self.assertEqual(caught.exception.code, "ECO_SOURCE_BUNDLE_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
