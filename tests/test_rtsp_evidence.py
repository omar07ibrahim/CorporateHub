"""Tests for deterministic RTSP evidence and its real generated visuals."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import rtsp_evidence
from rtsp_evidence import (
    ARTIFACT_PATHS,
    CHECKED_ENTRY_POINTS,
    EvidenceError,
    FORBIDDEN_ARTIFACT_FRAGMENTS,
    SOURCE_FILES,
    artifact_differences,
    collect_evidence,
    format_artifact_status,
    format_receipt,
    render_artifacts,
    render_cli_svg,
    render_flow_svg,
    render_matrix_svg,
    run_policy_cases,
    write_current_artifacts,
)


ROOT = Path(__file__).resolve().parents[1]
JSON_PATH = ARTIFACT_PATHS[0]
SVG_PATHS = ARTIFACT_PATHS[1:]
SVG_NAMESPACE = "http://www.w3.org/2000/svg"


def _source_overrides() -> dict[str, str]:
    return {
        filename: (ROOT / filename).read_text(encoding="utf-8")
        for filename in SOURCE_FILES
    }


class RtspEvidenceModelTests(unittest.TestCase):
    def test_evidence_records_only_bounded_source_only_claims(self) -> None:
        evidence = collect_evidence(ROOT)

        self.assertEqual("corporatehub.rtsp-quarantine", evidence["artifact"])
        self.assertEqual(1, evidence["schema_version"])
        self.assertEqual(
            {"failed": 0, "passed": 10, "total": 10},
            evidence["summary"],
        )
        self.assertEqual(
            {
                "application_started": False,
                "kind": "policy execution and AST source inspection",
                "live_camera_requested": False,
                "native_runtime_loaded": False,
                "vendor_runtime_requested": False,
            },
            evidence["scope"],
        )
        self.assertEqual("pass", evidence["source_binding"]["status"])
        self.assertEqual([], evidence["source_binding"]["violations"])
        self.assertEqual(
            list(CHECKED_ENTRY_POINTS),
            evidence["source_binding"]["checked_entry_points"],
        )
        self.assertFalse(evidence["decision"]["allowed"])
        self.assertEqual("rtsp-unavailable", evidence["decision"]["code"])
        self.assertEqual(0, evidence["privacy"]["endpoint_values_serialized"])
        self.assertFalse(
            evidence["privacy"]["exception_messages_embed_input"]
        )
        self.assertTrue(evidence["privacy"]["tracebacks_can_retain_input"])

        cases = evidence["cases"]
        self.assertEqual(10, len(cases))
        self.assertEqual(10, len({case["id"] for case in cases}))
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["passed"])
                self.assertFalse(case["allowed"])
                self.assertEqual(
                    {
                        "allowed",
                        "boundary",
                        "id",
                        "input_class",
                        "observed_code",
                        "passed",
                        "syntax",
                    },
                    set(case),
                )

    def test_json_is_canonical_and_hashes_exact_sources(self) -> None:
        raw = (ROOT / JSON_PATH).read_bytes()
        parsed = json.loads(raw)
        self.assertEqual(
            json.dumps(
                parsed,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
            raw,
        )
        self.assertEqual(
            {
                "artifact",
                "cases",
                "decision",
                "privacy",
                "schema_version",
                "scope",
                "source_binding",
                "source_sha256",
                "summary",
            },
            set(parsed),
        )
        self.assertEqual(set(SOURCE_FILES), set(parsed["source_sha256"]))
        for filename, digest in parsed["source_sha256"].items():
            with self.subTest(filename=filename):
                actual = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
                self.assertEqual(actual, digest)
                self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")

    def test_artifacts_are_deterministic_and_current(self) -> None:
        first = render_artifacts(ROOT)
        second = render_artifacts(ROOT)
        self.assertEqual(first, second)
        self.assertEqual((), artifact_differences(ROOT, first))

        result = subprocess.run(
            ["python3", "rtsp_evidence.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        expected_stdout = (
            format_receipt(collect_evidence(ROOT))
            + "\n"
            + format_artifact_status("CURRENT")
            + "\n"
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(expected_stdout, result.stdout)
        self.assertEqual("", result.stderr)

    def test_artifacts_never_serialize_endpoint_fixtures_or_host_state(self) -> None:
        artifacts = render_artifacts(ROOT)
        combined = b"\n".join(artifacts.values())
        forbidden = (
            b"rtsp://",
            b"rtsps://",
            *(fragment.encode("utf-8") for fragment in FORBIDDEN_ARTIFACT_FRAGMENTS),
            b"/home/",
            b"gitcode",
        )
        for marker in forbidden:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, combined)

        parsed = json.loads(artifacts[JSON_PATH])
        all_keys: set[str] = set()

        def visit(value: object) -> None:
            if isinstance(value, dict):
                all_keys.update(str(key).casefold() for key in value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(parsed)
        self.assertTrue(
            {"created_at", "generated_at", "timestamp", "commit_sha"}.isdisjoint(
                all_keys
            )
        )

    def test_source_mutation_changes_machine_and_visual_evidence(self) -> None:
        original = render_artifacts(ROOT)
        overrides = _source_overrides()
        overrides["main.py"] += "\n# source-fingerprint mutation\n"
        mutated = render_artifacts(ROOT, overrides)

        self.assertNotEqual(original[JSON_PATH], mutated[JSON_PATH])
        self.assertNotEqual(
            original[Path("docs/assets/rtsp-quarantine-matrix.svg")],
            mutated[Path("docs/assets/rtsp-quarantine-matrix.svg")],
        )
        original_json = json.loads(original[JSON_PATH])
        mutated_json = json.loads(mutated[JSON_PATH])
        self.assertNotEqual(
            original_json["source_sha256"]["main.py"],
            mutated_json["source_sha256"]["main.py"],
        )

    def test_one_byte_mutation_of_every_artifact_is_detected(self) -> None:
        artifacts = render_artifacts(ROOT)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            for relative_path, content in artifacts.items():
                target = temporary_root / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            self.assertEqual(
                (),
                artifact_differences(temporary_root, artifacts),
            )

            for relative_path, content in artifacts.items():
                with self.subTest(path=relative_path.as_posix()):
                    target = temporary_root / relative_path
                    mutation = bytearray(content)
                    mutation[-2] ^= 1
                    target.write_bytes(mutation)
                    self.assertEqual(
                        (relative_path,),
                        artifact_differences(temporary_root, artifacts),
                    )
                    target.write_bytes(content)

    def test_failed_case_or_source_binding_refuses_all_writes(self) -> None:
        failing_case = dict(run_policy_cases()[0])
        failing_case["passed"] = False
        overrides = _source_overrides()

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            with mock.patch.object(
                rtsp_evidence,
                "run_policy_cases",
                return_value=(failing_case,),
            ):
                with self.assertRaisesRegex(
                    EvidenceError,
                    "refusing to publish failing RTSP evidence",
                ):
                    write_current_artifacts(temporary_root, overrides)
            self.assertFalse(any(temporary_root.rglob("*")))

        main_source = overrides["main.py"]
        unsafe_main_sources = {
            "callback argument": main_source.replace(
                "        def select_rtsp():",
                "        def select_rtsp(endpoint):",
                1,
            ),
            "callback decorator": main_source.replace(
                "        def select_rtsp():",
                "        @staticmethod\n        def select_rtsp():",
                1,
            ),
            "rerouted RTSP button": main_source.replace(
                "            command=select_rtsp,",
                "            command=select_files,",
                1,
            ),
            "raw status": main_source.replace(
                "self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)",
                "self.status_var.set(endpoint)",
                1,
            ),
            "retained source": main_source.replace(
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)\n"
                "            self.saved_value = self.camera_source",
                1,
            ),
            "dead fixed calls": main_source.replace(
                "            self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)\n"
                '            messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                "            if False:\n"
                "                self.status_var.set("
                "RTSP_UNAVAILABLE_MESSAGE)\n"
                '                messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                1,
            ),
        }
        for label, unsafe_main in unsafe_main_sources.items():
            with self.subTest(label=label):
                self.assertNotEqual(main_source, unsafe_main)
                unsafe_overrides = dict(overrides)
                unsafe_overrides["main.py"] = unsafe_main
                with tempfile.TemporaryDirectory(dir=ROOT) as directory:
                    temporary_root = Path(directory)
                    with self.assertRaisesRegex(
                        EvidenceError,
                        "refusing to publish failing RTSP evidence",
                    ):
                        write_current_artifacts(
                            temporary_root,
                            unsafe_overrides,
                        )
                    self.assertFalse(any(temporary_root.rglob("*")))

    def test_symlink_parent_is_rejected_before_any_write_or_directory(self) -> None:
        overrides = _source_overrides()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            boundary = Path(directory)
            repository = boundary / "repository"
            outside = boundary / "outside"
            repository.mkdir()
            outside.mkdir()
            try:
                (repository / "docs").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaisesRegex(
                EvidenceError,
                "artifact destination",
            ):
                write_current_artifacts(repository, overrides)

            self.assertFalse((repository / "evidence").exists())
            self.assertFalse((outside / "assets").exists())
            self.assertEqual([repository / "docs"], list(repository.iterdir()))


class RtspEvidenceVisualTests(unittest.TestCase):
    def test_svgs_are_accessible_local_and_parseable(self) -> None:
        artifacts = render_artifacts(ROOT)
        for relative_path in SVG_PATHS:
            with self.subTest(path=relative_path.as_posix()):
                raw = artifacts[relative_path]
                root = ET.fromstring(raw)
                self.assertEqual(f"{{{SVG_NAMESPACE}}}svg", root.tag)
                self.assertEqual("img", root.attrib.get("role"))
                labelled_by = root.attrib.get("aria-labelledby", "").split()
                self.assertEqual(2, len(labelled_by))
                identifiers = {
                    element.attrib.get("id")
                    for element in root.iter()
                    if element.attrib.get("id")
                }
                self.assertTrue(set(labelled_by).issubset(identifiers))
                title = root.find(f"{{{SVG_NAMESPACE}}}title")
                description = root.find(f"{{{SVG_NAMESPACE}}}desc")
                self.assertIsNotNone(title)
                self.assertIsNotNone(description)
                self.assertTrue(title.text.strip())
                self.assertTrue(description.text.strip())

                for element in root.iter():
                    local_name = element.tag.rsplit("}", maxsplit=1)[-1].casefold()
                    self.assertNotIn(local_name, {"a", "image", "script", "foreignobject"})
                    for attribute, value in element.attrib.items():
                        self.assertNotIn("href", attribute.casefold())
                        if "url(" in value.casefold():
                            self.assertRegex(value, r"\Aurl\(#[A-Za-z0-9_-]+\)\Z")

    def test_cli_visual_contains_the_exact_executed_receipt(self) -> None:
        evidence = collect_evidence(ROOT)
        root = ET.fromstring(render_cli_svg(evidence))
        visible_text = "\n".join(
            text.strip() for text in root.itertext() if text.strip()
        )
        for line in format_receipt(evidence).splitlines():
            with self.subTest(line=line):
                self.assertIn(line, visible_text)
        self.assertIn(format_artifact_status("CURRENT"), visible_text)

    def test_flow_names_each_binding_and_separates_the_parser_path(self) -> None:
        evidence = collect_evidence(ROOT)
        original = render_flow_svg(evidence)
        visible_text = "\n".join(ET.fromstring(original).itertext())
        for entry_point in CHECKED_ENTRY_POINTS:
            with self.subTest(entry_point=entry_point):
                self.assertIn(entry_point, visible_text)
        self.assertIn("SEPARATE POLICY EVIDENCE PATH", visible_text)
        self.assertIn("Not wired to GUI", visible_text)

        mutated = deepcopy(evidence)
        mutated["source_binding"]["checked_entry_points"][0] = (
            "main.py:changed_binding"
        )
        changed = render_flow_svg(mutated)
        self.assertNotEqual(original, changed)
        self.assertIn(
            "main.py:changed_binding",
            "\n".join(ET.fromstring(changed).itertext()),
        )

    def test_matrix_defines_match_and_uses_contrasting_headers(self) -> None:
        root = ET.fromstring(render_matrix_svg(collect_evidence(ROOT)))
        visible_text = "\n".join(root.itertext())
        self.assertIn(
            "MATCH = expected policy outcome observed · capture remains DENIED",
            visible_text,
        )
        self.assertNotIn("CASES PASS", visible_text)
        for heading in (
            "INPUT CLASS",
            "BOUNDARY",
            "OBSERVED STATE",
            "STABLE CODE",
            "EVIDENCE",
        ):
            element = next(
                node
                for node in root.iter()
                if (node.text or "").strip() == heading
            )
            self.assertEqual("#94a3b8", element.attrib.get("fill"))

    def test_dynamic_visual_text_is_xml_escaped(self) -> None:
        evidence = deepcopy(collect_evidence(ROOT))
        evidence["decision"]["code"] = '<deny & "inspect">'
        raw = render_cli_svg(evidence)
        self.assertNotIn(b'<deny & "inspect">', raw)
        root = ET.fromstring(raw)
        self.assertIn(
            '<deny & "inspect">',
            "\n".join(root.itertext()),
        )

    def test_readme_embeds_every_visual_and_links_machine_evidence(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for relative_path in ARTIFACT_PATHS:
            with self.subTest(path=relative_path.as_posix()):
                self.assertIn(relative_path.as_posix(), readme)
                self.assertTrue((ROOT / relative_path).is_file())
        self.assertIn("python3 rtsp_evidence.py --check", readme)
        self.assertIn("source-only evidence, not camera runtime evidence", readme)


if __name__ == "__main__":
    unittest.main()
