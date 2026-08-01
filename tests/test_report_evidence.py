"""Reproducibility, provenance, and publication checks for report evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zlib

import report_evidence
from report_evidence import (
    CAPTURE_IMAGE,
    CLI_SVG_PATH,
    DEMO_ROOT,
    EvidenceError,
    FLOW_SVG_PATH,
    PRIVACY_SVG_PATH,
    RECEIPT_PATH,
    SCREENSHOT_BROWSER_SHA256,
    SCREENSHOT_CAPTURE_SCRIPT_SHA256,
    SCREENSHOT_HEIGHT,
    SCREENSHOT_INDEX_SHA256,
    SCREENSHOT_PATH,
    SCREENSHOT_REPORT_ID,
    SCREENSHOT_SHA256,
    SCREENSHOT_SUMMARY_ASSET_SHA256,
    SCREENSHOT_WIDTH,
    SOURCE_FILES,
    _FIXTURE_CANARIES,
    _gui_binding_errors,
    _validate_screenshot,
    artifact_differences,
    collect_evidence,
    format_artifact_status,
    format_receipt,
    prepare_demo,
    render_artifacts,
    write_current_artifacts,
)
from report_export import (
    INDEX_NAME,
    MANIFEST_NAME,
    export_offline_report,
    verify_report_bundle,
)


ROOT = Path(__file__).resolve().parents[1]


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _source_overrides() -> dict[str, str]:
    return {
        filename: (ROOT / filename).read_text(encoding="utf-8")
        for filename in SOURCE_FILES
    }


def _copy_artifacts(root: Path, artifacts: dict[Path, bytes]) -> None:
    for relative, content in artifacts.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", checksum)


def _insert_before_iend(content: bytes, chunk_type: bytes, payload: bytes) -> bytes:
    iend = content.rfind(b"\x00\x00\x00\x00IEND")
    if iend < 0:
        raise AssertionError("test fixture PNG has no IEND")
    return content[:iend] + _png_chunk(chunk_type, payload) + content[iend:]


class OfflineReportEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.screenshot = (ROOT / SCREENSHOT_PATH).read_bytes()
        cls.evidence, _ = collect_evidence(ROOT)
        cls.artifacts = render_artifacts(ROOT)

    def test_model_is_exact_bounded_and_source_bound(self) -> None:
        evidence = self.evidence
        self.assertEqual("corporatehub.offline-report.evidence", evidence["artifact"])
        self.assertEqual(1, evidence["schema_version"])
        self.assertEqual(
            {
                "average_confidence_pct": 82.7,
                "blacklisted_records": 2,
                "confidence_bands": [
                    {"count": 1, "label": "unscored"},
                    {"count": 1, "label": "below 60%"},
                    {"count": 2, "label": "60–79.9%"},
                    {"count": 2, "label": "80–89.9%"},
                    {"count": 3, "label": "90–100%"},
                ],
                "observation_records": 9,
                "plate_records": 4,
                "scored_observations": 8,
            },
            evidence["bundle"]["summary"],
        )
        self.assertTrue(evidence["bundle"]["verified"])
        self.assertTrue(evidence["bundle"]["idempotent"])
        self.assertTrue(evidence["bundle"]["source_database_unchanged"])
        self.assertEqual("fixed synthetic SQLite", evidence["fixture"]["kind"])
        self.assertEqual(4, evidence["fixture"]["plate_records"])
        self.assertEqual(9, evidence["fixture"]["observation_records"])
        self.assertRegex(
            evidence["fixture"]["specification_sha256"],
            r"\A[0-9a-f]{64}\Z",
        )
        self.assertNotIn("sha256", evidence["fixture"])
        self.assertEqual(0, evidence["privacy"]["fixture_canaries_serialized"])
        self.assertEqual("pass", evidence["source_binding"]["status"])
        self.assertEqual([], evidence["source_binding"]["violations"])
        self.assertEqual(set(SOURCE_FILES), set(evidence["source_sha256"]))
        for filename, expected in evidence["source_sha256"].items():
            with self.subTest(filename=filename):
                self.assertEqual(_digest((ROOT / filename).read_bytes()), expected)
        self.assertNotEqual("0" * 64, SCREENSHOT_SHA256)
        self.assertRegex(evidence["source_set_sha256"], r"\A[0-9a-f]{64}\Z")

    def test_receipt_demo_and_browser_bind_the_same_report(self) -> None:
        raw_receipt = (ROOT / RECEIPT_PATH).read_bytes()
        parsed = json.loads(raw_receipt)
        self.assertEqual(
            json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            + b"\n",
            raw_receipt,
        )
        bundle = parsed["bundle"]
        bundle_root = ROOT / DEMO_ROOT / bundle["bundle_name"]
        verified = verify_report_bundle(bundle_root)
        self.assertEqual(bundle["report_id"], verified.report_id)
        self.assertEqual(SCREENSHOT_REPORT_ID, verified.report_id)
        self.assertEqual(3, len(bundle["files"]))
        for record in bundle["files"]:
            content = (bundle_root / record["path"]).read_bytes()
            self.assertEqual(len(content), record["bytes"])
            self.assertEqual(_digest(content), record["sha256"])
        browser = parsed["browser_capture"]
        self.assertEqual(SCREENSHOT_SHA256, browser["sha256"])
        self.assertEqual(SCREENSHOT_INDEX_SHA256, browser["index_sha256"])
        self.assertEqual(
            SCREENSHOT_SUMMARY_ASSET_SHA256,
            browser["summary_asset_sha256"],
        )
        self.assertEqual(
            SCREENSHOT_CAPTURE_SCRIPT_SHA256,
            browser["capture_script_sha256"],
        )
        self.assertEqual(CAPTURE_IMAGE, browser["container_image"])
        self.assertEqual(
            SCREENSHOT_BROWSER_SHA256,
            browser["browser_binary_sha256"],
        )
        self.assertEqual(
            [SCREENSHOT_WIDTH, SCREENSHOT_HEIGHT],
            [browser["width"], browser["height"]],
        )
        self.assertFalse(browser["browser_sandbox_enabled"])
        self.assertTrue(browser["network_disabled"])

    def test_artifacts_are_deterministic_current_and_exact(self) -> None:
        self.assertEqual(self.artifacts, render_artifacts(ROOT))
        self.assertEqual(8, len(self.artifacts))
        self.assertEqual((), artifact_differences(ROOT, self.artifacts))
        expected_static = {
            RECEIPT_PATH,
            CLI_SVG_PATH,
            FLOW_SVG_PATH,
            PRIVACY_SVG_PATH,
            SCREENSHOT_PATH,
        }
        self.assertTrue(expected_static.issubset(self.artifacts))
        self.assertEqual(
            3,
            sum(DEMO_ROOT in path.parents for path in self.artifacts),
        )

    def test_every_artifact_mutation_and_extra_demo_are_detected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            _copy_artifacts(temporary_root, self.artifacts)
            self.assertEqual((), artifact_differences(temporary_root, self.artifacts))
            for relative, content in self.artifacts.items():
                with self.subTest(path=relative.as_posix()):
                    target = temporary_root / relative
                    mutation = bytearray(content)
                    mutation[len(mutation) // 2] ^= 1
                    target.write_bytes(mutation)
                    self.assertIn(
                        relative,
                        artifact_differences(temporary_root, self.artifacts),
                    )
                    target.write_bytes(content)
            stale = temporary_root / DEMO_ROOT / ("corporatehub-report-" + "a" * 64)
            stale.mkdir()
            self.assertIn(
                stale.relative_to(temporary_root),
                artifact_differences(temporary_root, self.artifacts),
            )

    def test_check_rejects_symlinked_managed_demo_parent(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            boundary = Path(directory)
            repository = boundary / "repository"
            repository.mkdir()
            _copy_artifacts(repository, self.artifacts)
            demo_root = repository / DEMO_ROOT
            outside = boundary / "outside-demo"
            os.replace(demo_root, outside)
            demo_root.symlink_to(outside, target_is_directory=True)
            self.assertIn(
                DEMO_ROOT,
                artifact_differences(repository, self.artifacts),
            )

    def test_fixed_fixture_drift_is_rejected_even_when_export_verifies(self) -> None:
        original = report_evidence._create_synthetic_database

        def changed_fixture(path: Path) -> None:
            original(path)
            connection = report_evidence.sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE plate_detections SET confidence = 96.201 "
                    "WHERE id = 101"
                )
                connection.execute(
                    "UPDATE plate_detections SET confidence = 91.499 "
                    "WHERE id = 102"
                )
                connection.commit()
            finally:
                connection.close()

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            with mock.patch.object(
                report_evidence,
                "_create_synthetic_database",
                side_effect=changed_fixture,
            ):
                with self.assertRaisesRegex(EvidenceError, "fixture rows changed"):
                    collect_evidence(
                        Path(directory),
                        _source_overrides(),
                        self.screenshot,
                    )

    def test_private_canaries_and_host_state_never_serialize(self) -> None:
        combined = b"\n".join(self.artifacts.values())
        for canary in _FIXTURE_CANARIES:
            with self.subTest(canary=canary):
                self.assertNotIn(canary.encode("utf-8"), combined)
        for marker in (
            b"/home/",
            b"file:///",
            b"gitcode",
            b"created_at",
            b"generated_at",
            b"commit_sha",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, combined)

    def test_png_is_bounded_exact_and_metadata_free(self) -> None:
        content = self.screenshot
        self.assertEqual(SCREENSHOT_SHA256, _digest(content))
        self.assertLess(len(content), 4 * 1024 * 1024)
        offset = 8
        chunks: list[bytes] = []
        while offset < len(content):
            length = struct.unpack(">I", content[offset : offset + 4])[0]
            chunk_type = content[offset + 4 : offset + 8]
            data_end = offset + 8 + length
            observed = struct.unpack(">I", content[data_end : data_end + 4])[0]
            self.assertEqual(
                zlib.crc32(content[offset + 4 : data_end]) & 0xFFFFFFFF,
                observed,
            )
            chunks.append(chunk_type)
            offset = data_end + 4
        self.assertEqual(b"IHDR", chunks[0])
        self.assertEqual(b"IEND", chunks[-1])
        self.assertEqual({b"IHDR", b"IDAT", b"IEND"}, set(chunks))

    def test_png_structural_mutations_fail_after_hash_rebinding(self) -> None:
        demo = self.evidence["bundle"]
        capture_script = (ROOT / "tools/capture_offline_report.sh").read_text(
            encoding="utf-8"
        )
        mutations: dict[str, bytes] = {
            "metadata": _insert_before_iend(self.screenshot, b"tEXt", b"host=private"),
            "trailing": self.screenshot + b"x",
            "truncated": self.screenshot[:-7],
        }
        header = bytearray(self.screenshot)
        header[16:20] = struct.pack(">I", SCREENSHOT_WIDTH - 1)
        header[29:33] = struct.pack(
            ">I",
            zlib.crc32(bytes(header[12:29])) & 0xFFFFFFFF,
        )
        mutations["dimensions"] = bytes(header)
        checksum = bytearray(self.screenshot)
        checksum[-1] ^= 1
        mutations["checksum"] = bytes(checksum)
        for label, mutation in mutations.items():
            with self.subTest(label=label), mock.patch.object(
                report_evidence,
                "SCREENSHOT_SHA256",
                _digest(mutation),
            ):
                with self.assertRaises(EvidenceError):
                    _validate_screenshot(mutation, demo, capture_script)

    def test_old_png_cannot_bind_to_a_new_report_or_capture_script(self) -> None:
        demo = dict(self.evidence["bundle"])
        demo["report_id"] = "a" * 64
        capture_script = (ROOT / "tools/capture_offline_report.sh").read_text(
            encoding="utf-8"
        )
        with self.assertRaisesRegex(EvidenceError, "source binding is stale"):
            _validate_screenshot(self.screenshot, demo, capture_script)
        with self.assertRaisesRegex(EvidenceError, "source binding is stale"):
            _validate_screenshot(
                self.screenshot,
                self.evidence["bundle"],
                capture_script + "\n# drift\n",
            )

    def test_source_mutation_changes_machine_and_visual_evidence(self) -> None:
        overrides = _source_overrides()
        overrides["report_evidence.py"] += "\n# source fingerprint mutation\n"
        mutated = render_artifacts(ROOT, overrides, self.screenshot)
        self.assertNotEqual(self.artifacts[RECEIPT_PATH], mutated[RECEIPT_PATH])
        self.assertNotEqual(self.artifacts[CLI_SVG_PATH], mutated[CLI_SVG_PATH])

    def test_gui_binding_rejects_dead_or_missing_live_calls(self) -> None:
        source = (ROOT / "report_panel.py").read_text(encoding="utf-8")
        mutations = {
            "wrong exporter import": source.replace(
                "from report_export import export_offline_report",
                "from attacker_module import export_offline_report",
                1,
            ),
            "shadowed exporter": source.replace(
                "from report_export import export_offline_report",
                "from report_export import export_offline_report\n"
                "export_offline_report = object()",
                1,
            ),
            "dead exporter": source.replace(
                "            try:\n                export_result = export_offline_report",
                "            try:\n"
                "                if False:\n"
                "                    export_result = export_offline_report",
                1,
            ),
            "missing start": source.replace("            worker.start()", "            pass", 1),
            "dead open": source.replace(
                "                try:\n                    webbrowser.open",
                "                try:\n"
                "                    if False:\n"
                "                        webbrowser.open",
                1,
            ),
        }
        self.assertEqual((), _gui_binding_errors(source))
        for label, mutated in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(source, mutated)
                self.assertTrue(_gui_binding_errors(mutated))

    def test_svg_visuals_are_accessible_local_and_receipt_bound(self) -> None:
        for path in (CLI_SVG_PATH, FLOW_SVG_PATH, PRIVACY_SVG_PATH):
            with self.subTest(path=path.as_posix()):
                content = self.artifacts[path]
                root = ET.fromstring(content)
                self.assertEqual("img", root.attrib["role"])
                self.assertIn("aria-labelledby", root.attrib)
                tags = {node.tag.rsplit("}", 1)[-1] for node in root.iter()}
                self.assertTrue({"title", "desc"}.issubset(tags))
                self.assertTrue(tags.isdisjoint({"a", "image", "script", "foreignObject"}))
                self.assertNotIn(b"http://", content.replace(b"http://www.w3.org/2000/svg", b""))
                self.assertNotIn(b"https://", content)
        cli_text = self.artifacts[CLI_SVG_PATH].decode("utf-8")
        for line in format_receipt(self.evidence).splitlines():
            self.assertIn(line, cli_text)
        self.assertIn(format_artifact_status("CURRENT", 8), cli_text)
        self.assertIn(b"GUI / DTK / camera NOT RUN", self.artifacts[FLOW_SVG_PATH])
        self.assertIn(b"SELECTED AGGREGATES", self.artifacts[PRIVACY_SVG_PATH])

    def test_prepare_demo_writes_only_three_verified_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            index = prepare_demo(temporary_root)
            files = [path for path in temporary_root.rglob("*") if path.is_file()]
            self.assertEqual(3, len(files))
            self.assertEqual(INDEX_NAME, index.name)
            self.assertEqual(SCREENSHOT_REPORT_ID, verify_report_bundle(index.parent).report_id)

    def test_writer_rejects_symlink_and_unknown_demo_before_publication(self) -> None:
        overrides = _source_overrides()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            boundary = Path(directory)
            repository = boundary / "repository"
            outside = boundary / "outside"
            repository.mkdir()
            outside.mkdir()
            (repository / "docs").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(EvidenceError, "parent"):
                write_current_artifacts(repository, overrides, self.screenshot)
            self.assertEqual([], list(outside.iterdir()))

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            repository = Path(directory)
            rogue = repository / DEMO_ROOT / "rogue.txt"
            rogue.parent.mkdir(parents=True)
            rogue.write_text("keep", encoding="utf-8")
            before = rogue.read_bytes()
            with self.assertRaisesRegex(EvidenceError, "unknown top-level"):
                write_current_artifacts(repository, overrides, self.screenshot)
            self.assertEqual(before, rogue.read_bytes())
            self.assertEqual([rogue], [path for path in repository.rglob("*") if path.is_file()])

    def test_writer_replaces_only_valid_stale_generated_bundle(self) -> None:
        overrides = _source_overrides()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            repository = Path(directory)
            self.assertEqual(8, write_current_artifacts(repository, overrides, self.screenshot))
            desired = next((repository / DEMO_ROOT).iterdir())
            stale = repository / DEMO_ROOT / ("corporatehub-report-" + "a" * 64)
            stale.mkdir()
            (stale / "assets").mkdir()
            (stale / INDEX_NAME).write_bytes((desired / INDEX_NAME).read_bytes())
            (stale / MANIFEST_NAME).write_bytes((desired / MANIFEST_NAME).read_bytes())
            asset = next((desired / "assets").iterdir())
            (stale / "assets" / asset.name).write_bytes(asset.read_bytes())
            self.assertEqual(8, write_current_artifacts(repository, overrides, self.screenshot))
            self.assertFalse(stale.exists())
            expected = render_artifacts(repository, overrides, self.screenshot)
            self.assertEqual((), artifact_differences(repository, expected))

    def test_failed_binding_refuses_all_writes(self) -> None:
        overrides = _source_overrides()
        overrides["report_panel.py"] = overrides["report_panel.py"].replace(
            "            worker.start()",
            "            pass",
            1,
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            repository = Path(directory)
            with self.assertRaisesRegex(EvidenceError, "refusing to publish"):
                write_current_artifacts(repository, overrides, self.screenshot)
            self.assertEqual([], list(repository.iterdir()))

    def test_cli_check_does_not_change_tracked_artifacts(self) -> None:
        before = {
            path: (_digest((ROOT / path).read_bytes()), (ROOT / path).stat().st_mtime_ns)
            for path in self.artifacts
        }
        result = subprocess.run(
            ["python3", "report_evidence.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            format_receipt(self.evidence)
            + "\n"
            + format_artifact_status("CURRENT", 8)
            + "\n",
            result.stdout,
        )
        self.assertEqual("", result.stderr)
        after = {
            path: (_digest((ROOT / path).read_bytes()), (ROOT / path).stat().st_mtime_ns)
            for path in self.artifacts
        }
        self.assertEqual(before, after)

    def test_capture_script_has_pinned_isolation_contract(self) -> None:
        path = ROOT / "tools/capture_offline_report.sh"
        source = path.read_text(encoding="utf-8")
        required = (
            CAPTURE_IMAGE,
            SCREENSHOT_BROWSER_SHA256,
            "Chromium 140.0.7339.186",
            "--pull=never",
            "--platform linux/amd64",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--memory 768m",
            "--memory-swap 768m",
            "--cpus 1",
            "--no-sandbox",
            "file:///demo/index.html",
            "dst=/demo,readonly",
            "dst=/output",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, source)
        for forbidden in (
            "docker pull",
            "curl ",
            "wget ",
            "--privileged",
            "docker.sock",
            "dst=/home",
            "dst=/repo",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(SCREENSHOT_CAPTURE_SCRIPT_SHA256, _digest(path.read_bytes()))
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        result = subprocess.run(
            ["bash", "-n", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        shellcheck = subprocess.run(
            ["sh", "-c", "command -v shellcheck"],
            capture_output=True,
        )
        if shellcheck.returncode == 0:
            checked = subprocess.run(
                ["shellcheck", str(path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, checked.returncode, checked.stdout + checked.stderr)

    def test_capture_rejects_a_valid_noncanonical_bundle_before_docker(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            repository = Path(directory) / "repository"
            tools = repository / "tools"
            demo_root = repository / DEMO_ROOT
            assets = repository / "docs/assets"
            tools.mkdir(parents=True)
            demo_root.mkdir(parents=True)
            assets.mkdir(parents=True)
            for relative in (
                "report_evidence.py",
                "report_export.py",
                "tools/capture_offline_report.sh",
            ):
                target = repository / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            capture = repository / "tools/capture_offline_report.sh"
            capture.chmod(0o755)

            database = repository / "synthetic.sqlite"
            report_evidence._create_synthetic_database(database)
            connection = report_evidence.sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO plates(id, is_blacklisted, plate_number, "
                    "profile, reason, image_path) VALUES "
                    "(999, 0, 'private-extra', 'private-extra', '', "
                    "'private-extra')"
                )
                connection.commit()
            finally:
                connection.close()
            export_offline_report(database, demo_root)
            database.unlink()

            fake_bin = repository / "fake-bin"
            fake_bin.mkdir()
            marker = repository / "docker-was-called"
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n: > \"$DOCKER_MARKER\"\nexit 99\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["DOCKER_MARKER"] = str(marker)
            result = subprocess.run(
                [str(capture)],
                cwd=repository,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("not the fixed canonical fixture", result.stderr)
            self.assertFalse(marker.exists())

    def test_capture_rejects_symlinked_docs_ancestor_before_docker(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            boundary = Path(directory)
            repository = boundary / "repository"
            tools = repository / "tools"
            outside_docs = boundary / "outside-docs"
            tools.mkdir(parents=True)
            outside_docs.mkdir()
            capture = tools / "capture_offline_report.sh"
            capture.write_bytes(
                (ROOT / "tools/capture_offline_report.sh").read_bytes()
            )
            capture.chmod(0o755)
            for relative, content in self.artifacts.items():
                if DEMO_ROOT not in relative.parents:
                    continue
                destination = outside_docs / Path(*relative.parts[1:])
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            (outside_docs / "assets").mkdir(exist_ok=True)
            (repository / "docs").symlink_to(
                outside_docs,
                target_is_directory=True,
            )

            fake_bin = repository / "fake-bin"
            fake_bin.mkdir()
            marker = repository / "docker-was-called"
            fake_docker = fake_bin / "docker"
            fake_docker.write_text(
                "#!/usr/bin/env bash\n: > \"$DOCKER_MARKER\"\nexit 99\n",
                encoding="utf-8",
            )
            fake_docker.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            environment["DOCKER_MARKER"] = str(marker)
            result = subprocess.run(
                [str(capture)],
                cwd=repository,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("contains a symlink", result.stderr)
            self.assertFalse(marker.exists())

    def test_readme_and_security_link_real_artifacts_and_boundaries(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        normalized_readme = " ".join(readme.split())
        normalized_security = " ".join(security.split())
        for relative in self.artifacts:
            if relative.suffix in {".png", ".svg", ".json", ".html"}:
                with self.subTest(relative=relative.as_posix()):
                    self.assertIn(relative.as_posix(), readme)
        required_readme = (
            "python3 report_evidence.py --prepare-demo",
            "tools/capture_offline_report.sh",
            "python3 report_evidence.py --write",
            "actual 1440×2200 page-only Chromium capture",
            "not recognition accuracy, a benchmark, or surveillance output",
            "not a Tkinter, DTK, video, LPR, or camera screenshot",
            "never launches Docker or a browser and never changes tracked artifacts",
        )
        for statement in required_readme:
            self.assertIn(statement, normalized_readme)
        required_security = (
            "Never substitute a real application database",
            "Chromium runs with `--no-sandbox`",
            "never auto-bless drift",
            "no secure-memory or secure-erasure claim",
            "not authorship, the identity or truth of a source database",
        )
        for statement in required_security:
            self.assertIn(statement, normalized_security)

    def test_tracked_evidence_modes_are_non_executable_regular_files(self) -> None:
        for relative in self.artifacts:
            metadata = (ROOT / relative).lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(0, metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


if __name__ == "__main__":
    unittest.main()
