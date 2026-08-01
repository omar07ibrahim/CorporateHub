"""Adversarial tests for the bounded, offline report-export boundary."""

from __future__ import annotations

import errno
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import report_export
from report_export import (
    BUNDLE_PREFIX,
    BUNDLE_SCHEMA,
    CONTENT_SECURITY_POLICY,
    INDEX_NAME,
    MANIFEST_NAME,
    PRIVACY_MODE,
    PUBLIC_MODEL_SCHEMA,
    ExportLimits,
    ReportLimitError,
    ReportPublishError,
    ReportSourceError,
    ReportVerificationError,
    export_offline_report,
    verify_report_bundle,
)


ROOT = Path(__file__).resolve().parents[1]

SENSITIVE_VALUES = (
    "PRIVATE-PLATE-7QX9",
    "Chief Executive <script>alert('stored-xss')</script>",
    "watch-list reason & private note 83d5c7",
    "/srv/corporatehub/private/vehicle-83d5c7.jpg",
    "https://camera.invalid/live?token=super-secret-83d5c7",
    "2026-07-31T23:59:59.123456+00:00",
    "garage-west-personal-camera-83d5c7",
)


def _create_database(
    path: Path,
    *,
    plates: tuple[tuple[object, ...], ...] | None = None,
    detections: tuple[tuple[object, ...], ...] | None = None,
) -> None:
    """Create a realistic source with deliberately sensitive unused columns."""

    if plates is None:
        plates = (
            (
                11,
                1,
                SENSITIVE_VALUES[0],
                SENSITIVE_VALUES[1],
                SENSITIVE_VALUES[2],
                SENSITIVE_VALUES[3],
            ),
            (29, 0, "SECOND-PRIVATE-PLATE", "private-profile-b", "", "private-b.jpg"),
            (51, None, "THIRD-PRIVATE-PLATE", "private-profile-c", "", "private-c.jpg"),
        )
    if detections is None:
        detections = (
            (101, 11, 95.5, SENSITIVE_VALUES[5], SENSITIVE_VALUES[3], SENSITIVE_VALUES[6]),
            (102, 11, None, "2026-07-31T23:58:00Z", "private-102.jpg", "private-source"),
            (103, 29, 75.0, "2026-07-31T23:57:00Z", "private-103.jpg", "private-source"),
            (104, 29, 55.0, "2026-07-31T23:56:00Z", SENSITIVE_VALUES[4], "private-source"),
        )

    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE plates (
                id INTEGER PRIMARY KEY,
                is_blacklisted BOOLEAN,
                plate_number TEXT,
                profile TEXT,
                reason TEXT,
                image_path TEXT
            );
            CREATE TABLE plate_detections (
                id INTEGER PRIMARY KEY,
                plate_id INTEGER,
                confidence REAL,
                detection_time TEXT,
                plate_image_path TEXT,
                source_name TEXT
            );
            """
        )
        connection.executemany(
            """
            INSERT INTO plates(
                id, is_blacklisted, plate_number, profile, reason, image_path
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            plates,
        )
        connection.executemany(
            """
            INSERT INTO plate_detections(
                id, plate_id, confidence, detection_time, plate_image_path, source_name
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            detections,
        )
        connection.commit()
    finally:
        connection.close()


def _create_script_database(path: Path, script: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(script)
        connection.commit()
    finally:
        connection.close()


def _bundle_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _manifest(root: Path) -> dict[str, object]:
    value = json.loads((root / MANIFEST_NAME).read_bytes())
    if not isinstance(value, dict):
        raise AssertionError("test fixture manifest is not an object")
    return value


def _write_manifest(root: Path, value: object) -> None:
    (root / MANIFEST_NAME).write_bytes(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _asset_path(root: Path) -> Path:
    paths = tuple((root / "assets").glob("*.svg"))
    if len(paths) != 1:
        raise AssertionError(f"expected one SVG asset, found {len(paths)}")
    return paths[0]


def _rehash_and_rename_bundle(root: Path, manifest: dict[str, object]) -> Path:
    inventory = manifest["files"]
    records = manifest["records"]
    summary = manifest["summary"]
    if not isinstance(inventory, list) or not isinstance(records, list):
        raise AssertionError("test fixture manifest model is malformed")
    if not isinstance(summary, dict):
        raise AssertionError("test fixture manifest summary is malformed")
    report_id = report_export._report_id(summary, records, inventory)
    manifest["report_id"] = report_id
    _write_manifest(root, manifest)
    renamed = root.with_name(f"{BUNDLE_PREFIX}{report_id}")
    root.rename(renamed)
    return renamed


class _StructureAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp: list[str] = []
        self.referrer: list[str] = []
        self.urls: list[tuple[str, str, str]] = []
        self.active: list[str] = []
        self.main: list[dict[str, str | None]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        tag = tag.casefold()
        attributes = {name.casefold(): value for name, value in attrs}
        if tag in {"script", "iframe", "object", "embed", "form", "link", "input"}:
            self.active.append(tag)
        for name, value in attrs:
            lowered = name.casefold()
            if lowered.startswith("on"):
                self.active.append(lowered)
            if lowered in {"href", "src", "action", "formaction", "poster"}:
                self.urls.append((tag, lowered, value or ""))
        if tag == "meta":
            if (attributes.get("http-equiv") or "").casefold() == "content-security-policy":
                self.csp.append(attributes.get("content") or "")
            if (attributes.get("name") or "").casefold() == "referrer":
                self.referrer.append(attributes.get("content") or "")
        if tag == "main":
            self.main.append(attributes)


class ReportExportContractTests(unittest.TestCase):
    def test_export_omits_adversarial_sensitive_fields_and_is_exactly_offline(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "sensitive.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)

            result = export_offline_report(database, output)
            verified = verify_report_bundle(result.bundle_root)

            self.assertEqual(result, verified)
            self.assertEqual(3, result.plate_count)
            self.assertEqual(4, result.detection_count)
            self.assertRegex(result.report_id, r"\A[0-9a-f]{64}\Z")
            all_public_bytes = b"\n".join(_bundle_bytes(result.bundle_root).values())
            for sensitive in (*SENSITIVE_VALUES, str(database), str(workspace)):
                with self.subTest(sensitive=sensitive):
                    self.assertNotIn(sensitive.encode("utf-8"), all_public_bytes)

            manifest = _manifest(result.bundle_root)
            self.assertEqual(BUNDLE_SCHEMA, manifest["artifact"])
            self.assertEqual(PRIVACY_MODE, manifest["privacy"]["mode"])
            self.assertFalse(manifest["runtime"]["network_required"])
            self.assertFalse(manifest["runtime"]["scripts_included"])
            self.assertEqual(
                "single read-only SQLite transaction",
                manifest["runtime"]["database_access"],
            )

            html_bytes = result.index_path.read_bytes()
            text = html_bytes.decode("utf-8")
            audit = _StructureAudit()
            audit.feed(text)
            audit.close()
            expected_asset = _asset_path(result.bundle_root).relative_to(
                result.bundle_root
            ).as_posix()
            self.assertEqual([CONTENT_SECURITY_POLICY], audit.csp)
            self.assertEqual(["no-referrer"], audit.referrer)
            self.assertEqual([], audit.active)
            self.assertEqual([("img", "src", expected_asset)], audit.urls)
            self.assertEqual(1, len(audit.main))
            self.assertEqual(PUBLIC_MODEL_SCHEMA, audit.main[0]["data-report-schema"])
            self.assertEqual(PRIVACY_MODE, audit.main[0]["data-privacy-mode"])
            self.assertEqual("3", audit.main[0]["data-plate-records"])
            self.assertEqual("4", audit.main[0]["data-observation-records"])
            lowered = text.casefold()
            for marker in (
                "<script",
                "javascript:",
                "data:",
                "http:",
                "https:",
                "file:",
                "url(",
                "@import",
            ):
                with self.subTest(marker=marker):
                    self.assertNotIn(marker, lowered)

    def test_logically_equal_snapshots_are_byte_identical_and_export_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            first_database = workspace / "first.sqlite"
            second_database = workspace / "second.sqlite"
            first_output = workspace / "first-output"
            second_output = workspace / "second-output"
            first_output.mkdir()
            second_output.mkdir()
            _create_database(first_database)
            _create_database(
                second_database,
                plates=(
                    (77, None, "changed-c", "changed-c", "changed-c", "changed-c"),
                    (4, 0, "changed-b", "changed-b", "changed-b", "changed-b"),
                    (900, 1, "changed-a", "changed-a", "changed-a", "changed-a"),
                ),
                detections=(
                    (6004, 4, 55.0, "changed", "changed", "changed"),
                    (6003, 4, 75.0, "changed", "changed", "changed"),
                    (6002, 900, None, "changed", "changed", "changed"),
                    (6001, 900, 95.5, "changed", "changed", "changed"),
                ),
            )

            first = export_offline_report(first_database, first_output)
            second = export_offline_report(second_database, second_output)
            before_stats = {
                path: path.stat().st_mtime_ns
                for path in first.bundle_root.rglob("*")
            }
            repeated = export_offline_report(first_database, first_output)

            self.assertEqual(first.report_id, second.report_id)
            self.assertEqual(
                _bundle_bytes(first.bundle_root),
                _bundle_bytes(second.bundle_root),
            )
            self.assertEqual(first, repeated)
            self.assertEqual(
                before_stats,
                {path: path.stat().st_mtime_ns for path in first.bundle_root.rglob("*")},
            )

    def test_confidence_aggregation_is_stable_across_adversarial_row_orders(self) -> None:
        plates = (report_export._SourcePlate(1, False),)
        scores = (0.1,) * 50_000 + (100.0,) * 50_000
        detections = tuple(
            report_export._SourceDetection(
                database_id=index,
                plate_id=1,
                confidence=score,
            )
            for index, score in enumerate(scores, start=1)
        )
        real_fsum = report_export.math.fsum
        with mock.patch.object(
            report_export.math,
            "fsum",
            wraps=real_fsum,
        ) as stable_sum:
            forward = report_export._build_public_snapshot(plates, detections)
            reverse = report_export._build_public_snapshot(
                plates,
                tuple(reversed(detections)),
            )

        self.assertEqual(4, stable_sum.call_count)
        self.assertEqual(forward, reverse)
        self.assertEqual(50.0, forward.average_confidence)

    def test_source_database_is_opened_read_only_and_remains_byte_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            before_bytes = database.read_bytes()
            before_metadata = database.stat()
            real_connect = sqlite3.connect
            observed_calls: list[tuple[object, dict[str, object]]] = []

            def recording_connect(database_value: object, *args: object, **kwargs: object):
                observed_calls.append((database_value, dict(kwargs)))
                return real_connect(database_value, *args, **kwargs)

            with mock.patch.object(
                report_export.sqlite3,
                "connect",
                side_effect=recording_connect,
            ):
                export_offline_report(database, output)

            self.assertEqual(1, len(observed_calls))
            uri, options = observed_calls[0]
            self.assertEqual(database.resolve().as_uri() + "?mode=ro", uri)
            self.assertIs(True, options["uri"])
            self.assertIsNone(options["isolation_level"])
            self.assertEqual(before_bytes, database.read_bytes())
            after_metadata = database.stat()
            self.assertEqual(before_metadata.st_size, after_metadata.st_size)
            self.assertEqual(before_metadata.st_mtime_ns, after_metadata.st_mtime_ns)
            self.assertFalse((database.parent / f"{database.name}-journal").exists())

    def test_sqlite_length_limit_is_fail_closed_and_active_before_row_reads(self) -> None:
        with self.assertRaisesRegex(
            ReportSourceError,
            "cannot enforce the source row-size limit",
        ):
            report_export._establish_sqlite_length_limit(  # type: ignore[arg-type]
                object(),
                64 * 1024,
            )

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            configured_limit = 64 * 1024
            observed_limits: list[int] = []
            original_read = report_export._read_plate_rows

            def observe_limit(
                connection: sqlite3.Connection,
                expected_count: int,
            ) -> tuple[report_export._SourcePlate, ...]:
                observed_limits.append(
                    connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
                )
                return original_read(connection, expected_count)

            with mock.patch.object(
                report_export,
                "_read_plate_rows",
                side_effect=observe_limit,
            ):
                export_offline_report(
                    database,
                    output,
                    limits=ExportLimits(max_sqlite_row_bytes=configured_limit),
                )

            self.assertEqual([configured_limit], observed_limits)

    def test_oversized_dynamic_sqlite_values_fail_before_publication(self) -> None:
        mutations = {
            "blacklist-blob": (
                "UPDATE plates SET is_blacklisted = zeroblob(?) WHERE id = 11",
            ),
            "plate-id-blob": (
                "UPDATE plate_detections SET plate_id = zeroblob(?) WHERE id = 101",
            ),
            "confidence-blob": (
                "UPDATE plate_detections SET confidence = zeroblob(?) WHERE id = 101",
            ),
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            configured_limit = 64 * 1024
            oversized_value = configured_limit * 4
            for name, (mutation,) in mutations.items():
                with self.subTest(name=name):
                    database = workspace / f"{name}.sqlite"
                    output = workspace / f"{name}-output"
                    output.mkdir()
                    _create_database(database)
                    with sqlite3.connect(database) as connection:
                        connection.execute(mutation, (oversized_value,))
                    with self.assertRaises(ReportSourceError):
                        export_offline_report(
                            database,
                            output,
                            limits=ExportLimits(
                                max_sqlite_row_bytes=configured_limit,
                            ),
                        )
                    self.assertEqual([], list(output.iterdir()))

    def test_wal_writer_during_read_keeps_one_coherent_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            with sqlite3.connect(database) as connection:
                self.assertEqual("wal", connection.execute("PRAGMA journal_mode=WAL").fetchone()[0])

            original_read = report_export._read_plate_rows
            writer_completed = False

            def read_then_write(
                connection: sqlite3.Connection,
                expected_count: int,
            ) -> tuple[report_export._SourcePlate, ...]:
                nonlocal writer_completed
                rows = original_read(connection, expected_count)
                with sqlite3.connect(database, timeout=2.0) as writer:
                    writer.execute(
                        """
                        INSERT INTO plates(
                            id, is_blacklisted, plate_number, profile, reason, image_path
                        ) VALUES (88, 0, 'late-private', 'late-private', '', 'late-private')
                        """
                    )
                    writer.execute(
                        """
                        INSERT INTO plate_detections(
                            id, plate_id, confidence, detection_time, plate_image_path, source_name
                        ) VALUES (188, 88, 88.0, 'late-private', 'late-private', 'late-private')
                        """
                    )
                writer_completed = True
                return rows

            with mock.patch.object(
                report_export,
                "_read_plate_rows",
                side_effect=read_then_write,
            ):
                result = export_offline_report(database, output)

            self.assertTrue(writer_completed)
            self.assertEqual((3, 4), (result.plate_count, result.detection_count))
            with sqlite3.connect(database) as connection:
                self.assertEqual(4, connection.execute("SELECT COUNT(*) FROM plates").fetchone()[0])
                self.assertEqual(
                    5,
                    connection.execute("SELECT COUNT(*) FROM plate_detections").fetchone()[0],
                )

    def test_export_limits_are_positive_exact_integers_and_enforced(self) -> None:
        for invalid in (0, -1, True, 1.5, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ExportLimits(max_plates=invalid)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    ExportLimits(  # type: ignore[arg-type]
                        max_sqlite_row_bytes=invalid,
                    )

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            _create_database(database)
            cases = (
                ExportLimits(max_plates=2),
                ExportLimits(max_detections=3),
                ExportLimits(max_html_bytes=1),
                ExportLimits(max_manifest_bytes=1),
                ExportLimits(max_svg_bytes=1),
            )
            for index, limits in enumerate(cases):
                with self.subTest(limits=limits):
                    output = workspace / f"output-{index}"
                    output.mkdir()
                    with self.assertRaises(ReportLimitError):
                        export_offline_report(database, output, limits=limits)
                    self.assertEqual([], list(output.iterdir()))
            output = workspace / "bad-limits-type"
            output.mkdir()
            with self.assertRaises(TypeError):
                export_offline_report(database, output, limits=object())  # type: ignore[arg-type]

    def test_default_output_limits_fit_the_declared_maximum_plate_model(self) -> None:
        limits = ExportLimits()
        snapshot = report_export._PublicSnapshot(
            plates=tuple(
                report_export._PublicPlate(
                    record_ref=f"Record {index:03d}",
                    observation_count=0,
                    average_confidence=None,
                    peak_confidence=None,
                    review_flagged=False,
                )
                for index in range(1, limits.max_plates + 1)
            ),
            observation_count=0,
            scored_observation_count=0,
            average_confidence=None,
            blacklisted_count=0,
            confidence_bands=(
                ("unscored", 0),
                ("below 60%", 0),
                ("60–79.9%", 0),
                ("80–89.9%", 0),
                ("90–100%", 0),
            ),
        )
        rendered = report_export._render_bundle(snapshot, limits)
        self.assertLessEqual(
            len(rendered.files[MANIFEST_NAME]),
            limits.max_manifest_bytes,
        )
        self.assertLessEqual(
            len(rendered.files[INDEX_NAME]),
            limits.max_html_bytes,
        )
        decoded_manifest = report_export._decode_json_strict(
            rendered.files[MANIFEST_NAME],
            maximum_structural_tokens=16 * limits.max_plates + 4_096,
        )
        self.assertIsInstance(decoded_manifest, dict)
        self.assertEqual(limits.max_plates, len(decoded_manifest["records"]))

    def test_schema_contract_rejects_missing_virtual_and_mistyped_sources(self) -> None:
        schema_cases = {
            "missing-table": """
                CREATE TABLE plates (id INTEGER PRIMARY KEY, is_blacklisted BOOLEAN);
            """,
            "view-instead-of-table": """
                CREATE TABLE raw_plates (id INTEGER PRIMARY KEY, is_blacklisted BOOLEAN);
                CREATE VIEW plates AS SELECT id, is_blacklisted FROM raw_plates;
                CREATE TABLE plate_detections (
                    id INTEGER PRIMARY KEY, plate_id INTEGER, confidence REAL
                );
            """,
            "wrong-declared-type": """
                CREATE TABLE plates (id INTEGER PRIMARY KEY, is_blacklisted INTEGER);
                CREATE TABLE plate_detections (
                    id INTEGER PRIMARY KEY, plate_id INTEGER, confidence REAL
                );
            """,
            "wrong-primary-key": """
                CREATE TABLE plates (id INTEGER, is_blacklisted BOOLEAN);
                CREATE TABLE plate_detections (
                    id INTEGER PRIMARY KEY, plate_id INTEGER, confidence REAL
                );
            """,
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            for name, script in schema_cases.items():
                with self.subTest(name=name):
                    database = workspace / f"{name}.sqlite"
                    output = workspace / f"{name}-output"
                    output.mkdir()
                    _create_script_database(database, script)
                    with self.assertRaises(ReportSourceError):
                        export_offline_report(database, output)
                    self.assertEqual([], list(output.iterdir()))

    def test_invalid_row_types_ranges_identifiers_and_orphans_are_rejected(self) -> None:
        mutations = {
            "blacklist-value": "UPDATE plates SET is_blacklisted = 2 WHERE id = 11",
            "confidence-type": "UPDATE plate_detections SET confidence = 'not-a-number' WHERE id = 101",
            "confidence-range": "UPDATE plate_detections SET confidence = 100.01 WHERE id = 101",
            "plate-id": "UPDATE plates SET id = -11 WHERE id = 11",
            "detection-id": "UPDATE plate_detections SET id = -101 WHERE id = 101",
            "detection-plate-id-type": (
                "UPDATE plate_detections SET plate_id = 'not-an-id' WHERE id = 101"
            ),
            "orphan": "UPDATE plate_detections SET plate_id = 999999 WHERE id = 101",
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            for name, mutation in mutations.items():
                with self.subTest(name=name):
                    database = workspace / f"{name}.sqlite"
                    output = workspace / f"{name}-output"
                    output.mkdir()
                    _create_database(database)
                    with sqlite3.connect(database) as connection:
                        connection.execute(mutation)
                    with self.assertRaises(ReportSourceError):
                        export_offline_report(database, output)
                    self.assertEqual([], list(output.iterdir()))

    def test_empty_snapshot_and_exact_confidence_band_boundaries(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            empty_database = workspace / "empty.sqlite"
            empty_output = workspace / "empty-output"
            empty_output.mkdir()
            _create_database(empty_database, plates=(), detections=())
            empty = export_offline_report(empty_database, empty_output)
            self.assertEqual((0, 0), (empty.plate_count, empty.detection_count))
            self.assertEqual(empty, verify_report_bundle(empty.bundle_root))
            self.assertIn(
                b"No plate records in this snapshot.",
                empty.index_path.read_bytes(),
            )

            boundary_database = workspace / "boundaries.sqlite"
            boundary_output = workspace / "boundary-output"
            boundary_output.mkdir()
            scores = (None, 0.0, 59.999, 60.0, 79.999, 80.0, 89.999, 90.0, 100.0)
            detections = tuple(
                (
                    100 + index,
                    11,
                    score,
                    "private-time",
                    "private-path",
                    "private-source",
                )
                for index, score in enumerate(scores, start=1)
            )
            _create_database(
                boundary_database,
                plates=((11, 0, "private", "private", "private", "private"),),
                detections=detections,
            )
            boundary = export_offline_report(boundary_database, boundary_output)
            manifest = _manifest(boundary.bundle_root)
            self.assertEqual(
                [1, 2, 2, 2, 2],
                [
                    band["count"]
                    for band in manifest["summary"]["confidence_bands"]
                ],
            )
            self.assertEqual(boundary, verify_report_bundle(boundary.bundle_root))

    def test_source_and_output_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            database_link = workspace / "source-link.sqlite"
            output = workspace / "output"
            output_link = workspace / "output-link"
            safe_output = workspace / "safe-output"
            output.mkdir()
            safe_output.mkdir()
            _create_database(database)
            database_link.symlink_to(database.name)
            output_link.symlink_to(output.name, target_is_directory=True)

            with self.assertRaises(ReportSourceError):
                export_offline_report(database_link, safe_output)
            with self.assertRaises(ReportPublishError):
                export_offline_report(database, output_link)
            self.assertEqual([], list(output.iterdir()))
            self.assertEqual([], list(safe_output.iterdir()))

    def test_staging_write_failure_is_atomic_and_fully_cleaned(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            source_before = database.read_bytes()
            real_write = report_export._write_exclusive
            calls = 0

            def fail_second_write(path: Path, content: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected staging failure")
                real_write(path, content)

            with mock.patch.object(
                report_export,
                "_write_exclusive",
                side_effect=fail_second_write,
            ):
                with self.assertRaisesRegex(OSError, "injected staging failure"):
                    export_offline_report(database, output)

            self.assertEqual(2, calls)
            self.assertEqual([], list(output.iterdir()))
            self.assertEqual(source_before, database.read_bytes())

    def test_post_rename_directory_fsync_failure_returns_published_bundle(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            calls = 0

            def fail_only_after_rename(_path: Path) -> bool:
                nonlocal calls
                calls += 1
                if calls == 3:
                    raise OSError("injected parent fsync failure")
                return True

            with mock.patch.object(
                report_export,
                "_fsync_directory",
                side_effect=fail_only_after_rename,
            ):
                result = export_offline_report(database, output)

            self.assertEqual(3, calls)
            self.assertEqual(
                "the bundle was published, but output-directory durability "
                "could not be confirmed",
                result.durability_warning,
            )
            self.assertEqual(result, verify_report_bundle(result.bundle_root))

    def test_pre_rename_directory_fsync_failure_aborts_and_cleans_staging(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)

            with mock.patch.object(
                report_export,
                "_fsync_directory",
                side_effect=OSError(errno.EIO, "injected directory fsync failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected directory fsync"):
                    export_offline_report(database, output)

            self.assertEqual([], list(output.iterdir()))

    @unittest.skipUnless(hasattr(os, "O_DIRECTORY"), "directory fsync unavailable")
    def test_directory_fsync_ignores_only_unsupported_errors(self) -> None:
        with mock.patch.object(
            report_export.os,
            "open",
            side_effect=OSError(errno.EINVAL, "unsupported directory fsync"),
        ):
            self.assertFalse(report_export._fsync_directory(ROOT))
        with mock.patch.object(
            report_export.os,
            "open",
            side_effect=OSError(errno.EIO, "real directory I/O failure"),
        ):
            with self.assertRaisesRegex(OSError, "real directory I/O failure"):
                report_export._fsync_directory(ROOT)

    def test_staging_chmod_failure_is_cleaned_without_publication(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)

            with mock.patch.object(
                report_export.os,
                "chmod",
                side_effect=OSError("injected staging chmod failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected staging chmod"):
                    export_offline_report(database, output)

            self.assertEqual([], list(output.iterdir()))


class ReportBundleVerificationTests(unittest.TestCase):
    def _export(self, workspace: Path) -> report_export.ExportResult:
        database = workspace / "source.sqlite"
        output = workspace / "output"
        output.mkdir()
        _create_database(database)
        return export_offline_report(database, output)

    def test_content_addressed_svg_is_accessible_static_and_hash_exact(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            asset = _asset_path(result.bundle_root)
            content = asset.read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), asset.stem)
            root = ET.fromstring(content)
            self.assertEqual("{http://www.w3.org/2000/svg}svg", root.tag)
            self.assertEqual("img", root.attrib.get("role"))
            labelled_by = root.attrib.get("aria-labelledby", "").split()
            self.assertEqual(2, len(labelled_by))
            nodes_by_id = {
                node.attrib["id"]: node
                for node in root.iter()
                if "id" in node.attrib
            }
            self.assertTrue(set(labelled_by).issubset(nodes_by_id))
            self.assertEqual("title", nodes_by_id[labelled_by[0]].tag.rsplit("}", 1)[-1])
            self.assertEqual("desc", nodes_by_id[labelled_by[1]].tag.rsplit("}", 1)[-1])
            self.assertTrue("".join(nodes_by_id[labelled_by[0]].itertext()).strip())
            self.assertTrue("".join(nodes_by_id[labelled_by[1]].itertext()).strip())
            for node in root.iter():
                local_name = node.tag.rsplit("}", 1)[-1].casefold()
                self.assertNotIn(
                    local_name,
                    {"a", "foreignobject", "image", "script", "style"},
                )
                for attribute, value in node.attrib.items():
                    self.assertFalse(attribute.casefold().startswith("on"))
                    self.assertNotIn("href", attribute.casefold())
                    self.assertNotIn("url(", value.casefold())
                    self.assertNotIn("://", value.casefold())

    def test_verifier_rejects_changed_file_bytes(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            result.index_path.write_bytes(result.index_path.read_bytes() + b"\nchanged\n")
            with self.assertRaisesRegex(
                ReportVerificationError,
                "bytes differ from the manifest",
            ):
                verify_report_bundle(result.bundle_root)

    def test_verifier_rejects_fully_rehashed_non_source_derived_html(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            root = result.bundle_root
            original_html = result.index_path.read_bytes()
            forged_html = original_html.replace(
                b"CorporateHub redacted offline report",
                b"PRIVATE-PLATE-INJECTED-AFTER-EXPORT-7QX9",
                1,
            )
            self.assertNotEqual(original_html, forged_html)
            manifest = _manifest(root)
            inventory = manifest["files"]
            self.assertIsInstance(inventory, list)
            for record in inventory:
                self.assertIsInstance(record, dict)
                if record["path"] == INDEX_NAME:
                    record["bytes"] = len(forged_html)
                    record["sha256"] = hashlib.sha256(forged_html).hexdigest()
            result.index_path.write_bytes(forged_html)
            forged_root = _rehash_and_rename_bundle(root, manifest)

            with self.assertRaisesRegex(
                ReportVerificationError,
                "index.html is not source-derived",
            ):
                with mock.patch.object(
                    report_export,
                    "_validate_html",
                    side_effect=AssertionError("forged HTML reached the parser"),
                ):
                    verify_report_bundle(forged_root)

    def test_verifier_rejects_fully_rehashed_but_non_source_derived_svg(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            old_root = result.bundle_root
            old_asset = _asset_path(old_root)
            old_asset_relative = old_asset.relative_to(old_root).as_posix()
            original_svg = old_asset.read_bytes()
            forged_svg = original_svg.replace(
                b"CorporateHub redacted offline report summary",
                b"CorporateHub forged offline report summary",
                1,
            )
            self.assertNotEqual(original_svg, forged_svg)
            report_export._validate_svg(forged_svg)

            forged_digest = hashlib.sha256(forged_svg).hexdigest()
            forged_asset_relative = f"assets/{forged_digest}.svg"
            forged_asset = old_root / forged_asset_relative
            old_asset.unlink()
            forged_asset.write_bytes(forged_svg)

            forged_html = result.index_path.read_bytes().replace(
                old_asset_relative.encode("utf-8"),
                forged_asset_relative.encode("utf-8"),
                1,
            )
            result.index_path.write_bytes(forged_html)

            manifest = _manifest(old_root)
            inventory = manifest["files"]
            self.assertIsInstance(inventory, list)
            for record in inventory:
                self.assertIsInstance(record, dict)
                if record["path"] == INDEX_NAME:
                    record["bytes"] = len(forged_html)
                    record["sha256"] = hashlib.sha256(forged_html).hexdigest()
                else:
                    record["bytes"] = len(forged_svg)
                    record["path"] = forged_asset_relative
                    record["sha256"] = forged_digest
            inventory.sort(key=lambda record: str(record["path"]))
            forged_root = _rehash_and_rename_bundle(old_root, manifest)

            with self.assertRaisesRegex(
                ReportVerificationError,
                "summary SVG is not source-derived",
            ):
                with mock.patch.object(
                    report_export,
                    "_validate_svg",
                    side_effect=AssertionError("forged SVG reached the parser"),
                ):
                    verify_report_bundle(forged_root)

    def test_verifier_rejects_missing_and_extra_paths(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            missing_workspace = workspace / "missing"
            extra_workspace = workspace / "extra"
            missing_workspace.mkdir()
            extra_workspace.mkdir()
            missing = self._export(missing_workspace)
            _asset_path(missing.bundle_root).unlink()
            with self.assertRaisesRegex(
                ReportVerificationError,
                "missing or unexpected paths",
            ):
                verify_report_bundle(missing.bundle_root)

            extra = self._export(extra_workspace)
            (extra.bundle_root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(
                ReportVerificationError,
                "missing or unexpected paths",
            ):
                verify_report_bundle(extra.bundle_root)

    def test_verifier_rejects_symlinked_bundle_content(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            asset = _asset_path(result.bundle_root)
            asset.unlink()
            asset.symlink_to(Path("..") / INDEX_NAME)
            with self.assertRaisesRegex(
                ReportVerificationError,
                "non-regular file",
            ):
                verify_report_bundle(result.bundle_root)

    def test_verifier_rejects_missing_or_symlinked_manifest(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            missing_workspace = workspace / "missing"
            symlink_workspace = workspace / "symlink"
            missing_workspace.mkdir()
            symlink_workspace.mkdir()
            missing = self._export(missing_workspace)
            missing.manifest_path.unlink()
            with self.assertRaisesRegex(ReportVerificationError, "manifest is missing"):
                verify_report_bundle(missing.bundle_root)

            symlinked = self._export(symlink_workspace)
            symlinked.manifest_path.unlink()
            symlinked.manifest_path.symlink_to(INDEX_NAME)
            with self.assertRaisesRegex(
                ReportVerificationError,
                "manifest must be a regular file",
            ):
                verify_report_bundle(symlinked.bundle_root)

    def test_verifier_rejects_manifest_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            content = result.manifest_path.read_text(encoding="utf-8")
            needle = f'  "artifact": "{BUNDLE_SCHEMA}",\n'
            self.assertEqual(1, content.count(needle))
            result.manifest_path.write_text(
                content.replace(needle, needle + needle),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReportVerificationError, "duplicate keys"):
                verify_report_bundle(result.bundle_root)

    def test_verifier_rejects_manifest_traversal_paths(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            manifest = _manifest(result.bundle_root)
            records = manifest["files"]
            self.assertIsInstance(records, list)
            records[0]["path"] = "../outside.svg"
            _write_manifest(result.bundle_root, manifest)
            with self.assertRaisesRegex(
                ReportVerificationError,
                "canonical and relative",
            ):
                verify_report_bundle(result.bundle_root)

    def test_html_and_svg_auditors_reject_active_content(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            manifest = _manifest(result.bundle_root)
            summary = manifest["summary"]
            asset_relative = _asset_path(result.bundle_root).relative_to(
                result.bundle_root
            ).as_posix()
            html_bytes = result.index_path.read_bytes()
            report_export._validate_html(html_bytes, asset_relative, summary)
            mutations = (
                html_bytes.replace(b"</body>", b"<script>active()</script></body>"),
                html_bytes.replace(
                    b"</head>",
                    (
                        b'<meta http-equiv="refresh" '
                        b'content="0;url=&#x68;ttps&#x3a;//attacker.invalid/pixel">'
                        b"</head>"
                    ),
                ),
                html_bytes.replace(
                    f'src="{asset_relative}"'.encode("utf-8"),
                    (
                        f'src="{asset_relative}" '.encode("utf-8")
                        + b'srcset="../../private.jpg 2x"'
                    ),
                ),
                html_bytes.replace(
                    f'src="{asset_relative}"'.encode("utf-8"),
                    (
                        f'src="{asset_relative}" '.encode("utf-8")
                        + f'src="{asset_relative}"'.encode("utf-8")
                    ),
                ),
                html_bytes.replace(
                    b"color-scheme: dark",
                    b"color-scheme: light",
                ),
                html_bytes.replace(
                    b"default-src &#x27;none&#x27;",
                    b"default-src *",
                ),
                html_bytes.replace(
                    f'src="{asset_relative}"'.encode("utf-8"),
                    b'src="https://camera.invalid/report.svg"',
                ),
            )
            for mutation in mutations:
                with self.subTest(mutation=hashlib.sha256(mutation).hexdigest()):
                    with self.assertRaises(ReportVerificationError):
                        report_export._validate_html(mutation, asset_relative, summary)

            repeated_invalid = report_export._OfflineHtmlAudit()
            repeated_invalid.feed("<x>" * 100_000)
            repeated_invalid.close()
            self.assertEqual(1, len(repeated_invalid.errors))

            svg_bytes = _asset_path(result.bundle_root).read_bytes()
            report_export._validate_svg(svg_bytes)
            active_svg = svg_bytes.replace(
                b"</svg>",
                b'<script xmlns="http://www.w3.org/2000/svg">active()</script></svg>',
            )
            with self.assertRaisesRegex(ReportVerificationError, "active content"):
                report_export._validate_svg(active_svg)
            svg_mutations = (
                b'<?xml-stylesheet href="https://attacker.invalid/x.css"?>\n'
                + svg_bytes,
                svg_bytes.replace(
                    b"</svg>",
                    (
                        b'<animate xmlns="http://www.w3.org/2000/svg" '
                        b'attributeName="href" values="//attacker.invalid/pixel"/>'
                        b"</svg>"
                    ),
                ),
                svg_bytes.replace(
                    b"</svg>",
                    b'<iframe xmlns="http://www.w3.org/1999/xhtml"/></svg>',
                ),
            )
            for mutation in svg_mutations:
                with self.subTest(svg=hashlib.sha256(mutation).hexdigest()):
                    with self.assertRaises(ReportVerificationError):
                        report_export._validate_svg(mutation)

    def test_verifier_enforces_limits_before_loading_inventory_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            asset_size = _asset_path(result.bundle_root).stat().st_size
            with self.assertRaises(ReportLimitError):
                verify_report_bundle(
                    result.bundle_root,
                    limits=ExportLimits(max_svg_bytes=asset_size - 1),
                )
            with self.assertRaises(ReportLimitError):
                verify_report_bundle(
                    result.bundle_root,
                    limits=ExportLimits(max_plates=result.plate_count - 1),
                )
            with self.assertRaises(TypeError):
                verify_report_bundle(
                    result.bundle_root,
                    limits=object(),  # type: ignore[arg-type]
                )

    def test_strict_manifest_decoder_wraps_hostile_json_failures(self) -> None:
        hostile_values = (
            b'{"value":"\\ud800"}',
            b'{"value":NaN}',
            b'{"value":' + b"9" * 5_000 + b"}",
            (b"[" * 1_500) + b"0" + (b"]" * 1_500),
        )
        for content in hostile_values:
            with self.subTest(digest=hashlib.sha256(content).hexdigest()):
                with self.assertRaises(ReportVerificationError):
                    report_export._decode_json_strict(content)

    def test_manifest_complexity_is_bounded_before_json_object_allocation(self) -> None:
        hostile = b"[" + b"{}," * 20_000 + b"{}]"
        with self.assertRaisesRegex(
            ReportVerificationError,
            "structural complexity exceeds",
        ):
            report_export._decode_json_strict(
                hostile,
                maximum_structural_tokens=4_096,
            )
        self.assertEqual(
            {"value": "[{},:]"},
            report_export._decode_json_strict(
                b'{"value":"[{},:]"}',
                maximum_structural_tokens=3,
            ),
        )

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            result = self._export(Path(temporary_directory))
            result.manifest_path.write_bytes(
                b"[" + b"{}," * 60_000 + b"{}]"
            )
            with self.assertRaisesRegex(
                ReportVerificationError,
                "structural complexity exceeds",
            ):
                verify_report_bundle(result.bundle_root)

    def test_summary_rejects_contradictory_scored_semantics(self) -> None:
        summary = {
            "average_confidence_pct": 50.0,
            "blacklisted_records": 0,
            "confidence_bands": [
                {"count": 0, "label": "unscored"},
                {"count": 1, "label": "below 60%"},
                {"count": 0, "label": "60–79.9%"},
                {"count": 0, "label": "80–89.9%"},
                {"count": 0, "label": "90–100%"},
            ],
            "observation_records": 1,
            "plate_records": 1,
            "scored_observations": 0,
        }
        with self.assertRaisesRegex(
            ReportVerificationError,
            "average and scored count disagree",
        ):
            report_export._validate_summary(summary, ExportLimits())

    def test_manifest_public_records_are_canonical_and_cross_checked(self) -> None:
        def wrong_reference(records: list[dict[str, object]]) -> None:
            records[0]["record_ref"] = "Database row 11"

        def wrong_total(records: list[dict[str, object]]) -> None:
            records[0]["observation_records"] = 999

        def wrong_flag(records: list[dict[str, object]]) -> None:
            records[0]["review_flagged"] = False

        def noncanonical_number(records: list[dict[str, object]]) -> None:
            records[0]["average_confidence_pct"] = 85

        def negative_zero(records: list[dict[str, object]]) -> None:
            records[0]["average_confidence_pct"] = -0.0

        def wrong_order(records: list[dict[str, object]]) -> None:
            first_values = {
                key: value
                for key, value in records[0].items()
                if key != "record_ref"
            }
            second_values = {
                key: value
                for key, value in records[1].items()
                if key != "record_ref"
            }
            records[0].update(second_values)
            records[1].update(first_values)

        mutations = {
            "reference": wrong_reference,
            "total": wrong_total,
            "flag": wrong_flag,
            "integer-confidence": noncanonical_number,
            "negative-zero": negative_zero,
            "order": wrong_order,
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    case = workspace / name
                    case.mkdir()
                    result = self._export(case)
                    manifest = _manifest(result.bundle_root)
                    records = manifest["records"]
                    self.assertIsInstance(records, list)
                    mutate(records)
                    _write_manifest(result.bundle_root, manifest)
                    with self.assertRaises(ReportVerificationError):
                        verify_report_bundle(result.bundle_root)

    def test_cli_export_and_verify_smoke_are_stable_and_path_private(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            workspace = Path(temporary_directory)
            database = workspace / "private-source.sqlite"
            output = workspace / "output"
            output.mkdir()
            _create_database(database)
            export_process = subprocess.run(
                [
                    sys.executable,
                    "report_export.py",
                    "export",
                    "--database",
                    str(database),
                    "--output-parent",
                    str(output),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, export_process.returncode, export_process.stderr)
            self.assertEqual("", export_process.stderr)
            bundle_paths = tuple(output.iterdir())
            self.assertEqual(1, len(bundle_paths))
            bundle = bundle_paths[0]
            verify_process = subprocess.run(
                [sys.executable, "report_export.py", "verify", str(bundle)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, verify_process.returncode, verify_process.stderr)
            self.assertEqual("", verify_process.stderr)
            self.assertEqual(export_process.stdout, verify_process.stdout)
            self.assertIn("CorporateHub offline report bundle v1\n", export_process.stdout)
            self.assertIn(f"privacy              {PRIVACY_MODE}\n", export_process.stdout)
            self.assertIn("plate records        3\n", export_process.stdout)
            self.assertIn("observation records  4\n", export_process.stdout)
            self.assertIn(f"bundle               {bundle.name}\n", export_process.stdout)
            self.assertTrue(bundle.name.startswith(BUNDLE_PREFIX))
            self.assertNotIn(str(database), export_process.stdout)
            self.assertNotIn(str(output), export_process.stdout)


if __name__ == "__main__":
    unittest.main()
