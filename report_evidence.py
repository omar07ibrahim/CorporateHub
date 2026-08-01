"""Generate a deterministic, privacy-bounded offline-report demonstration.

The evidence path creates a synthetic SQLite fixture, executes the standalone
report exporter, verifies the resulting immutable bundle, and renders the
machine receipt and explanatory SVGs tracked by the repository.  It never
imports the GUI, application database wrapper, Pillow, OpenCV, DTK wrappers, or
native code, and it never reads a real application database or source image.
"""

from __future__ import annotations

import argparse
import ast
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import struct
import sys
import tempfile
from typing import Mapping, Sequence
import zlib

from report_export import (
    BUNDLE_PREFIX,
    INDEX_NAME,
    MANIFEST_NAME,
    PRIVACY_MODE,
    ExportResult,
    ReportExportError,
    export_offline_report,
    verify_report_bundle,
)


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
SOURCE_FILES = (
    "report_evidence.py",
    "report_export.py",
    "report_panel.py",
    "tools/capture_offline_report.sh",
)
RECEIPT_PATH = Path("evidence/offline-report-v1.json")
CLI_SVG_PATH = Path("docs/assets/offline-report-cli.svg")
FLOW_SVG_PATH = Path("docs/assets/offline-report-flow.svg")
PRIVACY_SVG_PATH = Path("docs/assets/offline-report-privacy.svg")
SCREENSHOT_PATH = Path("docs/assets/offline-report-browser.png")
DEMO_ROOT = Path("docs/demo/offline-report-v1")
STATIC_ARTIFACT_PATHS = (
    RECEIPT_PATH,
    CLI_SVG_PATH,
    FLOW_SVG_PATH,
    PRIVACY_SVG_PATH,
    SCREENSHOT_PATH,
)
SCREENSHOT_SHA256 = (
    "fcd69332bd023e55b0d7c7d06ff7ba4b867eb61b6ff12ce62f1a1639644c3fb9"
)
SCREENSHOT_REPORT_ID = (
    "20f6b7acf55a0a7cb53ecd650febaf21c90c4abdd299c16d9a8d06ad02b52af1"
)
SCREENSHOT_INDEX_SHA256 = (
    "fcded95cb025d6b28a3622b557ca01193ce4d0ef9f1d12ea22150b47bee1c861"
)
SCREENSHOT_SUMMARY_ASSET_SHA256 = (
    "af06cf68d0dd042c32d30ea05e85360837fb4bce6b329ef3c48744d74465a327"
)
SCREENSHOT_CAPTURE_SCRIPT_SHA256 = (
    "ca18dd72b3b59b1cc2ddc3d9118a2e0c79060acb783515b2a063feef1f851ff0"
)
SCREENSHOT_WIDTH = 1440
SCREENSHOT_HEIGHT = 2200
SCREENSHOT_RENDERER = "Chromium 140.0.7339.186"
SCREENSHOT_REVISION = 1193
SCREENSHOT_BROWSER_SHA256 = (
    "003728e0b77eb9d52e4d258594bd55ce22ecd245eb6d3b6858fbd844c901ad7d"
)
CAPTURE_IMAGE = (
    "mcr.microsoft.com/playwright@"
    "sha256:2f29369043d81d6d69a815ceb80760f55e85f5020371ad06a4d996f18503ad1c"
)
CAPTURE_SCHEMA = "corporatehub.offline-report.chromium-capture.v1"
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_ALLOWED_CHUNKS = {b"IHDR", b"IDAT", b"IEND"}
_MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024
_BUNDLE_NAME_PATTERN = re.compile(rf"\A{BUNDLE_PREFIX}[0-9a-f]{{64}}\Z")
_ASSET_NAME_PATTERN = re.compile(r"\A[0-9a-f]{64}\.svg\Z")
_FIXTURE_CANARIES = (
    "SYNTHETIC-PRIVATE-PLATE-A7Q9",
    "synthetic-private-profile-a7q9",
    "synthetic-private-reason-a7q9",
    "/synthetic/private/frame-a7q9.jpg",
    "2099-12-31T23:59:59Z",
    "synthetic-private-camera-a7q9",
    "SYNTHETIC-PRIVATE-PLATE-B",
    "synthetic-profile-b",
    "synthetic-b.jpg",
    "SYNTHETIC-PRIVATE-PLATE-C",
    "synthetic-profile-c",
    "synthetic-c.jpg",
    "SYNTHETIC-PRIVATE-PLATE-D",
    "synthetic-profile-d",
    "synthetic-private-reason-d",
    "synthetic-d.jpg",
)
_FIXTURE_PLATES = (
    (
        11,
        1,
        _FIXTURE_CANARIES[0],
        _FIXTURE_CANARIES[1],
        _FIXTURE_CANARIES[2],
        _FIXTURE_CANARIES[3],
    ),
    (
        29,
        0,
        _FIXTURE_CANARIES[6],
        _FIXTURE_CANARIES[7],
        "",
        _FIXTURE_CANARIES[8],
    ),
    (
        51,
        None,
        _FIXTURE_CANARIES[9],
        _FIXTURE_CANARIES[10],
        "",
        _FIXTURE_CANARIES[11],
    ),
    (
        77,
        1,
        _FIXTURE_CANARIES[12],
        _FIXTURE_CANARIES[13],
        _FIXTURE_CANARIES[14],
        _FIXTURE_CANARIES[15],
    ),
)
_FIXTURE_SCORE_ROWS = (
    (101, 11, 96.2),
    (102, 11, 91.5),
    (103, 11, None),
    (104, 29, 82.0),
    (105, 29, 78.4),
    (106, 51, 58.3),
    (107, 77, 66.6),
    (108, 77, 88.8),
    (109, 77, 100.0),
)
class EvidenceError(RuntimeError):
    """Raised when the tracked evidence would be stale, unsafe, or untruthful."""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _digest(content: bytes) -> str:
    return sha256(content).hexdigest()


def _fixture_specification() -> dict[str, object]:
    """Return the public, source-derived fixed fixture specification."""

    return {
        "observation_records": len(_FIXTURE_SCORE_ROWS),
        "observations": [
            {"confidence": confidence, "id": identifier, "plate_id": plate_id}
            for identifier, plate_id, confidence in _FIXTURE_SCORE_ROWS
        ],
        "plates": [
            {"blacklist_storage": blacklist, "id": identifier}
            for identifier, blacklist, *_private in _FIXTURE_PLATES
        ],
        "plate_records": len(_FIXTURE_PLATES),
        "schema": "corporatehub.offline-report.synthetic-fixture.v1",
        "subject": (
            "public row layout and aggregate inputs; private canaries are "
            "bound by generator source hash"
        ),
    }


def _is_expression(node: ast.AST, expression: str) -> bool:
    expected = ast.parse(expression, mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected,
        include_attributes=False,
    )


def _gui_binding_errors(source: str) -> tuple[str, ...]:
    """Return fixed errors for the GUI-to-exporter thread and open binding."""

    tree = ast.parse(source, filename="report_panel.py")
    exporter_imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and node.level == 0
        and node.module == "report_export"
        and len(node.names) == 1
        and node.names[0].name == "export_offline_report"
        and node.names[0].asname is None
    ]
    shadow_bindings = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Store)
            and node.id == "export_offline_report"
        )
        or (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "export_offline_report"
        )
        or (isinstance(node, ast.arg) and node.arg == "export_offline_report")
    ]
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "export_report"
    ]
    if len(functions) != 1:
        return ("report_panel.py must contain one export_report method",)
    export_function = functions[0]
    nested_functions: dict[str, list[ast.FunctionDef]] = {}
    for node in export_function.body:
        if isinstance(node, ast.FunctionDef):
            nested_functions.setdefault(node.name, []).append(node)
    workers = nested_functions.get("run_export", [])
    finishers = nested_functions.get("finish_export", [])
    errors: list[str] = []
    if len(exporter_imports) != 1 or shadow_bindings:
        errors.append("report exporter import binding changed")
    expected_export = "export_offline_report(self.db.path, output_parent)"
    all_export_calls = [
        node
        for node in ast.walk(export_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "export_offline_report"
    ]
    if (
        len(workers) != 1
        or workers[0].decorator_list
        or workers[0].args.args
        or workers[0].args.posonlyargs
        or workers[0].args.kwonlyargs
        or workers[0].args.vararg is not None
        or workers[0].args.kwarg is not None
    ):
        errors.append("export_report must contain one background worker")
    else:
        live_export_assignments = [
            statement
            for try_node in workers[0].body
            if isinstance(try_node, ast.Try)
            for statement in try_node.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == "export_result"
            and _is_expression(statement.value, expected_export)
        ]
        if len(live_export_assignments) != 1:
            errors.append("background worker exporter dataflow changed")
    if len(all_export_calls) != 1:
        errors.append("export_report must call the offline exporter exactly once")
    expected_thread = (
        "threading.Thread(target=run_export, "
        "name='CorporateHub-report-export', daemon=True)"
    )
    thread_assignments = [
        node
        for node in export_function.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "worker"
        and _is_expression(node.value, expected_thread)
    ]
    if len(thread_assignments) != 1:
        errors.append("export_report background-thread contract changed")
    live_starts = [
        statement
        for try_node in export_function.body
        if isinstance(try_node, ast.Try)
        for statement in try_node.body
        if isinstance(statement, ast.Expr)
        and _is_expression(statement.value, "worker.start()")
    ]
    if len(live_starts) != 1:
        errors.append("export_report must start the background worker")
    expected_open = "webbrowser.open(local_file_uri(export_result.index_path))"
    all_open_calls = [
        node
        for node in ast.walk(export_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "open"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "webbrowser"
    ]
    expected_prompt = (
        "messagebox.askyesno('Open Report', "
        "'Would you like to open the exported report in your browser?')"
    )
    live_open_calls: list[ast.Call] = []
    if len(finishers) == 1 and not finishers[0].decorator_list:
        for conditional in finishers[0].body:
            if not (
                isinstance(conditional, ast.If)
                and _is_expression(conditional.test, expected_prompt)
            ):
                continue
            for try_node in conditional.body:
                if not isinstance(try_node, ast.Try):
                    continue
                live_open_calls.extend(
                    statement.value
                    for statement in try_node.body
                    if isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Call)
                    and _is_expression(statement.value, expected_open)
                )
    if len(finishers) != 1 or len(live_open_calls) != 1 or len(all_open_calls) != 1:
        errors.append("verified report browser binding changed")
    forbidden = {"analyze_similar_plates", "export_html", "get_all_plates"}
    if any(
        isinstance(node, ast.Attribute) and node.attr in forbidden
        for node in ast.walk(export_function)
    ):
        errors.append("legacy mutable report path is reachable")
    return tuple(errors)


def _read_sources(
    root: Path,
    source_overrides: Mapping[str, str] | None,
) -> dict[str, str]:
    overrides = source_overrides or {}
    unknown = set(overrides) - set(SOURCE_FILES)
    if unknown:
        raise EvidenceError("source override is outside the evidence boundary")
    sources: dict[str, str] = {}
    for filename in SOURCE_FILES:
        if filename in overrides:
            sources[filename] = overrides[filename]
        else:
            sources[filename] = (root / filename).read_text(encoding="utf-8")
    return sources


def _create_synthetic_database(path: Path) -> None:
    detections = tuple(
        (
            identifier,
            plate_id,
            confidence,
            _FIXTURE_CANARIES[4],
            _FIXTURE_CANARIES[3],
            _FIXTURE_CANARIES[5],
        )
        for identifier, plate_id, confidence in _FIXTURE_SCORE_ROWS
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
            _FIXTURE_PLATES,
        )
        connection.executemany(
            """
            INSERT INTO plate_detections(
                id, plate_id, confidence, detection_time,
                plate_image_path, source_name
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            detections,
        )
        connection.commit()
    finally:
        connection.close()
    path.chmod(0o600)


def _assert_synthetic_fixture_rows(path: Path) -> None:
    uri = f"{path.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        observed_plates = tuple(
            connection.execute(
                "SELECT id, is_blacklisted FROM plates ORDER BY id"
            )
        )
        observed_scores = tuple(
            connection.execute(
                "SELECT id, plate_id, confidence "
                "FROM plate_detections ORDER BY id"
            )
        )
    finally:
        connection.close()
    expected_plates = tuple(
        (identifier, blacklist)
        for identifier, blacklist, *_private in _FIXTURE_PLATES
    )
    if observed_plates != expected_plates or observed_scores != _FIXTURE_SCORE_ROWS:
        raise EvidenceError("synthetic fixture rows changed before export")


def _bundle_files(result: ExportResult) -> dict[str, bytes]:
    files = {
        path.relative_to(result.bundle_root).as_posix(): path.read_bytes()
        for path in sorted(result.bundle_root.rglob("*"))
        if path.is_file()
    }
    asset_paths = [
        path
        for path in files
        if path.startswith("assets/") and path.endswith(".svg")
    ]
    if len(asset_paths) != 1:
        raise EvidenceError("synthetic report bundle asset inventory changed")
    expected = {INDEX_NAME, MANIFEST_NAME, asset_paths[0]}
    if set(files) != expected:
        raise EvidenceError("synthetic report bundle has an unexpected inventory")
    return files


def _render_demo_bundle(root: Path) -> tuple[dict[Path, bytes], dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix=".offline-report-evidence-", dir=root) as temporary:
        workspace = Path(temporary)
        database = workspace / "synthetic.sqlite"
        output = workspace / "output"
        output.mkdir()
        _create_synthetic_database(database)
        _assert_synthetic_fixture_rows(database)
        source_before = database.read_bytes()
        if not all(
            canary.encode("utf-8") in source_before
            for canary in _FIXTURE_CANARIES
        ):
            raise EvidenceError("synthetic source canary fixture is incomplete")
        first = export_offline_report(database, output)
        repeated = export_offline_report(database, output)
        verified = verify_report_bundle(first.bundle_root)
        if first != repeated or first != verified:
            raise EvidenceError("synthetic export is not idempotent and verified")
        if database.read_bytes() != source_before:
            raise EvidenceError("synthetic source database changed during export")
        files = _bundle_files(first)
        public_bytes = b"\n".join(files.values())
        for canary in _FIXTURE_CANARIES:
            if canary.encode("utf-8") in public_bytes:
                raise EvidenceError("a synthetic private field reached the demo bundle")
        forbidden_public_fragments = (
            str(workspace).encode("utf-8"),
            str(root.resolve()).encode("utf-8"),
            b"/home/",
            b"file://",
        )
        if any(fragment in public_bytes for fragment in forbidden_public_fragments):
            raise EvidenceError("host state reached the synthetic demo bundle")
        demo_files = {
            DEMO_ROOT / first.bundle_root.name / PurePosixPath(relative): content
            for relative, content in files.items()
        }
        manifest = json.loads(files[MANIFEST_NAME])
        if manifest["summary"] != {
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
        }:
            raise EvidenceError("synthetic report summary changed unexpectedly")
        model = {
            "bundle_name": first.bundle_root.name,
            "files": [
                {
                    "bytes": len(content),
                    "path": relative,
                    "sha256": _digest(content),
                }
                for relative, content in sorted(files.items())
            ],
            "idempotent": True,
            "report_id": first.report_id,
            "source_database_unchanged": True,
            "summary": manifest["summary"],
            "verified": True,
        }
        return demo_files, model


def demo_index_path(root: Path = ROOT) -> Path:
    """Return the deterministic tracked index path without requiring a screenshot."""

    demo_files, model = _render_demo_bundle(root)
    index = DEMO_ROOT / str(model["bundle_name"]) / INDEX_NAME
    if index not in demo_files:
        raise EvidenceError("synthetic demo index is missing")
    return root / index


def _validate_screenshot(
    content: bytes,
    demo: Mapping[str, object],
    capture_script: str,
) -> dict[str, object]:
    capture_constants = (
        SCREENSHOT_SHA256,
        SCREENSHOT_REPORT_ID,
        SCREENSHOT_INDEX_SHA256,
        SCREENSHOT_SUMMARY_ASSET_SHA256,
        SCREENSHOT_CAPTURE_SCRIPT_SHA256,
    )
    if any(value == "0" * 64 for value in capture_constants):
        raise EvidenceError("browser capture constants have not been reviewed")
    if _digest(content) != SCREENSHOT_SHA256:
        raise EvidenceError("browser screenshot hash is stale")
    if not content.startswith(_PNG_SIGNATURE) or not 33 <= len(content) <= _MAX_SCREENSHOT_BYTES:
        raise EvidenceError("browser screenshot is not PNG")
    offset = len(_PNG_SIGNATURE)
    chunks: list[str] = []
    compressed = bytearray()
    width = height = None
    saw_iend = False
    saw_idat = False
    idat_finished = False
    color_type = None
    while offset < len(content):
        if offset + 12 > len(content):
            raise EvidenceError("browser screenshot has a truncated PNG chunk")
        length = struct.unpack(">I", content[offset : offset + 4])[0]
        chunk_type = content[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(content):
            raise EvidenceError("browser screenshot has a truncated PNG payload")
        payload = content[data_start:data_end]
        observed_crc = struct.unpack(">I", content[data_end:crc_end])[0]
        expected_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if observed_crc != expected_crc:
            raise EvidenceError("browser screenshot has an invalid PNG checksum")
        if chunk_type not in _PNG_ALLOWED_CHUNKS:
            raise EvidenceError("browser screenshot contains a non-pixel PNG chunk")
        try:
            chunks.append(chunk_type.decode("ascii"))
        except UnicodeDecodeError as error:
            raise EvidenceError("browser screenshot has an invalid PNG chunk type") from error
        if chunk_type == b"IHDR":
            if width is not None or length != 13 or len(chunks) != 1:
                raise EvidenceError("browser screenshot has an invalid PNG header")
            width, height = struct.unpack(">II", payload[:8])
            bit_depth, color_type, compression, filtering, interlace = payload[8:]
            if (
                bit_depth != 8
                or color_type not in {2, 6}
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                raise EvidenceError("browser screenshot pixel format is unsupported")
        elif chunk_type == b"IDAT":
            if width is None or idat_finished or saw_iend:
                raise EvidenceError("browser screenshot IDAT ordering is invalid")
            saw_idat = True
            compressed.extend(payload)
        if chunk_type == b"IEND":
            idat_finished = True
            if not saw_idat or length != 0 or crc_end != len(content):
                raise EvidenceError("browser screenshot has trailing PNG data")
            saw_iend = True
        elif saw_idat and chunk_type != b"IDAT":
            idat_finished = True
        offset = crc_end
    if not saw_iend or (width, height) != (SCREENSHOT_WIDTH, SCREENSHOT_HEIGHT):
        raise EvidenceError("browser screenshot dimensions or terminator are stale")
    if not chunks or chunks[0] != "IHDR" or chunks[-1] != "IEND":
        raise EvidenceError("browser screenshot PNG structure is incomplete")
    channels = 3 if color_type == 2 else 4
    expected_decoded_bytes = SCREENSHOT_HEIGHT * (
        1 + SCREENSHOT_WIDTH * channels
    )
    decompressor = zlib.decompressobj()
    try:
        decoded = decompressor.decompress(
            bytes(compressed),
            expected_decoded_bytes + 1,
        )
    except zlib.error as error:
        raise EvidenceError("browser screenshot pixel stream is invalid") from error
    if len(decoded) > expected_decoded_bytes or decompressor.unconsumed_tail:
        raise EvidenceError("browser screenshot pixel stream exceeds its dimensions")
    try:
        decoded += decompressor.flush()
    except zlib.error as error:
        raise EvidenceError("browser screenshot pixel stream is invalid") from error
    if (
        len(decoded) != expected_decoded_bytes
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise EvidenceError("browser screenshot pixel stream length is invalid")

    files = demo["files"]
    if not isinstance(files, list):
        raise EvidenceError("synthetic demo inventory has an invalid shape")
    index_records = [record for record in files if record.get("path") == INDEX_NAME]
    asset_records = [
        record
        for record in files
        if str(record.get("path", "")).startswith("assets/")
    ]
    if len(index_records) != 1 or len(asset_records) != 1:
        raise EvidenceError("synthetic demo browser inventory is incomplete")
    if (
        demo.get("report_id") != SCREENSHOT_REPORT_ID
        or index_records[0].get("sha256") != SCREENSHOT_INDEX_SHA256
        or asset_records[0].get("sha256")
        != SCREENSHOT_SUMMARY_ASSET_SHA256
        or _digest(capture_script.encode("utf-8"))
        != SCREENSHOT_CAPTURE_SCRIPT_SHA256
    ):
        raise EvidenceError("browser screenshot source binding is stale")
    return {
        "browser_binary_sha256": SCREENSHOT_BROWSER_SHA256,
        "browser_sandbox_enabled": False,
        "bytes": len(content),
        "container_image": CAPTURE_IMAGE,
        "container_isolation": (
            "nonroot; read-only; no network; all capabilities dropped; "
            "no-new-privileges"
        ),
        "capture_schema": CAPTURE_SCHEMA,
        "capture_script_sha256": SCREENSHOT_CAPTURE_SCRIPT_SHA256,
        "color_profile": "sRGB",
        "decoded_scanlines_sha256": _digest(decoded),
        "device_scale_factor": 1,
        "font_environment": (
            "pinned Playwright v1.55.1 Noble image defaults; pixel hash is "
            "environment-sensitive"
        ),
        "height": height,
        "index_sha256": SCREENSHOT_INDEX_SHA256,
        "locale": "en-US",
        "network_disabled": True,
        "path": SCREENSHOT_PATH.as_posix(),
        "renderer": SCREENSHOT_RENDERER,
        "renderer_revision": SCREENSHOT_REVISION,
        "report_id": SCREENSHOT_REPORT_ID,
        "sha256": SCREENSHOT_SHA256,
        "summary_asset_sha256": SCREENSHOT_SUMMARY_ASSET_SHA256,
        "timezone": "UTC",
        "width": width,
    }


def collect_evidence(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
    screenshot_override: bytes | None = None,
) -> tuple[dict[str, object], dict[Path, bytes]]:
    """Execute the synthetic export and return its bounded evidence model."""

    sources = _read_sources(root, source_overrides)
    binding_errors = _gui_binding_errors(sources["report_panel.py"])
    demo_files, demo = _render_demo_bundle(root)
    screenshot = (
        screenshot_override
        if screenshot_override is not None
        else (root / SCREENSHOT_PATH).read_bytes()
    )
    screenshot_model = _validate_screenshot(
        screenshot,
        demo,
        sources["tools/capture_offline_report.sh"],
    )
    source_hashes = {
        filename: _digest(source.encode("utf-8"))
        for filename, source in sources.items()
    }
    fixture_specification = _fixture_specification()
    evidence = {
        "artifact": "corporatehub.offline-report.evidence",
        "browser_capture": screenshot_model,
        "bundle": demo,
        "fixture": {
            "kind": "fixed synthetic SQLite",
            "specification_sha256": _digest(
                _canonical_json(fixture_specification)
            ),
            **fixture_specification,
        },
        "privacy": {
            "fixture_canaries_serialized": 0,
            "privacy_mode": PRIVACY_MODE,
            "raw_identifiers_selected": False,
            "source_images_copied": 0,
            "timestamps_selected": False,
        },
        "schema_version": SCHEMA_VERSION,
        "scope": {
            "application_started": False,
            "database_kind": "generated synthetic fixture",
            "gui_executed": False,
            "native_runtime_loaded": False,
            "network_required_by_bundle": False,
            "source_images_opened": 0,
            "vendor_runtime_loaded": False,
        },
        "source_binding": {
            "checked_entry_point": "report_panel.py:ReportPanel.export_report",
            "status": "pass" if not binding_errors else "fail",
            "violations": list(binding_errors),
        },
        "source_set_sha256": _digest(_canonical_json(source_hashes)),
        "source_sha256": source_hashes,
    }
    return evidence, {**demo_files, SCREENSHOT_PATH: screenshot}


def _assert_publishable(evidence: Mapping[str, object]) -> None:
    bundle = evidence.get("bundle")
    privacy = evidence.get("privacy")
    scope = evidence.get("scope")
    binding = evidence.get("source_binding")
    screenshot = evidence.get("browser_capture")
    fixture = evidence.get("fixture")
    fixture_specification = _fixture_specification()
    if not all(
        isinstance(value, Mapping)
        for value in (bundle, privacy, scope, binding, screenshot, fixture)
    ):
        raise EvidenceError("offline-report evidence model has an invalid shape")
    summary = bundle.get("summary")
    if (
        bundle.get("verified") is not True
        or bundle.get("idempotent") is not True
        or bundle.get("source_database_unchanged") is not True
        or not isinstance(bundle.get("report_id"), str)
        or not str(bundle.get("bundle_name", "")).startswith(BUNDLE_PREFIX)
        or not isinstance(summary, Mapping)
        or summary.get("plate_records") != 4
        or summary.get("observation_records") != 9
        or summary.get("scored_observations") != 8
        or summary.get("blacklisted_records") != 2
        or fixture
        != {
            "kind": "fixed synthetic SQLite",
            "specification_sha256": _digest(
                _canonical_json(fixture_specification)
            ),
            **fixture_specification,
        }
        or privacy
        != {
            "fixture_canaries_serialized": 0,
            "privacy_mode": PRIVACY_MODE,
            "raw_identifiers_selected": False,
            "source_images_copied": 0,
            "timestamps_selected": False,
        }
        or scope
        != {
            "application_started": False,
            "database_kind": "generated synthetic fixture",
            "gui_executed": False,
            "native_runtime_loaded": False,
            "network_required_by_bundle": False,
            "source_images_opened": 0,
            "vendor_runtime_loaded": False,
        }
        or binding.get("status") != "pass"
        or binding.get("violations") != []
        or screenshot.get("report_id") != bundle.get("report_id")
        or screenshot.get("network_disabled") is not True
        or screenshot.get("container_image") != CAPTURE_IMAGE
        or screenshot.get("browser_binary_sha256")
        != SCREENSHOT_BROWSER_SHA256
        or screenshot.get("renderer") != SCREENSHOT_RENDERER
        or screenshot.get("browser_sandbox_enabled") is not False
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(evidence.get("source_set_sha256", "")),
        )
    ):
        raise EvidenceError("refusing to publish failing offline-report evidence")


def format_receipt(evidence: Mapping[str, object]) -> str:
    bundle = evidence["bundle"]
    privacy = evidence["privacy"]
    binding = evidence["source_binding"]
    screenshot = evidence["browser_capture"]
    source_set = evidence["source_set_sha256"]
    if not all(
        isinstance(value, Mapping)
        for value in (bundle, privacy, binding, screenshot)
    ):
        raise EvidenceError("offline-report receipt has an invalid shape")
    summary = bundle["summary"]
    if not isinstance(summary, Mapping):
        raise EvidenceError("offline-report summary has an invalid shape")
    return "\n".join(
        (
            "CorporateHub offline report evidence v1",
            f"GUI source binding     {str(binding['status']).upper()} (1/1)",
            (
                "synthetic snapshot    PASS "
                f"({summary['plate_records']} records / "
                f"{summary['observation_records']} observations)"
            ),
            f"bundle verification    PASS ({str(bundle['report_id'])[:12]})",
            (
                "private canaries      OMITTED "
                f"({privacy['fixture_canaries_serialized']} serialized)"
            ),
            (
                "browser capture       BOUND "
                f"({screenshot['width']}x{screenshot['height']} / DPR 1)"
            ),
            f"source set            BOUND ({str(source_set)[:12]})",
            "scope                   synthetic · offline · no GUI/native runtime",
        )
    )


def format_artifact_status(status: str, count: int) -> str:
    if status not in {"CURRENT", "WROTE"} or type(count) is not int or count <= 0:
        raise EvidenceError("offline-report artifact status is invalid")
    return f"tracked artifacts       {status} ({count}/{count})"


def _svg_document(
    *,
    width: int,
    height: int,
    title_id: str,
    title: str,
    description_id: str,
    description: str,
    body: str,
) -> bytes:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="{title_id} {description_id}">\n'
        f'  <title id="{title_id}">{escape(title, quote=True)}</title>\n'
        f'  <desc id="{description_id}">{escape(description, quote=True)}</desc>\n'
        f"{body}\n"
        "</svg>\n"
    ).encode("utf-8")


def _svg_text(
    x: int,
    y: int,
    value: object,
    *,
    size: int = 22,
    fill: str = "#d8e5ff",
    weight: str = "400",
    family: str = "Inter,Segoe UI,sans-serif",
    anchor: str | None = None,
) -> str:
    anchor_attribute = f' text-anchor="{anchor}"' if anchor else ""
    return (
        f'  <text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
        f'font-weight="{weight}" font-family="{family}"{anchor_attribute}>'
        f"{escape(str(value), quote=True)}</text>"
    )


def render_cli_svg(evidence: Mapping[str, object], artifact_count: int) -> bytes:
    """Render the exact CLI receipt as an accessible terminal visual."""

    lines = format_receipt(evidence).splitlines()
    lines.append(format_artifact_status("CURRENT", artifact_count))
    body = [
        '  <rect x="0" y="0" width="1240" height="520" rx="24" fill="#09111f"/>',
        '  <rect x="0" y="0" width="1240" height="64" rx="24" fill="#16243a"/>',
        '  <rect x="0" y="40" width="1240" height="24" fill="#16243a"/>',
        '  <circle cx="34" cy="32" r="8" fill="#ff6b6b"/>',
        '  <circle cx="60" cy="32" r="8" fill="#ffd166"/>',
        '  <circle cx="86" cy="32" r="8" fill="#60d394"/>',
        _svg_text(
            620,
            40,
            "python3 report_evidence.py --check",
            size=18,
            fill="#a9bdd8",
            family="ui-monospace,SFMono-Regular,Consolas,monospace",
            anchor="middle",
        ),
    ]
    for index, line in enumerate(lines):
        body.append(
            _svg_text(
                48,
                106 + index * 47,
                line,
                size=21,
                fill="#e8f1ff" if index == 0 else "#b8f7d4",
                weight="700" if index == 0 else "500",
                family="ui-monospace,SFMono-Regular,Consolas,monospace",
            )
        )
    return _svg_document(
        width=1240,
        height=520,
        title_id="offline-cli-title",
        title="Exact CorporateHub offline report evidence receipt",
        description_id="offline-cli-description",
        description=(
            "Terminal-style rendering of the same source-bound synthetic report "
            "receipt printed by the evidence checker."
        ),
        body="\n".join(body),
    )


def render_flow_svg(evidence: Mapping[str, object]) -> bytes:
    """Render the executed synthetic report and browser-capture workflow."""

    bundle = evidence["bundle"]
    screenshot = evidence["browser_capture"]
    binding = evidence["source_binding"]
    if not all(
        isinstance(value, Mapping)
        for value in (bundle, screenshot, binding)
    ):
        raise EvidenceError("offline-report flow model has an invalid shape")
    nodes = (
        (
            40,
            150,
            230,
            132,
            "1 · FIXTURE",
            "4 records · 9 rows",
            "fixed synthetic SQLite",
        ),
        (
            330,
            150,
            230,
            132,
            "2 · EXPORT",
            "report_export.py",
            "read-only · redacted-v1",
        ),
        (
            620,
            150,
            230,
            132,
            "3 · VERIFY",
            str(bundle["report_id"])[:12],
            "HTML · JSON · SVG",
        ),
        (
            910,
            150,
            250,
            132,
            "4 · RENDER",
            "Chromium 140.0.7339.186",
            "network none · 1440×2200",
        ),
    )
    body = [
        '  <rect x="0" y="0" width="1200" height="500" rx="28" fill="#071426"/>',
        _svg_text(
            40,
            62,
            "Executed synthetic offline-report workflow",
            size=31,
            fill="#f7fbff",
            weight="700",
        ),
        _svg_text(
            40,
            100,
            f"GUI binding {str(binding['status']).upper()} by AST · GUI / DTK / camera NOT RUN",
            size=20,
            fill="#9cb2cf",
        ),
    ]
    for x, y, width, height, heading, detail, note in nodes:
        body.extend(
            (
                (
                    f'  <rect x="{x}" y="{y}" width="{width}" '
                    f'height="{height}" rx="18" fill="#112a45" '
                    'stroke="#3e76a8" stroke-width="2"/>'
                ),
                _svg_text(
                    x + 20,
                    y + 35,
                    heading,
                    size=17,
                    fill="#66e0b4",
                    weight="700",
                ),
                _svg_text(
                    x + 20,
                    y + 73,
                    detail,
                    size=17,
                    fill="#f0f6ff",
                    weight="700",
                ),
                _svg_text(x + 20, y + 105, note, size=16, fill="#abc0d9"),
            )
        )
    for start in (270, 560, 850):
        body.extend(
            (
                (
                    f'  <line x1="{start}" y1="216" x2="{start + 48}" '
                    'y2="216" stroke="#66e0b4" stroke-width="4"/>'
                ),
                (
                    f'  <polygon points="{start + 48},216 '
                    f'{start + 34},207 {start + 34},225" fill="#66e0b4"/>'
                ),
            )
        )
    body.extend(
        (
            (
                '  <rect x="40" y="340" width="1120" height="108" '
                'rx="18" fill="#0d2138" stroke="#284b70"/>'
            ),
            _svg_text(
                68,
                380,
                "Published evidence",
                size=19,
                fill="#66e0b4",
                weight="700",
            ),
            _svg_text(
                68,
                414,
                f"verified bundle + canonical receipt + real PNG {str(screenshot['sha256'])[:12]}",
                size=20,
                fill="#e9f2ff",
                weight="600",
            ),
            _svg_text(
                718,
                414,
                "not recognition, accuracy, performance, or production evidence",
                size=16,
                fill="#ffcc80",
            ),
        )
    )
    return _svg_document(
        width=1200,
        height=500,
        title_id="offline-flow-title",
        title="CorporateHub synthetic offline report evidence flow",
        description_id="offline-flow-description",
        description=(
            "A fixed synthetic SQLite fixture is exported, verified, and rendered "
            "by isolated Chromium while the GUI and native recognition stack stay off."
        ),
        body="\n".join(body),
    )


def render_privacy_svg(evidence: Mapping[str, object]) -> bytes:
    """Render selected aggregate fields and deliberately omitted private fields."""

    summary = evidence["bundle"]["summary"]
    privacy = evidence["privacy"]
    if not isinstance(summary, Mapping) or not isinstance(privacy, Mapping):
        raise EvidenceError("offline-report privacy model has an invalid shape")
    selected = (
        f"{summary['plate_records']} report-local records",
        f"{summary['observation_records']} observation rows",
        f"{summary['scored_observations']} scored observations",
        f"{summary['blacklisted_records']} review-flagged records",
        f"{summary['average_confidence_pct']}% aggregate confidence",
    )
    omitted = (
        "raw plate identifiers",
        "profiles, reasons, and source names",
        "timestamps and filesystem paths",
        "source and cropped images",
        "fixture private-field canaries",
    )
    body = [
        '  <rect x="0" y="0" width="1200" height="560" rx="28" fill="#08131f"/>',
        _svg_text(
            48,
            62,
            "Redacted-v1 publication boundary",
            size=31,
            fill="#f5f9ff",
            weight="700",
        ),
        _svg_text(
            48,
            100,
            (
                "Observed from the fixed synthetic export · redaction reduces "
                "exposure, not all inference risk"
            ),
            size=18,
            fill="#a8b9cc",
        ),
        (
            '  <rect x="48" y="140" width="520" height="338" rx="20" '
            'fill="#0c2c29" stroke="#2d8b70" stroke-width="2"/>'
        ),
        (
            '  <rect x="632" y="140" width="520" height="338" rx="20" '
            'fill="#30231f" stroke="#a96b52" stroke-width="2"/>'
        ),
        _svg_text(
            80,
            185,
            "SELECTED AGGREGATES",
            size=19,
            fill="#6de2b7",
            weight="700",
        ),
        _svg_text(
            664,
            185,
            "OMITTED FROM PUBLIC BYTES",
            size=19,
            fill="#ffb08e",
            weight="700",
        ),
    ]
    for index, value in enumerate(selected):
        y = 232 + index * 48
        body.append(_svg_text(82, y, f"✓  {value}", size=19, fill="#e0fff3"))
    for index, value in enumerate(omitted):
        y = 232 + index * 48
        body.append(_svg_text(666, y, f"—  {value}", size=19, fill="#ffe8df"))
    body.extend(
        (
            (
                '  <rect x="48" y="500" width="1104" height="36" '
                'rx="12" fill="#13263a"/>'
            ),
            _svg_text(
                600,
                525,
                (
                    "serialized fixture canaries: "
                    f"{privacy['fixture_canaries_serialized']} · real data used: NO"
                ),
                size=17,
                fill="#c9d8e8",
                weight="600",
                anchor="middle",
            ),
        )
    )
    return _svg_document(
        width=1200,
        height=560,
        title_id="offline-privacy-title",
        title="CorporateHub offline report redaction boundary",
        description_id="offline-privacy-description",
        description=(
            "A comparison of the aggregate synthetic fields published by redacted-v1 "
            "and identifier, path, timestamp, profile, and image fields omitted."
        ),
        body="\n".join(body),
    )


def render_artifacts(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
    screenshot_override: bytes | None = None,
) -> dict[Path, bytes]:
    """Render every tracked evidence byte from one validated model."""

    evidence, bound_artifacts = collect_evidence(
        root,
        source_overrides,
        screenshot_override,
    )
    _assert_publishable(evidence)
    artifact_count = len(bound_artifacts) + 4
    artifacts = {
        **bound_artifacts,
        RECEIPT_PATH: _canonical_json(evidence),
        CLI_SVG_PATH: render_cli_svg(evidence, artifact_count),
        FLOW_SVG_PATH: render_flow_svg(evidence),
        PRIVACY_SVG_PATH: render_privacy_svg(evidence),
    }
    if len(artifacts) != artifact_count:
        raise EvidenceError("offline-report artifact inventory is ambiguous")
    text_artifacts = b"\n".join(
        content
        for path, content in artifacts.items()
        if path.suffix != ".png"
    )
    forbidden = (
        *(_canary.encode("utf-8") for _canary in _FIXTURE_CANARIES),
        str(root.resolve()).encode("utf-8"),
        b"/home/",
        b"file:///",
        b"created_at",
        b"generated_at",
        b"commit_sha",
    )
    if any(fragment in text_artifacts for fragment in forbidden):
        raise EvidenceError("private fixture or host state reached tracked evidence")
    for relative in artifacts:
        if relative.is_absolute() or ".." in relative.parts:
            raise EvidenceError("offline-report artifact path escaped its boundary")
    return artifacts


def _actual_demo_paths(root: Path) -> set[Path]:
    demo_root = root / DEMO_ROOT
    if not demo_root.exists() and not demo_root.is_symlink():
        return set()
    paths: set[Path] = {DEMO_ROOT}
    if demo_root.is_symlink() or not demo_root.is_dir():
        return paths
    for directory, directory_names, filenames in os.walk(
        demo_root,
        topdown=True,
        followlinks=False,
    ):
        base = Path(directory)
        for name in directory_names:
            paths.add((base / name).relative_to(root))
        for name in filenames:
            paths.add((base / name).relative_to(root))
    return paths


def artifact_differences(
    root: Path,
    expected: Mapping[Path, bytes],
) -> tuple[Path, ...]:
    """Return stale, missing, unsafe, and extra managed artifact paths."""

    differences: set[Path] = set()
    for relative, content in expected.items():
        current = root
        unsafe_parent: Path | None = None
        for component in relative.parts[:-1]:
            current /= component
            try:
                parent_metadata = current.lstat()
            except FileNotFoundError:
                break
            if not stat.S_ISDIR(parent_metadata.st_mode):
                unsafe_parent = current.relative_to(root)
                break
        if unsafe_parent is not None:
            differences.add(unsafe_parent)
            continue
        target = root / relative
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            differences.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or target.read_bytes() != content:
            differences.add(relative)

    expected_demo_files = {
        path for path in expected if path == DEMO_ROOT or DEMO_ROOT in path.parents
    }
    expected_demo_paths: set[Path] = {DEMO_ROOT}
    for path in expected_demo_files:
        expected_demo_paths.add(path)
        expected_demo_paths.update(
            parent
            for parent in path.parents
            if parent == DEMO_ROOT or DEMO_ROOT in parent.parents
        )
    differences.update(_actual_demo_paths(root) - expected_demo_paths)
    return tuple(sorted(differences, key=lambda path: path.as_posix()))


def _validate_demo_tree(root: Path) -> tuple[Path, ...]:
    demo_root = root / DEMO_ROOT
    if not demo_root.exists() and not demo_root.is_symlink():
        return ()
    metadata = demo_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise EvidenceError("managed demo root is not a regular directory")
    bundles: list[Path] = []
    for candidate in demo_root.iterdir():
        candidate_metadata = candidate.lstat()
        if (
            not stat.S_ISDIR(candidate_metadata.st_mode)
            or not _BUNDLE_NAME_PATTERN.fullmatch(candidate.name)
        ):
            raise EvidenceError("managed demo contains an unknown top-level entry")
        children = {child.name: child for child in candidate.iterdir()}
        if set(children) != {INDEX_NAME, MANIFEST_NAME, "assets"}:
            raise EvidenceError("managed demo bundle inventory is not generated")
        for filename in (INDEX_NAME, MANIFEST_NAME):
            child_metadata = children[filename].lstat()
            if not stat.S_ISREG(child_metadata.st_mode):
                raise EvidenceError("managed demo contains an unsafe report file")
        assets = children["assets"]
        if not stat.S_ISDIR(assets.lstat().st_mode):
            raise EvidenceError("managed demo assets path is unsafe")
        asset_entries = list(assets.iterdir())
        if len(asset_entries) != 1:
            raise EvidenceError("managed demo asset inventory is not generated")
        asset = asset_entries[0]
        if (
            not stat.S_ISREG(asset.lstat().st_mode)
            or not _ASSET_NAME_PATTERN.fullmatch(asset.name)
        ):
            raise EvidenceError("managed demo contains an unsafe report asset")
        bundles.append(candidate)
    return tuple(sorted(bundles))


def _assert_safe_target(root: Path, relative: Path) -> None:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise EvidenceError("artifact target escaped the repository root")
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceError("artifact root is not a regular directory")
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError("artifact parent is not a regular directory")
    target = root / relative
    try:
        target_metadata = target.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(target_metadata.st_mode) or target_metadata.st_nlink != 1:
        raise EvidenceError("artifact target is not a private regular file")


def _ensure_parent(root: Path, relative_parent: Path) -> Path:
    current = root
    for component in relative_parent.parts:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceError("artifact parent is not a regular directory")
    return current


def _atomic_write(root: Path, relative: Path, content: bytes) -> None:
    parent = _ensure_parent(root, relative.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{relative.name}.",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, root / relative)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _remove_validated_tree(path: Path) -> None:
    for candidate in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        metadata = candidate.lstat()
        if stat.S_ISREG(metadata.st_mode):
            candidate.unlink()
        elif stat.S_ISDIR(metadata.st_mode):
            candidate.rmdir()
        else:
            raise EvidenceError("managed demo changed during cleanup")
    path.rmdir()


def _publish_demo(root: Path, demo_files: Mapping[Path, bytes]) -> None:
    existing_bundles = _validate_demo_tree(root)
    desired_bundle_names = {
        relative.parts[len(DEMO_ROOT.parts)]
        for relative in demo_files
    }
    if len(desired_bundle_names) != 1 or len(demo_files) != 3:
        raise EvidenceError("generated demo inventory is invalid")
    desired_name = next(iter(desired_bundle_names))
    for relative, content in sorted(
        demo_files.items(),
        key=lambda item: item[0].as_posix(),
    ):
        _atomic_write(root, relative, content)
    expected_targets = {root / relative for relative in demo_files}
    desired_root = root / DEMO_ROOT / desired_name
    for candidate in sorted(
        desired_root.rglob("*"),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        if candidate in expected_targets or any(
            candidate in target.parents for target in expected_targets
        ):
            continue
        metadata = candidate.lstat()
        if stat.S_ISREG(metadata.st_mode):
            candidate.unlink()
        elif stat.S_ISDIR(metadata.st_mode):
            candidate.rmdir()
        else:
            raise EvidenceError("managed demo changed during publication")
    for bundle in existing_bundles:
        if bundle.name != desired_name:
            _remove_validated_tree(bundle)


def _write_artifact_map(root: Path, artifacts: Mapping[Path, bytes]) -> int:
    _validate_demo_tree(root)
    for relative in artifacts:
        _assert_safe_target(root, relative)
    demo_files = {
        path: content
        for path, content in artifacts.items()
        if DEMO_ROOT in path.parents
    }
    static_files = {
        path: content
        for path, content in artifacts.items()
        if path not in demo_files
    }
    _publish_demo(root, demo_files)
    for relative, content in sorted(
        static_files.items(),
        key=lambda item: item[0].as_posix(),
    ):
        _atomic_write(root, relative, content)
    return len(artifacts)


def write_current_artifacts(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
    screenshot_override: bytes | None = None,
) -> int:
    """Validate and atomically replace the fixed tracked evidence files."""

    artifacts = render_artifacts(root, source_overrides, screenshot_override)
    return _write_artifact_map(root, artifacts)


def prepare_demo(root: Path = ROOT) -> Path:
    """Publish only the exact synthetic bundle needed for browser capture."""

    demo_files, model = _render_demo_bundle(root)
    _validate_demo_tree(root)
    for relative in demo_files:
        _assert_safe_target(root, relative)
    _publish_demo(root, demo_files)
    index = DEMO_ROOT / str(model["bundle_name"]) / INDEX_NAME
    return root / index


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate bounded CorporateHub offline-report evidence.",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--check",
        action="store_true",
        help=(
            "regenerate in temporary storage and byte-compare tracked artifacts "
            "without changing them or launching Docker"
        ),
    )
    actions.add_argument(
        "--write",
        action="store_true",
        help="publish the validated evidence using the existing reviewed screenshot",
    )
    actions.add_argument(
        "--prepare-demo",
        action="store_true",
        help="write only the fixed synthetic bundle required for browser capture",
    )
    actions.add_argument(
        "--demo-index",
        action="store_true",
        help=(
            "regenerate in temporary storage and print the deterministic "
            "synthetic demo index path without changing tracked artifacts"
        ),
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(arguments)
    try:
        if args.prepare_demo:
            index = prepare_demo(ROOT)
            print(f"prepared demo           {index.relative_to(ROOT).as_posix()}")
            return 0
        if args.demo_index:
            index = demo_index_path(ROOT)
            print(index.relative_to(ROOT).as_posix())
            return 0

        evidence, _ = collect_evidence(ROOT)
        _assert_publishable(evidence)
        if args.write:
            count = write_current_artifacts(ROOT)
            print(format_receipt(evidence))
            print(format_artifact_status("WROTE", count))
            return 0
        if args.check:
            artifacts = render_artifacts(ROOT)
            differences = artifact_differences(ROOT, artifacts)
            if differences:
                names = ", ".join(path.as_posix() for path in differences)
                raise EvidenceError(f"tracked offline-report evidence is stale: {names}")
            print(format_receipt(evidence))
            print(format_artifact_status("CURRENT", len(artifacts)))
            return 0
        print(format_receipt(evidence))
        return 0
    except (EvidenceError, ReportExportError, OSError, sqlite3.Error, ValueError) as error:
        print(f"offline-report evidence error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
