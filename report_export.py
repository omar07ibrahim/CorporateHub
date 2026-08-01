"""Build privacy-bounded, offline report bundles from a read-only SQLite snapshot.

This module intentionally depends only on the Python standard library.  It does
not import the application's database wrapper because constructing that wrapper
creates tables and settings.  Version one exports aggregate, redacted records
and a generator-owned SVG; it never reads or copies image paths from SQLite.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import errno
import hashlib
import html
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
from typing import Mapping, Sequence
import xml.etree.ElementTree as ET


BUNDLE_SCHEMA = "corporatehub.offline-report.bundle.v1"
PUBLIC_MODEL_SCHEMA = "corporatehub.offline-report.public.v1"
PRIVACY_MODE = "redacted-v1"
TEMPLATE_VERSION = 1
ANALYSIS_VERSION = 1
BUNDLE_PREFIX = "corporatehub-report-"
MANIFEST_NAME = "manifest.json"
INDEX_NAME = "index.html"
REPORT_ID_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
ASSET_PATH_PATTERN = re.compile(r"\Aassets/[0-9a-f]{64}\.svg\Z")
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'none'; "
    "connect-src 'none'; "
    "img-src 'self'; "
    "style-src 'unsafe-inline'; "
    "font-src 'none'; "
    "media-src 'none'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "worker-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

_CONFIDENCE_BANDS = (
    ("unscored", None, None),
    ("below 60%", 0.0, 60.0),
    ("60–79.9%", 60.0, 80.0),
    ("80–89.9%", 80.0, 90.0),
    ("90–100%", 90.0, 100.0000001),
)
_STATIC_WARNINGS = (
    "Redaction reduces exposure but does not guarantee anonymity.",
    "Observation rows may include legacy duplicates and are not deduplicated events.",
    "Identifiers, timestamps, profiles, source names, reasons, paths, and images are omitted.",
)
_REQUIRED_SCHEMA = {
    "plates": {
        "id": ("INTEGER", 1),
        "is_blacklisted": ("BOOLEAN", 0),
    },
    "plate_detections": {
        "id": ("INTEGER", 1),
        "plate_id": ("INTEGER", 0),
        "confidence": ("REAL", 0),
    },
}
_ACTIVE_HTML_ELEMENTS = {
    "audio",
    "base",
    "button",
    "embed",
    "form",
    "iframe",
    "input",
    "link",
    "media",
    "object",
    "script",
    "source",
    "track",
    "video",
}
_ALLOWED_HTML_ATTRIBUTES = {
    "body": frozenset(),
    "details": frozenset({"open"}),
    "div": frozenset({"aria-label", "class"}),
    "figure": frozenset({"class"}),
    "footer": frozenset(),
    "h1": frozenset(),
    "h2": frozenset(),
    "head": frozenset(),
    "header": frozenset(),
    "html": frozenset({"lang"}),
    "img": frozenset({"alt", "src"}),
    "li": frozenset(),
    "main": frozenset(
        {
            "data-blacklisted-records",
            "data-observation-records",
            "data-plate-records",
            "data-privacy-mode",
            "data-report-schema",
            "data-scored-observations",
        }
    ),
    "meta": frozenset({"charset", "content", "http-equiv", "name"}),
    "p": frozenset({"class"}),
    "section": frozenset(),
    "span": frozenset({"class"}),
    "strong": frozenset(),
    "style": frozenset(),
    "summary": frozenset(),
    "table": frozenset(),
    "tbody": frozenset(),
    "td": frozenset({"class", "colspan"}),
    "th": frozenset({"scope"}),
    "thead": frozenset(),
    "title": frozenset(),
    "tr": frozenset(),
    "ul": frozenset({"class"}),
}
_URL_BEARING_HTML_ATTRIBUTES = {
    "action",
    "background",
    "cite",
    "formaction",
    "href",
    "longdesc",
    "manifest",
    "ping",
    "poster",
    "profile",
    "src",
    "srcset",
    "usemap",
}
_REPORT_STYLE_SHA256 = "a9d5792f958c5ba248d7b313bd38c4dd5449a24cb350958e96a44b9efbc4c3ea"
_ALLOWED_SVG_ATTRIBUTES = {
    "svg": frozenset(
        {"aria-labelledby", "height", "role", "viewBox", "width"}
    ),
    "title": frozenset({"id"}),
    "desc": frozenset({"id"}),
    "rect": frozenset(
        {"fill", "height", "rx", "stroke", "width", "x", "y"}
    ),
    "text": frozenset(
        {"fill", "font-family", "font-size", "font-weight", "x", "y"}
    ),
}


class ReportExportError(RuntimeError):
    """Base class for bounded report-export failures."""


class ReportSourceError(ReportExportError):
    """Raised when the SQLite source cannot produce a valid typed snapshot."""


class ReportLimitError(ReportExportError):
    """Raised when source or rendered output exceeds a configured bound."""


class ReportPublishError(ReportExportError):
    """Raised when an immutable bundle cannot be safely published."""


class ReportVerificationError(ReportExportError):
    """Raised when a bundle is stale, malformed, active, or tampered."""


@dataclass(frozen=True, slots=True)
class ExportLimits:
    """Hard resource limits for a single export."""

    max_plates: int = 10_000
    max_detections: int = 100_000
    max_html_bytes: int = 4 * 1024 * 1024
    max_manifest_bytes: int = 4 * 1024 * 1024
    max_svg_bytes: int = 256 * 1024
    max_sqlite_row_bytes: int = 1 * 1024 * 1024

    def __post_init__(self) -> None:
        for field_name in (
            "max_plates",
            "max_detections",
            "max_html_bytes",
            "max_manifest_bytes",
            "max_svg_bytes",
            "max_sqlite_row_bytes",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ExportResult:
    """Verified public coordinates and counts for an immutable bundle."""

    bundle_root: Path
    index_path: Path
    manifest_path: Path
    report_id: str
    plate_count: int
    detection_count: int
    durability_warning: str | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class _SourcePlate:
    database_id: int
    blacklisted: bool


@dataclass(frozen=True, slots=True)
class _SourceDetection:
    database_id: int
    plate_id: int
    confidence: float | None


@dataclass(frozen=True, slots=True)
class _PublicPlate:
    record_ref: str
    observation_count: int
    average_confidence: float | None
    peak_confidence: float | None
    review_flagged: bool


@dataclass(frozen=True, slots=True)
class _PublicSnapshot:
    plates: tuple[_PublicPlate, ...]
    observation_count: int
    scored_observation_count: int
    average_confidence: float | None
    blacklisted_count: int
    confidence_bands: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class _RenderedBundle:
    report_id: str
    files: Mapping[str, bytes]


def _canonical_json(value: object, *, pretty: bool) -> bytes:
    options: dict[str, object] = {
        "allow_nan": False,
        "ensure_ascii": False,
        "sort_keys": True,
    }
    if pretty:
        options["indent"] = 2
    else:
        options["separators"] = (",", ":")
    return json.dumps(value, **options).encode("utf-8") + b"\n"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _lexical_absolute(path: str | os.PathLike[str], label: str) -> Path:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError(f"{label} must be a text path")
    raw_value = os.fspath(path)
    if type(raw_value) is not str:
        raise TypeError(f"{label} must be a text path")
    if not raw_value or "\x00" in raw_value:
        raise ReportPublishError(f"{label} must be a non-empty text path")
    return Path(os.path.abspath(raw_value))


def _existing_plain_file(path: str | os.PathLike[str]) -> Path:
    lexical = _lexical_absolute(path, "database path")
    try:
        resolved = lexical.resolve(strict=True)
        metadata = lexical.lstat()
    except OSError as error:
        raise ReportSourceError("database source must be an existing file") from error
    if resolved != lexical or stat.S_ISLNK(metadata.st_mode):
        raise ReportSourceError("database source must not use symlinks")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReportSourceError("database source must be a regular file")
    return resolved


def _existing_plain_directory(path: str | os.PathLike[str]) -> Path:
    lexical = _lexical_absolute(path, "output parent")
    try:
        resolved = lexical.resolve(strict=True)
        metadata = lexical.lstat()
    except OSError as error:
        raise ReportPublishError("output parent must be an existing directory") from error
    if resolved != lexical or stat.S_ISLNK(metadata.st_mode):
        raise ReportPublishError("output parent must not use symlinks")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReportPublishError("output parent must be a directory")
    return resolved


def _authorizer(action: int, _one: str, _two: str, _db: str, _trigger: str) -> int:
    denied_names = (
        "SQLITE_CREATE_INDEX",
        "SQLITE_CREATE_TABLE",
        "SQLITE_CREATE_TEMP_INDEX",
        "SQLITE_CREATE_TEMP_TABLE",
        "SQLITE_CREATE_TEMP_TRIGGER",
        "SQLITE_CREATE_TEMP_VIEW",
        "SQLITE_CREATE_TRIGGER",
        "SQLITE_CREATE_VIEW",
        "SQLITE_DELETE",
        "SQLITE_DROP_INDEX",
        "SQLITE_DROP_TABLE",
        "SQLITE_DROP_TEMP_INDEX",
        "SQLITE_DROP_TEMP_TABLE",
        "SQLITE_DROP_TEMP_TRIGGER",
        "SQLITE_DROP_TEMP_VIEW",
        "SQLITE_DROP_TRIGGER",
        "SQLITE_DROP_VIEW",
        "SQLITE_INSERT",
        "SQLITE_PRAGMA",
        "SQLITE_UPDATE",
        "SQLITE_ATTACH",
        "SQLITE_DETACH",
        "SQLITE_ALTER_TABLE",
        "SQLITE_REINDEX",
        "SQLITE_ANALYZE",
        "SQLITE_CREATE_VTABLE",
        "SQLITE_DROP_VTABLE",
        "SQLITE_SAVEPOINT",
    )
    denied = {getattr(sqlite3, name, None) for name in denied_names}
    return sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK


def _establish_sqlite_length_limit(
    connection: sqlite3.Connection,
    maximum_bytes: int,
) -> None:
    """Fail closed unless SQLite can bound every returned row/value."""

    category = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
    set_limit = getattr(connection, "setlimit", None)
    get_limit = getattr(connection, "getlimit", None)
    if category is None or not callable(set_limit) or not callable(get_limit):
        raise ReportSourceError(
            "the Python SQLite runtime cannot enforce the source row-size limit"
        )
    try:
        set_limit(category, maximum_bytes)
        observed = get_limit(category)
    except sqlite3.Error as error:
        raise ReportSourceError(
            "unable to establish the SQLite source row-size limit"
        ) from error
    if type(observed) is not int or observed <= 0 or observed > maximum_bytes:
        raise ReportSourceError("SQLite did not establish the source row-size limit")


def _schema_rows(connection: sqlite3.Connection, table: str) -> dict[str, sqlite3.Row]:
    return {
        row["name"]: row
        for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    }


def _validate_schema(connection: sqlite3.Connection) -> None:
    table_rows = connection.execute(
        "SELECT name, type FROM sqlite_schema WHERE name IN (?, ?) ORDER BY name",
        tuple(sorted(_REQUIRED_SCHEMA)),
    ).fetchall()
    observed_types = {row["name"]: row["type"] for row in table_rows}
    if observed_types != {name: "table" for name in _REQUIRED_SCHEMA}:
        raise ReportSourceError("required report sources must be real SQLite tables")

    for table, required_columns in _REQUIRED_SCHEMA.items():
        observed_columns = _schema_rows(connection, table)
        for column, (declared_type, primary_key) in required_columns.items():
            row = observed_columns.get(column)
            if row is None:
                raise ReportSourceError(f"{table}.{column} is required")
            if str(row["type"]).strip().upper() != declared_type:
                raise ReportSourceError(
                    f"{table}.{column} must declare type {declared_type}"
                )
            if int(row["pk"]) != primary_key:
                raise ReportSourceError(
                    f"{table}.{column} has an incompatible key contract"
                )


def _bounded_count(
    connection: sqlite3.Connection,
    table: str,
    maximum: int,
    label: str,
) -> int:
    value = connection.execute(
        f'SELECT COUNT(*) FROM (SELECT 1 FROM "{table}" LIMIT ?)',
        (maximum + 1,),
    ).fetchone()[0]
    if type(value) is not int or value < 0:
        raise ReportSourceError(f"{label} count is not a non-negative integer")
    if value > maximum:
        raise ReportLimitError(f"{label} count exceeds the configured limit")
    return value


def _read_plate_rows(
    connection: sqlite3.Connection,
    expected_count: int,
) -> tuple[_SourcePlate, ...]:
    rows = connection.execute(
        """
        SELECT
            id,
            typeof(is_blacklisted) AS blacklist_storage_class,
            CASE
                WHEN typeof(is_blacklisted) IN ('null', 'integer')
                THEN is_blacklisted
                ELSE NULL
            END AS is_blacklisted
        FROM plates
        ORDER BY id
        """
    ).fetchall()
    if len(rows) != expected_count:
        raise ReportSourceError("plate rows changed inside the read snapshot")

    results: list[_SourcePlate] = []
    identifiers: set[int] = set()
    for row in rows:
        identifier = row["id"]
        if type(identifier) is not int or identifier <= 0 or identifier in identifiers:
            raise ReportSourceError("plate ids must be unique positive integers")
        identifiers.add(identifier)
        storage_class = row["blacklist_storage_class"]
        raw_flag = row["is_blacklisted"]
        if storage_class == "null" and raw_flag is None:
            blacklisted = False
        elif (
            storage_class == "integer"
            and type(raw_flag) is int
            and raw_flag in (0, 1)
        ):
            blacklisted = bool(raw_flag)
        else:
            raise ReportSourceError("blacklist flags must be NULL, 0, or 1")
        results.append(_SourcePlate(identifier, blacklisted))
    return tuple(results)


def _validated_confidence(value: object) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float):
        raise ReportSourceError("detection confidence must be numeric or NULL")
    confidence = float(value)
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 100.0:
        raise ReportSourceError("detection confidence must be finite and within 0..100")
    return 0.0 if confidence == 0.0 else confidence


def _read_detection_rows(
    connection: sqlite3.Connection,
    expected_count: int,
    plate_ids: frozenset[int],
) -> tuple[_SourceDetection, ...]:
    rows = connection.execute(
        """
        SELECT
            id,
            typeof(plate_id) AS plate_id_storage_class,
            CASE
                WHEN typeof(plate_id) = 'integer' THEN plate_id
                ELSE NULL
            END AS plate_id,
            typeof(confidence) AS confidence_storage_class,
            CASE
                WHEN typeof(confidence) IN ('null', 'integer', 'real')
                THEN confidence
                ELSE NULL
            END AS confidence
        FROM plate_detections
        ORDER BY id
        """
    ).fetchall()
    if len(rows) != expected_count:
        raise ReportSourceError("detection rows changed inside the read snapshot")

    results: list[_SourceDetection] = []
    identifiers: set[int] = set()
    for row in rows:
        identifier = row["id"]
        plate_id = row["plate_id"]
        if type(identifier) is not int or identifier <= 0 or identifier in identifiers:
            raise ReportSourceError("detection ids must be unique positive integers")
        if (
            row["plate_id_storage_class"] != "integer"
            or type(plate_id) is not int
            or plate_id not in plate_ids
        ):
            raise ReportSourceError("every detection must reference a snapshot plate")
        confidence_storage_class = row["confidence_storage_class"]
        if confidence_storage_class not in {"null", "integer", "real"}:
            raise ReportSourceError(
                "detection confidence must use a numeric or NULL SQLite value"
            )
        identifiers.add(identifier)
        results.append(
            _SourceDetection(
                database_id=identifier,
                plate_id=plate_id,
                confidence=_validated_confidence(row["confidence"]),
            )
        )
    return tuple(results)


def _read_snapshot(
    database_path: Path,
    limits: ExportLimits,
) -> tuple[tuple[_SourcePlate, ...], tuple[_SourceDetection, ...]]:
    uri = database_path.as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(
            uri,
            uri=True,
            isolation_level=None,
            timeout=2.0,
        )
    except sqlite3.Error as error:
        raise ReportSourceError("unable to open the report database read-only") from error

    connection.row_factory = sqlite3.Row
    try:
        _establish_sqlite_length_limit(
            connection,
            limits.max_sqlite_row_bytes,
        )
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA temp_store = MEMORY")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ReportSourceError("SQLite query-only mode was not established")
        connection.execute("BEGIN")
        _validate_schema(connection)
        connection.set_authorizer(_authorizer)
        plate_count = _bounded_count(
            connection,
            "plates",
            limits.max_plates,
            "plate",
        )
        detection_count = _bounded_count(
            connection,
            "plate_detections",
            limits.max_detections,
            "detection",
        )
        plates = _read_plate_rows(connection, plate_count)
        detections = _read_detection_rows(
            connection,
            detection_count,
            frozenset(plate.database_id for plate in plates),
        )
        connection.execute("ROLLBACK")
        return plates, detections
    except ReportExportError:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except sqlite3.Error as error:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise ReportSourceError("unable to read a coherent report snapshot") from error
    finally:
        connection.close()


def _confidence_band(confidence: float | None) -> str:
    if confidence is None:
        return "unscored"
    for label, lower, upper in _CONFIDENCE_BANDS[1:]:
        if lower is not None and upper is not None and lower <= confidence < upper:
            return label
    raise AssertionError("validated confidence did not match a band")


def _round_confidence(value: float | None) -> float | None:
    return None if value is None else round(value, 1)


def _build_public_snapshot(
    plates: Sequence[_SourcePlate],
    detections: Sequence[_SourceDetection],
) -> _PublicSnapshot:
    by_plate: dict[int, list[float]] = {
        plate.database_id: [] for plate in plates
    }
    observation_counts = {plate.database_id: 0 for plate in plates}
    all_scores: list[float] = []
    band_counts = {label: 0 for label, _lower, _upper in _CONFIDENCE_BANDS}

    for detection in detections:
        observation_counts[detection.plate_id] += 1
        band_counts[_confidence_band(detection.confidence)] += 1
        if detection.confidence is not None:
            by_plate[detection.plate_id].append(detection.confidence)
            all_scores.append(detection.confidence)

    aggregates: list[tuple[int, float | None, float | None, bool]] = []
    for plate in plates:
        scores = by_plate[plate.database_id]
        average = math.fsum(scores) / len(scores) if scores else None
        peak = max(scores) if scores else None
        aggregates.append(
            (
                observation_counts[plate.database_id],
                _round_confidence(average),
                _round_confidence(peak),
                plate.blacklisted,
            )
        )

    aggregates.sort(
        key=lambda value: (
            -value[0],
            -int(value[3]),
            value[1] is None,
            -(value[1] if value[1] is not None else -1.0),
            -(value[2] if value[2] is not None else -1.0),
        )
    )
    public_plates = tuple(
        _PublicPlate(
            record_ref=f"Record {index:03d}",
            observation_count=aggregate[0],
            average_confidence=aggregate[1],
            peak_confidence=aggregate[2],
            review_flagged=aggregate[3],
        )
        for index, aggregate in enumerate(aggregates, start=1)
    )
    overall_average = (
        math.fsum(all_scores) / len(all_scores) if all_scores else None
    )
    return _PublicSnapshot(
        plates=public_plates,
        observation_count=len(detections),
        scored_observation_count=len(all_scores),
        average_confidence=_round_confidence(overall_average),
        blacklisted_count=sum(plate.blacklisted for plate in plates),
        confidence_bands=tuple(
            (label, band_counts[label])
            for label, _lower, _upper in _CONFIDENCE_BANDS
        ),
    )


def _summary(snapshot: _PublicSnapshot) -> dict[str, object]:
    return {
        "average_confidence_pct": snapshot.average_confidence,
        "blacklisted_records": snapshot.blacklisted_count,
        "confidence_bands": [
            {"count": count, "label": label}
            for label, count in snapshot.confidence_bands
        ],
        "observation_records": snapshot.observation_count,
        "plate_records": len(snapshot.plates),
        "scored_observations": snapshot.scored_observation_count,
    }


def _public_records(snapshot: _PublicSnapshot) -> list[dict[str, object]]:
    return [
        {
            "average_confidence_pct": plate.average_confidence,
            "observation_records": plate.observation_count,
            "peak_confidence_pct": plate.peak_confidence,
            "record_ref": plate.record_ref,
            "review_flagged": plate.review_flagged,
        }
        for plate in snapshot.plates
    ]


def _format_confidence(value: float | None) -> str:
    return "Not available" if value is None else f"{value:.1f}%"


def _render_summary_svg(snapshot: _PublicSnapshot) -> bytes:
    total = max(snapshot.observation_count, 1)
    bars: list[str] = []
    start_y = 330
    for index, (label, count) in enumerate(snapshot.confidence_bands):
        y = start_y + index * 54
        width = round(590 * count / total, 2)
        bars.append(
            f'  <text x="76" y="{y + 19}" fill="#cbd5e1" font-size="16" '
            f'font-family="Arial,sans-serif">{html.escape(label)}</text>\n'
            f'  <rect x="238" y="{y}" width="590" height="28" rx="14" '
            'fill="#16263b"/>\n'
            f'  <rect x="238" y="{y}" width="{width}" height="28" rx="14" '
            'fill="#38bdf8"/>\n'
            f'  <text x="850" y="{y + 20}" fill="#f8fafc" font-size="16" '
            f'font-weight="700" font-family="Arial,sans-serif">{count}</text>'
        )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="650" viewBox="0 0 1200 650" role="img" aria-labelledby="title desc">
  <title id="title">CorporateHub redacted offline report summary</title>
  <desc id="desc">Source-generated chart of {len(snapshot.plates)} redacted plate records and {snapshot.observation_count} observed detection rows. No identifiers, paths, timestamps, or images are included.</desc>
  <rect width="1200" height="650" rx="28" fill="#07111f"/>
  <text x="60" y="78" fill="#f8fafc" font-size="36" font-weight="700" font-family="Arial,sans-serif">Redacted offline snapshot</text>
  <text x="60" y="116" fill="#94a3b8" font-size="18" font-family="Arial,sans-serif">Read-only SQLite transaction · no application or native runtime</text>
  <rect x="60" y="154" width="250" height="116" rx="18" fill="#102238" stroke="#27415f"/>
  <text x="84" y="194" fill="#94a3b8" font-size="15" font-weight="700" font-family="Arial,sans-serif">PLATE RECORDS</text>
  <text x="84" y="246" fill="#f8fafc" font-size="40" font-weight="700" font-family="Arial,sans-serif">{len(snapshot.plates)}</text>
  <rect x="330" y="154" width="250" height="116" rx="18" fill="#102238" stroke="#27415f"/>
  <text x="354" y="194" fill="#94a3b8" font-size="15" font-weight="700" font-family="Arial,sans-serif">OBSERVATION ROWS</text>
  <text x="354" y="246" fill="#f8fafc" font-size="40" font-weight="700" font-family="Arial,sans-serif">{snapshot.observation_count}</text>
  <rect x="600" y="154" width="250" height="116" rx="18" fill="#102238" stroke="#27415f"/>
  <text x="624" y="194" fill="#94a3b8" font-size="15" font-weight="700" font-family="Arial,sans-serif">REVIEW-FLAGGED</text>
  <text x="624" y="246" fill="#fb7185" font-size="40" font-weight="700" font-family="Arial,sans-serif">{snapshot.blacklisted_count}</text>
  <rect x="870" y="154" width="270" height="116" rx="18" fill="#102238" stroke="#27415f"/>
  <text x="894" y="194" fill="#94a3b8" font-size="15" font-weight="700" font-family="Arial,sans-serif">AVG. CONFIDENCE</text>
  <text x="894" y="246" fill="#67e8f9" font-size="36" font-weight="700" font-family="Arial,sans-serif">{html.escape(_format_confidence(snapshot.average_confidence))}</text>
  <text x="60" y="316" fill="#7dd3fc" font-size="17" font-weight="700" font-family="Arial,sans-serif">OBSERVED CONFIDENCE DISTRIBUTION</text>
{chr(10).join(bars)}
  <rect x="920" y="330" width="220" height="220" rx="22" fill="#172033" stroke="#475569"/>
  <text x="948" y="374" fill="#a7f3d0" font-size="15" font-weight="700" font-family="Arial,sans-serif">PRIVACY BOUNDARY</text>
  <text x="948" y="416" fill="#f8fafc" font-size="17" font-family="Arial,sans-serif">Identifiers omitted</text>
  <text x="948" y="450" fill="#f8fafc" font-size="17" font-family="Arial,sans-serif">Exact times omitted</text>
  <text x="948" y="484" fill="#f8fafc" font-size="17" font-family="Arial,sans-serif">Images omitted</text>
  <text x="948" y="518" fill="#f8fafc" font-size="17" font-family="Arial,sans-serif">Network disabled</text>
  <text x="60" y="618" fill="#94a3b8" font-size="15" font-family="Arial,sans-serif">Redacted does not mean anonymous · review the bundle before sharing</text>
</svg>
'''
    return svg.encode("utf-8")


def _render_html(snapshot: _PublicSnapshot, asset_path: str) -> bytes:
    record_rows = []
    for plate in snapshot.plates:
        status_class = "flagged" if plate.review_flagged else "clear"
        status_text = "Review flagged" if plate.review_flagged else "No review flag"
        record_rows.append(
            "<tr>"
            f"<th scope=\"row\">{html.escape(plate.record_ref, quote=True)}</th>"
            f"<td>{plate.observation_count}</td>"
            f"<td>{html.escape(_format_confidence(plate.average_confidence))}</td>"
            f"<td>{html.escape(_format_confidence(plate.peak_confidence))}</td>"
            f"<td><span class=\"status {status_class}\">{status_text}</span></td>"
            "</tr>"
        )
    if not record_rows:
        record_rows.append(
            '<tr><td colspan="5" class="empty">No plate records in this snapshot.</td></tr>'
        )

    band_rows = "".join(
        "<li>"
        f"<span>{html.escape(label)}</span>"
        f"<strong>{count}</strong>"
        "</li>"
        for label, count in snapshot.confidence_bands
    )
    warning_items = "".join(
        f"<li>{html.escape(warning, quote=True)}</li>" for warning in _STATIC_WARNINGS
    )
    csp = html.escape(CONTENT_SECURITY_POLICY, quote=True)
    html_content = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="{csp}">
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CorporateHub redacted offline report</title>
  <style>
    :root {{ color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; color: #e5eefb; background: #07111f; line-height: 1.5; }}
    main {{ width: min(1120px, calc(100% - 32px)); margin: 0 auto; padding: 42px 0 64px; }}
    header {{ display: grid; gap: 12px; margin-bottom: 28px; }}
    .eyebrow {{ color: #67e8f9; font-size: .78rem; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }}
    h1 {{ margin: 0; color: #f8fafc; font-size: clamp(2rem, 5vw, 3.6rem); letter-spacing: -.04em; }}
    .lede {{ max-width: 760px; margin: 0; color: #a9b8cd; font-size: 1.05rem; }}
    .boundary {{ padding: 18px 20px; border: 1px solid #31537c; border-radius: 16px; background: #0d1c30; }}
    .boundary strong {{ color: #a7f3d0; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin: 26px 0; }}
    .card {{ min-height: 126px; padding: 20px; border: 1px solid #263e5c; border-radius: 18px; background: #102238; }}
    .card span {{ display: block; color: #94a3b8; font-size: .78rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }}
    .card strong {{ display: block; margin-top: 14px; color: #f8fafc; font-size: 2rem; }}
    .visual {{ margin: 28px 0; padding: 14px; border: 1px solid #263e5c; border-radius: 22px; background: #0b192b; }}
    .visual img {{ display: block; width: 100%; height: auto; border-radius: 14px; }}
    section, details {{ margin-top: 24px; padding: 24px; border: 1px solid #263e5c; border-radius: 18px; background: #0b192b; }}
    h2 {{ margin: 0 0 14px; color: #f8fafc; font-size: 1.35rem; }}
    .bands {{ display: grid; gap: 8px; padding: 0; list-style: none; }}
    .bands li {{ display: flex; justify-content: space-between; padding: 10px 12px; border-radius: 10px; background: #102238; }}
    .bands span {{ color: #b8c6d9; }}
    .bands strong {{ color: #67e8f9; }}
    summary {{ cursor: pointer; color: #f8fafc; font-size: 1.2rem; font-weight: 750; }}
    .table-wrap {{ overflow-x: auto; margin-top: 18px; }}
    table {{ width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #203650; text-align: left; white-space: nowrap; }}
    thead th {{ color: #94a3b8; font-size: .75rem; letter-spacing: .06em; text-transform: uppercase; }}
    tbody th {{ color: #f8fafc; }}
    td {{ color: #c7d3e3; }}
    .status {{ display: inline-block; padding: 4px 9px; border-radius: 999px; font-size: .8rem; font-weight: 750; }}
    .status.flagged {{ color: #fecdd3; background: #4c1d2f; }}
    .status.clear {{ color: #a7f3d0; background: #123c35; }}
    .empty {{ color: #94a3b8; text-align: center; }}
    .warnings {{ color: #c7d3e3; }}
    footer {{ margin-top: 28px; color: #7f91aa; font-size: .85rem; }}
    @media print {{ body {{ color: #111827; background: white; }} main {{ width: 100%; padding: 0; }} .card, section, details, .visual, .boundary {{ border-color: #cbd5e1; background: white; }} h1, h2, summary, .card strong, tbody th {{ color: #111827; }} }}
  </style>
</head>
<body>
<main data-report-schema="{PUBLIC_MODEL_SCHEMA}" data-privacy-mode="{PRIVACY_MODE}" data-plate-records="{len(snapshot.plates)}" data-observation-records="{snapshot.observation_count}" data-blacklisted-records="{snapshot.blacklisted_count}" data-scored-observations="{snapshot.scored_observation_count}">
  <header>
    <span class="eyebrow">CorporateHub · source-owned export boundary</span>
    <h1>Redacted offline report</h1>
    <p class="lede">A static report generated from one coherent read-only SQLite transaction. It contains observed aggregate records, not a camera, recognition, or deduplicated-event claim.</p>
  </header>
  <div class="boundary"><strong>Privacy mode: redacted-v1.</strong> Raw identifiers, exact times, profiles, source names, reasons, filesystem paths, and source images were not selected for export. Review aggregate attributes before sharing.</div>
  <div class="stats" aria-label="Snapshot summary">
    <div class="card"><span>Plate records</span><strong>{len(snapshot.plates)}</strong></div>
    <div class="card"><span>Observation rows</span><strong>{snapshot.observation_count}</strong></div>
    <div class="card"><span>Review flagged</span><strong>{snapshot.blacklisted_count}</strong></div>
    <div class="card"><span>Average confidence</span><strong>{html.escape(_format_confidence(snapshot.average_confidence))}</strong></div>
  </div>
  <figure class="visual">
    <img src="{asset_path}" alt="Source-generated chart of the redacted snapshot summary and confidence distribution">
  </figure>
  <section>
    <h2>Confidence observations</h2>
    <ul class="bands">{band_rows}</ul>
  </section>
  <details open>
    <summary>Redacted record detail</summary>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Record</th><th>Observations</th><th>Average confidence</th><th>Peak confidence</th><th>Review state</th></tr></thead>
        <tbody>{''.join(record_rows)}</tbody>
      </table>
    </div>
  </details>
  <section>
    <h2>Interpretation limits</h2>
    <ul class="warnings">{warning_items}</ul>
  </section>
  <footer>Bundle schema {BUNDLE_SCHEMA} · template {TEMPLATE_VERSION} · analysis {ANALYSIS_VERSION} · manifest stored as {MANIFEST_NAME}</footer>
</main>
</body>
</html>
'''
    return html_content.encode("utf-8")


def _inventory_record(path: str, content: bytes, media_type: str, role: str) -> dict[str, object]:
    return {
        "bytes": len(content),
        "media_type": media_type,
        "path": path,
        "role": role,
        "sha256": _sha256(content),
    }


def _report_id(
    summary: Mapping[str, object],
    records: Sequence[Mapping[str, object]],
    inventory: Sequence[Mapping[str, object]],
) -> str:
    descriptor = {
        "artifact": BUNDLE_SCHEMA,
        "files": list(inventory),
        "privacy_mode": PRIVACY_MODE,
        "records": list(records),
        "summary": dict(summary),
    }
    return _sha256(_canonical_json(descriptor, pretty=False))


def _manifest(
    report_id: str,
    summary: Mapping[str, object],
    records: Sequence[Mapping[str, object]],
    inventory: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "analysis": {
            "confidence_version": ANALYSIS_VERSION,
            "observation_semantics": "stored plate_detections rows; no deduplication claim",
            "similarity_analysis_included": False,
            "template_version": TEMPLATE_VERSION,
            "timestamp_fields_included": False,
        },
        "artifact": BUNDLE_SCHEMA,
        "files": list(inventory),
        "privacy": {
            "database_path_serialized": False,
            "images": "omitted",
            "mode": PRIVACY_MODE,
            "raw_text_fields": "omitted",
            "shareability": "review-required",
        },
        "records": list(records),
        "report_id": report_id,
        "runtime": {
            "application_started": False,
            "database_access": "single read-only SQLite transaction",
            "network_required": False,
            "scripts_included": False,
            "vendor_runtime_loaded": False,
        },
        "summary": dict(summary),
    }


def _render_bundle(snapshot: _PublicSnapshot, limits: ExportLimits) -> _RenderedBundle:
    summary_svg = _render_summary_svg(snapshot)
    if len(summary_svg) > limits.max_svg_bytes:
        raise ReportLimitError("rendered SVG exceeds the configured limit")
    asset_digest = _sha256(summary_svg)
    asset_path = f"assets/{asset_digest}.svg"
    index_html = _render_html(snapshot, asset_path)
    if len(index_html) > limits.max_html_bytes:
        raise ReportLimitError("rendered HTML exceeds the configured limit")

    inventory = sorted(
        (
            _inventory_record(
                INDEX_NAME,
                index_html,
                "text/html; charset=utf-8",
                "offline-report",
            ),
            _inventory_record(
                asset_path,
                summary_svg,
                "image/svg+xml",
                "generated-summary",
            ),
        ),
        key=lambda record: str(record["path"]),
    )
    summary = _summary(snapshot)
    records = _public_records(snapshot)
    report_id = _report_id(summary, records, inventory)
    manifest_bytes = _canonical_json(
        _manifest(report_id, summary, records, inventory),
        pretty=True,
    )
    if len(manifest_bytes) > limits.max_manifest_bytes:
        raise ReportLimitError("rendered manifest exceeds the configured limit")
    return _RenderedBundle(
        report_id=report_id,
        files={
            INDEX_NAME: index_html,
            MANIFEST_NAME: manifest_bytes,
            asset_path: summary_svg,
        },
    )


def _safe_relative_path(value: object) -> str:
    if type(value) is not str or not value:
        raise ReportVerificationError("manifest paths must be non-empty text")
    if "\\" in value or any(ord(character) < 32 for character in value):
        raise ReportVerificationError("manifest paths contain forbidden characters")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in ("", ".", "..") for part in path.parts
    ):
        raise ReportVerificationError("manifest paths must be canonical and relative")
    return value


def _decode_json_strict(
    content: bytes,
    *,
    maximum_structural_tokens: int = 164_096,
    maximum_depth: int = 16,
) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReportVerificationError("manifest contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ReportVerificationError(f"manifest contains non-finite value: {value}")

    structural_tokens = 0
    stack: list[int] = []
    in_string = False
    escaped = False
    matching = {ord("}"): ord("{"), ord("]"): ord("[")}
    for byte in content:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
            continue
        if byte in (ord("{"), ord("[")):
            structural_tokens += 1
            stack.append(byte)
            if len(stack) > maximum_depth:
                raise ReportVerificationError("manifest nesting exceeds the limit")
        elif byte in matching:
            structural_tokens += 1
            if not stack or stack.pop() != matching[byte]:
                raise ReportVerificationError("manifest delimiters are malformed")
        elif byte in (ord(","), ord(":")):
            structural_tokens += 1
        if structural_tokens > maximum_structural_tokens:
            raise ReportVerificationError("manifest structural complexity exceeds the limit")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReportVerificationError("manifest is not canonical UTF-8 JSON") from error

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
        _canonical_json(parsed, pretty=True)
        return parsed
    except ReportVerificationError:
        raise
    except (
        UnicodeEncodeError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ) as error:
        raise ReportVerificationError("manifest is not canonical UTF-8 JSON") from error


class _OfflineHtmlAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.csp_values: list[str] = []
        self.referrers: list[str] = []
        self.urls: list[tuple[str, str, str]] = []
        self.main_metadata: list[dict[str, str | None]] = []
        self.errors: list[str] = []
        self.styles: list[str] = []
        self._style_parts: list[str] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if self.errors:
            return
        lowered_tag = tag.casefold()
        attribute_names = [name.casefold() for name, _value in attrs]
        attribute_map = {
            name.casefold(): value for name, value in attrs
        }
        allowed_attributes = _ALLOWED_HTML_ATTRIBUTES.get(lowered_tag)
        if allowed_attributes is None or lowered_tag in _ACTIVE_HTML_ELEMENTS:
            self.errors.append(f"unapproved HTML element: {lowered_tag}")
            return
        if len(attribute_names) != len(set(attribute_names)):
            self.errors.append(f"duplicate attribute on {lowered_tag}")
            return
        unexpected_attributes = set(attribute_names) - allowed_attributes
        if unexpected_attributes:
            self.errors.append(
                f"unapproved attribute on {lowered_tag}: "
                f"{sorted(unexpected_attributes)[0]}"
            )
            return
        for name, value in attrs:
            lowered_name = name.casefold()
            if lowered_name.startswith("on"):
                self.errors.append(f"event attribute: {lowered_name}")
                return
            if lowered_name in _URL_BEARING_HTML_ATTRIBUTES:
                if self.urls:
                    self.errors.append("index.html contains multiple URL attributes")
                    return
                self.urls.append((lowered_tag, lowered_name, value or ""))
        if lowered_tag == "meta":
            http_equiv = (attribute_map.get("http-equiv") or "").casefold()
            name = (attribute_map.get("name") or "").casefold()
            if "charset" in attribute_map:
                if attribute_map != {"charset": "utf-8"}:
                    self.errors.append("unexpected charset metadata")
            elif http_equiv:
                if (
                    http_equiv != "content-security-policy"
                    or set(attribute_map) != {"content", "http-equiv"}
                ):
                    self.errors.append("unapproved http-equiv metadata")
                else:
                    if self.csp_values:
                        self.errors.append("index.html contains multiple CSP values")
                        return
                    self.csp_values.append(attribute_map.get("content") or "")
            elif name == "referrer":
                if set(attribute_map) != {"content", "name"}:
                    self.errors.append("malformed referrer metadata")
                    return
                if self.referrers:
                    self.errors.append("index.html contains multiple referrer policies")
                    return
                self.referrers.append(attribute_map.get("content") or "")
            elif name == "viewport":
                if attribute_map != {
                    "content": "width=device-width, initial-scale=1",
                    "name": "viewport",
                }:
                    self.errors.append("unexpected viewport metadata")
            else:
                self.errors.append("unapproved metadata")
        if lowered_tag == "main":
            if self.main_metadata:
                self.errors.append("index.html contains multiple report roots")
                return
            self.main_metadata.append(attribute_map)
        if lowered_tag in {"style", "img"} and not self.csp_values:
            self.errors.append("resource appears before the CSP")
        if lowered_tag == "style":
            if self._style_parts is not None or self.styles:
                self.errors.append("duplicate or nested style element")
                return
            self._style_parts = []

    def handle_endtag(self, tag: str) -> None:
        if self.errors:
            return
        if tag.casefold() == "style":
            if self._style_parts is None:
                self.errors.append("unmatched style element")
                return
            self.styles.append("".join(self._style_parts))
            self._style_parts = None

    def handle_data(self, data: str) -> None:
        if not self.errors and self._style_parts is not None:
            self._style_parts.append(data)


def _validate_html(content: bytes, asset_path: str, summary: Mapping[str, object]) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReportVerificationError("index.html is not UTF-8") from error
    parser = _OfflineHtmlAudit()
    parser.feed(text)
    parser.close()
    if parser.errors:
        raise ReportVerificationError(parser.errors[0])
    if parser.csp_values != [CONTENT_SECURITY_POLICY]:
        raise ReportVerificationError("index.html has an unexpected CSP")
    if parser.referrers != ["no-referrer"]:
        raise ReportVerificationError("index.html must disable referrers")
    if len(parser.styles) != 1 or _sha256(parser.styles[0].encode("utf-8")) != (
        _REPORT_STYLE_SHA256
    ):
        raise ReportVerificationError("index.html stylesheet is not source-bound")
    if parser.urls != [("img", "src", asset_path)]:
        raise ReportVerificationError("index.html references an unexpected URL")
    lowered = text.casefold()
    for marker in ("url(", "@import", "javascript:", "data:", "http:", "https:", "file:"):
        if marker in lowered:
            raise ReportVerificationError(f"index.html contains forbidden content: {marker}")
    if len(parser.main_metadata) != 1:
        raise ReportVerificationError("index.html must contain one report root")
    metadata = parser.main_metadata[0]
    expected_metadata = {
        "data-report-schema": PUBLIC_MODEL_SCHEMA,
        "data-privacy-mode": PRIVACY_MODE,
        "data-plate-records": str(summary["plate_records"]),
        "data-observation-records": str(summary["observation_records"]),
        "data-blacklisted-records": str(summary["blacklisted_records"]),
        "data-scored-observations": str(summary["scored_observations"]),
    }
    for name, value in expected_metadata.items():
        if metadata.get(name) != value:
            raise ReportVerificationError("index.html summary metadata is stale")


def _validate_svg(content: bytes) -> None:
    lowered_content = content.lower()
    if b"<?" in lowered_content or b"<!" in lowered_content:
        raise ReportVerificationError("summary SVG contains XML directives")
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        raise ReportVerificationError("summary SVG is not well-formed") from error
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        raise ReportVerificationError("summary asset must be SVG")
    if root.attrib.get("role") != "img":
        raise ReportVerificationError("summary SVG must expose an image role")
    labelled_by = root.attrib.get("aria-labelledby", "").split()
    identifiers = {
        node.attrib["id"] for node in root.iter() if "id" in node.attrib
    }
    if len(labelled_by) != 2 or not set(labelled_by).issubset(identifiers):
        raise ReportVerificationError("summary SVG needs title and description labels")
    for node in root.iter():
        if not isinstance(node.tag, str) or not node.tag.startswith(
            "{http://www.w3.org/2000/svg}"
        ):
            raise ReportVerificationError("summary SVG uses a foreign namespace")
        local_name = node.tag.rsplit("}", maxsplit=1)[-1].casefold()
        allowed_attributes = _ALLOWED_SVG_ATTRIBUTES.get(local_name)
        if allowed_attributes is None:
            raise ReportVerificationError(
                "summary SVG contains active content or an unapproved element"
            )
        if set(node.attrib) - allowed_attributes:
            raise ReportVerificationError("summary SVG contains an unapproved attribute")
        for attribute, value in node.attrib.items():
            lowered_attribute = attribute.casefold()
            lowered_value = value.casefold()
            if lowered_attribute.startswith("on") or "href" in lowered_attribute:
                raise ReportVerificationError("summary SVG contains an active attribute")
            if "url(" in lowered_value or "://" in lowered_value:
                raise ReportVerificationError("summary SVG references external content")


def _canonical_public_confidence(value: object, label: str) -> float | None:
    if value is None:
        return None
    if (
        type(value) is not float
        or not math.isfinite(value)
        or not 0.0 <= value <= 100.0
        or value != round(value, 1)
        or (value == 0.0 and math.copysign(1.0, value) < 0.0)
    ):
        raise ReportVerificationError(f"{label} is not a canonical confidence")
    return value


def _validate_summary(
    value: object,
    limits: ExportLimits,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ReportVerificationError("manifest summary must be an object")
    expected_keys = {
        "average_confidence_pct",
        "blacklisted_records",
        "confidence_bands",
        "observation_records",
        "plate_records",
        "scored_observations",
    }
    if set(value) != expected_keys:
        raise ReportVerificationError("manifest summary has an unexpected shape")
    for key in (
        "blacklisted_records",
        "observation_records",
        "plate_records",
        "scored_observations",
    ):
        if type(value[key]) is not int or value[key] < 0:
            raise ReportVerificationError("manifest counts must be non-negative integers")
    if value["blacklisted_records"] > value["plate_records"]:
        raise ReportVerificationError("blacklisted count exceeds plate count")
    if value["scored_observations"] > value["observation_records"]:
        raise ReportVerificationError("scored count exceeds observation count")
    if value["plate_records"] == 0 and value["observation_records"] != 0:
        raise ReportVerificationError("observations require at least one plate record")
    if value["plate_records"] > limits.max_plates:
        raise ReportLimitError("bundle plate count exceeds the configured limit")
    if value["observation_records"] > limits.max_detections:
        raise ReportLimitError("bundle observation count exceeds the configured limit")
    average = _canonical_public_confidence(
        value["average_confidence_pct"],
        "manifest average confidence",
    )
    if (value["scored_observations"] == 0) != (average is None):
        raise ReportVerificationError("manifest average and scored count disagree")
    bands = value["confidence_bands"]
    if type(bands) is not list or len(bands) != len(_CONFIDENCE_BANDS):
        raise ReportVerificationError("manifest confidence bands are invalid")
    expected_labels = [label for label, _lower, _upper in _CONFIDENCE_BANDS]
    observed_labels: list[str] = []
    band_total = 0
    for band in bands:
        if type(band) is not dict or set(band) != {"count", "label"}:
            raise ReportVerificationError("manifest confidence band is malformed")
        if type(band["label"]) is not str or type(band["count"]) is not int:
            raise ReportVerificationError("manifest confidence band types are invalid")
        if band["count"] < 0:
            raise ReportVerificationError("manifest confidence band count is negative")
        observed_labels.append(band["label"])
        band_total += band["count"]
    unscored = bands[0]["count"]
    if (
        observed_labels != expected_labels
        or band_total != value["observation_records"]
        or unscored != value["observation_records"] - value["scored_observations"]
    ):
        raise ReportVerificationError("manifest confidence bands are stale")
    return value


def _validate_public_records(
    value: object,
    summary: Mapping[str, object],
    limits: ExportLimits,
) -> tuple[_PublicPlate, ...]:
    if type(value) is not list:
        raise ReportVerificationError("manifest public records must be a list")
    expected_count = int(summary["plate_records"])
    if len(value) != expected_count:
        raise ReportVerificationError("manifest public record count is stale")
    if len(value) > limits.max_plates:
        raise ReportLimitError("bundle public record count exceeds the configured limit")

    expected_keys = {
        "average_confidence_pct",
        "observation_records",
        "peak_confidence_pct",
        "record_ref",
        "review_flagged",
    }
    records: list[_PublicPlate] = []
    observation_total = 0
    flagged_total = 0
    scored_record_capacity = 0
    scored_record_count = 0
    for index, record in enumerate(value, start=1):
        if type(record) is not dict or set(record) != expected_keys:
            raise ReportVerificationError("manifest public record is malformed")
        expected_ref = f"Record {index:03d}"
        if record["record_ref"] != expected_ref:
            raise ReportVerificationError("manifest public records are not canonical")
        observations = record["observation_records"]
        if type(observations) is not int or observations < 0:
            raise ReportVerificationError(
                "manifest record observations must be a non-negative integer"
            )
        review_flagged = record["review_flagged"]
        if type(review_flagged) is not bool:
            raise ReportVerificationError("manifest review flag must be boolean")
        average = _canonical_public_confidence(
            record["average_confidence_pct"],
            "manifest record average confidence",
        )
        peak = _canonical_public_confidence(
            record["peak_confidence_pct"],
            "manifest record peak confidence",
        )
        if (average is None) != (peak is None):
            raise ReportVerificationError(
                "manifest record confidence fields disagree"
            )
        if observations == 0 and average is not None:
            raise ReportVerificationError(
                "manifest empty record cannot contain confidence"
            )
        if average is not None and peak is not None and average > peak:
            raise ReportVerificationError(
                "manifest record average exceeds peak confidence"
            )
        if average is not None:
            scored_record_count += 1
            scored_record_capacity += observations
        records.append(
            _PublicPlate(
                record_ref=expected_ref,
                observation_count=observations,
                average_confidence=average,
                peak_confidence=peak,
                review_flagged=review_flagged,
            )
        )
        observation_total += observations
        flagged_total += int(review_flagged)

    if observation_total != summary["observation_records"]:
        raise ReportVerificationError("manifest record observations are stale")
    if flagged_total != summary["blacklisted_records"]:
        raise ReportVerificationError("manifest record review flags are stale")
    scored_observations = int(summary["scored_observations"])
    if not scored_record_count <= scored_observations <= scored_record_capacity:
        raise ReportVerificationError("manifest record scored counts are stale")
    numeric_averages = [
        record.average_confidence
        for record in records
        if record.average_confidence is not None
    ]
    overall_average = summary["average_confidence_pct"]
    if numeric_averages and overall_average is not None:
        if not (
            min(numeric_averages) - 0.1
            <= float(overall_average)
            <= max(numeric_averages) + 0.1
        ):
            raise ReportVerificationError("manifest record averages are stale")
    canonical_order = sorted(
        records,
        key=lambda record: (
            -record.observation_count,
            -int(record.review_flagged),
            record.average_confidence is None,
            -(
                record.average_confidence
                if record.average_confidence is not None
                else -1.0
            ),
            -(
                record.peak_confidence
                if record.peak_confidence is not None
                else -1.0
            ),
        ),
    )
    if records != canonical_order:
        raise ReportVerificationError("manifest public record order is stale")
    return tuple(records)


def _actual_bundle_paths(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()

    def entries(directory: Path, maximum: int) -> list[tuple[str, os.stat_result]]:
        result: list[tuple[str, os.stat_result]] = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                result.append((entry.name, entry.stat(follow_symlinks=False)))
                if len(result) > maximum:
                    raise ReportVerificationError(
                        "bundle contains missing or unexpected paths"
                    )
        return result

    for name, metadata in entries(root, 3):
        if stat.S_ISREG(metadata.st_mode):
            files.add(name)
        elif stat.S_ISDIR(metadata.st_mode):
            directories.add(name)
        else:
            raise ReportVerificationError("bundle contains a non-regular file")
    assets = root / "assets"
    if "assets" in directories:
        for name, metadata in entries(assets, 1):
            if not stat.S_ISREG(metadata.st_mode):
                raise ReportVerificationError("bundle contains a non-regular file")
            files.add(f"assets/{name}")
    return files, directories


def _read_bounded_regular_file(
    path: Path,
    maximum_bytes: int,
    label: str,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReportVerificationError(f"unable to open {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReportVerificationError(f"{label} must be a regular file")
        if before.st_size > maximum_bytes:
            raise ReportLimitError(f"{label} exceeds the configured limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(content) > maximum_bytes:
            raise ReportLimitError(f"{label} exceeds the configured limit")
        if before.st_size != len(content) or after.st_size != len(content):
            raise ReportVerificationError(f"{label} changed while it was read")
        return content
    finally:
        os.close(descriptor)


def verify_report_bundle(
    bundle_root: str | os.PathLike[str],
    *,
    limits: ExportLimits = ExportLimits(),
) -> ExportResult:
    """Verify every byte and offline invariant in a published report bundle."""

    if type(limits) is not ExportLimits:
        raise TypeError("limits must be an ExportLimits value")
    root = _existing_plain_directory(bundle_root)
    if not root.name.startswith(BUNDLE_PREFIX):
        raise ReportVerificationError("bundle directory name has an invalid prefix")
    directory_report_id = root.name.removeprefix(BUNDLE_PREFIX)
    if not REPORT_ID_PATTERN.fullmatch(directory_report_id):
        raise ReportVerificationError("bundle directory name has an invalid report id")

    manifest_path = root / MANIFEST_NAME
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as error:
        raise ReportVerificationError("bundle manifest is missing") from error
    if not stat.S_ISREG(manifest_metadata.st_mode):
        raise ReportVerificationError("bundle manifest must be a regular file")
    if manifest_metadata.st_size > limits.max_manifest_bytes:
        raise ReportLimitError("bundle manifest exceeds the configured limit")
    manifest_bytes = _read_bounded_regular_file(
        manifest_path,
        limits.max_manifest_bytes,
        "bundle manifest",
    )
    manifest = _decode_json_strict(
        manifest_bytes,
        maximum_structural_tokens=16 * limits.max_plates + 4_096,
    )
    if type(manifest) is not dict:
        raise ReportVerificationError("bundle manifest must be a JSON object")
    if manifest_bytes != _canonical_json(manifest, pretty=True):
        raise ReportVerificationError("bundle manifest is not canonical")
    expected_manifest_keys = {
        "analysis",
        "artifact",
        "files",
        "privacy",
        "records",
        "report_id",
        "runtime",
        "summary",
    }
    if set(manifest) != expected_manifest_keys or manifest["artifact"] != BUNDLE_SCHEMA:
        raise ReportVerificationError("bundle manifest schema is invalid")
    if manifest["report_id"] != directory_report_id:
        raise ReportVerificationError("manifest and directory report ids differ")
    if manifest["privacy"] != {
        "database_path_serialized": False,
        "images": "omitted",
        "mode": PRIVACY_MODE,
        "raw_text_fields": "omitted",
        "shareability": "review-required",
    }:
        raise ReportVerificationError("bundle privacy contract is invalid")
    if manifest["runtime"] != {
        "application_started": False,
        "database_access": "single read-only SQLite transaction",
        "network_required": False,
        "scripts_included": False,
        "vendor_runtime_loaded": False,
    }:
        raise ReportVerificationError("bundle runtime contract is invalid")
    if manifest["analysis"] != {
        "confidence_version": ANALYSIS_VERSION,
        "observation_semantics": "stored plate_detections rows; no deduplication claim",
        "similarity_analysis_included": False,
        "template_version": TEMPLATE_VERSION,
        "timestamp_fields_included": False,
    }:
        raise ReportVerificationError("bundle analysis contract is invalid")
    summary = _validate_summary(manifest["summary"], limits)
    public_plates = _validate_public_records(
        manifest["records"],
        summary,
        limits,
    )
    public_snapshot = _PublicSnapshot(
        plates=public_plates,
        observation_count=int(summary["observation_records"]),
        scored_observation_count=int(summary["scored_observations"]),
        average_confidence=(
            None
            if summary["average_confidence_pct"] is None
            else float(summary["average_confidence_pct"])
        ),
        blacklisted_count=int(summary["blacklisted_records"]),
        confidence_bands=tuple(
            (str(band["label"]), int(band["count"]))
            for band in summary["confidence_bands"]
        ),
    )

    inventory = manifest["files"]
    if type(inventory) is not list or len(inventory) != 2:
        raise ReportVerificationError("bundle must inventory exactly two public files")
    normalized_inventory: list[dict[str, object]] = []
    observed_paths: set[str] = set()
    for record in inventory:
        if type(record) is not dict or set(record) != {
            "bytes",
            "media_type",
            "path",
            "role",
            "sha256",
        }:
            raise ReportVerificationError("bundle inventory record is malformed")
        path = _safe_relative_path(record["path"])
        if path in observed_paths:
            raise ReportVerificationError("bundle inventory paths must be unique")
        observed_paths.add(path)
        if type(record["bytes"]) is not int or record["bytes"] < 0:
            raise ReportVerificationError("bundle inventory size is invalid")
        if type(record["sha256"]) is not str or not REPORT_ID_PATTERN.fullmatch(
            record["sha256"]
        ):
            raise ReportVerificationError("bundle inventory digest is invalid")
        if type(record["media_type"]) is not str or type(record["role"]) is not str:
            raise ReportVerificationError("bundle inventory labels are invalid")
        normalized_inventory.append(record)
    if normalized_inventory != sorted(
        normalized_inventory,
        key=lambda record: str(record["path"]),
    ):
        raise ReportVerificationError("bundle inventory must be sorted")

    html_records = [record for record in inventory if record["path"] == INDEX_NAME]
    asset_records = [
        record
        for record in inventory
        if isinstance(record["path"], str)
        and ASSET_PATH_PATTERN.fullmatch(record["path"])
    ]
    if len(html_records) != 1 or len(asset_records) != 1:
        raise ReportVerificationError("bundle inventory roles are incomplete")
    html_record = html_records[0]
    asset_record = asset_records[0]
    if (
        html_record["media_type"] != "text/html; charset=utf-8"
        or html_record["role"] != "offline-report"
        or asset_record["media_type"] != "image/svg+xml"
        or asset_record["role"] != "generated-summary"
    ):
        raise ReportVerificationError("bundle inventory media contract is invalid")
    if PurePosixPath(str(asset_record["path"])).stem != asset_record["sha256"]:
        raise ReportVerificationError("summary asset path is not content-addressed")

    actual_files, actual_directories = _actual_bundle_paths(root)
    expected_files = observed_paths | {MANIFEST_NAME}
    if actual_files != expected_files or actual_directories != {"assets"}:
        raise ReportVerificationError("bundle contains missing or unexpected paths")

    content_by_path: dict[str, bytes] = {}
    for record in inventory:
        target = root.joinpath(*PurePosixPath(str(record["path"])).parts)
        maximum_bytes = (
            limits.max_html_bytes
            if record["path"] == INDEX_NAME
            else limits.max_svg_bytes
        )
        if record["bytes"] > maximum_bytes:
            raise ReportLimitError("bundle file exceeds the configured limit")
        content = _read_bounded_regular_file(
            target,
            maximum_bytes,
            f"bundle file {record['path']}",
        )
        if len(content) != record["bytes"] or _sha256(content) != record["sha256"]:
            raise ReportVerificationError("bundle file bytes differ from the manifest")
        content_by_path[str(record["path"])] = content
    expected_html = _render_html(public_snapshot, str(asset_record["path"]))
    if content_by_path[INDEX_NAME] != expected_html:
        raise ReportVerificationError("index.html is not source-derived")
    _validate_html(
        content_by_path[INDEX_NAME],
        str(asset_record["path"]),
        summary,
    )
    asset_content = content_by_path[str(asset_record["path"])]
    expected_svg = _render_summary_svg(public_snapshot)
    if asset_content != expected_svg:
        raise ReportVerificationError("summary SVG is not source-derived")
    _validate_svg(asset_content)

    expected_report_id = _report_id(summary, manifest["records"], inventory)
    if expected_report_id != directory_report_id:
        raise ReportVerificationError("bundle report id is stale")
    return ExportResult(
        bundle_root=root,
        index_path=root / INDEX_NAME,
        manifest_path=manifest_path,
        report_id=directory_report_id,
        plate_count=int(summary["plate_records"]),
        detection_count=int(summary["observation_records"]),
    )


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> bool:
    """Sync a directory, returning False only for documented unsupported cases."""

    if not hasattr(os, "O_DIRECTORY"):
        return False
    unsupported_errors = {
        code
        for code in (
            getattr(errno, "EINVAL", None),
            getattr(errno, "ENOTSUP", None),
            getattr(errno, "EOPNOTSUPP", None),
        )
        if code is not None
    }
    flags = os.O_RDONLY
    flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in unsupported_errors:
            return False
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno in unsupported_errors:
                return False
            raise
        return True
    finally:
        os.close(descriptor)


def _publish_bundle(
    rendered: _RenderedBundle,
    output_parent: Path,
    limits: ExportLimits,
) -> ExportResult:
    final_root = output_parent / f"{BUNDLE_PREFIX}{rendered.report_id}"
    if os.path.lexists(final_root):
        return verify_report_bundle(final_root, limits=limits)

    stage_container = Path(
        tempfile.mkdtemp(prefix=".corporatehub-report-stage-", dir=output_parent)
    )
    staged_bundle = stage_container / final_root.name
    published = False
    try:
        os.chmod(stage_container, 0o700)
        staged_bundle.mkdir(mode=0o700)
        (staged_bundle / "assets").mkdir(mode=0o700)
        for relative_path, content in sorted(rendered.files.items()):
            target = staged_bundle.joinpath(*PurePosixPath(relative_path).parts)
            _write_exclusive(target, content)
        _fsync_directory(staged_bundle / "assets")
        _fsync_directory(staged_bundle)
        staged_result = verify_report_bundle(staged_bundle, limits=limits)
        if os.path.lexists(final_root):
            raise ReportPublishError("report bundle appeared during publication")
        os.rename(staged_bundle, final_root)
        published = True
        try:
            stage_container.rmdir()
        except OSError:
            try:
                shutil.rmtree(stage_container)
            except OSError:
                pass
        durability_warning = None
        try:
            _fsync_directory(output_parent)
        except OSError:
            # The verified directory entry already exists.  Surface a fixed,
            # path-private warning instead of claiming the publication failed.
            durability_warning = (
                "the bundle was published, but output-directory durability "
                "could not be confirmed"
            )
        return ExportResult(
            bundle_root=final_root,
            index_path=final_root / INDEX_NAME,
            manifest_path=final_root / MANIFEST_NAME,
            report_id=staged_result.report_id,
            plate_count=staged_result.plate_count,
            detection_count=staged_result.detection_count,
            durability_warning=durability_warning,
        )
    except BaseException as error:
        if not published and stage_container.exists():
            try:
                shutil.rmtree(stage_container)
            except OSError as cleanup_error:
                add_note = getattr(error, "add_note", None)
                if callable(add_note):
                    add_note(f"staging cleanup also failed: {cleanup_error}")
        raise


def export_offline_report(
    database_path: str | os.PathLike[str],
    output_parent: str | os.PathLike[str],
    *,
    limits: ExportLimits = ExportLimits(),
) -> ExportResult:
    """Publish or reuse an immutable redacted report bundle.

    The source database is opened with ``mode=ro`` and ``query_only``.  The
    output parent must already exist and must not traverse symlinks.  Existing
    bundles are never overwritten; an exact bundle is verified and reused.
    """

    if type(limits) is not ExportLimits:
        raise TypeError("limits must be an ExportLimits value")
    source = _existing_plain_file(database_path)
    destination = _existing_plain_directory(output_parent)
    plates, detections = _read_snapshot(source, limits)
    public_snapshot = _build_public_snapshot(plates, detections)
    rendered = _render_bundle(public_snapshot, limits)
    return _publish_bundle(rendered, destination, limits)


def _print_result(result: ExportResult) -> None:
    print("CorporateHub offline report bundle v1")
    print(f"privacy              {PRIVACY_MODE}")
    print(f"plate records        {result.plate_count}")
    print(f"observation records  {result.detection_count}")
    print(f"report id            {result.report_id}")
    print(f"bundle               {result.bundle_root.name}")
    if result.durability_warning is not None:
        print(f"warning              {result.durability_warning}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export or verify a redacted, offline CorporateHub report bundle."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    export_parser = subparsers.add_parser("export", help="export a read-only snapshot")
    export_parser.add_argument("--database", required=True)
    export_parser.add_argument("--output-parent", required=True)
    verify_parser = subparsers.add_parser("verify", help="verify an existing bundle")
    verify_parser.add_argument("bundle")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "export":
            result = export_offline_report(
                arguments.database,
                arguments.output_parent,
            )
        else:
            result = verify_report_bundle(arguments.bundle)
    except (ReportExportError, OSError) as error:
        print(f"report export refused: {error}", file=sys.stderr)
        return 2
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
