"""Standard-library-only admission policy for the quarantined RTSP surface.

CorporateHub cannot safely start a live camera in its current public runtime.
The vendor adapter, lifecycle, backpressure, GUI-thread handoff, and secret
channel are all unverified.  This module therefore validates only a narrow
credential-free endpoint shape, immediately discards the endpoint, and returns
non-sensitive public metadata describing an unavailable capability.

The module deliberately does not import the GUI, OpenCV, the database, or the
DTK wrappers.  It is a boundary for future work, not a camera client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
import re
from urllib.parse import unquote_to_bytes, urlsplit


MAX_RTSP_ENDPOINT_BYTES = 2_048
MAX_RTSP_PATH_BYTES = 1_024
RTSP_SOURCE_LABEL = "RTSP source"
RTSP_UNAVAILABLE_CODE = "rtsp-unavailable"
RTSP_UNAVAILABLE_MESSAGE = (
    "RTSP capture is unavailable because the vendor runtime and live-camera "
    "lifecycle have not been verified."
)
RTSP_INVALID_MESSAGE = "The RTSP endpoint was rejected by the local policy."

_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_RTSP_SOURCE_TOKEN = object()


class RtspPolicyError(ValueError):
    """Base class for stable RTSP failures with input-free messages."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RtspInputError(RtspPolicyError):
    """Raised when an endpoint is outside the credential-free input policy."""


class RtspUnavailableError(RtspPolicyError):
    """Raised before any quarantined RTSP capture can be queued or opened."""

    def __init__(self) -> None:
        super().__init__(RTSP_UNAVAILABLE_CODE)


@dataclass(frozen=True, slots=True, init=False)
class RtspSource:
    """Opaque marker returned after an endpoint passes syntax admission.

    The raw endpoint is intentionally not retained.  A future live-camera
    adapter must introduce a dedicated secret-bearing type and lifecycle
    contract instead of recovering an endpoint from this object.
    """

    label: str = field(default=RTSP_SOURCE_LABEL, init=False)
    _admitted: bool = field(default=False, init=False, repr=False)

    def __init__(self, token: object = None) -> None:
        if token is not _RTSP_SOURCE_TOKEN:
            raise TypeError("RtspSource values come from parse_rtsp_source")
        object.__setattr__(self, "label", RTSP_SOURCE_LABEL)
        object.__setattr__(self, "_admitted", True)

    def __str__(self) -> str:
        return self.label

    def public_metadata(self) -> dict[str, str]:
        """Return the complete allowlisted public representation."""

        return {"capability": RTSP_UNAVAILABLE_CODE, "label": self.label}


@dataclass(frozen=True, slots=True)
class RtspAdmission:
    """Public fail-closed decision for a syntactically admitted source."""

    allowed: bool
    code: str
    label: str
    message: str

    def public_metadata(self) -> dict[str, bool | str]:
        """Return deterministic metadata safe for UI, logs, or evidence."""

        return {
            "allowed": self.allowed,
            "code": self.code,
            "label": self.label,
            "message": self.message,
        }


def _reject(code: str) -> None:
    raise RtspInputError(code)


def _validate_hostname(hostname: str) -> None:
    if not hostname or len(hostname) > 253 or hostname.endswith("."):
        _reject("rtsp-host-invalid")

    if ":" in hostname:
        try:
            ip_address(hostname)
        except ValueError:
            _reject("rtsp-host-invalid")
        return

    if hostname.replace(".", "").isdigit():
        try:
            ip_address(hostname)
        except ValueError:
            _reject("rtsp-host-invalid")
        return

    labels = hostname.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        _reject("rtsp-host-invalid")


def _validate_path(path: str) -> None:
    if not path.startswith("/") or path == "/":
        _reject("rtsp-path-required")
    if len(path.encode("ascii")) > MAX_RTSP_PATH_BYTES:
        _reject("rtsp-path-too-long")

    unmatched_percent = _PERCENT_ESCAPE.sub("", path)
    if "%" in unmatched_percent:
        _reject("rtsp-path-escape-invalid")

    try:
        decoded = unquote_to_bytes(path)
    except UnicodeEncodeError:
        _reject("rtsp-path-invalid")
    if any(byte < 32 or byte == 127 for byte in decoded):
        _reject("rtsp-path-control")
    if b"\\" in decoded:
        _reject("rtsp-path-invalid")

    for segment in path.split("/")[1:]:
        decoded_segment = unquote_to_bytes(segment)
        if decoded_segment in {b".", b".."} or b"/" in decoded_segment:
            _reject("rtsp-path-ambiguous")


def parse_rtsp_source(endpoint: str) -> RtspSource:
    """Validate and discard one credential-free RTSP endpoint.

    Only lowercase ``rtsp://host[:port]/path`` endpoints are admitted.
    User information, query strings, fragments, controls, non-ASCII text, and
    ambiguous paths are rejected.  No returned object, exception, or public
    metadata embeds any part of *endpoint*.  Python tracebacks can retain frame
    locals, so callers must not persist tracebacks from sensitive input.
    """

    if type(endpoint) is not str:
        raise TypeError("RTSP endpoints must be text")
    try:
        endpoint_bytes = endpoint.encode("ascii")
    except UnicodeEncodeError:
        _reject("rtsp-endpoint-non-ascii")
    if not endpoint_bytes or len(endpoint_bytes) > MAX_RTSP_ENDPOINT_BYTES:
        _reject("rtsp-endpoint-size")
    if any(byte <= 32 or byte == 127 for byte in endpoint_bytes):
        _reject("rtsp-endpoint-control")
    if "\\" in endpoint:
        _reject("rtsp-endpoint-invalid")

    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        _reject("rtsp-endpoint-invalid")
    if not endpoint.startswith("rtsp://") or parsed.scheme != "rtsp":
        _reject("rtsp-scheme-invalid")
    if not parsed.netloc or parsed.hostname is None:
        _reject("rtsp-host-invalid")
    if (
        "@" in parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        _reject("rtsp-credentials-forbidden")
    if "?" in endpoint or parsed.query:
        _reject("rtsp-query-forbidden")
    if "#" in endpoint or parsed.fragment:
        _reject("rtsp-fragment-forbidden")

    if parsed.netloc.endswith(":"):
        _reject("rtsp-port-invalid")
    try:
        port = parsed.port
    except ValueError:
        _reject("rtsp-port-invalid")
    if port is not None and not 1 <= port <= 65_535:
        _reject("rtsp-port-invalid")

    _validate_hostname(parsed.hostname)
    _validate_path(parsed.path)
    return RtspSource(_RTSP_SOURCE_TOKEN)


def reject_rtsp_transport(video_path: str) -> None:
    """Keep RTSP-shaped values out of the legacy local-file entry point.

    This guard intentionally runs before queue mutation, progress updates,
    OpenCV, endpoint-dependent database writes, or vendor calls.  It does not
    parse a potential endpoint or embed it in an exception message.
    """

    if type(video_path) is not str:
        raise TypeError("video paths must be text")
    prefix_start = 0
    while (
        prefix_start < len(video_path)
        and ord(video_path[prefix_start]) <= 32
    ):
        prefix_start += 1
    transport_prefix = video_path[prefix_start : prefix_start + 6].casefold()
    if transport_prefix.startswith("rtsp:") or transport_prefix == "rtsps:":
        raise RtspUnavailableError


def quarantine_rtsp(source: RtspSource) -> RtspAdmission:
    """Return the only supported public decision without touching runtime I/O."""

    if (
        type(source) is not RtspSource
        or getattr(source, "_admitted", False) is not True
        or source.label != RTSP_SOURCE_LABEL
    ):
        raise TypeError("RTSP admission requires an RtspSource")
    return RtspAdmission(
        allowed=False,
        code=RTSP_UNAVAILABLE_CODE,
        label=source.label,
        message=RTSP_UNAVAILABLE_MESSAGE,
    )


def require_rtsp_available(source: RtspSource) -> None:
    """Fail before endpoint-dependent queue, UI, DB, OpenCV, or vendor work."""

    if (
        type(source) is not RtspSource
        or getattr(source, "_admitted", False) is not True
        or source.label != RTSP_SOURCE_LABEL
    ):
        raise TypeError("RTSP admission requires an RtspSource")
    raise RtspUnavailableError
