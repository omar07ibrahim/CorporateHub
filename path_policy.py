"""Small, standard-library-only policy for project-managed filesystem paths.

The helpers in this module are intentionally independent from the GUI, database,
and native DTK bindings so their behavior can be verified without loading the
application runtime.
"""

from __future__ import annotations

from hashlib import sha256
from os import PathLike, fspath
from pathlib import Path
import re
import unicodedata


PROJECT_ROOT = Path(__file__).resolve().parent
MANAGED_DIRECTORIES = frozenset(
    {
        "blacklist_matches",
        "detection_history",
        "images",
    }
)
MAX_COMPONENT_LENGTH = 80
_DIGEST_LENGTH = 20
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")
_GENERATED_SUFFIX = re.compile(r"--[0-9A-Fa-f]{20}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "AUX",
        "CON",
        "NUL",
        "PRN",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


class PathPolicyError(ValueError):
    """Raised when a requested path is outside a managed filesystem boundary."""


def safe_path_component(value: str) -> str:
    """Return a bounded ASCII filename component derived from untrusted text.

    Common uppercase ASCII plate identifiers containing letters, numbers,
    ``-``, or ``_`` are preserved. Lowercase text and any normalization,
    replacement, reserved-name handling, generated-suffix reservation, or
    truncation append a digest of the original text. This keeps case variants
    and values sharing a sanitized stem distinct on case-insensitive filesystems
    unless their truncated SHA-256 digests collide.
    """

    if not isinstance(value, str):
        raise TypeError("path components must be text")

    normalized = unicodedata.normalize("NFKC", value)
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", normalized)
    cleaned = re.sub(r"_+", "_", cleaned).strip("_-")

    unchanged = (
        bool(value)
        and normalized == value
        and bool(_SAFE_COMPONENT.fullmatch(value))
        and value == value.upper()
        and not _GENERATED_SUFFIX.search(value)
        and value.upper() not in _WINDOWS_RESERVED_NAMES
        and len(value) <= MAX_COMPONENT_LENGTH
    )
    if unchanged:
        return value

    if not cleaned:
        cleaned = "item"
    if cleaned.upper() in _WINDOWS_RESERVED_NAMES:
        cleaned = f"item_{cleaned}"

    digest = sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()[
        :_DIGEST_LENGTH
    ]
    suffix = f"--{digest}"
    stem_length = MAX_COMPONENT_LENGTH - len(suffix)
    stem = cleaned[:stem_length].rstrip("_-") or "item"
    return f"{stem}{suffix}"


def managed_path(
    directory: str,
    *components: str,
    project_root: Path | None = None,
) -> Path:
    """Build an absolute path contained by one approved project directory.

    Existing symlinks are resolved for the containment check. The function does
    not create directories and is not a replacement for operating-system access
    controls or race-resistant directory-descriptor operations.
    """

    if directory not in MANAGED_DIRECTORIES:
        raise PathPolicyError(f"unmanaged directory: {directory!r}")

    for component in components:
        if not isinstance(component, str):
            raise TypeError("managed path components must be text")
        if (
            not component
            or component in {".", ".."}
            or "/" in component
            or "\\" in component
            or any(ord(character) < 32 or ord(character) == 127 for character in component)
        ):
            raise PathPolicyError(f"invalid managed path component: {component!r}")

    boundary = (project_root or PROJECT_ROOT).resolve(strict=False)
    managed_root = boundary / directory
    candidate = managed_root.joinpath(*components)

    resolved_root = managed_root.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    if not resolved_root.is_relative_to(boundary):
        raise PathPolicyError("managed directory resolves outside the project root")
    if not resolved_candidate.is_relative_to(resolved_root):
        raise PathPolicyError("managed path resolves outside its directory")

    return resolved_candidate


def local_file_uri(path: str | PathLike[str]) -> str:
    """Return an encoded absolute ``file:`` URI for a local filesystem path."""

    raw_path = fspath(path)
    if not isinstance(raw_path, str):
        raise TypeError("local file paths must be text")
    if "\x00" in raw_path:
        raise PathPolicyError("local file paths must not contain NUL")
    return Path(raw_path).expanduser().resolve(strict=False).as_uri()
