"""Source-only public-baseline checks.

These tests deliberately do not import any project or vendor module.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
NOTICE = ROOT / "THIRD_PARTY_NOTICES.md"
README = ROOT / "README.md"

WRAPPER_HASHES = {
    "DTKLPR5.py": "115e5696effab17f0e9ea8584656260cfeffc7dc5badad75f0d6c87dfef2e810",
    "DTKVID.py": "c89903b7c5a2119c1084db08146a06146703606f8282498895b0161af0eb0125",
}
RUNTIME_DIRECTORIES = frozenset(
    {
        "blacklist_matches",
        "camera",
        "captures",
        "detection_history",
        "exports",
        "images",
        "logs",
        "recordings",
        "report_exports",
        "report_images",
        "reports",
        "videos",
    }
)
RUNTIME_SUFFIXES = frozenset(
    {
        ".avi",
        ".db",
        ".db-journal",
        ".db-shm",
        ".db-wal",
        ".dll",
        ".dylib",
        ".exe",
        ".flv",
        ".log",
        ".mkv",
        ".mov",
        ".mp4",
        ".mpeg",
        ".pyd",
        ".so",
        ".sqlite",
        ".sqlite-journal",
        ".sqlite-shm",
        ".sqlite-wal",
        ".sqlite3",
        ".sqlite3-journal",
        ".sqlite3-shm",
        ".sqlite3-wal",
        ".wmv",
    }
)
REQUIRED_IGNORE_PATTERNS = frozenset(
    {
        "__pycache__/",
        "*.py[cod]",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".coverage",
        "htmlcov/",
        ".env",
        ".env.*",
        "!.env.example",
        ".venv/",
        "venv/",
        *(f"/{directory}/" for directory in RUNTIME_DIRECTORIES),
        *(f"*{suffix}" for suffix in RUNTIME_SUFFIXES),
    }
)


def secret_signatures() -> dict[str, re.Pattern[str]]:
    """Return the bounded high-confidence patterns used for public files."""
    return {
        "private key": re.compile(
            "-----BEGIN "
            + r"(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?"
            + "PRIVATE KEY-----"
        ),
        "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "GitHub token": re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
        ),
        "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "credential in URL": re.compile(r"\b(?:https?|rtsp)://[^/\s:@]+:[^@/\s]+@"),
        "assigned secret": re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|
                secret[_-]?access[_-]?key|access[_-]?token|password)
            \s*[:=]\s*["'][^"'\r\n]{8,}["']
            """
        ),
    }


def repository_candidates() -> tuple[Path, ...]:
    """Return tracked files plus untracked, non-ignored commit candidates."""
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    relative_paths = result.stdout.decode("utf-8").split("\0")
    return tuple(ROOT / path for path in relative_paths if path)


def imported_roots(filename: str) -> set[str]:
    """Return direct top-level import roots without importing the module."""
    tree = ast.parse((ROOT / filename).read_bytes(), filename=filename)
    result: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.add(node.module.split(".", maxsplit=1)[0])
    return result


class PublicBaselineTests(unittest.TestCase):
    def test_all_repository_python_parses_without_importing(self) -> None:
        python_files = tuple(
            path for path in repository_candidates() if path.suffix == ".py"
        )
        self.assertTrue(python_files)
        for path in python_files:
            with self.subTest(path=path.relative_to(ROOT)):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_password_gate_is_absent_from_entry_point(self) -> None:
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename="main.py")
        entry_point = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        entry_calls = {
            node.func.attr
            for node in ast.walk(entry_point)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        entry_text = ast.get_source_segment(source, entry_point)

        self.assertNotIn("askstring", entry_calls)
        self.assertNotIn("askinteger", entry_calls)
        self.assertNotIn("askfloat", entry_calls)
        self.assertIn("Tk", entry_calls)
        self.assertIn("mainloop", entry_calls)
        forbidden_gate_nodes = (ast.Compare, ast.If, ast.IfExp)
        self.assertFalse(
            any(isinstance(node, forbidden_gate_nodes) for node in ast.walk(entry_point))
        )
        self.assertIsNotNone(entry_text)
        self.assertNotIn("password", entry_text.casefold())

    def test_gitignore_covers_known_runtime_artifacts(self) -> None:
        ignore_lines = {
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(set(), REQUIRED_IGNORE_PATTERNS - ignore_lines)

    def test_no_runtime_data_is_a_commit_candidate(self) -> None:
        offenders: list[str] = []
        for path in repository_candidates():
            relative = path.relative_to(ROOT)
            relative_text = relative.as_posix().casefold()
            top_level = relative.parts[0].casefold() if relative.parts else ""
            if top_level in RUNTIME_DIRECTORIES:
                offenders.append(relative.as_posix())
            elif any(relative_text.endswith(suffix) for suffix in RUNTIME_SUFFIXES):
                offenders.append(relative.as_posix())
        self.assertEqual([], offenders)

    def test_wrapper_hashes_are_bound_to_notices(self) -> None:
        notice = NOTICE.read_text(encoding="utf-8")
        notice_rows = {
            cells[0]: cells
            for line in notice.splitlines()
            if len(cells := [cell.strip() for cell in line.split("|")[1:-1]]) == 3
            and cells[0].startswith("`")
        }
        self.assertEqual({f"`{filename}`" for filename in WRAPPER_HASHES}, set(notice_rows))
        for filename, expected_hash in WRAPPER_HASHES.items():
            with self.subTest(filename=filename):
                actual_hash = hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
                self.assertEqual(expected_hash, actual_hash)
                self.assertEqual(f"`{expected_hash}`", notice_rows[f"`{filename}`"][2])

        self.assertIn("Copyright (c) DTK Software", notice)
        self.assertIn("No native DTK", notice)
        self.assertIn("does not grant a license", notice)
        self.assertFalse((ROOT / "LICENSE").exists())

    def test_readme_states_evidence_and_nonclaims(self) -> None:
        readme = README.read_text(encoding="utf-8")
        normalized_readme = " ".join(readme.split())
        required_statements = {
            "Static architecture map — not runtime evidence",
            "no authentication or authorization",
            "No performance, security, accuracy, or production-readiness claim is made.",
            "does not currently grant an open-source license",
            "The application has not been executed in this stage",
            "There is no dependency manifest or lock file",
            "Known RTSP breakage",
            "Do not treat RTSP as a working feature.",
            "python3 -m unittest discover -s tests -v",
        }
        for statement in required_statements:
            with self.subTest(statement=statement):
                self.assertIn(statement, normalized_readme)

        prohibited_claims = {
            "production-ready",
            "secure by default",
            "high performance",
            "real-time performance",
            "fully tested",
            "open source project",
            "MIT License",
            "Apache License",
        }
        for claim in prohibited_claims:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, readme)

    def test_static_architecture_edges_are_bound_to_direct_imports(self) -> None:
        readme = README.read_text(encoding="utf-8")
        bindings = (
            ("main.py", "database", "GUI --> DB"),
            ("main.py", "processing_manager", 'GUI --> Manager["VideoProcessingManager'),
            ("processing_manager.py", "database", "Manager --> DB"),
            ("processing_manager.py", "video_processor", 'Manager --> Processor["VideoProcessor'),
            ("video_processor.py", "DTKLPR5", "Processor --> LPRWrapper"),
            ("video_processor.py", "DTKVID", "Processor --> VIDWrapper"),
            ("video_processor.py", "database", "Processor --> DB"),
            ("video_processor.py", "PIL", "Processor -. imports .-> Pillow"),
            ("video_processor.py", "cv2", "Processor -. imports .-> OpenCV"),
            ("video_processor.py", "Levenshtein", "Processor -. imports .-> Levenshtein"),
            ("processing_manager.py", "cv2", "Manager -. imports .-> OpenCV"),
            ("database.py", "Levenshtein", "DB -. imports .-> Levenshtein"),
            ("DTKLPR5.py", "PIL", "LPRWrapper -. imports .-> Pillow"),
            ("DTKLPR5.py", "numpy", "LPRWrapper -. imports .-> NumPy"),
            ("DTKVID.py", "PIL", "VIDWrapper -. imports .-> Pillow"),
            ("DTKVID.py", "numpy", "VIDWrapper -. imports .-> NumPy"),
        )
        for filename, imported_root, mermaid_edge in bindings:
            with self.subTest(filename=filename, mermaid_edge=mermaid_edge):
                self.assertIn(imported_root, imported_roots(filename))
                self.assertIn(mermaid_edge, readme)

    def test_high_confidence_secret_signatures_are_absent(self) -> None:
        findings: list[str] = []
        for path in repository_candidates():
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for label, pattern in secret_signatures().items():
                if pattern.search(text):
                    findings.append(f"{path.relative_to(ROOT)}: {label}")
        self.assertEqual([], findings)

    def test_secret_signatures_detect_synthetic_canaries(self) -> None:
        canaries = {
            "private key": (
                "-----BEGIN " + "ENCRYPTED " + "PRIVATE KEY-----",
                "-----BEGIN " + "DSA " + "PRIVATE KEY-----",
            ),
            "AWS access key": ("AKIA" + "A" * 16,),
            "GitHub token": (
                "github_" + "pat_" + "A" * 32,
                "gh" + "p_" + "A" * 40,
            ),
            "Slack token": ("xox" + "b-" + "A" * 24,),
            "credential in URL": (
                "rtsp://" + "user:secret@" + "camera.invalid/live",
            ),
            "assigned secret": (
                "pass" + "word = " + "'synthetic-value'",
                "AWS_" + "SECRET_ACCESS_KEY=" + "'synthetic-value'",
            ),
        }
        signatures = secret_signatures()
        self.assertEqual(set(signatures), set(canaries))
        for label, values in canaries.items():
            for value in values:
                with self.subTest(label=label, value=value):
                    self.assertIsNotNone(signatures[label].search(value))


if __name__ == "__main__":
    unittest.main()
