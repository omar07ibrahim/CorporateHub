"""Unit tests for the standard-library-only filesystem path policy."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from urllib.parse import unquote, urlsplit

from path_policy import (
    MAX_COMPONENT_LENGTH,
    PathPolicyError,
    local_file_uri,
    managed_path,
    safe_path_component,
)

ROOT = Path(__file__).resolve().parents[1]


class SafePathComponentTests(unittest.TestCase):
    def test_common_ascii_plate_components_are_unchanged(self) -> None:
        for value in ("ABC123", "AB-1234", "LV_42"):
            with self.subTest(value=value):
                self.assertEqual(value, safe_path_component(value))

    def test_generated_suffix_namespace_cannot_be_claimed_by_raw_ascii(self) -> None:
        unsafe_value = "AB/123"
        generated = safe_path_component(unsafe_value)
        crafted_raw_value = generated

        self.assertRegex(generated, r"--[0-9a-f]{20}\Z")
        self.assertNotEqual(generated, safe_path_component(crafted_raw_value))
        self.assertNotEqual(
            generated.casefold(),
            safe_path_component(crafted_raw_value.upper()).casefold(),
        )
        reserved_uppercase = "ABC123--" + "A" * 20
        self.assertNotEqual(
            reserved_uppercase,
            safe_path_component(reserved_uppercase),
        )

    def test_ascii_case_variants_do_not_collide_after_casefold(self) -> None:
        variants = ("ABC123", "abc123", "AbC123")
        components = [safe_path_component(value) for value in variants]

        self.assertEqual(
            len(components),
            len({value.casefold() for value in components}),
        )
        self.assertEqual("ABC123", components[0])
        self.assertTrue(all("--" in component for component in components[1:]))

    def test_traversal_dots_controls_and_shell_characters_are_removed(self) -> None:
        unsafe_values = (
            "../outside",
            ".",
            "..",
            "ABC.DEF",
            "ABC\n123",
            "ABC\x00123",
            "ABC\x85123",
            "ABC\u2028123",
            "ABC\u202e123",
            'ABC"; touch marker; #',
            "ABC$(touch marker)",
            r"ABC\..\outside",
            "\ud800",
        )
        for value in unsafe_values:
            with self.subTest(value=repr(value)):
                component = safe_path_component(value)
                self.assertRegex(component, r"\A[A-Za-z0-9_-]+\Z")
                self.assertNotIn(".", component)
                self.assertNotIn("/", component)
                self.assertNotIn("\\", component)
                self.assertLessEqual(len(component), MAX_COMPONENT_LENGTH)

    def test_unicode_is_ascii_bounded_and_stable(self) -> None:
        value = "ÅВ１２３🚗"
        first = safe_path_component(value)
        second = safe_path_component(value)

        self.assertEqual(first, second)
        self.assertTrue(first.isascii())
        self.assertRegex(first, r"\A[A-Za-z0-9_-]+\Z")
        self.assertLessEqual(len(first), MAX_COMPONENT_LENGTH)

    def test_unsafe_values_with_same_readable_stem_keep_distinct_digests(self) -> None:
        components = {
            safe_path_component("AB/123"),
            safe_path_component(r"AB\123"),
            safe_path_component("AB:123"),
            safe_path_component("AB 123"),
        }
        self.assertEqual(4, len(components))

    def test_long_common_prefixes_keep_stable_distinct_digests(self) -> None:
        first_value = "A" * 500 + "X"
        second_value = "A" * 500 + "Y"

        first = safe_path_component(first_value)
        second = safe_path_component(second_value)

        self.assertEqual(first, safe_path_component(first_value))
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), MAX_COMPONENT_LENGTH)
        self.assertLessEqual(len(second), MAX_COMPONENT_LENGTH)

    def test_empty_reserved_and_long_values_are_bounded(self) -> None:
        for value in ("", "CON", "NUL", "A" * 500):
            with self.subTest(value=value[:20]):
                component = safe_path_component(value)
                self.assertTrue(component)
                self.assertLessEqual(len(component), MAX_COMPONENT_LENGTH)
                self.assertNotIn(component.upper(), {"CON", "NUL"})

    def test_non_text_values_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            safe_path_component(None)  # type: ignore[arg-type]


class ManagedPathTests(unittest.TestCase):
    def test_managed_paths_are_absolute_and_contained(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            project_root = Path(temporary_directory)
            result = managed_path(
                "detection_history",
                "ABC123",
                "ABC123_plate_1.jpg",
                project_root=project_root,
            )

            self.assertTrue(result.is_absolute())
            self.assertTrue(result.is_relative_to(project_root.resolve()))
            self.assertEqual(
                Path("detection_history/ABC123/ABC123_plate_1.jpg"),
                result.relative_to(project_root.resolve()),
            )

    def test_unmanaged_and_traversal_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            project_root = Path(temporary_directory)
            invalid_requests = (
                ("exports", ("report.html",)),
                ("images", ("..", "outside.jpg")),
                ("images", ("nested/outside.jpg",)),
                ("images", (r"nested\outside.jpg",)),
                ("images", ("\n",)),
            )
            for directory, components in invalid_requests:
                with self.subTest(directory=directory, components=components):
                    with self.assertRaises(PathPolicyError):
                        managed_path(
                            directory,
                            *components,
                            project_root=project_root,
                        )

    def test_existing_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as project_directory:
            with tempfile.TemporaryDirectory(dir=ROOT) as outside_directory:
                project_root = Path(project_directory)
                images = project_root / "images"
                images.mkdir()
                try:
                    (images / "escape").symlink_to(
                        Path(outside_directory),
                        target_is_directory=True,
                    )
                except OSError as error:
                    self.skipTest(f"directory symlinks unavailable: {error}")

                with self.assertRaises(PathPolicyError):
                    managed_path(
                        "images",
                        "escape",
                        "outside.jpg",
                        project_root=project_root,
                    )

    def test_managed_root_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as project_directory:
            with tempfile.TemporaryDirectory(dir=ROOT) as outside_directory:
                project_root = Path(project_directory)
                try:
                    (project_root / "images").symlink_to(
                        Path(outside_directory),
                        target_is_directory=True,
                    )
                except OSError as error:
                    self.skipTest(f"directory symlinks unavailable: {error}")

                with self.assertRaises(PathPolicyError):
                    managed_path(
                        "images",
                        "outside.jpg",
                        project_root=project_root,
                    )

    def test_existing_leaf_file_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as project_directory:
            with tempfile.TemporaryDirectory(dir=ROOT) as outside_directory:
                project_root = Path(project_directory)
                images = project_root / "images"
                images.mkdir()
                outside_file = Path(outside_directory) / "outside.jpg"
                outside_file.touch()
                try:
                    (images / "plate.jpg").symlink_to(outside_file)
                except OSError as error:
                    self.skipTest(f"file symlinks unavailable: {error}")

                with self.assertRaises(PathPolicyError):
                    managed_path(
                        "images",
                        "plate.jpg",
                        project_root=project_root,
                    )


class LocalFileUriTests(unittest.TestCase):
    def test_uri_percent_encodes_spaces_quotes_hash_and_unicode(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary_directory:
            path = Path(temporary_directory) / """report '"Q3" # Å;$(x).html"""
            uri = local_file_uri(path)
            parsed = urlsplit(uri)

            self.assertEqual("file", parsed.scheme)
            self.assertNotIn(" ", uri)
            self.assertNotIn('"', uri)
            self.assertIn("%20", uri)
            self.assertIn("%27", uri)
            self.assertIn("%22", uri)
            self.assertIn("%23", uri)
            self.assertIn("%C3%85", uri)
            self.assertIn("%3B", uri)
            self.assertIn("%24", uri)
            self.assertIn("%28", uri)
            self.assertIn("%29", uri)
            self.assertEqual(str(path.resolve()), unquote(parsed.path))

    def test_nul_and_bytes_paths_are_rejected(self) -> None:
        with self.assertRaises(PathPolicyError):
            local_file_uri("unsafe\x00path")
        with self.assertRaises(TypeError):
            local_file_uri(b"report.html")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
