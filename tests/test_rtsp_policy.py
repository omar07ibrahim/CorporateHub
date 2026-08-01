"""Tests for the standard-library-only, fail-closed RTSP boundary."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import unittest

from rtsp_evidence import rtsp_quarantine_errors
from rtsp_policy import (
    MAX_RTSP_ENDPOINT_BYTES,
    RTSP_INVALID_MESSAGE,
    RTSP_SOURCE_LABEL,
    RTSP_UNAVAILABLE_CODE,
    RTSP_UNAVAILABLE_MESSAGE,
    RtspInputError,
    RtspSource,
    RtspUnavailableError,
    parse_rtsp_source,
    quarantine_rtsp,
    reject_rtsp_transport,
    require_rtsp_available,
)

ROOT = Path(__file__).resolve().parents[1]


class RtspInputPolicyTests(unittest.TestCase):
    def test_credential_free_hostname_ipv4_and_ipv6_shapes_are_admitted(self) -> None:
        endpoints = (
            "rtsp://camera.invalid/live",
            "rtsp://192.0.2.10:8554/channel/1",
            "rtsp://[2001:db8::10]/live/main",
            "rtsp://cam-01.example.test/media%20stream",
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                source = parse_rtsp_source(endpoint)
                self.assertEqual(RTSP_SOURCE_LABEL, str(source))
                self.assertEqual(
                    {
                        "capability": RTSP_UNAVAILABLE_CODE,
                        "label": RTSP_SOURCE_LABEL,
                    },
                    source.public_metadata(),
                )

    def test_ambiguous_or_secret_bearing_endpoints_are_rejected(self) -> None:
        credential_endpoint = "".join(
            ("rtsp://", "alice:", "secret@", "camera.invalid/live")
        )
        cases = {
            "": "rtsp-endpoint-size",
            "rtsp://": "rtsp-host-invalid",
            "RTSP://camera.invalid/live": "rtsp-scheme-invalid",
            "http://camera.invalid/live": "rtsp-scheme-invalid",
            "https://camera.invalid/live": "rtsp-scheme-invalid",
            "file:///camera/live": "rtsp-scheme-invalid",
            "rtsp://camera.invalid": "rtsp-path-required",
            "rtsp://camera.invalid/": "rtsp-path-required",
            "rtsp://camera.invalid:0/live": "rtsp-port-invalid",
            "rtsp://camera.invalid:65536/live": "rtsp-port-invalid",
            "rtsp://camera.invalid:/live": "rtsp-port-invalid",
            "rtsp://[2001:db8::10]:/live": "rtsp-port-invalid",
            "rtsp://camera.invalid:not-a-port/live": "rtsp-port-invalid",
            "rtsp://999.999.999.999/live": "rtsp-host-invalid",
            "rtsp://bad_host.invalid/live": "rtsp-host-invalid",
            "rtsp://camera.invalid/live?token=secret": "rtsp-query-forbidden",
            "rtsp://camera.invalid/live?": "rtsp-query-forbidden",
            "rtsp://camera.invalid/live#camera": "rtsp-fragment-forbidden",
            "rtsp://camera.invalid/live#": "rtsp-fragment-forbidden",
            credential_endpoint: "rtsp-credentials-forbidden",
            "rtsp://camera.invalid/a/../live": "rtsp-path-ambiguous",
            "rtsp://camera.invalid/a/%2e%2e/live": "rtsp-path-ambiguous",
            "rtsp://camera.invalid/a%2Flive": "rtsp-path-ambiguous",
            "rtsp://camera.invalid/live%": "rtsp-path-escape-invalid",
            "rtsp://camera.invalid/live%0A": "rtsp-path-control",
            r"rtsp://camera.invalid/\live": "rtsp-endpoint-invalid",
            "rtsp://camera.invalid/ливestream": "rtsp-endpoint-non-ascii",
            "rtsp://camera.invalid/live\nsecret": "rtsp-endpoint-control",
            "rtsp://camera.invalid/live\tsecret": "rtsp-endpoint-control",
            "rtsp://camera.invalid/live\x00secret": "rtsp-endpoint-control",
            "rtsp://camera.invalid/" + "a" * 1_025: "rtsp-path-too-long",
            "rtsp://camera.invalid/" + "a" * MAX_RTSP_ENDPOINT_BYTES: (
                "rtsp-endpoint-size"
            ),
        }
        for endpoint, expected_code in cases.items():
            with self.subTest(endpoint=repr(endpoint)):
                with self.assertRaises(RtspInputError) as caught:
                    parse_rtsp_source(endpoint)
                self.assertEqual(expected_code, caught.exception.code)
                self.assertEqual(expected_code, str(caught.exception))
                self.assertEqual((expected_code,), caught.exception.args)
                if endpoint:
                    for surface in (
                        str(caught.exception),
                        repr(caught.exception),
                        repr(caught.exception.args),
                    ):
                        self.assertNotIn(endpoint, surface)

    def test_non_text_and_subclassed_inputs_are_rejected(self) -> None:
        class Endpoint(str):
            pass

        for endpoint in (None, b"rtsp://camera.invalid/live", Endpoint("x")):
            with self.subTest(type=type(endpoint).__name__):
                with self.assertRaises(TypeError):
                    parse_rtsp_source(endpoint)  # type: ignore[arg-type]

        with self.assertRaises(TypeError):
            RtspSource()

    def test_rtsp_shapes_cannot_enter_the_local_video_path(self) -> None:
        secret = "very-secret-value"
        candidates = (
            f"rtsp://camera.invalid/{secret}",
            "RTSP://camera.invalid/live",
            "  rtsp://camera.invalid/live",
            "\x00rTsPs://camera.invalid/live",
            "\x7fRTSP://camera.invalid/live",
            "RTSPS://camera.invalid/live",
            "rtsp:opaque-camera-reference",
        )
        for candidate in candidates:
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaises(RtspUnavailableError) as caught:
                    reject_rtsp_transport(candidate)
                for surface in (
                    str(caught.exception),
                    repr(caught.exception),
                    repr(caught.exception.args),
                ):
                    self.assertNotIn(secret, surface)

        self.assertIsNone(reject_rtsp_transport("/data/camera-01.mp4"))

        class VideoPath(str):
            pass

        for value in (None, b"camera.mp4", VideoPath("camera.mp4")):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(TypeError):
                    reject_rtsp_transport(value)  # type: ignore[arg-type]


class RtspQuarantineTests(unittest.TestCase):
    def test_admitted_endpoint_is_discarded_from_every_public_surface(self) -> None:
        secret = "very-secret-value"
        endpoint = f"rtsp://camera.invalid/{secret}"
        source = parse_rtsp_source(endpoint)
        admission = quarantine_rtsp(source)

        surfaces = (
            str(source),
            repr(source),
            repr(asdict(source)),
            repr(source.public_metadata()),
            str(admission),
            repr(admission),
            repr(asdict(admission)),
            repr(admission.public_metadata()),
            RTSP_INVALID_MESSAGE,
            RTSP_UNAVAILABLE_MESSAGE,
        )
        for surface in surfaces:
            with self.subTest(surface=surface):
                self.assertNotIn(secret, surface)
                self.assertNotIn("camera.invalid", surface)

        self.assertFalse(admission.allowed)
        self.assertEqual(RTSP_UNAVAILABLE_CODE, admission.code)
        self.assertEqual(RTSP_SOURCE_LABEL, admission.label)
        self.assertEqual(RTSP_UNAVAILABLE_MESSAGE, admission.message)

    def test_runtime_gate_always_raises_fixed_unavailable_error(self) -> None:
        source = parse_rtsp_source("rtsp://camera.invalid/live")
        with self.assertRaises(RtspUnavailableError) as caught:
            require_rtsp_available(source)
        self.assertEqual(RTSP_UNAVAILABLE_CODE, caught.exception.code)
        self.assertEqual(RTSP_UNAVAILABLE_CODE, str(caught.exception))

    def test_forged_or_subclassed_sources_fail_before_admission(self) -> None:
        class SourceSubclass(RtspSource):
            pass

        subclass = object.__new__(SourceSubclass)
        object.__setattr__(subclass, "label", RTSP_SOURCE_LABEL)
        object.__setattr__(subclass, "_admitted", True)
        forged = object.__new__(RtspSource)
        object.__setattr__(forged, "label", "secret-label")

        for source in (subclass, forged, object()):
            with self.subTest(type=type(source).__name__):
                with self.assertRaises(TypeError):
                    quarantine_rtsp(source)  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    require_rtsp_available(source)  # type: ignore[arg-type]


class RtspSourceBindingTests(unittest.TestCase):
    def test_gui_and_manager_deny_before_any_sensitive_or_runtime_flow(self) -> None:
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        manager_source = (ROOT / "processing_manager.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual((), rtsp_quarantine_errors(main_source, manager_source))

    def test_quarantine_verifier_rejects_dead_calls_and_raw_display_mutations(
        self,
    ) -> None:
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        manager_source = (ROOT / "processing_manager.py").read_text(
            encoding="utf-8"
        )
        main_mutations = {
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
            "misleading RTSP button label": main_source.replace(
                '            text="RTSP Stream (Unavailable)",',
                '            text="RTSP Stream",',
                1,
            ),
            "raw status": main_source.replace(
                "self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)",
                "self.status_var.set(endpoint)",
                1,
            ),
            "dead endpoint read": main_source.replace(
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)\n"
                "            if False:\n"
                "                rtsp_var.get()",
                1,
            ),
            "runtime call": main_source.replace(
                "self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)",
                "self.process_rtsp(endpoint)",
                1,
            ),
            "retained attribute": main_source.replace(
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)\n"
                "            self.saved_value = self.camera_source",
                1,
            ),
            "retained alias": main_source.replace(
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)",
                'messagebox.showwarning("RTSP unavailable", '
                "RTSP_UNAVAILABLE_MESSAGE)\n"
                "            self.source_value = self.status_var.get()",
                1,
            ),
            "fixed calls in dead branch": main_source.replace(
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
        for label, mutated_main in main_mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(main_source, mutated_main)
                self.assertTrue(
                    rtsp_quarantine_errors(mutated_main, manager_source),
                    f"mutation escaped RTSP verifier: {label}",
                )

        manager_mutations = {
            "RTSP argument rename": manager_source.replace(
                "def add_rtsp_stream(self, rtsp_url, stream_name):",
                "def add_rtsp_stream(self, rtsp_url, camera_name):",
                1,
            ),
            "RTSP argument default": manager_source.replace(
                "def add_rtsp_stream(self, rtsp_url, stream_name):",
                "def add_rtsp_stream(self, rtsp_url, stream_name=None):",
                1,
            ),
            "RTSP variadic argument": manager_source.replace(
                "def add_rtsp_stream(self, rtsp_url, stream_name):",
                "def add_rtsp_stream(self, rtsp_url, stream_name, *extra):",
                1,
            ),
            "RTSP method decorator": manager_source.replace(
                "    def add_rtsp_stream(self, rtsp_url, stream_name):",
                "    @staticmethod\n"
                "    def add_rtsp_stream(self, rtsp_url, stream_name):",
                1,
            ),
            "local-video argument rename": manager_source.replace(
                "def add_video(self, video_path):",
                "def add_video(self, source_path):",
                1,
            ),
            "local-video argument default": manager_source.replace(
                "def add_video(self, video_path):",
                "def add_video(self, video_path=None):",
                1,
            ),
            "local-video method decorator": manager_source.replace(
                "    def add_video(self, video_path):",
                "    @staticmethod\n    def add_video(self, video_path):",
                1,
            ),
            "queue endpoint": manager_source.replace(
                "del rtsp_url, stream_name\n        raise RtspUnavailableError",
                "self.video_queue.put((rtsp_url, stream_name))",
                1,
            ),
            "log endpoint": manager_source.replace(
                "del rtsp_url, stream_name",
                "logging.info(rtsp_url)",
                1,
            ),
            "dead queue after raise": manager_source.replace(
                "raise RtspUnavailableError",
                "raise RtspUnavailableError\n"
                "        self.video_queue.put((rtsp_url, stream_name))",
                1,
            ),
            "local-video bypass": manager_source.replace(
                "        reject_rtsp_transport(video_path)\n",
                "",
                1,
            ),
            "late local-video guard": manager_source.replace(
                "        reject_rtsp_transport(video_path)\n"
                "        self.total_videos += 1",
                "        self.total_videos += 1\n"
                "        reject_rtsp_transport(video_path)",
                1,
            ),
        }
        for label, mutated_manager in manager_mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(manager_source, mutated_manager)
                self.assertTrue(
                    rtsp_quarantine_errors(main_source, mutated_manager),
                    f"mutation escaped RTSP verifier: {label}",
                )


if __name__ == "__main__":
    unittest.main()
