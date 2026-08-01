"""Tests for the standard-library-only, fail-closed RTSP boundary."""

from __future__ import annotations

import ast
from dataclasses import asdict
from pathlib import Path
import unittest

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


def _is_expression(node: ast.AST, expression: str) -> bool:
    expected = ast.parse(expression, mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected,
        include_attributes=False,
    )


def rtsp_quarantine_errors(main_source: str, manager_source: str) -> tuple[str, ...]:
    """Return static violations in the two legacy RTSP entry surfaces."""

    main_tree = ast.parse(main_source, filename="main.py")
    manager_tree = ast.parse(manager_source, filename="processing_manager.py")
    errors: list[str] = []

    main_functions = [
        node for node in ast.walk(main_tree) if isinstance(node, ast.FunctionDef)
    ]
    select_functions = [
        node for node in main_functions if node.name == "select_rtsp"
    ]
    if len(select_functions) != 1:
        errors.append("main.py must contain exactly one select_rtsp callback")
    else:
        select_function = select_functions[0]
        calls = [node for node in ast.walk(select_function) if isinstance(node, ast.Call)]
        status_calls = [
            call
            for call in calls
            if _is_expression(
                call,
                "self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)",
            )
        ]
        warning_calls = [
            call
            for call in calls
            if _is_expression(
                call,
                (
                    "messagebox.showwarning("
                    "'RTSP unavailable', RTSP_UNAVAILABLE_MESSAGE)"
                ),
            )
        ]
        if len(calls) != 2 or len(status_calls) != 1 or len(warning_calls) != 1:
            errors.append("select_rtsp must perform only two fixed public UI calls")
        forbidden_names = {"endpoint", "rtsp_entry", "rtsp_url", "rtsp_var"}
        if any(
            isinstance(node, ast.Name) and node.id in forbidden_names
            for node in ast.walk(select_function)
        ):
            errors.append("select_rtsp must not solicit or retain endpoint text")

    if any(function.name == "process_rtsp" for function in main_functions):
        errors.append("main.py must not expose a process_rtsp path")
    forbidden_main_methods = {"add_rtsp_stream", "process_rtsp"}
    if any(
        isinstance(node, ast.Attribute) and node.attr in forbidden_main_methods
        for node in ast.walk(main_tree)
    ):
        errors.append("main.py reaches an RTSP runtime method")
    if any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "rtsp://" in node.value.casefold()
        for node in ast.walk(main_tree)
    ):
        errors.append("main.py contains an endpoint-shaped UI value")

    manager_functions = [
        node for node in ast.walk(manager_tree) if isinstance(node, ast.FunctionDef)
    ]
    add_functions = [
        node for node in manager_functions if node.name == "add_rtsp_stream"
    ]
    if len(add_functions) != 1:
        errors.append("manager must contain exactly one RTSP denial method")
    else:
        body = add_functions[0].body
        if (
            len(body) != 3
            or not isinstance(body[0], ast.Expr)
            or not isinstance(body[0].value, ast.Constant)
            or not isinstance(body[0].value.value, str)
            or not isinstance(body[1], ast.Delete)
            or len(body[1].targets) != 2
            or not all(
                isinstance(target, ast.Name) for target in body[1].targets
            )
            or [target.id for target in body[1].targets]
            != ["rtsp_url", "stream_name"]
            or not isinstance(body[2], ast.Raise)
            or not isinstance(body[2].exc, ast.Name)
            or body[2].exc.id != "RtspUnavailableError"
            or body[2].cause is not None
        ):
            errors.append("manager RTSP denial must discard arguments then raise")
        if any(isinstance(node, ast.Call) for node in ast.walk(add_functions[0])):
            errors.append("manager RTSP denial must perform no calls")

    video_functions = [
        node for node in manager_functions if node.name == "add_video"
    ]
    if len(video_functions) != 1:
        errors.append("manager must contain exactly one local-video entry method")
    else:
        video_body = video_functions[0].body
        if (
            len(video_body) < 2
            or not isinstance(video_body[0], ast.Expr)
            or not isinstance(video_body[0].value, ast.Constant)
            or not isinstance(video_body[0].value.value, str)
            or not isinstance(video_body[1], ast.Expr)
            or not _is_expression(
                video_body[1].value,
                "reject_rtsp_transport(video_path)",
            )
        ):
            errors.append("local-video entry must guard RTSP before any work")

    forbidden_manager_names = {"is_rtsp", "rtsp_queue"}
    if any(
        (isinstance(node, ast.Name) and node.id in forbidden_manager_names)
        or (isinstance(node, ast.Attribute) and node.attr in forbidden_manager_names)
        for node in ast.walk(manager_tree)
    ):
        errors.append("manager retains a legacy RTSP processing surface")
    if any(function.name == "_process_rtsp_wrapper" for function in manager_functions):
        errors.append("manager retains the broken RTSP worker")

    return tuple(errors)


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
        }
        for label, mutated_main in main_mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    rtsp_quarantine_errors(mutated_main, manager_source),
                    f"mutation escaped RTSP verifier: {label}",
                )

        manager_mutations = {
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
                self.assertTrue(
                    rtsp_quarantine_errors(main_source, mutated_manager),
                    f"mutation escaped RTSP verifier: {label}",
                )


if __name__ == "__main__":
    unittest.main()
