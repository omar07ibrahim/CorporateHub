"""Generate deterministic, source-only evidence for the RTSP quarantine.

This module executes the isolated RTSP policy and inspects the two legacy entry
modules as source text.  It never imports the GUI, OpenCV, the database, the
vendor wrappers, or a native runtime, and it never requests a camera endpoint.
"""

from __future__ import annotations

import argparse
import ast
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Mapping, Sequence

from rtsp_policy import (
    RTSP_UNAVAILABLE_CODE,
    RtspInputError,
    RtspUnavailableError,
    parse_rtsp_source,
    quarantine_rtsp,
    reject_rtsp_transport,
    require_rtsp_available,
)


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = 1
SOURCE_FILES = (
    "main.py",
    "processing_manager.py",
    "rtsp_evidence.py",
    "rtsp_policy.py",
)
CHECKED_ENTRY_POINTS = (
    "main.py:select_rtsp",
    "processing_manager.py:add_rtsp_stream",
    "processing_manager.py:add_video",
)
ARTIFACT_PATHS = (
    Path("evidence/rtsp-quarantine-v1.json"),
    Path("docs/assets/rtsp-quarantine-cli.svg"),
    Path("docs/assets/rtsp-quarantine-flow.svg"),
    Path("docs/assets/rtsp-quarantine-matrix.svg"),
)
FORBIDDEN_ARTIFACT_FRAGMENTS = (
    "camera.invalid",
    "evidence.invalid",
    "192.0.2.10",
    "2001:db8",
    "operator:",
    "synthetic@",
    "session=synthetic",
)


class EvidenceError(RuntimeError):
    """Raised when truthful evidence cannot be rendered or published."""


def _is_expression(node: ast.AST, expression: str) -> bool:
    expected = ast.parse(expression, mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected,
        include_attributes=False,
    )


def _has_plain_signature(
    function: ast.FunctionDef,
    argument_names: tuple[str, ...],
) -> bool:
    """Return whether a function has only the named, annotation-free arguments."""

    arguments = function.args
    positional_arguments = (*arguments.posonlyargs, *arguments.args)
    return (
        not function.decorator_list
        and not arguments.posonlyargs
        and tuple(argument.arg for argument in arguments.args) == argument_names
        and all(argument.annotation is None for argument in positional_arguments)
        and arguments.vararg is None
        and arguments.kwarg is None
        and not arguments.kwonlyargs
        and not arguments.kw_defaults
        and not arguments.defaults
        and function.returns is None
        and function.type_comment is None
        and not getattr(function, "type_params", ())
    )


def _is_ttk_button_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ttk"
        and node.func.attr == "Button"
    )


def _button_mentions_rtsp_binding(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if (
            keyword.arg == "text"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
            and "rtsp" in keyword.value.value.casefold()
        ):
            return True
        if (
            keyword.arg == "command"
            and isinstance(keyword.value, ast.Name)
            and keyword.value.id == "select_rtsp"
        ):
            return True
    return False


def rtsp_quarantine_errors(
    main_source: str,
    manager_source: str,
) -> tuple[str, ...]:
    """Return fixed, input-free violations in the RTSP entry surfaces."""

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
        if not _has_plain_signature(select_function, ()):
            errors.append("select_rtsp must be an undecorated zero-argument callback")
        body = select_function.body
        if (
            len(body) != 3
            or not isinstance(body[0], ast.Expr)
            or not isinstance(body[0].value, ast.Constant)
            or not isinstance(body[0].value.value, str)
            or not isinstance(body[1], ast.Expr)
            or not _is_expression(
                body[1].value,
                "self.status_var.set(RTSP_UNAVAILABLE_MESSAGE)",
            )
            or not isinstance(body[2], ast.Expr)
            or not _is_expression(
                body[2].value,
                (
                    "messagebox.showwarning("
                    "'RTSP unavailable', RTSP_UNAVAILABLE_MESSAGE)"
                ),
            )
        ):
            errors.append(
                "select_rtsp must contain only two unconditional fixed UI calls"
            )
        forbidden_names = {"endpoint", "rtsp_entry", "rtsp_url", "rtsp_var"}
        if any(
            (isinstance(node, ast.Name) and node.id in forbidden_names)
            or (isinstance(node, ast.Attribute) and node.attr in forbidden_names)
            for node in ast.walk(select_function)
        ):
            errors.append("select_rtsp must not solicit or retain endpoint text")

    select_input_functions = [
        node for node in main_functions if node.name == "select_input"
    ]
    rtsp_button_calls = [
        node
        for node in ast.walk(main_tree)
        if _is_ttk_button_call(node) and _button_mentions_rtsp_binding(node)
    ]
    expected_button_expression = (
        "ttk.Button(input_dialog, "
        "text='RTSP Stream (Unavailable)', command=select_rtsp)"
        ".pack(pady=10, padx=20, fill=tk.X)"
    )
    direct_rtsp_bindings: list[ast.stmt] = []
    if len(select_input_functions) == 1:
        direct_rtsp_bindings = [
            statement
            for statement in select_input_functions[0].body
            if isinstance(statement, ast.Expr)
            and _is_expression(statement.value, expected_button_expression)
        ]
    if len(select_input_functions) != 1:
        errors.append("main.py must contain exactly one select_input GUI entry")
    if len(direct_rtsp_bindings) != 1 or len(rtsp_button_calls) != 1:
        errors.append(
            "select_input must bind exactly one unavailable RTSP button to select_rtsp"
        )

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
        node
        for node in ast.walk(manager_tree)
        if isinstance(node, ast.FunctionDef)
    ]
    add_functions = [
        node for node in manager_functions if node.name == "add_rtsp_stream"
    ]
    if len(add_functions) != 1:
        errors.append("manager must contain exactly one RTSP denial method")
    else:
        add_function = add_functions[0]
        if not _has_plain_signature(
            add_function,
            ("self", "rtsp_url", "stream_name"),
        ):
            errors.append("manager RTSP denial must keep its plain public signature")
        body = add_function.body
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
        video_function = video_functions[0]
        if not _has_plain_signature(video_function, ("self", "video_path")):
            errors.append("local-video entry must keep its plain public signature")
        video_body = video_function.body
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
        or (
            isinstance(node, ast.Attribute)
            and node.attr in forbidden_manager_names
        )
        for node in ast.walk(manager_tree)
    ):
        errors.append("manager retains a legacy RTSP processing surface")
    if any(
        function.name == "_process_rtsp_wrapper"
        for function in manager_functions
    ):
        errors.append("manager retains the broken RTSP worker")

    return tuple(errors)


def _parse_case(
    case_id: str,
    input_class: str,
    endpoint: str,
    expected_syntax: str,
    expected_code: str,
) -> dict[str, bool | str]:
    syntax = "unexpected-error"
    observed_code = "unexpected-error"
    allowed = False
    try:
        source = parse_rtsp_source(endpoint)
        decision = quarantine_rtsp(source)
    except RtspInputError as error:
        syntax = "rejected"
        observed_code = error.code
    except Exception:
        pass
    else:
        syntax = "admitted"
        observed_code = decision.code
        allowed = decision.allowed

    return {
        "allowed": allowed,
        "boundary": "syntax admission",
        "id": case_id,
        "input_class": input_class,
        "observed_code": observed_code,
        "passed": (
            syntax == expected_syntax
            and observed_code == expected_code
            and allowed is False
        ),
        "syntax": syntax,
    }


def _local_ingress_case(endpoint: str) -> dict[str, bool | str]:
    syntax = "unexpected-error"
    observed_code = "unexpected-error"
    try:
        reject_rtsp_transport(endpoint)
    except RtspUnavailableError as error:
        syntax = "blocked-before-file"
        observed_code = error.code
    except Exception:
        pass
    return {
        "allowed": False,
        "boundary": "local-video ingress",
        "id": "local-ingress-rtsp",
        "input_class": "RTSP transport at file ingress",
        "observed_code": observed_code,
        "passed": (
            syntax == "blocked-before-file"
            and observed_code == RTSP_UNAVAILABLE_CODE
        ),
        "syntax": syntax,
    }


def _runtime_gate_case(endpoint: str) -> dict[str, bool | str]:
    syntax = "unexpected-error"
    observed_code = "unexpected-error"
    try:
        source = parse_rtsp_source(endpoint)
        require_rtsp_available(source)
    except RtspUnavailableError as error:
        syntax = "admitted-then-denied"
        observed_code = error.code
    except Exception:
        pass
    return {
        "allowed": False,
        "boundary": "runtime availability",
        "id": "runtime-gate",
        "input_class": "admitted credential-free source",
        "observed_code": observed_code,
        "passed": (
            syntax == "admitted-then-denied"
            and observed_code == RTSP_UNAVAILABLE_CODE
        ),
        "syntax": syntax,
    }


def _fixture_values() -> tuple[str, ...]:
    credential = "".join(
        ("rtsp://", "operator:", "synthetic@", "camera.invalid/live")
    )
    return (
        "rtsp://camera.invalid/live",
        "rtsp://192.0.2.10:8554/channel/1",
        "rtsp://[2001:db8::10]/live/main",
        credential,
        "rtsp://camera.invalid/live?session=synthetic",
        "rtsp://camera.invalid/live#fragment",
        "rtsp://camera.invalid/a/../live",
        "rtsp://camera.invalid/a%2Flive",
        "\x7fRTSPS://camera.invalid/live",
    )


def run_policy_cases() -> tuple[dict[str, bool | str], ...]:
    """Execute ten deterministic cases without serializing their inputs."""

    fixtures = _fixture_values()
    return (
        _parse_case(
            "hostname-admitted",
            "credential-free hostname",
            fixtures[0],
            "admitted",
            RTSP_UNAVAILABLE_CODE,
        ),
        _parse_case(
            "ipv4-admitted",
            "documentation IPv4",
            fixtures[1],
            "admitted",
            RTSP_UNAVAILABLE_CODE,
        ),
        _parse_case(
            "ipv6-admitted",
            "documentation IPv6",
            fixtures[2],
            "admitted",
            RTSP_UNAVAILABLE_CODE,
        ),
        _parse_case(
            "userinfo-rejected",
            "credential-bearing userinfo",
            fixtures[3],
            "rejected",
            "rtsp-credentials-forbidden",
        ),
        _parse_case(
            "query-rejected",
            "query-bearing endpoint",
            fixtures[4],
            "rejected",
            "rtsp-query-forbidden",
        ),
        _parse_case(
            "fragment-rejected",
            "fragment-bearing endpoint",
            fixtures[5],
            "rejected",
            "rtsp-fragment-forbidden",
        ),
        _parse_case(
            "parent-path-rejected",
            "parent path segment",
            fixtures[6],
            "rejected",
            "rtsp-path-ambiguous",
        ),
        _parse_case(
            "encoded-slash-rejected",
            "encoded path separator",
            fixtures[7],
            "rejected",
            "rtsp-path-ambiguous",
        ),
        _local_ingress_case(fixtures[8]),
        _runtime_gate_case(fixtures[0]),
    )


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
            sources[filename] = (root / filename).read_bytes().decode("utf-8")
    return sources


def collect_evidence(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return the deterministic evidence model used by every output."""

    sources = _read_sources(root, source_overrides)
    violations = rtsp_quarantine_errors(
        sources["main.py"],
        sources["processing_manager.py"],
    )
    cases = run_policy_cases()
    passed = sum(case["passed"] is True for case in cases)
    decision = quarantine_rtsp(
        parse_rtsp_source("rtsp://evidence.invalid/source")
    ).public_metadata()

    return {
        "artifact": "corporatehub.rtsp-quarantine",
        "cases": list(cases),
        "decision": decision,
        "privacy": {
            "endpoint_values_serialized": 0,
            "exception_messages_embed_input": False,
            "public_fields": ["allowed", "code", "label", "message"],
            "tracebacks_can_retain_input": True,
        },
        "schema_version": SCHEMA_VERSION,
        "scope": {
            "application_started": False,
            "kind": "policy execution and AST source inspection",
            "live_camera_requested": False,
            "native_runtime_loaded": False,
            "vendor_runtime_requested": False,
        },
        "source_binding": {
            "checked_entry_points": list(CHECKED_ENTRY_POINTS),
            "status": "pass" if not violations else "fail",
            "violations": list(violations),
        },
        "source_sha256": {
            filename: sha256(source.encode("utf-8")).hexdigest()
            for filename, source in sources.items()
        },
        "summary": {
            "failed": len(cases) - passed,
            "passed": passed,
            "total": len(cases),
        },
    }


def format_receipt(evidence: Mapping[str, object]) -> str:
    """Format the exact deterministic CLI receipt shown in the visual."""

    binding = evidence["source_binding"]
    summary = evidence["summary"]
    decision = evidence["decision"]
    privacy = evidence["privacy"]
    scope = evidence["scope"]
    if not all(
        isinstance(value, Mapping)
        for value in (binding, summary, decision, privacy, scope)
    ):
        raise EvidenceError("evidence model has an invalid shape")

    checked = binding["checked_entry_points"]
    if not isinstance(checked, list):
        raise EvidenceError("evidence entry-point list has an invalid shape")
    binding_status = "PASS" if binding["status"] == "pass" else "FAIL"
    bound_count = len(checked) if binding["status"] == "pass" else 0
    case_status = "PASS" if summary["failed"] == 0 else "FAIL"
    capture = "DENY" if decision["allowed"] is False else "ALLOW"
    started = "not started" if scope["application_started"] is False else "started"
    return "\n".join(
        (
            "CorporateHub RTSP quarantine evidence v1",
            (
                f"source bindings       {binding_status} "
                f"({bound_count}/{len(CHECKED_ENTRY_POINTS)})"
            ),
            (
                f"policy cases          {case_status} "
                f"({summary['passed']}/{summary['total']})"
            ),
            (
                f"capture decision      {capture} / "
                f"{decision['code']}"
            ),
            (
                "serialized endpoints  "
                f"{privacy['endpoint_values_serialized']}"
            ),
            f"scope                  source-only; application {started}",
        )
    )


def format_artifact_status(status: str) -> str:
    """Return the shared deterministic artifact-status line."""

    if status not in {"CURRENT", "WROTE"}:
        raise EvidenceError("unsupported artifact status")
    count = len(ARTIFACT_PATHS)
    return f"tracked artifacts      {status} ({count}/{count})"


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
    document = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="{title_id} {description_id}">\n'
        f'  <title id="{title_id}">{escape(title, quote=True)}</title>\n'
        f'  <desc id="{description_id}">{escape(description, quote=True)}</desc>\n'
        f"{body}\n"
        "</svg>\n"
    )
    return document.encode("utf-8")


def render_cli_svg(evidence: Mapping[str, object]) -> bytes:
    """Render the exact CLI receipt as a deterministic terminal SVG."""

    receipt_lines = (
        format_receipt(evidence).splitlines()
        + [format_artifact_status("CURRENT")]
    )
    rows = []
    for index, line in enumerate(receipt_lines):
        color = "#f8fafc" if index == 0 else "#cbd5e1"
        rows.append(
            f'  <text x="92" y="{178 + index * 42}" fill="{color}" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace" '
            f'font-size="22">{escape(line, quote=True)}</text>'
        )
    body = "\n".join(
        (
            '  <rect width="1200" height="500" rx="24" fill="#07111f"/>',
            '  <rect x="28" y="28" width="1144" height="444" rx="18" '
            'fill="#0b1728" stroke="#24324a" stroke-width="2"/>',
            '  <circle cx="62" cy="62" r="8" fill="#fb7185"/>',
            '  <circle cx="88" cy="62" r="8" fill="#fbbf24"/>',
            '  <circle cx="114" cy="62" r="8" fill="#34d399"/>',
            '  <text x="146" y="70" fill="#94a3b8" font-size="18" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
            'python3 rtsp_evidence.py --check</text>',
            '  <rect x="930" y="48" width="104" height="30" rx="15" '
            'fill="#123d36"/>',
            '  <text x="982" y="69" text-anchor="middle" fill="#6ee7b7" '
            'font-size="13" font-weight="700" '
            'font-family="Arial,sans-serif">SOURCE ONLY</text>',
            '  <rect x="1044" y="48" width="88" height="30" rx="15" '
            'fill="#4c1d2f"/>',
            '  <text x="1088" y="69" text-anchor="middle" fill="#fda4af" '
            'font-size="13" font-weight="700" '
            'font-family="Arial,sans-serif">DENY</text>',
            '  <text x="72" y="126" fill="#34d399" font-size="22" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">$</text>',
            *rows,
        )
    )
    return _svg_document(
        width=1200,
        height=500,
        title_id="cli-title",
        title="CorporateHub RTSP quarantine CLI receipt",
        description_id="cli-desc",
        description=(
            "Exact deterministic output of the source-only RTSP evidence check. "
            "It reports three bound entry points, ten passing policy cases, "
            "a denied capture decision, and zero serialized endpoints."
        ),
        body=body,
    )


def render_flow_svg(evidence: Mapping[str, object]) -> bytes:
    """Render the verified RTSP entry and blocked-runtime flow."""

    binding = evidence["source_binding"]
    decision = evidence["decision"]
    if not isinstance(binding, Mapping) or not isinstance(decision, Mapping):
        raise EvidenceError("evidence model has an invalid flow shape")
    checked = binding["checked_entry_points"]
    if not isinstance(checked, list) or len(checked) != len(CHECKED_ENTRY_POINTS):
        raise EvidenceError("evidence entry-point list has an invalid shape")
    status = "PASS" if binding["status"] == "pass" else "FAIL"
    code = escape(str(decision["code"]), quote=True)
    entry_points = [escape(str(entry), quote=True) for entry in checked]
    body = f'''  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3"
      orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L0,6 L9,3 z" fill="#60a5fa"/>
    </marker>
  </defs>
  <rect width="1440" height="860" rx="28" fill="#07111f"/>
  <text x="70" y="82" fill="#f8fafc" font-size="34" font-weight="700"
    font-family="Arial,sans-serif">Fail-closed RTSP boundary</text>
  <text x="70" y="116" fill="#94a3b8" font-size="18"
    font-family="Arial,sans-serif">Policy execution + AST source inspection; no application or camera started</text>
  <rect x="1120" y="58" width="250" height="44" rx="22" fill="#123d36"/>
  <text x="1245" y="86" text-anchor="middle" fill="#6ee7b7"
    font-size="15" font-weight="700" font-family="Arial,sans-serif">{status} · {len(checked)}/{len(CHECKED_ENTRY_POINTS)} ENTRY POINTS</text>

  <rect x="60" y="154" width="390" height="430" rx="22" fill="#10213a" stroke="#31537c"/>
  <text x="90" y="198" fill="#93c5fd" font-size="15" font-weight="700" font-family="Arial,sans-serif">THREE SOURCE-BOUND ENTRY SURFACES</text>
  <text x="90" y="242" fill="#f8fafc" font-size="14" font-weight="700" font-family="ui-monospace,SFMono-Regular,Consolas,monospace">{entry_points[0]}</text>
  <text x="90" y="268" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Two unconditional fixed calls</text>
  <text x="90" y="292" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">No input field · no endpoint read</text>
  <line x1="90" y1="312" x2="420" y2="312" stroke="#31537c"/>
  <text x="90" y="344" fill="#f8fafc" font-size="14" font-weight="700" font-family="ui-monospace,SFMono-Regular,Consolas,monospace">{entry_points[1]}</text>
  <text x="90" y="372" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Delete both arguments</text>
  <text x="90" y="396" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Raise fixed unavailable error</text>
  <line x1="90" y1="416" x2="420" y2="416" stroke="#31537c"/>
  <text x="90" y="448" fill="#f8fafc" font-size="14" font-weight="700" font-family="ui-monospace,SFMono-Regular,Consolas,monospace">{entry_points[2]}</text>
  <text x="90" y="476" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">RTSP/RTSPS prefix guard runs first</text>
  <text x="90" y="500" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Before counters, queue, or progress</text>
  <text x="90" y="524" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Before OpenCV or processor creation</text>
  <text x="90" y="562" fill="#93c5fd" font-size="14" font-weight="700" font-family="Arial,sans-serif">INDEPENDENT PATHS · FIXED DENIAL</text>

  <line x1="450" y1="354" x2="516" y2="354" stroke="#60a5fa" stroke-width="4" marker-end="url(#arrow)"/>
  <rect x="526" y="190" width="375" height="330" rx="22" fill="#102a32" stroke="#2b7a78" stroke-width="2"/>
  <text x="558" y="232" fill="#5eead4" font-size="15" font-weight="700" font-family="Arial,sans-serif">FIXED FAIL-CLOSED OUTCOMES</text>
  <text x="558" y="278" fill="#f8fafc" font-size="20" font-weight="700" font-family="Arial,sans-serif">GUI → constant warning</text>
  <text x="558" y="320" fill="#f8fafc" font-size="20" font-weight="700" font-family="Arial,sans-serif">Manager → discard + fixed raise</text>
  <text x="558" y="362" fill="#f8fafc" font-size="19" font-weight="700" font-family="Arial,sans-serif">File ingress → prefix guard</text>
  <text x="558" y="390" fill="#f8fafc" font-size="19" font-weight="700" font-family="Arial,sans-serif">then fixed raise</text>
  <rect x="558" y="420" width="275" height="46" rx="23" fill="#4c1d2f"/>
  <text x="695" y="449" text-anchor="middle" fill="#fda4af" font-size="16" font-weight="700" font-family="Arial,sans-serif">DENY · {code}</text>
  <text x="558" y="496" fill="#cbd5e1" font-size="15" font-family="Arial,sans-serif">No shared camera adapter is invoked</text>

  <rect x="526" y="536" width="375" height="144" rx="20" fill="#132235" stroke="#31537c"/>
  <text x="558" y="576" fill="#93c5fd" font-size="14" font-weight="700" font-family="Arial,sans-serif">SEPARATE POLICY EVIDENCE PATH</text>
  <text x="558" y="614" fill="#f8fafc" font-size="20" font-weight="700" font-family="Arial,sans-serif">Parse → discard → quarantine</text>
  <text x="558" y="647" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">Not wired to GUI · decision remains DENY</text>

  <line x1="901" y1="354" x2="1011" y2="354" stroke="#fb7185" stroke-width="5" stroke-dasharray="10 9"/>
  <circle cx="956" cy="354" r="24" fill="#4c1d2f" stroke="#fb7185" stroke-width="3"/>
  <path d="M945 343 L967 365 M967 343 L945 365" stroke="#fecdd3" stroke-width="4" stroke-linecap="round"/>

  <rect x="1021" y="154" width="359" height="526" rx="22" fill="#231522" stroke="#7f1d3b" stroke-width="2"/>
  <text x="1051" y="198" fill="#fda4af" font-size="15" font-weight="700" font-family="Arial,sans-serif">BLOCKED RUNTIME-SIDE WORK</text>
  <text x="1051" y="256" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">Queue mutation</text>
  <text x="1051" y="312" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">Progress / status data</text>
  <text x="1051" y="368" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">OpenCV network open</text>
  <text x="1051" y="424" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">SQLite endpoint writes</text>
  <text x="1051" y="480" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">VideoProcessor construction</text>
  <text x="1051" y="536" fill="#f8fafc" font-size="21" font-weight="700" font-family="Arial,sans-serif">DTK live capture</text>
  <text x="1051" y="592" fill="#fda4af" font-size="16" font-family="Arial,sans-serif">No runtime claim</text>
  <text x="1051" y="623" fill="#fda4af" font-size="16" font-family="Arial,sans-serif">No camera evidence</text>

  <rect x="60" y="728" width="1320" height="84" rx="18" fill="#0b1728" stroke="#24324a"/>
  <text x="90" y="763" fill="#f8fafc" font-size="18" font-weight="700" font-family="Arial,sans-serif">Bounded claim</text>
  <text x="90" y="792" fill="#cbd5e1" font-size="16" font-family="Arial,sans-serif">RTSP/RTSPS entries are quarantined. This is not a general URI sandbox, secure memory erasure, or live-camera support.</text>'''
    return _svg_document(
        width=1440,
        height=860,
        title_id="flow-title",
        title="CorporateHub fail-closed RTSP flow",
        description_id="flow-desc",
        description=(
            "Three named source-bound entry points independently produce fixed "
            "denials. A separate syntax-evidence path validates, discards, and "
            "quarantines input. Endpoint-dependent queue, UI data, OpenCV, "
            "SQLite write, processor, and DTK work remain blocked."
        ),
        body=body,
    )


def render_matrix_svg(evidence: Mapping[str, object]) -> bytes:
    """Render the ten observed policy outcomes and source fingerprints."""

    cases = evidence["cases"]
    hashes = evidence["source_sha256"]
    summary = evidence["summary"]
    if (
        not isinstance(cases, list)
        or not isinstance(hashes, Mapping)
        or not isinstance(summary, Mapping)
    ):
        raise EvidenceError("evidence model has an invalid matrix shape")

    rows = []
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise EvidenceError("evidence case has an invalid shape")
        y = 205 + index * 54
        background = "#0f1d31" if index % 2 == 0 else "#0b1728"
        result = "MATCH" if case["passed"] is True else "MISMATCH"
        result_color = "#6ee7b7" if result == "MATCH" else "#fda4af"
        rows.append(
            f'  <rect x="56" y="{y - 34}" width="1328" height="50" '
            f'rx="10" fill="{background}"/>\n'
            f'  <text x="78" y="{y}" fill="#f8fafc" font-size="18" '
            'font-family="Arial,sans-serif">'
            f'{escape(str(case["input_class"]), quote=True)}</text>\n'
            f'  <text x="440" y="{y}" fill="#cbd5e1" font-size="17" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
            f'{escape(str(case["boundary"]), quote=True)}</text>\n'
            f'  <text x="700" y="{y}" fill="#cbd5e1" font-size="17" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
            f'{escape(str(case["syntax"]), quote=True)}</text>\n'
            f'  <text x="985" y="{y}" fill="#93c5fd" font-size="15" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
            f'{escape(str(case["observed_code"]), quote=True)}</text>\n'
            f'  <text x="1328" y="{y}" text-anchor="end" fill="{result_color}" '
            'font-size="16" font-weight="700" font-family="Arial,sans-serif">'
            f"{result}</text>"
        )

    fingerprints = " · ".join(
        f"{name} {str(digest)[:12]}"
        for name, digest in sorted(hashes.items())
    )
    body = "\n".join(
        (
            '  <rect width="1440" height="850" rx="28" fill="#07111f"/>',
            '  <text x="56" y="70" fill="#f8fafc" font-size="34" '
            'font-weight="700" font-family="Arial,sans-serif">Observed RTSP policy matrix</text>',
            '  <text x="56" y="104" fill="#94a3b8" font-size="18" '
            'font-family="Arial,sans-serif">Actual source-only results; inputs are classified but never serialized</text>',
            '  <text x="56" y="132" fill="#fda4af" font-size="15" '
            'font-weight="700" font-family="Arial,sans-serif">MATCH = expected policy outcome observed · capture remains DENIED</text>',
            '  <rect x="1080" y="50" width="304" height="44" rx="22" '
            'fill="#123d36"/>',
            f'  <text x="1232" y="78" text-anchor="middle" fill="#6ee7b7" '
            'font-size="15" font-weight="700" font-family="Arial,sans-serif">'
            f'{summary["passed"]}/{summary["total"]} POLICY OUTCOMES MATCH</text>',
            '  <text x="78" y="154" fill="#94a3b8" font-size="15" '
            'font-weight="700" font-family="Arial,sans-serif">INPUT CLASS</text>',
            '  <text x="440" y="154" fill="#94a3b8" font-size="15" '
            'font-weight="700" font-family="Arial,sans-serif">BOUNDARY</text>',
            '  <text x="700" y="154" fill="#94a3b8" font-size="15" '
            'font-weight="700" font-family="Arial,sans-serif">OBSERVED STATE</text>',
            '  <text x="985" y="154" fill="#94a3b8" font-size="15" '
            'font-weight="700" font-family="Arial,sans-serif">STABLE CODE</text>',
            '  <text x="1328" y="154" text-anchor="end" fill="#94a3b8" '
            'font-size="15" font-weight="700" font-family="Arial,sans-serif">EVIDENCE</text>',
            *rows,
            '  <rect x="56" y="760" width="1328" height="54" rx="12" '
            'fill="#0b1728" stroke="#24324a"/>',
            '  <text x="78" y="793" fill="#94a3b8" font-size="14" '
            'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
            f'{escape(fingerprints, quote=True)}</text>',
        )
    )
    return _svg_document(
        width=1440,
        height=850,
        title_id="matrix-title",
        title="CorporateHub observed RTSP policy matrix",
        description_id="matrix-desc",
        description=(
            "Ten executed policy cases list input class, boundary, observed "
            "state, stable decision code, and expected-outcome match without "
            "serializing any endpoint value; capture remains denied."
        ),
        body=body,
    )


def _json_bytes(evidence: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            evidence,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _assert_publishable(evidence: Mapping[str, object]) -> None:
    summary = evidence["summary"]
    binding = evidence["source_binding"]
    decision = evidence["decision"]
    privacy = evidence["privacy"]
    scope = evidence["scope"]
    cases = evidence["cases"]
    if not all(
        isinstance(value, Mapping)
        for value in (summary, binding, decision, privacy, scope)
    ) or not isinstance(cases, list):
        raise EvidenceError("evidence model has an invalid publish shape")
    if (
        len(cases) != 10
        or any(
            not isinstance(case, Mapping)
            or case.get("passed") is not True
            or case.get("allowed") is not False
            for case in cases
        )
        or summary != {"failed": 0, "passed": 10, "total": 10}
        or binding["status"] != "pass"
        or binding["checked_entry_points"] != list(CHECKED_ENTRY_POINTS)
        or binding["violations"] != []
        or decision["allowed"] is not False
        or decision["code"] != RTSP_UNAVAILABLE_CODE
        or privacy["endpoint_values_serialized"] != 0
        or privacy["exception_messages_embed_input"] is not False
        or privacy["tracebacks_can_retain_input"] is not True
        or scope["application_started"] is not False
        or scope["live_camera_requested"] is not False
        or scope["native_runtime_loaded"] is not False
        or scope["vendor_runtime_requested"] is not False
    ):
        raise EvidenceError("refusing to publish failing RTSP evidence")


def _assert_endpoint_free(artifacts: Mapping[Path, bytes]) -> None:
    combined = b"\n".join(artifacts.values())
    if re.search(rb"(?i)rtsps?://", combined):
        raise EvidenceError("an endpoint-shaped value reached a public artifact")
    markers = (*_fixture_values(), *FORBIDDEN_ARTIFACT_FRAGMENTS)
    for marker in markers:
        if marker.encode("utf-8") in combined:
            raise EvidenceError("an endpoint value reached a public artifact")


def render_artifacts(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
) -> dict[Path, bytes]:
    """Render every tracked artifact in memory from one evidence model."""

    evidence = collect_evidence(root, source_overrides)
    artifacts = {
        ARTIFACT_PATHS[0]: _json_bytes(evidence),
        ARTIFACT_PATHS[1]: render_cli_svg(evidence),
        ARTIFACT_PATHS[2]: render_flow_svg(evidence),
        ARTIFACT_PATHS[3]: render_matrix_svg(evidence),
    }
    _assert_endpoint_free(artifacts)
    return artifacts


def artifact_differences(
    root: Path,
    artifacts: Mapping[Path, bytes],
) -> tuple[Path, ...]:
    """Return missing or stale artifact paths in deterministic order."""

    differences = []
    for relative_path in ARTIFACT_PATHS:
        target = root / relative_path
        if not target.is_file() or target.read_bytes() != artifacts[relative_path]:
            differences.append(relative_path)
    return tuple(differences)


def _validate_destination(root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise EvidenceError("artifact destination is outside the repository")
    target = root / relative_path
    resolved_root = root.resolve(strict=False)
    resolved_parent = target.parent.resolve(strict=False)
    if not resolved_parent.is_relative_to(resolved_root):
        raise EvidenceError("artifact destination escapes the repository")

    cursor = root
    if cursor.is_symlink():
        raise EvidenceError("artifact destination must not use symlink parents")
    for component in relative_path.parent.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise EvidenceError(
                "artifact destination must not use symlink parents"
            )
    if target.is_symlink():
        raise EvidenceError("artifact destination must not be a symlink")
    return target


def _atomic_write(root: Path, relative_path: Path, content: bytes) -> None:
    target = _validate_destination(root, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def write_current_artifacts(
    root: Path = ROOT,
    source_overrides: Mapping[str, str] | None = None,
) -> dict[Path, bytes]:
    """Validate and atomically replace all deterministic artifacts."""

    evidence = collect_evidence(root, source_overrides)
    _assert_publishable(evidence)
    artifacts = {
        ARTIFACT_PATHS[0]: _json_bytes(evidence),
        ARTIFACT_PATHS[1]: render_cli_svg(evidence),
        ARTIFACT_PATHS[2]: render_flow_svg(evidence),
        ARTIFACT_PATHS[3]: render_matrix_svg(evidence),
    }
    _assert_endpoint_free(artifacts)
    for relative_path in ARTIFACT_PATHS:
        _validate_destination(root, relative_path)
    for relative_path in ARTIFACT_PATHS:
        _atomic_write(root, relative_path, artifacts[relative_path])
    return artifacts


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate source-only RTSP quarantine evidence.",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check",
        action="store_true",
        help="fail when a tracked JSON or SVG artifact is stale",
    )
    action.add_argument(
        "--write",
        action="store_true",
        help="atomically regenerate the tracked JSON and SVG artifacts",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the deterministic receipt, freshness check, or writer."""

    arguments = _parser().parse_args(argv)
    try:
        evidence = collect_evidence(ROOT)
        _assert_publishable(evidence)
        if arguments.write:
            write_current_artifacts(ROOT)
        artifacts = render_artifacts(ROOT)
        differences = artifact_differences(ROOT, artifacts)
    except (EvidenceError, OSError, SyntaxError) as error:
        print(f"evidence error: {error}", file=sys.stderr)
        return 1

    print(format_receipt(evidence))
    if arguments.write:
        print(format_artifact_status("WROTE"))
        return 0
    if arguments.check:
        if differences:
            print(
                "stale artifacts: "
                + ", ".join(path.as_posix() for path in differences),
                file=sys.stderr,
            )
            return 1
        print(format_artifact_status("CURRENT"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
