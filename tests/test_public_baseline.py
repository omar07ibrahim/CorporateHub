"""Source-only checks that avoid GUI, database, vendor, and native imports.

Focused tests import the project-owned policy and evidence modules; this module
itself inspects the remaining project source as text and AST.
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
SECURITY = ROOT / "SECURITY.md"

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
        "/.offline-report-evidence-*/",
        "/.offline-report-capture.*/",
        "/evidence/.offline-report-v1.json.*",
        "/docs/assets/.offline-report-*.svg.*",
        "/docs/assets/.offline-report-browser.png.*",
        "/docs/demo/offline-report-v1/**/.*.*",
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


def _call_named(node: ast.AST, name: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    )


def _zero_argument_method_call(
    node: ast.AST,
    receiver: str,
    method: str,
) -> bool:
    return (
        isinstance(node, ast.Call)
        and not node.args
        and not node.keywords
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == receiver
    )


def _assignments_to(function: ast.FunctionDef, name: str) -> list[ast.AST]:
    def bound_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, ast.Starred):
            return bound_names(target.value)
        if isinstance(target, (ast.List, ast.Tuple)):
            return {
                bound_name
                for element in target.elts
                for bound_name in bound_names(element)
            }
        return set()

    assignments: list[ast.AST] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            if any(name in bound_names(target) for target in node.targets):
                assignments.append(node)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if name in bound_names(node.target):
                assignments.append(node)
        elif isinstance(node, ast.NamedExpr):
            if name in bound_names(node.target):
                assignments.append(node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if name in bound_names(node.target):
                assignments.append(node)
        elif isinstance(node, ast.comprehension):
            if name in bound_names(node.target):
                assignments.append(node)
        elif isinstance(node, ast.With):
            if any(
                item.optional_vars is not None
                and name in bound_names(item.optional_vars)
                for item in node.items
            ):
                assignments.append(node)
    return assignments


def _single_assignment_value(
    function: ast.FunctionDef,
    name: str,
) -> ast.AST | None:
    assignments = _assignments_to(function, name)
    if len(assignments) != 1:
        return None
    assignment = assignments[0]
    if (
        not isinstance(assignment, ast.Assign)
        or len(assignment.targets) != 1
        or not isinstance(assignment.targets[0], ast.Name)
        or assignment.targets[0].id != name
    ):
        return None
    return assignment.value


def _sanitized_expression_names(
    node: ast.AST,
    allowed_names: frozenset[str],
) -> set[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return set()
    if isinstance(node, ast.Name) and node.id in allowed_names:
        return {node.id}
    if isinstance(node, ast.JoinedStr):
        names: set[str] = set()
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                continue
            if (
                not isinstance(value, ast.FormattedValue)
                or value.conversion != -1
                or value.format_spec is not None
            ):
                return None
            nested_names = _sanitized_expression_names(value.value, allowed_names)
            if nested_names is None:
                return None
            names.update(nested_names)
        return names
    return None


def _is_str_of(node: ast.AST, name: str) -> bool:
    return (
        _call_named(node, "str")
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == name
    )


def _is_self_db_call(node: ast.AST, method: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == method
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "db"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "self"
    )


def video_write_policy_errors(source: str) -> tuple[str, ...]:
    """Return structural path-dataflow violations in ``video_processor.py``."""

    tree = ast.parse(source, filename="video_processor.py")
    functions_by_name: dict[str, list[ast.FunctionDef]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions_by_name.setdefault(node.name, []).append(node)

    specifications = {
        "_add_detection_history": {
            "root": "detection_history",
            "outputs": ("pp", "fp"),
            "plate_source": ("name", "plate_text"),
            "timestamp_source": ("name", "ts_str"),
        },
        "_handle_blacklist_match": {
            "root": "blacklist_matches",
            "outputs": ("fp",),
            "plate_source": ("method", "plate", "Text"),
            "timestamp_source": ("str_name", "ts"),
        },
        "_update_existing_plate": {
            "root": "images",
            "outputs": ("pp", "fp"),
            "plate_source": ("method", "plate", "Text"),
            "timestamp_source": ("name", "filename_ts"),
        },
        "_save_new_plate": {
            "root": "images",
            "outputs": ("pp", "fp"),
            "plate_source": ("name", "pt"),
            "timestamp_source": ("name", "filename_ts"),
        },
    }
    sanitized_names = frozenset({"plate_component", "timestamp_component"})
    errors: list[str] = []
    direct_try_calls: dict[str, list[ast.Call]] = {}

    for function_name, specification in specifications.items():
        candidates = functions_by_name.get(function_name, [])
        if len(candidates) != 1:
            errors.append(f"{function_name}: expected exactly one function")
            continue
        function = candidates[0]
        direct_tries = [
            statement for statement in function.body if isinstance(statement, ast.Try)
        ]
        if len(direct_tries) != 1:
            errors.append(f"{function_name}: expected one direct try block")
            direct_try_body: list[ast.stmt] = []
        else:
            direct_try_body = direct_tries[0].body
        direct_try_calls[function_name] = [
            statement.value
            for statement in direct_try_body
            if isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
        ]
        sanitizer_assignment_nodes: list[ast.AST] = []
        output_assignment_nodes: list[ast.AST] = []

        safe_calls = [
            node
            for node in ast.walk(function)
            if _call_named(node, "safe_path_component")
        ]
        if len(safe_calls) != 2:
            errors.append(f"{function_name}: expected two assigned sanitizer calls")

        sanitizer_values: dict[str, ast.AST] = {}
        for sanitized_name in sanitized_names:
            sanitizer_assignments = _assignments_to(function, sanitized_name)
            if len(sanitizer_assignments) == 1:
                sanitizer_assignment_nodes.append(sanitizer_assignments[0])
            value = _single_assignment_value(function, sanitized_name)
            if (
                not _call_named(value, "safe_path_component")
                or len(value.args) != 1
                or value.keywords
            ):
                errors.append(
                    f"{function_name}: {sanitized_name} must be assigned by sanitizer"
                )
                continue
            sanitizer_values[sanitized_name] = value.args[0]

        plate_source = specification["plate_source"]
        actual_plate_source = sanitizer_values.get("plate_component")
        if plate_source[0] == "name":
            valid_plate_source = (
                isinstance(actual_plate_source, ast.Name)
                and actual_plate_source.id == plate_source[1]
            )
        else:
            valid_plate_source = _zero_argument_method_call(
                actual_plate_source,
                plate_source[1],
                plate_source[2],
            )
        if not valid_plate_source:
            errors.append(f"{function_name}: plate sanitizer source is not raw plate text")

        timestamp_source = specification["timestamp_source"]
        actual_timestamp_source = sanitizer_values.get("timestamp_component")
        if timestamp_source[0] == "name":
            valid_timestamp_source = (
                isinstance(actual_timestamp_source, ast.Name)
                and actual_timestamp_source.id == timestamp_source[1]
            )
        else:
            valid_timestamp_source = _is_str_of(
                actual_timestamp_source,
                timestamp_source[1],
            )
        if not valid_timestamp_source:
            errors.append(f"{function_name}: timestamp sanitizer source is invalid")

        for output_name in specification["outputs"]:
            output_assignments = _assignments_to(function, output_name)
            if len(output_assignments) == 1:
                output_assignment_nodes.append(output_assignments[0])
            value = _single_assignment_value(function, output_name)
            if (
                not _call_named(value, "managed_path")
                or value.keywords
                or len(value.args) < 2
                or not isinstance(value.args[0], ast.Constant)
                or value.args[0].value != specification["root"]
            ):
                errors.append(
                    f"{function_name}: {output_name} must come from its managed root"
                )
                continue

            referenced_names: set[str] = set()
            valid_components = True
            for component in value.args[1:]:
                component_names = _sanitized_expression_names(
                    component,
                    sanitized_names,
                )
                if component_names is None:
                    valid_components = False
                    break
                referenced_names.update(component_names)
            if not valid_components or referenced_names != sanitized_names:
                errors.append(
                    f"{function_name}: {output_name} must use only both sanitized values"
                )

        save_calls = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "save"
        ]
        actual_save_targets: list[str] = []
        for call in save_calls:
            if (
                len(call.args) != 1
                or call.keywords
                or not isinstance(call.args[0], ast.Name)
            ):
                errors.append(f"{function_name}: image save target is not a path variable")
                continue
            target_name = call.args[0].id
            actual_save_targets.append(target_name)
            if target_name == "pp":
                valid_receiver = _zero_argument_method_call(
                    call.func.value,
                    "plate",
                    "GetPlateImage",
                )
            elif target_name == "fp":
                valid_receiver = (
                    isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "img"
                )
            else:
                valid_receiver = False
            if not valid_receiver:
                errors.append(
                    f"{function_name}: {target_name} save has an unexpected image source"
                )
        if sorted(actual_save_targets) != sorted(specification["outputs"]):
            errors.append(f"{function_name}: image save targets do not match outputs")
        if any(call not in direct_try_calls[function_name] for call in save_calls):
            errors.append(f"{function_name}: image saves must be direct guarded operations")

        required_assignments = sanitizer_assignment_nodes + output_assignment_nodes
        if (
            len(required_assignments)
            != len(sanitized_names) + len(specification["outputs"])
            or any(node not in direct_try_body for node in required_assignments)
        ):
            errors.append(
                f"{function_name}: sanitizer and path assignments must be direct"
            )
        elif max(
            direct_try_body.index(node) for node in sanitizer_assignment_nodes
        ) >= min(direct_try_body.index(node) for node in output_assignment_nodes):
            errors.append(f"{function_name}: paths are assigned before sanitization")

    history = functions_by_name.get("_add_detection_history", [None])[0]
    if history is not None:
        history_db_calls = [
            node
            for node in ast.walk(history)
            if _is_self_db_call(node, "add_plate_detection")
        ]
        if (
            len(history_db_calls) != 1
            or len(history_db_calls[0].args) < 2
            or not _is_str_of(history_db_calls[0].args[-2], "pp")
            or not _is_str_of(history_db_calls[0].args[-1], "fp")
        ):
            errors.append("_add_detection_history: DB paths must be str(pp), str(fp)")
        elif history_db_calls[0] not in direct_try_calls.get(
            "_add_detection_history",
            [],
        ):
            errors.append("_add_detection_history: DB write must be direct")

    blacklist = functions_by_name.get("_handle_blacklist_match", [None])[0]
    if blacklist is not None:
        alert_calls = [
            node
            for node in ast.walk(blacklist)
            if _is_self_db_call(node, "add_blacklist_alert")
        ]
        valid_raw_plate = (
            len(alert_calls) == 1
            and len(alert_calls[0].args) == 2
            and _zero_argument_method_call(alert_calls[0].args[0], "plate", "Text")
        )
        valid_image_path = (
            len(alert_calls) == 1 and _is_str_of(alert_calls[0].args[1], "fp")
        )
        if not valid_raw_plate or not valid_image_path:
            errors.append(
                "_handle_blacklist_match: alert must keep raw text and str(fp)"
            )
        elif alert_calls[0] not in direct_try_calls.get(
            "_handle_blacklist_match",
            [],
        ):
            errors.append("_handle_blacklist_match: DB write must be direct")

    save_new_candidates = functions_by_name.get("_save_new_plate", [])
    if len(save_new_candidates) == 1:
        plate_data_tuple = _single_assignment_value(
            save_new_candidates[0],
            "plate_data_tuple",
        )
        if (
            not isinstance(plate_data_tuple, ast.Tuple)
            or not plate_data_tuple.elts
            or not isinstance(plate_data_tuple.elts[0], ast.Name)
            or plate_data_tuple.elts[0].id != "pt"
        ):
            errors.append("_save_new_plate: DB tuple must retain raw plate text")

    return tuple(errors)


def production_execution_errors(sources: dict[str, str]) -> tuple[str, ...]:
    """Return forbidden shell/process execution constructs in production source."""

    errors: list[str] = []
    forbidden_os_attributes = {"startfile", "system"}
    for filename, source in sources.items():
        tree = ast.parse(source, filename=filename)
        os_aliases = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "os"
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                forbidden_imports = {
                    alias.name
                    for alias in node.names
                    if alias.name in forbidden_os_attributes
                }
                if forbidden_imports:
                    errors.append(
                        f"{filename}: forbidden os import {sorted(forbidden_imports)}"
                    )

            if (
                isinstance(node, ast.Attribute)
                and node.attr in forbidden_os_attributes
                and isinstance(node.value, ast.Name)
                and node.value.id in os_aliases
            ):
                errors.append(f"{filename}: forbidden os.{node.attr} attribute")

            if not isinstance(node, ast.Call):
                continue
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                errors.append(f"{filename}: shell=True is forbidden")
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in os_aliases
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in forbidden_os_attributes
            ):
                errors.append(
                    f"{filename}: literal getattr(os, {node.args[1].value!r})"
                )

    return tuple(errors)


def _matches_expression(node: ast.AST | None, expression: str) -> bool:
    if node is None:
        return False
    expected = ast.parse(expression, mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected,
        include_attributes=False,
    )


def _calls_named(function: ast.FunctionDef, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _browser_open_calls(function: ast.FunctionDef | ast.Module) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "webbrowser"
        and node.func.attr == "open"
    ]


def _folder_open_dataflow_errors(
    function: ast.FunctionDef,
    safe_expression: str,
    *,
    raw_assignment: tuple[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    if raw_assignment is not None:
        raw_name, raw_expression = raw_assignment
        if not _matches_expression(
            _single_assignment_value(function, raw_name),
            raw_expression,
        ):
            errors.append(f"{function.name}: raw plate assignment changed")

    if not _matches_expression(
        _single_assignment_value(function, "plate_component"),
        safe_expression,
    ):
        errors.append(f"{function.name}: plate component dataflow changed")
    if len(_calls_named(function, "safe_path_component")) != 1:
        errors.append(f"{function.name}: sanitizer must have one assigned call")

    if not _matches_expression(
        _single_assignment_value(function, "folder_path"),
        "managed_path('detection_history', plate_component)",
    ):
        errors.append(f"{function.name}: folder path dataflow changed")
    if len(_calls_named(function, "managed_path")) != 1:
        errors.append(f"{function.name}: managed path must have one assigned call")

    directory_guards = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.If)
        and _matches_expression(node.test, "folder_path.is_dir()")
    ]
    if len(directory_guards) != 1:
        errors.append(f"{function.name}: expected one folder is_dir guard")

    browser_calls = _browser_open_calls(function)
    expected_browser_expression = "webbrowser.open(local_file_uri(folder_path))"
    if (
        len(browser_calls) != 1
        or not _matches_expression(browser_calls[0], expected_browser_expression)
    ):
        errors.append(f"{function.name}: browser URI dataflow changed")
    if len(_calls_named(function, "local_file_uri")) != 1:
        errors.append(f"{function.name}: URI encoder must be nested exactly once")

    if len(directory_guards) == 1 and len(browser_calls) == 1:
        guarded_browser_calls = {
            id(node)
            for statement in directory_guards[0].body
            for node in ast.walk(statement)
            if node in browser_calls
        }
        if id(browser_calls[0]) not in guarded_browser_calls:
            errors.append(f"{function.name}: browser open is outside is_dir guard")

    return errors


def browser_policy_errors(
    progress_source: str,
    report_source: str,
) -> tuple[str, ...]:
    """Return structural violations in the three local-file browser sites."""

    progress_tree = ast.parse(progress_source, filename="progress_frame.py")
    report_tree = ast.parse(report_source, filename="report_panel.py")
    errors: list[str] = []

    progress_functions = [
        node
        for node in ast.walk(progress_tree)
        if isinstance(node, ast.FunctionDef) and node.name == "open_image_folder"
    ]
    if len(progress_functions) != 1:
        errors.append("progress_frame.py: expected one open_image_folder")
    else:
        errors.extend(
            _folder_open_dataflow_errors(
                progress_functions[0],
                "safe_path_component(str(detection['plate_text']))",
            )
        )

    report_functions: dict[str, list[ast.FunctionDef]] = {}
    for node in ast.walk(report_tree):
        if isinstance(node, ast.FunctionDef):
            report_functions.setdefault(node.name, []).append(node)

    detection_functions = report_functions.get("open_detection_folder", [])
    if len(detection_functions) != 1:
        errors.append("report_panel.py: expected one open_detection_folder")
    else:
        errors.extend(
            _folder_open_dataflow_errors(
                detection_functions[0],
                "safe_path_component(str(plate_text))",
                raw_assignment=(
                    "plate_text",
                    "self.tree.item(selection[0])['values'][0]",
                ),
            )
        )

    export_functions = report_functions.get("export_report", [])
    if len(export_functions) != 1:
        errors.append("report_panel.py: expected one export_report")
    else:
        export_function = export_functions[0]
        output_parent = _single_assignment_value(export_function, "output_parent")
        if not (
            isinstance(output_parent, ast.Call)
            and isinstance(output_parent.func, ast.Attribute)
            and isinstance(output_parent.func.value, ast.Name)
            and output_parent.func.value.id == "filedialog"
            and output_parent.func.attr == "askdirectory"
        ):
            errors.append("export_report: parent must come from directory dialog")
        if not _matches_expression(
            _single_assignment_value(export_function, "export_result"),
            "export_offline_report(self.db.path, output_parent)",
        ):
            errors.append("export_report: offline exporter dataflow changed")
        if len(_calls_named(export_function, "export_offline_report")) != 1:
            errors.append("export_report: expected exactly one offline export call")
        worker_functions = [
            node
            for node in export_function.body
            if isinstance(node, ast.FunctionDef) and node.name == "run_export"
        ]
        if len(worker_functions) != 1:
            errors.append("export_report: expected one background export worker")
        elif len(_calls_named(worker_functions[0], "export_offline_report")) != 1:
            errors.append("export_report: offline export must run only in its worker")
        if not _matches_expression(
            _single_assignment_value(export_function, "worker"),
            (
                "threading.Thread(target=run_export, "
                "name='CorporateHub-report-export', daemon=True)"
            ),
        ):
            errors.append("export_report: background thread contract changed")
        thread_start_calls = [
            node
            for node in ast.walk(export_function)
            if isinstance(node, ast.Call)
            and _matches_expression(node, "worker.start()")
        ]
        after_calls = [
            node
            for node in ast.walk(export_function)
            if isinstance(node, ast.Call)
            and _matches_expression(node, "self.master.after(50, poll_completion)")
        ]
        if len(thread_start_calls) != 1 or len(after_calls) != 2:
            errors.append("export_report: worker polling contract changed")
        export_browser_calls = _browser_open_calls(export_function)
        if (
            len(export_browser_calls) != 1
            or not _matches_expression(
                export_browser_calls[0],
                "webbrowser.open(local_file_uri(export_result.index_path))",
            )
        ):
            errors.append("export_report: browser URI dataflow changed")
        if len(_calls_named(export_function, "local_file_uri")) != 1:
            errors.append("export_report: URI encoder must be nested exactly once")
        forbidden_export_calls = {
            "analyze_similar_plates",
            "export_html",
            "get_all_plates",
        }
        if any(
            isinstance(node, ast.Attribute)
            and node.attr in forbidden_export_calls
            for node in ast.walk(export_function)
        ):
            errors.append("export_report: legacy mutable export path is reachable")

    if report_functions.get("export_html"):
        errors.append("report_panel.py: legacy export_html surface remains")

    if len(_browser_open_calls(progress_tree)) != 1:
        errors.append("progress_frame.py: unexpected browser-open site count")
    if len(_browser_open_calls(report_tree)) != 2:
        errors.append("report_panel.py: unexpected browser-open site count")

    return tuple(errors)


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
        parsed_rows = [
            cells
            for line in notice.splitlines()
            if len(cells := [cell.strip() for cell in line.split("|")[1:-1]]) == 3
            and cells[0].startswith("`")
        ]
        filenames = [cells[0] for cells in parsed_rows]
        self.assertEqual(len(WRAPPER_HASHES), len(parsed_rows))
        self.assertEqual(len(filenames), len(set(filenames)))

        notice_rows = {cells[0]: cells for cells in parsed_rows}
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
            "Source-verified RTSP quarantine",
            "The GUI does not solicit an endpoint",
            "Do not treat RTSP as a working feature.",
            "Python tracebacks retain frame locals",
            "RTSP-specific, not a general URI or network sandbox",
            "No camera stream was opened",
            "source-only evidence, not camera runtime evidence",
            "python3 rtsp_evidence.py --check",
            "evidence/rtsp-quarantine-v1.json",
            "docs/assets/rtsp-quarantine-cli.svg",
            "docs/assets/rtsp-quarantine-flow.svg",
            "docs/assets/rtsp-quarantine-matrix.svg",
            "not a complete filesystem sandbox",
            "Existing artifacts whose names were derived by older code are not renamed or migrated",
            "Source-verified redacted offline reports",
            "Version one has one privacy mode: `redacted-v1`.",
            "Stored `plate_detections` rows are labelled observation records",
            "Redaction reduces exposure but does not guarantee anonymity",
            "requires Python 3.11+",
            "lowers `SQLITE_LIMIT_LENGTH`",
            "Confidence aggregation uses `math.fsum`",
            "regenerates both HTML and SVG byte-for-byte",
            "bounds manifest nesting and structural tokens",
            "The manifest is content-addressed, not signed.",
            "it does not establish who created it",
            "python3 report_export.py export",
            "content-addressed directory",
            "Reproduce the synthetic browser demo",
            "python3 report_evidence.py --check",
            "tools/capture_offline_report.sh",
            "docs/assets/offline-report-browser.png",
            "docs/assets/offline-report-cli.svg",
            "docs/assets/offline-report-flow.svg",
            "docs/assets/offline-report-privacy.svg",
            "evidence/offline-report-v1.json",
            "fixed synthetic SQLite fixture",
            "4 report-local records, 9 observation rows, 8 scored observations",
            "not recognition accuracy, a benchmark, or surveillance output",
            "It is not a Tkinter, DTK, video, LPR, or camera screenshot.",
            "`--check` never launches Docker or a browser and never changes tracked artifacts",
            "The tooling never auto-accepts it.",
            "The generated suffix namespace is reserved",
            (
                "Raw recognition text remains in legacy database, UI, "
                "matching/cache, and logging flows; only the new managed "
                "filenames use derived components."
            ),
            "Logging redaction is a later rehabilitation stage.",
            (
                "imports the project-owned `path_policy`, `rtsp_policy`, "
                "`rtsp_evidence`, `report_export`, and `report_evidence` modules"
            ),
            (
                "does not import the GUI, mutable database wrapper, vendor "
                "wrappers, or native runtime"
            ),
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

    def test_security_policy_states_the_path_policy_limits(self) -> None:
        security = " ".join(SECURITY.read_text(encoding="utf-8").split())
        required_statements = {
            "not a complete filesystem sandbox or authorization boundary",
            "subject to the collision resistance of the truncated SHA-256 digest",
            (
                "Raw recognition text remains in legacy database, UI, "
                "matching/cache, and logging flows; only the new managed "
                "filenames use derived components."
            ),
            "Logging redaction is a later rehabilitation stage.",
            "No legacy artifact migration is included.",
            "Redacted offline-report boundary",
            "SQLite URI `mode=ro`",
            "Version-one bundles are always `redacted-v1`",
            "It copies no source images",
            "Redacted aggregates can still enable re-identification",
            "fails closed unless the runtime exposes `SQLITE_LIMIT_LENGTH`",
            "`math.fsum` aggregation keeps equal confidence multisets deterministic",
            "both HTML and SVG must equal a byte-exact regeneration",
            "pre-parse complexity scan bounds JSON structure",
            "do not prove authorship, source-database provenance, or truth",
            "same-user adversary can race parent-directory changes",
            "This boundary is RTSP-specific, not a general URI or network sandbox.",
            "Python tracebacks retain frame locals",
            "never substitute a real camera URL",
            "secure memory erasure",
            "Fixed synthetic evidence and browser-capture boundary",
            "accepts no database, URL, image, timestamp, profile, plate identifier",
            "Never substitute a real application database",
            "no ancillary text, time, profile, EXIF, or trailing data",
            "uses the already-cached container by full digest with `--pull=never`",
            "Chromium runs with `--no-sandbox`",
            "Docker daemon, host kernel/CPU",
            "never auto-bless drift",
            "no secure-memory or secure-erasure claim",
            "not authorship, the identity or truth of a source database",
        }
        for statement in required_statements:
            with self.subTest(statement=statement):
                self.assertIn(statement, security)

    def test_static_architecture_edges_are_bound_to_direct_imports(self) -> None:
        readme = README.read_text(encoding="utf-8")
        bindings = (
            ("main.py", "database", "GUI --> DB"),
            ("main.py", "processing_manager", 'GUI --> Manager["VideoProcessingManager'),
            ("main.py", "rtsp_policy", "GUI --> RTSPPolicy"),
            ("processing_manager.py", "database", "Manager --> DB"),
            ("processing_manager.py", "video_processor", 'Manager --> Processor["VideoProcessor'),
            ("processing_manager.py", "rtsp_policy", "Manager --> RTSPPolicy"),
            ("video_processor.py", "DTKLPR5", "Processor --> LPRWrapper"),
            ("video_processor.py", "DTKVID", "Processor --> VIDWrapper"),
            ("video_processor.py", "database", "Processor --> DB"),
            ("video_processor.py", "path_policy", "Processor --> PathPolicy"),
            ("progress_frame.py", "path_policy", "Progress --> PathPolicy"),
            ("report_panel.py", "path_policy", "Reports --> PathPolicy"),
            (
                "report_panel.py",
                "report_export",
                'Reports --> ReportExport["report_export.py',
            ),
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

    def test_path_policy_usage_is_bound_to_the_edited_source_sites(self) -> None:
        video_source = (ROOT / "video_processor.py").read_text(encoding="utf-8")
        self.assertEqual((), video_write_policy_errors(video_source))

        progress_source = (ROOT / "progress_frame.py").read_text(encoding="utf-8")
        report_source = (ROOT / "report_panel.py").read_text(encoding="utf-8")
        self.assertEqual(
            (),
            browser_policy_errors(progress_source, report_source),
        )

        self.assertEqual(
            {
                "__future__",
                "hashlib",
                "os",
                "pathlib",
                "re",
                "unicodedata",
            },
            imported_roots("path_policy.py"),
        )
        self.assertEqual(
            {
                "__future__",
                "dataclasses",
                "ipaddress",
                "re",
                "urllib",
            },
            imported_roots("rtsp_policy.py"),
        )
        self.assertEqual(
            {
                "__future__",
                "argparse",
                "ast",
                "hashlib",
                "html",
                "json",
                "os",
                "pathlib",
                "re",
                "rtsp_policy",
                "sys",
                "tempfile",
                "typing",
            },
            imported_roots("rtsp_evidence.py"),
        )
        self.assertEqual(
            {
                "__future__",
                "argparse",
                "dataclasses",
                "errno",
                "hashlib",
                "html",
                "json",
                "math",
                "os",
                "pathlib",
                "re",
                "shutil",
                "sqlite3",
                "stat",
                "sys",
                "tempfile",
                "typing",
                "xml",
            },
            imported_roots("report_export.py"),
        )
        self.assertEqual(
            {
                "__future__",
                "argparse",
                "ast",
                "hashlib",
                "html",
                "json",
                "os",
                "pathlib",
                "re",
                "report_export",
                "sqlite3",
                "stat",
                "struct",
                "sys",
                "tempfile",
                "typing",
                "zlib",
            },
            imported_roots("report_evidence.py"),
        )

    def test_video_write_policy_rejects_dead_calls_and_broken_dataflow(self) -> None:
        source = (ROOT / "video_processor.py").read_text(encoding="utf-8")

        def replace_first(old: str, new: str) -> str:
            self.assertIn(old, source)
            return source.replace(old, new, 1)

        mutations = {
            "dead sanitizer beside raw assignment": replace_first(
                "plate_component = safe_path_component(pt)",
                "plate_component = pt\n"
                "            safe_path_component(pt)",
            ),
            "sanitizer hidden in dead branch": replace_first(
                "            plate_component = safe_path_component(plate_text)",
                "            if False:\n"
                "                plate_component = safe_path_component(plate_text)",
            ),
            "raw plate enters managed filename": replace_first(
                'f"{plate_component}_plate_{timestamp_component}.jpg",',
                'f"{plate_text}_plate_{timestamp_component}.jpg",',
            ),
            "dead managed call beside raw assignment": replace_first(
                "            pp = managed_path(\n"
                '                "detection_history",\n'
                "                plate_component,\n"
                '                f"{plate_component}_plate_'
                '{timestamp_component}.jpg",\n'
                "            )",
                "            managed_path(\n"
                '                "detection_history",\n'
                "                plate_component,\n"
                '                f"{plate_component}_plate_'
                '{timestamp_component}.jpg",\n'
                "            )\n"
                '            pp = f"detection_history/'
                '{plate_component}_plate.jpg"',
            ),
            "image save bypasses managed variable": replace_first(
                "plate.GetPlateImage().save(pp)",
                'plate.GetPlateImage().save("outside.jpg")',
            ),
            "history DB receives non-string path": replace_first(
                "                str(fp),\n"
                "            )",
                "                fp,\n"
                "            )",
            ),
            "blacklist DB receives non-string path": replace_first(
                "self.db.add_blacklist_alert(plate.Text(), str(fp))",
                "self.db.add_blacklist_alert(plate.Text(), fp)",
            ),
        }
        for label, mutated_source in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    video_write_policy_errors(mutated_source),
                    f"mutation escaped structural verifier: {label}",
                )

    def test_browser_policy_rejects_dead_calls_and_broken_dataflow(self) -> None:
        progress_source = (ROOT / "progress_frame.py").read_text(encoding="utf-8")
        report_source = (ROOT / "report_panel.py").read_text(encoding="utf-8")

        mutations = {
            "progress dead sanitizer": (
                progress_source.replace(
                    "plate_component = safe_path_component("
                    "str(detection['plate_text']))",
                    "plate_component = str(detection['plate_text'])\n"
                    "                    safe_path_component("
                    "str(detection['plate_text']))",
                    1,
                ),
                report_source,
            ),
            "progress folder bypass": (
                progress_source.replace(
                    'managed_path("detection_history", plate_component)',
                    "managed_path("
                    '"detection_history", str(detection[\'plate_text\']))',
                    1,
                ),
                report_source,
            ),
            "progress missing directory guard": (
                progress_source.replace(
                    "if folder_path.is_dir():",
                    "if True:",
                    1,
                ),
                report_source,
            ),
            "report folder bypass": (
                progress_source,
                report_source.replace(
                    'managed_path("detection_history", plate_component)',
                    "managed_path("
                    '"detection_history", str(plate_text))',
                    1,
                ),
            ),
            "export dead URI encoder": (
                progress_source,
                report_source.replace(
                    "webbrowser.open(local_file_uri(export_result.index_path))",
                    "webbrowser.open(str(export_result.index_path))\n"
                    "                    local_file_uri(export_result.index_path)",
                    1,
                ),
            ),
            "export bypasses immutable boundary": (
                progress_source,
                report_source.replace(
                    "export_result = export_offline_report(self.db.path, output_parent)",
                    "export_result = self.export_html("
                    "output_parent, self.db.get_all_plates())",
                    1,
                ),
            ),
            "export opens selected parent": (
                progress_source,
                report_source.replace(
                    "webbrowser.open(local_file_uri(export_result.index_path))",
                    "webbrowser.open(local_file_uri(output_parent))",
                    1,
                ),
            ),
            "export worker runs synchronously": (
                progress_source,
                report_source.replace(
                    "target=run_export,",
                    "target=finish_export,",
                    1,
                ),
            ),
            "export worker blocks process exit": (
                progress_source,
                report_source.replace(
                    "            daemon=True,",
                    "            daemon=False,",
                    1,
                ),
            ),
        }
        for label, (mutated_progress, mutated_report) in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    browser_policy_errors(mutated_progress, mutated_report),
                    f"mutation escaped browser verifier: {label}",
                )

    def test_production_source_forbids_shell_execution(self) -> None:
        production_sources: dict[str, str] = {}
        for path in repository_candidates():
            relative = path.relative_to(ROOT)
            if path.suffix == ".py" and relative.parts[0] != "tests":
                production_sources[relative.as_posix()] = path.read_text(
                    encoding="utf-8"
                )
        self.assertTrue(production_sources)
        self.assertEqual((), production_execution_errors(production_sources))

    def test_shell_execution_gate_rejects_ast_mutations(self) -> None:
        mutations = {
            "attribute system": "import os\nos.system('synthetic')\n",
            "attribute startfile alias": (
                "import os as operating_system\n"
                "operating_system.startfile('synthetic')\n"
            ),
            "from import alias": (
                "from os import system as launch\nlaunch('synthetic')\n"
            ),
            "literal getattr": (
                "import os\ngetattr(os, 'startfile')('synthetic')\n"
            ),
            "shell true": (
                "import subprocess\n"
                "subprocess.run(['synthetic'], shell=True)\n"
            ),
        }
        for label, source in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    production_execution_errors({"synthetic.py": source}),
                    f"mutation escaped execution gate: {label}",
                )

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
