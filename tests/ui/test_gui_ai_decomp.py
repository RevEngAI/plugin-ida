import json
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.ida_ui

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_decomp_ui_runner.py")
HELLO_ELF = os.path.join(ROOT, "tests", "fixtures", "hello.elf")

# IDA 9.0/9.1 never invoke get_lines_rendering_info under -A, so these only
# apply where the host delivers the callback at all (see rendering_hook_delivered).
REPAINT_CHECKS = {
    "rendering_hook_runs_on_repaint",
    "rendering_hook_sees_the_disassembly",
    "attributed_addresses_paint",
    "unattributed_lines_are_left_alone",
}

CHECKS = [
    "view_created",
    "editor_read_only",
    "only_identifiers_offer_rename",
    "render_shows_code",
    "rename_double_click_overrides",
    "rename_overrides_correct",
    "rename_non_token_info",
    "rename_non_token_reason",
    "rename_comment_line_reason",
    "rename_data_type_reason",
    "predicted_hidden_without_a_prediction",
    "predicted_shown_with_a_prediction",
    "predicted_button_renames",
    "predicted_hidden_when_cleared",
    "comment_add_sets",
    "comment_add_args_correct",
    "comment_edit_empty_removes",
    "comment_remove_deletes",
    "comment_remove_args_correct",
    "decomp_line_lights_its_disassembly",
    "a_line_with_no_counterpart_lights_nothing",
    "disassembly_ea_lights_its_decomp_line",
    "an_unattributed_address_lights_nothing",
    "rendering_hook_runs_on_repaint",
    "rendering_hook_sees_the_disassembly",
    "attributed_addresses_paint",
    "unattributed_lines_are_left_alone",
    "refresh_button_invalidates",
]


def _ida_gui_binary() -> str | None:
    path = os.path.join(os.environ.get("IDADIR", ""), "ida")
    return path if os.path.isfile(path) else None


def _ida_gui_running() -> bool:
    for name in ("ida", "ida64", "idat"):
        try:
            if subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0:
                return True
        except FileNotFoundError:
            return False
    return False


def _headless_env() -> dict[str, str]:
    if sys.platform == "linux" and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        return {"QT_QPA_PLATFORM": "offscreen"}
    return {}

def _isolated_idausr(tmp_path) -> dict[str, str]:
    # conftest points IDAUSR at one directory shared with the idalib session in
    # this process. The GUI IDA spawned below must not share it: with the same
    # IDAUSR it starts but never creates its windows, so OnCreate never runs.
    usr = tmp_path / "idausr"
    usr.mkdir(exist_ok=True)
    reg = os.path.join(os.environ.get("IDADIR", ""), "ida.reg")
    if os.path.isfile(reg):
        shutil.copy(reg, usr / "ida.reg")
    return {"IDAUSR": str(usr)}

def _ida_path_without_venv(env: dict[str, str]) -> dict[str, str]:
    # IDA's embedded Python resolves its site-packages from the first python3
    # on PATH. Under `uv run` that is the project venv, which carries PySide6 as
    # a dev dependency, so IDA 9.0/9.1 load Qt6 bindings into a Qt5 application
    # and PluginForm never builds its widgets. Drop the venv so IDA uses the Qt
    # binding it ships with.
    venv = env.get("VIRTUAL_ENV")
    if not venv:
        return env
    env = dict(env)
    env["PATH"] = os.pathsep.join(
        p for p in env.get("PATH", "").split(os.pathsep) if p and not p.startswith(venv)
    )
    return env


@pytest.mark.skipif(
    os.environ.get("REAI_UI_TESTS") != "1",
    reason="GUI IDA test; set REAI_UI_TESTS=1 to enable",
)
def test_ai_decomp_editing_flow_in_gui(tmp_path):
    ida = _ida_gui_binary()
    if ida is None:
        pytest.skip("IDADIR not set or ida binary missing")
    if _ida_gui_running():
        pytest.skip("an IDA instance is already running (license seat busy)")
    if not os.path.isfile(HELLO_ELF):
        pytest.skip(f"missing fixture {HELLO_ELF}")

    binary = tmp_path / "hello.elf"
    shutil.copy(HELLO_ELF, binary)
    report_path = tmp_path / "report.json"
    log_path = tmp_path / "ida.log"
    env = _ida_path_without_venv(dict(
        os.environ,
        REAI_UI_REPORT=str(report_path),
        REAI_UI_ROOT=ROOT,
        **_headless_env(),
        **_isolated_idausr(tmp_path),
    ))

    proc = subprocess.run(
        [ida, "-A", f"-S{RUNNER}", f"-L{log_path}", str(binary)],
        env=env,
        capture_output=True,
        timeout=300,
    )

    if not report_path.is_file():
        log = log_path.read_text() if log_path.is_file() else ""
        stderr = proc.stderr.decode(errors="replace")
        stdout = proc.stdout.decode(errors="replace")
        if "license" in log.lower() or "license" in stderr.lower():
            pytest.skip("IDA license unavailable")
        pytest.fail(
            f"IDA produced no report (rc={proc.returncode});"
            f"\nstderr tail:\n{stderr[-2000:]}"
            f"\nstdout tail:\n{stdout[-2000:]}"
            f"\nlog tail:\n{log[-2000:]}"
        )

    report = json.loads(report_path.read_text())

    assert report["errors"] == [], (
        f"{report['errors']}"
        f"\nreport: {report}"
        f"\nida log tail:\n{log_path.read_text()[-3000:] if log_path.is_file() else '(no log)'}"
    )
    assert report["ok"] is True
    delivered = report.get("rendering_hook_delivered", False)
    for check in CHECKS:
        if check in REPAINT_CHECKS and not delivered:
            continue
        assert report.get(check) is True, f"{check} failed: {report}"
