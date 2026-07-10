import json
import os
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.ida_ui

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ida_ui_runner.py")
HELLO_ELF = os.path.join(ROOT, "tests", "fixtures", "hello.elf")


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


@pytest.mark.skipif(
    os.environ.get("REAI_UI_TESTS") != "1",
    reason="GUI IDA test; set REAI_UI_TESTS=1 to enable",
)
def test_sync_never_opens_or_switches_pseudocode(tmp_path):
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
    env = dict(
        os.environ,
        REAI_UI_REPORT=str(report_path),
        REAI_UI_ROOT=ROOT,
        **_headless_env(),
    )

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

    assert report["errors"] == []
    assert report["ok"] is True
    assert report["target_count"] > 0
    assert report["import_failed_ids"] == []
    assert report["functions_imported"] == report["target_count"]
    assert report["functions_read"] == report["target_count"]

    assert report["pseudocode_opens"] == []
    assert report["pseudocode_switches"] == []
    assert report["final_vdui_ea"] == report["baseline_ea"]
    assert report["screen_ea_after"] == report["screen_ea_before"]
