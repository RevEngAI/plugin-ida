"""Bump the `revengai` SDK floor in pyproject.toml to the latest PyPI release.

Emits GitHub Actions outputs on stdout (`key=value` lines) describing the
result. Designed to be invoked as:

    python .github/scripts/bump_revengai.py >> "$GITHUB_OUTPUT"

When run locally, the outputs print to the terminal and the file is edited
in place. Run `git restore pyproject.toml` to undo.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

from packaging.version import Version

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"
PYPI_URL = "https://pypi.org/pypi/revengai/json"

SDK_PIN_RE = re.compile(r'"revengai>=([\d.]+)"')
PLUGIN_VERSION_RE = re.compile(r'^version = "([\d.]+)"', re.MULTILINE)


def fetch_latest_pypi_version() -> str:
    with urllib.request.urlopen(PYPI_URL, timeout=30) as resp:
        data = json.load(resp)
    return data["info"]["version"]


def bump_patch(version: str) -> str:
    parts = [int(p) for p in version.split(".")]
    parts[-1] += 1
    return ".".join(str(p) for p in parts)


def emit(key: str, value: str) -> None:
    print(f"{key}={value}")


def main() -> int:
    text = PYPROJECT.read_text()

    sdk_match = SDK_PIN_RE.search(text)
    if not sdk_match:
        print("error: could not find revengai pin in pyproject.toml", file=sys.stderr)
        return 1
    current_sdk = sdk_match.group(1)

    plugin_match = PLUGIN_VERSION_RE.search(text)
    if not plugin_match:
        print("error: could not find plugin version in pyproject.toml", file=sys.stderr)
        return 1
    current_plugin = plugin_match.group(1)

    latest_sdk = fetch_latest_pypi_version()

    emit("current_sdk", current_sdk)
    emit("new_sdk", latest_sdk)
    emit("current_plugin", current_plugin)

    if Version(latest_sdk) <= Version(current_sdk):
        emit("changed", "false")
        emit("new_plugin", current_plugin)
        return 0

    new_plugin = bump_patch(current_plugin)
    new_text = text.replace(
        f'"revengai>={current_sdk}"',
        f'"revengai>={latest_sdk}"',
    ).replace(
        f'version = "{current_plugin}"',
        f'version = "{new_plugin}"',
        1,
    )
    PYPROJECT.write_text(new_text)

    emit("new_plugin", new_plugin)
    emit("changed", "true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
