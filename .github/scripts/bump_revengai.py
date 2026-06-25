"""Bump the `revengai` SDK floor in pyproject.toml to the latest PyPI release.

Emits GitHub Actions outputs on stdout (`key=value` lines) describing the
result. Designed to be invoked as:

    python .github/scripts/bump_revengai.py >> "$GITHUB_OUTPUT"

The plugin version is sourced from git tags (see release.yaml) and stays pinned
at 0.0.1 in pyproject.toml, so this script touches only the SDK pin.
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


def fetch_latest_pypi_version() -> str:
    with urllib.request.urlopen(PYPI_URL, timeout=30) as resp:
        return json.load(resp)["info"]["version"]


def emit(key: str, value: str) -> None:
    print(f"{key}={value}")


def main() -> int:
    text = PYPROJECT.read_text()

    sdk_match = SDK_PIN_RE.search(text)
    if not sdk_match:
        print("error: could not find revengai pin in pyproject.toml", file=sys.stderr)
        return 1
    current_sdk = sdk_match.group(1)

    latest_sdk = fetch_latest_pypi_version()

    emit("current_sdk", current_sdk)
    emit("new_sdk", latest_sdk)

    if Version(latest_sdk) <= Version(current_sdk):
        emit("changed", "false")
        return 0

    PYPROJECT.write_text(
        text.replace(f'"revengai>={current_sdk}"', f'"revengai>={latest_sdk}"')
    )
    emit("changed", "true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
