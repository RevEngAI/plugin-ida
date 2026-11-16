import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _manifest():
    with open(os.path.join(ROOT, "ida-plugin.json")) as fh:
        return json.load(fh)["plugin"]


def test_python_dependencies_match_uv_lock():
    result = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "emit_plugin_deps.py"), "--check"])

    assert result.returncode == 0


def test_entry_point_exists():
    assert os.path.isfile(os.path.join(ROOT, _manifest()["entryPoint"]))


def test_logo_exists():
    assert os.path.isfile(os.path.join(ROOT, _manifest()["logoPath"]))


def test_version_matches_entry_point():
    plugin = _manifest()
    with open(os.path.join(ROOT, plugin["entryPoint"])) as fh:
        match = re.search(r'^__PLUGIN_VERSION__ = "([^"]+)"', fh.read(), re.M)

    assert match and match.group(1) == plugin["version"]
