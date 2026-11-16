import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "ida-plugin.json"
BLOCK = re.compile(r'("pythonDependencies": \[)(.*?)(\n *\])', re.S)


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def direct():
    # no tomllib on 3.10, the block is simple enough to pull out by hand
    text = (ROOT / "pyproject.toml").read_text()
    block = re.search(r"^dependencies = \[(.*?)^\]", text, re.M | re.S).group(1)
    return [re.match(r"[A-Za-z0-9._-]+", d).group(0) for d in re.findall(r'"([^"]+)"', block)]


def locked():
    text = (ROOT / "uv.lock").read_text()
    versions = {}
    for name, version in re.findall(r'^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', text, re.M):
        versions.setdefault(normalise(name), set()).add(version)
    return versions


def build_dependencies():
    versions = locked()
    pins = []
    for name in direct():
        found = versions.get(normalise(name), set())
        if len(found) != 1:
            raise SystemExit(f"expected one locked version of {name}, found {sorted(found)}")
        pins.append(f"{name}=={found.pop()}")
    return pins


def serialize(current):
    body = "".join(f'\n      "{pin}",' for pin in build_dependencies()).rstrip(",")
    return BLOCK.sub(lambda m: m.group(1) + body + m.group(3), current, count=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    current = MANIFEST_PATH.read_text()
    content = serialize(current)
    if args.check:
        if current != content:
            print(
                "ida-plugin.json pythonDependencies are out of date; run: python scripts/emit_plugin_deps.py",
                file=sys.stderr,
            )
            return 1
        print("ida-plugin.json pythonDependencies are up to date.")
        return 0

    MANIFEST_PATH.write_text(content)
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
