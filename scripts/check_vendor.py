import re
import subprocess
import sys
from pathlib import Path

from packaging.markers import Marker

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "reai_toolkit" / "vendor"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)\s*(?:;\s*(.+))?$")


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def locked():
    out = subprocess.run(
        ["uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--no-hashes"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    pinned = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        match = PIN.match(line)
        if not match:
            continue
        name, version, marker = match.groups()
        if marker and not Marker(marker).evaluate():
            continue
        pinned[normalise(name)] = version
    return pinned


def vendored():
    found = {}
    for dist in VENDOR.glob("*.dist-info"):
        name, _, version = dist.name[: -len(".dist-info")].rpartition("-")
        if name:
            found[normalise(name)] = version
    return found


def main():
    if not VENDOR.is_dir():
        print(f"vendor tree missing at {VENDOR}; run scripts/build_vendor.sh", file=sys.stderr)
        return 1

    want = locked()
    have = vendored()
    problems = []

    for name, version in sorted(want.items()):
        if name not in have:
            problems.append(f"  missing: {name}=={version}")
        elif have[name] != version:
            problems.append(f"  mismatch: {name} vendored {have[name]}, lock wants {version}")

    for name, version in sorted(have.items()):
        if name not in want:
            problems.append(f"  unexpected: {name}=={version} is vendored but not in uv.lock")

    if problems:
        print("vendor tree does not match uv.lock:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print("\nrun scripts/build_vendor.sh to rebuild", file=sys.stderr)
        return 1

    print(f"vendor tree matches uv.lock ({len(want)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
