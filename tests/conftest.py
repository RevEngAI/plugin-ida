import json
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Mirror reai_toolkit_entry
def _add_vendor_paths() -> None:
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    roots = [ROOT, os.path.join(ROOT, "reai_toolkit")]
    suffixes = [
        "vendor",
        "vendor/site-packages",
        "vendor/Lib/site-packages",
        f"vendor/lib/{pyver}/site-packages",
        f"vendor/{pyver}/site-packages",
    ]
    for root in roots:
        for suf in suffixes:
            p = os.path.join(root, suf)
            if os.path.isdir(p) and p not in sys.path:
                sys.path.insert(0, p)


# Required ida imports
if "IDADIR" not in os.environ:
    try:
        with open(os.path.expanduser("~/.idapro/ida-config.json")) as fh:
            os.environ["IDADIR"] = json.load(fh)["Paths"]["ida-install-dir"]
    except (OSError, KeyError, ValueError):
        pass

_ida_usr = os.path.join(tempfile.gettempdir(), "ida-tests-usr")
os.makedirs(_ida_usr, exist_ok=True)

os.environ["IDAUSR"] = _ida_usr

try:
    import idapro  # noqa: F401  boots the IDA kernel so ida_* imports resolve
except ImportError as e:
    raise pytest.UsageError(
        f"idalib is not importable: {e}\n"
        "Run py-activate-idalib.py from your IDA install once, or set IDADIR "
        "to the IDA installation directory."
    )

# idapro reinitializes sys.path, so add vendor + repo root afterwards.
_add_vendor_paths()
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
