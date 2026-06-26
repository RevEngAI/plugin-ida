import os
import sys

import pytest

import idapro

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
HELLO_ELF = os.path.join(FIXTURES_DIR, "hello.elf")


def _diag(msg: str) -> None:
    print(f"[idalib] {msg}", file=sys.stderr, flush=True)


@pytest.fixture(scope="session")
def loaded_binary():
    """Open hello.elf once under headless idalib for the whole idalib session."""
    if not os.path.isfile(HELLO_ELF):
        pytest.skip(f"missing fixture {HELLO_ELF} (see tests/README.md to rebuild)")

    idadir = os.environ.get("IDADIR", "")
    idausr = os.environ.get("IDAUSR", "")
    _diag(f"IDADIR={idadir!r} IDAUSR={idausr!r}")
    _diag(f"$IDADIR/ida.reg exists={os.path.isfile(os.path.join(idadir, 'ida.reg'))}")
    _diag(f"IDAUSR files={os.listdir(idausr) if os.path.isdir(idausr) else 'MISSING'}")
    _diag(f"IDA_LICENSE set={'IDA_LICENSE' in os.environ}")

    idapro.enable_console_messages(True)
    rc = idapro.open_database(os.path.abspath(HELLO_ELF), True)
    _diag(f"open_database rc={rc}")
    if rc != 0:
        pytest.fail(f"idapro.open_database failed rc={rc}")
    try:
        yield os.path.abspath(HELLO_ELF)
    finally:
        idapro.close_database(False)
