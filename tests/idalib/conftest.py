import os

import pytest

import idapro

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
HELLO_ELF = os.path.join(FIXTURES_DIR, "hello.elf")


@pytest.fixture(scope="session")
def loaded_binary():
    """Open hello.elf once under headless idalib for the whole idalib session."""
    if not os.path.isfile(HELLO_ELF):
        pytest.skip(f"missing fixture {HELLO_ELF} (see tests/README.md to rebuild)")
    if idapro.open_database(os.path.abspath(HELLO_ELF), True) != 0:
        pytest.fail("idapro.open_database failed")
    try:
        yield os.path.abspath(HELLO_ELF)
    finally:
        idapro.close_database(False)
