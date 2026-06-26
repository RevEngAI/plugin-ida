import pytest

from reai_toolkit.app.core.utils import (
    collect_symbols_from_ida,
    demangle,
    get_function_boundaries_hash,
)

pytestmark = pytest.mark.idalib


def test_collect_symbols_returns_boundaries(loaded_binary):
    symbols = collect_symbols_from_ida()

    assert symbols.base_address > 0
    names = {fb.mangled_name for fb in symbols.function_boundaries}
    assert "main" in names
    for fb in symbols.function_boundaries:
        assert fb.end_address >= fb.start_address


def test_boundaries_hash_is_stable_hex_digest(loaded_binary):
    first = get_function_boundaries_hash()
    second = get_function_boundaries_hash()

    assert first == second
    assert len(first) == 64
    int(first, 16)  # hex-decodable


def test_demangle_passthrough_for_plain_name(loaded_binary):
    assert demangle("main") == "main"


def test_demangle_resolves_mangled_name(loaded_binary):
    assert "foo" in demangle("_Z3foov")
