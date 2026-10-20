import hashlib
from unittest.mock import MagicMock

import pytest

from revengai import ApiException, BaseResponse

from reai_toolkit.app.core import utils
from reai_toolkit.app.core.utils import (
    MAX_FUNCTION_BOUNDARIES,
    MAX_MANGLED_NAME_LENGTH,
    build_function_boundary,
    build_symbols,
    parse_exception,
    sha256_file,
)


@pytest.fixture
def fake_logger(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(utils, "logger", logger)
    return logger


def test_parse_exception_returns_base_response_for_json_body():
    exc = ApiException(status=400)
    exc.body = '{"status": false, "message": "bad request", "errors": []}'

    parsed = parse_exception(exc)

    assert isinstance(parsed, BaseResponse)
    assert parsed.message == "bad request"


def test_parse_exception_returns_none_for_non_json_body():
    exc = ApiException(status=500)
    exc.body = "<html>gateway error</html>"

    assert parse_exception(exc) is None


def test_parse_exception_returns_none_when_body_empty():
    exc = ApiException(status=500)
    exc.body = None

    assert parse_exception(exc) is None


def test_sha256_file_matches_hashlib(tmp_path):
    payload = b"\x7fELF\x02\x01\x01\x00 hello world"
    f = tmp_path / "blob.bin"
    f.write_bytes(payload)

    assert sha256_file(f) == hashlib.sha256(payload).hexdigest()


def test_sha256_file_handles_multichunk(tmp_path):
    payload = b"A" * (1024 * 1024 * 2 + 7)
    f = tmp_path / "big.bin"
    f.write_bytes(payload)

    assert sha256_file(f, chunk_size=1024) == hashlib.sha256(payload).hexdigest()


def test_build_function_boundary_skips_empty_mangled_name():
    assert build_function_boundary("", 0x1000, 0x1010) is None
    assert build_function_boundary(None, 0x1000, 0x1010) is None


def test_build_function_boundary_truncates_overlong_mangled_name():
    boundary = build_function_boundary("_Z" + "a" * 8192, 0x1000, 0x1010)

    assert boundary is not None
    assert len(boundary.mangled_name) == MAX_MANGLED_NAME_LENGTH
    assert boundary.mangled_name.startswith("_Za")


def test_build_function_boundary_skips_negative_addresses():
    assert build_function_boundary("main", -1, 0x10) is None
    assert build_function_boundary("main", 0x10, -1) is None


def test_build_function_boundary_keeps_valid_entry():
    boundary = build_function_boundary("main", 0x1000, 0x1010)

    assert boundary.mangled_name == "main"
    assert boundary.start_address == 0x1000
    assert boundary.end_address == 0x1010


def test_build_symbols_caps_function_boundaries(fake_logger):
    boundary = build_function_boundary("main", 0x1000, 0x1010)

    symbols = build_symbols(0x400000, [boundary] * (MAX_FUNCTION_BOUNDARIES + 25))

    assert len(symbols.function_boundaries) == MAX_FUNCTION_BOUNDARIES
    fake_logger.warning.assert_called_once()


def test_build_symbols_keeps_list_under_cap(fake_logger):
    boundary = build_function_boundary("main", 0x1000, 0x1010)

    symbols = build_symbols(0x400000, [boundary])

    assert symbols.base_address == 0x400000
    assert len(symbols.function_boundaries) == 1
    fake_logger.warning.assert_not_called()


def test_build_symbols_clamps_negative_base_address():
    assert build_symbols(-1, []).base_address == 0
