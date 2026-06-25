import hashlib

from revengai import ApiException, BaseResponse

from reai_toolkit.app.core.utils import parse_exception, sha256_file


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
