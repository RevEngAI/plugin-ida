from unittest.mock import MagicMock

import pytest
from revengai import ApiException

from reai_toolkit.app.interfaces import base_service as base_mod
from reai_toolkit.app.interfaces.base_service import BaseService


def _raise(exc):
    def fn():
        raise exc

    return fn


def test_api_request_returning_success_carries_data():
    result = BaseService.api_request_returning(lambda: "payload")

    assert result.success is True
    assert result.data == "payload"


def test_api_request_returning_parses_api_exception_errors(mocker):
    mocker.patch.object(
        base_mod,
        "parse_exception",
        return_value=MagicMock(errors=[MagicMock(code="404", message="missing")]),
    )

    result = BaseService.api_request_returning(_raise(ApiException(status=404)))

    assert result.success is False
    assert result.error_message == "404: missing"


def test_api_request_returning_api_exception_without_body(mocker):
    mocker.patch.object(base_mod, "parse_exception", return_value=None)

    result = BaseService.api_request_returning(_raise(ApiException(status=500)))

    assert result.success is False
    assert result.error_message.startswith("API Exception:")


def test_api_request_returning_unexpected_error():
    result = BaseService.api_request_returning(_raise(RuntimeError("kaboom")))

    assert result.success is False
    assert "kaboom" in result.error_message


def test_api_request_no_return_success_has_no_data():
    called = MagicMock()

    result = BaseService.api_request_no_return(called, 1, key="v")

    assert result.success is True
    assert result.data is None
    called.assert_called_once_with(1, key="v")


def test_api_request_no_return_unexpected_error():
    result = BaseService.api_request_no_return(_raise(ValueError("bad")))

    assert result.success is False
    assert "bad" in result.error_message


def test_yield_api_client_propagates_user_agent_header(mocker):
    api_client = MagicMock()
    api_client.default_headers = {}
    mocker.patch.object(base_mod, "ApiClient", return_value=api_client)

    cfg = MagicMock()
    cfg.user_agent = "IDA/9.3 RevEng.AI_Plugin/1.0"

    with BaseService.yield_api_client(cfg) as client:
        assert client is api_client

    assert api_client.user_agent == "IDA/9.3 RevEng.AI_Plugin/1.0"
    assert api_client.default_headers["X-RevEng-Application"] == "IDA/9.3 RevEng.AI_Plugin/1.0"
