from unittest.mock import MagicMock

import pytest
from revengai import ApiException

from reai_toolkit.app.services.auth import auth_service as svc_mod
from reai_toolkit.app.services.auth.auth_service import AuthService


@pytest.fixture
def cfg():
    c = MagicMock()
    c.api_url = "https://api.reveng.ai"
    c.api_key = "secret-key"
    return c


@pytest.fixture
def service(cfg):
    return AuthService(cfg=cfg, ida_version="9.3", plugin_version="1.2.3")


@pytest.fixture
def config_api(mocker):
    mocker.patch.object(svc_mod, "ApiClient")
    api_class = mocker.patch.object(svc_mod, "ConfigApi")
    inst = MagicMock()
    api_class.return_value = inst
    return inst


def test_build_sdk_config_sets_host_key_and_user_agent(service):
    cfg = service.build_sdk_config()

    assert cfg.host == "https://api.reveng.ai"
    assert cfg.api_key == {"APIKey": "secret-key"}
    assert cfg.user_agent == "IDA/9.3 RevEng.AI_Plugin/1.2.3"


def test_get_sdk_config_builds_once_and_mutates_in_place(service):
    first = service.get_sdk_config()
    service.config_service.api_url = "https://other.host"
    service.config_service.api_key = "new-key"

    second = service.build_sdk_config()

    assert first is second
    assert second.host == "https://other.host"
    assert second.api_key == {"APIKey": "new-key"}


def test_verify_success(service, config_api):
    config_api.get_config.return_value = MagicMock()

    ok, msg = service.verify()

    assert ok is True
    assert msg == ""
    assert service.is_authenticated() is True


def test_verify_api_exception_with_parsed_errors(service, config_api, mocker):
    config_api.get_config.side_effect = ApiException(status=401)
    mocker.patch.object(
        svc_mod,
        "parse_exception",
        return_value=MagicMock(errors=[MagicMock(code="401", message="bad key")]),
    )

    ok, msg = service.verify()

    assert ok is False
    assert msg == "401: bad key"
    assert service.is_authenticated() is False


def test_verify_api_exception_without_parsed_body(service, config_api, mocker):
    config_api.get_config.side_effect = ApiException(status=500, reason="boom")
    mocker.patch.object(svc_mod, "parse_exception", return_value=None)

    ok, msg = service.verify()

    assert ok is False
    assert msg.startswith("API Exception:")
    assert service.is_authenticated() is False


def test_verify_unexpected_exception(service, config_api):
    config_api.get_config.side_effect = RuntimeError("network down")

    ok, msg = service.verify()

    assert ok is False
    assert "network down" in msg
    assert service.is_authenticated() is False
