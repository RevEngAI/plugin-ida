import pytest

from reai_toolkit.app.core import config_service as svc_mod
from reai_toolkit.app.core.config_service import ConfigService


@pytest.fixture
def ida_user_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(svc_mod.idaapi, "get_user_idadir", lambda: str(tmp_path))
    return tmp_path


def test_defaults_when_no_config_present(ida_user_dir):
    cfg = ConfigService()

    assert cfg.api_url == svc_mod._DEFAULT_API_URL
    assert cfg.portal_url == svc_mod._DEFAULT_PORTAL_URL
    assert cfg.api_key == ""
    assert cfg.valid() is False


def test_first_init_writes_config_file(ida_user_dir):
    ConfigService()
    assert (ida_user_dir / ".reai.cfg").exists()


def test_urls_are_normalised(ida_user_dir):
    cfg = ConfigService()

    cfg.api_url = "https://api.example.com/"
    cfg.portal_url = "  https://portal.example.com/  "
    cfg.api_key = "  token  "

    assert cfg.api_url == "https://api.example.com"
    assert cfg.portal_url == "https://portal.example.com"
    assert cfg.api_key == "token"


def test_empty_url_falls_back_to_default(ida_user_dir):
    cfg = ConfigService()
    cfg.api_url = None
    assert cfg.api_url == svc_mod._DEFAULT_API_URL


def test_valid_when_all_fields_set(ida_user_dir):
    cfg = ConfigService()
    cfg.api_key = "token"
    assert cfg.valid() is True


def test_config_persists_across_instances(ida_user_dir):
    cfg = ConfigService()
    cfg.api_url = "https://api.example.com"
    cfg.api_key = "token"
    cfg.save()

    reloaded = ConfigService()
    assert reloaded.api_url == "https://api.example.com"
    assert reloaded.api_key == "token"


def test_as_dict_returns_copy(ida_user_dir):
    cfg = ConfigService()
    d = cfg.as_dict()
    d["api_key"] = "mutated"
    assert cfg.api_key == ""
