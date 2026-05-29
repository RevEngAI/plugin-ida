from revengai import ConfigApi


def test_auth_verification_method_exists():
    assert callable(getattr(ConfigApi, "get_config", None))
