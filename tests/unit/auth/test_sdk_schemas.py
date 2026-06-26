from revengai import ConfigApi, IAMUsersApi, User


def test_auth_verification_method_exists():
    assert callable(getattr(ConfigApi, "get_config", None))


def test_iam_get_me_method_exists():
    assert callable(getattr(IAMUsersApi, "get_me", None))


def test_user_model_exposes_tier():
    assert "tier" in User.model_fields
