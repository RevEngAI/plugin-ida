from revengai import ConfigApi, GetConfigOutputBody, IAMUsersApi, User


def test_auth_verification_method_exists():
    assert callable(getattr(ConfigApi, "v3_get_config", None))


def test_config_output_body_exposes_max_file_size_bytes():
    assert "max_file_size_bytes" in GetConfigOutputBody.model_fields


def test_iam_get_me_method_exists():
    assert callable(getattr(IAMUsersApi, "get_me", None))


def test_user_model_exposes_tier():
    assert "tier" in User.model_fields
