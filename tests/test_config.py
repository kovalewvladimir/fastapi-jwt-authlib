from fastapi_jwt_authlib.auth import AuthJWT, SameSiteTypes


def test_config_empty_secret_key():
    """Test config with empty string as secret_key."""
    AuthJWT.config(secret_key="")
    assert AuthJWT._secret_key == ""  # pylint: disable=protected-access  # noqa: SLF001


def test_config_algorithm_variations():
    """Test config with different algorithm values."""
    for algo in ["HS256", "HS384", "HS512"]:
        AuthJWT.config(secret_key="test", algorithm=algo)  # noqa: S106
        assert AuthJWT.get_algorithm() == algo


def test_config_zero_token_lifetimes():
    """Test config with zero token lifetimes."""
    AuthJWT.config(
        secret_key="test",  # noqa: S106
        token_access_lifetime=0,
        token_refresh_lifetime=0,
    )
    assert AuthJWT.get_token_access_lifetime() == 0
    assert AuthJWT.get_token_refresh_lifetime() == 0


def test_config_negative_token_lifetimes():
    """Test config with negative token lifetimes."""
    AuthJWT.config(
        secret_key="test",  # noqa: S106
        token_access_lifetime=-100,
        token_refresh_lifetime=-1000,
    )
    assert AuthJWT.get_token_access_lifetime() == -100
    assert AuthJWT.get_token_refresh_lifetime() == -1000


def test_config_default_samesite():
    """Test that default samesite value is 'lax'."""
    AuthJWT.config(secret_key="test")  # noqa: S106
    assert AuthJWT.get_cookie_samesite() == "lax"


def test_config_samesite_variations():
    """Test config with different samesite values."""
    samesite_values: list[SameSiteTypes] = ["lax", "strict", "none"]
    for samesite in samesite_values:
        AuthJWT.config(secret_key="test", cookie_samesite=samesite)  # noqa: S106
        assert AuthJWT.get_cookie_samesite() == samesite
