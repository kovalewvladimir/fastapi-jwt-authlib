import pytest

from fastapi_jwt_authlib.auth import AuthJWT


@pytest.fixture(autouse=True)
def reset_auth_config():
    """Reset AuthJWT config before each test to avoid state pollution."""
    yield
    # Reset to defaults after each test
    AuthJWT.config(
        secret_key="test_secret",
        algorithm="HS256",
        cookie_access_key="__Host-access_token",
        cookie_refresh_key="__Host-refresh_token",
        cookie_access_path="/",
        cookie_refresh_path="/",
        cookie_secure=False,
        token_access_lifetime=15 * 60,
        token_refresh_lifetime=2 * 24 * 60 * 60,
    )


def test_config_missing_secret_key():
    """Test that config raises error when secret_key is missing."""
    with pytest.raises(TypeError):
        AuthJWT.config()


def test_config_empty_secret_key():
    """Test config with empty string as secret_key."""
    AuthJWT.config(secret_key="")
    assert AuthJWT._secret_key == ""  # pylint: disable=protected-access


def test_config_algorithm_variations():
    """Test config with different algorithm values."""
    for algo in ["HS256", "HS384", "HS512"]:
        AuthJWT.config(secret_key="test", algorithm=algo)
        assert AuthJWT._algorithm == algo  # pylint: disable=protected-access


def test_config_zero_token_lifetimes():
    """Test config with zero token lifetimes."""
    AuthJWT.config(
        secret_key="test",
        token_access_lifetime=0,
        token_refresh_lifetime=0,
    )
    assert AuthJWT._token_access_lifetime == 0  # pylint: disable=protected-access
    assert AuthJWT._token_refresh_lifetime == 0  # pylint: disable=protected-access


def test_config_negative_token_lifetimes():
    """Test config with negative token lifetimes."""
    AuthJWT.config(
        secret_key="test",
        token_access_lifetime=-100,
        token_refresh_lifetime=-1000,
    )
    assert AuthJWT._token_access_lifetime == -100  # pylint: disable=protected-access
    assert AuthJWT._token_refresh_lifetime == -1000  # pylint: disable=protected-access
