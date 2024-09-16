from http.cookies import SimpleCookie

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_jwt_authlib.auth import AuthJWT
from fastapi_jwt_authlib.depends import (
    AuthAccessContextDepends,
    AuthDepends,
    AuthRefreshContextDepends,
)
from fastapi_jwt_authlib.exception import AuthJWTException


def create_example_client():
    app = FastAPI()

    username = "example"

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(_request: Request, exc: AuthJWTException):
        return JSONResponse(status_code=exc.status_code, content={"error": {"detail": exc.message}})

    @app.post("/login")
    def login(auth: AuthDepends):
        auth.generate_and_store_access_token(subject=username)
        auth.generate_and_store_refresh_token(subject=username)
        return {"msg": "Successful login"}

    @app.delete("/logout")
    def logout(auth: AuthDepends):
        auth.unset_access_cookies()
        auth.unset_refresh_cookies()
        return {"msg": "Successful logout"}

    @app.post("/refresh")
    def refresh(auth: AuthRefreshContextDepends):
        auth.jwt.generate_and_store_access_token(subject=auth.user)
        return {"msg": "The token has been refresh"}

    @app.get("/protected")
    def protected(auth: AuthAccessContextDepends):
        return {"user": auth.user}

    return TestClient(app)


openapi_schema = {
    "openapi": "3.1.0",
    "info": {"title": "FastAPI", "version": "0.1.0"},
    "paths": {
        "/login": {
            "post": {
                "summary": "Login",
                "operationId": "login_login_post",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/logout": {
            "delete": {
                "summary": "Logout",
                "operationId": "logout_logout_delete",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/refresh": {
            "post": {
                "summary": "Refresh",
                "operationId": "refresh_refresh_post",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/protected": {
            "get": {
                "summary": "Protected",
                "operationId": "protected_protected_get",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
    },
}


def test_openapi_schema():
    client = create_example_client()
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    assert response.json() == openapi_schema


def test_login():
    client = create_example_client()
    response = client.post("/login")
    assert response.status_code == 200, response.text
    assert response.json() == {"msg": "Successful login"}


def test_logout():
    client = create_example_client()
    response = client.delete("/logout")
    assert response.status_code == 200, response.text
    assert response.json() == {"msg": "Successful logout"}

    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])

    access_key = AuthJWT._cookie_access_key  # pylint: disable=protected-access
    refresh_key = AuthJWT._cookie_refresh_key  # pylint: disable=protected-access

    access_token_cookie = cookies[access_key]
    assert access_token_cookie.value == ""
    assert access_token_cookie["max-age"] == "0"

    refresh_token_cookie = cookies[refresh_key]
    assert refresh_token_cookie.value == ""
    assert refresh_token_cookie["max-age"] == "0"


def test_cookies_secure():
    client = create_example_client()
    response = client.post("/login")
    assert response.status_code == 200, response.text

    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])

    access_key = AuthJWT._cookie_access_key  # pylint: disable=protected-access
    refresh_key = AuthJWT._cookie_refresh_key  # pylint: disable=protected-access

    access_token_cookie = cookies[access_key]
    assert access_token_cookie["httponly"]
    assert access_token_cookie["secure"] == ""

    refresh_token_cookie = cookies[refresh_key]
    assert refresh_token_cookie["httponly"]
    assert refresh_token_cookie["secure"] == ""


def test_cookies_value_lifetime():
    client = create_example_client()
    response = client.post("/login")
    assert response.status_code == 200, response.text

    cookies = SimpleCookie()
    cookies.load(response.headers["set-cookie"])

    access_key = AuthJWT._cookie_access_key  # pylint: disable=protected-access
    refresh_key = AuthJWT._cookie_refresh_key  # pylint: disable=protected-access
    secret_key = AuthJWT._secret_key  # pylint: disable=protected-access
    algorithm = AuthJWT._algorithm  # pylint: disable=protected-access
    token_access_lifetime = AuthJWT._token_access_lifetime  # pylint: disable=protected-access
    token_refresh_lifetime = AuthJWT._token_refresh_lifetime  # pylint: disable=protected-access

    access_token_cookie = cookies[access_key]
    decoded_access_token = jwt.decode(access_token_cookie.value, secret_key, algorithms=[algorithm])
    assert decoded_access_token["exp"] == decoded_access_token["iat"] + token_access_lifetime

    refresh_token_cookie = cookies[refresh_key]
    decoded_refresh_token = jwt.decode(refresh_token_cookie.value, secret_key, algorithms=[algorithm])
    assert decoded_refresh_token["exp"] == decoded_refresh_token["iat"] + token_refresh_lifetime


def test_refresh_token():
    client = create_example_client()
    response = client.post("/login")
    assert response.status_code == 200, response.text

    response = client.post("/refresh")
    assert response.status_code == 200, response.text
    assert response.json() == {"msg": "The token has been refresh"}


def test_protected():
    client = create_example_client()
    response = client.post("/login")
    assert response.status_code == 200, response.text

    response = client.get("/protected")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example"}


def test_protected_no_access_token():
    client = create_example_client()
    response = client.get("/protected")
    assert response.status_code == 401, response.text
    assert response.json() == {"error": {"detail": "Missing access token"}}
