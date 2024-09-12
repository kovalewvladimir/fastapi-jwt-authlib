from http.cookies import SimpleCookie
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_jwt_authlib.auth import AuthJWT

AuthDepends = Annotated[AuthJWT, Depends(AuthJWT)]


def create_example_client():
    app = FastAPI()

    username = "example"

    @app.post("/login")
    def login(auth: AuthDepends):
        auth.generate_and_store_access_token(subject=username)
        auth.generate_and_store_refresh_token(subject=username)
        return {"msg": "Successful login"}

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
        }
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
