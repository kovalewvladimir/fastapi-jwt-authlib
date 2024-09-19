from http.cookies import SimpleCookie

import jwt

from fastapi_jwt_authlib.auth import AuthJWT

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
        "/login/admin": {
            "post": {
                "summary": "Login Admin",
                "operationId": "login_admin_login_admin_post",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/login/users": {
            "post": {
                "summary": "Login Roles",
                "operationId": "login_roles_login_users_post",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/login/user1": {
            "post": {
                "summary": "Login User1",
                "operationId": "login_user1_login_user1_post",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/login/user2": {
            "post": {
                "summary": "Login User2",
                "operationId": "login_user2_login_user2_post",
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
        "/protected/admin": {
            "get": {
                "summary": "Protected Admin",
                "operationId": "protected_admin_protected_admin_get",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/protected/users": {
            "get": {
                "summary": "Protected Users",
                "operationId": "protected_users_protected_users_get",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/protected/user1": {
            "get": {
                "summary": "Protected User1",
                "operationId": "protected_user1_protected_user1_get",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
        "/protected/user2": {
            "get": {
                "summary": "Protected User2",
                "operationId": "protected_user2_protected_user2_get",
                "responses": {
                    "200": {"description": "Successful Response", "content": {"application/json": {"schema": {}}}}
                },
            }
        },
    },
}


def test_openapi_schema(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200, response.text
    assert response.json() == openapi_schema


def test_login(client):
    response = client.post("/login")
    assert response.status_code == 200, response.text
    assert response.json() == {"msg": "Successful login"}


def test_logout(client):
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


def test_cookies_secure(client):
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


def test_cookies_value_lifetime(client):
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


def test_refresh_token(client):
    response = client.post("/login")
    assert response.status_code == 200, response.text

    response = client.post("/refresh")
    assert response.status_code == 200, response.text
    assert response.json() == {"msg": "The token has been refresh"}


def test_protected(client):
    response = client.post("/login")
    assert response.status_code == 200, response.text

    response = client.get("/protected")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": []}


def test_protected_no_access_token(client):
    response = client.get("/protected")
    assert response.status_code == 401, response.text
    assert response.json() == {"error": {"detail": "Missing access token"}}


def test_protected_admin(client):
    response = client.post("/login/admin")
    assert response.status_code == 200, response.text

    response = client.get("/protected/admin")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["admin"]}


def test_protected_admin_no_access_token(client):
    response = client.post("/login")
    assert response.status_code == 200, response.text

    response = client.get("/protected/admin")
    assert response.status_code == 403, response.text
    assert response.json() == {"error": {"detail": "Invalid user role"}}


def test_user1_protection_endpoint_user1(client):
    response = client.post("/login/user1")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user1")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1"]}


def test_user1_protection_endpoint_user2(client):
    response = client.post("/login/user1")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user2")
    assert response.status_code == 403, response.text
    assert response.json() == {"error": {"detail": "Invalid user role"}}


def test_user1_protection_endpoint_users(client):
    response = client.post("/login/user1")
    assert response.status_code == 200, response.text

    response = client.get("/protected/users")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1"]}


def test_user1_protection_endpoint_protected(client):
    response = client.post("/login/user1")
    assert response.status_code == 200, response.text

    response = client.get("/protected")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1"]}


def test_user2_protection_endpoint_user1(client):
    response = client.post("/login/user2")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user1")
    assert response.status_code == 403, response.text
    assert response.json() == {"error": {"detail": "Invalid user role"}}


def test_user2_protection_endpoint_user2(client):
    response = client.post("/login/user2")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user2")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user2"]}


def test_user2_protection_endpoint_users(client):
    response = client.post("/login/user2")
    assert response.status_code == 200, response.text

    response = client.get("/protected/users")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user2"]}


def test_user2_protection_endpoint_protected(client):
    response = client.post("/login/user2")
    assert response.status_code == 200, response.text

    response = client.get("/protected")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user2"]}


def test_users_protection_endpoint_user1(client):
    response = client.post("/login/users")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user1")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1", "user2"]}


def test_users_protection_endpoint_user2(client):
    response = client.post("/login/users")
    assert response.status_code == 200, response.text

    response = client.get("/protected/user2")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1", "user2"]}


def test_users_protection_endpoint_users(client):
    response = client.post("/login/users")
    assert response.status_code == 200, response.text

    response = client.get("/protected/users")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1", "user2"]}


def test_users_protection_endpoint_protected(client):
    response = client.post("/login/users")
    assert response.status_code == 200, response.text

    response = client.get("/protected")
    assert response.status_code == 200, response.text
    assert response.json() == {"user": "example", "roles": ["user1", "user2"]}
