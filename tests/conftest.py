from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from fastapi_jwt_authlib.auth import AuthContext, AuthData, JWTUserData
from fastapi_jwt_authlib.depends import (
    AuthAccessDepends,
    AuthDepends,
    AuthRefreshDepends,
)
from fastapi_jwt_authlib.exception import AuthJWTException

AuthAccessAdminDepends = Annotated[AuthData, Depends(AuthContext("access", ["admin"]))]
AuthAccessUsersDepends = Annotated[AuthData, Depends(AuthContext("access", ["user1", "user2"]))]
AuthAccessUser1Depends = Annotated[AuthData, Depends(AuthContext("access", ["user1"]))]
AuthAccessUser2Depends = Annotated[AuthData, Depends(AuthContext("access", ["user2"]))]


def create_example_client():
    app = FastAPI()

    username = "example"

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(_request: Request, exc: AuthJWTException):
        return JSONResponse(status_code=exc.status_code, content={"error": {"detail": exc.message}})

    @app.post("/login")
    def login(auth: AuthDepends):
        jwt_data = JWTUserData(user=username)
        auth.generate_and_store_access_token(jwt_data)
        auth.generate_and_store_refresh_token(jwt_data)
        return {"msg": "Successful login"}

    @app.post("/login/admin")
    def login_admin(auth: AuthDepends):
        jwt_data = JWTUserData(user=username, roles=["admin"])
        auth.generate_and_store_access_token(jwt_data)
        auth.generate_and_store_refresh_token(jwt_data)
        return {"msg": "Successful login"}

    @app.post("/login/users")
    def login_roles(auth: AuthDepends):
        jwt_data = JWTUserData(user=username, roles=["user1", "user2"])
        auth.generate_and_store_access_token(jwt_data)
        auth.generate_and_store_refresh_token(jwt_data)
        return {"msg": "Successful login"}

    @app.post("/login/user1")
    def login_user1(auth: AuthDepends):
        jwt_data = JWTUserData(user=username, roles=["user1"])
        auth.generate_and_store_access_token(jwt_data)
        auth.generate_and_store_refresh_token(jwt_data)
        return {"msg": "Successful login"}

    @app.post("/login/user2")
    def login_user2(auth: AuthDepends):
        jwt_data = JWTUserData(user=username, roles=["user2"])
        auth.generate_and_store_access_token(jwt_data)
        auth.generate_and_store_refresh_token(jwt_data)
        return {"msg": "Successful login"}

    @app.delete("/logout")
    def logout(auth: AuthDepends):
        auth.unset_access_cookies()
        auth.unset_refresh_cookies()
        return {"msg": "Successful logout"}

    @app.post("/refresh")
    def refresh(auth: AuthRefreshDepends):
        jwt_data = JWTUserData(user=username)
        auth.jwt.generate_and_store_access_token(jwt_data)
        return {"msg": "The token has been refresh"}

    @app.get("/protected")
    def protected(auth: AuthAccessDepends):
        return {"user": auth.user, "roles": auth.roles}

    @app.get("/protected/admin")
    def protected_admin(auth: AuthAccessAdminDepends):
        return {"user": auth.user, "roles": auth.roles}

    @app.get("/protected/users")
    def protected_users(auth: AuthAccessUsersDepends):
        return {"user": auth.user, "roles": auth.roles}

    @app.get("/protected/user1")
    def protected_user1(auth: AuthAccessUser1Depends):
        return {"user": auth.user, "roles": auth.roles}

    @app.get("/protected/user2")
    def protected_user2(auth: AuthAccessUser2Depends):
        return {"user": auth.user, "roles": auth.roles}

    return TestClient(app)


@pytest.fixture
def client():
    return create_example_client()
