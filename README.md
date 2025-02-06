# fastapi-jwt-authlib

[![PyPI version](https://badge.fury.io/py/fastapi-jwt-authlib.svg)](https://badge.fury.io/py/fastapi-jwt-authlib)

---

**Source Code**: <a href="https://github.com/kovalewvladimir/fastapi-jwt-authlib" target="_blank">https://github.com/kovalewvladimir/fastapi-jwt-authlib</a>

---

## Описание проекта

Библиотека для аутентификации JWT в FastAPI. Она предоставляет удобные инструменты для работы с JWT токенами, обеспечивая безопасность и простоту интеграции в ваши FastAPI приложения.

## Установка

```bash
pip install fastapi-jwt-authlib
```

## Пример использования

main.py: 

```python 
from fastapi_jwt_authlib.auth import AuthJWT

AuthJWT.config(
    secret_key=settings.SECRET_KEY,
    cookie_access_key=settings.COOKIE_ACCESS_KEY,
    cookie_refresh_key=settings.COOKIE_REFRESH_KEY,
    cookie_refresh_path=f"{settings.ROOT_PATH}/auth/refresh",
)
```

auth.py:

```python
from fastapi import APIRouter, HTTPException
from fastapi.security import HTTPBasicCredentials
from fastapi_jwt_authlib.auth import JWTUserData
from fastapi_jwt_authlib.depends import (
    AuthAccessDepends,
    AuthDepends,
    AuthRefreshDepends,
)

router = APIRouter()


@router.post("/login")
def login(user: HTTPBasicCredentials, auth: AuthDepends):
    if user.username != "admin" or user.password != "admin":
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    roles = ["admin"]
    data_jwt = JWTUserData(user=user.username, roles=roles)
    auth.generate_and_store_access_token(data_jwt)
    auth.generate_and_store_refresh_token(data_jwt)

    return {"msg": "Successful login"}


@router.delete("/logout")
def logout(auth: AuthDepends):
    auth.unset_cookies()
    return {"msg": "Successful logout"}


@router.post("/refresh")
def refresh(auth: AuthRefreshDepends):
    roles = ["admin"] if is_admin(auth.user) else []
    data_jwt = JWTUserData(user=auth.user, roles=roles)
    auth.jwt.generate_and_store_access_token(data_jwt)
    return {"msg": "The token has been refresh"}


@router.get("/protected")
def protected(auth: AuthAccessDepends):
    return {"user": auth.user}
```