from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

import jwt
from fastapi import Response
from fastapi.requests import HTTPConnection

from fastapi_jwt_authlib.exception import JWTDecodeError, MissingTokenError
from fastapi_jwt_authlib.helper import default_if_none

TokenTypes = Literal["access", "refresh"]


@dataclass
class AuthContextData:
    user: str
    jwt: "AuthJWT"


class AuthJWT:
    _secret_key: str = ""
    _algorithm: str = "HS256"

    _cookie_access_key: str = "__Host-access_token"
    _cookie_refresh_key: str = "__Host-refresh_token"
    _cookie_access_path: str = "/"
    _cookie_refresh_path: str = "/"
    _cookie_secure: bool = False

    _token_access_lifetime: int = 15 * 60  # 15 minutes
    _token_refresh_lifetime: int = 2 * 24 * 60 * 60  # 1 day

    def __init__(self, request: HTTPConnection, response: Response):
        self._request = request
        self._response = response

    @classmethod
    def config(
        cls,
        *,
        secret_key: str,
        algorithm: str | None = None,
        cookie_access_key: str | None = None,
        cookie_refresh_key: str | None = None,
        cookie_access_path: str | None = None,
        cookie_refresh_path: str | None = None,
        cookie_secure: bool | None = None,
        token_access_lifetime: int | None = None,
        token_refresh_lifetime: int | None = None,
    ):
        cls._secret_key = secret_key
        cls._algorithm = default_if_none(algorithm, cls._algorithm)

        cls._cookie_access_key = default_if_none(cookie_access_key, cls._cookie_access_key)
        cls._cookie_refresh_key = default_if_none(cookie_refresh_key, cls._cookie_refresh_key)
        cls._cookie_access_path = default_if_none(cookie_access_path, cls._cookie_access_path)
        cls._cookie_refresh_path = default_if_none(cookie_refresh_path, cls._cookie_refresh_path)
        cls._cookie_secure = default_if_none(cookie_secure, cls._cookie_secure)

        cls._token_access_lifetime = default_if_none(token_access_lifetime, cls._token_access_lifetime)
        cls._token_refresh_lifetime = default_if_none(token_refresh_lifetime, cls._token_refresh_lifetime)

    def _get_jwt_identifier(self) -> str:
        return str(uuid4())

    def _get_int_from_datetime_now(self) -> int:
        return int(datetime.now(timezone.utc).timestamp())

    def _create_token(self, subject: str, token_type: TokenTypes) -> str:
        match token_type:
            case "access":
                lifetime = self._token_access_lifetime
            case "refresh":
                lifetime = self._token_refresh_lifetime
            case _:
                raise ValueError("Invalid token type")

        payload = {
            "sub": subject,
            "iat": self._get_int_from_datetime_now(),
            "nbf": self._get_int_from_datetime_now(),
            "jti": self._get_jwt_identifier(),
            "exp": self._get_int_from_datetime_now() + lifetime,
            "type": token_type,
        }
        token = jwt.encode(
            payload=payload,
            key=self._secret_key,
            algorithm=self._algorithm,
        )

        return token

    def _set_cookie(self, key: str, value: str, expires: int, path: str):
        self._response.set_cookie(
            key=key,
            value=value,
            expires=expires,
            path=path,
            secure=self._cookie_secure,
            httponly=True,
        )

    def _set_access_cookies(self, token: str):
        self._set_cookie(
            key=self._cookie_access_key,
            value=token,
            expires=self._token_access_lifetime,
            path=self._cookie_access_path,
        )

    def _set_refresh_cookies(self, token: str):
        self._set_cookie(
            key=self._cookie_refresh_key,
            value=token,
            expires=self._token_refresh_lifetime,
            path=self._cookie_refresh_path,
        )

    def decode_token(self, token_type: TokenTypes) -> dict:
        match token_type:
            case "access":
                key = self._cookie_access_key
            case "refresh":
                key = self._cookie_refresh_key
            case _:
                raise ValueError("Invalid token type")

        token = self._request.cookies.get(key)
        if token is None:
            raise MissingTokenError(401, f"Missing {token_type} token")

        try:
            decoded_token = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
        except jwt.ExpiredSignatureError as err:
            raise JWTDecodeError(status_code=401, message=str(err)) from err
        except Exception as err:
            raise JWTDecodeError(status_code=422, message=str(err)) from err

        return decoded_token

    def generate_and_store_access_token(self, subject: str):
        token = self._create_token(subject, "access")
        self._set_access_cookies(token)

    def generate_and_store_refresh_token(self, subject: str):
        token = self._create_token(subject, "refresh")
        self._set_refresh_cookies(token)

    def unset_access_cookies(self):
        self._response.delete_cookie(self._cookie_access_key, path=self._cookie_access_path)

    def unset_refresh_cookies(self):
        self._response.delete_cookie(self._cookie_refresh_key, path=self._cookie_refresh_path)

    def unset_cookies(self):
        self.unset_access_cookies()
        self.unset_refresh_cookies()


class AuthContext:
    _token_type: TokenTypes

    def __init__(self, token_type: TokenTypes):
        self._token_type = token_type

    def __call__(self, request: HTTPConnection, response: Response) -> AuthContextData:
        auth_jwt = AuthJWT(request, response)
        decoded_token = auth_jwt.decode_token(self._token_type)

        if decoded_token["type"] != self._token_type:
            if self._token_type == "access":
                raise JWTDecodeError(401, "Invalid token type, expected access token")

        return AuthContextData(
            user=decoded_token["sub"],
            jwt=auth_jwt,
        )
