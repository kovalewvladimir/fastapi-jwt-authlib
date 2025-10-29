from typing import Annotated

from fastapi import Depends

from fastapi_jwt_authlib.auth import AuthContext, AuthData, AuthJWT

AuthAccess = AuthContext("access")
AuthRefresh = AuthContext("refresh")

AuthDepends = Annotated[AuthJWT, Depends(AuthJWT)]
AuthAccessDepends = Annotated[AuthData, Depends(AuthAccess)]
AuthRefreshDepends = Annotated[AuthData, Depends(AuthRefresh)]


def create_access_role_dependency(roles: tuple[str, ...]):
    """Фабрика для создания зависимости с проверкой роли"""
    return Depends(AuthContext("access", roles))
