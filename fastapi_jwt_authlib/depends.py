from typing import Annotated

from fastapi import Depends

from fastapi_jwt_authlib.auth import AuthContext, AuthData, AuthJWT

AuthAccess = AuthContext("access")
AuthRefresh = AuthContext("refresh")

AuthDepends = Annotated[AuthJWT, Depends(AuthJWT)]
AuthAccessDepends = Annotated[AuthData, Depends(AuthAccess)]
AuthRefreshDepends = Annotated[AuthData, Depends(AuthRefresh)]
