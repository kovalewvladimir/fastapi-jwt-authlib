from typing import Annotated

from fastapi import Depends

from fastapi_jwt_authlib.auth import AuthContext, AuthData, AuthJWT

AuthDepends = Annotated[AuthJWT, Depends(AuthJWT)]
AuthAccessDepends = Annotated[AuthData, Depends(AuthContext("access"))]
AuthRefreshDepends = Annotated[AuthData, Depends(AuthContext("refresh"))]
