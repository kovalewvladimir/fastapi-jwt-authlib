from typing import Annotated

from fastapi import Depends

from fastapi_jwt_authlib.auth import AuthContext, AuthContextData, AuthJWT

AuthDepends = Annotated[AuthJWT, Depends(AuthJWT)]
AuthAccessContextDepends = Annotated[AuthContextData, Depends(AuthContext("access"))]
AuthRefreshContextDepends = Annotated[AuthContextData, Depends(AuthContext("refresh"))]
