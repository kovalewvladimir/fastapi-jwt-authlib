class AuthJWTError(Exception):
    """Base except which all libre_fastapi_jwt errors extend"""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class MissingTokenError(AuthJWTError):
    """Error raised when token not found"""


class JWTDecodeError(AuthJWTError):
    """Error raised when token cannot be decoded"""
