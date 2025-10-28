from typing import TypeVar

T = TypeVar("T")


def default_if_none(value: T | None, default: T):
    return value if value is not None else default
