from typing import Generic, TypeVar

from fastapi import status as http_status
from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")


# common response schema
class CommonResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    code: int = http_status.HTTP_200_OK
    message: str = "success"
    data: T | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    page: int = Field(ge=1)
    size: int = Field(ge=1)
    total: int = Field(ge=0)
    items: list[T]
