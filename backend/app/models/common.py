"""Shared response models used across multiple endpoints."""

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorResponse(BaseModel):
    """Standard error envelope returned by all error responses."""

    model_config = {"frozen": True}

    success: bool = False
    error: str
    detail: str | None = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    model_config = {"frozen": True}

    success: bool = True
    data: list[T]
    total: int
    page: int = Field(ge=1)
    limit: int = Field(ge=1, le=100)
    has_next: bool
