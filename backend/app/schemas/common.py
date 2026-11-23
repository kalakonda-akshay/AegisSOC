from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number starting at 1")
    limit: int = Field(default=50, ge=1, le=500, description="Items per page")
    sort_by: Optional[str] = Field(default=None, description="Field name to sort by")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$", description="Sort direction")
    q: Optional[str] = Field(default=None, description="Optional search query filter")


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    limit: int
    pages: int


class StandardResponse(BaseModel, Generic[T]):
    success: bool = True
    message: Optional[str] = None
    data: T
