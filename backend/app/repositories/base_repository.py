from typing import Any, Generic, List, Optional, Type, TypeVar
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from app.core.database import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], db: Session):
        self.model = model
        self.db = db

    def get_by_id(self, id: Any) -> Optional[ModelType]:
        return self.db.get(self.model, id)

    def get_all(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        stmt = select(self.model).offset(skip).limit(limit)
        return list(self.db.scalars(stmt).all())

    def count(self) -> int:
        return self.db.scalar(select(func.count()).select_from(self.model)) or 0

    def create(self, obj: ModelType) -> ModelType:
        self.db.add(obj)
        self.db.flush()
        return obj

    def delete_by_id(self, id: Any) -> bool:
        stmt = delete(self.model).where(self.model.id == id)
        result = self.db.execute(stmt)
        return result.rowcount > 0
