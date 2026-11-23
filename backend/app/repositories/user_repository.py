from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.models.user import Role, User
from app.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self, db: Session):
        super().__init__(User, db)

    def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email).options(selectinload(User.role_rel))
        return self.db.scalars(stmt).first()

    def get_by_id(self, user_id: str) -> Optional[User]:
        stmt = select(User).where(User.id == user_id).options(selectinload(User.role_rel))
        return self.db.scalars(stmt).first()

    def get_role_by_name(self, role_name: str) -> Optional[Role]:
        stmt = select(Role).where(Role.name == role_name)
        return self.db.scalars(stmt).first()
