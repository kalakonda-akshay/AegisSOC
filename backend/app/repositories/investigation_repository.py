from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.models.investigation import AIConversation, AIMessage, Investigation
from app.repositories.base_repository import BaseRepository


class InvestigationRepository(BaseRepository[Investigation]):
    def __init__(self, db: Session):
        super().__init__(Investigation, db)

    def get_by_id_with_messages(self, inv_id: str) -> Optional[Investigation]:
        stmt = select(Investigation).where(
            Investigation.id == inv_id
        ).options(
            selectinload(Investigation.conversations).selectinload(AIConversation.messages)
        )
        return self.db.scalars(stmt).first()

    def list_recent(self, organization_id: Optional[str] = None, limit: int = 20) -> List[Investigation]:
        stmt = select(Investigation)
        if organization_id:
            stmt = stmt.where(Investigation.organization_id == organization_id)
        stmt = stmt.order_by(Investigation.created_at.desc()).limit(limit)
        return list(self.db.scalars(stmt).all())
