from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.event import SecurityEvent
from app.repositories.base_repository import BaseRepository


class EventRepository(BaseRepository[SecurityEvent]):
    def __init__(self, db: Session):
        super().__init__(SecurityEvent, db)

    def get_recent_events(self, limit: int = 25, severity: Optional[str] = None) -> List[SecurityEvent]:
        stmt = select(SecurityEvent)
        if severity and severity.lower() != "all":
            stmt = stmt.where(SecurityEvent.severity.ilike(severity))
        stmt = stmt.order_by(SecurityEvent.timestamp.desc()).limit(limit)
        return list(self.db.scalars(stmt).all())
