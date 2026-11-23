from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.threat_intel import ThreatIntelCache
from app.repositories.base_repository import BaseRepository


class ThreatIntelRepository(BaseRepository[ThreatIntelCache]):
    def __init__(self, db: Session):
        super().__init__(ThreatIntelCache, db)

    def get_by_indicator(self, indicator: str) -> Optional[ThreatIntelCache]:
        stmt = select(ThreatIntelCache).where(
            ThreatIntelCache.indicator == indicator,
            ThreatIntelCache.expires_at > datetime.now(timezone.utc)
        )
        return self.db.scalars(stmt).first()
