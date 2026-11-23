from typing import List
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.telemetry import NetworkMetric, NetworkNode, SystemHealthCheck
from app.repositories.base_repository import BaseRepository


class TelemetryRepository(BaseRepository[NetworkMetric]):
    def __init__(self, db: Session):
        super().__init__(NetworkMetric, db)

    def get_latest_metrics(self, limit: int = 40) -> List[NetworkMetric]:
        stmt = select(NetworkMetric).order_by(NetworkMetric.recorded_at.desc()).limit(limit)
        results = list(self.db.scalars(stmt).all())
        return list(reversed(results))

    def get_all_nodes(self) -> List[NetworkNode]:
        stmt = select(NetworkNode)
        return list(self.db.scalars(stmt).all())

    def get_latest_health_checks(self) -> List[SystemHealthCheck]:
        stmt = select(SystemHealthCheck).order_by(SystemHealthCheck.id.asc())
        return list(self.db.scalars(stmt).all())
