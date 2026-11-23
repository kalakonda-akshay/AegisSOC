from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload
from app.models.incident import Incident, IncidentComment, IncidentTimeline
from app.repositories.base_repository import BaseRepository


class IncidentRepository(BaseRepository[Incident]):
    def __init__(self, db: Session):
        super().__init__(Incident, db)

    def get_by_code_or_id(self, code_or_id: str) -> Optional[Incident]:
        stmt = select(Incident).where(
            or_(Incident.incident_code == code_or_id, Incident.id == code_or_id)
        ).options(
            selectinload(Incident.timeline),
            selectinload(Incident.comments),
            selectinload(Incident.evidence)
        )
        return self.db.scalars(stmt).first()

    def search_incidents(
        self,
        q: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        sort_by: Optional[str] = "time",
        sort_order: str = "desc",
        skip: int = 0,
        limit: int = 50
    ) -> Tuple[List[Incident], int]:
        stmt = select(Incident)
        count_stmt = select(func.count(Incident.id))

        conditions = []
        if q:
            search_pattern = f"%{q.lower()}%"
            conditions.append(
                or_(
                    func.lower(Incident.incident_code).like(search_pattern),
                    func.lower(Incident.title).like(search_pattern),
                    func.lower(Incident.attack_type).like(search_pattern),
                    func.lower(Incident.source_ip).like(search_pattern),
                    func.lower(Incident.destination_ip).like(search_pattern)
                )
            )

        if severity and severity.lower() != "all":
            conditions.append(func.lower(Incident.severity) == severity.lower())

        if status and status.lower() != "all":
            conditions.append(func.lower(Incident.status) == status.lower())

        if conditions:
            for cond in conditions:
                stmt = stmt.where(cond)
                count_stmt = count_stmt.where(cond)

        total = self.db.scalar(count_stmt) or 0

        sort_column_map = {
            "id": Incident.incident_code,
            "incident_code": Incident.incident_code,
            "title": Incident.title,
            "type": Incident.attack_type,
            "attack_type": Incident.attack_type,
            "src": Incident.source_ip,
            "source_ip": Incident.source_ip,
            "sev": Incident.severity,
            "severity": Incident.severity,
            "time": Incident.detected_at,
            "detected_at": Incident.detected_at,
            "status": Incident.status,
            "analyst": Incident.analyst_name,
            "analyst_name": Incident.analyst_name,
            "conf": Incident.confidence,
            "confidence": Incident.confidence
        }

        col = sort_column_map.get(sort_by or "time", Incident.detected_at)
        if sort_order.lower() == "asc":
            stmt = stmt.order_by(col.asc())
        else:
            stmt = stmt.order_by(col.desc())

        stmt = stmt.offset(skip).limit(limit)
        items = list(self.db.scalars(stmt).all())
        return items, total

    def update_status(self, incident: Incident, new_status: str, user_name: str, notes: Optional[str] = None) -> Incident:
        old_status = incident.status
        incident.status = new_status
        incident.updated_at = datetime.now(timezone.utc)
        if new_status == "Contained":
            incident.contained_at = datetime.now(timezone.utc)
        elif new_status == "Resolved":
            incident.resolved_at = datetime.now(timezone.utc)

        timeline_entry = IncidentTimeline(
            incident_id=incident.id,
            user_name=user_name,
            from_status=old_status,
            to_status=new_status,
            notes=notes
        )
        self.db.add(timeline_entry)
        self.db.flush()
        return incident

    def get_counts_by_status(self) -> Dict[str, int]:
        stmt = select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
        rows = self.db.execute(stmt).all()
        counts = {"New": 0, "Investigating": 0, "Contained": 0, "Resolved": 0}
        for status_val, count in rows:
            counts[status_val] = count
        return counts

    def get_counts_by_severity(self) -> Dict[str, int]:
        stmt = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        rows = self.db.execute(stmt).all()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for sev_val, count in rows:
            counts[sev_val] = count
        return counts

    def get_counts_by_type(self) -> List[Tuple[str, int]]:
        stmt = select(Incident.attack_type, func.count(Incident.id)).group_by(Incident.attack_type)
        return self.db.execute(stmt).all()
