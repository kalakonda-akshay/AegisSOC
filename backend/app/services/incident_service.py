"""
AegisSOC Incident Management Service
Handles incident creation, prioritization, severity & analyst assignment,
evidence collection, investigation history, and lifecycle transitions with audit trails.
"""

from datetime import datetime, timezone
import json
import math
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.core.exceptions import BadRequestException, NotFoundException
from app.core.logging import logger
from app.models.audit import AuditLog
from app.models.incident import (
    Incident,
    IncidentComment,
    IncidentEvidence,
    IncidentResponseAction,
    IncidentTimeline
)
from app.models.investigation import Investigation
from app.repositories.incident_repository import IncidentRepository
from app.schemas.common import PaginatedResponse
from app.schemas.incident import (
    AnalystAssignRequest,
    EvidenceCreateRequest,
    IncidentCreate,
    IncidentDetailResponse,
    IncidentEvidenceItem,
    IncidentResponse,
    IncidentStatusUpdate,
    IncidentTimelineItem,
    ResponseActionResponse,
    SeverityUpdateRequest
)


class IncidentService:
    def __init__(self, db: Session):
        self.db = db
        self.incident_repo = IncidentRepository(db)

    def _compute_priority(self, severity: str, destination_ip: str) -> str:
        """Calculates operational priority (P1 through P4) based on severity and asset criticality."""
        critical_assets = {"10.0.0.10", "10.0.0.1", "10.0.2.5", "10.0.0.2"}
        sev_upper = severity.upper()

        if sev_upper == "CRITICAL":
            return "P1 - Critical" if destination_ip in critical_assets else "P2 - High"
        elif sev_upper == "HIGH":
            return "P2 - High" if destination_ip in critical_assets else "P3 - Medium"
        elif sev_upper == "MEDIUM":
            return "P3 - Medium"
        else:
            return "P4 - Low"

    def _map_to_response(self, inc: Incident) -> IncidentResponse:
        priority = self._compute_priority(inc.severity, inc.destination_ip)
        return IncidentResponse(
            id=inc.incident_code,
            db_id=inc.id,
            title=inc.title,
            type=inc.attack_type,
            src=inc.source_ip,
            dst=inc.destination_ip,
            sev=inc.severity,
            priority=priority,
            time=inc.detected_at,
            status=inc.status,
            analyst=inc.analyst_name,
            conf=inc.confidence,
            ai_analysis=inc.ai_summary,
            recommended_actions=inc.recommended_actions
        )

    def list_incidents(
        self,
        q: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        sort_by: Optional[str] = "time",
        sort_order: str = "desc",
        page: int = 1,
        limit: int = 50
    ) -> PaginatedResponse[IncidentResponse]:
        skip = (page - 1) * limit
        items, total = self.incident_repo.search_incidents(
            q=q,
            severity=severity,
            status=status,
            sort_by=sort_by,
            sort_order=sort_order,
            skip=skip,
            limit=limit
        )

        resp_items = [self._map_to_response(item) for item in items]
        pages = math.ceil(total / limit) if limit > 0 else 1

        return PaginatedResponse(
            items=resp_items,
            total=total,
            page=page,
            limit=limit,
            pages=pages
        )

    def get_incident(self, code_or_id: str) -> IncidentDetailResponse:
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        timeline_items = [
            IncidentTimelineItem(
                from_status=t.from_status,
                to_status=t.to_status,
                user_name=t.user_name,
                notes=t.notes,
                created_at=t.created_at
            ) for t in inc.timeline
        ]

        evidence_items = [
            IncidentEvidenceItem(
                id=e.id,
                evidence_type=e.evidence_type,
                data=e.data,
                description=e.description,
                source=e.source,
                collected_at=e.collected_at
            ) for e in inc.evidence
        ]

        actions_items = [
            ResponseActionResponse(
                id=a.id,
                incident_id=a.incident_id,
                action_type=a.action_type,
                title=a.title,
                target=a.target,
                status=a.status,
                mode=a.mode,
                proposed_by=a.proposed_by,
                approved_by=a.approved_by,
                approval_notes=a.approval_notes,
                details=a.details,
                execution_result=a.execution_result,
                created_at=a.created_at,
                approved_at=a.approved_at,
                executed_at=a.executed_at
            ) for a in getattr(inc, "response_actions", [])
        ]

        base_resp = self._map_to_response(inc)
        return IncidentDetailResponse(
            **base_resp.model_dump(),
            timeline=timeline_items,
            evidence=evidence_items,
            response_actions=actions_items
        )

    def create_incident(self, create_data: IncidentCreate, user_name: str = "System Engine") -> IncidentResponse:
        """Creates a new incident record, assigns initial priority, and initializes lifecycle."""
        count = self.incident_repo.count()
        code = f"INC-{2041 + count}"

        inc = Incident(
            incident_code=code,
            title=create_data.title,
            attack_type=create_data.attack_type,
            source_ip=create_data.source_ip,
            destination_ip=create_data.destination_ip,
            severity=create_data.severity,
            status="New",
            analyst_name=create_data.analyst_name or "Unassigned",
            confidence=create_data.confidence,
            ai_summary=create_data.ai_analysis,
            recommended_actions=create_data.recommended_actions
        )
        created = self.incident_repo.create(inc)

        # Initial timeline entry
        timeline_entry = IncidentTimeline(
            incident_id=created.id,
            user_name=user_name,
            from_status=None,
            to_status="New",
            notes=f"Incident ingested and categorized as {created.attack_type}."
        )
        self.db.add(timeline_entry)

        self._record_audit_log(
            action="INCIDENT_CREATED",
            resource_id=created.id,
            user_name=user_name,
            details={"code": code, "title": created.title, "severity": created.severity}
        )

        self.db.commit()
        return self._map_to_response(created)

    def update_status(
        self,
        code_or_id: str,
        update_data: IncidentStatusUpdate,
        user_name: str = "Analyst"
    ) -> IncidentResponse:
        """
        Transitions incident lifecycle: New -> Investigating -> Contained -> Resolved.
        Enforces state transition rules and updates containment/resolution timestamps.
        """
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        old_status = inc.status
        new_status = update_data.status
        now = datetime.now(timezone.utc)

        # Valid lifecycle state transitions
        valid_transitions = {
            "New": {"Investigating", "Contained", "Resolved"},
            "Investigating": {"Contained", "Resolved"},
            "Contained": {"Resolved", "Investigating"},
            "Resolved": {"Investigating"}  # Reopen if new evidence emerges
        }

        if new_status != old_status:
            allowed = valid_transitions.get(old_status, set())
            if new_status not in allowed:
                raise BadRequestException(
                    f"Invalid lifecycle transition from '{old_status}' to '{new_status}'. "
                    f"Allowed transitions: {', '.join(sorted(allowed))}"
                )

        if new_status == "Contained" and not inc.contained_at:
            inc.contained_at = now
        elif new_status == "Resolved" and not inc.resolved_at:
            inc.resolved_at = now

        updated_inc = self.incident_repo.update_status(
            incident=inc,
            new_status=new_status,
            user_name=user_name,
            notes=update_data.notes
        )

        self._record_audit_log(
            action="INCIDENT_STATUS_CHANGE",
            resource_id=inc.id,
            user_name=user_name,
            details={"from": old_status, "to": new_status, "notes": update_data.notes}
        )

        self.db.commit()
        return self._map_to_response(updated_inc)

    def assign_analyst(
        self,
        code_or_id: str,
        req: AnalystAssignRequest,
        user_name: str = "Lead Analyst"
    ) -> IncidentResponse:
        """Assigns or reassigns a SOC analyst to an incident."""
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        old_analyst = inc.analyst_name
        inc.analyst_name = req.analyst_name
        if req.analyst_id:
            inc.assigned_analyst_id = req.analyst_id

        timeline_entry = IncidentTimeline(
            incident_id=inc.id,
            user_name=user_name,
            from_status=inc.status,
            to_status=inc.status,
            notes=f"Reassigned from '{old_analyst}' to '{req.analyst_name}'. {req.notes or ''}".strip()
        )
        self.db.add(timeline_entry)

        self._record_audit_log(
            action="INCIDENT_ANALYST_REASSIGNED",
            resource_id=inc.id,
            user_name=user_name,
            details={"from_analyst": old_analyst, "to_analyst": req.analyst_name}
        )

        self.db.commit()
        return self._map_to_response(inc)

    def update_severity(
        self,
        code_or_id: str,
        req: SeverityUpdateRequest,
        user_name: str = "Lead Analyst"
    ) -> IncidentResponse:
        """Updates severity assignment and recalculates priority."""
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        old_sev = inc.severity
        inc.severity = req.severity

        timeline_entry = IncidentTimeline(
            incident_id=inc.id,
            user_name=user_name,
            from_status=inc.status,
            to_status=inc.status,
            notes=f"Severity updated from '{old_sev}' to '{req.severity}'. {req.notes or ''}".strip()
        )
        self.db.add(timeline_entry)

        self._record_audit_log(
            action="INCIDENT_SEVERITY_UPDATED",
            resource_id=inc.id,
            user_name=user_name,
            details={"from_severity": old_sev, "to_severity": req.severity}
        )

        self.db.commit()
        return self._map_to_response(inc)

    def patch_incident(
        self,
        code_or_id: str,
        update_data: Any,
        user_name: str = "Analyst"
    ) -> IncidentResponse:
        """Generic PATCH update for incident attributes (title, status, severity, analyst)."""
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        if getattr(update_data, "title", None):
            inc.title = update_data.title
        if getattr(update_data, "status", None):
            self.update_status(code_or_id, IncidentStatusUpdate(status=update_data.status, notes=getattr(update_data, "notes", None)), user_name=user_name)
        if getattr(update_data, "severity", None):
            self.update_severity(code_or_id, SeverityUpdateRequest(severity=update_data.severity, notes=getattr(update_data, "notes", None)), user_name=user_name)
        if getattr(update_data, "analyst_name", None):
            self.assign_analyst(code_or_id, AnalystAssignRequest(analyst_name=update_data.analyst_name, notes=getattr(update_data, "notes", None)), user_name=user_name)

        self.db.commit()
        self.db.refresh(inc)
        return self._map_to_response(inc)

    def add_evidence(
        self,
        code_or_id: str,
        req: EvidenceCreateRequest,
        user_name: str = "Analyst"
    ) -> IncidentEvidenceItem:
        """Appends verifiable forensic evidence to an incident with audit logging."""
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        evidence = IncidentEvidence(
            incident_id=inc.id,
            evidence_type=req.evidence_type,
            data=req.data,
            description=req.description,
            source=req.source
        )
        self.db.add(evidence)
        self.db.commit()
        self.db.refresh(evidence)

        self._record_audit_log(
            action="EVIDENCE_ADDED",
            resource_id=inc.id,
            user_name=user_name,
            details={"evidence_id": evidence.id, "type": req.evidence_type, "source": req.source}
        )

        return IncidentEvidenceItem(
            id=evidence.id,
            evidence_type=evidence.evidence_type,
            data=evidence.data,
            description=evidence.description,
            source=evidence.source,
            collected_at=evidence.collected_at
        )

    def get_investigation_history(self, code_or_id: str) -> Dict[str, Any]:
        """Retrieves investigation sessions, AI conversations, and audit trails for an incident."""
        inc = self.incident_repo.get_by_code_or_id(code_or_id)
        if not inc:
            raise NotFoundException(f"Incident '{code_or_id}' not found.")

        investigations = (
            self.db.query(Investigation)
            .filter(Investigation.incident_id == inc.id)
            .order_by(Investigation.created_at.desc())
            .all()
        )

        inv_items = []
        for inv in investigations:
            inv_items.append({
                "investigation_id": inv.id,
                "title": inv.title,
                "status": inv.status,
                "severity": inv.severity,
                "summary": inv.summary,
                "created_at": inv.created_at.isoformat() if inv.created_at else None
            })

        timeline_items = [
            {
                "from_status": t.from_status,
                "to_status": t.to_status,
                "user_name": t.user_name,
                "notes": t.notes,
                "created_at": t.created_at.isoformat() if t.created_at else None
            } for t in inc.timeline
        ]

        return {
            "incident_code": inc.incident_code,
            "title": inc.title,
            "investigations_count": len(inv_items),
            "investigations": inv_items,
            "timeline": timeline_items
        }

    def _record_audit_log(self, action: str, resource_id: str, user_name: str, details: Dict[str, Any]):
        try:
            log_entry = AuditLog(
                user_email=user_name,
                action=action,
                resource_type="incident",
                resource_id=resource_id,
                details=json.dumps(details)
            )
            self.db.add(log_entry)
        except Exception as e:
            logger.warning(f"Failed to record incident audit log: {e}")
