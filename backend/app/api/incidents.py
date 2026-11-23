"""
AegisSOC Incident Management & Defensive Response API Router
Handles incident lifecycles, prioritization, analyst assignment, evidence collection,
investigation histories, and approval-based defensive containment workflows.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_role_or_demo
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.incident import (
    AnalystAssignRequest,
    EvidenceCreateRequest,
    IncidentCreate,
    IncidentDetailResponse,
    IncidentEvidenceItem,
    IncidentResponse,
    IncidentStatusUpdate,
    IncidentPatchUpdate,
    ResponseActionApproveRequest,
    ResponseActionExecuteRequest,
    ResponseActionProposeRequest,
    ResponseActionResponse,
    SeverityUpdateRequest
)
from app.services.incident_service import IncidentService
from app.services.response_service import DefensiveResponseService

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("", response_model=PaginatedResponse[IncidentResponse])
def list_incidents(
    q: Optional[str] = Query(default=None, description="Search by ID, title, type, source IP, or destination IP"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: Critical, High, Medium, Low, All"),
    status: Optional[str] = Query(default=None, description="Filter by status: New, Investigating, Contained, Resolved, All"),
    sort_by: Optional[str] = Query(default="time", description="Field to sort by: id, title, type, src, sev, time, status, analyst"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$", description="Sort direction"),
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=500, description="Items per page"),
    db: Session = Depends(get_db)
):
    """Retrieves paginated, searchable, and sortable security incidents matching active filters."""
    service = IncidentService(db)
    return service.list_incidents(
        q=q,
        severity=severity,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        limit=limit
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full incident details, forensic timeline, evidence items, and response actions."""
    service = IncidentService(db)
    return service.get_incident(incident_id)


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
def create_incident(
    incident_in: IncidentCreate,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Creates a new security incident case, assigns priority, and initializes lifecycle."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "SecOps Ingestion Engine"
    return service.create_incident(incident_in, user_name=user_name)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def patch_incident_attributes(
    incident_id: str,
    patch_update: IncidentPatchUpdate,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generic update endpoint for incident attributes (status, severity, analyst, title)."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "Security Analyst"
    return service.patch_incident(incident_id, patch_update, user_name=user_name)


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
def update_incident_status(
    incident_id: str,
    status_update: IncidentStatusUpdate,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Executes a workflow lifecycle transition (New -> Investigating -> Contained -> Resolved)."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "Security Analyst"
    return service.update_status(incident_id, status_update, user_name=user_name)


@router.patch("/{incident_id}/analyst", response_model=IncidentResponse)
def assign_analyst_to_incident(
    incident_id: str,
    req: AnalystAssignRequest,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Assigns or reassigns an incident to a SOC analyst with audit logging."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "SOC Manager"
    return service.assign_analyst(incident_id, req, user_name=user_name)


@router.patch("/{incident_id}/severity", response_model=IncidentResponse)
def update_incident_severity(
    incident_id: str,
    req: SeverityUpdateRequest,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Updates the severity rating of an incident and recalculates priority."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "Lead Analyst"
    return service.update_severity(incident_id, req, user_name=user_name)


@router.post("/{incident_id}/evidence", response_model=IncidentEvidenceItem, status_code=status.HTTP_201_CREATED)
def add_incident_evidence(
    incident_id: str,
    req: EvidenceCreateRequest,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Appends forensic evidence (pcap, log snippet, memory dump, hash) to an incident."""
    service = IncidentService(db)
    user_name = current_user.full_name if current_user else "Analyst"
    return service.add_evidence(incident_id, req, user_name=user_name)


@router.get("/{incident_id}/investigations")
def get_incident_investigation_history(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves all investigation sessions, AI conversations, and timeline events for this incident."""
    service = IncidentService(db)
    return service.get_investigation_history(incident_id)


# -----------------------------------------------------------------------------
# Defensive Response Endpoints (Approval-Based Workflow)
# -----------------------------------------------------------------------------
@router.post("/{incident_id}/response/propose", response_model=ResponseActionResponse, status_code=status.HTTP_201_CREATED)
def propose_defensive_response(
    incident_id: str,
    req: ResponseActionProposeRequest,
    current_user: Optional[User] = Depends(require_role_or_demo(["Admin", "Security Analyst"])),
    db: Session = Depends(get_db)
):
    """
    Proposes an approval-based defensive containment action.
    Supports: SUSPICIOUS_ACCOUNT_REVIEW, ENDPOINT_ISOLATION_PLAN, FIREWALL_RULE_REVIEW, EVIDENCE_PRESERVATION.
    Actions start in PROPOSED status in SIMULATION mode.
    """
    service = DefensiveResponseService(db)
    proposed_by = current_user.full_name if current_user else "AI Security Analyst"
    return service.propose_action(incident_id, req, proposed_by=proposed_by)


@router.get("/{incident_id}/response/actions", response_model=List[ResponseActionResponse])
def list_incident_response_actions(
    incident_id: str,
    db: Session = Depends(get_db)
):
    """Lists all defensive response actions associated with an incident."""
    service = DefensiveResponseService(db)
    return service.list_actions_for_incident(incident_id)


@router.post("/response/{action_id}/approve", response_model=ResponseActionResponse)
def approve_response_action(
    action_id: str,
    req: ResponseActionApproveRequest,
    current_user: Optional[User] = Depends(require_role_or_demo(["Admin", "Security Analyst"])),
    db: Session = Depends(get_db)
):
    """Explicit authorization gate: approves a proposed defensive containment action."""
    service = DefensiveResponseService(db)
    approved_by = current_user.full_name if current_user else "Authorized Analyst"
    return service.approve_action(action_id, req, approved_by=approved_by)


@router.post("/response/{action_id}/reject", response_model=ResponseActionResponse)
def reject_response_action(
    action_id: str,
    reason: str = Query("Action rejected by analyst", description="Reason for rejecting action"),
    current_user: Optional[User] = Depends(require_role_or_demo(["Admin", "Security Analyst"])),
    db: Session = Depends(get_db)
):
    """Rejects a proposed defensive containment action."""
    service = DefensiveResponseService(db)
    rejected_by = current_user.full_name if current_user else "Authorized Analyst"
    return service.reject_action(action_id, reason=reason, rejected_by=rejected_by)


@router.post("/response/{action_id}/execute", response_model=ResponseActionResponse)
def execute_response_action(
    action_id: str,
    req: ResponseActionExecuteRequest,
    current_user: Optional[User] = Depends(require_role_or_demo(["Admin"])),
    db: Session = Depends(get_db)
):
    """
    Executes an approved defensive containment action.
    Requires explicit prior approval. Starts in SIMULATION mode by default.
    Never modifies live production firewall rules without human authorization.
    """
    service = DefensiveResponseService(db)
    executed_by = current_user.full_name if current_user else "SecOps Engineer"
    return service.execute_action(action_id, req, executed_by=executed_by)
