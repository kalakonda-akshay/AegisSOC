from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IncidentTimelineItem(BaseModel):
    from_status: Optional[str] = None
    to_status: str
    user_name: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime


class IncidentEvidenceItem(BaseModel):
    id: str
    evidence_type: str
    data: str
    description: Optional[str] = None
    source: Optional[str] = None
    collected_at: datetime


class ResponseActionResponse(BaseModel):
    id: str
    incident_id: str
    action_type: str
    title: str
    target: str
    status: str  # 'PROPOSED', 'APPROVED', 'REJECTED', 'EXECUTED'
    mode: str    # 'SIMULATION', 'LIVE_AUTHORIZED'
    proposed_by: str
    approved_by: Optional[str] = None
    approval_notes: Optional[str] = None
    details: Optional[str] = None
    execution_result: Optional[str] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None


class IncidentResponse(BaseModel):
    id: str  # maps to incident_code like INC-2041
    db_id: Optional[str] = None
    title: str
    type: str  # maps to attack_type
    src: str   # maps to source_ip
    dst: str   # maps to destination_ip
    sev: str   # maps to severity ('Critical', 'High', 'Medium', 'Low')
    priority: Optional[str] = "P2 - High"
    time: datetime  # maps to detected_at
    status: str     # 'New', 'Investigating', 'Contained', 'Resolved'
    analyst: str    # maps to analyst_name
    conf: int       # maps to confidence (0-100)
    ai_analysis: Optional[str] = None
    recommended_actions: Optional[str] = None

    model_config = {"from_attributes": True}


class IncidentDetailResponse(IncidentResponse):
    timeline: List[IncidentTimelineItem] = []
    evidence: List[IncidentEvidenceItem] = []
    response_actions: List[ResponseActionResponse] = []


class IncidentCreate(BaseModel):
    title: str
    attack_type: str
    source_ip: str
    destination_ip: str
    severity: str = "Medium"
    analyst_name: Optional[str] = "Unassigned"
    confidence: int = Field(default=85, ge=0, le=100)
    ai_analysis: Optional[str] = None
    recommended_actions: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(New|Investigating|Contained|Resolved)$")
    notes: Optional[str] = None


class IncidentPatchUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(New|Investigating|Contained|Resolved)$")
    severity: Optional[str] = Field(None, pattern="^(Critical|High|Medium|Low)$")
    analyst_name: Optional[str] = None
    notes: Optional[str] = None


class AnalystAssignRequest(BaseModel):
    analyst_name: str
    analyst_id: Optional[str] = None
    notes: Optional[str] = None


class SeverityUpdateRequest(BaseModel):
    severity: str = Field(pattern="^(Critical|High|Medium|Low)$")
    notes: Optional[str] = None


class EvidenceCreateRequest(BaseModel):
    evidence_type: str = Field(..., description="'pcap', 'log_snippet', 'hash', 'ip_flow', 'memory_dump'")
    data: str
    description: Optional[str] = None
    source: Optional[str] = "SOC Sensor"


class ResponseActionProposeRequest(BaseModel):
    action_type: str = Field(
        ...,
        pattern="^(SUSPICIOUS_ACCOUNT_REVIEW|ENDPOINT_ISOLATION_PLAN|FIREWALL_RULE_REVIEW|EVIDENCE_PRESERVATION)$"
    )
    title: str
    target: str
    details: Optional[Dict[str, Any]] = None


class ResponseActionApproveRequest(BaseModel):
    approval_notes: Optional[str] = "Approved by Security Analyst"


class ResponseActionExecuteRequest(BaseModel):
    mode: str = Field("SIMULATION", pattern="^(SIMULATION|LIVE_AUTHORIZED)$")
