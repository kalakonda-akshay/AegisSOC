from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.event import (
    SecurityEventCreate,
    SecurityEventResponse,
    ThreatAnalyzeRequest,
    ThreatAnalyzeResponse
)
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["Threat Detection"])


@router.get("", response_model=List[SecurityEventResponse])
def list_recent_threats(
    limit: int = Query(default=25, ge=1, le=100),
    severity: Optional[str] = Query(default=None, description="Filter by severity: Critical, High, Medium, Low"),
    db: Session = Depends(get_db)
):
    """Returns recent threat detections for the live feed and monitoring views."""
    service = ThreatService(db)
    return service.get_recent_threats(limit=limit, severity=severity)


@router.get("/{threat_id}", response_model=SecurityEventResponse)
def get_threat_detail(
    threat_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full telemetry for a specific threat event by ID."""
    service = ThreatService(db)
    return service.get_threat_by_id(threat_id)


@router.post("/analyze", response_model=ThreatAnalyzeResponse)
def analyze_threat_payload(
    req: ThreatAnalyzeRequest,
    db: Session = Depends(get_db)
):
    """Performs ML anomaly inference, IOC correlation, and risk analysis on an incoming traffic payload."""
    service = ThreatService(db)
    return service.analyze_threat(req)


@router.post("/ingest", response_model=SecurityEventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_threat_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    """Ingests incoming network flow/syslog events, runs ML anomaly scoring, and broadcasts to real-time subscribers."""
    service = ThreatService(db)
    return await service.record_event(event_in)
