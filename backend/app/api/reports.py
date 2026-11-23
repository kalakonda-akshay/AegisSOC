from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.services.report_service import ReportService
from app.schemas.reports import (
    ReportListItem,
    ReportGenerateRequest,
    ReportGenerateResponse
)

router = APIRouter(prefix="/reports", tags=["Reporting"])


@router.get("", response_model=List[ReportListItem])
def list_reports(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lists available compliance and executive security reports."""
    service = ReportService(db)
    return service.list_reports(limit=limit)


@router.post("/generate", response_model=ReportGenerateResponse, status_code=status.HTTP_201_CREATED)
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generates a new security incident or threat intelligence report."""
    service = ReportService(db)
    user_name = current_user.full_name or current_user.username
    return service.generate_report(req=req, user_name=user_name)


@router.get("/incidents/export")
def export_incidents_report(
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    severity: Optional[str] = Query(default="All"),
    status: Optional[str] = Query(default="All"),
    db: Session = Depends(get_db)
):
    """Exports filtered incidents in CSV or JSON format for compliance and reporting."""
    service = ReportService(db)
    if format == "json":
        json_data = service.generate_incidents_json(severity=severity, status=status)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="aegissoc-incidents.json"'}
        )
    else:
        csv_data = service.generate_incidents_csv(severity=severity, status=status)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="aegissoc-incidents.csv"'}
        )
