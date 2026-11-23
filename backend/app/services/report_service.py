import csv
from datetime import datetime, timezone
import io
import json
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.report import SecurityReport
from app.repositories.incident_repository import IncidentRepository
from app.schemas.reports import (
    ReportGenerateRequest,
    ReportGenerateResponse,
    ReportListItem
)


class ReportService:
    def __init__(self, db: Session):
        self.db = db
        self.incident_repo = IncidentRepository(db)

    def list_reports(self, limit: int = 20) -> List[ReportListItem]:
        """Lists previously generated security and compliance reports."""
        reports = self.db.query(SecurityReport).order_by(SecurityReport.created_at.desc()).limit(limit).all()
        if not reports:
            # Provide sample reports if none exist
            return [
                ReportListItem(
                    id="REP-9001",
                    title="Executive SOC Threat & Incident Summary",
                    report_type="executive_summary",
                    status="Completed",
                    format="json",
                    generated_by="SOC Admin",
                    generated_at=datetime.now(timezone.utc),
                    summary="24h overview: 10 incidents tracked, 7 active threats, 87/100 posture score."
                ),
                ReportListItem(
                    id="REP-9002",
                    title="Perimeter Threat Intelligence & C2 Indicators",
                    report_type="threat_intel",
                    status="Completed",
                    format="csv",
                    generated_by="Threat Intelligence Engine",
                    generated_at=datetime.now(timezone.utc),
                    summary="Curated list of 15 malicious IOCs detected targeting internal endpoints."
                )
            ]

        return [
            ReportListItem(
                id=r.id,
                title=r.title,
                report_type=r.report_type,
                status="Completed",
                format=r.format,
                generated_by="Analyst",
                generated_at=r.created_at,
                summary=f"Report format: {r.format.upper()}, parameters: {r.parameters or 'None'}"
            ) for r in reports
        ]

    def generate_report(
        self,
        req: ReportGenerateRequest,
        user_name: str = "Analyst"
    ) -> ReportGenerateResponse:
        """Generates an executive or technical compliance report."""
        rep_id = f"REP-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        now = datetime.now(timezone.utc)

        # Generate summary
        summary = (
            f"Generated {req.report_type} for time range {req.range_key}. "
            f"Format: {req.format.upper()}. Generated at {now.isoformat()}."
        )

        db_report = SecurityReport(
            id=rep_id,
            title=req.title,
            report_type=req.report_type,
            format=req.format,
            parameters=json.dumps({"range": req.range_key, "filters": req.filters or {}}),
            file_path=f"/exports/{rep_id}.{req.format}"
        )
        self.db.add(db_report)
        self.db.commit()

        download_url = f"/api/reports/incidents/export?format={req.format}"

        return ReportGenerateResponse(
            report_id=rep_id,
            title=req.title,
            report_type=req.report_type,
            status="Completed",
            format=req.format,
            download_url=download_url,
            summary=summary,
            generated_at=now
        )

    def generate_incidents_csv(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> str:
        incidents, _ = self.incident_repo.search_incidents(
            severity=severity,
            status=status,
            limit=500
        )

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["id", "title", "type", "severity", "status", "source_ip", "destination_ip"])

        for inc in incidents:
            writer.writerow([
                inc.incident_code,
                inc.title,
                inc.attack_type,
                inc.severity,
                inc.status,
                inc.source_ip,
                inc.destination_ip
            ])

        return output.getvalue()

    def generate_incidents_json(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None
    ) -> str:
        incidents, _ = self.incident_repo.search_incidents(
            severity=severity,
            status=status,
            limit=500
        )
        data = [
            {
                "id": inc.incident_code,
                "title": inc.title,
                "type": inc.attack_type,
                "src": inc.source_ip,
                "dst": inc.destination_ip,
                "severity": inc.severity,
                "status": inc.status,
                "analyst": inc.analyst_name,
                "confidence": inc.confidence,
                "detected_at": inc.detected_at.isoformat() if inc.detected_at else None
            } for inc in incidents
        ]
        return json.dumps(data, indent=2)
