from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportExportParams(BaseModel):
    format: str = "csv"  # 'csv', 'json'
    severity: Optional[str] = "All"
    status: Optional[str] = "All"


class ReportListItem(BaseModel):
    id: str
    title: str
    report_type: str  # 'executive_summary', 'incident_triage', 'threat_intel', 'compliance'
    status: str       # 'Completed', 'Processing'
    format: str       # 'json', 'csv', 'pdf'
    generated_by: str
    generated_at: datetime
    summary: Optional[str] = None


class ReportGenerateRequest(BaseModel):
    title: str
    report_type: str = Field("executive_summary", pattern="^(executive_summary|incident_triage|threat_intel|compliance)$")
    range_key: str = Field("24h", pattern="^(24h|7d|30d)$")
    format: str = Field("json", pattern="^(json|csv)$")
    filters: Optional[Dict[str, Any]] = None


class ReportGenerateResponse(BaseModel):
    report_id: str
    title: str
    report_type: str
    status: str
    format: str
    download_url: str
    summary: str
    generated_at: datetime
