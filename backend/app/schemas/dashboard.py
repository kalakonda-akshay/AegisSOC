from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.incident import IncidentResponse
from app.schemas.telemetry import SystemHealthItem


class KpiItem(BaseModel):
    key: str
    label: str
    value: str
    delta_percent: float
    is_increase: bool
    color: str
    sparkline: List[float]


class ThreatDistributionItem(BaseModel):
    type: str
    count: int
    color: str


class AttackSeverityItem(BaseModel):
    severity: str
    count: int
    color: str


class DashboardOverviewResponse(BaseModel):
    kpis: List[KpiItem]
    timeline_series: Dict[str, List[float]]
    threat_distribution: List[ThreatDistributionItem]
    attack_severity: List[AttackSeverityItem]
    recent_incidents: List[IncidentResponse]
    system_health: List[SystemHealthItem]
    updated_at: str


class SecurityEventFeedItem(BaseModel):
    id: int
    t: int  # Epoch timestamp in seconds matching frontend's fmt(e.t)
    type: str  # e.g. "Brute Force", "Port Scanning"
    src: str   # source IP
    dst: str   # destination IP
    sev: str   # Critical, High, Medium, Low
    by: str    # e.g. "ML anomaly model", "Signature rule"
    confidence: Optional[int] = 85
    timestamp_iso: Optional[str] = None


class DashboardMetricsResponse(BaseModel):
    active_threats: int
    critical_incidents: int
    traffic_analyzed_tb: float
    network_anomalies: int
    system_status: str
    kpis: List[KpiItem]
    inbound_mbps: float
    outbound_mbps: float
