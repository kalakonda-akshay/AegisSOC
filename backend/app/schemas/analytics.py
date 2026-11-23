from typing import Dict, List
from pydantic import BaseModel
from app.schemas.dashboard import AttackSeverityItem, KpiItem, ThreatDistributionItem


class AnalyticsTimelineResponse(BaseModel):
    range: str
    timestamps: List[str]
    series: Dict[str, List[float]]  # 'total', 'high', 'critical'


class AnalyticsOverviewResponse(BaseModel):
    range: str
    kpis: List[KpiItem]
    distribution: List[ThreatDistributionItem]
    severity_counts: List[AttackSeverityItem]


class TrendDataPoint(BaseModel):
    timestamp: str
    incident_count: int
    threat_count: int
    mean_time_to_resolve_minutes: float


class AnalyticsTrendsResponse(BaseModel):
    range: str
    trends: List[TrendDataPoint]
    category_breakdown: Dict[str, int]
    mttr_trend_direction: str
