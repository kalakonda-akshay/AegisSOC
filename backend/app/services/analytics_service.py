import random
from typing import Dict, List
from sqlalchemy.orm import Session
from app.repositories.incident_repository import IncidentRepository
from app.schemas.analytics import (
    AnalyticsOverviewResponse,
    AnalyticsTimelineResponse,
    AnalyticsTrendsResponse,
    TrendDataPoint
)
from app.services.dashboard_service import DashboardService


class AnalyticsService:
    def __init__(self, db: Session):
        self.db = db
        self.dashboard_service = DashboardService(db)

    def get_timeline(self, range_key: str = "24h") -> AnalyticsTimelineResponse:
        points = 24 if range_key == "24h" else (28 if range_key == "7d" else 30)
        timestamps = [f"{i:02d}:00" if range_key == "24h" else f"Day {i+1}" for i in range(points)]

        series = {
            "total": [round(20 + random.random() * 60, 1) for _ in range(points)],
            "high": [round(8 + random.random() * 30, 1) for _ in range(points)],
            "critical": [round(2 + random.random() * 12, 1) for _ in range(points)]
        }

        return AnalyticsTimelineResponse(
            range=range_key,
            timestamps=timestamps,
            series=series
        )

    def get_analytics_overview(self, range_key: str = "24h") -> AnalyticsOverviewResponse:
        dashboard = self.dashboard_service.get_overview(range_key=range_key)
        return AnalyticsOverviewResponse(
            range=range_key,
            kpis=dashboard.kpis,
            distribution=dashboard.threat_distribution,
            severity_counts=dashboard.attack_severity
        )

    def get_trends(self, range_key: str = "24h") -> AnalyticsTrendsResponse:
        points = 24 if range_key == "24h" else (7 if range_key == "7d" else 30)
        trends = []
        for i in range(points):
            label = f"{i:02d}:00" if range_key == "24h" else f"2026-11-{i+1:02d}"
            trends.append(TrendDataPoint(
                timestamp=label,
                incident_count=random.randint(1, 5),
                threat_count=random.randint(10, 45),
                mean_time_to_resolve_minutes=round(random.uniform(14.0, 32.0), 1)
            ))
        cats = {
            "Brute Force": 14,
            "Port Scanning": 9,
            "DDoS": 5,
            "Malware Communication": 4,
            "Suspicious Traffic": 8
        }
        return AnalyticsTrendsResponse(
            range=range_key,
            trends=trends,
            category_breakdown=cats,
            mttr_trend_direction="improving"
        )
