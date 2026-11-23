from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.dashboard import (
    DashboardMetricsResponse,
    DashboardOverviewResponse,
    KpiItem,
    SecurityEventFeedItem
)
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/overview", response_model=DashboardOverviewResponse)
def get_dashboard_overview(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$", description="Time range for KPIs and charts"),
    db: Session = Depends(get_db)
):
    """Provides the complete aggregated security operations overview for the dashboard."""
    service = DashboardService(db)
    return service.get_overview(range_key=range)


@router.get("/events", response_model=List[SecurityEventFeedItem])
def get_dashboard_events_feed(
    limit: int = Query(default=25, ge=1, le=100, description="Max event items to return for live feed"),
    db: Session = Depends(get_db)
):
    """Returns chronological security events formatted for the dashboard live event feed."""
    service = DashboardService(db)
    return service.get_events(limit=limit)


@router.get("/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Returns top-level metric counters, live Mbps readings, and executive KPIs."""
    service = DashboardService(db)
    return service.get_metrics(range_key=range)


@router.get("/kpis", response_model=List[KpiItem])
def get_dashboard_kpis(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Returns the 6 primary executive security KPIs with trend percentages and sparklines."""
    service = DashboardService(db)
    overview = service.get_overview(range_key=range)
    return overview.kpis
