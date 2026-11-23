from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.schemas.analytics import (
    AnalyticsOverviewResponse,
    AnalyticsTimelineResponse,
    AnalyticsTrendsResponse
)
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/timeline", response_model=AnalyticsTimelineResponse)
def get_analytics_timeline(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Provides time-series data for the multi-series security events timeline chart."""
    service = AnalyticsService(db)
    return service.get_timeline(range_key=range)


@router.get("/overview", response_model=AnalyticsOverviewResponse)
def get_analytics_overview(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Provides analytical distributions and posture scores for executive reporting."""
    service = AnalyticsService(db)
    return service.get_analytics_overview(range_key=range)


@router.get("/trends", response_model=AnalyticsTrendsResponse)
def get_analytics_trends(
    range: str = Query(default="24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Returns historical incident, threat volume, and MTTR trends over time."""
    service = AnalyticsService(db)
    return service.get_trends(range_key=range)
