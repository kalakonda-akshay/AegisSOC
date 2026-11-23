"""
AegisSOC Threat Intelligence API Router
Provides high-speed IOC lookup, multi-type enrichment, query telemetry, and cache controls.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.intelligence import (
    CacheClearResponse,
    IndicatorLookupRequest,
    IndicatorLookupResponse,
    PaginatedIOCResponse,
    ThreatIntelQueryHistoryItem
)
from app.services.intelligence_service import IntelligenceService

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


@router.get("/ioc", response_model=PaginatedIOCResponse)
def list_indicators_of_compromise(
    type: Optional[str] = Query(None, description="Filter by type: ip, domain, url, hash"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: Clean, Suspicious, Malicious, Unknown"),
    min_score: int = Query(0, ge=0, le=100, description="Minimum reputation score"),
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Lists indicators of compromise (IOCs) with filtering, categorization, and pagination."""
    service = IntelligenceService(db)
    return service.list_iocs(
        ioc_type=type,
        verdict=verdict,
        min_score=min_score,
        page=page,
        limit=limit
    )


@router.post("/lookup", response_model=IndicatorLookupResponse)
def lookup_indicator(
    lookup_req: IndicatorLookupRequest,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enriches an indicator (IP, Domain, URL, or File Hash) with reputation score,
    verdict (Clean, Suspicious, Malicious, Unknown), categorization, and ASN/Geo context.
    """
    service = IntelligenceService(db)
    user_name = current_user.full_name if current_user else "Analyst"
    return service.lookup_indicator(lookup_req, user_name=user_name)


@router.get("/ip/{ip_address}", response_model=IndicatorLookupResponse)
def check_ip_reputation(
    ip_address: str,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Direct lookup endpoint for IP address threat intelligence."""
    service = IntelligenceService(db)
    user_name = current_user.full_name if current_user else "Analyst"
    req = IndicatorLookupRequest(indicator=ip_address, indicator_type="ip")
    return service.lookup_indicator(req, user_name=user_name)


@router.get("/domain/{domain_name}", response_model=IndicatorLookupResponse)
def check_domain_reputation(
    domain_name: str,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Direct lookup endpoint for Domain reputation and threat categories."""
    service = IntelligenceService(db)
    user_name = current_user.full_name if current_user else "Analyst"
    req = IndicatorLookupRequest(indicator=domain_name, indicator_type="domain")
    return service.lookup_indicator(req, user_name=user_name)


@router.get("/hash/{file_hash}", response_model=IndicatorLookupResponse)
def check_hash_reputation(
    file_hash: str,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Direct lookup endpoint for cryptographic file hashes (MD5, SHA-1, SHA-256)."""
    service = IntelligenceService(db)
    user_name = current_user.full_name if current_user else "Analyst"
    req = IndicatorLookupRequest(indicator=file_hash, indicator_type="hash")
    return service.lookup_indicator(req, user_name=user_name)


@router.get("/history", response_model=List[ThreatIntelQueryHistoryItem])
def get_intelligence_query_history(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves audit history of threat intelligence indicator lookups."""
    service = IntelligenceService(db)
    return service.get_query_history(limit=limit)


@router.post("/cache/clear", response_model=CacheClearResponse)
def clear_intelligence_cache(
    indicator: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Flushes cached threat intelligence entries to force fresh vendor enrichment."""
    service = IntelligenceService(db)
    return service.clear_cache(indicator=indicator)
