"""
AegisSOC Threat Intelligence Service
Coordinates multi-source IOC enrichment, cache management, and threat history.
"""

import math
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.intelligence.engine import ThreatIntelEngine
from app.models.threat_intel import ThreatIntelCache
from app.schemas.intelligence import (
    CacheClearResponse,
    IOCListItem,
    IndicatorLookupRequest,
    IndicatorLookupResponse,
    PaginatedIOCResponse,
    ThreatIntelQueryHistoryItem
)


class IntelligenceService:
    def __init__(self, db: Session):
        self.db = db
        self.engine = ThreatIntelEngine(db)

    def lookup_indicator(
        self,
        req: IndicatorLookupRequest,
        user_name: Optional[str] = "Analyst"
    ) -> IndicatorLookupResponse:
        """Looks up and enriches an IOC across IPs, Domains, URLs, and Hashes."""
        res = self.engine.lookup(
            indicator=req.indicator,
            indicator_type=req.indicator_type,
            user_name=user_name
        )
        return IndicatorLookupResponse(**res.to_dict())

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        verdict: Optional[str] = None,
        min_score: int = 0,
        page: int = 1,
        limit: int = 25
    ) -> PaginatedIOCResponse:
        """Lists cached and curated indicators of compromise with filtering and pagination."""
        query = self.db.query(ThreatIntelCache)
        if ioc_type:
            query = query.filter(ThreatIntelCache.indicator_type == ioc_type)
        if verdict:
            query = query.filter(ThreatIntelCache.verdict == verdict)
        if min_score > 0:
            query = query.filter(ThreatIntelCache.reputation_score >= min_score)

        total = query.count()
        if total == 0:
            now = datetime.now(timezone.utc)
            samples = [
                IOCListItem(
                    id="ioc-1",
                    indicator="185.220.101.5",
                    indicator_type="ip",
                    verdict="Malicious",
                    reputation_score=94,
                    is_malicious=True,
                    threat_types=["Tor Exit Node", "Brute Force"],
                    country_code="DE",
                    last_seen=now
                ),
                IOCListItem(
                    id="ioc-2",
                    indicator="45.142.214.8",
                    indicator_type="ip",
                    verdict="Malicious",
                    reputation_score=88,
                    is_malicious=True,
                    threat_types=["C2 Server", "Cobalt Strike"],
                    country_code="RU",
                    last_seen=now
                ),
                IOCListItem(
                    id="ioc-3",
                    indicator="c2-updater-payload.com",
                    indicator_type="domain",
                    verdict="Suspicious",
                    reputation_score=72,
                    is_malicious=False,
                    threat_types=["Phishing", "DGA"],
                    country_code="US",
                    last_seen=now
                )
            ]
            return PaginatedIOCResponse(
                items=samples,
                total=len(samples),
                page=1,
                limit=limit,
                pages=1
            )

        skip = (page - 1) * limit
        items = query.order_by(ThreatIntelCache.created_at.desc()).offset(skip).limit(limit).all()

        ioc_items = []
        for it in items:
            threats = [t.strip() for t in it.threat_types.split(",") if t.strip()] if it.threat_types else []
            ioc_items.append(IOCListItem(
                id=it.id,
                indicator=it.indicator,
                indicator_type=it.indicator_type,
                verdict=it.verdict,
                reputation_score=it.reputation_score,
                is_malicious=it.is_malicious,
                threat_types=threats,
                country_code=it.country_code,
                last_seen=it.last_seen
            ))

        pages = math.ceil(total / limit) if limit > 0 else 1
        return PaginatedIOCResponse(
            items=ioc_items,
            total=total,
            page=page,
            limit=limit,
            pages=pages
        )

    def get_query_history(self, limit: int = 50) -> List[ThreatIntelQueryHistoryItem]:
        """Retrieves chronological indicator query history."""
        items = self.engine.get_query_history(limit=limit)
        return [
            ThreatIntelQueryHistoryItem(
                id=item.id,
                indicator=item.indicator,
                indicator_type=item.indicator_type,
                verdict=item.verdict,
                reputation_score=item.reputation_score,
                provider_name=item.provider_name,
                queried_by=item.queried_by or "Analyst",
                queried_at=item.queried_at
            ) for item in items
        ]

    def clear_cache(self, indicator: Optional[str] = None) -> CacheClearResponse:
        """Flushes cache entries."""
        count = self.engine.clear_cache(indicator=indicator)
        return CacheClearResponse(
            success=True,
            entries_removed=count,
            message=f"Flushed {count} threat intelligence cache entries."
        )
