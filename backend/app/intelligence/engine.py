"""
AegisSOC Threat Intelligence Engine
Orchestrates multi-provider IOC enrichment, cache management with TTL,
verdict categorization, and query history persistence.
"""

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.intelligence.providers import (
    AbuseIPDBProvider,
    SimulatedThreatIntelProvider,
    ThreatIntelProvider,
    VirusTotalProvider
)
from app.intelligence.types import ThreatIntelResult, detect_ioc_type
from app.models.threat_intel import ThreatIntelCache, ThreatIntelQueryHistory


class ThreatIntelEngine:
    """
    Enterprise Threat Intelligence aggregator.
    Checks local DB cache, queries available vendor providers, classifies verdicts,
    and logs query telemetry.
    """

    def __init__(self, db: Session, cache_ttl_hours: int = 24):
        self.db = db
        self.cache_ttl_hours = cache_ttl_hours

        # Multi-provider chain: live providers first, followed by deterministic simulation
        self.providers: List[ThreatIntelProvider] = [
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            SimulatedThreatIntelProvider()  # Fallback provider, always available
        ]

    def lookup(
        self,
        indicator: str,
        indicator_type: Optional[str] = None,
        user_name: Optional[str] = None
    ) -> ThreatIntelResult:
        """
        Performs IOC lookup and enrichment across IPs, Domains, URLs, and File Hashes.
        Distinguishes Clean, Suspicious, Malicious, and Unknown verdicts.
        """
        clean_indicator = indicator.strip()
        resolved_type = indicator_type or detect_ioc_type(clean_indicator)
        now = datetime.now(timezone.utc)

        # 1. Cache Check
        cached = (
            self.db.query(ThreatIntelCache)
            .filter(ThreatIntelCache.indicator == clean_indicator)
            .first()
        )

        if cached:
            # Check expiration
            exp = cached.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)

            if exp > now:
                threats = [t.strip() for t in cached.threat_types.split(",") if t.strip()] if cached.threat_types else []
                attrs = json.loads(cached.raw_attributes) if cached.raw_attributes else {}

                self._log_query(clean_indicator, resolved_type, cached.verdict, cached.reputation_score, "Cache", user_name)

                return ThreatIntelResult(
                    indicator=cached.indicator,
                    indicator_type=cached.indicator_type,
                    verdict=cached.verdict,
                    reputation_score=cached.reputation_score,
                    is_malicious=cached.is_malicious,
                    threat_types=threats,
                    asn=cached.asn,
                    country_code=cached.country_code,
                    organization=attrs.get("organization"),
                    first_seen=cached.first_seen.isoformat() if cached.first_seen else None,
                    last_seen=cached.last_seen.isoformat() if cached.last_seen else None,
                    source_provider="AegisSOC Cache",
                    cache_hit=True,
                    attributes=attrs
                )

        # 2. Query Available Providers
        result: Optional[ThreatIntelResult] = None
        for prov in self.providers:
            if prov.is_available():
                try:
                    res = prov.lookup(clean_indicator, resolved_type)
                    if res:
                        result = res
                        break
                except Exception as e:
                    logger.warning(f"Provider {prov.name} failed for {clean_indicator}: {e}")

        if not result:
            result = ThreatIntelResult(
                indicator=clean_indicator,
                indicator_type=resolved_type,
                verdict="Unknown",
                reputation_score=0,
                is_malicious=False,
                threat_types=[],
                source_provider="None",
                cache_hit=False
            )

        # 3. Update or Insert Cache
        try:
            expires_at = now + timedelta(hours=self.cache_ttl_hours)
            raw_attrs_json = json.dumps(result.attributes)

            if cached:
                cached.indicator_type = result.indicator_type
                cached.reputation_score = result.reputation_score
                cached.is_malicious = result.is_malicious
                cached.verdict = result.verdict
                cached.threat_types = ",".join(result.threat_types)
                cached.asn = result.asn
                cached.country_code = result.country_code
                cached.raw_attributes = raw_attrs_json
                cached.expires_at = expires_at
                cached.last_seen = now
            else:
                new_cache = ThreatIntelCache(
                    indicator=result.indicator,
                    indicator_type=result.indicator_type,
                    reputation_score=result.reputation_score,
                    is_malicious=result.is_malicious,
                    verdict=result.verdict,
                    threat_types=",".join(result.threat_types),
                    asn=result.asn,
                    country_code=result.country_code,
                    raw_attributes=raw_attrs_json,
                    first_seen=now,
                    last_seen=now,
                    expires_at=expires_at
                )
                self.db.add(new_cache)

            self.db.commit()
        except Exception as e:
            logger.warning(f"Failed to cache threat intel result for {clean_indicator}: {e}")
            self.db.rollback()

        # 4. Record Query History
        self._log_query(clean_indicator, resolved_type, result.verdict, result.reputation_score, result.source_provider, user_name)

        return result

    def get_query_history(self, limit: int = 50) -> List[ThreatIntelQueryHistory]:
        """Returns chronological indicator query history."""
        return (
            self.db.query(ThreatIntelQueryHistory)
            .order_by(ThreatIntelQueryHistory.queried_at.desc())
            .limit(limit)
            .all()
        )

    def clear_cache(self, indicator: Optional[str] = None) -> int:
        """Flushes specific indicator or entire threat intelligence cache."""
        query = self.db.query(ThreatIntelCache)
        if indicator:
            query = query.filter(ThreatIntelCache.indicator == indicator.strip())
        deleted_count = query.delete(synchronize_session=False)
        self.db.commit()
        return deleted_count

    def _log_query(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str,
        reputation: int,
        provider_name: str,
        user_name: Optional[str]
    ):
        """Internal helper recording queries for auditability."""
        try:
            log_item = ThreatIntelQueryHistory(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                reputation_score=reputation,
                provider_name=provider_name,
                queried_by=user_name or "Analyst"
            )
            self.db.add(log_item)
            self.db.commit()
        except Exception as e:
            logger.warning(f"Failed to log threat intel query: {e}")
            self.db.rollback()
