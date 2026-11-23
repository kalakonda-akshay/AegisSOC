from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IndicatorLookupRequest(BaseModel):
    indicator: str = Field(..., description="IP address, Domain, URL, or File Hash")
    indicator_type: Optional[str] = Field(None, description="'ip', 'domain', 'url', 'hash', or None for auto-detection")


class IndicatorLookupResponse(BaseModel):
    indicator: str
    indicator_type: str
    verdict: str  # 'Clean', 'Suspicious', 'Malicious', 'Unknown'
    reputation_score: int  # 0 to 100
    is_malicious: bool
    threat_types: List[str] = Field(default_factory=list)
    asn: Optional[str] = None
    country_code: Optional[str] = None
    organization: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_provider: str = "AegisSOC Intelligence Engine"
    cache_hit: bool = False
    attributes: Dict[str, Any] = Field(default_factory=dict)


class IOCListItem(BaseModel):
    id: str
    indicator: str
    indicator_type: str
    verdict: str
    reputation_score: int
    is_malicious: bool
    threat_types: List[str] = Field(default_factory=list)
    country_code: Optional[str] = None
    last_seen: Optional[datetime] = None


class PaginatedIOCResponse(BaseModel):
    items: List[IOCListItem]
    total: int
    page: int
    limit: int
    pages: int


class ThreatIntelQueryHistoryItem(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    verdict: str
    reputation_score: int
    provider_name: str
    queried_by: str
    queried_at: datetime


class CacheClearResponse(BaseModel):
    success: bool
    entries_removed: int
    message: str
