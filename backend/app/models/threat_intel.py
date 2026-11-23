from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from app.core.database import Base
from app.models.base import generate_uuid, get_utc_now


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    indicator = Column(String(255), unique=True, nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False)  # 'ip', 'domain', 'hash', 'url'
    reputation_score = Column(Integer, nullable=False, default=0)
    is_malicious = Column(Boolean, default=False, nullable=False)
    verdict = Column(String(30), default="Unknown", nullable=False)  # 'Clean', 'Suspicious', 'Malicious', 'Unknown'
    threat_types = Column(String(255), nullable=True)     # 'Botnet,C2,Ransomware'
    asn = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True)
    raw_attributes = Column(Text, nullable=True)          # JSON-encoded raw vendor reports
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)


class ThreatIntelQueryHistory(Base):
    __tablename__ = "threat_intel_query_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    indicator = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(20), nullable=False)
    verdict = Column(String(30), nullable=False)
    reputation_score = Column(Integer, nullable=False)
    provider_name = Column(String(100), nullable=False)
    queried_by = Column(String(100), nullable=True)
    queried_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
