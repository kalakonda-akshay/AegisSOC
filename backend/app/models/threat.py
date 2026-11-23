from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, get_utc_now


class Threat(Base, TimestampMixin):
    __tablename__ = "threats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False, default="ip")
    threat_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, default="High", index=True)  # 'Critical', 'High', 'Medium', 'Low'
    confidence = Column(Integer, nullable=False, default=85)
    category = Column(String(50), nullable=False, default="Malware")
    status = Column(String(30), nullable=False, default="Active", index=True)  # 'Active', 'Mitigated', 'Whitelisted'
    first_detected = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    last_detected = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
    details = Column(Text, nullable=True)

    organization = relationship("Organization", back_populates="threats")
