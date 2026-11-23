from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import generate_uuid, get_utc_now


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    event_uuid = Column(String(36), default=generate_uuid, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="TCP", nullable=False)
    attack_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # 'Critical', 'High', 'Medium', 'Low'
    detected_by = Column(String(100), nullable=False)  # 'ML anomaly model', 'Signature rule', 'Threat intel match', 'Behavioural baseline'
    confidence = Column(Integer, nullable=False, default=85)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    raw_payload = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="security_events")
