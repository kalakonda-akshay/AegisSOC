from sqlalchemy import BigInteger, Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import generate_uuid, get_utc_now


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(20), nullable=False, default="TCP")
    bytes_sent = Column(BigInteger, default=0, nullable=False)
    bytes_received = Column(BigInteger, default=0, nullable=False)
    packets_sent = Column(Integer, default=0, nullable=False)
    packets_received = Column(Integer, default=0, nullable=False)
    status = Column(String(30), nullable=False, default="ESTABLISHED", index=True)
    started_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, default=0.0, nullable=False)

    organization = relationship("Organization", back_populates="network_connections")
