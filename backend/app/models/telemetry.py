from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from app.core.database import Base
from app.models.base import generate_uuid, get_utc_now


class NetworkMetric(Base):
    __tablename__ = "network_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    inbound_mbps = Column(Float, nullable=False)
    outbound_mbps = Column(Float, nullable=False)
    packets_in = Column(Integer, default=0)
    packets_out = Column(Integer, default=0)
    dropped_packets = Column(Integer, default=0)
    recorded_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)


class NetworkNode(Base):
    __tablename__ = "network_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    node_name = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=False)
    role = Column(String(50), nullable=False)  # 'bastion', 'gateway', 'dmz-web', 'workstation', 'database'
    is_compromised = Column(Boolean, default=False, nullable=False)
    latency_ms = Column(Float, default=5.0, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)


class SystemHealthCheck(Base):
    __tablename__ = "system_health_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    service_name = Column(String(100), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="Healthy")  # 'Healthy', 'Degraded', 'Down'
    latency_ms = Column(Float, nullable=False)
    notes = Column(Text, nullable=True)
    checked_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
