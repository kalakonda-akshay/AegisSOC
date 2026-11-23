from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    domain = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="organization", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="organization", cascade="all, delete-orphan")
    network_connections = relationship("NetworkConnection", back_populates="organization", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="organization", cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="organization", cascade="all, delete-orphan")
    security_reports = relationship("SecurityReport", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")
