from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, get_utc_now


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    incident_code = Column(String(32), unique=True, nullable=False, index=True)  # e.g. 'INC-2041'
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    attack_type = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # 'Critical', 'High', 'Medium', 'Low'
    status = Column(String(30), nullable=False, default="New", index=True)  # 'New', 'Investigating', 'Contained', 'Resolved'
    assigned_analyst_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    analyst_name = Column(String(100), nullable=False, default="Unassigned")
    confidence = Column(Integer, nullable=False, default=85)
    ai_summary = Column(Text, nullable=True)
    recommended_actions = Column(Text, nullable=True)
    detected_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="incidents")
    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id])
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentTimeline.created_at.asc()")
    comments = relationship("IncidentComment", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentComment.created_at.asc()")
    investigations = relationship("Investigation", back_populates="incident", cascade="all, delete-orphan")
    response_actions = relationship("IncidentResponseAction", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentResponseAction.created_at.desc()")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False)  # 'pcap', 'log_snippet', 'hash', 'ip_flow', 'memory_dump'
    data = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    collected_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    incident = relationship("Incident", back_populates="evidence")


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_name = Column(String(100), nullable=True)
    from_status = Column(String(30), nullable=True)
    to_status = Column(String(30), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    incident = relationship("Incident", back_populates="timeline")


class IncidentComment(Base):
    __tablename__ = "incident_comments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_name = Column(String(100), nullable=False)
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    incident = relationship("Incident", back_populates="comments")


class IncidentResponseAction(Base):
    __tablename__ = "incident_response_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(50), nullable=False)  # 'SUSPICIOUS_ACCOUNT_REVIEW', 'ENDPOINT_ISOLATION_PLAN', 'FIREWALL_RULE_REVIEW', 'EVIDENCE_PRESERVATION'
    title = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(30), default="PROPOSED", nullable=False, index=True)  # 'PROPOSED', 'APPROVED', 'REJECTED', 'EXECUTED'
    mode = Column(String(30), default="SIMULATION", nullable=False)              # 'SIMULATION', 'LIVE_AUTHORIZED'
    proposed_by = Column(String(100), nullable=False, default="AI Security Analyst")
    approved_by = Column(String(100), nullable=True)
    approval_notes = Column(Text, nullable=True)
    details = Column(Text, nullable=True)          # JSON-encoded parameters and draft rule/plan
    execution_result = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)

    incident = relationship("Incident", back_populates="response_actions")
