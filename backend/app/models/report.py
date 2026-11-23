from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import generate_uuid, get_utc_now


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False, default="incident_summary", index=True)  # 'incident_summary', 'executive_posture', 'compliance_audit'
    format = Column(String(20), nullable=False, default="csv")  # 'csv', 'json', 'pdf'
    parameters = Column(Text, nullable=True)  # JSON-encoded query filters
    file_path = Column(String(255), nullable=True)
    generated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False, index=True)

    organization = relationship("Organization", back_populates="security_reports")
    generated_by = relationship("User", foreign_keys=[generated_by_id])
