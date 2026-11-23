import pytest
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.models.organization import Organization
from app.models.user import User, Role, RefreshToken
from app.models.connection import NetworkConnection
from app.models.threat import Threat
from app.models.incident import Incident, IncidentEvidence, IncidentTimeline, IncidentComment
from app.models.event import SecurityEvent
from app.models.investigation import Investigation, AIConversation, AIMessage
from app.models.threat_intel import ThreatIntelCache
from app.models.report import SecurityReport
from app.models.audit import AuditLog
from app.models.telemetry import NetworkNode, SystemHealthCheck, NetworkMetric


def test_database_models_integrity(db_session: Session):
    # Verify Organizations
    org = db_session.scalars(select(Organization).limit(1)).first()
    assert org is not None
    assert org.slug == "aegis-global"

    # Verify Roles
    roles = db_session.scalars(select(Role)).all()
    role_names = [r.name for r in roles]
    assert "Admin" in role_names
    assert "Security Analyst" in role_names
    assert "Viewer" in role_names

    # Verify Users with Roles
    users = db_session.scalars(select(User)).all()
    assert len(users) >= 7
    roles_assigned = set(u.role for u in users)
    assert "Admin" in roles_assigned
    assert "Security Analyst" in roles_assigned
    assert "Viewer" in roles_assigned

    # Verify Incidents & Evidence
    incidents = db_session.scalars(select(Incident)).all()
    assert len(incidents) >= 10
    first_inc = incidents[0]
    assert len(first_inc.evidence) >= 1
    assert len(first_inc.timeline) >= 1

    # Verify Threats
    threats = db_session.scalars(select(Threat)).all()
    assert len(threats) >= 2
    threat_indicators = [t.indicator for t in threats]
    assert "185.45.103.91" in threat_indicators

    # Verify Network Connections
    connections = db_session.scalars(select(NetworkConnection)).all()
    assert len(connections) >= 3
    conn_statuses = [c.status for c in connections]
    assert "ESTABLISHED" in conn_statuses

    # Verify Security Events
    events = db_session.scalars(select(SecurityEvent)).all()
    assert len(events) >= 15

    # Verify Audit Logs
    audit_logs = db_session.scalars(select(AuditLog)).all()
    assert len(audit_logs) >= 1
    assert audit_logs[0].action == "SYSTEM_INIT"

    # Verify Telemetry & Nodes
    nodes = db_session.scalars(select(NetworkNode)).all()
    assert len(nodes) == 8

    health = db_session.scalars(select(SystemHealthCheck)).all()
    assert len(health) == 5

    metrics = db_session.scalars(select(NetworkMetric)).all()
    assert len(metrics) == 40
