"""Initial schema with full SOC entity support

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-23 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Organizations
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False, unique=True),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 2. Roles
    op.create_table(
        'roles',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=50), nullable=False, unique=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('permissions', sa.Text(), nullable=False, default="[]"),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 3. Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=100), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, default='Security Analyst'),
        sa.Column('role_id', sa.String(length=36), sa.ForeignKey('roles.id', ondelete='SET NULL'), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_users_email', 'users', ['email'])
    op.create_index('ix_users_org', 'users', ['organization_id'])

    # 4. Refresh Tokens
    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 5. Network Connections
    op.create_table(
        'network_connections',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('destination_ip', sa.String(length=45), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=False, default='TCP'),
        sa.Column('bytes_sent', sa.BigInteger(), nullable=False, default=0),
        sa.Column('bytes_received', sa.BigInteger(), nullable=False, default=0),
        sa.Column('packets_sent', sa.Integer(), nullable=False, default=0),
        sa.Column('packets_received', sa.Integer(), nullable=False, default=0),
        sa.Column('status', sa.String(length=30), nullable=False, default='ESTABLISHED'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=False, default=0.0)
    )
    op.create_index('ix_net_conn_src', 'network_connections', ['source_ip'])
    op.create_index('ix_net_conn_dst', 'network_connections', ['destination_ip'])

    # 6. Threats
    op.create_table(
        'threats',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('indicator', sa.String(length=255), nullable=False),
        sa.Column('indicator_type', sa.String(length=50), nullable=False, default='ip'),
        sa.Column('threat_name', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, default='High'),
        sa.Column('confidence', sa.Integer(), nullable=False, default=85),
        sa.Column('category', sa.String(length=50), nullable=False, default='Malware'),
        sa.Column('status', sa.String(length=30), nullable=False, default='Active'),
        sa.Column('first_detected', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_detected', sa.DateTime(timezone=True), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_threats_ind', 'threats', ['indicator'])

    # 7. Incidents
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('incident_code', sa.String(length=32), nullable=False, unique=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('attack_type', sa.String(length=100), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('destination_ip', sa.String(length=45), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, default='Medium'),
        sa.Column('status', sa.String(length=30), nullable=False, default='New'),
        sa.Column('assigned_analyst_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('analyst_name', sa.String(length=100), nullable=False, default='Unassigned'),
        sa.Column('confidence', sa.Integer(), nullable=False, default=85),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('recommended_actions', sa.Text(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('contained_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_incidents_code', 'incidents', ['incident_code'])
    op.create_index('ix_incidents_status', 'incidents', ['status'])
    op.create_index('ix_incidents_sev', 'incidents', ['severity'])

    # 8. Incident Evidence
    op.create_table(
        'incident_evidence',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('data', sa.Text(), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 9. Incident Timeline
    op.create_table(
        'incident_timeline',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_name', sa.String(length=100), nullable=True),
        sa.Column('from_status', sa.String(length=30), nullable=True),
        sa.Column('to_status', sa.String(length=30), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 10. Incident Comments
    op.create_table(
        'incident_comments',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_name', sa.String(length=100), nullable=False),
        sa.Column('comment', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 11. Security Events
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('event_uuid', sa.String(length=36), nullable=False, unique=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('destination_ip', sa.String(length=45), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=20), nullable=False, default='TCP'),
        sa.Column('attack_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('detected_by', sa.String(length=100), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=False, default=85),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('raw_payload', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_events_ts', 'security_events', ['timestamp'])
    op.create_index('ix_events_src', 'security_events', ['source_ip'])

    # 12. Investigations
    op.create_table(
        'investigations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('incident_id', sa.String(length=36), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=True),
        sa.Column('lead_analyst_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False, default='In Progress'),
        sa.Column('severity', sa.String(length=20), nullable=False, default='Medium'),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 13. AI Conversations
    op.create_table(
        'ai_conversations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('investigation_id', sa.String(length=36), sa.ForeignKey('investigations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 14. AI Messages
    op.create_table(
        'ai_messages',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('conversation_id', sa.String(length=36), sa.ForeignKey('ai_conversations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('sender_role', sa.String(length=20), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('structured_sections', sa.Text(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=False, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 15. Threat Intelligence Cache
    op.create_table(
        'threat_intel_cache',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('indicator', sa.String(length=255), nullable=False, unique=True),
        sa.Column('indicator_type', sa.String(length=20), nullable=False),
        sa.Column('reputation_score', sa.Integer(), nullable=False, default=0),
        sa.Column('is_malicious', sa.Boolean(), nullable=False, default=False),
        sa.Column('verdict', sa.String(length=30), nullable=False, server_default='Unknown'),
        sa.Column('threat_types', sa.String(length=255), nullable=True),
        sa.Column('asn', sa.String(length=100), nullable=True),
        sa.Column('country_code', sa.String(length=10), nullable=True),
        sa.Column('raw_attributes', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_threat_intel_ind', 'threat_intel_cache', ['indicator'])

    # 16. Security Reports
    op.create_table(
        'security_reports',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('report_type', sa.String(length=50), nullable=False, default='incident_summary'),
        sa.Column('format', sa.String(length=20), nullable=False, default='csv'),
        sa.Column('parameters', sa.Text(), nullable=True),
        sa.Column('file_path', sa.String(length=255), nullable=True),
        sa.Column('generated_by_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )

    # 17. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('organization_id', sa.String(length=36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created', 'audit_logs', ['created_at'])

    # 18. Telemetry tables (Network Metrics, Nodes, Health)
    op.create_table(
        'network_metrics',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('inbound_mbps', sa.Float(), nullable=False),
        sa.Column('outbound_mbps', sa.Float(), nullable=False),
        sa.Column('packets_in', sa.Integer(), nullable=True, default=0),
        sa.Column('packets_out', sa.Integer(), nullable=True, default=0),
        sa.Column('dropped_packets', sa.Integer(), nullable=True, default=0),
        sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False)
    )

    op.create_table(
        'network_nodes',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('node_name', sa.String(length=100), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_compromised', sa.Boolean(), nullable=False, default=False),
        sa.Column('latency_ms', sa.Float(), nullable=False, default=5.0),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False)
    )

    op.create_table(
        'system_health_checks',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('service_name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False, default='Healthy'),
        sa.Column('latency_ms', sa.Float(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False)
    )


def downgrade() -> None:
    op.drop_table('system_health_checks')
    op.drop_table('network_nodes')
    op.drop_table('network_metrics')
    op.drop_table('audit_logs')
    op.drop_table('security_reports')
    op.drop_table('threat_intel_cache')
    op.drop_table('ai_messages')
    op.drop_table('ai_conversations')
    op.drop_table('investigations')
    op.drop_table('security_events')
    op.drop_table('incident_comments')
    op.drop_table('incident_timeline')
    op.drop_table('incident_evidence')
    op.drop_table('incidents')
    op.drop_table('threats')
    op.drop_table('network_connections')
    op.drop_table('refresh_tokens')
    op.drop_table('users')
    op.drop_table('roles')
    op.drop_table('organizations')
