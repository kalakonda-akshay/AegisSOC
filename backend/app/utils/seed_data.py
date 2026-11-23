from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.core.logging import logger
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.connection import NetworkConnection
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvidence, IncidentTimeline
from app.models.organization import Organization
from app.models.telemetry import NetworkMetric, NetworkNode, SystemHealthCheck
from app.models.threat import Threat
from app.models.user import Role, User


def seed_initial_data(db: Session) -> None:
    """Populates the database with initial organization, roles, analysts, and baseline records."""
    # 1. Seed Organization
    org_count = db.scalar(select(func.count(Organization.id))) or 0
    if org_count == 0:
        logger.info("Seeding default organization...")
        org = Organization(
            name="Aegis Global Operations",
            slug="aegis-global",
            domain="soc.aegis.internal",
            is_active=True
        )
        db.add(org)
        db.flush()
    else:
        org = db.scalars(select(Organization).limit(1)).first()

    # 2. Seed Roles (Admin, Security Analyst, Viewer)
    role_count = db.scalar(select(func.count(Role.id))) or 0
    if role_count == 0:
        logger.info("Seeding default SOC roles...")
        roles = [
            Role(name="Admin", description="Super Admin with full platform access", permissions='["*"]'),
            Role(name="Security Analyst", description="Security Analyst conducting triage & containment", permissions='["incidents:*", "investigations:*", "threats:*", "reports:*", "events:read", "analytics:read"]'),
            Role(name="Viewer", description="Read-only compliance auditor & viewer", permissions='["incidents:read", "events:read", "reports:read", "analytics:read"]')
        ]
        db.add_all(roles)
        db.flush()

    # 3. Seed Users
    user_count = db.scalar(select(func.count(User.id))) or 0
    if user_count == 0:
        logger.info("Seeding default SOC users...")
        admin_hash = hash_password("AdminPass123!")
        analyst_hash = hash_password("AnalystPass123!")
        viewer_hash = hash_password("ViewerPass123!")

        users = [
            User(organization_id=org.id, email="admin@soc.aegis.internal", full_name="SOC Administrator", hashed_password=admin_hash, role="Admin"),
            User(organization_id=org.id, email="analyst@soc.aegis.internal", full_name="Security Analyst", hashed_password=analyst_hash, role="Security Analyst"),
            User(organization_id=org.id, email="viewer@soc.aegis.internal", full_name="Compliance Auditor", hashed_password=viewer_hash, role="Viewer"),
            User(organization_id=org.id, email="a.rao@soc.aegis.internal", full_name="A. Rao", hashed_password=analyst_hash, role="Security Analyst"),
            User(organization_id=org.id, email="m.iyer@soc.aegis.internal", full_name="M. Iyer", hashed_password=analyst_hash, role="Security Analyst"),
            User(organization_id=org.id, email="s.khan@soc.aegis.internal", full_name="S. Khan", hashed_password=analyst_hash, role="Security Analyst"),
            User(organization_id=org.id, email="p.nair@soc.aegis.internal", full_name="P. Nair", hashed_password=analyst_hash, role="Security Analyst")
        ]
        db.add_all(users)
        db.flush()

    # 4. Seed Incidents
    inc_count = db.scalar(select(func.count(Incident.id))) or 0
    if inc_count == 0:
        logger.info("Seeding baseline security incidents...")
        titles = [
            "SSH credential stuffing against bastion host",
            "Horizontal port sweep on DMZ subnet",
            "Volumetric UDP flood on API gateway",
            "Beaconing to known C2 domain from endpoint",
            "Anomalous outbound transfer to unknown ASN",
            "RDP brute force from rotating proxies",
            "Slow HTTP flood on public web tier",
            "DNS tunnelling pattern from finance VLAN",
            "Repeated failed MFA from foreign geolocation",
            "Internal lateral scan from workstation"
        ]
        types = ["Brute Force", "Port Scanning", "DDoS", "Malware Communication", "Suspicious Traffic"]
        sevs = ["Critical", "High", "High", "Critical", "Medium", "High", "Medium", "Medium", "Low", "Medium"]
        statuses = ["Investigating", "New", "Investigating", "Contained", "New", "Resolved", "Investigating", "New", "Resolved", "Investigating"]
        analysts_pool = ["A. Rao", "M. Iyer", "S. Khan", "P. Nair"]
        ips = ["185.45.103.91", "45.132.88.14", "194.26.29.112", "23.106.56.201", "103.245.92.10"]

        now = datetime.now(timezone.utc)
        for i, t in enumerate(titles):
            inc = Incident(
                organization_id=org.id,
                incident_code=f"INC-{2041 + i}",
                title=t,
                description=f"Automated threat detection flagged unusual {types[i % 5]} patterns targeting production infrastructure.",
                attack_type=types[i % 5],
                source_ip=ips[i % len(ips)],
                destination_ip=f"10.0.{i % 4}.{10 + i * 3}",
                severity=sevs[i],
                status=statuses[i],
                analyst_name=analysts_pool[i % 4],
                confidence=78 + (i * 3 % 20),
                ai_summary=f"Pattern is consistent with {types[i % 5].lower()} activity originating from {ips[i % len(ips)]}. Correlated with {3 + i % 4} related flows in the last hour.",
                recommended_actions="Enforce account lockout, require MFA, block source range at the perimeter." if types[i % 5] == "Brute Force" else "Rate-limit scanning sources, review exposed services, add IDS rule.",
                detected_at=now - timedelta(hours=i * 2 + 1)
            )
            db.add(inc)
            db.flush()

            # Add incident evidence
            evd = IncidentEvidence(
                incident_id=inc.id,
                evidence_type="ip_flow",
                data=f'{{"source": "{ips[i % len(ips)]}", "destination": "10.0.{i % 4}.{10 + i * 3}", "packets": {5000 + i * 400}, "alert": "{t}"}}',
                description=f"Network flow packet capture summary for {inc.incident_code}",
                source="Suricata IDS Sensor 01"
            )
            db.add(evd)

            # Add initial timeline
            tl = IncidentTimeline(
                incident_id=inc.id,
                user_name="ML Detection Engine",
                from_status=None,
                to_status=statuses[i],
                notes="Initial threat correlation and incident creation."
            )
            db.add(tl)

    # 5. Seed Security Events
    ev_count = db.scalar(select(func.count(SecurityEvent.id))) or 0
    if ev_count == 0:
        logger.info("Seeding initial security events...")
        types = ["Brute Force", "Port Scanning", "DDoS", "Malware Communication", "Suspicious Traffic"]
        sevs = ["Critical", "High", "Medium", "Low"]
        engines = ["ML anomaly model", "Signature rule", "Threat intel match", "Behavioural baseline"]
        now = datetime.now(timezone.utc)
        events = []
        for i in range(15):
            port = 40000 + i * 100
            events.append(SecurityEvent(
                organization_id=org.id,
                source_ip=f"185.45.{i+10}.{i*5+1}",
                destination_ip=f"10.0.{i%4}.{i*7+2}",
                source_port=port,
                destination_port=22 if i % 2 == 0 else 443,
                protocol="TCP",
                attack_type=types[i % len(types)],
                severity=sevs[i % len(sevs)],
                detected_by=engines[i % len(engines)],
                confidence=80 + (i % 18),
                timestamp=now - timedelta(minutes=i * 4 + 2)
            ))
        db.add_all(events)

    # 6. Seed Threats
    threat_count = db.scalar(select(func.count(Threat.id))) or 0
    if threat_count == 0:
        logger.info("Seeding active threat indicators...")
        threats = [
            Threat(organization_id=org.id, indicator="185.45.103.91", indicator_type="ip", threat_name="SSH BruteForce Bot", severity="Critical", confidence=95, category="Botnet", status="Active"),
            Threat(organization_id=org.id, indicator="45.132.88.14", indicator_type="ip", threat_name="Mirai Scanner Variant", severity="High", confidence=88, category="Scanner", status="Active"),
            Threat(organization_id=org.id, indicator="malicious-c2-beacon.xyz", indicator_type="domain", threat_name="Cobalt Strike C2", severity="Critical", confidence=98, category="C2", status="Active"),
            Threat(organization_id=org.id, indicator="194.26.29.112", indicator_type="ip", threat_name="Emotet Loader Relay", severity="Critical", confidence=92, category="Malware", status="Mitigated")
        ]
        db.add_all(threats)

    # 7. Seed Network Connections
    conn_count = db.scalar(select(func.count(NetworkConnection.id))) or 0
    if conn_count == 0:
        logger.info("Seeding network connections...")
        connections = [
            NetworkConnection(organization_id=org.id, source_ip="185.45.103.91", destination_ip="10.0.0.10", source_port=54212, destination_port=22, protocol="TCP", bytes_sent=152000, bytes_received=84000, packets_sent=450, packets_received=380, status="RESET", duration_seconds=12.4),
            NetworkConnection(organization_id=org.id, source_ip="45.132.88.14", destination_ip="10.0.1.13", source_port=49152, destination_port=80, protocol="TCP", bytes_sent=4800, bytes_received=1200, packets_sent=12, packets_received=8, status="CLOSED", duration_seconds=1.2),
            NetworkConnection(organization_id=org.id, source_ip="10.0.3.99", destination_ip="194.26.29.112", source_port=60124, destination_port=443, protocol="TCP", bytes_sent=2840000, bytes_received=540000, packets_sent=3200, packets_received=1800, status="ESTABLISHED", duration_seconds=184.0)
        ]
        db.add_all(connections)

    # 8. Seed Network Nodes & Health Checks
    node_count = db.scalar(select(func.count(NetworkNode.id))) or 0
    if node_count == 0:
        logger.info("Seeding network nodes...")
        nodes = [
            NetworkNode(node_name="bastion-01", ip_address="10.0.0.10", role="bastion", is_compromised=False, latency_ms=4.1),
            NetworkNode(node_name="edge-gateway", ip_address="10.0.0.1", role="gateway", is_compromised=False, latency_ms=2.3),
            NetworkNode(node_name="dmz-web-01", ip_address="10.0.1.13", role="dmz-web", is_compromised=True, latency_ms=19.4),
            NetworkNode(node_name="finance-sql", ip_address="10.0.2.5", role="database", is_compromised=False, latency_ms=3.2),
            NetworkNode(node_name="ad-domain-ctrl", ip_address="10.0.0.2", role="auth", is_compromised=False, latency_ms=1.8),
            NetworkNode(node_name="workstation-corp", ip_address="10.0.3.99", role="endpoint", is_compromised=True, latency_ms=25.1),
            NetworkNode(node_name="api-reverse-proxy", ip_address="10.0.1.50", role="proxy", is_compromised=False, latency_ms=5.4),
            NetworkNode(node_name="backup-storage", ip_address="10.0.2.100", role="storage", is_compromised=False, latency_ms=6.8)
        ]
        db.add_all(nodes)

    health_count = db.scalar(select(func.count(SystemHealthCheck.id))) or 0
    if health_count == 0:
        logger.info("Seeding system health checks...")
        health = [
            SystemHealthCheck(service_name="Network monitoring", status="Healthy", latency_ms=12.0),
            SystemHealthCheck(service_name="ML detection engine", status="Healthy", latency_ms=38.0),
            SystemHealthCheck(service_name="AI investigation engine", status="Healthy", latency_ms=210.0),
            SystemHealthCheck(service_name="Threat intelligence", status="Degraded", latency_ms=640.0, notes="Mock feed active"),
            SystemHealthCheck(service_name="Database connection", status="Healthy", latency_ms=4.0)
        ]
        db.add_all(health)

    metric_count = db.scalar(select(func.count(NetworkMetric.id))) or 0
    if metric_count == 0:
        logger.info("Seeding network throughput baseline...")
        now = datetime.now(timezone.utc)
        metrics = []
        for i in range(40):
            metrics.append(NetworkMetric(
                inbound_mbps=round(40.0 + (i * 1.5 % 35), 2),
                outbound_mbps=round(20.0 + (i * 1.1 % 20), 2),
                packets_in=25000 + i * 500,
                packets_out=14000 + i * 300,
                dropped_packets=i % 3,
                recorded_at=now - timedelta(seconds=(40 - i) * 2)
            ))
        db.add_all(metrics)

    # 9. Seed Audit Log sample
    audit_count = db.scalar(select(func.count(AuditLog.id))) or 0
    if audit_count == 0:
        db.add(AuditLog(
            organization_id=org.id,
            user_email="system@soc.aegis.internal",
            action="SYSTEM_INIT",
            resource_type="platform",
            resource_id="core",
            ip_address="127.0.0.1",
            details='{"event": "AegisSOC database successfully initialized with Zero Trust controls"}'
        ))

    db.commit()
    logger.info("Database seeding completed.")
