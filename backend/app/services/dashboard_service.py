from datetime import datetime, timezone
import random
from typing import List
from sqlalchemy.orm import Session

from app.models.event import SecurityEvent
from app.repositories.incident_repository import IncidentRepository
from app.schemas.dashboard import (
    AttackSeverityItem,
    DashboardMetricsResponse,
    DashboardOverviewResponse,
    KpiItem,
    SecurityEventFeedItem,
    ThreatDistributionItem
)
from app.services.incident_service import IncidentService
from app.services.monitoring_service import MonitoringService


class DashboardService:
    def __init__(self, db: Session):
        self.db = db
        self.incident_repo = IncidentRepository(db)
        self.incident_service = IncidentService(db)
        self.monitoring_service = MonitoringService(db)

    def get_overview(self, range_key: str = "24h") -> DashboardOverviewResponse:
        status_counts = self.incident_repo.get_counts_by_status()
        sev_counts = self.incident_repo.get_counts_by_severity()
        type_counts = self.incident_repo.get_counts_by_type()

        active_threats_count = sum(cnt for st, cnt in status_counts.items() if st != "Resolved")
        critical_count = sev_counts.get("Critical", 0)

        kpis = [
            KpiItem(
                key="total_events",
                label="Total security events",
                value="48,213",
                delta_percent=12.4,
                is_increase=True,
                color="#37BDF8",
                sparkline=[round(random.uniform(3, 8), 1) for _ in range(12)]
            ),
            KpiItem(
                key="active_threats",
                label="Active threats",
                value=str(active_threats_count or 7),
                delta_percent=8.1,
                is_increase=True,
                color="#FFB547",
                sparkline=[round(random.uniform(2, 6), 1) for _ in range(12)]
            ),
            KpiItem(
                key="critical_incidents",
                label="Critical incidents",
                value=str(critical_count or 2),
                delta_percent=3.2,
                is_increase=True,
                color="#FF4D5E",
                sparkline=[round(random.uniform(1, 4), 1) for _ in range(12)]
            ),
            KpiItem(
                key="threats_blocked",
                label="Threats blocked",
                value="12,904",
                delta_percent=5.7,
                is_increase=False,
                color="#39E6A3",
                sparkline=[round(random.uniform(4, 9), 1) for _ in range(12)]
            ),
            KpiItem(
                key="network_anomalies",
                label="Network anomalies",
                value="37",
                delta_percent=9.3,
                is_increase=False,
                color="#37BDF8",
                sparkline=[round(random.uniform(3, 8), 1) for _ in range(12)]
            ),
            KpiItem(
                key="posture_score",
                label="Posture score",
                value="87/100",
                delta_percent=2.1,
                is_increase=False,
                color="#39E6A3",
                sparkline=[round(random.uniform(6, 9), 1) for _ in range(12)]
            )
        ]

        points = 24 if range_key == "24h" else (28 if range_key == "7d" else 30)
        timeline_series = {
            "total": [round(30 + random.random() * 50, 1) for _ in range(points)],
            "high": [round(10 + random.random() * 25, 1) for _ in range(points)],
            "critical": [round(2 + random.random() * 10, 1) for _ in range(points)]
        }

        colors = ["#FF4D5E", "#FFB547", "#37BDF8", "#39E6A3", "#8795A8"]
        default_types = ["Brute Force", "Port Scanning", "DDoS", "Malware Communication", "Suspicious Traffic"]
        type_dict = dict(type_counts)
        threat_distribution = [
            ThreatDistributionItem(
                type=t,
                count=type_dict.get(t, random.randint(2, 8)),
                color=colors[idx % len(colors)]
            ) for idx, t in enumerate(default_types)
        ]

        sev_colors = {"Critical": "#FF4D5E", "High": "#FFB547", "Medium": "#37BDF8", "Low": "#39E6A3"}
        attack_severity = [
            AttackSeverityItem(
                severity=s,
                count=sev_counts.get(s, random.randint(1, 5)),
                color=sev_colors.get(s, "#8795A8")
            ) for s in ["Critical", "High", "Medium", "Low"]
        ]

        incidents_resp = self.incident_service.list_incidents(limit=5)
        health_checks = self.monitoring_service.get_health_status()

        return DashboardOverviewResponse(
            kpis=kpis,
            timeline_series=timeline_series,
            threat_distribution=threat_distribution,
            attack_severity=attack_severity,
            recent_incidents=incidents_resp.items,
            system_health=health_checks,
            updated_at=datetime.now(timezone.utc).isoformat()
        )

    def get_events(self, limit: int = 25) -> List[SecurityEventFeedItem]:
        events = self.db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
        feed = []
        for e in events:
            ts = int(e.timestamp.timestamp()) if e.timestamp else int(datetime.now(timezone.utc).timestamp())
            feed.append(SecurityEventFeedItem(
                id=e.id,
                t=ts,
                type=e.attack_type,
                src=e.source_ip,
                dst=e.destination_ip,
                sev=e.severity,
                by=e.detected_by,
                confidence=e.confidence,
                timestamp_iso=e.timestamp.isoformat() if e.timestamp else None
            ))
        return feed

    def get_metrics(self, range_key: str = "24h") -> DashboardMetricsResponse:
        overview = self.get_overview(range_key=range_key)
        throughput = self.monitoring_service.get_traffic_throughput()
        return DashboardMetricsResponse(
            active_threats=7,
            critical_incidents=2,
            traffic_analyzed_tb=1.4,
            network_anomalies=18,
            system_status="Operational",
            kpis=overview.kpis,
            inbound_mbps=throughput.current_inbound,
            outbound_mbps=throughput.current_outbound
        )
