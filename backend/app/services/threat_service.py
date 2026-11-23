from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundException
from app.intelligence.engine import ThreatIntelEngine
from app.ml.anomaly_detector import anomaly_detector
from app.models.event import SecurityEvent
from app.repositories.event_repository import EventRepository
from app.schemas.event import (
    SecurityEventCreate,
    SecurityEventResponse,
    ThreatAnalyzeRequest,
    ThreatAnalyzeResponse
)
from app.websocket.manager import ws_manager


class ThreatService:
    def __init__(self, db: Session):
        self.db = db
        self.event_repo = EventRepository(db)
        self.intel_engine = ThreatIntelEngine(db)

    def get_recent_threats(self, limit: int = 25, severity: Optional[str] = None) -> List[SecurityEventResponse]:
        events = self.event_repo.get_recent_events(limit=limit, severity=severity)
        return [
            SecurityEventResponse(
                id=ev.id,
                t=ev.timestamp,
                src=ev.source_ip,
                dst=ev.destination_ip,
                type=ev.attack_type,
                sev=ev.severity,
                by=ev.detected_by,
                conf=ev.confidence
            ) for ev in events
        ]

    def get_threat_by_id(self, threat_id: str) -> SecurityEventResponse:
        ev = None
        if threat_id.isdigit():
            ev = self.db.query(SecurityEvent).filter(SecurityEvent.id == int(threat_id)).first()
        if not ev:
            ev = self.db.query(SecurityEvent).filter(SecurityEvent.event_uuid == threat_id).first()

        if not ev:
            raise NotFoundException(f"Threat event '{threat_id}' not found.")

        return SecurityEventResponse(
            id=ev.id,
            t=ev.timestamp,
            src=ev.source_ip,
            dst=ev.destination_ip,
            type=ev.attack_type,
            sev=ev.severity,
            by=ev.detected_by,
            conf=ev.confidence
        )

    def analyze_threat(self, req: ThreatAnalyzeRequest) -> ThreatAnalyzeResponse:
        score, calc_sev, calc_type = anomaly_detector.score_flow(
            source_ip=req.source_ip,
            destination_ip=req.destination_ip or "10.0.0.10",
            flow_data={
                "destination_port": req.destination_port or 80,
                "packet_count": req.packet_count or 100,
                "byte_count": req.byte_count or 50000,
                "raw_payload": req.raw_payload or ""
            }
        )

        intel_res = self.intel_engine.lookup(req.source_ip, "ip")

        rules = []
        if score > 0.8:
            rules.append("SIG-ANOMALY-01: Volumetric packet rate anomaly")
        if intel_res.is_malicious:
            rules.append(f"SIG-INTEL-04: Known malicious indicator ({', '.join(intel_res.threat_types)})")
        if req.destination_port in (22, 3389, 445):
            rules.append("SIG-PORT-02: High-risk administrative port probing")

        rec_actions = [
            f"Apply perimeter IP block on {req.source_ip}",
            "Audit ingress firewall telemetry on target subnet",
            "Enable connection rate limiting on gateway"
        ]

        return ThreatAnalyzeResponse(
            threat_classification=calc_type,
            anomaly_score=round(score, 3),
            risk_level=calc_sev,
            confidence=int(score * 100),
            matched_rules=rules or ["BASELINE-SIG-00: Generic flow baseline"],
            threat_intel_verdict=intel_res.verdict,
            recommended_actions=rec_actions,
            is_malicious=intel_res.is_malicious or (score >= 0.85)
        )

    async def record_event(self, event_in: SecurityEventCreate) -> SecurityEventResponse:
        score, calc_sev, calc_type = anomaly_detector.score_flow(
            source_ip=event_in.source_ip,
            destination_ip=event_in.destination_ip,
            flow_data={"attack_type": event_in.attack_type}
        )

        ev = SecurityEvent(
            source_ip=event_in.source_ip,
            destination_ip=event_in.destination_ip,
            attack_type=event_in.attack_type or calc_type,
            severity=event_in.severity or calc_sev,
            detected_by=event_in.detected_by,
            confidence=int(score * 100) if not event_in.confidence else event_in.confidence,
            raw_payload=event_in.raw_payload
        )
        created = self.event_repo.create(ev)
        self.db.commit()

        resp = SecurityEventResponse(
            id=created.id,
            t=created.timestamp,
            src=created.source_ip,
            dst=created.destination_ip,
            type=created.attack_type,
            sev=created.severity,
            by=created.detected_by,
            conf=created.confidence
        )

        # Broadcast to active WebSockets
        await ws_manager.broadcast_to_channel({
            "type": "security_event",
            "event": resp.model_dump(mode="json")
        }, "events")

        return resp
