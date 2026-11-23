"""
AegisSOC AI Security Analyst - Grounded Context Builder
Extracts verifiable incidents, evidence files, telemetry, and past conversation turns
from the database, sanitizing untrusted inputs before injecting into LLM prompts.
"""

from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.ai.sanitizer import format_untrusted_evidence, sanitize_untrusted_input
from app.models.connection import NetworkConnection
from app.models.event import SecurityEvent
from app.models.incident import Incident, IncidentEvidence
from app.models.investigation import AIConversation, AIMessage


class ContextBuilder:
    """Builds sanitized, grounded context windows from database records."""

    def __init__(self, db: Session):
        self.db = db

    def resolve_target_incident(
        self,
        incident_id_or_code: Optional[str] = None,
        user_prompt: str = ""
    ) -> Optional[Incident]:
        """
        Resolves the incident entity to investigate.
        Checks direct ID/code, searches keyword in prompt, or falls back to most critical incident.
        """
        if incident_id_or_code:
            inc = (
                self.db.query(Incident)
                .filter((Incident.id == incident_id_or_code) | (Incident.incident_code == incident_id_or_code))
                .first()
            )
            if inc:
                return inc

        prompt_lower = user_prompt.lower()
        query = self.db.query(Incident)

        # Keyword mapping to attack types
        if "brute" in prompt_lower:
            match = query.filter(Incident.attack_type.ilike("%brute%")).first()
            if match:
                return match
        if "port" in prompt_lower or "scan" in prompt_lower:
            match = query.filter(Incident.attack_type.ilike("%port%")).first()
            if match:
                return match
        if "ddos" in prompt_lower or "flood" in prompt_lower:
            match = query.filter(Incident.attack_type.ilike("%ddos%")).first()
            if match:
                return match
        if "malware" in prompt_lower or "c2" in prompt_lower or "beacon" in prompt_lower:
            match = query.filter(Incident.attack_type.ilike("%malware%")).first()
            if match:
                return match

        # Default to highest severity active incident
        critical_inc = query.filter(Incident.severity == "Critical").first()
        if critical_inc:
            return critical_inc

        return query.first()

    def build_incident_context(self, incident: Incident) -> Tuple[str, str]:
        """
        Retrieves actual evidence items and related security events from the database,
        sanitizing and packaging them into tagged untrusted blocks.
        """
        # 1. Collect IncidentEvidence rows
        evidence_rows = (
            self.db.query(IncidentEvidence)
            .filter(IncidentEvidence.incident_id == incident.id)
            .limit(10)
            .all()
        )
        evidence_blocks = []
        if evidence_rows:
            for ev in evidence_rows:
                block = format_untrusted_evidence(
                    evidence_id=ev.id,
                    evidence_type=ev.evidence_type,
                    content=f"Description: {ev.description or 'None'}\nSource: {ev.source or 'Sensor'}\nPayload:\n{ev.data}"
                )
                evidence_blocks.append(block)
        else:
            evidence_blocks.append(
                format_untrusted_evidence(
                    evidence_id="DB-DEFAULT-EVID",
                    evidence_type="flow_summary",
                    content=f"Observed flow: {incident.source_ip} -> {incident.destination_ip} ({incident.attack_type})."
                )
            )

        # 2. Collect matching SecurityEvents from DB
        events = (
            self.db.query(SecurityEvent)
            .filter(
                (SecurityEvent.incident_id == incident.id) |
                (SecurityEvent.source_ip == incident.source_ip) |
                (SecurityEvent.destination_ip == incident.destination_ip)
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(5)
            .all()
        )
        event_lines = []
        for e in events:
            event_lines.append(
                f"- [{e.timestamp}] {e.attack_type} (Severity: {e.severity}, Conf: {e.confidence}%) "
                f"{e.source_ip}:{e.source_port} -> {e.destination_ip}:{e.destination_port} ({e.protocol}) "
                f"Detected by: {e.detected_by}"
            )
        events_block = "\n".join(event_lines) if event_lines else "No additional raw telemetry events found in database."

        return "\n\n".join(evidence_blocks), events_block

    def get_conversation_history(
        self,
        conversation_id: str,
        limit: int = 6
    ) -> List[Dict[str, str]]:
        """Retrieves recent conversation messages for conversational memory."""
        messages = (
            self.db.query(AIMessage)
            .filter(AIMessage.conversation_id == conversation_id)
            .order_by(AIMessage.created_at.desc())
            .limit(limit)
            .all()
        )
        history = []
        for m in reversed(messages):
            history.append({
                "role": m.sender_role,
                "content": m.content
            })
        return history
