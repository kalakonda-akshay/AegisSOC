"""
AegisSOC Network Monitoring Engine - Event Processor
Detects suspicious network patterns, port scans, brute force attempts,
volumetric floods, and C2 beacons. Generates standardized SecurityEvents.
"""

from collections import defaultdict
from dataclasses import asdict, dataclass, field
import datetime
import time
from typing import Any, Dict, List, Optional, Set
import uuid

from app.network.flow_analyzer import NetworkFlow
from app.network.packet_processor import ProcessedPacket

try:
    from sqlalchemy.orm import Session
    from app.models.event import SecurityEvent as SecurityEventModel
    DB_SUPPORT = True
except ImportError:
    DB_SUPPORT = False


@dataclass
class NetworkEvent:
    """Standardized event structure emitted by the detection rules."""
    event_uuid: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    attack_type: str
    severity: str  # Critical, High, Medium, Low, Info
    detected_by: str
    confidence: int  # 0 to 100
    traffic_type: str  # "simulated" or "live"
    description: str
    raw_payload: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventProcessor:
    """
    Evaluates packets and flows against heuristic rules and anomaly thresholds
    to identify suspicious activities and generate actionable security events.
    """

    SUSPICIOUS_C2_PORTS = {4444, 1337, 31337, 6667, 8888, 9001, 9999}
    AUTH_SERVICES = {22: "SSH", 3389: "RDP", 445: "SMB", 21: "FTP", 23: "Telnet"}

    def __init__(
        self,
        port_scan_threshold: int = 8,      # Unique ports in window
        brute_force_threshold: int = 5,    # Auth attempts in window
        syn_flood_threshold: int = 30,     # SYNs without ACKs
        window_seconds: float = 10.0
    ):
        self.port_scan_threshold = port_scan_threshold
        self.brute_force_threshold = brute_force_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.window_seconds = window_seconds

        # Sliding window state trackers:
        # src_ip -> list of (timestamp, dst_port)
        self.src_port_probes: Dict[str, List[tuple]] = defaultdict(list)
        # (src_ip, dst_port) -> list of timestamps
        self.auth_attempts: Dict[tuple, List[float]] = defaultdict(list)
        # src_ip -> list of timestamps for SYN-only packets
        self.syn_packet_times: Dict[str, List[float]] = defaultdict(list)
        # Deduplication tracker: (src_ip, attack_type) -> last_alert_time
        self.alert_dedup: Dict[tuple, float] = {}
        self.dedup_cooldown = 15.0

        # Generated events list
        self.generated_events: List[NetworkEvent] = []

    def evaluate_packet(self, packet: ProcessedPacket) -> List[NetworkEvent]:
        """
        Inspects an individual packet for immediate single-packet signatures
        (e.g., suspicious C2 ports, ICMP flood patterns).
        """
        events = []
        now = packet.timestamp

        # 1. Suspicious C2 Port Detection
        if packet.destination_port in self.SUSPICIOUS_C2_PORTS:
            dedup_key = (packet.source_ip, f"C2_PORT_{packet.destination_port}")
            if now - self.alert_dedup.get(dedup_key, 0) > self.dedup_cooldown:
                self.alert_dedup[dedup_key] = now
                event = NetworkEvent(
                    event_uuid=str(uuid.uuid4()),
                    timestamp=packet.datetime_utc,
                    source_ip=packet.source_ip,
                    destination_ip=packet.destination_ip,
                    source_port=packet.source_port,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    attack_type="Potential C2 Beacon",
                    severity="High",
                    detected_by="Suspicious Port Rule",
                    confidence=85,
                    traffic_type=packet.traffic_type,
                    description=f"Outbound connection attempt to known suspicious C2 port {packet.destination_port} [{packet.traffic_type.upper()}]",
                    raw_payload=packet.raw_preview
                )
                events.append(event)
                self.generated_events.append(event)

        # 2. Track Port Scan activity (SYN packets or TCP attempts to multiple ports)
        if packet.protocol in ("TCP", "HTTP", "TLS", "SSH") and packet.destination_port:
            probes = self.src_port_probes[packet.source_ip]
            probes.append((now, packet.destination_port))
            # Clean window
            cutoff = now - self.window_seconds
            self.src_port_probes[packet.source_ip] = [p for p in probes if p[0] >= cutoff]

            unique_ports = {p[1] for p in self.src_port_probes[packet.source_ip]}
            if len(unique_ports) >= self.port_scan_threshold:
                dedup_key = (packet.source_ip, "PORT_SCAN")
                if now - self.alert_dedup.get(dedup_key, 0) > self.dedup_cooldown:
                    self.alert_dedup[dedup_key] = now
                    event = NetworkEvent(
                        event_uuid=str(uuid.uuid4()),
                        timestamp=packet.datetime_utc,
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        source_port=packet.source_port,
                        destination_port=packet.destination_port,
                        protocol="TCP",
                        attack_type="Port Scanning Activity",
                        severity="Medium",
                        detected_by="Sequential Port Heuristic",
                        confidence=90,
                        traffic_type=packet.traffic_type,
                        description=f"Host probed {len(unique_ports)} distinct ports within {self.window_seconds}s [{packet.traffic_type.upper()}]",
                        raw_payload=packet.raw_preview
                    )
                    events.append(event)
                    self.generated_events.append(event)

        # 3. Authentication Brute Force Detection (repeated attempts to 22, 3389, etc.)
        if packet.destination_port in self.AUTH_SERVICES:
            service_name = self.AUTH_SERVICES[packet.destination_port]
            key = (packet.source_ip, packet.destination_port)
            attempts = self.auth_attempts[key]
            attempts.append(now)
            cutoff = now - self.window_seconds
            self.auth_attempts[key] = [t for t in attempts if t >= cutoff]

            if len(self.auth_attempts[key]) >= self.brute_force_threshold:
                dedup_key = (packet.source_ip, f"BRUTE_FORCE_{packet.destination_port}")
                if now - self.alert_dedup.get(dedup_key, 0) > self.dedup_cooldown:
                    self.alert_dedup[dedup_key] = now
                    event = NetworkEvent(
                        event_uuid=str(uuid.uuid4()),
                        timestamp=packet.datetime_utc,
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        source_port=packet.source_port,
                        destination_port=packet.destination_port,
                        protocol=packet.protocol,
                        attack_type=f"{service_name} Brute Force",
                        severity="High",
                        detected_by="Auth Attempt Threshold",
                        confidence=88,
                        traffic_type=packet.traffic_type,
                        description=f"Rapid {service_name} connection attempts ({len(self.auth_attempts[key])} requests in {self.window_seconds}s) [{packet.traffic_type.upper()}]",
                        raw_payload=packet.raw_preview
                    )
                    events.append(event)
                    self.generated_events.append(event)

        # 4. SYN Flood Detection (High rate of SYN-only packets)
        if packet.tcp_flags.get("SYN") and not packet.tcp_flags.get("ACK"):
            syn_times = self.syn_packet_times[packet.source_ip]
            syn_times.append(now)
            cutoff = now - self.window_seconds
            self.syn_packet_times[packet.source_ip] = [t for t in syn_times if t >= cutoff]

            if len(self.syn_packet_times[packet.source_ip]) >= self.syn_flood_threshold:
                dedup_key = (packet.source_ip, "SYN_FLOOD")
                if now - self.alert_dedup.get(dedup_key, 0) > self.dedup_cooldown:
                    self.alert_dedup[dedup_key] = now
                    event = NetworkEvent(
                        event_uuid=str(uuid.uuid4()),
                        timestamp=packet.datetime_utc,
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        source_port=packet.source_port,
                        destination_port=packet.destination_port,
                        protocol="TCP",
                        attack_type="SYN Flood Attack",
                        severity="Critical",
                        detected_by="Volumetric SYN Analyzer",
                        confidence=95,
                        traffic_type=packet.traffic_type,
                        description=f"Excessive SYN packet bursts ({len(self.syn_packet_times[packet.source_ip])} SYNs in {self.window_seconds}s without ACK completion) [{packet.traffic_type.upper()}]",
                        raw_payload=packet.raw_preview
                    )
                    events.append(event)
                    self.generated_events.append(event)

        return events

    def evaluate_flow(self, flow: NetworkFlow) -> List[NetworkEvent]:
        """
        Inspects an aggregated flow for behavioral anomalies
        (e.g., high packet rate, abnormal payload ratios, long-lived beaconing).
        """
        events = []
        now = flow.last_seen

        # High-rate volumetric flow anomaly (> 250 pps with high byte count)
        if flow.packets_per_second > 250.0 and flow.packet_count > 50:
            dedup_key = (flow.source_ip, "VOLUMETRIC_SPIKE")
            if now - self.alert_dedup.get(dedup_key, 0) > self.dedup_cooldown:
                self.alert_dedup[dedup_key] = now
                dt_utc = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()
                event = NetworkEvent(
                    event_uuid=str(uuid.uuid4()),
                    timestamp=dt_utc,
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    source_port=flow.source_port,
                    destination_port=flow.destination_port,
                    protocol=flow.protocol,
                    attack_type="Volumetric Traffic Spike",
                    severity="High",
                    detected_by="Flow Rate Baseline",
                    confidence=84,
                    traffic_type=flow.traffic_type,
                    description=f"Abnormal burst flow rate ({flow.packets_per_second} pps, {flow.bytes_per_second} Bps) [{flow.traffic_type.upper()}]",
                    raw_payload=""
                )
                events.append(event)
                self.generated_events.append(event)

        return events

    def persist_events_to_db(self, db: Any, events: List[NetworkEvent]) -> int:
        """
        Persists generated NetworkEvents to the database as SecurityEvent models.
        Returns count of saved events.
        """
        if not DB_SUPPORT or not events:
            return 0

        saved = 0
        try:
            for ev in events:
                db_event = SecurityEventModel(
                    event_uuid=ev.event_uuid,
                    source_ip=ev.source_ip,
                    destination_ip=ev.destination_ip,
                    source_port=ev.source_port,
                    destination_port=ev.destination_port,
                    protocol=ev.protocol,
                    attack_type=ev.attack_type,
                    severity=ev.severity,
                    detected_by=ev.detected_by,
                    confidence=ev.confidence,
                    raw_payload=ev.description + (f" | Raw: {ev.raw_payload}" if ev.raw_payload else "")
                )
                db.add(db_event)
                saved += 1
            db.commit()
        except Exception as e:
            if hasattr(db, "rollback"):
                db.rollback()
            return 0
        return saved

    def clear(self):
        """Clears all sliding window states and history."""
        self.src_port_probes.clear()
        self.auth_attempts.clear()
        self.syn_packet_times.clear()
        self.alert_dedup.clear()
        self.generated_events.clear()
