"""
AegisSOC Network Monitoring Engine - Packet Processor
Extracts 5-tuples, protocols, TCP/UDP attributes, and packet features using Scapy.
"""

from dataclasses import asdict, dataclass, field
import datetime
import time
from typing import Any, Dict, List, Optional, Set

try:
    import scapy.all as scapy
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class ProcessedPacket:
    """Normalized, structured representation of an analyzed network packet."""
    packet_id: int
    timestamp: float
    datetime_utc: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP, DNS, HTTP, TLS, ARP, OTHER
    ip_version: int  # 4, 6, or 0 (non-IP)
    packet_size: int  # bytes
    payload_size: int  # bytes
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    tcp_flags_str: str = ""
    ttl: Optional[int] = None
    summary: str = ""
    traffic_type: str = "simulated"  # "simulated" or "live"
    raw_preview: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PacketProcessor:
    """
    Ingests and normalizes network packets.
    Extracts L2, L3, L4, and L7 metadata with robust fallback and error handling.
    """

    def __init__(self):
        self._packet_counter = 0

    @property
    def total_processed(self) -> int:
        return self._packet_counter

    def process_scapy_packet(
        self,
        packet: Any,
        traffic_type: str = "simulated"
    ) -> Optional[ProcessedPacket]:
        """
        Parses a Scapy packet object into a structured ProcessedPacket.
        Handles IP, IPv6, ARP, TCP, UDP, ICMP, DNS, HTTP, and TLS layers.
        """
        try:
            self._packet_counter += 1
            pkt_id = self._packet_counter

            # Timestamp extraction
            ts = float(getattr(packet, "time", time.time()))
            dt_utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
            pkt_len = len(packet)

            # L3 / Addressing
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            ip_version = 0
            ttl = None

            if SCAPY_AVAILABLE and packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                ip_version = 4
                ttl = int(ip_layer.ttl)
            elif SCAPY_AVAILABLE and packet.haslayer(IPv6):
                ip_layer = packet.getlayer(IPv6)
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
                ip_version = 6
                ttl = int(getattr(ip_layer, "hlim", 64))
            elif SCAPY_AVAILABLE and packet.haslayer(ARP):
                arp = packet.getlayer(ARP)
                src_ip = str(arp.psrc)
                dst_ip = str(arp.pdst)
                ip_version = 0
                return ProcessedPacket(
                    packet_id=pkt_id,
                    timestamp=ts,
                    datetime_utc=dt_utc,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=None,
                    destination_port=None,
                    protocol="ARP",
                    ip_version=0,
                    packet_size=pkt_len,
                    payload_size=len(getattr(arp, "payload", b"")),
                    summary=f"ARP {arp.op} who-has {dst_ip} tell {src_ip}",
                    traffic_type=traffic_type
                )
            else:
                # Non-IP or unsupported frame
                return None

            # L4 / Transport
            src_port = None
            dst_port = None
            protocol = "OTHER"
            payload_size = 0
            tcp_flags = {}
            tcp_flags_str = ""

            if SCAPY_AVAILABLE and packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                protocol = "TCP"
                payload_size = len(bytes(tcp_layer.payload))

                # Parse TCP flags
                raw_flags = int(tcp_layer.flags)
                tcp_flags = {
                    "FIN": bool(raw_flags & 0x01),
                    "SYN": bool(raw_flags & 0x02),
                    "RST": bool(raw_flags & 0x04),
                    "PSH": bool(raw_flags & 0x08),
                    "ACK": bool(raw_flags & 0x10),
                    "URG": bool(raw_flags & 0x20),
                    "ECE": bool(raw_flags & 0x40),
                    "CWR": bool(raw_flags & 0x80),
                }
                tcp_flags_str = "".join(f for f, set_ in tcp_flags.items() if set_)

                # Application layer heuristics
                if dst_port == 80 or src_port == 80 or dst_port == 8080:
                    protocol = "HTTP"
                elif dst_port == 443 or src_port == 443 or dst_port == 8443:
                    protocol = "TLS"
                elif dst_port == 22 or src_port == 22:
                    protocol = "SSH"
                elif dst_port == 3389 or src_port == 3389:
                    protocol = "RDP"

            elif SCAPY_AVAILABLE and packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                protocol = "UDP"
                payload_size = len(bytes(udp_layer.payload))

                if packet.haslayer(DNS) or dst_port == 53 or src_port == 53:
                    protocol = "DNS"
                elif dst_port in (67, 68) or src_port in (67, 68):
                    protocol = "DHCP"
                elif dst_port == 123 or src_port == 123:
                    protocol = "NTP"

            elif SCAPY_AVAILABLE and packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                protocol = "ICMP"
                payload_size = len(bytes(icmp_layer.payload))
                src_port = None
                dst_port = None

            # Payload preview (safe string snippet)
            raw_preview = ""
            try:
                raw_bytes = bytes(packet)
                if len(raw_bytes) > 64:
                    raw_preview = raw_bytes[:64].hex()
                else:
                    raw_preview = raw_bytes.hex()
            except Exception:
                raw_preview = ""

            summary = f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({pkt_len} bytes)"

            return ProcessedPacket(
                packet_id=pkt_id,
                timestamp=ts,
                datetime_utc=dt_utc,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                ip_version=ip_version,
                packet_size=pkt_len,
                payload_size=payload_size,
                tcp_flags=tcp_flags,
                tcp_flags_str=tcp_flags_str,
                ttl=ttl,
                summary=summary,
                traffic_type=traffic_type,
                raw_preview=raw_preview
            )

        except Exception as e:
            # Resilient packet parser: do not crash monitoring thread on malformed packet
            return None

    def process_raw_dict(
        self,
        pkt_dict: Dict[str, Any],
        traffic_type: str = "simulated"
    ) -> ProcessedPacket:
        """Parses a dictionary-based packet representation into ProcessedPacket."""
        self._packet_counter += 1
        ts = float(pkt_dict.get("timestamp", time.time()))
        dt_utc = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
        return ProcessedPacket(
            packet_id=self._packet_counter,
            timestamp=ts,
            datetime_utc=dt_utc,
            source_ip=pkt_dict.get("source_ip", "0.0.0.0"),
            destination_ip=pkt_dict.get("destination_ip", "0.0.0.0"),
            source_port=pkt_dict.get("source_port"),
            destination_port=pkt_dict.get("destination_port"),
            protocol=pkt_dict.get("protocol", "TCP").upper(),
            ip_version=int(pkt_dict.get("ip_version", 4)),
            packet_size=int(pkt_dict.get("packet_size", 64)),
            payload_size=int(pkt_dict.get("payload_size", 0)),
            tcp_flags=pkt_dict.get("tcp_flags", {}),
            tcp_flags_str=pkt_dict.get("tcp_flags_str", ""),
            ttl=pkt_dict.get("ttl", 64),
            summary=pkt_dict.get("summary", ""),
            traffic_type=traffic_type,
            raw_preview=pkt_dict.get("raw_preview", "")
        )
