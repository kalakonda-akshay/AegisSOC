"""
AegisSOC Network Monitoring Engine - Flow Analyzer
Aggregates bidirectional network flows, extracts temporal & statistical features,
and computes real-time traffic statistics and protocol distributions.
"""

from collections import defaultdict
from dataclasses import asdict, dataclass, field
import datetime
import math
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from app.network.packet_processor import ProcessedPacket


@dataclass
class NetworkFlow:
    """Represents an aggregated bidirectional network flow between two endpoints."""
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str
    traffic_type: str  # "simulated" or "live"
    start_time: float
    last_seen: float
    duration_seconds: float = 0.0

    # Packet & byte counts
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0

    # Rate statistics
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # TCP flag counts
    tcp_flags_count: Dict[str, int] = field(default_factory=lambda: {
        "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0
    })

    # State & connection metrics
    state: str = "NEW"  # NEW, ESTABLISHED, TERMINATED, TIMED_OUT
    connection_frequency: float = 0.0  # recent connection rate from src IP
    is_bidirectional: bool = False

    def update_with_packet(self, pkt: ProcessedPacket, is_forward: bool = True):
        """Updates flow counters and temporal metrics with an incoming packet."""
        self.packet_count += 1
        self.byte_count += pkt.packet_size
        self.last_seen = pkt.timestamp
        self.duration_seconds = max(0.0001, self.last_seen - self.start_time)

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += pkt.packet_size
        else:
            self.reverse_packets += 1
            self.reverse_bytes += pkt.packet_size
            self.is_bidirectional = True

        # Update rates
        self.packets_per_second = round(self.packet_count / self.duration_seconds, 2)
        self.bytes_per_second = round(self.byte_count / self.duration_seconds, 2)

        # Update TCP flags
        if pkt.tcp_flags:
            for flag, set_ in pkt.tcp_flags.items():
                if set_ and flag in self.tcp_flags_count:
                    self.tcp_flags_count[flag] += 1

            if pkt.tcp_flags.get("SYN") and not pkt.tcp_flags.get("ACK"):
                if self.state == "NEW":
                    self.state = "SYN_SENT"
            elif pkt.tcp_flags.get("SYN") and pkt.tcp_flags.get("ACK"):
                self.state = "SYN_RCVD"
            elif pkt.tcp_flags.get("ACK") and self.state in ("SYN_SENT", "SYN_RCVD"):
                self.state = "ESTABLISHED"
            elif pkt.tcp_flags.get("FIN") or pkt.tcp_flags.get("RST"):
                self.state = "TERMINATED"

    def extract_features(self) -> Dict[str, float]:
        """
        Extracts tabular numerical features formatted for ML anomaly and threat detection models.
        """
        fwd_b_ratio = self.forward_bytes / max(1, self.byte_count)
        fwd_p_ratio = self.forward_packets / max(1, self.packet_count)
        avg_pkt_size = self.byte_count / max(1, self.packet_count)
        syn_ratio = self.tcp_flags_count.get("SYN", 0) / max(1, self.packet_count)
        rst_ratio = self.tcp_flags_count.get("RST", 0) / max(1, self.packet_count)

        return {
            "duration": float(round(self.duration_seconds, 4)),
            "packet_count": float(self.packet_count),
            "byte_count": float(self.byte_count),
            "packets_per_second": float(self.packets_per_second),
            "bytes_per_second": float(self.bytes_per_second),
            "forward_bytes_ratio": float(round(fwd_b_ratio, 4)),
            "forward_packets_ratio": float(round(fwd_p_ratio, 4)),
            "average_packet_size": float(round(avg_pkt_size, 2)),
            "syn_count": float(self.tcp_flags_count.get("SYN", 0)),
            "ack_count": float(self.tcp_flags_count.get("ACK", 0)),
            "fin_count": float(self.tcp_flags_count.get("FIN", 0)),
            "rst_count": float(self.tcp_flags_count.get("RST", 0)),
            "syn_ratio": float(round(syn_ratio, 4)),
            "rst_ratio": float(round(rst_ratio, 4)),
            "is_bidirectional": 1.0 if self.is_bidirectional else 0.0,
            "connection_frequency": float(self.connection_frequency)
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["features"] = self.extract_features()
        return d


class FlowAnalyzer:
    """
    Manages bidirectional flow aggregation, connection frequency tracking,
    flow expiration timeouts, and aggregate traffic statistics.
    """

    def __init__(self, idle_timeout: float = 60.0, max_active_duration: float = 300.0):
        self.idle_timeout = idle_timeout
        self.max_active_duration = max_active_duration

        # Active flows indexed by normalized canonical flow key
        self.active_flows: Dict[str, NetworkFlow] = {}
        # History of expired flows
        self.expired_flows: List[NetworkFlow] = []
        self.max_expired_history = 500

        # Global statistics
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counter: Dict[str, int] = defaultdict(int)
        self.top_source_ips: Dict[str, int] = defaultdict(int)
        self.top_destination_ports: Dict[int, int] = defaultdict(int)

        # Sliding window for connection frequency tracking per source IP
        # Format: source_ip -> list of timestamps
        self.src_connection_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.frequency_window_seconds = 10.0

    @staticmethod
    def _generate_canonical_flow_key(
        src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str
    ) -> str:
        """Creates a canonical bidirectional flow ID."""
        p1 = f"{src_ip}:{src_port or 0}"
        p2 = f"{dst_ip}:{dst_port or 0}"
        if p1 <= p2:
            return f"{protocol}:{p1}<->{p2}"
        else:
            return f"{protocol}:{p2}<->{p1}"

    def ingest_packet(self, packet: ProcessedPacket) -> NetworkFlow:
        """
        Ingests a processed packet, locates or creates its bidirectional flow,
        updates flow metrics, and returns the active flow.
        """
        self.total_packets += 1
        self.total_bytes += packet.packet_size
        self.protocol_counter[packet.protocol] += 1
        self.top_source_ips[packet.source_ip] += 1
        if packet.destination_port:
            self.top_destination_ports[packet.destination_port] += 1

        # Track connection frequency for source IP (sliding window of 10s)
        now = packet.timestamp
        ts_list = self.src_connection_timestamps[packet.source_ip]
        ts_list.append(now)
        # Prune old timestamps
        cutoff = now - self.frequency_window_seconds
        while ts_list and ts_list[0] < cutoff:
            ts_list.pop(0)
        conn_frequency = round(len(ts_list) / self.frequency_window_seconds, 2)

        canonical_key = self._generate_canonical_flow_key(
            packet.source_ip, packet.destination_ip,
            packet.source_port, packet.destination_port,
            packet.protocol
        )

        flow = self.active_flows.get(canonical_key)
        if flow is None:
            # New flow: this packet establishes the forward direction
            is_forward = True
            flow = NetworkFlow(
                flow_id=canonical_key,
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                source_port=packet.source_port,
                destination_port=packet.destination_port,
                protocol=packet.protocol,
                traffic_type=packet.traffic_type,
                start_time=packet.timestamp,
                last_seen=packet.timestamp,
                connection_frequency=conn_frequency
            )
            self.active_flows[canonical_key] = flow
        else:
            flow.connection_frequency = conn_frequency
            is_forward = (packet.source_ip == flow.source_ip and packet.source_port == flow.source_port)

        flow.update_with_packet(packet, is_forward=is_forward)
        return flow

    def prune_idle_flows(self, current_time: Optional[float] = None) -> List[NetworkFlow]:
        """
        Prunes flows that have timed out or terminated.
        Returns the list of pruned flows.
        """
        now = current_time or time.time()
        to_prune = []

        for flow_id, flow in list(self.active_flows.items()):
            idle_time = now - flow.last_seen
            total_duration = now - flow.start_time

            if flow.state == "TERMINATED" or idle_time >= self.idle_timeout or total_duration >= self.max_active_duration:
                if flow.state != "TERMINATED":
                    flow.state = "TIMED_OUT"
                to_prune.append(flow_id)
                self.expired_flows.append(flow)

        pruned_list = []
        for fid in to_prune:
            pruned_list.append(self.active_flows.pop(fid))

        # Keep expired flows list bounded
        if len(self.expired_flows) > self.max_expired_history:
            self.expired_flows = self.expired_flows[-self.max_expired_history:]

        return pruned_list

    def get_protocol_distribution(self) -> Dict[str, float]:
        """Returns the percentage distribution of captured protocols."""
        if self.total_packets == 0:
            return {}
        return {
            proto: round((count / self.total_packets) * 100.0, 2)
            for proto, count in self.protocol_counter.items()
        }

    def get_traffic_statistics(self) -> Dict[str, Any]:
        """Computes aggregate traffic telemetry and summary statistics."""
        # Calculate instantaneous throughput from active flows
        active_pps = sum(f.packets_per_second for f in self.active_flows.values())
        active_bps = sum(f.bytes_per_second for f in self.active_flows.values())
        mbps = round((active_bps * 8) / 1_000_000, 3)

        # Sort top destination ports
        sorted_ports = sorted(self.top_destination_ports.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports_dict = {f"Port {p}": cnt for p, cnt in sorted_ports}

        # Sort top source talkers
        sorted_sources = sorted(self.top_source_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        top_sources_dict = {ip: cnt for ip, cnt in sorted_sources}

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_flows_tracked": len(self.active_flows) + len(self.expired_flows),
            "active_flows_count": len(self.active_flows),
            "expired_flows_count": len(self.expired_flows),
            "current_throughput_mbps": mbps,
            "current_pps": round(active_pps, 1),
            "current_bps": round(active_bps, 1),
            "protocol_distribution": self.get_protocol_distribution(),
            "top_destination_ports": top_ports_dict,
            "top_source_ips": top_sources_dict,
        }

    def reset(self):
        """Resets all flow tracking states and metrics."""
        self.active_flows.clear()
        self.expired_flows.clear()
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counter.clear()
        self.top_source_ips.clear()
        self.top_destination_ports.clear()
        self.src_connection_timestamps.clear()
