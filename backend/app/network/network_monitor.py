"""
AegisSOC Network Monitoring Engine - Core Orchestrator
Coordinates packet capture/ingestion, flow aggregation, anomaly event generation,
WebSocket broadcasting, and offline PCAP inspection with Scapy.
"""

import asyncio
from dataclasses import asdict, dataclass, field
import datetime
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from app.core.logging import logger
from app.network.event_processor import EventProcessor, NetworkEvent
from app.network.flow_analyzer import FlowAnalyzer, NetworkFlow
from app.network.packet_processor import PacketProcessor, ProcessedPacket

try:
    import scapy.all as scapy
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.utils import PcapReader, rdpcap, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class PCAPAnalysisResult:
    """Summary result returned after analyzing an offline PCAP capture file."""
    filepath: str
    total_packets: int
    duration_seconds: float
    packets_per_second: float
    bytes_per_second: float
    traffic_type: str  # "simulated" or "live"
    protocol_distribution: Dict[str, float]
    total_flows: int
    suspicious_events: List[Dict[str, Any]]
    top_source_ips: Dict[str, int]
    top_destination_ports: Dict[str, int]
    sample_flows: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NetworkMonitorEngine:
    """
    Central operational engine for network monitoring in AegisSOC.
    Supports offline PCAP parsing, authorized live interface capture,
    controlled traffic simulation, and real-time WebSocket telemetry broadcasting.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[NetworkEvent], None]] = None,
        telemetry_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.packet_processor = PacketProcessor()
        self.flow_analyzer = FlowAnalyzer()
        self.event_processor = EventProcessor()

        # Callbacks for real-time notification / WebSocket broadcasting
        self.event_callback = event_callback
        self.telemetry_callback = telemetry_callback

        # Threading & lifecycle state
        self._running = False
        self._paused = False
        self._status = "stopped"  # "stopped", "running", "paused", "analyzing_pcap"
        self._active_interface: Optional[str] = None
        self._start_time: Optional[float] = None
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Engine counters
        self._packets_captured = 0
        self._packets_analyzed = 0
        self._events_generated = 0
        self._error_count = 0
        self._last_error: Optional[str] = None

    # -------------------------------------------------------------------------
    # Status & Diagnostic Controls
    # -------------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        """Returns the real-time operational status and metrics of the monitoring engine."""
        uptime = 0.0
        if self._running and self._start_time:
            uptime = round(time.time() - self._start_time, 2)

        stats = self.flow_analyzer.get_traffic_statistics()

        return {
            "status": self._status,
            "is_running": self._running,
            "is_paused": self._paused,
            "active_interface": self._active_interface,
            "uptime_seconds": uptime,
            "scapy_available": SCAPY_AVAILABLE,
            "packets_captured": self._packets_captured,
            "packets_analyzed": self._packets_analyzed,
            "events_generated": self._events_generated,
            "active_flows": stats["active_flows_count"],
            "current_throughput_mbps": stats["current_throughput_mbps"],
            "current_pps": stats["current_pps"],
            "protocol_distribution": stats["protocol_distribution"],
            "errors_count": self._error_count,
            "last_error": self._last_error
        }

    # -------------------------------------------------------------------------
    # 1. Offline PCAP File Analysis
    # -------------------------------------------------------------------------
    def analyze_pcap(
        self,
        filepath: str,
        traffic_type: str = "simulated",
        max_packets: Optional[int] = None
    ) -> PCAPAnalysisResult:
        """
        Ingests and performs complete flow & anomaly analysis on an offline PCAP file.
        Uses streaming reader to handle captures without memory exhaustion.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP analysis.")

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        with self._lock:
            prev_status = self._status
            self._status = "analyzing_pcap"

        # Local temporary analyzers for isolation
        local_pkt_proc = PacketProcessor()
        local_flow_anlz = FlowAnalyzer()
        local_event_proc = EventProcessor()

        first_ts: Optional[float] = None
        last_ts: Optional[float] = None
        pkt_count = 0

        try:
            reader = PcapReader(filepath)
            for scapy_pkt in reader:
                if max_packets and pkt_count >= max_packets:
                    break

                proc_pkt = local_pkt_proc.process_scapy_packet(scapy_pkt, traffic_type=traffic_type)
                if not proc_pkt:
                    continue

                pkt_count += 1
                if first_ts is None:
                    first_ts = proc_pkt.timestamp
                last_ts = proc_pkt.timestamp

                # Flow analysis
                flow = local_flow_anlz.ingest_packet(proc_pkt)

                # Anomaly & signature event analysis
                pkt_events = local_event_proc.evaluate_packet(proc_pkt)
                flow_events = local_event_proc.evaluate_flow(flow)

            reader.close()

        except Exception as e:
            self._error_count += 1
            self._last_error = str(e)
            logger.error(f"Error analyzing PCAP {filepath}: {e}")
            raise
        finally:
            with self._lock:
                self._status = prev_status

        duration = 0.0001
        if first_ts and last_ts:
            duration = max(0.0001, last_ts - first_ts)

        pps = round(pkt_count / duration, 2)
        bps = round(local_flow_anlz.total_bytes / duration, 2)
        stats = local_flow_anlz.get_traffic_statistics()

        # Collect sample flows (first 10)
        sample_flows = [f.to_dict() for f in list(local_flow_anlz.active_flows.values())[:10]]

        return PCAPAnalysisResult(
            filepath=os.path.abspath(filepath),
            total_packets=pkt_count,
            duration_seconds=round(duration, 3),
            packets_per_second=pps,
            bytes_per_second=bps,
            traffic_type=traffic_type,
            protocol_distribution=stats["protocol_distribution"],
            total_flows=stats["total_flows_tracked"],
            suspicious_events=[e.to_dict() for e in local_event_proc.generated_events],
            top_source_ips=stats["top_source_ips"],
            top_destination_ports=stats["top_destination_ports"],
            sample_flows=sample_flows
        )

    # -------------------------------------------------------------------------
    # 2. Authorized Live Network Interface Monitoring
    # -------------------------------------------------------------------------
    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """Safely lists system network interfaces available for packet capture."""
        if not SCAPY_AVAILABLE:
            return []

        interfaces = []
        try:
            if hasattr(scapy, "get_if_list"):
                for iface_name in scapy.get_if_list():
                    interfaces.append({
                        "name": str(iface_name),
                        "description": str(iface_name),
                        "is_loopback": "loopback" in str(iface_name).lower() or "lo" == str(iface_name).lower()
                    })
        except Exception as e:
            logger.warning(f"Could not list interfaces via Scapy: {e}")
        return interfaces

    def start_live_capture(
        self,
        interface: Optional[str] = None,
        filter_bpf: Optional[str] = None,
        packet_count: Optional[int] = None
    ) -> bool:
        """
        Initiates authorized live packet capture in a background thread.
        Requires appropriate OS capture privileges (e.g., Npcap on Windows or CAP_NET_RAW on Linux).
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Live capture unavailable.")

        with self._lock:
            if self._running:
                logger.warning("Capture is already active.")
                return False

            self._running = True
            self._paused = False
            self._status = "running"
            self._active_interface = interface or "default"
            self._start_time = time.time()
            self._stop_event.clear()

        def _capture_worker():
            logger.info(f"Starting live network capture on interface '{self._active_interface}'")
            try:
                def _packet_handler(packet):
                    if self._stop_event.is_set():
                        return True  # Stop filter returns True
                    if self._paused:
                        return False

                    self._packets_captured += 1
                    proc_pkt = self.packet_processor.process_scapy_packet(packet, traffic_type="live")
                    if proc_pkt:
                        self._process_single_packet(proc_pkt)
                    return False

                # Scapy sniff with stop_filter
                scapy.sniff(
                    iface=interface,
                    filter=filter_bpf,
                    prn=_packet_handler,
                    stop_filter=lambda p: self._stop_event.is_set(),
                    count=packet_count or 0,
                    store=False
                )
            except Exception as e:
                self._error_count += 1
                self._last_error = str(e)
                logger.error(f"Live network capture stopped with error: {e}")
            finally:
                with self._lock:
                    self._running = False
                    self._status = "stopped"
                    self._active_interface = None
                logger.info("Live network capture thread terminated.")

        self._worker_thread = threading.Thread(target=_capture_worker, daemon=True)
        self._worker_thread.start()
        return True

    def stop_capture(self):
        """Safely signals and stops the active live capture or simulation."""
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()
            self._running = False
            self._status = "stopped"

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("Network monitoring stopped.")

    def pause_capture(self):
        """Pauses processing of captured packets."""
        with self._lock:
            if self._running:
                self._paused = True
                self._status = "paused"

    def resume_capture(self):
        """Resumes processing of captured packets."""
        with self._lock:
            if self._running:
                self._paused = False
                self._status = "running"

    # -------------------------------------------------------------------------
    # 3. Controlled Sample Traffic Generation & Simulation
    # -------------------------------------------------------------------------
    def generate_sample_pcap(
        self,
        filepath: str,
        include_anomalies: bool = True
    ) -> str:
        """
        Creates a synthetic PCAP file with Scapy containing benign web/DNS/TLS flows
        and clearly labeled simulated security anomalies (SYN scan, SSH brute force).
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required to generate sample PCAPs.")

        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        packets = []
        base_time = time.time() - 60.0

        # 1. Normal DNS Query & Response (Simulated)
        dns_req = (
            scapy.Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") /
            IP(src="10.0.1.15", dst="10.0.0.1", ttl=64) /
            UDP(sport=53535, dport=53) /
            DNS(rd=1, qd=DNSQR(qname="api.corp.internal"))
        )
        dns_req.time = base_time + 1.0
        packets.append(dns_req)

        # 2. Normal HTTP Traffic (Simulated)
        http_syn = (
            scapy.Ether() /
            IP(src="10.0.1.20", dst="10.0.1.50", ttl=64) /
            TCP(sport=49152, dport=80, flags="S", seq=1000)
        )
        http_syn.time = base_time + 2.0
        packets.append(http_syn)

        http_synack = (
            scapy.Ether() /
            IP(src="10.0.1.50", dst="10.0.1.20", ttl=64) /
            TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)
        )
        http_synack.time = base_time + 2.02
        packets.append(http_synack)

        http_ack = (
            scapy.Ether() /
            IP(src="10.0.1.20", dst="10.0.1.50", ttl=64) /
            TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)
        )
        http_ack.time = base_time + 2.04
        packets.append(http_ack)

        # 3. Normal TLS / HTTPS Handshake (Simulated)
        for i in range(5):
            tls_pkt = (
                scapy.Ether() /
                IP(src="10.0.3.99", dst="142.250.190.46", ttl=128) /
                TCP(sport=51000 + i, dport=443, flags="PA", seq=2000 + i*100) /
                scapy.Raw(load=b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + b"A"*100)
            )
            tls_pkt.time = base_time + 5.0 + (i * 0.5)
            packets.append(tls_pkt)

        if include_anomalies:
            # Anomaly A: Simulated Port Scan (Probing 12 distinct ports from 192.168.1.150)
            target_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389]
            for idx, port in enumerate(target_ports):
                scan_pkt = (
                    scapy.Ether() /
                    IP(src="192.168.1.150", dst="10.0.1.13", ttl=64) /
                    TCP(sport=40000 + idx, dport=port, flags="S", seq=9000 + idx)
                )
                scan_pkt.time = base_time + 15.0 + (idx * 0.1)
                packets.append(scan_pkt)

            # Anomaly B: Simulated SSH Brute Force (7 rapid connection attempts to port 22 from 192.168.1.151)
            for idx in range(7):
                ssh_bf = (
                    scapy.Ether() /
                    IP(src="192.168.1.151", dst="10.0.0.10", ttl=64) /
                    TCP(sport=52000 + idx, dport=22, flags="S", seq=3000 + idx)
                )
                ssh_bf.time = base_time + 25.0 + (idx * 0.2)
                packets.append(ssh_bf)

            # Anomaly C: Simulated Suspicious C2 Beacon (Connection to port 4444)
            c2_pkt = (
                scapy.Ether() /
                IP(src="10.0.1.13", dst="198.51.100.42", ttl=64) /
                TCP(sport=55555, dport=4444, flags="PA", seq=7777) /
                scapy.Raw(load=b"BEACON_ID=91283_PING_CHECK")
            )
            c2_pkt.time = base_time + 35.0
            packets.append(c2_pkt)

        # Write packets to PCAP
        wrpcap(filepath, packets)
        logger.info(f"Generated controlled synthetic PCAP with {len(packets)} packets at: {filepath}")
        return os.path.abspath(filepath)

    def start_traffic_simulation(
        self,
        rate_pps: int = 5,
        target_duration_seconds: Optional[int] = None
    ) -> bool:
        """
        Runs a controlled in-memory traffic generator streaming synthetic packets.
        Ideal for safe end-to-end testing, WebSocket broadcasting, and UI dashboard validation.
        """
        with self._lock:
            if self._running:
                logger.warning("Simulation/capture already in progress.")
                return False

            self._running = True
            self._paused = False
            self._status = "running"
            self._active_interface = "simulated_veth0"
            self._start_time = time.time()
            self._stop_event.clear()

        def _simulation_worker():
            logger.info(f"Started simulated network stream at {rate_pps} pps.")
            sim_ips = ["10.0.1.13", "10.0.2.5", "10.0.0.10", "10.0.3.99", "192.168.1.150"]
            ports = [80, 443, 22, 53, 8080, 4444]
            counter = 0

            while not self._stop_event.is_set():
                if target_duration_seconds and (time.time() - self._start_time) >= target_duration_seconds:
                    break

                if not self._paused:
                    counter += 1
                    src_ip = sim_ips[counter % len(sim_ips)]
                    dst_ip = sim_ips[(counter + 1) % len(sim_ips)]
                    dst_p = ports[counter % len(ports)]
                    proto = "TCP" if dst_p != 53 else "UDP"

                    pkt_dict = {
                        "timestamp": time.time(),
                        "source_ip": src_ip,
                        "destination_ip": dst_ip,
                        "source_port": 40000 + (counter % 10000),
                        "destination_port": dst_p,
                        "protocol": proto,
                        "ip_version": 4,
                        "packet_size": 128 + (counter % 512),
                        "payload_size": 64,
                        "tcp_flags": {"SYN": (counter % 5 == 0), "ACK": True},
                        "tcp_flags_str": "SA" if (counter % 5 == 0) else "A",
                        "ttl": 64,
                        "summary": f"[SIMULATED] {proto} {src_ip} -> {dst_ip}:{dst_p}",
                        "raw_preview": "00112233445566778899aabbccddeeff"
                    }

                    proc_pkt = self.packet_processor.process_raw_dict(pkt_dict, traffic_type="simulated")
                    self._packets_captured += 1
                    self._process_single_packet(proc_pkt)

                time.sleep(1.0 / max(1, rate_pps))

            with self._lock:
                self._running = False
                self._status = "stopped"
                self._active_interface = None
            logger.info("Traffic simulation thread ended.")

        self._worker_thread = threading.Thread(target=_simulation_worker, daemon=True)
        self._worker_thread.start()
        return True

    # -------------------------------------------------------------------------
    # Internal Pipeline Processing
    # -------------------------------------------------------------------------
    def _process_single_packet(self, packet: ProcessedPacket):
        """Processes a single incoming packet through the flow and event engines."""
        self._packets_analyzed += 1

        # 1. Flow Aggregator
        flow = self.flow_analyzer.ingest_packet(packet)

        # 2. Security Event Detection
        new_events = []
        pkt_events = self.event_processor.evaluate_packet(packet)
        if pkt_events:
            new_events.extend(pkt_events)

        flow_events = self.event_processor.evaluate_flow(flow)
        if flow_events:
            new_events.extend(flow_events)

        self._events_generated += len(new_events)

        # 3. Real-Time Callbacks (WebSocket / Subscribers)
        if new_events and self.event_callback:
            for ev in new_events:
                try:
                    self.event_callback(ev)
                except Exception as e:
                    logger.warning(f"Error in event_callback: {e}")

        # Periodic telemetry update
        if self._packets_analyzed % 10 == 0 and self.telemetry_callback:
            stats = self.flow_analyzer.get_traffic_statistics()
            try:
                self.telemetry_callback(stats)
            except Exception as e:
                logger.warning(f"Error in telemetry_callback: {e}")

    def reset_statistics(self):
        """Resets engine counters and internal data stores."""
        with self._lock:
            self._packets_captured = 0
            self._packets_analyzed = 0
            self._events_generated = 0
            self._error_count = 0
            self._last_error = None
            self.flow_analyzer.reset()
            self.event_processor.clear()
