"""
Comprehensive Unit and Integration Tests for AegisSOC Network Monitoring Engine
Verifies packet processing, flow aggregation, feature extraction, anomaly detection,
offline PCAP analysis, and safe lifecycle controls.
"""

import os
import tempfile
import time
import pytest

from app.network.event_processor import EventProcessor, NetworkEvent
from app.network.flow_analyzer import FlowAnalyzer, NetworkFlow
from app.network.network_monitor import NetworkMonitorEngine, PCAPAnalysisResult
from app.network.packet_processor import PacketProcessor, ProcessedPacket

# Also test root wrapper imports
from event_processor import EventProcessor as RootEventProcessor
from flow_analyzer import FlowAnalyzer as RootFlowAnalyzer
from network_monitor import NetworkMonitorEngine as RootNetworkMonitorEngine
from packet_processor import PacketProcessor as RootPacketProcessor


class TestPacketProcessor:
    def test_root_imports(self):
        """Verifies that root wrapper files import cleanly."""
        assert RootPacketProcessor is PacketProcessor
        assert RootFlowAnalyzer is FlowAnalyzer
        assert RootEventProcessor is EventProcessor
        assert RootNetworkMonitorEngine is NetworkMonitorEngine

    def test_process_raw_dict(self):
        """Verifies parsing of packet dictionary."""
        processor = PacketProcessor()
        raw = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "ip_version": 4,
            "packet_size": 1500,
            "payload_size": 1460,
            "tcp_flags": {"SYN": True, "ACK": False},
            "tcp_flags_str": "S",
            "ttl": 64,
            "summary": "TCP 192.168.1.100:54321 -> 10.0.0.1:443 [S]"
        }

        packet = processor.process_raw_dict(raw, traffic_type="simulated")
        assert packet.packet_id == 1
        assert packet.source_ip == "192.168.1.100"
        assert packet.destination_ip == "10.0.0.1"
        assert packet.source_port == 54321
        assert packet.destination_port == 443
        assert packet.protocol == "TCP"
        assert packet.packet_size == 1500
        assert packet.tcp_flags["SYN"] is True
        assert packet.tcp_flags["ACK"] is False
        assert packet.traffic_type == "simulated"

    def test_process_scapy_packet_layers(self):
        """Verifies Scapy packet parsing for IP/TCP/UDP/DNS layers."""
        import scapy.all as scapy
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS, DNSQR

        processor = PacketProcessor()

        # Build synthetic TCP packet
        tcp_pkt = IP(src="10.0.1.5", dst="10.0.2.10", ttl=64) / TCP(sport=12345, dport=80, flags="S")
        res = processor.process_scapy_packet(tcp_pkt, traffic_type="live")

        assert res is not None
        assert res.source_ip == "10.0.1.5"
        assert res.destination_ip == "10.0.2.10"
        assert res.source_port == 12345
        assert res.destination_port == 80
        assert res.protocol == "HTTP"  # Port 80 identified as HTTP
        assert res.tcp_flags["SYN"] is True
        assert res.traffic_type == "live"

        # Build synthetic DNS packet
        dns_pkt = IP(src="10.0.1.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.corp"))
        dns_res = processor.process_scapy_packet(dns_pkt, traffic_type="simulated")

        assert dns_res is not None
        assert dns_res.protocol == "DNS"
        assert dns_res.destination_port == 53
        assert dns_res.traffic_type == "simulated"


class TestFlowAnalyzer:
    def test_bidirectional_aggregation_and_features(self):
        """Verifies bidirectional flow matching and feature calculation."""
        analyzer = FlowAnalyzer()
        base_time = 1700000000.0

        # Packet 1: Forward SYN (A -> B)
        p1 = ProcessedPacket(
            packet_id=1,
            timestamp=base_time,
            datetime_utc="2023-11-14T22:13:20Z",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
            source_port=40001,
            destination_port=443,
            protocol="TCP",
            ip_version=4,
            packet_size=60,
            payload_size=0,
            tcp_flags={"SYN": True, "ACK": False, "FIN": False, "RST": False},
            tcp_flags_str="S",
            traffic_type="simulated"
        )
        flow = analyzer.ingest_packet(p1)
        assert flow.packet_count == 1
        assert flow.forward_packets == 1
        assert flow.reverse_packets == 0
        assert flow.state == "SYN_SENT"
        assert flow.is_bidirectional is False

        # Packet 2: Reverse SYN-ACK (B -> A)
        p2 = ProcessedPacket(
            packet_id=2,
            timestamp=base_time + 0.05,
            datetime_utc="2023-11-14T22:13:20.05Z",
            source_ip="10.0.0.5",
            destination_ip="192.168.1.50",
            source_port=443,
            destination_port=40001,
            protocol="TCP",
            ip_version=4,
            packet_size=60,
            payload_size=0,
            tcp_flags={"SYN": True, "ACK": True, "FIN": False, "RST": False},
            tcp_flags_str="SA",
            traffic_type="simulated"
        )
        flow = analyzer.ingest_packet(p2)
        assert flow.packet_count == 2
        assert flow.forward_packets == 1
        assert flow.reverse_packets == 1
        assert flow.is_bidirectional is True
        assert flow.state == "SYN_RCVD"

        # Packet 3: Forward ACK (A -> B)
        p3 = ProcessedPacket(
            packet_id=3,
            timestamp=base_time + 0.10,
            datetime_utc="2023-11-14T22:13:20.10Z",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.5",
            source_port=40001,
            destination_port=443,
            protocol="TCP",
            ip_version=4,
            packet_size=52,
            payload_size=0,
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False},
            tcp_flags_str="A",
            traffic_type="simulated"
        )
        flow = analyzer.ingest_packet(p3)
        assert flow.packet_count == 3
        assert flow.state == "ESTABLISHED"
        assert flow.duration_seconds >= 0.095

        # Verify extracted ML features
        features = flow.extract_features()
        assert features["packet_count"] == 3.0
        assert features["byte_count"] == 172.0
        assert features["is_bidirectional"] == 1.0
        assert features["syn_count"] == 2.0
        assert features["ack_count"] == 2.0
        assert "packets_per_second" in features
        assert "bytes_per_second" in features

    def test_traffic_statistics_and_protocol_distribution(self):
        """Verifies global statistics and protocol breakdowns."""
        analyzer = FlowAnalyzer()

        for i in range(10):
            proto = "TCP" if i < 7 else "UDP"
            pkt = ProcessedPacket(
                packet_id=i + 1,
                timestamp=time.time(),
                datetime_utc="2026-11-23T00:00:00Z",
                source_ip="10.0.0.10",
                destination_ip=f"10.0.0.{20 + i}",
                source_port=50000 + i,
                destination_port=80 if proto == "TCP" else 53,
                protocol=proto,
                ip_version=4,
                packet_size=100,
                payload_size=50,
                traffic_type="simulated"
            )
            analyzer.ingest_packet(pkt)

        stats = analyzer.get_traffic_statistics()
        assert stats["total_packets"] == 10
        assert stats["total_bytes"] == 1000
        dist = stats["protocol_distribution"]
        assert dist["TCP"] == 70.0
        assert dist["UDP"] == 30.0
        assert "10.0.0.10" in stats["top_source_ips"]


class TestEventProcessor:
    def test_port_scan_detection(self):
        """Verifies detection of sequential port probing."""
        event_proc = EventProcessor(port_scan_threshold=5, window_seconds=10.0)
        base_time = time.time()
        events = []

        # Probe 6 distinct ports from attacker
        for port in [21, 22, 23, 80, 443, 3389]:
            pkt = ProcessedPacket(
                packet_id=port,
                timestamp=base_time,
                datetime_utc="2026-11-23T00:00:00Z",
                source_ip="192.168.1.200",
                destination_ip="10.0.0.10",
                source_port=45000,
                destination_port=port,
                protocol="TCP",
                ip_version=4,
                packet_size=60,
                payload_size=0,
                tcp_flags={"SYN": True, "ACK": False},
                tcp_flags_str="S",
                traffic_type="simulated"
            )
            evs = event_proc.evaluate_packet(pkt)
            if evs:
                events.extend(evs)

        assert len(events) >= 1
        scan_event = events[0]
        assert scan_event.attack_type == "Port Scanning Activity"
        assert scan_event.source_ip == "192.168.1.200"
        assert scan_event.traffic_type == "simulated"
        assert scan_event.severity in ("Medium", "High")

    def test_ssh_brute_force_detection(self):
        """Verifies detection of repeated authentication attempts to port 22."""
        event_proc = EventProcessor(brute_force_threshold=4, window_seconds=10.0)
        base_time = time.time()
        events = []

        # 5 rapid attempts to port 22
        for i in range(5):
            pkt = ProcessedPacket(
                packet_id=i + 1,
                timestamp=base_time + (i * 0.1),
                datetime_utc="2026-11-23T00:00:00Z",
                source_ip="192.168.1.201",
                destination_ip="10.0.0.10",
                source_port=50000 + i,
                destination_port=22,
                protocol="SSH",
                ip_version=4,
                packet_size=100,
                payload_size=40,
                tcp_flags={"SYN": True, "ACK": False},
                tcp_flags_str="S",
                traffic_type="simulated"
            )
            evs = event_proc.evaluate_packet(pkt)
            if evs:
                events.extend(evs)

        assert len(events) >= 1
        bf_event = events[0]
        assert bf_event.attack_type == "SSH Brute Force"
        assert bf_event.source_ip == "192.168.1.201"
        assert bf_event.severity == "High"

    def test_suspicious_c2_port_detection(self):
        """Verifies alert for connections to known C2 listener ports (4444)."""
        event_proc = EventProcessor()
        pkt = ProcessedPacket(
            packet_id=99,
            timestamp=time.time(),
            datetime_utc="2026-11-23T00:00:00Z",
            source_ip="10.0.1.13",
            destination_ip="198.51.100.5",
            source_port=49000,
            destination_port=4444,
            protocol="TCP",
            ip_version=4,
            packet_size=120,
            payload_size=60,
            traffic_type="live"
        )
        events = event_proc.evaluate_packet(pkt)
        assert len(events) == 1
        assert events[0].attack_type == "Potential C2 Beacon"
        assert events[0].traffic_type == "live"


class TestNetworkMonitorEngine:
    def test_sample_pcap_generation_and_offline_analysis(self):
        """Verifies creating a synthetic PCAP and performing offline analysis."""
        engine = NetworkMonitorEngine()

        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, "test_traffic.pcap")
            generated_path = engine.generate_sample_pcap(pcap_path, include_anomalies=True)

            assert os.path.exists(generated_path)
            assert os.path.getsize(generated_path) > 0

            # Analyze PCAP
            result: PCAPAnalysisResult = engine.analyze_pcap(generated_path, traffic_type="simulated")

            assert result.total_packets > 0
            assert result.total_flows > 0
            assert result.duration_seconds > 0
            assert "TCP" in result.protocol_distribution or "HTTP" in result.protocol_distribution
            assert result.traffic_type == "simulated"
            # Anomalies should have triggered suspicious events
            assert len(result.suspicious_events) >= 1
            attack_types = [e["attack_type"] for e in result.suspicious_events]
            assert any("Port Scanning" in at or "Brute Force" in at or "C2" in at for at in attack_types)

    def test_engine_lifecycle_and_simulation(self):
        """Verifies starting, pausing, and safely stopping traffic simulation."""
        captured_events = []
        captured_telemetry = []

        def on_event(ev):
            captured_events.append(ev)

        def on_telemetry(t):
            captured_telemetry.append(t)

        engine = NetworkMonitorEngine(
            event_callback=on_event,
            telemetry_callback=on_telemetry
        )

        status_initial = engine.get_status()
        assert status_initial["is_running"] is False
        assert status_initial["status"] == "stopped"

        # Start simulation at high rate for quick test
        started = engine.start_traffic_simulation(rate_pps=50, target_duration_seconds=5)
        assert started is True

        time.sleep(0.3)
        status_running = engine.get_status()
        assert status_running["is_running"] is True
        assert status_running["packets_captured"] > 0

        # Pause
        engine.pause_capture()
        status_paused = engine.get_status()
        assert status_paused["is_paused"] is True
        assert status_paused["status"] == "paused"

        # Resume
        engine.resume_capture()
        status_resumed = engine.get_status()
        assert status_resumed["is_paused"] is False
        assert status_resumed["status"] == "running"

        # Stop
        engine.stop_capture()
        status_stopped = engine.get_status()
        assert status_stopped["is_running"] is False
        assert status_stopped["status"] == "stopped"
