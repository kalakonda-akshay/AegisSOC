from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NetworkThroughputResponse(BaseModel):
    interval_seconds: float = 1.5
    current_inbound: float
    current_outbound: float
    tIn: List[float]
    tOut: List[float]


class NetworkTopologyNode(BaseModel):
    id: int
    name: str
    ip: str
    role: str
    bad: bool
    latency_ms: float


class NetworkTopologyResponse(BaseModel):
    center_node: dict
    nodes: List[NetworkTopologyNode]


class SystemHealthItem(BaseModel):
    name: str
    latency_ms: float
    status: str  # 'Healthy', 'Degraded', 'Down'
    notes: Optional[str] = None


class EngineStatusResponse(BaseModel):
    status: str
    is_running: bool
    is_paused: bool
    active_interface: Optional[str] = None
    uptime_seconds: float
    scapy_available: bool
    packets_captured: int
    packets_analyzed: int
    events_generated: int
    active_flows: int
    current_throughput_mbps: float
    current_pps: float
    protocol_distribution: Dict[str, float]
    errors_count: int
    last_error: Optional[str] = None


class InterfaceInfo(BaseModel):
    name: str
    description: str
    is_loopback: bool


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = None
    filter_bpf: Optional[str] = None
    packet_count: Optional[int] = Field(None, ge=1, le=10000)


class SimulateRequest(BaseModel):
    rate_pps: int = Field(5, ge=1, le=100)
    duration_seconds: Optional[int] = Field(30, ge=1, le=3600)


class PCAPAnalysisResponse(BaseModel):
    filepath: str
    total_packets: int
    duration_seconds: float
    packets_per_second: float
    bytes_per_second: float
    traffic_type: str
    protocol_distribution: Dict[str, float]
    total_flows: int
    suspicious_events: List[Dict[str, Any]]
    top_source_ips: Dict[str, int]
    top_destination_ports: Dict[str, int]
    sample_flows: List[Dict[str, Any]]
