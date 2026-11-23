from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityEventResponse(BaseModel):
    id: int
    t: datetime  # matches frontend key 't'
    src: str     # matches frontend key 'src'
    dst: str     # matches frontend key 'dst'
    type: str    # matches frontend key 'type'
    sev: str     # matches frontend key 'sev'
    by: str      # matches frontend key 'by'
    conf: Optional[int] = 85

    model_config = {"from_attributes": True}


class SecurityEventCreate(BaseModel):
    source_ip: str
    destination_ip: str
    attack_type: str
    severity: str = "Medium"
    detected_by: str = "ML anomaly model"
    confidence: int = Field(default=85, ge=0, le=100)
    raw_payload: Optional[str] = None


class ThreatAnalyzeRequest(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = "10.0.0.10"
    destination_port: Optional[int] = 80
    protocol: Optional[str] = "TCP"
    packet_count: Optional[int] = 100
    byte_count: Optional[int] = 50000
    raw_payload: Optional[str] = None


class ThreatAnalyzeResponse(BaseModel):
    threat_classification: str
    anomaly_score: float
    risk_level: str  # Critical, High, Medium, Low
    confidence: int
    matched_rules: List[str]
    threat_intel_verdict: str
    recommended_actions: List[str]
    is_malicious: bool
