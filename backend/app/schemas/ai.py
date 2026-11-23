from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InvestigationChatRequest(BaseModel):
    prompt: str = Field(default="Investigate the latest security threat", description="Investigation query or prompt")
    incident_id: Optional[str] = None
    investigation_id: Optional[str] = None


class InvestigationRunRequest(BaseModel):
    incident_id: Optional[str] = None
    prompt: Optional[str] = "Perform comprehensive forensic investigation"
    focus_areas: Optional[List[str]] = Field(default_factory=lambda: ["root_cause", "mitre_mapping", "containment"])


class EvidenceCard(BaseModel):
    id: str
    src: str
    dst: str
    type: str
    status: str
    conf: int


class StructuredReport(BaseModel):
    inc: Dict[str, Any]
    sev: str
    sec: List[List[str]]  # Each item is [section_title, section_body]


class InvestigationChatResponse(BaseModel):
    investigation_id: str
    title: str
    reply_text: str
    structured_report: StructuredReport
    evidence_card: Optional[EvidenceCard] = None
    provider_used: Optional[str] = None
    model_used: Optional[str] = None
    tokens_used: int = 0


class InvestigationHistoryItem(BaseModel):
    id: str
    title: str
    incident_id: Optional[str] = None
    created_at: datetime


class AIProviderStatusResponse(BaseModel):
    provider: str
    model: str
    is_available: bool
    status: str
    message: Optional[str] = None
    has_credentials: bool = False
    api_base: Optional[str] = None


class AlertExplanationRequest(BaseModel):
    alert_id: Optional[str] = None
    attack_type: str
    source_ip: str
    destination_ip: str
    severity: str
    confidence: int
    raw_payload: Optional[str] = None


class AlertExplanationResponse(BaseModel):
    alert_summary: str
    technical_explanation: str
    potential_risk: str
    recommended_mitigation: str
    confidence_score: int


class NetworkEventSummaryRequest(BaseModel):
    event_ids: Optional[List[int]] = None
    limit: int = Field(10, ge=1, le=50)


class NetworkEventSummaryResponse(BaseModel):
    event_count: int
    summary_text: str
    observed_patterns: List[str]
    high_risk_sources: List[str]
    defensive_recommendations: List[str]


class MLPredictionExplanationRequest(BaseModel):
    incident_id: Optional[str] = None
    model_name: str = "IsolationForest Anomaly Classifier"
    anomaly_score: float = 0.89
    top_features: Dict[str, float] = Field(default_factory=dict)


class MLPredictionExplanationResponse(BaseModel):
    model_name: str
    confidence_tier: str
    explanation: str
    key_drivers: List[str]
    limitations: str


class DefensiveRecommendationsRequest(BaseModel):
    incident_id: str


class DefensiveRecommendationsResponse(BaseModel):
    incident_code: str
    severity: str
    tactical_actions: List[str]
    strategic_hardening: List[str]
    audit_references: List[str]
