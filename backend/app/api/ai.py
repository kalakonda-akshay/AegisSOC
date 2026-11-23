"""
AegisSOC AI Security Analyst API Router
Exposes enterprise endpoints for security alert explanation, incident investigation,
network event summarization, ML explanation, defensive hardening, and audit history.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.ai import (
    AIProviderStatusResponse,
    AlertExplanationRequest,
    AlertExplanationResponse,
    DefensiveRecommendationsRequest,
    DefensiveRecommendationsResponse,
    InvestigationChatRequest,
    InvestigationChatResponse,
    InvestigationHistoryItem,
    MLPredictionExplanationRequest,
    MLPredictionExplanationResponse,
    NetworkEventSummaryRequest,
    NetworkEventSummaryResponse
)
from app.services.ai_service import AIService

router = APIRouter(prefix="/ai", tags=["AI Security Analyst"])


@router.get("/status", response_model=AIProviderStatusResponse)
def get_ai_provider_status(db: Session = Depends(get_db)):
    """Returns the operational status, model, and availability of the AI inference provider."""
    service = AIService(db)
    return service.get_provider_status()


@router.post("/chat", response_model=InvestigationChatResponse)
@router.post("/investigate", response_model=InvestigationChatResponse)
def chat_with_analyst(
    chat_req: InvestigationChatRequest,
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Submits an operational prompt to the AI Security Analyst and generates a structured
    7-section MITRE investigation report grounded in actual database evidence.
    """
    service = AIService(db)
    user_id = current_user.id if current_user else None
    return service.generate_investigation(chat_req, user_id=user_id)


@router.get("/history", response_model=List[InvestigationHistoryItem])
def list_investigation_history(
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves previous investigation sessions and transcripts."""
    service = AIService(db)
    org_id = current_user.organization_id if current_user else None
    return service.list_history(organization_id=org_id)


@router.post("/alert/explain", response_model=AlertExplanationResponse)
def explain_alert(
    req: AlertExplanationRequest,
    db: Session = Depends(get_db)
):
    """Explains an individual security alert with technical root-cause and defensive mitigation."""
    service = AIService(db)
    return service.explain_security_alert(req)


@router.post("/events/summarize", response_model=NetworkEventSummaryResponse)
def summarize_events(
    req: NetworkEventSummaryRequest,
    db: Session = Depends(get_db)
):
    """Summarizes raw network security events and highlights high-risk external origins."""
    service = AIService(db)
    return service.summarize_network_events(req)


@router.post("/ml/explain", response_model=MLPredictionExplanationResponse)
def explain_ml_model_prediction(
    req: MLPredictionExplanationRequest,
    db: Session = Depends(get_db)
):
    """Explains machine learning anomaly score and feature contributions for SOC analysts."""
    service = AIService(db)
    return service.explain_ml_prediction(req)


@router.post("/recommendations", response_model=DefensiveRecommendationsResponse)
def get_defensive_recommendations(
    req: DefensiveRecommendationsRequest,
    db: Session = Depends(get_db)
):
    """Produces prioritized tactical containment and strategic hardening recommendations for an incident."""
    service = AIService(db)
    return service.generate_defensive_recommendations(req)
