from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.monitoring import router as monitoring_router
from app.api.threats import router as threats_router
from app.api.incidents import router as incidents_router
from app.api.ai import router as ai_router
from app.api.intelligence import router as intelligence_router
from app.api.analytics import router as analytics_router
from app.api.reports import router as reports_router
from app.api.health import router as health_router
from app.websocket.routes import router as ws_router

api_router = APIRouter(prefix="/api")

api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(monitoring_router)
api_router.include_router(threats_router)
api_router.include_router(incidents_router)
api_router.include_router(ai_router)
api_router.include_router(intelligence_router)
api_router.include_router(analytics_router)
api_router.include_router(reports_router)
api_router.include_router(health_router)
api_router.include_router(ws_router)

__all__ = ["api_router"]
