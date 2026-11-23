from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

import os
from fastapi.responses import FileResponse, HTMLResponse

from app.api import api_router
from app.core.config import settings
from app.core.database import init_db
from app.core.exceptions import (
    AegisSOCException,
    aegissoc_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler
)
from app.core.logging import logger, setup_logging
from app.middleware.logging_middleware import RequestLoggingMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    setup_logging()
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}]...")
    init_db()
    logger.info("Application startup completed successfully.")
    yield
    # Shutdown sequence
    logger.info(f"Shutting down {settings.APP_NAME}...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise Autonomous AI-driven Cybersecurity Operations Center (SOC) Platform API.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Logging Middleware
app.add_middleware(RequestLoggingMiddleware)

# Centralized Exception Handlers (RFC 7807)
app.add_exception_handler(AegisSOCException, aegissoc_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Include Main API Router
app.include_router(api_router)

# Mount WebSocket routes at root for /ws/monitoring compatibility
from app.websocket.routes import router as ws_router
app.include_router(ws_router)


def get_frontend_path():
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "aegissoc.html")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "aegissoc.html")),
        os.path.abspath(os.path.join(os.getcwd(), "frontend", "aegissoc.html")),
        os.path.abspath(os.path.join(os.getcwd(), "..", "frontend", "aegissoc.html")),
        "/app/frontend/aegissoc.html",
        "/app/backend/frontend/aegissoc.html",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]

frontend_html_path = get_frontend_path()


@app.get("/", tags=["Root"])
async def root(request: Request):
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header and os.path.exists(frontend_html_path):
        return FileResponse(frontend_html_path, media_type="text/html")
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "api_prefix": settings.API_V1_STR
    }


@app.get("/ui", tags=["UI"])
async def get_ui():
    if os.path.exists(frontend_html_path):
        return FileResponse(frontend_html_path, media_type="text/html")
    return HTMLResponse("<h1>AegisSOC UI not found</h1>", status_code=404)


@app.get("/health", tags=["Health"])
async def root_health():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
