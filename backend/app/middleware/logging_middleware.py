import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logging import logger


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        response = await call_next(request)
        process_time = round((time.time() - start_time) * 1000, 2)

        # Log request summary
        logger.info(f"{request.method} {path} - {response.status_code} ({process_time}ms) from {client_ip}")
        response.headers["X-Process-Time"] = f"{process_time}ms"
        return response
