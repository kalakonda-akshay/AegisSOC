# =============================================================================
# AegisSOC Production Dockerfile (Fast & Lightweight)
# =============================================================================
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install python dependencies from pre-built wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code and frontend
COPY . .

# Ensure entrypoint scripts are executable
RUN chmod +x /app/backend/scripts/*.sh 2>/dev/null || true

EXPOSE 8000

CMD ["sh", "-c", "cd /app/backend && python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
