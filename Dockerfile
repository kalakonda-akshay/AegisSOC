# =============================================================================
# AegisSOC Enterprise Root Dockerfile (Root Context)
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --user --no-warn-script-location -r requirements.txt

FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/aegis/.local/bin:$PATH \
    PYTHONPATH=/app/backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 aegis && \
    useradd --uid 10001 --gid aegis --shell /bin/bash --create-home aegis

COPY --from=builder --chown=aegis:aegis /root/.local /home/aegis/.local

COPY --chown=aegis:aegis . /app

RUN if [ -f /app/backend/scripts/entrypoint.sh ]; then chmod +x /app/backend/scripts/entrypoint.sh; fi

USER aegis
WORKDIR /app/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys, os; port = os.getenv('PORT', '8000'); sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}/health').getcode() == 200 else 1)"

ENTRYPOINT ["/app/backend/scripts/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
