# =============================================================================
# AegisSOC Enterprise Backend Dockerfile
# Multi-stage build with non-root runtime security, libpcap, and PostgreSQL driver
# =============================================================================

# --- Stage 1: Build & Dependencies ---
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies to user directory
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --user --no-warn-script-location -r requirements.txt


# --- Stage 2: Hardened Runtime Container ---
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/aegis/.local/bin:$PATH \
    PYTHONPATH=/app

# Install runtime shared libraries (PostgreSQL client, libpcap packet capture, curl)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpcap0.8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user and group
RUN groupadd --gid 10001 aegis && \
    useradd --uid 10001 --gid aegis --shell /bin/bash --create-home aegis

# Copy installed python wheels from builder to the aegis user's local directory
COPY --from=builder --chown=aegis:aegis /root/.local /home/aegis/.local

# Copy application source code and configurations
COPY --chown=aegis:aegis . /app

# Ensure entrypoint scripts are executable
RUN if [ -f /app/scripts/entrypoint.sh ]; then chmod +x /app/scripts/entrypoint.sh; fi

# Switch to unprivileged non-root user
USER aegis

# Expose FastAPI service port
EXPOSE 8000

# Docker native healthcheck using python standard library (zero curl dependency failure)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').getcode() == 200 else 1)"

# Start container through production entrypoint
ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
