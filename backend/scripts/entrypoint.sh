#!/usr/bin/env bash
# =============================================================================
# AegisSOC Container Entrypoint Script
# Waits for database readiness, applies Alembic migrations, seeds initial data,
# and starts the FastAPI service.
# =============================================================================
set -e

echo "[AegisSOC] Starting container initialization..."

# Function to wait for PostgreSQL availability if configured
wait_for_db() {
    echo "[AegisSOC] Checking database connection..."
    python << 'EOF'
import os
import sys
import time
from urllib.parse import urlparse

db_url = os.getenv("DATABASE_URL", "sqlite:///./aegissoc.db")

# Only perform network connection wait for PostgreSQL/MySQL
if "postgres" in db_url or "pg" in db_url:
    clean_url = db_url.replace("+asyncpg", "").replace("+psycopg2", "")
    parsed = urlparse(clean_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 5432
    print(f"[AegisSOC] Waiting for PostgreSQL at {host}:{port}...")

    import socket
    max_retries = 30
    for attempt in range(1, max_retries + 1):
        try:
            with socket.create_connection((host, port), timeout=2):
                print(f"[AegisSOC] PostgreSQL is ready and accepting connections!")
                sys.exit(0)
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"[AegisSOC] Attempt {attempt}/{max_retries}: PostgreSQL not ready yet. Retrying in 2s...")
            time.sleep(2)

    print("[AegisSOC] ERROR: PostgreSQL failed to become ready in time.")
    sys.exit(1)
else:
    print("[AegisSOC] Using SQLite database. Proceeding without network wait.")
EOF
}

# Wait for DB
wait_for_db

# Run Alembic migrations
echo "[AegisSOC] Running database migrations (alembic upgrade head)..."
python -m alembic upgrade head || {
    echo "[AegisSOC] WARNING: Alembic migration encountered an issue, initializing schema via ORM fallback..."
    python -c "from app.core.database import init_db; init_db()"
}

# Seed initial organization, users, and baseline records if database is empty
echo "[AegisSOC] Checking initial data seeding..."
python -c "from app.core.database import SessionLocal; from app.utils.seed_data import seed_initial_data; s = SessionLocal(); seed_initial_data(s); s.close(); print('[AegisSOC] Seed verification completed.')"

echo "[AegisSOC] Initialization complete. Starting service..."
PORT="${PORT:-8000}"
if [ -n "$PORT" ] && [ "$PORT" != "8000" ]; then
    echo "[AegisSOC] Custom port detected: $PORT (substituting into command)..."
    args=()
    skip_next=false
    for arg in "$@"; do
        if [ "$skip_next" = true ]; then
            args+=("$PORT")
            skip_next=false
        elif [ "$arg" = "--port" ]; then
            args+=("$arg")
            skip_next=true
        else
            args+=("$arg")
        fi
    done
    exec "${args[@]}"
fi
exec "$@"
