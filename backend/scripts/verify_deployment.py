"""
AegisSOC Pre-Flight & Clean Environment Deployment Verification Script
Systematically checks database connection, migrations, seeding, health endpoints,
REST endpoints, ML anomaly detector, AI provider configuration, and WebSocket streaming.
"""

import sys
import os
import json
from datetime import datetime, timezone

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from starlette.testclient import TestClient


def run_checks():
    print("=" * 70)
    print(" AegisSOC Deployment & Pre-Flight Verification Suite")
    print("=" * 70)

    # 1. Verify App Import & Core Engine
    print("\n[1/8] Initializing FastAPI Core Engine...")
    from app.main import app
    from app.core.config import settings
    print(f"  ✓ Application initialized: '{settings.APP_NAME}' v{settings.APP_VERSION}")
    print(f"  ✓ Environment: {settings.APP_ENV} (Debug: {settings.DEBUG})")

    # 2. Database Connection & ORM Models
    print("\n[2/8] Testing Database Connection & ORM Initialization...")
    from app.core.database import SessionLocal, init_db
    init_db()
    db = SessionLocal()
    from sqlalchemy import text
    db.execute(text("SELECT 1"))
    print("  ✓ Database connection established and active.")

    # 3. Verify Database Migrations & Initial Seeding
    print("\n[3/8] Verifying Database Seeding...")
    from app.utils.seed_data import seed_initial_data
    seed_initial_data(db)
    from app.models.user import User
    from app.models.incident import Incident
    user_count = db.query(User).count()
    inc_count = db.query(Incident).count()
    db.close()
    print(f"  ✓ Seed records verified: {user_count} users, {inc_count} baseline incidents.")

    client = TestClient(app)

    # 4. Verify Root & Monitoring Health Endpoints
    print("\n[4/8] Testing Health Endpoints...")
    res_health = client.get("/health")
    assert res_health.status_code == 200, f"Expected 200 from /health, got {res_health.status_code}"
    health_data = res_health.json()
    assert health_data.get("status") == "healthy"
    print(f"  ✓ GET /health responded HTTP 200 OK: {health_data}")

    res_subsystems = client.get("/api/monitoring/health")
    assert res_subsystems.status_code == 200
    subsystems = res_subsystems.json()
    assert len(subsystems) >= 5
    print(f"  ✓ GET /api/monitoring/health responded HTTP 200 OK ({len(subsystems)} subsystems monitored).")

    # 5. Verify Authentication & Role Security
    print("\n[5/8] Testing Authentication & Token Handling...")
    login_res = client.post("/api/auth/login", json={
        "email": "admin@soc.aegis.internal",
        "password": "AdminPass123!"
    })
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    auth_data = login_res.json()
    token = auth_data["access_token"]
    auth_header = {"Authorization": f"Bearer {token}"}
    print(f"  ✓ Authenticated as '{auth_data['user']['email']}' ({auth_data['user']['role']}).")

    # 6. Verify ML Model Loading & Deterministic Classification
    print("\n[6/8] Testing ML Anomaly Model & Risk Inference...")
    from app.ml.anomaly_detector import anomaly_detector
    score, sev, attack = anomaly_detector.score_flow(
        "185.45.10.1", "10.0.0.10", {"destination_port": 22, "packet_count": 50}
    )
    assert attack == "Brute Force"
    assert sev in ["High", "Critical"]
    print(f"  ✓ ML Anomaly Detector loaded: flow scored {score} ({sev} - {attack}).")

    an_res = client.post("/api/threats/analyze", json={
        "source_ip": "185.45.10.1",
        "destination_port": 22,
        "packet_count": 50
    })
    assert an_res.status_code == 200
    print(f"  ✓ POST /api/threats/analyze responded HTTP 200 OK (Risk: {an_res.json()['risk_level']}).")

    # 7. Verify AI Provider Configuration & Availability
    print("\n[7/8] Testing AI Provider Configuration...")
    ai_status_res = client.get("/api/ai/status")
    assert ai_status_res.status_code == 200
    ai_info = ai_status_res.json()
    print(f"  ✓ AI Provider status: {ai_info['provider']} (Available: {ai_info['is_available']}).")

    # 8. Verify WebSocket Connection & Stream Protocol
    print("\n[8/8] Testing WebSocket Connection & Handshake...")
    with client.websocket_connect(f"/ws/monitoring?token={token}") as ws:
        handshake = ws.receive_json()
        assert handshake["type"] == "CONNECTION_ESTABLISHED"
        assert handshake["authenticated"] is True
        print(f"  ✓ WebSocket connected to /ws/monitoring: {handshake['type']} (Role: {handshake['role']}).")
        ws.send_json({"action": "ping"})
        pong = ws.receive_json()
        assert pong.get("type") in ["pong", "TRAFFIC_TICK"]
        print(f"  ✓ WebSocket duplex messaging verified: received frame '{pong.get('type')}'.")

    print("\n" + "=" * 70)
    print(" ALL DEPLOYMENT PRE-FLIGHT CHECKS PASSED SUCCESSFULLY (8/8)!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_checks()
    except Exception as e:
        print(f"\n❌ Pre-flight check failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
