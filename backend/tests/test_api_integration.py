import pytest
from httpx import AsyncClient
from starlette.testclient import TestClient

from app.main import app


@pytest.fixture
def auth_token_sync():
    """Sync fixture for WebSocket TestClient auth."""
    from app.core.security import create_access_token
    token = create_access_token(
        subject="admin@soc.aegis.internal",
        extra_claims={"role": "Admin", "name": "Admin User"}
    )
    return token


@pytest.mark.asyncio
async def test_auth_login_and_token(client: AsyncClient):
    """Verifies authentication returns JWT tokens for subsequent requests."""
    res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    assert res.status_code == 200
    body = res.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_dashboard_endpoints(client: AsyncClient):
    """Verifies GET /api/dashboard/overview, GET /api/dashboard/events, GET /api/dashboard/metrics."""
    # 1. GET /api/dashboard/overview
    ov_res = await client.get("/api/dashboard/overview?range=24h")
    assert ov_res.status_code == 200
    ov_data = ov_res.json()
    assert "kpis" in ov_data
    assert "timeline_series" in ov_data
    assert "threat_distribution" in ov_data

    # 2. GET /api/dashboard/events
    ev_res = await client.get("/api/dashboard/events?limit=10")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert isinstance(ev_data, list)
    assert len(ev_data) <= 10
    if ev_data:
        item = ev_data[0]
        assert "t" in item
        assert "type" in item
        assert "src" in item
        assert "dst" in item
        assert "sev" in item
        assert "by" in item

    # 3. GET /api/dashboard/metrics
    m_res = await client.get("/api/dashboard/metrics")
    assert m_res.status_code == 200
    m_data = m_res.json()
    assert "kpis" in m_data
    assert "active_threats" in m_data
    assert "critical_incidents" in m_data
    assert "traffic_analyzed_tb" in m_data


@pytest.mark.asyncio
async def test_monitoring_endpoints(client: AsyncClient):
    """Verifies GET /api/monitoring/status, GET /api/monitoring/traffic, GET /api/monitoring/events."""
    # 1. GET /api/monitoring/status
    s_res = await client.get("/api/monitoring/status")
    assert s_res.status_code == 200
    s_data = s_res.json()
    assert "status" in s_data
    assert "is_running" in s_data
    assert "packets_captured" in s_data

    # 2. GET /api/monitoring/traffic
    t_res = await client.get("/api/monitoring/traffic")
    assert t_res.status_code == 200
    t_data = t_res.json()
    assert "tIn" in t_data
    assert "tOut" in t_data
    assert len(t_data["tIn"]) == 40
    assert len(t_data["tOut"]) == 40

    # 3. GET /api/monitoring/events
    e_res = await client.get("/api/monitoring/events?limit=5")
    assert e_res.status_code == 200
    e_data = e_res.json()
    assert isinstance(e_data, list)
    assert len(e_data) <= 5


def test_websocket_monitoring_connection(auth_token_sync):
    """Verifies WS /ws/monitoring connection, handshake, and message receipt."""
    test_client = TestClient(app)
    with test_client.websocket_connect(f"/ws/monitoring?token={auth_token_sync}") as ws:
        # Handshake frame
        handshake = ws.receive_json()
        assert handshake["type"] == "CONNECTION_ESTABLISHED"
        assert handshake["authenticated"] is True
        assert handshake["role"] == "Admin"

        # Ping-pong action
        ws.send_json({"action": "ping"})
        pong = ws.receive_json()
        if pong.get("type") == "TRAFFIC_TICK":
            assert "inbound_mbps" in pong
        elif pong.get("type") == "pong":
            assert "time" in pong


@pytest.mark.asyncio
async def test_threats_endpoints(client: AsyncClient):
    """Verifies GET /api/threats, GET /api/threats/{id}, POST /api/threats/analyze."""
    # 1. GET /api/threats
    t_res = await client.get("/api/threats?limit=5")
    assert t_res.status_code == 200
    t_data = t_res.json()
    assert isinstance(t_data, list)
    assert len(t_data) >= 1
    sample_id = t_data[0]["id"]

    # 2. GET /api/threats/{id}
    detail_res = await client.get(f"/api/threats/{sample_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["id"] == sample_id
    assert "sev" in detail_data

    # 3. POST /api/threats/analyze
    analyze_res = await client.post(
        "/api/threats/analyze",
        json={"source_ip": "185.220.101.5", "destination_port": 22, "packet_count": 500}
    )
    assert analyze_res.status_code == 200
    an_data = analyze_res.json()
    assert "risk_level" in an_data
    assert "confidence" in an_data
    assert "recommended_actions" in an_data


@pytest.mark.asyncio
async def test_incidents_crud_endpoints(client: AsyncClient):
    """Verifies GET /api/incidents, POST /api/incidents, GET /api/incidents/{id}, PATCH /api/incidents/{id}."""
    # Authenticate
    login_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET /api/incidents
    inc_list_res = await client.get("/api/incidents?limit=10")
    assert inc_list_res.status_code == 200
    inc_list = inc_list_res.json()
    assert "items" in inc_list
    assert len(inc_list["items"]) >= 1

    # 2. POST /api/incidents
    create_payload = {
        "title": "API Integration Test Incident",
        "attack_type": "Brute Force",
        "severity": "High",
        "source_ip": "198.51.100.99",
        "destination_ip": "10.0.1.15",
        "confidence": 88,
        "analyst_name": "Test Analyst",
        "summary": "Automated integration testing incident creation."
    }
    create_res = await client.post("/api/incidents", json=create_payload, headers=headers)
    assert create_res.status_code == 201
    created_data = create_res.json()
    created_id = created_data["id"]
    assert created_data["title"] == create_payload["title"]

    # 3. GET /api/incidents/{id}
    get_res = await client.get(f"/api/incidents/{created_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == created_id

    # 4. PATCH /api/incidents/{id}
    patch_payload = {
        "status": "Investigating",
        "analyst_name": "Senior Analyst",
        "notes": "Triage verified threat activity."
    }
    patch_res = await client.patch(f"/api/incidents/{created_id}", json=patch_payload, headers=headers)
    assert patch_res.status_code == 200
    patched_data = patch_res.json()
    assert patched_data["status"] == "Investigating"
    assert patched_data["analyst"] == "Senior Analyst"


@pytest.mark.asyncio
async def test_ai_endpoints(client: AsyncClient):
    """Verifies POST /api/ai/chat, POST /api/ai/investigate, GET /api/ai/history."""
    # Authenticate
    login_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. POST /api/ai/chat (with null LLM fallback handling)
    chat_res = await client.post(
        "/api/ai/chat",
        json={"incident_id": "INC-2041", "message": "Explain this attack."},
        headers=headers
    )
    assert chat_res.status_code in [200, 502, 503]

    # 2. POST /api/ai/investigate
    inv_res = await client.post(
        "/api/ai/investigate",
        json={"incident_id": "INC-2041", "investigation_depth": "deep"},
        headers=headers
    )
    assert inv_res.status_code in [200, 502, 503]

    # 3. GET /api/ai/history
    hist_res = await client.get("/api/ai/history?incident_id=INC-2041", headers=headers)
    assert hist_res.status_code == 200
    hist_data = hist_res.json()
    assert isinstance(hist_data, list)


@pytest.mark.asyncio
async def test_intelligence_endpoints(client: AsyncClient):
    """Verifies GET /api/intelligence/ioc, POST /api/intelligence/lookup."""
    # 1. GET /api/intelligence/ioc
    ioc_res = await client.get("/api/intelligence/ioc?limit=10")
    assert ioc_res.status_code == 200
    ioc_data = ioc_res.json()
    assert "items" in ioc_data
    assert len(ioc_data["items"]) >= 1
    assert "total" in ioc_data

    # 2. POST /api/intelligence/lookup
    lookup_res = await client.post(
        "/api/intelligence/lookup",
        json={"indicator": "185.220.101.5", "ioc_type": "ip"}
    )
    assert lookup_res.status_code == 200
    lookup_data = lookup_res.json()
    assert lookup_data["indicator"] == "185.220.101.5"
    assert "reputation_score" in lookup_data
    assert "verdict" in lookup_data


@pytest.mark.asyncio
async def test_analytics_endpoints(client: AsyncClient):
    """Verifies GET /api/analytics/overview, GET /api/analytics/trends."""
    # 1. GET /api/analytics/overview
    ov_res = await client.get("/api/analytics/overview")
    assert ov_res.status_code == 200
    ov_data = ov_res.json()
    assert "kpis" in ov_data
    assert "distribution" in ov_data
    assert "severity_counts" in ov_data

    # 2. GET /api/analytics/trends
    tr_res = await client.get("/api/analytics/trends?period=7d")
    assert tr_res.status_code == 200
    tr_data = tr_res.json()
    assert "range" in tr_data
    assert "trends" in tr_data
    assert len(tr_data["trends"]) >= 1


@pytest.mark.asyncio
async def test_reports_endpoints(client: AsyncClient):
    """Verifies GET /api/reports, POST /api/reports/generate."""
    # Authenticate
    login_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. GET /api/reports
    list_res = await client.get("/api/reports?limit=10", headers=headers)
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert isinstance(list_data, list)
    assert len(list_data) >= 1
    assert "title" in list_data[0]

    # 2. POST /api/reports/generate
    gen_payload = {
        "title": "Quarterly Executive SOC Threat Review",
        "report_type": "executive_summary",
        "range_key": "30d",
        "format": "json"
    }
    gen_res = await client.post("/api/reports/generate", json=gen_payload, headers=headers)
    assert gen_res.status_code == 201
    gen_data = gen_res.json()
    assert gen_data["report_id"].startswith("REP-")
    assert gen_data["format"] == "json"
    assert gen_data["status"] == "Completed"
    assert "download_url" in gen_data
