import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_dashboard_overview(client: AsyncClient):
    response = await client.get("/api/dashboard/overview?range=24h")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert len(data["kpis"]) == 6
    assert "timeline_series" in data
    assert "total" in data["timeline_series"]
    assert "threat_distribution" in data
    assert "attack_severity" in data
    assert "recent_incidents" in data
    assert "system_health" in data


@pytest.mark.asyncio
async def test_get_dashboard_kpis(client: AsyncClient):
    response = await client.get("/api/dashboard/kpis?range=7d")
    assert response.status_code == 200
    kpis = response.json()
    assert len(kpis) == 6
    keys = [k["key"] for k in kpis]
    assert "total_events" in keys
    assert "active_threats" in keys
    assert "critical_incidents" in keys
    assert "threats_blocked" in keys
    assert "network_anomalies" in keys
    assert "posture_score" in keys
