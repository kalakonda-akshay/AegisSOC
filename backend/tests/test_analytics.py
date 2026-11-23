import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_analytics_timeline(client: AsyncClient):
    response = await client.get("/api/analytics/timeline?range=24h")
    assert response.status_code == 200
    data = response.json()
    assert "series" in data
    assert "total" in data["series"]
    assert "high" in data["series"]
    assert "critical" in data["series"]
    assert len(data["timestamps"]) == 24


@pytest.mark.asyncio
async def test_analytics_overview(client: AsyncClient):
    response = await client.get("/api/analytics/overview?range=7d")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert "distribution" in data
    assert "severity_counts" in data
