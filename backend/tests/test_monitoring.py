import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_traffic(client: AsyncClient):
    response = await client.get("/api/monitoring/traffic")
    assert response.status_code == 200
    data = response.json()
    assert "tIn" in data
    assert "tOut" in data
    assert len(data["tIn"]) == 40
    assert len(data["tOut"]) == 40


@pytest.mark.asyncio
async def test_get_topology(client: AsyncClient):
    response = await client.get("/api/monitoring/topology")
    assert response.status_code == 200
    data = response.json()
    assert "center_node" in data
    assert "nodes" in data
    assert len(data["nodes"]) >= 8
    # verify nodes have bad flag and ip
    first_node = data["nodes"][0]
    assert "bad" in first_node
    assert "ip" in first_node


@pytest.mark.asyncio
async def test_get_health(client: AsyncClient):
    response = await client.get("/api/monitoring/health")
    assert response.status_code == 200
    health = response.json()
    assert len(health) == 5
    names = [h["name"] for h in health]
    assert "Network monitoring" in names
    assert "ML detection engine" in names
    assert "AI investigation engine" in names
    assert "Threat intelligence" in names
    assert "Database connection" in names
