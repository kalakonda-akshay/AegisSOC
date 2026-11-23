import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_threats(client: AsyncClient):
    response = await client.get("/api/threats?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert len(events) <= 10
    assert len(events) > 0
    first_ev = events[0]
    assert "t" in first_ev
    assert "src" in first_ev
    assert "dst" in first_ev
    assert "type" in first_ev
    assert "sev" in first_ev
    assert "by" in first_ev


@pytest.mark.asyncio
async def test_ingest_threat(client: AsyncClient):
    payload = {
        "source_ip": "185.45.103.99",
        "destination_ip": "10.0.0.10",
        "attack_type": "Brute Force",
        "severity": "Critical",
        "detected_by": "ML anomaly model",
        "confidence": 95
    }
    response = await client.post("/api/threats/ingest", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["src"] == payload["source_ip"]
    assert data["type"] == payload["attack_type"]
    assert data["sev"] == payload["severity"]
