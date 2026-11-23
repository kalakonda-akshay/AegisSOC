import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_export_incidents_csv(client: AsyncClient):
    response = await client.get("/api/reports/incidents/export?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    content = response.text
    # Verify exact CSV header matching frontend exportCsv()
    assert content.startswith("id,title,type,severity,status")
    assert "INC-2041" in content


@pytest.mark.asyncio
async def test_export_incidents_json(client: AsyncClient):
    response = await client.get("/api/reports/incidents/export?format=json")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 10
    ids = [d["id"] for d in data]
    assert "INC-2041" in ids
