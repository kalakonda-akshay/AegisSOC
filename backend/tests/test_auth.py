import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "admin@soc.aegis.internal"
    assert data["user"]["role"] in ["Admin", "admin"]


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient):
    response = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "WrongPassword!"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["status"] == 401


@pytest.mark.asyncio
async def test_token_refresh(client: AsyncClient):
    login_resp = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    refresh_token = login_resp.json()["refresh_token"]

    refresh_resp = await client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_resp.status_code == 200
    assert "access_token" in refresh_resp.json()


@pytest.mark.asyncio
async def test_get_current_user_profile(client: AsyncClient):
    login_resp = await client.post(
        "/api/auth/login",
        json={"email": "a.rao@soc.aegis.internal", "password": "AnalystPass123!"}
    )
    token = login_resp.json()["access_token"]

    profile_resp = await client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert profile_resp.status_code == 200
    profile = profile_resp.json()
    assert profile["full_name"] == "A. Rao"
    assert profile["email"] == "a.rao@soc.aegis.internal"
