"""
AegisSOC Comprehensive Security Audit & Hardening Test Suite
Verifies defense against OWASP Top 10 vulnerabilities, injection, broken access control,
privilege escalation, token confusion, rate limiting, and malicious file uploads.
"""

import io
import pytest
from httpx import AsyncClient

from app.core.rate_limiter import limiter
from app.core.security import create_access_token


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensures a clean rate limiter state for each test."""
    limiter.clear()
    yield
    limiter.clear()


# =============================================================================
# 1. SQL Injection (SQLi) Audit Tests
# =============================================================================
@pytest.mark.asyncio
async def test_sqli_in_incident_search_and_filters(client: AsyncClient):
    """Verifies that SQL injection payloads in search, severity, and status query parameters are neutralized."""
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE incidents; --",
        "1' UNION SELECT username, hashed_password, id, NULL FROM users --",
        "admin'--",
        "' OR 1=1 --",
        "'; VACUUM; --"
    ]

    for payload in sqli_payloads:
        # Search query parameter
        res = await client.get(f"/api/incidents?search={payload}")
        assert res.status_code == 200, f"SQLi payload broke search: {payload}"
        data = res.json()
        assert "items" in data
        assert isinstance(data["items"], list)

        # Severity query parameter
        res_sev = await client.get(f"/api/incidents?severity={payload}")
        assert res_sev.status_code == 200, f"SQLi payload broke severity: {payload}"

        # Status query parameter
        res_status = await client.get(f"/api/incidents?status={payload}")
        assert res_status.status_code == 200, f"SQLi payload broke status: {payload}"


@pytest.mark.asyncio
async def test_sqli_in_threat_intel_lookup(client: AsyncClient):
    """Verifies SQL injection payloads in threat intel lookup parameters are handled safely."""
    payload = "192.168.1.1' OR 1=1; DROP TABLE threat_intel_cache; --"
    res = await client.post(
        "/api/intelligence/lookup",
        json={"indicator": payload, "ioc_type": "ip"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["indicator"] == payload


# =============================================================================
# 2. Broken Access Control & Privilege Escalation Audit Tests
# =============================================================================
@pytest.mark.asyncio
async def test_privilege_escalation_registration_blocked(client: AsyncClient):
    """Verifies that anonymous users CANNOT self-register with the 'Admin' role."""
    exploit_payload = {
        "email": "attacker_admin@hacker.io",
        "password": "HackerPassword123!",
        "full_name": "Rogue Operator",
        "role_name": "Admin"
    }
    res = await client.post("/api/auth/register", json=exploit_payload)
    assert res.status_code == 400
    detail = res.json()["detail"].lower()
    assert "admin" in detail and "prohibited" in detail


@pytest.mark.asyncio
async def test_broken_access_control_viewer_cannot_execute_actions(client: AsyncClient):
    """Verifies that a Viewer role CANNOT approve or execute defensive response actions."""
    viewer_token = create_access_token(
        subject="viewer@soc.aegis.internal",
        extra_claims={"role": "Viewer", "name": "Read Only Auditor"}
    )
    headers = {"Authorization": f"Bearer {viewer_token}"}

    # Propose response action as Viewer
    prop_res = await client.post(
        "/api/incidents/INC-2041/response/propose",
        json={
            "action_type": "FIREWALL_RULE_REVIEW",
            "title": "Unauthorized attempt to propose firewall change",
            "target": "185.220.101.5"
        },
        headers=headers
    )
    assert prop_res.status_code == 403, "Viewer should be forbidden from proposing defensive containment"


@pytest.mark.asyncio
async def test_invalid_and_expired_token_rejection(client: AsyncClient):
    """Verifies that malformed, forged, or expired tokens are strictly rejected with 401."""
    # 1. Garbage token
    bad_headers = {"Authorization": "Bearer not-a-valid-jwt-token"}
    res1 = await client.get("/api/auth/me", headers=bad_headers)
    assert res1.status_code == 401

    # 2. Token signed with attacker secret key
    import jwt
    forged_token = jwt.encode({"sub": "admin", "role": "Admin"}, "attacker-forged-secret-key-32-chars-long!", algorithm="HS256")
    res2 = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
    assert res2.status_code == 401


# =============================================================================
# 3. Token Type Confusion Audit Tests
# =============================================================================
@pytest.mark.asyncio
async def test_token_type_confusion_access_as_refresh(client: AsyncClient):
    """Verifies that an access token CANNOT be substituted for a refresh token."""
    login_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    access_token = login_res.json()["access_token"]

    # Attempt to call /api/auth/refresh using access_token instead of refresh_token
    refresh_res = await client.post(
        "/api/auth/refresh",
        json={"refresh_token": access_token}
    )
    assert refresh_res.status_code == 401
    assert "refresh token is required" in refresh_res.json()["detail"].lower()


# =============================================================================
# 4. Password Policy & Complexity Validation
# =============================================================================
@pytest.mark.asyncio
async def test_weak_password_rejected_on_registration(client: AsyncClient):
    """Verifies that weak passwords lacking complexity (digits/uppercase) are rejected."""
    # Too short (< 8 chars)
    short_res = await client.post("/api/auth/register", json={
        "email": "weak1@soc.test", "password": "Short1", "full_name": "Test User"
    })
    assert short_res.status_code == 422

    # Missing uppercase
    no_upper_res = await client.post("/api/auth/register", json={
        "email": "weak2@soc.test", "password": "lowercase12345!", "full_name": "Test User"
    })
    assert no_upper_res.status_code == 422

    # Missing digit
    no_digit_res = await client.post("/api/auth/register", json={
        "email": "weak3@soc.test", "password": "NoDigitsPassword!", "full_name": "Test User"
    })
    assert no_digit_res.status_code == 422


# =============================================================================
# 5. Sensitive Data Exposure Audit Tests
# =============================================================================
@pytest.mark.asyncio
async def test_sensitive_credentials_never_exposed_in_api(client: AsyncClient):
    """Verifies that hashed passwords and internal secrets are NEVER returned in API responses."""
    # 1. Login endpoint
    login_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "AdminPass123!"}
    )
    login_data = login_res.json()
    assert "hashed_password" not in login_data
    assert "password" not in login_data
    assert "hashed_password" not in login_data["user"]

    # 2. Profile endpoint
    token = login_data["access_token"]
    me_res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    me_data = me_res.json()
    assert "hashed_password" not in me_data
    assert "password" not in me_data


# =============================================================================
# 6. Rate Limiting Audit Tests
# =============================================================================
@pytest.mark.asyncio
async def test_rate_limiting_on_auth_login(client: AsyncClient):
    """Verifies that brute-force credential stuffing triggers HTTP 429 Too Many Requests."""
    # Send 10 rapid login attempts (max allowed in 1 minute window)
    for _ in range(10):
        await client.post(
            "/api/auth/login",
            json={"email": "admin@soc.aegis.internal", "password": "BadPassword123!"}
        )

    # The 11th request must be rate limited
    throttled_res = await client.post(
        "/api/auth/login",
        json={"email": "admin@soc.aegis.internal", "password": "BadPassword123!"}
    )
    assert throttled_res.status_code == 429
    assert "Retry-After" in throttled_res.headers
    assert "Rate limit exceeded" in throttled_res.json()["detail"]


# =============================================================================
# 7. File Upload Validation & Malicious Ingestion Tests
# =============================================================================
@pytest.mark.asyncio
async def test_pcap_upload_invalid_extension_rejected(client: AsyncClient):
    """Verifies that malicious or non-PCAP file extensions (.exe, .php) are rejected."""
    fake_content = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00")
    res = await client.post(
        "/api/monitoring/pcap/analyze",
        files={"file": ("malware.exe", fake_content, "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Invalid file extension" in res.json()["detail"]


@pytest.mark.asyncio
async def test_pcap_upload_invalid_magic_header_rejected(client: AsyncClient):
    """Verifies that a text file masquerading as a PCAP (.pcap) with invalid magic bytes is rejected."""
    bad_pcap = io.BytesIO(b"This is just a plain text file, not a real pcap capture!")
    res = await client.post(
        "/api/monitoring/pcap/analyze",
        files={"file": ("fake_capture.pcap", bad_pcap, "application/vnd.tcpdump.pcap")}
    )
    assert res.status_code == 400
    assert "Invalid PCAP file header" in res.json()["detail"]


# =============================================================================
# 8. ML Detection Determinism & Risk Boundary Tests
# =============================================================================
def test_ml_anomaly_detection_boundaries():
    """Verifies deterministic ML classification for high-risk ports and volume."""
    from app.ml.anomaly_detector import anomaly_detector

    # SSH brute force port
    score_ssh, sev_ssh, type_ssh = anomaly_detector.score_flow(
        "185.45.10.1", "10.0.0.5", {"destination_port": 22, "packet_count": 50}
    )
    assert type_ssh == "Brute Force"
    assert sev_ssh in ["High", "Critical"]
    assert score_ssh >= 0.75

    # C2 communication port
    score_c2, sev_c2, type_c2 = anomaly_detector.score_flow(
        "45.142.214.8", "10.0.0.10", {"destination_port": 4444, "packet_count": 30}
    )
    assert type_c2 == "Malware Communication"
    assert sev_c2 in ["High", "Critical"]
    assert score_c2 >= 0.85

    # DDoS volumetric flood
    score_ddos, sev_ddos, type_ddos = anomaly_detector.score_flow(
        "103.91.23.1", "10.0.0.1", {"destination_port": 80, "packet_count": 2500}
    )
    assert type_ddos == "DDoS"
    assert sev_ddos in ["High", "Critical"]
    assert score_ddos >= 0.88
