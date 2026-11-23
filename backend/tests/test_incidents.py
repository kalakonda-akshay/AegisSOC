"""
Comprehensive Unit & Integration Tests for AegisSOC Incident Management & Defensive Response
Verifies lifecycle transitions, prioritization, analyst assignment, evidence collection,
investigation histories, and approval-based defensive containment workflows.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_incidents(client: AsyncClient):
    response = await client.get("/api/incidents")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert len(data["items"]) >= 10
    # verify item structure matches frontend expectations
    first_item = data["items"][0]
    assert "id" in first_item
    assert "title" in first_item
    assert "type" in first_item
    assert "src" in first_item
    assert "dst" in first_item
    assert "sev" in first_item
    assert "status" in first_item
    assert "analyst" in first_item
    assert "priority" in first_item


@pytest.mark.asyncio
async def test_filter_incidents_by_severity(client: AsyncClient):
    response = await client.get("/api/incidents?severity=Critical")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["sev"] == "Critical"


@pytest.mark.asyncio
async def test_filter_incidents_by_status(client: AsyncClient):
    response = await client.get("/api/incidents?status=Investigating")
    assert response.status_code == 200
    data = response.json()
    for item in data["items"]:
        assert item["status"] == "Investigating"


@pytest.mark.asyncio
async def test_search_incidents(client: AsyncClient):
    response = await client.get("/api/incidents?q=bastion")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert "bastion" in data["items"][0]["title"].lower()


@pytest.mark.asyncio
async def test_get_incident_detail(client: AsyncClient):
    response = await client.get("/api/incidents/INC-2041")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "INC-2041"
    assert "ai_analysis" in data
    assert "recommended_actions" in data
    assert "timeline" in data
    assert "evidence" in data
    assert "response_actions" in data


@pytest.mark.asyncio
async def test_update_incident_status(client: AsyncClient):
    update_resp = await client.patch(
        "/api/incidents/INC-2041/status",
        json={"status": "Contained", "notes": "Blocked IP at edge firewall"}
    )
    assert update_resp.status_code == 200
    data = update_resp.json()
    assert data["id"] == "INC-2041"
    assert data["status"] == "Contained"

    # Verify change persisted
    detail_resp = await client.get("/api/incidents/INC-2041")
    assert detail_resp.json()["status"] == "Contained"


@pytest.mark.asyncio
async def test_create_incident_with_priority(client: AsyncClient):
    new_inc = {
        "title": "SQL Injection attempt on customer portal",
        "attack_type": "Suspicious Traffic",
        "source_ip": "194.26.29.99",
        "destination_ip": "10.0.2.5",  # database asset
        "severity": "Critical",
        "confidence": 91
    }
    response = await client.post("/api/incidents", json=new_inc)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == new_inc["title"]
    assert data["src"] == "194.26.29.99"
    assert data["status"] == "New"
    assert data["priority"] == "P1 - Critical"  # Critical severity targeting database asset


@pytest.mark.asyncio
async def test_incident_lifecycle_transitions(client: AsyncClient):
    """Verifies complete lifecycle flow: New -> Investigating -> Contained -> Resolved."""
    # 1. Create fresh incident
    create_res = await client.post("/api/incidents", json={
        "title": "Unauthorized SSH brute force attempt",
        "attack_type": "Brute Force",
        "source_ip": "185.45.103.91",
        "destination_ip": "10.0.0.10",
        "severity": "High"
    })
    inc_code = create_res.json()["id"]

    # 2. Transition New -> Investigating
    t1 = await client.patch(f"/api/incidents/{inc_code}/status", json={"status": "Investigating", "notes": "Triage begun"})
    assert t1.status_code == 200
    assert t1.json()["status"] == "Investigating"

    # 3. Transition Investigating -> Contained
    t2 = await client.patch(f"/api/incidents/{inc_code}/status", json={"status": "Contained", "notes": "VLAN quarantine placed"})
    assert t2.status_code == 200
    assert t2.json()["status"] == "Contained"

    # 4. Transition Contained -> Resolved
    t3 = await client.patch(f"/api/incidents/{inc_code}/status", json={"status": "Resolved", "notes": "Credentials rotated"})
    assert t3.status_code == 200
    assert t3.json()["status"] == "Resolved"


@pytest.mark.asyncio
async def test_analyst_and_severity_assignment(client: AsyncClient):
    """Verifies reassigning analyst and updating severity."""
    # Analyst assignment
    assign_res = await client.patch(
        "/api/incidents/INC-2041/analyst",
        json={"analyst_name": "Jane Doe, Lead IR", "notes": "Escalated for senior review"}
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["analyst"] == "Jane Doe, Lead IR"

    # Severity update
    sev_res = await client.patch(
        "/api/incidents/INC-2041/severity",
        json={"severity": "Critical", "notes": "Privilege escalation verified"}
    )
    assert sev_res.status_code == 200
    assert sev_res.json()["sev"] == "Critical"


@pytest.mark.asyncio
async def test_evidence_collection_and_history(client: AsyncClient):
    """Verifies adding forensic evidence items and querying investigation history."""
    ev_payload = {
        "evidence_type": "pcap",
        "data": "PCAP stream: 45 SYN packets within 2.5s from 185.45.103.91",
        "description": "Port scan capture snippet",
        "source": "Core Tap 01"
    }
    ev_res = await client.post("/api/incidents/INC-2041/evidence", json=ev_payload)
    assert ev_res.status_code == 201
    assert ev_res.json()["evidence_type"] == "pcap"

    # Query history
    hist_res = await client.get("/api/incidents/INC-2041/investigations")
    assert hist_res.status_code == 200
    data = hist_res.json()
    assert data["incident_code"] == "INC-2041"
    assert "timeline" in data


@pytest.mark.asyncio
async def test_defensive_response_approval_workflow(client: AsyncClient):
    """
    Verifies the complete approval-based defensive containment workflow:
    1. Propose action (simulation mode by default)
    2. Execution blocked without approval (403 Forbidden)
    3. Explicit authorization / approval
    4. Execution in simulation mode with dry-run verification
    5. Execution in live authorized mode with audit receipt
    """
    # 1. Propose Firewall Rule Review
    prop_payload = {
        "action_type": "FIREWALL_RULE_REVIEW",
        "title": "Perimeter ingress drop rule for attacker IP",
        "target": "185.45.103.91",
        "details": {"protocol": "TCP", "port": 22}
    }
    prop_res = await client.post("/api/incidents/INC-2041/response/propose", json=prop_payload)
    assert prop_res.status_code == 201
    action = prop_res.json()
    action_id = action["id"]
    assert action["status"] == "PROPOSED"
    assert action["mode"] == "SIMULATION"
    assert "iptables" in action["details"]

    # 2. Attempt Execution without Approval -> MUST BE BLOCKED (HTTP 403 Forbidden)
    exec_unauth = await client.post(
        f"/api/incidents/response/{action_id}/execute",
        json={"mode": "SIMULATION"}
    )
    assert exec_unauth.status_code == 403
    assert "Execution denied" in exec_unauth.json()["detail"]

    # 3. Explicit Approval Gate
    approve_res = await client.post(
        f"/api/incidents/response/{action_id}/approve",
        json={"approval_notes": "Reviewed and verified by Senior Incident Commander"}
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"

    # 4. Safe Execution in Simulation Mode
    exec_sim = await client.post(
        f"/api/incidents/response/{action_id}/execute",
        json={"mode": "SIMULATION"}
    )
    assert exec_sim.status_code == 200
    sim_data = exec_sim.json()
    assert sim_data["status"] == "EXECUTED"
    assert sim_data["mode"] == "SIMULATION"
    assert "[SIMULATION MODE - DRY RUN SUCCESSFUL]" in sim_data["execution_result"]

    # 5. Propose & Authorize Endpoint Isolation Plan
    prop_iso = await client.post("/api/incidents/INC-2041/response/propose", json={
        "action_type": "ENDPOINT_ISOLATION_PLAN",
        "title": "Quarantine compromised workstation",
        "target": "10.0.3.99"
    })
    iso_id = prop_iso.json()["id"]

    await client.post(f"/api/incidents/response/{iso_id}/approve", json={"approval_notes": "Host quarantine authorized"})

    exec_live = await client.post(
        f"/api/incidents/response/{iso_id}/execute",
        json={"mode": "LIVE_AUTHORIZED"}
    )
    assert exec_live.status_code == 200
    live_data = exec_live.json()
    assert live_data["status"] == "EXECUTED"
    assert live_data["mode"] == "LIVE_AUTHORIZED"
    assert "[LIVE AUTHORIZED EXECUTION COMPLETED]" in live_data["execution_result"]
