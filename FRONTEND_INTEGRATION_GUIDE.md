# AegisSOC API & WebSocket Integration Guide for Frontend

This guide documents the API contracts, WebSocket channels, authentication mechanisms, and data schemas provided by the AegisSOC FastAPI backend for seamless integration with the existing Claude-developed React frontend (`frontend/aegissoc.html`).

---

## 1. Architecture Overview & Base URLs

- **HTTP API Base URL**: `http://localhost:8000/api`
- **Interactive Swagger Documentation**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **WebSocket Base URL**: `ws://localhost:8000/ws` (also mounted at root `ws://localhost:8000/ws/monitoring`)
- **Error Standard**: RFC 7807 Problem Details (`type`, `title`, `status`, `detail`, `instance`, `code`)

---

## 2. Authentication & Authorization

### Endpoints
- `POST /api/auth/login`: Authenticate with email and password to receive JWT tokens.
- `POST /api/auth/refresh`: Refresh expired access token using the refresh token.
- `GET /api/auth/me`: Retrieve current user profile and role permissions.

### Headers
Include the JWT Bearer token in the `Authorization` header for all protected endpoints:
```http
Authorization: Bearer <access_token>
Content-Type: application/json
```

### Roles
- **Admin**: Full access across all system controls, user management, and actions.
- **Security Analyst**: Access to triage, incident lifecycle changes, AI investigations, intelligence lookups, and report generation.
- **Viewer**: Read-only access to dashboards, monitoring telemetry, incidents, and reports.

---

## 3. Real-Time WebSocket Channel (`WS /ws/monitoring`)

The unified WebSocket channel connects live telemetry, network throughput ticks, and threat detection events directly to the React frontend state.

### Connection URL
```
ws://localhost:8000/ws/monitoring?token=<jwt_access_token>&last_seq=<optional_sequence_id>
```

### Authentication & Handshake
Upon successful handshake, the server immediately returns a `CONNECTION_ESTABLISHED` message:
```json
{
  "type": "CONNECTION_ESTABLISHED",
  "authenticated": true,
  "identity": "admin@soc.aegis.internal",
  "role": "Admin",
  "timestamp": "2026-11-23T18:00:00Z",
  "latest_seq_id": 42
}
```

### Streamed Message Types
1. **Traffic Tick (`TRAFFIC_TICK`)** (broadcast every 1.5s):
   Updates the area chart throughput history (`tIn`, `tOut`) and dashboard telemetry:
   ```json
   {
     "type": "TRAFFIC_TICK",
     "inbound_mbps": 78.4,
     "outbound_mbps": 34.2,
     "active_threats": 7,
     "critical_incidents": 2,
     "timestamp": "2026-11-23T18:00:01.500Z"
   }
   ```

2. **Security Event (`security_event`)**:
   Streams live detections to the security event feed table:
   ```json
   {
     "type": "security_event",
     "seq": 43,
     "event": {
       "id": 84920,
       "t": 1795543200,
       "src": "185.220.101.5",
       "dst": "10.0.1.20",
       "type": "Brute Force",
       "sev": "High",
       "by": "ML anomaly model"
     }
   }
   ```

### Reconnection & Resiliency Replay
If a frontend client temporarily disconnects and reconnects, passing `?last_seq=<id>` replays all events missed during the network interruption from the server's ring buffer:
```json
{
  "type": "RECONNECTION_REPLAY",
  "events_count": 3,
  "events": [ ... ]
}
```

### Client Actions (Inbound over WebSocket)
- **Ping**: Send `{"action": "ping"}` $\rightarrow$ receives `{"type": "pong", "time": "..."}`.
- **Resync**: Send `{"action": "resync", "since_seq_id": 35}` $\rightarrow$ receives `{"type": "RESYNC_DATA", "events": [ ... ]}`.

---

## 4. REST API Endpoint Specifications

### 4.1 Dashboard
- **`GET /api/dashboard/overview?range=24h`**
  - **Query Params**: `range` (`24h`, `7d`, `30d`)
  - **Response**:
    - `kpis`: 6 KPI items with labels, values, deltas, and 8-point sparklines (`total_events`, `active_threats`, `critical_incidents`, `threats_blocked`, `network_anomalies`, `posture_score`).
    - `timeline_series`: 40-point time-series arrays for `total`, `threats`, `blocked`, and `anomalies`.
    - `threat_distribution`: Counts and colors for Brute Force, Port Scanning, DDoS, Malware, etc.
    - `attack_severity`: Distribution across Critical, High, Medium, Low.
    - `recent_incidents`: Latest 5 incidents.
    - `system_health`: Subsystem statuses and latencies.
- **`GET /api/dashboard/events?limit=25`**
  - **Response**: Array of event items (`id`, `t`, `src`, `dst`, `type`, `sev`, `by`).
- **`GET /api/dashboard/metrics`**
  - **Response**: Current SOC posture, active threats, critical incidents, and bandwidth statistics.

---

### 4.2 Network Monitoring
- **`GET /api/monitoring/status`**
  - **Response**: Scapy engine status (`running`, `stopped`, `paused`), active interface, captured packets, and active flows.
- **`GET /api/monitoring/traffic`**
  - **Response**: 40-point `tIn` and `tOut` numeric arrays for area chart rendering.
- **`GET /api/monitoring/events`**
  - **Response**: Real-time event log for network monitoring.
- **`GET /api/monitoring/topology`**
  - **Response**: Perimeter node graph (`nodes` with `id`, `name`, `ip`, `role`, `bad`, `status`).

---

### 4.3 Threat Detection & ML Inference
- **`GET /api/threats?limit=25&severity=Critical`**
  - **Response**: List of threat events matching frontend event table schema (`id`, `t`, `src`, `dst`, `type`, `sev`, `by`, `conf`).
- **`GET /api/threats/{id}`**
  - **Response**: Detailed threat telemetry and payload inspection.
- **`POST /api/threats/analyze`**
  - **Payload**:
    ```json
    {
      "source_ip": "185.220.101.5",
      "destination_ip": "10.0.1.15",
      "destination_port": 22,
      "protocol": "TCP",
      "packet_count": 500,
      "byte_count": 64000
    }
    ```
  - **Response**: Anomaly classification score, risk level, IOC verdict, and recommended actions.

---

### 4.4 Incident Management & Lifecycle
- **`GET /api/incidents?page=1&limit=25&severity=All&status=All&search=`**
  - **Response**: Paginated incident cases (`items`, `total`, `page`, `pages`, `limit`).
  - **Item Fields**: `id` (e.g. `INC-2041`), `title`, `type`, `src`, `dst`, `sev`, `time`, `status`, `analyst`, `conf`.
- **`POST /api/incidents`**
  - **Payload**: `title`, `attack_type`, `source_ip`, `destination_ip`, `severity`, `analyst_name`, `confidence`.
  - **Response**: Created incident with assigned priority.
- **`GET /api/incidents/{id}`**
  - **Response**: Full incident dossier including forensic `evidence`, lifecycle `timeline`, and `response_actions`.
- **`PATCH /api/incidents/{id}`**
  - **Payload**:
    ```json
    {
      "status": "Investigating",
      "analyst_name": "A. Rao",
      "notes": "Verified malicious authentication spikes."
    }
    ```
  - **Transitions Supported**: `New` $\rightarrow$ `Investigating` $\rightarrow$ `Contained` $\rightarrow$ `Resolved`.

---

### 4.5 AI Security Analyst
- **`POST /api/ai/chat`** & **`POST /api/ai/investigate`**
  - **Payload**:
    ```json
    {
      "incident_id": "INC-2041",
      "message": "Conduct automated investigation and mitigation analysis."
    }
    ```
  - **Response Structure (Binds directly to `rep.sec` and `rep.inc` in frontend)**:
    ```json
    {
      "incident_id": "INC-2041",
      "incident": {
        "id": "INC-2041",
        "title": "SSH Brute Force Attack",
        "type": "Brute Force",
        "src": "185.220.101.5",
        "dst": "10.0.1.15",
        "sev": "High",
        "status": "Investigating",
        "conf": 78
      },
      "sections": {
        "summary": "...",
        "severity": "...",
        "evidence": "...",
        "attack_technique": "...",
        "impact": "...",
        "recommendations": "...",
        "confidence": "..."
      },
      "ai_provider": "google-gemini",
      "model": "gemini-1.5-pro",
      "tokens_used": 1420
    }
    ```
- **`GET /api/ai/history?incident_id=INC-2041`**
  - **Response**: Chronological AI conversation history and investigation audit trail.

---

### 4.6 Threat Intelligence
- **`GET /api/intelligence/ioc?page=1&limit=25&ioc_type=ip&verdict=Malicious`**
  - **Response**: Paginated indicators of compromise (`indicator`, `indicator_type`, `verdict`, `reputation_score`, `is_malicious`, `threat_types`, `country_code`, `last_seen`).
- **`POST /api/intelligence/lookup`**
  - **Payload**: `{"indicator": "185.220.101.5", "ioc_type": "ip"}`
  - **Response**: Reputation enrichment score (0-100), verdict (`Malicious`, `Suspicious`, `Clean`), ASN, and threat categories.

---

### 4.7 Analytics
- **`GET /api/analytics/overview`**
  - **Response**: Overall threat distribution, severity breakdowns, and metric KPIs.
- **`GET /api/analytics/trends?period=7d`**
  - **Response**: Multi-hour trend points with MTTR metrics and category breakdowns.

---

### 4.8 Reporting & Exports
- **`GET /api/reports?limit=20`**
  - **Response**: List of generated security reports (`id`, `title`, `report_type`, `status`, `format`, `generated_at`, `summary`).
- **`POST /api/reports/generate`**
  - **Payload**:
    ```json
    {
      "title": "Executive Incident Briefing",
      "report_type": "executive_summary",
      "range_key": "24h",
      "format": "json"
    }
    ```
  - **Response**: Report metadata with immediate download URL.
- **`GET /api/reports/incidents/export?format=csv&severity=All&status=All`**
  - **Response**: Direct CSV download matching frontend's `exportCsv()` format (`id,title,type,severity,status,source_ip,destination_ip`).
- **`GET /api/reports/incidents/export?format=json&severity=All&status=All`**
  - **Response**: Direct JSON download.

---

## 5. Summary of Frontend Compatibility
| Frontend Feature / State | Backend Endpoint / Channel | Verified Status |
| :--- | :--- | :--- |
| Live Traffic Chart (`tIn`, `tOut`) | `GET /api/monitoring/traffic`, `WS /ws/monitoring` | **Verified** |
| Real-time Event Feed | `GET /api/dashboard/events`, `WS /ws/monitoring` | **Verified** |
| 6 KPI Cards & Sparklines | `GET /api/dashboard/overview`, `GET /api/dashboard/metrics` | **Verified** |
| Perimeter Map Nodes | `GET /api/monitoring/topology` | **Verified** |
| Subsystem Health Badges | `GET /api/monitoring/health` | **Verified** |
| Incident Center Table & Lifecycle | `GET /api/incidents`, `PATCH /api/incidents/{id}` | **Verified** |
| AI Analyst 7 Structured Sections | `POST /api/ai/chat`, `POST /api/ai/investigate` | **Verified** |
| CSV / JSON Export | `GET /api/reports/incidents/export` | **Verified** |
| Threat Intel Lookups | `POST /api/intelligence/lookup`, `GET /api/intelligence/ioc` | **Verified** |
| Analytics Trends & MTTR | `GET /api/analytics/trends` | **Verified** |
