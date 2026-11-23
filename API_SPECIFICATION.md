# AegisSOC — OpenAPI 3.1 & REST/WebSocket API Specification

## 1. Overview & Protocol Standards

The AegisSOC API provides a unified communication contract for the operations dashboard. All endpoints follow RESTful conventions over HTTP/2 with JSON payloads, complemented by full-duplex WebSockets for real-time telemetry streaming and Server-Sent Events (SSE) for token-by-token LLM report streaming.

- **Base URL**: `https://api.soc.aegis.internal/api/v1` (Production) / `http://localhost:8000/api/v1` (Local Development)
- **Content-Type**: `application/json`
- **Authentication**: Bearer Token in `Authorization` header (`Bearer <JWT_ACCESS_TOKEN>`) or `X-API-Key` for telemetry ingest.
- **Specification Format**: OpenAPI 3.1.0 compliant.

---

## 2. Frontend Contract Mapping Matrix

This table maps every user interface element, state variable, and callback in `frontend/aegissoc.html` directly to its corresponding backend API contract.

| Frontend Variable / Function | Purpose in `aegissoc.html` | Backend Route / Protocol | HTTP Method |
| :--- | :--- | :--- | :--- |
| `API.incidents()` / `INC` | Populate Incident Center & Recent Incidents | `/api/v1/incidents` | `GET` |
| `openInc(id)` | Load modal details for specific incident | `/api/v1/incidents/{id}` | `GET` |
| `setSt(id, s)` | Workflow transition (`New`➔`Investigating`➔`Contained`➔`Resolved`) | `/api/v1/incidents/{id}/status` | `PATCH` |
| `exportCsv()` | Download CSV of filtered incidents | `/api/v1/reports/incidents/export?format=csv` | `GET` |
| `API.events()` / `EV` | Live threat feed & Monitoring event stream | `/api/v1/events` | `GET` |
| `EV` (real-time 3.5s interval) | Continuous streaming of incoming threats | `/api/v1/ws/events` | `WebSocket` |
| `tIn`, `tOut` (1.5s interval) | Bandwidth throughput chart (inbound/outbound Mbps) | `/api/v1/ws/traffic` | `WebSocket` |
| `tIn`, `tOut` (initial load) | Historical throughput data points | `/api/v1/monitoring/traffic/history` | `GET` |
| `netDraw()` / `#net` | Perimeter network topology and node compromise status | `/api/v1/monitoring/topology` | `GET` |
| System Health list | Subsystem latencies and operational states | `/api/v1/monitoring/health` | `GET` |
| System Health (heartbeat) | Real-time latency updates for the 5 engines | `/api/v1/ws/health` | `WebSocket` |
| Overview KPIs & Sparklines | Total events, active threats, criticals, posture score | `/api/v1/analytics/kpis?range={24h\|7d\|30d}` | `GET` |
| Timeline Area Chart | Total, High, Critical event trends over time | `/api/v1/analytics/timeline?range={24h\|7d\|30d}` | `GET` |
| Threat Distribution Donut | Counts and ratios grouped by attack type | `/api/v1/analytics/distribution/types` | `GET` |
| Attack Severity Bars | Counts grouped by Critical, High, Medium, Low | `/api/v1/analytics/distribution/severity` | `GET` |
| `send(t)` / `report(t)` | AI Security Analyst interactive query & report | `/api/v1/investigations/chat` | `POST` (SSE) |
| `newInv()` / `hist` | Investigation history list & session management | `/api/v1/investigations` | `GET` / `POST` |
| `loadInv(i)` | Load previous investigation messages and evidence | `/api/v1/investigations/{id}` | `GET` |

---

## 3. REST API Endpoint Specifications

### 3.1 Authentication & Operator Identity

#### `POST /api/v1/auth/login`
Authenticates an analyst using credentials and returns JWT access and refresh tokens.

* **Request Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "email": "a.rao@soc.aegis.internal",
  "password": "SuperSecretPassword123!"
}
```
* **Response `200 OK`**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "refresh_token": "4f8a92b1-c4d7-4e5f-a189-98317c24f5a6",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": "c7a8b921-8f3a-493e-90f7-111222333444",
    "email": "a.rao@soc.aegis.internal",
    "full_name": "A. Rao",
    "role": "analyst"
  }
}
```

#### `POST /api/v1/auth/refresh`
Exchanges a valid refresh token for a fresh access token.
* **Request Body**: `{ "refresh_token": "4f8a92b1-c4d7-4e5f-a189-98317c24f5a6" }`
* **Response `200 OK`**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "refresh_token": "7a1b83d4-e2a1-4321-bf99-881122334455",
  "token_type": "bearer",
  "expires_in": 900
}
```

---

### 3.2 Incidents Management (`/api/v1/incidents`)

#### `GET /api/v1/incidents`
Returns a paginated list of security incidents matching search queries and severity filters.

* **Query Parameters**:
  - `q` (string, optional): Search string matching `id`, `title`, `type`, `src`, or `dst`.
  - `severity` (string, optional): Filter by `Critical`, `High`, `Medium`, `Low`, or `All` (default: `All`).
  - `status` (string, optional): Filter by `New`, `Investigating`, `Contained`, `Resolved`.
  - `sort_by` (string, optional): Field to sort by (`id`, `title`, `type`, `src`, `sev`, `time`, `status`, `analyst`). Default: `time`.
  - `sort_order` (string, optional): `asc` or `desc`. Default: `desc`.
  - `limit` (integer, optional): Number of records per page (default: 50).
  - `offset` (integer, optional): Pagination offset (default: 0).

* **Response `200 OK`**:
```json
{
  "total": 10,
  "items": [
    {
      "id": "INC-2041",
      "title": "SSH credential stuffing against bastion host",
      "type": "Brute Force",
      "src": "185.45.103.91",
      "dst": "10.0.0.10",
      "sev": "Critical",
      "time": "2026-11-23T15:20:00Z",
      "status": "Investigating",
      "analyst": "A. Rao",
      "conf": 94
    },
    {
      "id": "INC-2042",
      "title": "Horizontal port sweep on DMZ subnet",
      "type": "Port Scanning",
      "src": "45.132.88.14",
      "dst": "10.0.1.13",
      "sev": "High",
      "time": "2026-11-23T14:28:00Z",
      "status": "New",
      "analyst": "M. Iyer",
      "conf": 88
    }
  ]
}
```

#### `GET /api/v1/incidents/{id}`
Returns complete forensic details for the incident modal (`openInc(id)`).

* **Response `200 OK`**:
```json
{
  "id": "INC-2041",
  "title": "SSH credential stuffing against bastion host",
  "type": "Brute Force",
  "src": "185.45.103.91",
  "dst": "10.0.0.10",
  "sev": "Critical",
  "time": "2026-11-23T15:20:00Z",
  "status": "Investigating",
  "analyst": "A. Rao",
  "conf": 94,
  "ai_analysis": "Pattern is consistent with brute force activity originating from 185.45.103.91. Correlated with 6 related flows in the last hour.",
  "recommended_actions": "Enforce account lockout, require MFA, block source range at the perimeter.",
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110.001",
    "technique_name": "Password Guessing"
  },
  "timeline": [
    {
      "from_status": null,
      "to_status": "New",
      "user": "System (ML Engine)",
      "timestamp": "2026-11-23T15:20:00Z"
    },
    {
      "from_status": "New",
      "to_status": "Investigating",
      "user": "A. Rao",
      "timestamp": "2026-11-23T15:25:00Z"
    }
  ]
}
```

#### `PATCH /api/v1/incidents/{id}/status`
Executes an incident state transition invoked by the modal workflow stepper (`setSt(id, s)`).

* **Request Body**:
```json
{
  "status": "Contained",
  "notes": "Source IP 185.45.103.91 blacklisted on edge gateway; active sessions dropped."
}
```
* **Response `200 OK`**:
```json
{
  "id": "INC-2041",
  "status": "Contained",
  "updated_at": "2026-11-23T15:35:10Z",
  "updated_by": "A. Rao"
}
```

---

### 3.3 Security Events Stream (`/api/v1/events`)

#### `GET /api/v1/events`
Returns recent raw security event detections for the live feed (`API.events()`).

* **Query Parameters**:
  - `limit` (integer, default: 25, max: 100)
  - `severity` (string, optional): `Critical`, `High`, `Medium`, `Low`
* **Response `200 OK`**:
```json
[
  {
    "id": 10842,
    "t": "2026-11-23T15:38:12Z",
    "src": "194.26.29.112",
    "dst": "10.0.2.45",
    "type": "Malware Communication",
    "sev": "Critical",
    "by": "Threat intel match"
  },
  {
    "id": 10841,
    "t": "2026-11-23T15:38:09Z",
    "src": "23.106.56.201",
    "dst": "10.0.0.12",
    "type": "Port Scanning",
    "sev": "High",
    "by": "Signature rule"
  }
]
```

---

### 3.4 Operational Monitoring (`/api/v1/monitoring`)

#### `GET /api/v1/monitoring/traffic/history`
Returns historical bandwidth records to initialize the 40-point `tIn` and `tOut` arrays.

* **Response `200 OK`**:
```json
{
  "interval_seconds": 1.5,
  "samples": 40,
  "inbound_mbps": [42.1, 45.3, 49.0, 52.4, 48.1, 44.2, 50.8, 55.1, 62.3, 58.7, 43.1, 47.9],
  "outbound_mbps": [21.0, 22.4, 25.1, 23.8, 20.9, 24.3, 27.0, 31.2, 28.5, 22.1, 20.4, 23.8]
}
```

#### `GET /api/v1/monitoring/topology`
Returns the operational perimeter map topology rendered in the `#net` SVG component.

* **Response `200 OK`**:
```json
{
  "center_node": {
    "name": "SOC Core",
    "role": "hub",
    "status": "online"
  },
  "nodes": [
    { "id": 0, "name": "bastion-01", "ip": "10.0.0.10", "bad": false, "latency_ms": 4.2 },
    { "id": 1, "name": "gateway-edge", "ip": "10.0.0.1", "bad": false, "latency_ms": 2.1 },
    { "id": 2, "name": "dmz-web-01", "ip": "10.0.1.13", "bad": true, "latency_ms": 18.5 },
    { "id": 3, "name": "finance-db", "ip": "10.0.2.5", "bad": false, "latency_ms": 3.8 },
    { "id": 4, "name": "ad-domain-ctrl", "ip": "10.0.0.2", "bad": false, "latency_ms": 1.9 },
    { "id": 5, "name": "workstation-vlan", "ip": "10.0.3.99", "bad": true, "latency_ms": 24.2 },
    { "id": 6, "name": "api-proxy", "ip": "10.0.1.50", "bad": false, "latency_ms": 5.1 },
    { "id": 7, "name": "backup-nas", "ip": "10.0.2.100", "bad": false, "latency_ms": 6.4 }
  ]
}
```

#### `GET /api/v1/monitoring/health`
Returns health check diagnostics for the 5 dashboard subsystems.

* **Response `200 OK`**:
```json
[
  { "name": "Network monitoring", "latency_ms": 12, "status": "Healthy" },
  { "name": "ML detection engine", "latency_ms": 38, "status": "Healthy" },
  { "name": "AI investigation engine", "latency_ms": 210, "status": "Healthy" },
  { "name": "Threat intelligence", "latency_ms": 640, "status": "Degraded", "notes": "Upstream rate limit reached; using local cache" },
  { "name": "Database connection", "latency_ms": 4, "status": "Healthy" }
]
```

---

### 3.5 Analytics & Executive KPIs (`/api/v1/analytics`)

#### `GET /api/v1/analytics/kpis`
Returns the 6 primary dashboard metric cards with trend percentages and sparkline data arrays.

* **Query Parameters**:
  - `range` (string, required): `24h` (0), `7d` (1), `30d` (2).
* **Response `200 OK`**:
```json
{
  "range": "24h",
  "kpis": [
    {
      "key": "total_events",
      "label": "Total security events",
      "value": "48,213",
      "delta_percent": 12.4,
      "is_increase": true,
      "color": "#37BDF8",
      "sparkline": [3.2, 4.1, 5.0, 4.6, 6.2, 5.8, 7.1, 6.4, 5.9, 7.8, 8.2, 9.1]
    },
    {
      "key": "active_threats",
      "label": "Active threats",
      "value": 7,
      "delta_percent": 8.1,
      "is_increase": true,
      "color": "#FFB547",
      "sparkline": [2.1, 3.0, 2.8, 3.5, 4.0, 3.9, 4.5, 5.2, 4.8, 5.9, 6.1, 7.0]
    },
    {
      "key": "critical_incidents",
      "label": "Critical incidents",
      "value": 2,
      "delta_percent": 3.2,
      "is_increase": true,
      "color": "#FF4D5E",
      "sparkline": [1.0, 1.2, 0.9, 1.4, 1.8, 1.5, 2.0, 2.1, 1.9, 2.3, 2.0, 2.0]
    },
    {
      "key": "threats_blocked",
      "label": "Threats blocked",
      "value": "12,904",
      "delta_percent": 5.7,
      "is_increase": false,
      "color": "#39E6A3",
      "sparkline": [4.1, 4.8, 5.2, 5.0, 4.9, 5.4, 5.1, 4.8, 4.5, 4.3, 4.2, 4.1]
    },
    {
      "key": "network_anomalies",
      "label": "Network anomalies",
      "value": 37,
      "delta_percent": 9.3,
      "is_increase": false,
      "color": "#37BDF8",
      "sparkline": [3.4, 4.0, 4.5, 4.2, 3.8, 3.6, 3.5, 3.2, 3.0, 2.8, 2.6, 2.5]
    },
    {
      "key": "posture_score",
      "label": "Posture score",
      "value": "87/100",
      "delta_percent": 2.1,
      "is_increase": false,
      "color": "#39E6A3",
      "sparkline": [6.1, 6.0, 6.2, 6.4, 6.5, 6.7, 6.8, 7.0, 7.1, 7.2, 7.4, 7.5]
    }
  ]
}
```

#### `GET /api/v1/analytics/timeline`
Provides multi-series historical data points for the `Security events timeline` SVG area chart.

* **Query Parameters**: `range` (`24h`, `7d`, `30d`)
* **Response `200 OK`**:
```json
{
  "timestamps": ["00:00", "02:00", "04:00", "06:00", "08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00"],
  "series": {
    "total": [45, 52, 48, 65, 80, 95, 110, 105, 98, 88, 76, 62],
    "high": [12, 15, 14, 22, 28, 34, 40, 38, 35, 30, 25, 20],
    "critical": [2, 3, 1, 5, 8, 10, 12, 11, 9, 7, 5, 3]
  }
}
```

#### `GET /api/v1/analytics/distribution/types`
Returns categorical counts driving the `Threat distribution` donut chart.

* **Response `200 OK`**:
```json
[
  { "type": "Brute Force", "count": 5, "color": "#FF4D5E" },
  { "type": "Port Scanning", "count": 4, "color": "#FFB547" },
  { "type": "DDoS", "count": 3, "color": "#37BDF8" },
  { "type": "Malware Communication", "count": 3, "color": "#39E6A3" },
  { "type": "Suspicious Traffic", "count": 2, "color": "#8795A8" }
]
```

---

### 3.6 AI Security Analyst & Investigations (`/api/v1/investigations`)

#### `POST /api/v1/investigations/chat`
Submits a query to the autonomous AI analyst. Returns a Server-Sent Events (SSE) stream delivering markdown tokens in real time, followed by the structured investigation report.

* **Request Body**:
```json
{
  "investigation_id": "optional-uuid-to-continue-session",
  "prompt": "Investigate the latest critical threat",
  "incident_id": "INC-2041"
}
```

* **SSE Streaming Protocol (`text/event-stream`)**:
```
event: token
data: {"token": "1. Threat "}

event: token
data: {"token": "summary\nINC-2041: "}

event: token
data: {"token": "SSH credential stuffing against bastion host...\n\n"}

event: structured_report
data: {
  "incident_id": "INC-2041",
  "severity": "Critical",
  "confidence": 94,
  "sections": [
    ["Threat summary", "INC-2041: SSH credential stuffing against bastion host."],
    ["Severity assessment", "Critical with 94% model confidence."],
    ["Evidence", "Source 185.45.103.91 to 10.0.0.10; flagged by behavioural baseline and signature match."],
    ["Possible attack technique", "Brute Force, consistent with MITRE ATT&CK credential access (T1110)."],
    ["Potential impact", "Credential compromise or service degradation if left unmitigated."],
    ["Recommended defensive actions", "Block the source at the perimeter, force credential resets on targeted accounts, raise logging on the affected segment."]
  ],
  "evidence_card": {
    "incident_id": "INC-2041",
    "source": "185.45.103.91",
    "target": "10.0.0.10",
    "technique": "Brute Force",
    "status": "Investigating",
    "confidence": 94
  }
}

event: done
data: {"status": "complete"}
```

#### `GET /api/v1/investigations`
Fetches the operator's previous investigation history (`hist`).

* **Response `200 OK`**:
```json
[
  {
    "id": "e4b1c2a0-9d8f-4312-87a1-23456789abcd",
    "title": "Investigate the latest critical threat",
    "incident_id": "INC-2041",
    "created_at": "2026-11-23T15:22:00Z"
  },
  {
    "id": "f5c2d3b1-0e9a-5423-98b2-34567890bcde",
    "title": "Analyze a brute-force attack",
    "incident_id": "INC-2046",
    "created_at": "2026-11-23T14:10:00Z"
  }
]
```

---

### 3.7 Reporting & Export (`/api/v1/reports`)

#### `GET /api/v1/reports/incidents/export`
Generates a downloadable CSV or JSON export directly supporting the frontend's `exportCsv()` action.

* **Query Parameters**:
  - `format` (string, required): `csv` or `json`.
  - `severity` (string, optional): `All`, `Critical`, `High`, `Medium`, `Low`.
  - `status` (string, optional): Filter by status.
* **Response `200 OK`**:
  - `Content-Type`: `text/csv`
  - `Content-Disposition`: `attachment; filename="aegissoc-incidents.csv"`
```csv
id,title,type,severity,status
INC-2041,"SSH credential stuffing against bastion host",Brute Force,Critical,Investigating
INC-2042,"Horizontal port sweep on DMZ subnet",Port Scanning,High,New
INC-2043,"Volumetric UDP flood on API gateway",DDoS,High,Investigating
INC-2044,"Beaconing to known C2 domain from endpoint",Malware Communication,Critical,Contained
INC-2045,"Anomalous outbound transfer to unknown ASN",Suspicious Traffic,Medium,New
```

---

## 4. WebSocket Real-Time Protocols

WebSocket connections are authenticated via a short-lived token passed in the connection query parameter (`?token=<JWT_TOKEN>`).

### 4.1 Throughput Feed: `/api/v1/ws/traffic`
* **Broadcast Frequency**: Every 1,500ms (1.5 seconds)
* **Payload Format**:
```json
{
  "type": "traffic_tick",
  "timestamp": 1795454400,
  "inbound_mbps": 54.82,
  "outbound_mbps": 26.15,
  "anomalous_flow_count": 2
}
```

### 4.2 Threat Feed: `/api/v1/ws/events`
* **Broadcast Frequency**: Emitted upon every event detection (averaging every 3.5 seconds)
* **Payload Format**:
```json
{
  "type": "security_event",
  "event": {
    "t": "2026-11-23T15:39:04Z",
    "src": "194.26.29.112",
    "dst": "10.0.2.88",
    "type": "Suspicious Traffic",
    "sev": "Medium",
    "by": "ML anomaly model"
  }
}
```

### 4.3 Subsystem Health Feed: `/api/v1/ws/health`
* **Broadcast Frequency**: Every 5,000ms (5 seconds)
* **Payload Format**:
```json
{
  "type": "health_tick",
  "subsystems": [
    { "name": "Network monitoring", "latency_ms": 11.4, "status": "Healthy" },
    { "name": "ML detection engine", "latency_ms": 36.8, "status": "Healthy" },
    { "name": "AI investigation engine", "latency_ms": 204.0, "status": "Healthy" },
    { "name": "Threat intelligence", "latency_ms": 612.5, "status": "Degraded" },
    { "name": "Database connection", "latency_ms": 3.9, "status": "Healthy" }
  ]
}
```

---

## 5. Standard Error Responses (RFC 7807)

All non-2xx responses adhere to the standard `application/problem+json` format:

```json
{
  "type": "https://errors.soc.aegis.internal/validation-error",
  "title": "Validation Error",
  "status": 422,
  "detail": "Invalid IPv4 address format provided in 'src'.",
  "instance": "/api/v1/incidents",
  "errors": [
    {
      "loc": ["body", "src"],
      "msg": "value is not a valid IPv4 address",
      "type": "value_error.ipv4address"
    }
  ]
}
```
