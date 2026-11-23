# AegisSOC API Documentation

This document provides complete technical specifications for the AegisSOC REST API and real-time WebSocket telemetry channels.

---

## 1. Overview & Conventions

- **Base URL**: `http://localhost:8000/api`
- **WebSocket Base**: `ws://localhost:8000/ws`
- **Default Content-Type**: `application/json`
- **Interactive OpenAPI Documentation**: `http://localhost:8000/docs`
- **Standard Error Specification**: RFC 7807 Problem Details

### Common HTTP Status Codes
| Code | Meaning | Description |
| :--- | :--- | :--- |
| `200 OK` | Success | Request succeeded. Returns requested entity or telemetry. |
| `201 Created` | Created | Resource successfully created (e.g. incident, report). |
| `400 Bad Request` | Client Error | Malformed request, invalid extension, or invalid parameter. |
| `401 Unauthorized` | Auth Required | Missing, forged, or expired JWT Bearer token. |
| `403 Forbidden` | Access Denied | Authenticated role lacks permission for the requested action. |
| `404 Not Found` | Not Found | Resource or case ID does not exist. |
| `413 Payload Too Large`| Too Large | File upload exceeds 50 MB limit. |
| `422 Unprocessable` | Validation Error| Pydantic payload validation failure. |
| `429 Too Many Requests`| Rate Limited | Request rate limit exceeded; check `Retry-After`. |
| `500 Server Error` | Internal Error | Unhandled server exception. |
| `502 Bad Gateway` | Provider Error | External AI provider or threat intel network failure. |

---

## 2. Authentication & Authorization

All protected endpoints require an `Authorization` header containing a valid JWT Bearer token:
```http
Authorization: Bearer <access_token>
```

### Roles & Access Matrix
- **Admin**: Full platform access (user management, cache purging, response execution).
- **Security Analyst**: Incident triage, AI investigations, evidence uploads, status updates.
- **Viewer**: Read-only dashboard telemetry, incident listing, and compliance reporting.

---

## 3. Endpoints by Domain Group

### 3.1 Authentication (`/api/auth`)

#### `POST /api/auth/login`
Authenticates user credentials and issues signed access and refresh tokens.
- **Rate Limit**: 10 requests / minute
- **Request Body**:
  ```json
  {
    "email": "analyst@soc.aegis.internal",
    "password": "AnalystPass123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "id": "usr-uuid",
      "email": "analyst@soc.aegis.internal",
      "full_name": "A. Rao",
      "role": "Security Analyst",
      "is_active": true
    }
  }
  ```

#### `POST /api/auth/register`
Registers a new SOC analyst or viewer account.
- **Rate Limit**: 5 requests / minute
- **Security Constraint**: Self-registration with `role_name: "Admin"` is blocked.
- **Request Body**:
  ```json
  {
    "email": "new.analyst@soc.aegis.internal",
    "password": "SecurePassword123!",
    "full_name": "Alex Mercer",
    "role_name": "Security Analyst"
  }
  ```
- **Response `201 Created`**: Returns created `UserResponse`.

#### `POST /api/auth/refresh`
Exchanges a valid refresh token for a fresh access token.
- **Request Body**: `{"refresh_token": "eyJhbGciOi..."}`
- **Response `200 OK`**: `{"access_token": "eyJhbGciOi...", "token_type": "bearer"}`

#### `GET /api/auth/me`
Retrieves current profile and role information for the caller.
- **Headers**: `Authorization: Bearer <token>`
- **Response `200 OK`**: Returns `UserResponse`.

---

### 3.2 Dashboard (`/api/dashboard`)

#### `GET /api/dashboard/overview?range=24h`
Returns SOC overview metrics, 6 KPI cards with sparklines, attack timelines, threat distributions, and subsystem health badges.
- **Query Parameters**: `range` (`24h`, `7d`, `30d`)
- **Response `200 OK`**:
  ```json
  {
    "kpis": [
      {
        "key": "total_events",
        "label": "Total security events",
        "value": "48,213",
        "delta_percent": 12.4,
        "is_increase": true,
        "color": "#39E6A3",
        "sparkline": [42.1, 44.5, 43.8, 46.2, 45.0, 47.1, 48.2]
      }
    ],
    "timeline_series": {
      "total": [120, 140, 110, ...],
      "threats": [5, 8, 4, ...],
      "blocked": [40, 52, 38, ...],
      "anomalies": [2, 4, 1, ...]
    },
    "threat_distribution": [
      {"type": "Brute Force", "count": 14, "color": "#FF4D5E"}
    ],
    "system_health": [
      {"name": "Network monitoring", "status": "Healthy", "latency_ms": 12.4}
    ]
  }
  ```

#### `GET /api/dashboard/events?limit=25`
Returns chronological security events for the live monitoring feed (`id`, `t`, `src`, `dst`, `type`, `sev`, `by`).

#### `GET /api/dashboard/metrics`
Returns real-time posture score, active threats, critical incidents count, and bandwidth usage.

---

### 3.3 Network Monitoring (`/api/monitoring`)

#### `GET /api/monitoring/status`
Returns Scapy capture engine state (`running`, `stopped`, `paused`), active interface, packets captured, and active flows.

#### `GET /api/monitoring/traffic`
Returns 40-point historical throughput arrays (`tIn`, `tOut`) formatted for SVG/Canvas area charts.

#### `GET /api/monitoring/topology`
Returns active perimeter node graph (`nodes` with `id`, `name`, `ip`, `role`, `bad`, `status`).

#### `POST /api/monitoring/start`
Starts live network capture on an authorized interface (`require_role(["Admin", "Security Analyst"])`).

#### `POST /api/monitoring/stop`
Stops active live network capture or traffic simulation.

#### `POST /api/monitoring/pcap/analyze`
Ingests an uploaded PCAP file for offline protocol and flow analysis.
- **Security Controls**: Enforces `.pcap`/`.pcapng` extension, magic byte validation, and 50 MB limit.
- **Form Data**: `file` (binary stream).
- **Response `200 OK`**:
  ```json
  {
    "file_name": "capture.pcap",
    "packets_analyzed": 1420,
    "total_bytes": 1258400,
    "flow_count": 84,
    "protocol_distribution": {"TCP": 1100, "UDP": 280, "ICMP": 40},
    "suspicious_connections": [ ... ]
  }
  ```

---

### 3.4 Threat Detection & ML Inference (`/api/threats`)

#### `GET /api/threats?limit=25&severity=High`
Lists recent threat detections matching frontend event feed schema (`id`, `t`, `src`, `dst`, `type`, `sev`, `by`, `conf`).

#### `GET /api/threats/{id}`
Returns full telemetry, flow attributes, and raw payload inspection for an event.

#### `POST /api/threats/analyze`
Runs deterministic ML anomaly inference and threat intelligence correlation on incoming network flow attributes.
- **Request Body**:
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
- **Response `200 OK`**:
  ```json
  {
    "threat_classification": "Brute Force",
    "anomaly_score": 0.82,
    "risk_level": "High",
    "confidence": 82,
    "matched_rules": ["SIG-PORT-02: High-risk administrative port probing"],
    "threat_intel_verdict": "Suspicious",
    "recommended_actions": ["Apply perimeter IP block on 185.220.101.5"],
    "is_malicious": false
  }
  ```

---

### 3.5 Incident Management & Response (`/api/incidents`)

#### `GET /api/incidents?page=1&limit=25&severity=All&status=All&search=`
Returns paginated incident cases (`items`, `total`, `page`, `pages`, `limit`).

#### `POST /api/incidents`
Creates a new security incident case and automatically calculates priority (`P1 - Critical` to `P4 - Low`).
- **Authorization**: `Admin` or `Security Analyst`.

#### `GET /api/incidents/{id}`
Returns incident case file including forensic `evidence`, lifecycle `timeline`, and `response_actions`.

#### `PATCH /api/incidents/{id}`
Applies updates to incident status, analyst assignment, or severity.
- **Allowed Transitions**: `New` $\rightarrow$ `Investigating` $\rightarrow$ `Contained` $\rightarrow$ `Resolved`.
- **Request Body**:
  ```json
  {
    "status": "Contained",
    "analyst_name": "Senior IR Analyst",
    "notes": "VLAN quarantine placed."
  }
  ```

#### `POST /api/incidents/{id}/response/propose`
Proposes an approval-based containment action (`SUSPICIOUS_ACCOUNT_REVIEW`, `ENDPOINT_ISOLATION_PLAN`, `FIREWALL_RULE_REVIEW`, `EVIDENCE_PRESERVATION`).

#### `POST /api/incidents/response/{action_id}/execute`
Executes an approved defensive containment action.
- **Authorization**: Strictly `Admin`-only.
- **Mode**: Starts in `SIMULATION` by default; requires explicit authorization before applying live changes.

---

### 3.6 AI Security Analyst (`/api/ai`)

#### `POST /api/ai/chat` & `POST /api/ai/investigate`
Submits an incident prompt to the AI Security Analyst and generates a structured 7-section MITRE report grounded in actual database evidence.
- **Request Body**:
  ```json
  {
    "incident_id": "INC-2041",
    "message": "Analyze attack techniques and recommend defensive mitigations."
  }
  ```
- **Response `200 OK`**:
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
    "ai_provider": "gemini",
    "model": "gemini-1.5-pro",
    "tokens_used": 1420
  }
  ```

#### `GET /api/ai/history?incident_id=INC-2041`
Retrieves chronological AI conversation history and investigation audit records.

---

### 3.7 Threat Intelligence (`/api/intelligence`)

#### `GET /api/intelligence/ioc?page=1&limit=25&ioc_type=ip`
Lists cached and curated indicators of compromise with reputation scores.

#### `POST /api/intelligence/lookup`
Performs reputation enrichment for an indicator (`ip`, `domain`, `hash`, `url`).
- **Request Body**: `{"indicator": "185.220.101.5", "ioc_type": "ip"}`
- **Response `200 OK`**:
  ```json
  {
    "indicator": "185.220.101.5",
    "indicator_type": "ip",
    "verdict": "Malicious",
    "reputation_score": 94,
    "is_malicious": true,
    "threat_types": ["Tor Exit Node", "Brute Force"],
    "country_code": "DE",
    "last_seen": "2026-11-23T18:00:00Z"
  }
  ```

---

### 3.8 Reporting & Exports (`/api/reports`)

#### `GET /api/reports?limit=20`
Lists generated compliance, executive, and technical threat intelligence reports.

#### `POST /api/reports/generate`
Generates an executive or technical security report on demand and returns a direct download link.

#### `GET /api/reports/incidents/export?format=csv`
Exports incidents in CSV format (`id,title,type,severity,status,source_ip,destination_ip`).

---

## 4. Real-Time WebSocket Channel (`WS /ws/monitoring`)

The primary streaming channel for real-time dashboard visualization.

### Connection Handshake
```
ws://localhost:8000/ws/monitoring?token=<access_token>&last_seq=<optional_id>
```

### Handshake Response Frame
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
1. **Traffic Tick (`TRAFFIC_TICK`)** (every 1.5s):
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

### Client Actions (Inbound over WebSocket)
- **Ping**: Send `{"action": "ping"}` $\rightarrow$ receives `{"type": "pong", "time": "..."}`.
- **Resync**: Send `{"action": "resync", "since_seq_id": 35}` $\rightarrow$ receives `{"type": "RESYNC_DATA", "events": [ ... ]}` from the ring buffer.
