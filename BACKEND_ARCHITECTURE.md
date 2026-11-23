# AegisSOC — Backend Architecture Specification

## 1. Executive Summary

AegisSOC is an Autonomous AI-driven Cybersecurity Operations Platform designed to ingest high-velocity network telemetry, detect anomalous and signature-based threats using machine learning, orchestrate autonomous security investigations via Large Language Models (LLMs), and manage the full incident lifecycle from initial detection to containment and resolution.

This document outlines the architectural blueprint for the **modular FastAPI backend**, engineered to provide high-concurrency event ingestion, sub-millisecond threat routing, deterministic incident state management, and real-time bidirectional telemetry streaming for the AegisSOC operations dashboard.

---

## 2. Architectural Principles & Patterns

The AegisSOC backend is designed around the following core architectural paradigms:

1. **Clean / Hexagonal Architecture (Ports and Adapters)**:
   - Core domain logic (incident management, threat scoring, investigation orchestration) is completely decoupled from external adapters (PostgreSQL, Redis, LLM providers, network probes).
   - Interfaces define strict boundaries, allowing threat intelligence providers and AI engines to be swapped or mocked without touching business rules.

2. **Asynchronous Non-Blocking I/O**:
   - Built on **Python 3.11+** and **FastAPI** on top of `uvicorn` and `asyncio`.
   - All database operations utilize asynchronous SQLAlchemy 2.0 with `asyncpg`.
   - Caching, pub/sub, and rate limiting utilize asynchronous Redis (`redis-py`).

3. **Event-Driven Microservices-Ready Monolith (Modular Monolith)**:
   - Developed as a unified deployable codebase structured into strictly isolated internal domain services.
   - Services communicate via internal typed Python interfaces and asynchronous domain events published over an in-memory or Redis-backed message bus.
   - Clear separation ensures zero cyclic dependencies and allows seamless extraction into independent microservices (e.g., containerized ML inference worker, distributed ingest workers) as throughput scales.

4. **Multi-Protocol Real-Time Delivery**:
   - RESTful JSON APIs for synchronous queries, command execution, and CRUD operations.
   - WebSocket (WS) / Server-Sent Events (SSE) for high-frequency telemetry (traffic throughput, live threat feed, real-time token streaming for AI analyst reports).

---

## 3. High-Level System Architecture

```
                                  +----------------------------------------------------+
                                  |                   AegisSOC Web UI                  |
                                  |           (Single Page App / aegissoc.html)        |
                                  +----------------------------------------------------+
                                             |                               ^
                              REST APIs (HTTP/2, JSON)            WebSockets / SSE (Real-Time)
                                             v                               |
+=======================================================================================================+
|                                  FASTAPI APPLICATION GATEWAY & ROUTER                                 |
|  - CORS & Security Middleware    - JWT Authentication & RBAC       - Rate Limiting (Redis Token Bucket)|
|  - Request Validation (Pydantic) - Compression & Error Handling    - Connection Manager (WS Multiplex) |
+=======================================================================================================+
     |                  |                  |                  |                  |                  |
     v                  v                  v                  v                  v                  v
+----------+      +----------+      +----------+      +----------+      +----------+      +----------+
|  Auth &  |      | Incident |      | Analytics|      |Reporting |      |Monitoring|      |WebSocket |
|  Access  |      |Management|      | Service  |      | Service  |      | Service  |      | Hub / WS |
+----------+      +----------+      +----------+      +----------+      +----------+      +----------+
     |                  |                  |                  |               |                 |
     |                  +------------------+------------------+               |                 |
     |                                     |                                  v                 |
     |                                     |                         +-----------------+        |
     |                                     |                         | Threat Ingest & |        |
     |                                     |                         | Stream Consumer |        |
     |                                     |                         +-----------------+        |
     |                                     |                                  |                 |
     |                                     |         +------------------------+                 |
     |                                     |         |                        |                 |
     |                                     v         v                        v                 |
     |                              +--------------------+           +--------------------+     |
     |                              | Threat Detection   |<--------->| ML Inference       |     |
     |                              | Engine (Rules/Sig) |           | Engine (Anomalies) |     |
     |                              +--------------------+           +--------------------+     |
     |                                        |                                                 |
     |                                        v                                                 |
     |                              +--------------------+           +--------------------+     |
     |                              | AI Investigation   |<--------->| Threat Intelligence|     |
     |                              | Service (LLM / RAG)|           | Service (Enrichment|     |
     |                              +--------------------+           +--------------------+     |
     |                                        |                                                 |
     +----------------------------------------+-------------------------------------------------+
                                              |
                   +--------------------------+--------------------------+
                   v                                                     v
+------------------------------------+               +--------------------------------------+
|       PostgreSQL 16 (Primary DB)    |               |          Redis 7 (Cache & Pub/Sub)    |
| - Users, Roles & API Keys          |               | - Real-time Ingest Queues            |
| - Incidents & Timelines            |               | - WebSocket Broadcast Channel        |
| - Security Events & Audit Logs     |               | - Session & Rate Limit Stores        |
| - AI Investigation Transcripts     |               | - Threat Intel Cache (TTL 24h)       |
+------------------------------------+               +--------------------------------------+
```

---

## 4. Modular Service Specifications

The backend is composed of ten core services, each encapsulated within its own module:

### 4.1 Authentication & Access Control Service (`auth_service`)
* **Role**: Manages operator identities, credentials, role-based authorization, and sensor API keys.
* **Key Responsibilities**:
  - User registration, login, and token exchange.
  - Password hashing using Argon2id (`passlib` / `argon2-cffi`).
  - Issuance of short-lived signed JWT access tokens (15 minutes) and cryptographically secure refresh tokens (7 days) with rotation.
  - Role-Based Access Control (RBAC) enforcement across 4 tiers: `Admin`, `SOC Lead`, `Security Analyst (L1/L2)`, and `Read-Only Auditor`.
  - Machine-to-machine API key management with SHA-256 hashing for external telemetry forwarders and sensors.
  - Comprehensive authentication audit trail (logins, logouts, failed attempts).

### 4.2 Monitoring & Telemetry Service (`monitoring_service`)
* **Role**: Ingests, processes, and queries operational network metrics and topology states.
* **Key Responsibilities**:
  - Ingestion of network flow records (`NetFlow v9`, `IPFIX`, or synthetic network probes).
  - Continuous calculation of aggregate throughput (inbound Mbps, outbound Mbps, packets/sec, dropped packets).
  - Maintenance of the 8-node perimeter/DMZ/internal topology map state, tracking node health and compromise flags (`bad: true`).
  - Real-time latency tracking and health checking for all internal subsystems:
    - Network monitoring collector (target: < 20ms)
    - ML detection engine (target: < 50ms)
    - AI investigation engine (target: < 300ms)
    - Threat intelligence feeds (target: < 800ms)
    - PostgreSQL connection pool (target: < 10ms)

### 4.3 Machine Learning Inference Service (`ml_service`)
* **Role**: Executes unsupervised and supervised anomaly detection on high-dimensional network flow data.
* **Key Responsibilities**:
  - Feature extraction from sliding flow windows (entropy of source/dest ports, byte ratios, packet velocity, inter-arrival time distributions).
  - Anomaly scoring via an ensemble model:
    - **Isolation Forest**: Identifies rare multidimensional outliers in traffic patterns.
    - **Autoencoder (ONNX Runtime)**: Reconstructs normal traffic baselines; high reconstruction error indicates novel zero-day behaviors.
    - **Random Forest / XGBoost**: Classifies specific attack signatures (Brute Force, Port Scanning, DDoS, Beaconing).
  - Emits normalized threat confidence scores (0% to 100%) and attribution labels.
  - Logs inference performance and model drift metrics.

### 4.4 Threat Detection Service (`detection_service`)
* **Role**: Synthesizes rule-based signatures, ML anomaly flags, and behavioral baselines into actionable security detections.
* **Key Responsibilities**:
  - Multi-vector correlation pipeline:
    - **Signature Rule Engine**: High-speed matching of known indicators, malicious regexes, and policy violations.
    - **Behavioral Baseline Engine**: Evaluates current host/subnet metrics against 7-day rolling baselines (e.g., unusual midnight outbound volume).
    - **ML Anomaly Correlator**: Links multiple low-confidence anomalous events across time into a single high-confidence detection.
  - Event severity assignment (`Critical`, `High`, `Medium`, `Low`) according to CVSSv3.1 and internal asset criticality weights.
  - Deduplication and event throttling to eliminate alert storms.
  - Auto-triggers incident promotion when threshold criteria are satisfied.

### 4.5 AI Investigation Service (`investigation_service`)
* **Role**: Powers the interactive AI Security Analyst, generating automated technical threat narratives, MITRE ATT&CK mapping, and remediation playbooks.
* **Key Responsibilities**:
  - Multi-turn conversation management with persistent investigation history (`hist`).
  - Context-aware Prompt Engineering: Injects real incident parameters, correlated event records, and target asset metadata into system instructions.
  - Structured Investigation Generation:
    1. **Threat Summary**: Executive briefing of what occurred and key assets involved.
    2. **Severity Assessment**: Deep-dive into model confidence, blast radius, and risk factors.
    3. **Evidence Synthesis**: Correlated IPs, timestamps, protocol signatures, and detection mechanisms.
    4. **MITRE ATT&CK Mapping**: Identification of tactics/techniques (e.g., Credential Access `TA0006`, Reconnaissance `TA0043`).
    5. **Potential Impact**: Impact assessment on business operations and confidentiality/integrity.
    6. **Defensive Actions**: Ordered, actionable mitigation steps (firewall rules, credential revokes, endpoint isolation).
  - Real-time token streaming via Server-Sent Events (SSE) or WebSockets with simulated or real LLM streaming.
  - Deterministic fallback generation in offline / air-gapped environments.

### 4.6 Incident Management Service (`incident_service`)
* **Role**: Serves as the central SOC workflow engine for tracking, assignment, state transitions, and auditing.
* **Key Responsibilities**:
  - Strict Finite State Machine (FSM):
    `New` ➔ `Investigating` ➔ `Contained` ➔ `Resolved`
  - Reversible and non-destructive status updates (`setSt(id, s)`).
  - Analyst ownership assignment and load balancing (`A. Rao`, `M. Iyer`, `S. Khan`, `P. Nair`).
  - Filterable, searchable, and sortable incident repository with sub-second response times across large archives.
  - Incident timeline recording: Every status transition, analyst comment, and containment action is permanently audited with user identity and timestamp.

### 4.7 Threat Intelligence Service (`threat_intel_service`)
* **Role**: Enriches indicators of compromise (IoCs) with global reputation, ASN context, and geolocation.
* **Key Responsibilities**:
  - Real-time IP and domain reputation lookups.
  - Multi-provider aggregator (AlienVault OTX, VirusTotal, AbuseIPDB, local MISP/STIX-TAXII feeds).
  - Two-tier caching strategy: In-memory L1 cache + Redis L2 cache with 24-hour TTL to respect upstream API rate limits.
  - Autonomous classification of C2 domains, known botnet IP subnets, and foreign geolocation anomalies.

### 4.8 Analytics & Metrics Service (`analytics_service`)
* **Role**: Computes aggregate SOC performance indicators, posture scores, and historical trends for the executive dashboard.
* **Key Responsibilities**:
  - Real-time KPI computations:
    - Total security events (with percentage delta vs. previous time window).
    - Active (unresolved) threats.
    - Critical incidents count.
    - Threats autonomously blocked.
    - Network anomaly counts.
    - Overall Security Posture Score (0–100 algorithm factoring open criticals, mean time to detect/respond, and patch state).
  - Aggregated timeline series for 24-hour, 7-day, and 30-day timeframes broken down by severity.
  - Attack type distribution calculation for categorical donut charts.
  - Severity distribution breakdowns.

### 4.9 Reporting Service (`reporting_service`)
* **Role**: Generates structured, exportable compliance and operational security reports.
* **Key Responsibilities**:
  - Instant CSV export of incidents matching active filters (`id,title,type,severity,status`).
  - Executive PDF summary report generator (incident breakdown, posture trend, analyst performance).
  - Technical JSON bundle export for external SIEM/SOAR ingestion.
  - Scheduled automated report generation and email dispatch.

### 4.10 WebSocket Service (`websocket_service`)
* **Role**: Manages persistent client connections and multiplexes real-time push streams.
* **Key Responsibilities**:
  - High-performance `ConnectionManager` handling client disconnects, reconnects, and heartbeat pings.
  - Channel subscription architecture:
    - `/api/v1/ws/traffic`: Sub-second inbound/outbound Mbps telemetry and topology updates.
    - `/api/v1/ws/events`: Live threat feed event stream with severity badges.
    - `/api/v1/ws/health`: Subsystem latency and operational status heartbeats.
    - `/api/v1/ws/investigations/{id}`: Interactive token streaming for AI analyst reports.
  - Redis Pub/Sub integration enabling seamless horizontal scaling across multiple backend worker processes.

---

## 5. End-to-End Ingestion & Processing Pipeline

```
[ Network Traffic / Syslog / Telemetry Agent ]
                       |
                       v
         [ 1. Ingestion Endpoint / Buffer ]
                       |
                       v
         [ 2. Pydantic Event Sanitization ]
                       |
        +--------------+--------------+
        |                             |
        v                             v
[ 3. Rule Signature Engine ]   [ 4. ML Feature Extractor ]
        |                             |
        |                             v
        |                     [ 5. ONNX / Isolation Forest ]
        |                             |
        +--------------+--------------+
                       |
                       v
       [ 6. Threat Correlation Engine ]
                       |
            (Threat Detected?)
             /              \
          [No]             [Yes]
           /                  \
          v                    v
[ Store In Telemetry ]   [ 7. Threat Intel Enrichment ]
                               |
                               v
                         [ 8. Create Incident (Status: New) ]
                               |
                               +-----------------------------+
                               |                             |
                               v                             v
                    [ 9. Broadcast via WS ]      [ 10. AI Autonomous Pre-Triage ]
```

---

## 6. Project Directory Structure

```
AegisSOC/
├── frontend/                                # READ-ONLY Claude Frontend
│   └── aegissoc.html
│
├── backend/                                 # Modular FastAPI Backend
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                          # FastAPI Application Entrypoint & Lifespan
│   │   ├── config.py                        # Pydantic BaseSettings & Environment Variables
│   │   │
│   │   ├── core/                            # Cross-Cutting Infrastructure
│   │   │   ├── security.py                  # JWT, Password Hashing, API Key Hashers
│   │   │   ├── database.py                  # Async SQLAlchemy Engine & SessionLocal
│   │   │   ├── redis.py                     # Redis Client & Pub/Sub Wrappers
│   │   │   ├── exceptions.py                # Global Exception Handlers & RFC7807 Errors
│   │   │   └── logging.py                   # Structured JSON Logging
│   │   │
│   │   ├── models/                          # SQLAlchemy ORM Models
│   │   │   ├── user.py                      # User, Role, RefreshToken, APIKey
│   │   │   ├── incident.py                  # Incident, IncidentTimeline, IncidentComment
│   │   │   ├── event.py                     # SecurityEvent, FlowRecord
│   │   │   ├── telemetry.py                 # NetworkMetric, SystemHealthLog
│   │   │   ├── investigation.py             # Investigation, InvestigationMessage
│   │   │   └── threat_intel.py              # ThreatIntelCache
│   │   │
│   │   ├── schemas/                         # Pydantic v2 Request/Response DTOs
│   │   │   ├── auth.py
│   │   │   ├── incident.py
│   │   │   ├── event.py
│   │   │   ├── telemetry.py
│   │   │   ├── analytics.py
│   │   │   ├── investigation.py
│   │   │   └── reporting.py
│   │   │
│   │   ├── services/                        # Business Logic (The 10 Domain Services)
│   │   │   ├── auth_service.py              # User Auth & RBAC
│   │   │   ├── monitoring_service.py        # Telemetry Aggregation & Health
│   │   │   ├── ml_service.py                # Anomaly Models & ONNX Runtime
│   │   │   ├── detection_service.py         # Signature & Behavioral Engine
│   │   │   ├── investigation_service.py     # AI LLM Orchestration & Prompts
│   │   │   ├── incident_service.py          # State Machine & Incident CRUD
│   │   │   ├── threat_intel_service.py      # IP Reputation & ASN Enrichment
│   │   │   ├── analytics_service.py         # KPIs & Time-Series Aggregates
│   │   │   ├── reporting_service.py         # CSV & PDF Report Generators
│   │   │   └── websocket_service.py         # ConnectionManager & PubSub Hub
│   │   │
│   │   ├── api/                             # API Presentation Layer
│   │   │   ├── deps.py                      # FastAPI Dependency Injection (DB, Auth)
│   │   │   └── v1/
│   │   │       ├── api_router.py            # Aggregates V1 Routers
│   │   │       ├── endpoints/
│   │   │       │   ├── auth.py
│   │   │       │   ├── monitoring.py
│   │   │       │   ├── incidents.py
│   │   │       │   ├── events.py
│   │   │       │   ├── investigation.py
│   │   │       │   ├── analytics.py
│   │   │       │   ├── reports.py
│   │   │       │   └── websockets.py
│   │   │
│   │   └── ml_assets/                       # Pre-Trained Weights & Scalers
│   │       ├── isolation_forest.onnx
│   │       └── feature_scaler.joblib
│   │
│   ├── alembic/                             # Database Migrations
│   │   ├── env.py
│   │   └── versions/
│   ├── tests/                               # Test Suite
│   │   ├── conftest.py
│   │   ├── test_auth.py
│   │   ├── test_incidents.py
│   │   ├── test_analytics.py
│   │   ├── test_investigations.py
│   │   └── test_websockets.py
│   ├── Dockerfile
│   ├── requirements.txt
│   └── alembic.ini
│
├── docker-compose.yml                       # Multi-Container Local Dev Setup
├── BACKEND_ARCHITECTURE.md                 # This Document
├── DATABASE_SCHEMA.md                      # Detailed ERD & Schema Specs
├── API_SPECIFICATION.md                    # Complete OpenAPI 3.1 & Contract Mapping
├── SECURITY_DESIGN.md                      # Security, RBAC & Hardening Specs
└── DEVELOPMENT_STATUS.md                   # Audit, Current State & Execution Plan
```

---

## 7. Scalability & Operational Characteristics

1. **Throughput & Capacity**:
   - Ingestion rate: Capable of ingesting 10,000+ flow records/sec per worker node via asynchronous bulk buffer endpoints.
   - Query latency: Sub-15ms for cached KPI endpoints; sub-30ms for complex filtered incident queries using compound B-Tree and GIN indexes.
   - Concurrent WebSockets: 5,000+ concurrent connections per single Uvicorn instance utilizing `uvloop`.

2. **Resilience & Fault Tolerance**:
   - Circuit breakers implemented around all third-party threat intelligence APIs and external LLM endpoints.
   - If Redis becomes unavailable, the WebSocket manager degrades gracefully to local broadcast mode, and threat intelligence falls back to local database lookups.
   - Database connection pooling managed via SQLAlchemy `AsyncEngine` with `pool_size=20`, `max_overflow=10`, and aggressive recycling (`pool_recycle=300`).
