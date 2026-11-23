# AegisSOC – Autonomous AI Cybersecurity Operations Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-72%20Passed-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/Coverage-82%25-green.svg)]()

AegisSOC is an enterprise-grade autonomous AI cybersecurity operations platform. It combines high-throughput network packet telemetry, real-time ML anomaly detection, grounded LLM security analysis, multi-source threat intelligence enrichment, and human-in-the-loop incident response automation into a unified operational console.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │    AegisSOC React Frontend Console    │
                      │  (Perimeter Map, Feed, Triage, AI UI) │
                      └──────────────────┬────────────────────┘
                                         │
                   HTTP REST / JSON      │      WebSocket (/ws/monitoring)
              (Auth, Incidents, Reports) │     (Traffic Ticks, Live Alerts)
                                         │
                                         ▼
                      ┌───────────────────────────────────────┐
                      │        FastAPI Backend Engine         │
                      │ ───────────────────────────────────── │
                      │ • Rate Limiting & RFC 7807 Errors     │
                      │ • RBAC: Admin, Analyst, Viewer        │
                      │ • Event Ring Buffer & Replay Manager  │
                      └───────┬──────────┬───────────┬────────┘
                              │          │           │
           ┌──────────────────┘          │           └──────────────────┐
           ▼                             ▼                              ▼
┌────────────────────┐        ┌────────────────────┐        ┌────────────────────┐
│ Network & ML Engine│        │ Threat Intel Engine│        │  AI SecOps Analyst │
│ ────────────────── │        │ ────────────────── │        │ ────────────────── │
│ • Scapy Ingestion  │        │ • VirusTotal API   │        │ • MITRE 7-Section  │
│ • Flow Aggregator  │        │ • AbuseIPDB API    │        │ • Prompt Guardrail │
│ • Heuristic Models │        │ • TTL LRU Cache    │        │ • DB Grounding     │
└────────────────────┘        └────────────────────┘        └────────────────────┘
           │                             │                              │
           └─────────────────────────────┼──────────────────────────────┘
                                         ▼
                      ┌───────────────────────────────────────┐
                      │      PostgreSQL 16 Storage Layer      │
                      │  (Incidents, Evidence, Audit, Users)  │
                      └───────────────────────────────────────┘
```

---

## Key Capabilities

- **Real-Time Network Telemetry**: Live packet capture via Scapy or offline PCAP file parsing with bi-directional flow feature extraction.
- **Bi-Directional WebSocket Streaming**: Monotonic sequence-buffered WebSocket endpoint (`WS /ws/monitoring`) streaming traffic throughput ticks (1.5s interval) and security alert feeds with reconnection event replay.
- **Explainable ML Anomaly Scoring**: Deterministic heuristic risk scoring evaluating destination port sensitivity, connection frequency, and byte entropy without stochastic jitter.
- **Grounded AI Security Analyst**: Multi-provider LLM integration (Google Gemini, OpenAI, Anthropic, Ollama) generating structured 7-section MITRE investigations grounded strictly in actual database evidence.
- **Approval-First Defensive Response**: Controlled containment workflows (quarantine planning, firewall review, account lock) starting in simulation mode and requiring explicit human authorization before live execution.
- **Enterprise RBAC**: Role-based access control strictly separating `Admin`, `Security Analyst`, and `Viewer` privileges.
- **Hardened Security Baseline**: Built-in sliding-window rate limiting, strict PCAP magic-byte/size validation, bcrypt password hashing, and parameterized SQLAlchemy queries.

---

## Quickstart with Docker Compose

To deploy the complete AegisSOC backend with PostgreSQL in one command:

```bash
# 1. Clone repository
git clone https://github.com/your-org/aegissoc.git
cd aegissoc

# 2. Configure environment variables
cp .env.example .env

# 3. Launch database and backend
docker compose up -d --build

# 4. Verify health
curl -f http://localhost:8000/health
```

The API documentation will be available immediately at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

---

## Documentation Links

- [DEPLOYMENT.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/DEPLOYMENT.md) – Docker infrastructure, hosting setup, Nginx reverse proxy, and monitoring.
- [BACKEND_SETUP.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/BACKEND_SETUP.md) – Local Python development, virtual environments, migrations, and test execution.
- [API_DOCUMENTATION.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/API_DOCUMENTATION.md) – Complete REST and WebSocket endpoint specifications.
- [SECURITY_NOTES.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/SECURITY_NOTES.md) – Threat modeling, OWASP Top 10 defenses, and production hardening checklist.
- [SECURITY_AUDIT_REPORT.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/SECURITY_AUDIT_REPORT.md) – Automated test results and vulnerability analysis report.
- [FRONTEND_INTEGRATION_GUIDE.md](file:///c:/Users/Akshay/Downloads/AegisSOC%20–%20Autonomous%20AI%20Cybersecurity%20Operations%20Platform/FRONTEND_INTEGRATION_GUIDE.md) – Integration contracts for Claude's React frontend.

---

## Automated Test Suite

AegisSOC includes 72 automated test cases with 82% code coverage:

```bash
# Run full test suite
python -m pytest backend/tests/ -v

# Run with test coverage report
python -m pytest backend/tests/ --cov=app --cov-report=term-missing
```

---

## License

Enterprise Proprietary - AegisSOC Operations Platform.
