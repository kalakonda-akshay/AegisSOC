# AegisSOC Backend Developer Setup Guide

This guide walks through setting up the AegisSOC backend for local development, debugging, running migrations, and executing automated test suites.

---

## 1. Prerequisites

- **Python**: Version 3.12.x or higher
- **Package Manager**: `pip` or `uv`
- **Database**:
  - Local SQLite (zero-config, default for rapid development)
  - OR PostgreSQL 16+ (for production parity)
- **Optional System Libraries**:
  - `libpcap` (Linux: `apt-get install libpcap-dev`, macOS: `brew install libpcap`, Windows: Npcap for live packet capture)

---

## 2. Environment Setup

### 2.1 Clone the Repository
```bash
git clone https://github.com/your-org/aegissoc.git
cd "aegissoc/backend"
```

### 2.2 Create & Activate Virtual Environment
```bash
# Using Python venv
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
```

### 2.3 Install Dependencies
```bash
# Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install test and development utilities
pip install pytest pytest-asyncio pytest-cov
```

---

## 3. Configuration

Copy the example environment configuration:
```bash
cp .env.example .env
```

Key environment variables in `.env`:
```ini
# Application Mode
APP_NAME="AegisSOC Platform API"
APP_ENV=development
DEBUG=true

# Security Secrets (Must be at least 32 characters in production)
SECRET_KEY=aegissoc_super_secret_jwt_signing_key_at_least_32_chars_long_123456
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=7

# Database Connection
# SQLite (default for development):
DATABASE_URL=sqlite+aiosqlite:///./aegissoc.db
# PostgreSQL (for staging/production):
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/aegissoc

# AI Provider Credentials (Optional: set one provider to enable live LLM features)
DEFAULT_AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
```

---

## 4. Database Initialization & Migrations

### 4.1 Apply Alembic Migrations
```bash
alembic upgrade head
```

### 4.2 Seed Initial Baseline Data
Seed the default organization, user accounts (`Admin`, `Security Analyst`, `Viewer`), baseline incidents, and telemetry:
```bash
python -c "from app.core.database import SessionLocal; from app.utils.seed_data import seed_initial_data; s = SessionLocal(); seed_initial_data(s); s.close(); print('Database seeded successfully.')"
```

### Seeded Default Credentials
| Email | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| `admin@soc.aegis.internal` | `AdminPass123!` | Admin | Superadmin full platform access |
| `a.rao@soc.aegis.internal` | `AnalystPass123!` | Security Analyst | Triage, investigations, containment |
| `v.chen@soc.aegis.internal` | `ViewerPass123!` | Viewer | Read-only compliance auditor |

---

## 5. Running the Application

Start the FastAPI application with live hot-reloading:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

The service will be accessible at:
- **API Base**: `http://localhost:8000`
- **Health Check**: `http://localhost:8000/health`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **Unified WebSocket Stream**: `ws://localhost:8000/ws/monitoring`

---

## 6. Running Automated Tests & Security Audits

Execute the test suites using Pytest:

```bash
# Run all 72 unit, integration, and security audit tests
python -m pytest tests/ -v

# Run the security audit test suite specifically
python -m pytest tests/test_security_audit.py -v

# Run with full statement coverage report
python -m pytest tests/ --cov=app --cov-report=term-missing
```

---

## 7. Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI application factory & router inclusion
│   ├── ai/                  # LLM integrations, prompt templates, sanitizers
│   ├── api/                 # REST API endpoints grouped by domain
│   ├── core/                # Database engine, security, rate limiting, logging
│   ├── intelligence/        # Threat intelligence engine & vendor integrations
│   ├── middleware/          # Request logging & correlation tracking
│   ├── ml/                  # ML anomaly detection models & scoring
│   ├── models/              # SQLAlchemy ORM entity definitions
│   ├── network/             # Scapy packet ingestion & flow analyzers
│   ├── repositories/        # Database access layer
│   ├── schemas/             # Pydantic v2 validation models
│   ├── services/            # Business logic orchestration
│   ├── utils/               # Database seeding & helper routines
│   └── websocket/           # WebSocket connection manager & routes
├── alembic/                 # Database migration versions
├── tests/                   # Automated unit, integration & audit tests
├── Dockerfile               # Production multi-stage Docker build
├── requirements.txt         # Production dependencies
└── alembic.ini              # Alembic configuration
```
