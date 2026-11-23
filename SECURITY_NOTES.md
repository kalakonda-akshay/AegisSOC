# AegisSOC Security Architecture & Production Hardening Notes

This document outlines the security architecture, threat models, input sanitization policies, and production deployment controls implemented in AegisSOC.

---

## 1. Security Architecture & Principles

AegisSOC is designed according to the principles of **Least Privilege**, **Defense-in-Depth**, **Grounded AI Inference**, and **Human-in-the-Loop Response Authorization**.

```
                [ Untrusted Telemetry / External IOCs ]
                                  │
                                  ▼
                ┌───────────────────────────────────┐
                │   Strict Validation & Sanitizer   │
                │ • Pydantic Schema Bounds          │
                │ • Regex Injection Filter          │
                │ • PCAP Magic Byte & Size Limit    │
                └─────────────────┬─────────────────┘
                                  │
                                  ▼
                ┌───────────────────────────────────┐
                │    RBAC & Rate Limiting Gate      │
                │ • JWT Signature Verification      │
                │ • Token Type Separation           │
                │ • Sliding-Window Throttling       │
                └─────────────────┬─────────────────┘
                                  │
                                  ▼
                ┌───────────────────────────────────┐
                │   Database & Evidence Isolation   │
                │ • Parameterized AST Queries       │
                │ • Strict Audit Trail Logs         │
                └─────────────────┬─────────────────┘
                                  │
                                  ▼
                ┌───────────────────────────────────┐
                │   Defensive Response Controller   │
                │ • Simulation Mode by Default      │
                │ • Explicit Admin Approval Gate    │
                └───────────────────────────────────┘
```

---

## 2. Threat Modeling & OWASP Top 10 Defenses

### 2.1 Injection Attacks (SQLi, Prompt Injection, Command Injection)
- **SQL Injection (CWE-89)**: Neutralized. All database transactions execute via SQLAlchemy Core and ORM AST expressions with parameterized query bindings. Direct string concatenation of SQL commands is prohibited. Sort keys are verified against internal attribute whitelists.
- **Prompt Injection (CWE-77)**: Untrusted network payloads, DNS hostnames, and external threat feeds are processed through `app.ai.sanitizer.SanitizerAndPromptInjectionDefense` before being introduced into LLM system prompts. System override tokens (`SYSTEM:`, `IGNORE PREVIOUS INSTRUCTIONS`, `<|im_start|>`) are stripped and redacted.
- **Command Injection (CWE-78)**: The Scapy network capture and traffic simulation modules invoke internal Python network sockets and Scapy protocol abstractions rather than shell subprocess wrappers (`exec`, `system`).

### 2.2 Broken Authentication & Token Handling (CWE-287 / CWE-384)
- **Password Storage**: Passwords are saved exclusively as bcrypt hashes with 12 salt rounds (4 rounds in debug test mode). Passwords exceeding 72 bytes are rejected to prevent bcrypt truncation collisions.
- **Token Signing**: Access and refresh tokens are signed with HMAC-SHA256 (`HS256`) using a minimum 32-byte secret key.
- **Token Type Isolation**: Refresh tokens require `type == "refresh"`. Presenting an access token to `/api/auth/refresh` results in immediate rejection (HTTP 401).
- **Strict Error Handling**: Expired or tampered tokens explicitly raise HTTP 401 Unauthorized rather than silently falling back to anonymous access.

### 2.3 Broken Access Control & Privilege Escalation (CWE-269 / CWE-862)
- **Role Hierarchy**:
  - `Admin`: Superadmin access to execute defensive response actions, clear intelligence caches, and configure network capture.
  - `Security Analyst`: Triage, update incident status, assign analysts, propose response actions, and run AI investigations.
  - `Viewer`: Read-only access to dashboard KPIs, event feeds, and reports.
- **Self-Registration Defense**: Public registration via `POST /api/auth/register` rejects any attempt to self-assign the `Admin` role with HTTP 400 Bad Request. All public accounts are provisioned as `Viewer` or `Security Analyst`.
- **Response Execution Gate**: Containment actions (`/response/{action_id}/execute`) are restricted strictly to `Admin` users.

### 2.4 Denial of Service & Malicious File Uploads (CWE-434 / CWE-400)
- **PCAP File Validation**: Offline packet analysis (`POST /api/monitoring/pcap/analyze`) enforces:
  - Whitelisted extensions: `.pcap`, `.pcapng`, `.cap`.
  - Magic header byte validation: Verifies PCAP microsecond (`0xd4c3b2a1`, `0xa1b2c3d4`), nanosecond (`0x4d3cb2a1`, `0xa1b23c4d`), or PCAP-NG (`0x0a0d0d0a`) section headers.
  - Maximum upload size: Bounded at **50 MB** via streaming chunk validation (HTTP 413 Payload Too Large).
  - Path traversal defense: Sanitizes temporary storage names via `os.path.basename`.

### 2.5 Sensitive Data Exposure (CWE-598 / CWE-532)
- **Credentials in URLs**: Gemini API credentials are transmitted via `x-goog-api-key` in HTTP headers rather than URL query parameters (`?key=...`).
- **Log Masking**: Request logging middleware records only the HTTP method, endpoint path, status code, process duration, and client IP. Request bodies, authorization headers, and password fields are never printed to log streams.
- **Model Isolation**: User response schemas (`UserResponse`) exclude `hashed_password` and authentication tokens.

### 2.6 Rate Limiting (CWE-307 / CWE-770)
- **Sliding-Window Limiter**: Process-local thread-safe rate limiter throttles rapid brute-force attempts:
  - `/api/auth/login`: 10 requests / minute per client IP.
  - `/api/auth/register`: 5 requests / minute per client IP.
- **Rate Limit Headers**: Returns HTTP 429 Too Many Requests with standard `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers.

---

## 3. Approval-Based Defensive Response Model

To prevent automated denial-of-service or erroneous containment actions:
1. **Simulation Default**: All recommended response actions (e.g. `FIREWALL_RULE_REVIEW`, `ENDPOINT_ISOLATION_PLAN`) start in `PROPOSED` status in `SIMULATION` mode.
2. **Explicit Human Authorization**: No containment action can transition to `EXECUTED` without prior explicit approval recorded in the audit log (`INCIDENT_ACTION_APPROVED`).
3. **No Automatic Firewall Rule Injection**: The system provides dry-run rules and proposed policies; it never automatically modifies external production firewalls without operator oversight.

---

## 4. Production Hardening Checklist

Before deploying AegisSOC to a live production environment, verify the following:

- [ ] **Secret Key**: `SECRET_KEY` is populated with a cryptographically random string (`openssl rand -hex 32`) and loaded via KMS or environment variable.
- [ ] **Database Credentials**: PostgreSQL password is non-default, complex, and uncommitted to source control.
- [ ] **CORS Restrictions**: `CORS_ORIGINS` is restricted strictly to production frontend domains (e.g. `https://soc.company.com`).
- [ ] **TLS / SSL Termination**: All inbound traffic is routed through HTTPS/WSS with TLS 1.2 or 1.3 enforced.
- [ ] **Non-Root Execution**: The backend container runs under the dedicated unprivileged user `aegis` (`UID 10001`).
- [ ] **Network Isolation**: The PostgreSQL container is accessible only within the internal Docker bridge network (`aegis-network`) and its port (5432) is not exposed to the public Internet.
- [ ] **Database Backups**: Automated nightly backups are scheduled with off-site replication and 30-day retention.
- [ ] **Container Log Rotation**: Docker logging driver is configured with `max-size: 20m` and `max-file: 5` to prevent disk exhaustion.
- [ ] **AI Provider Credentials**: API keys for external models (Gemini, OpenAI, Anthropic) and threat feeds (VirusTotal, AbuseIPDB) are restricted with billing caps and minimum necessary scopes.
