# AegisSOC — Enterprise Security Architecture & Threat Defense Design

## 1. Executive Summary & Security Objectives

AegisSOC is an operational security platform designed to handle mission-critical telemetry, active cyber incident triage, and autonomous AI-assisted remediation. Because the platform itself represents a high-value target for adversaries seeking to blind detection capabilities or execute unauthorized actions, AegisSOC enforces a **Zero Trust Security Architecture**.

### Core Security Objectives
1. **Confidentiality**: Protect proprietary threat signatures, internal network topologies, and sensitive incident investigation data from unauthorized disclosure.
2. **Integrity**: Guarantee that incoming telemetry, incident states, and audit trails cannot be altered or falsified by attackers.
3. **Availability**: Ensure resilient high-throughput ingestion and sub-second dashboard delivery even during distributed volumetric denial-of-service (DDoS) events.
4. **Accountability**: Enforce non-repudiation for every state change, containment order, and analyst action through immutable audit logging.
5. **AI Safety & Guardrails**: Eliminate prompt injection vulnerabilities, hallucinated remediations, and unauthorized autonomous destructive actions.

---

## 2. Threat Modeling (STRIDE Analysis)

A systematic STRIDE threat assessment was conducted across the AegisSOC boundary:

| Threat Category | Potential Attack Vector | AegisSOC Mitigating Control |
| :--- | :--- | :--- |
| **Spoofing** | Adversary injects spoofed NetFlow/telemetry to hide active exfiltration or frame benign nodes. | mTLS and SHA-256 HMAC authentication on ingest pipelines; cryptographic API keys for sensors. |
| **Tampering** | Rogue actor modifies incident severity or drops records from `security_events`. | Strict RBAC; parameterized async queries via SQLAlchemy; database trigger-based append-only audit logs. |
| **Repudiation** | Analyst denies executing an incorrect containment command (e.g., isolating production gateway). | Immutable audit logging recording User ID, IP, user-agent, timestamp, and pre/post state. |
| **Information Disclosure** | Unauthorized user views confidential vulnerability scans and internal IP topologies. | JWT-based RBAC with least-privilege scoping; field-level redaction of internal infrastructure IPs. |
| **Denial of Service** | Alert flooding aimed at exhausting FastAPI worker threads or database connection pools. | Redis-backed token bucket rate limiting; event deduplication buffer; async non-blocking architecture. |
| **Elevation of Privilege** | Analyst L1 attempts to assign admin privileges or reconfigure ML detection thresholds. | Scoped OAuth2 bearer tokens; server-side RBAC dependency injection validation on every endpoint. |

---

## 3. Authentication & Credential Management

### 3.1 Password Hashing Architecture
Passwords are never stored in plaintext. AegisSOC mandates **Argon2id** (`argon2-cffi`), the winner of the Password Hashing Competition (PHC), optimized against GPU-accelerated brute-force attacks:
- **Memory Cost (`m`)**: 65,536 KiB (64 MiB)
- **Time Cost (`t`)**: 3 iterations
- **Parallelism (`p`)**: 4 threads
- **Salt Length**: 16 bytes cryptographically secure random bytes (`os.urandom`)

### 3.2 Token Architecture & Lifecycle
AegisSOC employs a dual-token authentication scheme:
1. **Access Tokens (JWT)**:
   - **Algorithm**: `RS256` (Asymmetric RSA signature) or `HS256` with a high-entropy 256-bit secret.
   - **Lifespan**: 15 minutes (short-lived to minimize exposure window).
   - **Payload Claims**:
     ```json
     {
       "sub": "c7a8b921-8f3a-493e-90f7-111222333444",
       "email": "a.rao@soc.aegis.internal",
       "role": "analyst",
       "scopes": ["incidents:read", "incidents:update_status", "investigations:*"],
       "iat": 1795454000,
       "exp": 1795454900,
       "iss": "aegissoc-auth-service"
     }
     ```
2. **Refresh Tokens**:
   - **Format**: High-entropy 256-bit CSPRNG UUID.
   - **Storage**: Only the SHA-256 hash of the refresh token is stored in PostgreSQL.
   - **Lifespan**: 7 days.
   - **Rotation**: Single-use token rotation. When a refresh token is used, it is revoked and replaced with a new token. Reuse of a revoked token immediately revokes all active sessions for that user (compromise detection).

### 3.3 Sensor API Keys (M2M Authentication)
External syslog agents, Zeek sensors, and network sniffers authenticate via API keys:
- Keys follow the format `aegis_live_<prefix>_<random_secret>`.
- Only the `SHA-256` hash of `<random_secret>` is stored in the database.
- Telemetry ingestion routes validate API keys with constant-time string comparisons (`secrets.compare_digest`) to prevent timing attacks.

---

## 4. Role-Based Access Control (RBAC) & Permissions

### 4.1 RBAC Roles Matrix

| Permission / Action | Admin | SOC Lead | Analyst (L1/L2) | Read-Only Auditor | Telemetry Sensor |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `incidents:read` | Yes | Yes | Yes | Yes | No |
| `incidents:create` | Yes | Yes | Yes (System) | No | No |
| `incidents:update_status` | Yes | Yes | Yes | No | No |
| `incidents:delete` | Yes | No | No | No | No |
| `events:read` | Yes | Yes | Yes | Yes | No |
| `events:ingest` | Yes | No | No | No | Yes |
| `investigations:chat` | Yes | Yes | Yes | No | No |
| `investigations:history`| Yes | Yes | Yes | Yes | No |
| `reports:export_csv` | Yes | Yes | Yes | Yes | No |
| `reports:generate_pdf` | Yes | Yes | No | Yes | No |
| `users:manage` | Yes | No | No | No | No |
| `ml_models:tune` | Yes | Yes | No | No | No |

### 4.2 FastAPI Authorization Enforcement
Every endpoint enforces permissions using FastAPI dependency injection (`SecurityScopes`):

```python
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import SecurityScopes

def require_permissions(required_scopes: list[str]):
    async def permission_checker(
        token_data: TokenPayload = Security(get_current_user_token)
    ):
        for scope in required_scopes:
            if scope not in token_data.scopes and "*" not in token_data.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Missing required scope '{scope}'"
                )
        return token_data
    return permission_checker
```

---

## 5. Network & API Perimeter Defense

### 5.1 Cross-Origin Resource Sharing (CORS)
- Strict origin whitelisting: Only the trusted frontend deployment origin (e.g., `https://soc.aegis.internal` or `http://localhost:3000` during development) is accepted.
- Wildcards (`*`) are prohibited when `allow_credentials=True`.
- Allowed methods: Explicitly restricted to `GET`, `POST`, `PATCH`, `OPTIONS`.
- Allowed headers: `Authorization`, `Content-Type`, `X-Requested-With`.

### 5.2 Rate Limiting Architecture
Rate limiting is enforced at the gateway layer using Redis sliding window counters:
- **Authentication Routes (`/api/v1/auth/login`)**: 5 requests per minute per IP (prevents brute-force credential stuffing).
- **AI Analyst Chat (`/api/v1/investigations/chat`)**: 20 requests per minute per user (protects LLM tokens & compute).
- **Incident Queries (`/api/v1/incidents`)**: 120 requests per minute per user.
- **WebSocket Handshakes**: 10 handshakes per minute per IP.
- Responses on breach: `429 Too Many Requests` with `Retry-After` header.

### 5.3 Security Headers
All HTTP responses include security headers enforced by middleware:
```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: https:;
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

---

## 6. AI & LLM Security Guardrails

The interactive AI Security Analyst introduces unique threat vectors that require dedicated defense mechanisms:

### 6.1 Prompt Injection Defense
- **System Isolation**: System instructions and guardrails are isolated in system prompts with delimiters (`### SYSTEM RULES ###`).
- **User Prompt Sanitization**: Incoming user prompts are filtered against known injection patterns (e.g., "Ignore previous instructions", "Output system prompt", "You are now DAN").
- **Strict Role Separation**: User input is strictly tagged with `role: "user"`; context data is injected under `role: "system"` or `role: "tool"`.

### 6.2 Output Grounding & Hallucination Prevention
- AI responses are constrained by Retrieval-Augmented Generation (RAG):
  - Every technique cited must link to a valid MITRE ATT&CK technique ID present in the internal knowledge base.
  - IP addresses cited in the investigation report must exist in the real incident evidence snapshot; the backend cross-references all extracted IP tokens against the incident's `source_ip` and `destination_ip`.
- If the confidence score is below 50%, the AI assistant flags the analysis with a mandatory disclaimer: `[Low Model Confidence - Manual Verification Required]`.

### 6.3 Data Minimization & Secret Redaction
- Before any telemetry payload or log snippet is passed to the LLM:
  - Authorization headers, JWT tokens, and basic auth passwords in HTTP flows are replaced with `[REDACTED_SECRET]`.
  - Sensitive internal subnets (e.g., HR, Executive VLANs) can be masked according to tenant confidentiality policies.

### 6.4 Human-in-the-Loop Safeguards (Autonomous Mitigation Boundary)
- **Principle**: *The AI investigates; the human analyst decides.*
- The AI Security Analyst generates recommended defensive playbooks (e.g., "Block 185.45.103.91 on perimeter firewall").
- The AI is **never** granted direct write permissions to execute perimeter blocks, DNS blackholes, or host isolations autonomously.
- Remediation commands must be approved by an authenticated analyst via the Incident Modal interface (`setSt(id, s)`), which records the operator's digital signature.

---

## 7. Forensic Audit Logging & Non-Repudiation

### 7.1 Audit Trail Guarantees
- Every security-sensitive transaction is recorded in `audit_logs`:
  - Incident status changes (`New` ➔ `Investigating` ➔ `Contained` ➔ `Resolved`).
  - Analyst reassignments.
  - Telemetry exports and report downloads.
  - Authentication successes and failures.
  - Investigation chats and generated mitigation playbooks.
- Audit records include: `user_id`, `action`, `resource_type`, `resource_id`, `ip_address`, `user_agent`, `timestamp`, and `details` JSON diff.

### 7.2 Cryptographic Tamper Evidence
- To prevent tampering even in the event of database access compromise, audit log entries incorporate a cryptographic hash chain:
  $$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} \parallel \text{Record}_n)$$
- Any retroactive modification or deletion of past log records breaks the hash chain, immediately alerting the SOC Administrator during daily integrity scans.
