# AegisSOC Production Deployment Guide

This guide details the deployment of AegisSOC in production environments using Docker Compose, reverse proxying with Nginx, TLS termination, persistent storage, and operational monitoring.

---

## 1. Hosting Architecture Overview

A production AegisSOC deployment consists of:
1. **Reverse Proxy (Nginx / Cloudflare / AWS ALB)**: Terminates TLS/HTTPS, enforces HTTP/2 or HTTP/3, and proxies WebSocket connections (`/ws/*`).
2. **AegisSOC Backend Container**: Multi-stage hardened Python container running FastAPI with Uvicorn workers under an unprivileged user (`aegis:10001`).
3. **PostgreSQL 16 Container**: Relational database with persistent volume storage (`postgres_data`) and automated migration execution.
4. **Isolated Bridge Network (`aegissoc_network`)**: Restricts inter-service traffic so that PostgreSQL is accessible only to the backend.

```
       Internet / Analysts
               │
               ▼  HTTPS / WSS (Port 443)
     ┌───────────────────┐
     │  Nginx / Envoy    │ (TLS Termination, Rate Limiting)
     └─────────┬─────────┘
               │  HTTP / WS (Port 8000)
               ▼
     ┌───────────────────┐
     │ aegissoc_backend  │ (FastAPI, Scapy, ML Engine, AI Analyst)
     └─────────┬─────────┘
               │  PostgreSQL TCP (Port 5432 - Internal Network Only)
               ▼
     ┌───────────────────┐
     │   aegissoc_db     │ (PostgreSQL 16 Alpine + Persistent Volume)
     └───────────────────┘
```

---

## 2. Server Preparation (Ubuntu 22.04 / 24.04 LTS)

### 2.1 Install Docker Engine & Compose
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker GPG key & repository
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
sudo systemctl enable --now docker
```

---

## 3. Step-by-Step Deployment

### 3.1 Clone the Repository
```bash
cd /opt
sudo git clone https://github.com/your-org/aegissoc.git
cd aegissoc
```

### 3.2 Configure Production Environment Variables
Generate cryptographically strong secrets for `SECRET_KEY` and `POSTGRES_PASSWORD`:
```bash
# Generate 64-character hex strings
JWT_SECRET=$(openssl rand -hex 32)
DB_SECRET=$(openssl rand -hex 24)

# Create production .env file
cp .env.example .env

# Populate keys
sed -i "s|change_me_to_a_random_32_character_hex_string_in_production|$JWT_SECRET|g" .env
sed -i "s|generate_strong_database_password_here|$DB_SECRET|g" .env
```

Review `.env` and configure:
- `CORS_ORIGINS`: Set to your production frontend domain (e.g. `https://soc.yourcompany.com`).
- `DEFAULT_AI_PROVIDER`: Set to `gemini`, `openai`, or `anthropic`.
- API keys: Provide `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, or `ABUSEIPDB_API_KEY`.

### 3.3 Deploy Containers
```bash
# Build images and start services in detached mode
sudo docker compose up -d --build
```

### 3.4 Verify Deployment Status
```bash
# Check container status and health checks
sudo docker compose ps

# Check backend startup and migration logs
sudo docker compose logs -f backend
```

Expected healthy output:
```
aegissoc_db        postgres:16-alpine      Up (healthy)   0.0.0.0:5432->5432/tcp
aegissoc_backend   aegissoc-backend:latest Up (healthy)   0.0.0.0:8000->8000/tcp
```

---

## 4. Reverse Proxy & SSL Configuration (Nginx)

Install Nginx and Certbot for automated Let's Encrypt certificates:
```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/aegissoc`:
```nginx
# Map for WebSocket connection upgrade
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name soc.yourcompany.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.yourcompany.com;

    # SSL Certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/soc.yourcompany.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/soc.yourcompany.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Request limits (50MB for PCAP uploads)
    client_max_body_size 50M;

    # 1. REST API Endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }

    # 2. WebSocket Real-Time Telemetry Stream
    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # 3. Health & Docs
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        proxy_set_header Host $host;
    }

    location /docs {
        proxy_pass http://127.0.0.1:8000/docs;
        proxy_set_header Host $host;
    }

    location /openapi.json {
        proxy_pass http://127.0.0.1:8000/openapi.json;
        proxy_set_header Host $host;
    }
}
```

Enable site and obtain SSL certificate:
```bash
sudo ln -s /etc/nginx/sites-available/aegissoc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d soc.yourcompany.com
```

---

## 5. Database Backups & Volume Persistence

The PostgreSQL database stores all incidents, evidence, audit logs, and indicators in the Docker volume `aegissoc_postgres_data`.

### Automated Nightly Backup Script
Create `/usr/local/bin/backup-aegissoc.sh`:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/aegissoc"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p "$BACKUP_DIR"

# Dump database to compressed SQL file
docker exec aegissoc_db pg_dump -U postgres aegissoc | gzip > "$BACKUP_DIR/aegissoc_$TIMESTAMP.sql.gz"

# Retain backups for 30 days
find "$BACKUP_DIR" -type f -name "*.sql.gz" -mtime +30 -delete
echo "[$(date)] AegisSOC database backup completed: aegissoc_$TIMESTAMP.sql.gz"
```
Make executable and schedule in crontab:
```bash
sudo chmod +x /usr/local/bin/backup-aegissoc.sh
# Run nightly at 02:00 AM
echo "0 2 * * * root /usr/local/bin/backup-aegissoc.sh >> /var/log/aegissoc_backup.log 2>&1" | sudo tee -a /etc/crontab
```

---

## 6. Zero-Downtime Updates & Rolling Restarts

To deploy new versions or updates:
```bash
cd /opt/aegissoc
git pull origin main

# Rebuild and restart containers
docker compose up -d --build --no-deps backend

# Prune dangling build images
docker image prune -f
```
The entrypoint script automatically executes pending Alembic migrations (`alembic upgrade head`) before launching Uvicorn workers.
