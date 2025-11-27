# Deploying Tenant

Tenant is a single binary with an embedded frontend. Choose your deployment method:

| Method | Best For | Database |
|--------|----------|----------|
| [Fly.io](#flyio) | Quick deploy, auto-scaling | Turso (recommended) |
| [Docker](#docker) | Any cloud, Kubernetes | SQLite or Turso |
| [DigitalOcean](#digitalocean) | Simple VPS | SQLite or Turso |
| [Binary](#binary-any-vps) | Any Linux/Mac server | SQLite or Turso |

---

## Environment Variables

All deployments use these environment variables:

```bash
# Required
TENANT_PASSWORD=your-secure-password    # Login password

# Database (pick one backend)
DB_BACKEND=sqlite                        # "sqlite" or "turso"

# For SQLite:
SQLITE_PATH=/data/tenant.db             # Path to database file

# For Turso:
TURSO_DATABASE_URL=libsql://your-db.turso.io
TURSO_AUTH_TOKEN=your-token

# Optional
PORT=8080                                # Server port (default: 8080)
PRODUCTION=true                          # Enable production mode
```

---

## Fly.io

**Pros:** Free tier, auto-sleep, global edge, easy deploys
**Cost:** Free for small apps, ~$2-5/month with activity

### 1. Install Fly CLI

```bash
# macOS
brew install flyctl

# Linux
curl -L https://fly.io/install.sh | sh

# Login
fly auth login
```

### 2. Create Turso Database

```bash
# Install Turso CLI
brew install tursodatabase/tap/turso
turso auth login

# Create database
turso db create tenant-prod

# Get credentials
turso db show tenant-prod --url
turso db tokens create tenant-prod
```

### 3. Deploy

```bash
cd tenant

# Create app
fly apps create tenant

# Set secrets
fly secrets set TENANT_PASSWORD=your-secure-password
fly secrets set TURSO_DATABASE_URL=libsql://tenant-prod-xxx.turso.io
fly secrets set TURSO_AUTH_TOKEN=your-token

# Deploy
fly deploy
```

Your app will be live at `https://tenant.fly.dev`

### fly.toml

```toml
app = "tenant"
primary_region = "ewr"  # Change to nearest region

[build]

[env]
  PORT = "8080"
  PRODUCTION = "true"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

---

## Docker

### Dockerfile

The included Dockerfile builds a minimal image (~30MB):

```dockerfile
# Build stage
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache nodejs npm
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN cd web && npm ci && npm run build
RUN CGO_ENABLED=0 go build -o tenant ./cmd/tenant

# Runtime stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/tenant .
RUN mkdir -p /data
EXPOSE 8080
ENV DB_BACKEND=sqlite
ENV SQLITE_PATH=/data/tenant.db
ENV PORT=8080
ENV PRODUCTION=true
CMD ["/app/tenant"]
```

### Build & Run Locally

```bash
# Build
docker build -t tenant .

# Run with SQLite (data persisted in ./data)
docker run -d \
  --name tenant \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e TENANT_PASSWORD=secret \
  tenant

# Run with Turso
docker run -d \
  --name tenant \
  -p 8080:8080 \
  -e DB_BACKEND=turso \
  -e TURSO_DATABASE_URL=libsql://your-db.turso.io \
  -e TURSO_AUTH_TOKEN=your-token \
  -e TENANT_PASSWORD=secret \
  tenant
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  tenant:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - tenant_data:/data
    environment:
      - TENANT_PASSWORD=${TENANT_PASSWORD}
      - DB_BACKEND=sqlite
      - SQLITE_PATH=/data/tenant.db
    restart: unless-stopped

volumes:
  tenant_data:
```

```bash
# Create .env file
echo "TENANT_PASSWORD=your-secure-password" > .env

# Run
docker-compose up -d
```

---

## DigitalOcean

### Option A: App Platform (Easiest)

1. Push code to GitHub
2. Go to [DigitalOcean App Platform](https://cloud.digitalocean.com/apps)
3. Create App → Select your repo
4. Set environment variables in the dashboard
5. Deploy

**Cost:** ~$5/month (Basic)

### Option B: Droplet (More Control)

```bash
# 1. Create a droplet (Ubuntu 22.04, $6/month)

# 2. SSH in
ssh root@your-droplet-ip

# 3. Install Docker
curl -fsSL https://get.docker.com | sh

# 4. Run Tenant
docker run -d \
  --name tenant \
  --restart unless-stopped \
  -p 80:8080 \
  -v /opt/tenant/data:/data \
  -e TENANT_PASSWORD=your-password \
  ghcr.io/yourusername/tenant:latest

# 5. (Optional) Add SSL with Caddy
docker run -d \
  --name caddy \
  --restart unless-stopped \
  -p 443:443 \
  -v caddy_data:/data \
  caddy caddy reverse-proxy --from tenant.yourdomain.com --to localhost:8080
```

---

## Binary (Any VPS)

For any Linux/Mac server without Docker.

### 1. Build

```bash
# On your local machine
cd tenant
make build

# Or cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o tenant-linux ./cmd/tenant
```

### 2. Deploy

```bash
# Copy to server
scp tenant-linux user@server:/opt/tenant/tenant
scp -r web/dist user@server:/opt/tenant/dist  # Only if not embedded

# SSH to server
ssh user@server

# Create data directory
mkdir -p /opt/tenant/data

# Run
cd /opt/tenant
TENANT_PASSWORD=secret SQLITE_PATH=/opt/tenant/data/tenant.db ./tenant
```

### 3. Systemd Service

```ini
# /etc/systemd/system/tenant.service
[Unit]
Description=Tenant
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/tenant
Environment=TENANT_PASSWORD=your-password
Environment=SQLITE_PATH=/opt/tenant/data/tenant.db
Environment=PORT=8080
Environment=PRODUCTION=true
ExecStart=/opt/tenant/tenant
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable tenant
sudo systemctl start tenant

# Check status
sudo systemctl status tenant
```

### 4. Nginx Reverse Proxy (Optional)

```nginx
# /etc/nginx/sites-available/tenant
server {
    listen 80;
    server_name tenant.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/tenant /etc/nginx/sites-enabled/
sudo certbot --nginx -d tenant.yourdomain.com  # Add SSL
sudo systemctl reload nginx
```

---

## Backups

### SQLite

```bash
# Simple backup
cp /data/tenant.db /backups/tenant-$(date +%Y%m%d).db

# Cron job (daily at 2am)
0 2 * * * cp /data/tenant.db /backups/tenant-$(date +\%Y\%m\%d).db
```

### Turso

Turso handles replication automatically. For manual exports:

```bash
turso db shell tenant-prod ".dump" > backup.sql
```

---

## Monitoring

### Health Check

```bash
curl https://your-tenant-url/api/auth/check
# Returns: {"authenticated":false}
```

### Logs

```bash
# Docker
docker logs -f tenant

# Systemd
journalctl -u tenant -f

# Fly.io
fly logs
```
