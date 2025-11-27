# Build frontend
FROM node:20-alpine AS frontend-builder

WORKDIR /app/web

# Copy package files
COPY web/package*.json ./
RUN npm ci

# Copy source and build
COPY web/ ./
RUN npm run build

# Build Go binary
FROM golang:1.24-alpine AS go-builder

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy built frontend to cmd/tenant/dist for embedding
COPY --from=frontend-builder /app/cmd/tenant/dist ./cmd/tenant/dist

# Build Go binary (pure Go, no CGO needed thanks to modernc.org/sqlite)
RUN CGO_ENABLED=0 go build -o tenant ./cmd/tenant

# Runtime stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=go-builder /app/tenant .

# Create data directory for local SQLite
RUN mkdir -p /data

# Expose port
EXPOSE 8080

# Environment variables (can be overridden at runtime):
#
# Data backend (pick one):
#   DB_BACKEND - "sqlite" or "turso" (auto-detects if not set)
#
# For SQLite:
#   SQLITE_PATH - path to database file (defaults to "tenant.db")
#
# For Turso:
#   TURSO_DATABASE_URL - e.g., "libsql://mydb.turso.io"
#   TURSO_AUTH_TOKEN - auth token
#
# Other:
#   PORT - server port (defaults to 8080)

ENV DB_BACKEND=sqlite
ENV SQLITE_PATH=/data/tenant.db
ENV PORT=8080

CMD ["/app/tenant"]
