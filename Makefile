.PHONY: dev dev-api dev-web build clean test test-cover

# Development: run both API and frontend
dev:
	@echo "Starting development servers..."
	@make -j2 dev-api dev-web

# Run Go API in dev mode (requires TURSO_DATABASE_URL and TURSO_AUTH_TOKEN from ../.env)
dev-api:
	@set -a && . ../.env && set +a && cd cmd/tenant && DEV=true go run .

# Run Vite dev server
dev-web:
	@cd web && npm run dev

# Build everything
build: build-web build-api

# Build frontend
build-web:
	@cd web && npm install && npm run build

# Build Go binary with embedded frontend
build-api:
	@cd cmd/tenant && go build -o ../../tenant .

# Clean build artifacts
clean:
	@rm -f tenant
	@rm -rf cmd/tenant/dist
	@rm -f tenant.db

# Install frontend dependencies
install:
	@cd web && npm install

# Run the built binary
run:
	@./tenant

# Run tests (requires TURSO_DATABASE_URL and TURSO_AUTH_TOKEN from ../.env)
test:
	@set -a && . ../.env && set +a && go test ./internal/api/... ./internal/auth/... ./internal/store/... -v

# Run tests with coverage report
test-cover:
	@set -a && . ../.env && set +a && go test ./internal/api/... ./internal/auth/... ./internal/store/... -v -coverprofile=coverage.out
	@go tool cover -func=coverage.out
	@rm coverage.out
