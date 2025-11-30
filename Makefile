.PHONY: dev dev-backend dev-frontend dev-watch build build-frontend build-go test test-go test-e2e test-cover clean deploy logs install fmt

# Development - run backend and frontend together
dev:
	@echo "Starting backend and frontend..."
	@make -j2 dev-backend dev-frontend

# Backend only (uses local SQLite by default, no hot reload)
dev-backend:
	go run ./cmd/tenant

# Backend with hot reload using air (install: go install github.com/cosmtrek/air@latest)
dev-watch:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/air-verse/air@latest)
	air -c .air.toml 2>/dev/null || air

# Frontend only (Vite dev server with hot reload on port 3069)
dev-frontend:
	cd web && npm run dev

# ===== BUILD TARGETS =====

# Build frontend for production
build-frontend:
	@echo "Building frontend..."
	cd web && npm ci && npm run build

# Build Go binary with embedded frontend
build-go:
	@echo "Building Go binary..."
	CGO_ENABLED=0 go build -o tenant ./cmd/tenant
	@echo "✅ Go binary built: ./tenant"

# Build everything (frontend + go binary)
build: build-frontend build-go
	@echo "✅ Full build complete"

# ===== TEST TARGETS =====

# Run all Go tests
test-go:
	@echo "Running Go tests..."
	go test -v ./...

# Run Go tests with coverage
test-cover:
	@echo "Running Go tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

# Run Playwright E2E tests (requires server running on :8069)
test-e2e:
	@echo "Running Playwright E2E tests..."
	@which npx > /dev/null || (echo "❌ npm not found"; exit 1)
	cd web && npm install --save-dev @playwright/test 2>/dev/null || true
	npx playwright test --config=playwright.config.ts
	@echo "✅ E2E tests complete. Report: playwright-report/index.html"

# Run all tests (Go + E2E)
test: test-go test-e2e
	@echo "✅ All tests passed"

# ===== DEPLOY TARGET =====

# Deploy to Fly.io (builds, tests, then deploys)
deploy: clean build test
	@echo "All checks passed! Deploying to Fly.io..."
	@git status --short | grep -q . && (echo "❌ Uncommitted changes. Commit first:" && git status && exit 1) || true
	@echo "✅ Repository clean, deploying..."
	fly deploy
	@echo "✅ Deployment complete!"

# ===== UTILITY TARGETS =====

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f tenant
	rm -f coverage.out coverage.html
	rm -rf playwright-report
	rm -rf web/dist
	@echo "✅ Clean complete"

# View Fly.io logs
logs:
	fly logs -a tenant-social

# Install all dependencies
install:
	@echo "Installing dependencies..."
	go mod download
	cd web && npm install
	@echo "✅ Dependencies installed"

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "✅ Code formatted"
