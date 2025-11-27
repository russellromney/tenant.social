.PHONY: dev dev-backend dev-frontend dev-watch build test clean deploy

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

# Build frontend for production
build-frontend:
	cd web && npm run build

# Build Go binary with embedded frontend
build:
	cd web && npm ci && npm run build
	CGO_ENABLED=0 go build -o tenant ./cmd/tenant

# Run tests
test:
	go test ./...

# Run tests with coverage
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f tenant
	rm -f coverage.out coverage.html
	rm -rf cmd/tenant/dist/*
	touch cmd/tenant/dist/.gitkeep

# Deploy to Fly.io
deploy:
	fly deploy

# View Fly.io logs
logs:
	fly logs -a tenant-social

# Install all dependencies
install:
	cd web && npm install
	go mod download

# Format code
fmt:
	go fmt ./...
