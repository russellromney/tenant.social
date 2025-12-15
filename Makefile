.PHONY: dev dev-backend dev-frontend dev-watch build build-frontend build-backend test test-backend test-e2e clean deploy logs install

# Development - run backend and frontend together
dev:
	@echo "Starting Rust backend and frontend..."
	@make -j2 dev-backend dev-frontend

# Backend only (Rust tenant-vm)
dev-backend:
	cd backend-rust/tenant-vm && ~/.cargo/bin/cargo run

# Backend with hot reload using cargo-watch
dev-watch:
	@which cargo-watch > /dev/null || (echo "Installing cargo-watch..." && ~/.cargo/bin/cargo install cargo-watch)
	cd backend-rust/tenant-vm && ~/.cargo/bin/cargo watch -x run

# Frontend only (Vite dev server with hot reload on port 3069)
dev-frontend:
	cd web && npm run dev

# ===== BUILD TARGETS =====

# Build frontend for production
build-frontend:
	@echo "Building frontend..."
	cd web && rm -rf dist .vite && npm ci && npm run build

# Build Rust backend
build-backend:
	@echo "Building Rust backend..."
	cd backend-rust/tenant-vm && ~/.cargo/bin/cargo build --release
	@echo "✅ Rust binary built: backend-rust/tenant-vm/target/release/tenant-vm"

# Build everything
build: build-frontend build-backend
	@echo "✅ Full build complete"

# ===== TEST TARGETS =====

# Run Rust backend tests
test-backend:
	@echo "Running Rust backend tests..."
	cd backend-rust/tenant-vm && ~/.cargo/bin/cargo test

# Run Playwright E2E tests (requires server running on :8069)
test-e2e:
	@echo "Running Playwright E2E tests..."
	@which npm > /dev/null || (echo "❌ npm not found"; exit 1)
	cd web && npm ci --save-dev @playwright/test 2>/dev/null || true
	cd web && npx playwright test --config=playwright.config.ts
	@echo "✅ E2E tests complete. Report: web/playwright-report/index.html"

# Run all tests
test: test-backend test-e2e
	@echo "✅ All tests passed"

# ===== DEPLOY TARGET =====

# Deploy to Fly.io (builds, tests, then deploys)
deploy: build test-backend
	@echo "All checks passed! Deploying to Fly.io..."
	@git status --short | grep -q . && (echo "❌ Uncommitted changes. Commit first:" && git status && exit 1) || true
	@echo "✅ Repository clean, deploying..."
	fly deploy
	@echo "✅ Deployment complete!"

# ===== UTILITY TARGETS =====

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf backend-rust/tenant-vm/target
	rm -rf playwright-report
	rm -rf web/dist
	rm -rf web/.vite
	@echo "✅ Clean complete"

# View Fly.io logs
logs:
	fly logs -a tenant-social

# Install all dependencies
install:
	@echo "Installing dependencies..."
	cd backend-rust/tenant-vm && ~/.cargo/bin/cargo fetch
	cd web && npm install
	@echo "✅ Dependencies installed"
