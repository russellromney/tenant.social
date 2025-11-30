# Deployment Guide

## Quick Deploy

To deploy to production, simply run:

```bash
make deploy
```

This is the **only** deployment command you need. It automatically:

1. **Cleans** previous builds
2. **Builds** frontend (JavaScript/TypeScript) with Vite
3. **Builds** Go binary with embedded frontend assets
4. **Tests** all Go unit tests
5. **Tests** all Playwright E2E tests
6. **Verifies** git repository is clean (no uncommitted changes)
7. **Deploys** to Fly.io using `fly deploy`

## What Gets Built

### Frontend Build (npm ci + npm run build)
- Compiles TypeScript/JavaScript with Vite
- Bundles and minifies assets
- Outputs to `web/dist`
- Automatically embedded in Go binary

### Go Binary Build
- Compiles Go code with `CGO_ENABLED=0`
- Embeds frontend assets from `web/dist`
- Produces single `tenant` binary
- Ready for deployment on any Linux system

## Test Coverage

### Go Unit Tests
Located in `internal/**/*_test.go`:
- Store tests: CRUD operations, visibility levels, photo handling
- API tests: Endpoint validation
- Gallery photo tests: Multi-photo upload, captions, ordering, visibility

Run with:
```bash
make test-go
```

### Playwright E2E Tests
Located in `tests/e2e/*.spec.ts`:
- Gallery photo upload flows
- Visibility level indicators
- Carousel navigation
- API endpoint validation
- Frontend rendering

Run with:
```bash
make test-e2e
```

## Other Commands

### Development
```bash
make dev              # Start backend + frontend with hot reload
make dev-backend      # Go server only
make dev-frontend     # Vite dev server only
make dev-watch        # Go with hot reload via air
```

### Building
```bash
make build            # Full production build
make build-frontend   # Frontend only
make build-go         # Go binary only
```

### Testing
```bash
make test             # Run all tests (Go + E2E)
make test-go          # Go tests only
make test-e2e         # Playwright E2E only
make test-cover       # Generate coverage report
```

### Utilities
```bash
make clean            # Remove build artifacts
make install          # Install all dependencies
make fmt              # Format Go code
make logs             # View Fly.io logs
```

## Deployment Requirements

- Fly.io CLI: `fly` command must be installed and authenticated
- Git: Repository must be clean (no uncommitted changes)
- Go 1.24+
- Node.js + npm
- All tests must pass

## Pre-Deployment Checklist

Before running `make deploy`:

- [ ] All changes are committed: `git status` is clean
- [ ] Tests pass locally: `make test`
- [ ] Frontend builds: `make build-frontend`
- [ ] Go builds: `make build-go`
- [ ] Your `.fly.toml` is configured correctly
- [ ] Fly.io app exists: `fly apps list`

## Troubleshooting

### "Uncommitted changes" error
```bash
# Check what's uncommitted
git status

# Commit changes
git add .
git commit -m "Your message"

# Try deploy again
make deploy
```

### Build fails
```bash
# Clean and rebuild from scratch
make clean
make build

# If still failing, check dependencies
make install
```

### Tests fail
```bash
# Run tests individually to debug
make test-go          # Debug Go tests
make test-e2e         # Debug E2E tests

# View full output
go test -v ./...
```

### Playwright tests require server
The E2E tests automatically start a server via `playwright.config.ts`.
If tests fail due to server not starting:
```bash
# Manually start server in another terminal
PORT=8069 ./tenant

# Run tests
make test-e2e
```

## Fly.io Setup

Ensure `fly.toml` exists with proper configuration:

```toml
app = "tenant-social"  # or your app name
primary_region = "sjc"

[build]
builder = "paketobuildpacks/builder:base"

[env]
PORT = "8080"
```

Configure with:
```bash
fly launch              # First time setup
fly deploy --remote    # Deploy (same as make deploy without tests)
```

## Rollback

If deployment fails or has issues:

```bash
# View deployment history
fly releases

# Rollback to previous version
fly releases rollback
```

## Monitoring

After deployment:

```bash
# View logs
make logs

# Watch logs in real-time
fly logs -a tenant-social --follow

# Check app status
fly status
```

## CI/CD Integration

To integrate with GitHub Actions or similar:

```yaml
- name: Deploy
  run: make deploy
  env:
    FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

The `make deploy` command handles all build, test, and verification steps.
