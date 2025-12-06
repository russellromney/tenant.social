# Claude Development Guidelines

## Stack
- **Go** backend (port 8069) - `cmd/tenant/`, `internal/`
- **Preact + Vite** frontend (port 3069 in dev) - `web/src/`
- **Rust backend** (in development) - `backend-rust/`
- **SQLite** (local) or **Turso** (cloud) - `DB_BACKEND=sqlite|turso`

## Critical Rules

### 1. Frontend Embedding
**The Go binary embeds frontend files at compile time via `embed.FS`.**

```bash
# ✅ CORRECT: After frontend changes
make build        # Rebuilds frontend AND Go binary
./tenant          # Restart with new binary

# ❌ WRONG: Causes hangs
cd web && npm run build  # Only builds to disk
./tenant                 # Still serving old embedded files
```

### 2. Always Use Make Commands
```bash
make dev          # Start backend + frontend
make build        # Build production binary
make test         # Run all tests (Go + E2E)
make deploy       # Deploy to Fly.io
```

### 3. Git Operations
🚨 **NEVER run git commands without explicit user permission.** Always ask first.

### 4. Write Tests
- Write tests for new features
- Run `make test` before completing tasks
- Tests must pass before marking complete

### 5. Code Style
- Concise over verbose
- No over-engineering or premature abstractions
- Edit existing files, only Write for new files
- Watch for security vulnerabilities

### 6. Secrets
- Never commit `.env` files
- Use `.env.local` for local overrides (git-ignored)

## Architecture

**Dev:** Two processes - Frontend (Vite :3069) + Backend (Go :8069). Visit `localhost:3069`.

**Prod:** Single binary with embedded frontend. Deploy to Fly.io/Docker/VPS.

## What NOT to Do

❌ Change frontend without `make build`
❌ Git commits/push without asking
❌ Skip tests
❌ Commit secrets
❌ Over-engineer

## Key Concepts

- **Things** - Core data model (tweets/notes/bookmarks)
- **Kinds** - Custom schemas for Things
- **Version History** - All changes tracked
- **API Keys** - Granular scopes: `things:read`, `things:write`, `kinds:*`, etc.
- **Federated Friendship** - Share content between instances

## Quick Reference

```bash
make dev           # Start both backend + frontend
make dev-watch     # Backend with hot reload
make build         # Build production binary
make test          # Run all tests
make test-go       # Go tests only
make test-e2e      # Playwright E2E tests
make deploy        # Build, test, deploy to Fly.io
```
