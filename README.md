# tenant.social

Your personal social data platform. Own your data, your way.

## What is Tenant?

Tenant is a personal data platform that combines the best parts of Twitter and Notion - without the creepy parts. It's open source, highly extensible, and puts you in control.

- **Store anything** - Notes, links, tasks, bookmarks, photos, anything
- **Your own schema** - Define custom types (Kinds) with your own attributes
- **Multiple views** - See the same data as a feed, table, board, or calendar
- **API-first** - Full REST API with granular scopes for integrations
- **Version history** - Never lose data, track every change
- **Cheap to run** - Single binary, SQLite or Turso, minimal resources

## Philosophy

Social platforms have become creepy data extractors. Notion-like tools are great but don't feel social. Tenant is different:

- **Single tenant** - One owner per instance. Your data, your server.
- **Open source** - See exactly what's running. Modify it how you like.
- **Extensible** - API keys with granular scopes let you build integrations
- **Not creepy** - No ads, no tracking, no selling your data

## Quick Start

### Run Locally

```bash
# Clone
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Install dependencies
cd web && npm install && cd ..

# Run (uses local SQLite by default)
make dev
```

Visit `http://localhost:3069` and register your account.

### Deploy Your Own

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for:
- Fly.io (recommended)
- Docker
- Any VPS

## API

Tenant has a full REST API for building integrations:

```bash
# Create an API key in the UI, then:
curl https://your-tenant.fly.dev/api/things \
  -H "Authorization: Bearer ts_your_api_key"
```

**Scopes:** `things:read`, `things:write`, `things:delete`, `kinds:*`, `keys:manage`

## Try It

Want to try before deploying? Use the public sandbox:

- **Sandbox:** [sandbox.tenant.social](https://sandbox.tenant.social)
  - No password required
  - Data resets periodically
  - Not for real use

## Data Backends

| Backend | Best For | Config |
|---------|----------|--------|
| SQLite | Self-hosting, single instance | `DB_BACKEND=sqlite` |
| Turso | Cloud, edge deployment | `DB_BACKEND=turso` |

## Architecture

**Development** runs two processes:
- **Frontend** (Vite) on port `3069` — hot reload, proxies `/api/*` to backend
- **Backend** (Go) on port `8069` — API only, serves JSON

Visit `localhost:3069` during development.

**Production** serves frontend from a CDN/static host:
- Frontend is built separately and hosted on S3/Tigris/CDN
- Backend fetches and serves static files on demand
- Set `PRODUCTION=true` and optionally `TIGRIS_STATIC_URL` to override the CDN URL
- Deploy anywhere: Fly.io, Docker, any VPS

This architecture allows instant frontend deployments without rebuilding the backend.

## Development

```bash
make dev          # Run both backend + frontend together
make dev-watch    # Backend with hot reload (requires air)
make dev-frontend # Frontend with Vite hot reload
make test         # Run tests
make build        # Build production binary
```

### ⚠️ Important: Embedded Frontend Files

The Go binary **embeds** the frontend files at compile time using `embed.FS`. This means:

- When you change frontend code, you **must rebuild the entire binary** with `make build`
- Running `npm run build` alone is **not sufficient** - the running server will still serve old embedded files
- Symptom: After frontend changes, browser requests new bundle files but server hangs because it doesn't have them embedded

**Correct workflow:**
```bash
# ✅ After making frontend changes:
make build        # Rebuilds frontend AND Go binary with new embedded files
./tenant          # Restart with the newly compiled binary

# ❌ This will cause hangs:
cd web && npm run build  # Builds new files to disk
./tenant                 # But running server still has old files embedded!
```

## License

MIT

## Links

- Website: [tenant.social](https://tenant.social)
- Sandbox: [sandbox.tenant.social](https://sandbox.tenant.social)
- GitHub: [github.com/russellromney/tenant.social](https://github.com/russellromney/tenant.social)
