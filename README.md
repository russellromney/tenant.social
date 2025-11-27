# tenant.social

A massively multi-tenant social platform where everyone runs their own space.

```
   /\
  /  \
 | || |
```

## What is Tenant?

Tenant is a personal data platform inspired by Notion. Store anything - notes, links, tasks, photos - in a flexible schema you control. Each user is a "tenant" with their own data space.

**Features:**
- **Things** - Universal data units (notes, links, tasks, photos, etc.)
- **Kinds** - Define your own schemas with custom attributes
- **Views** - See the same data as feed, table, board, or calendar
- **Multi-tenant** - Each user owns their data
- **Self-hostable** - Run on your own hardware or use hosted version

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

Visit `http://localhost:8069`

### Deploy

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for:
- Fly.io
- Docker
- DigitalOcean
- Any VPS

## Data Backends

Tenant supports two database backends:

| Backend | Best For | Config |
|---------|----------|--------|
| SQLite | Self-hosting, single instance | `DB_BACKEND=sqlite` |
| Turso | Cloud, multi-region | `DB_BACKEND=turso` |

## Environment Variables

```bash
# Required
TENANT_PASSWORD=your-password    # Login password

# Database
DB_BACKEND=sqlite                # "sqlite" or "turso"
SQLITE_PATH=tenant.db            # For SQLite
TURSO_DATABASE_URL=libsql://...  # For Turso
TURSO_AUTH_TOKEN=...             # For Turso

# Optional
PORT=8080
PRODUCTION=true
```

## Development

```bash
make dev        # Run API + frontend in dev mode
make test       # Run tests
make build      # Build production binary
```

## License

MIT

## Links

- Website: [tenant.social](https://tenant.social)
- GitHub: [github.com/russellromney/tenant.social](https://github.com/russellromney/tenant.social)
