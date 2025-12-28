# Extensibility Technical Discussion

*Compiled from discussion on 2025-12-27*

---

## Guiding Principles

1. **External integrations first** (over internal automation)
2. **Developer-facing** (APIs, SDKs over end-user themes)
3. **Self-hosted first** (monetize by hosting for others)
4. **Tenant-specific network** (not ActivityPub/fediverse integration)

---

## Current Extensibility Mechanisms

| Mechanism | What It Enables | Status |
|-----------|-----------------|--------|
| **Events + Subscriptions** | React to system events → trigger actions | Model exists, partially wired |
| **Metadata** | Open `HashMap<String, Value>` on every Thing | ✅ Working |
| **Kinds** | User-defined types with templates | ✅ Working |
| **API Keys** | Scoped access: `things:read`, `things:write`, etc. | ✅ Working |
| **Views** | Saved filters/sorts (feed, table, board, calendar) | ✅ Working |

---

## Webhooks

### Outbound Webhooks (Events → External Systems)

Subscribe to system events, POST to external URLs.

**Delivery Options:**
- **Fire-and-forget (default):** Send once, don't retry
- **Delivery queue (configurable):** Track failures, retry with backoff

**Rationale:** Can't guarantee webhook targets are idempotent, so fire-and-forget is safer default. But users should be able to opt into delivery guarantees.

**Implementation:**

```rust
Subscription {
  id: String,
  user_id: String,
  name: Option<String>,
  event_type: String,           // "thing.created", "reaction.added", etc.
  source_type: Option<String>,  // Filter by source
  action_type: String,          // "webhook"
  action_config: {
    url: String,
    method: "POST",             // Could support GET, etc.
    headers: HashMap<String, String>,
    retry: bool,                // Enable delivery queue
    max_retries: u32,           // Default 3
    signing_secret: Option<String>, // HMAC signing
  },
  enabled: bool,
}
```

**Webhook Payload:**

```json
{
  "event_type": "thing.created",
  "timestamp": "2025-01-15T10:30:00Z",
  "thing": {
    "id": "abc123",
    "type": "note",
    "content": "...",
    "metadata": {}
  }
}
```

**Security:**
- HMAC signing (optional but recommended)
- Signature in `X-Tenant-Signature` header
- Users provide signing secret when creating webhook

### Inbound Webhooks (External Systems → Things)

Authenticated endpoints to create Things from external systems.

**Use cases:**
- GitHub: Create Thing when issue opened
- Pocket: Sync saved articles
- Readwise: Import highlights
- Zapier/n8n: General automation

**Implementation options:**

1. **Generic endpoint with API key:**
   ```
   POST /api/things
   Authorization: Bearer ts_api_key
   ```
   Already works. External systems use API keys with `things:write` scope.

2. **Dedicated inbound webhook endpoint:**
   ```
   POST /api/webhooks/inbound/{webhook_id}
   ```
   Each inbound webhook has its own URL and optional transform rules.

**Decision:** Start with option 1 (API keys). Add option 2 later if needed for no-code integrations.

---

## Source Attribution

When Things are imported from external systems, track the source.

### Schema

```rust
Thing {
  // ... existing fields
  source: Option<Source>,
}

Source {
  system: String,           // "pocket", "github", "readwise", "manual"
  external_id: Option<String>, // ID in source system
  url: Option<String>,      // Link to original
  imported_at: DateTime<Utc>,
}
```

### Benefits

- Query by source: "Show me all Things from Pocket"
- Deduplication: Don't re-import same item
- Provenance: Know where data came from
- Sync: Update Thing if source changes (future)

### Open Question: Staleness

What happens when the source changes?
- **Option A:** One-time import, no sync (simple, but stale)
- **Option B:** Periodic re-sync (complex, but fresh)
- **Option C:** User-triggered refresh (middle ground)

**Decision:** Start with Option A, add refresh later.

---

## API Improvements

### OpenAPI Specification

Auto-generate OpenAPI spec from Rust types.

**Benefits:**
- Developers can generate their own clients
- Interactive API docs (Swagger UI)
- Consistent, always up-to-date

**Implementation:**
- Use `utoipa` crate for Rust
- Generate spec at build time or serve at `/api/openapi.json`

### Error Responses

Standardize error format:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Content is required",
    "field": "content",
    "details": {}
  }
}
```

### Rate Limit Headers

Include in all responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312800
```

---

## SDKs

### Priority Order

1. **OpenAPI spec first** - Foundation for everything
2. **TypeScript SDK** - Most integrations will be JS
3. **Python SDK** - Data science / automation crowd

### Generation Strategy

**Option A:** Generate from OpenAPI
- Pro: Always in sync with API
- Con: Generated code can be awkward

**Option B:** Hand-written with better ergonomics
- Pro: Better DX
- Con: Can drift from API

**Decision:** Start with OpenAPI generation, hand-tune later if needed.

### TypeScript SDK Example

```typescript
import { TenantClient } from '@tenant/sdk';

const client = new TenantClient({
  baseUrl: 'https://alice.tenant.social',
  apiKey: 'ts_...',
});

// List things
const things = await client.things.list({ type: 'note', limit: 10 });

// Create thing
const thing = await client.things.create({
  type: 'link',
  content: 'Check this out',
  metadata: { url: 'https://example.com' },
  visibility: 'public',
});

// Subscribe to webhook
await client.webhooks.create({
  eventType: 'thing.created',
  url: 'https://my-server.com/webhook',
  retry: true,
});
```

---

## CLI (Deprioritized)

**Why deprioritize:**
- API is young and changing (CLI becomes maintenance burden)
- SDK + curl covers 90% of use cases
- Not enough users to justify investment yet

**When to revisit:**
- After OpenAPI + SDK are stable
- If power users request it
- For debugging/admin tasks

**Potential commands (future):**

```bash
tenant things list --type note --limit 10
tenant things create --type link --content "..."
tenant push thing.json
tenant export --format json
tenant config set instance https://alice.tenant.social
```

---

## Event System

### Current Events

```
thing.created
thing.updated
thing.deleted
follow.created
follow.deleted
reaction.added
reaction.removed
comment.created
mention.created (planned)
```

### Subscription Actions

| Action | Description |
|--------|-------------|
| `notification` | Create in-app notification |
| `webhook` | POST to external URL |
| `create_thing` | Auto-create a Thing based on event |

### Event Payload Structure

```rust
Event {
  event_type: String,           // "thing.created"
  source_type: String,          // "first_party", "friend", "webhook"
  source_id: Option<String>,
  actor_id: String,             // Who triggered it
  actor_type: String,           // "user", "system"
  resource_type: Option<String>, // "thing", "follow", "comment"
  resource_id: Option<String>,
  payload: Option<HashMap<String, serde_json::Value>>,
  timestamp: DateTime<Utc>,
}
```

---

## Integration Patterns

### Sync Adapters (Future)

Bidirectional sync between tenant.social and external systems.

**Examples:**
- Obsidian vault ↔ tenant.social notes
- Pocket ↔ tenant.social links
- Readwise ↔ tenant.social highlights

**Challenges:**
- Conflict resolution
- Mapping schemas
- Rate limits on external APIs

### Import Pipelines (Future)

One-time imports from other platforms.

**Priority imports:**
- Twitter archive
- Notion export
- Pocket export
- Browser bookmarks (HTML)

**Implementation:**
- CLI or web UI upload
- Parser for each format
- Map to Things with appropriate source attribution

---

## Priority Roadmap

### Tier 1: API Foundation
| Item | Description | Effort |
|------|-------------|--------|
| OpenAPI spec | Auto-generate from Rust types | Medium |
| Webhook subscriptions | Events → POST to external URLs | Medium |
| Webhook delivery queue | Track failures, retry | Medium |
| Source attribution field | First-class `source` on Things | Small |

### Tier 2: Developer Tools
| Item | Description | Effort |
|------|-------------|--------|
| TypeScript SDK | Generated from OpenAPI | Medium |
| Python SDK | Generated from OpenAPI | Medium |
| Better error responses | Consistent error schema | Small |
| Rate limit headers | Include in all responses | Small |

### Tier 3: Integration Patterns
| Item | Description | Effort |
|------|-------------|--------|
| Inbound webhook endpoints | Dedicated URLs per integration | Medium |
| Import: Twitter archive | One-time import | Medium |
| Import: Notion export | One-time import | Medium |

---

## What NOT to Build

- **ActivityPub integration** - Want tenant-specific network, not fediverse
- **Topic-based organization** - Algorithm over categories
- **Complex automation rules** - Keep it simple, use webhooks for complex logic
- **Built-in integrations** - Provide API, let users build integrations

---

## Summary

The extensibility strategy is:

1. **Make the API bulletproof** - OpenAPI, good errors, rate limit headers
2. **Webhooks as the universal primitive** - Events out, data in
3. **SDKs for developer experience** - TypeScript first, then Python
4. **Source attribution** - Track where data came from
5. **Let external tools do the heavy lifting** - Zapier, n8n, custom scripts

This keeps the core simple while enabling infinite extensibility through the API.
