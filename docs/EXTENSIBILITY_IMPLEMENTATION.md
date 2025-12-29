# Extensibility Implementation Plan

*Created: 2025-12-28*

## Key Discovery

**Already Built:**
- `Subscription` model with event_type, action_type, action_config
- `DeliveryQueueItem` with status, attempts, exponential backoff
- `EventProcessor` with webhook dispatch (fires HTTP, queues retries)
- Store methods for subscriptions and delivery queue
- `subscriptions` and `delivery_queue` tables

**What's Missing:**
- API endpoints for subscription/webhook CRUD
- HMAC signing for webhook payloads
- OpenAPI spec generation
- Standardized error responses
- Source attribution on Things
- Inbound webhook endpoints

---

## Phase 1: Foundation

### 1A. Standardized Error Responses

**Create** `src/api/errors.rs`:
- `ApiError` enum with variants: NotFound, Validation, Unauthorized, Forbidden, Internal, BadRequest
- Implement `actix_web::ResponseError` returning consistent JSON:
  ```json
  {"error": {"code": "not_found", "message": "...", "field": null}}
  ```
- Add `impl From<StoreError> for ApiError`

**Modify** `src/api/mod.rs`:
- Add `mod errors;`
- Use ApiError in new endpoints (don't refactor existing ones yet)

### 1B. Source Attribution

**Modify** `src/models/mod.rs`:
- Add `Source` struct with: system, external_id, url, imported_at
- Add `source: Option<Source>` to Thing struct

**Modify** `src/store/mod.rs`:
- Add migration for 4 new columns: source_system, source_external_id, source_url, source_imported_at
- Add unique index on (user_id, source_system, source_external_id)
- Update `row_to_thing()` to populate Source
- Update `create_thing()` to persist source fields
- Add `get_thing_by_source(user_id, system, external_id)` for dedup
- Add `source_system` filter to `query_things()`

---

## Phase 2: OpenAPI + Webhook API

### 2A. OpenAPI Specification

**Modify** `Cargo.toml`:
```toml
utoipa = { version = "4", features = ["actix_extras", "chrono"] }
utoipa-swagger-ui = { version = "7", features = ["actix-web"] }
```

**Modify** `src/models/mod.rs`:
- Add `#[derive(ToSchema)]` to: Thing, Kind, Subscription, ApiKey, User, ApiError
- Start with core types, expand later

**Create** `src/api/openapi.rs`:
- `ApiDoc` struct with `#[derive(OpenApi)]`
- List paths and schemas

**Modify** `src/api/mod.rs`:
- Add routes: `/api/openapi.json`, `/api/docs/{_:.*}` (Swagger UI)

### 2B. Webhook Subscription API Endpoints

**Modify** `src/models/mod.rs`:
- Add scopes: `webhooks:read`, `webhooks:write`

**Modify** `src/api/mod.rs`:
- Add handlers using existing store methods:
  - `GET /api/webhooks` → list_subscriptions
  - `POST /api/webhooks` → create_subscription
  - `GET /api/webhooks/{id}` → get_subscription
  - `PUT /api/webhooks/{id}` → update_subscription
  - `DELETE /api/webhooks/{id}` → delete_subscription
  - `POST /api/webhooks/{id}/test` → test_subscription
  - `GET /api/webhooks/{id}/deliveries` → list_deliveries

### 2C. HMAC Signing

**Modify** `Cargo.toml`:
```toml
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
```

**Modify** `src/events/mod.rs`:
- In `execute_webhook_action()`, add HMAC-SHA256 signature if `signing_secret` in action_config
- Add `X-Tenant-Signature: sha256={hex}` header

---

## Phase 3: Inbound Webhooks

### 3A. InboundWebhook Model

**Modify** `src/models/mod.rs`:
- Add `InboundWebhook` struct with: id, user_id, name, secret_token, default_thing_type, default_visibility, source_system, transform_config, enabled, timestamps

**Modify** `src/store/mod.rs`:
- Add `inbound_webhooks` table in schema
- Add CRUD: create_inbound_webhook, list_inbound_webhooks, get_inbound_webhook, update_inbound_webhook, delete_inbound_webhook

### 3B. Inbound Webhook Endpoints

**Modify** `src/api/mod.rs`:
- CRUD endpoints (authenticated):
  - `GET/POST /api/webhooks/inbound`
  - `GET/PUT/DELETE /api/webhooks/inbound/{id}`
- Receiver endpoint (token auth):
  - `POST /api/webhooks/receive/{id}?token={secret}`
  - Verifies token, applies transform, creates Thing with source attribution

---

## Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` | Add utoipa, hmac, sha2, hex |
| `src/api/mod.rs` | Add webhook endpoints, inbound endpoints, OpenAPI routes |
| `src/api/errors.rs` | **NEW** - ApiError enum |
| `src/api/openapi.rs` | **NEW** - ApiDoc struct |
| `src/models/mod.rs` | Add Source, InboundWebhook, ToSchema derives, webhook scopes |
| `src/store/mod.rs` | Source migration, inbound_webhooks table, new store methods |
| `src/events/mod.rs` | Add HMAC signing to webhook dispatch |

---

## Implementation Order

1. **Phase 1A**: ApiError (needed by all new endpoints)
2. **Phase 1B**: Source attribution (needed by inbound webhooks)
3. **Phase 2A**: OpenAPI spec
4. **Phase 2B**: Webhook subscription endpoints
5. **Phase 2C**: HMAC signing
6. **Phase 3**: Inbound webhooks

---

## Tests to Add

- `test_webhook_subscription_crud` - API endpoint tests
- `test_webhook_hmac_signature` - Verify signature computation
- `test_source_attribution` - Create/query things with source
- `test_inbound_webhook_creates_thing` - End-to-end inbound test
- `test_inbound_webhook_deduplication` - Same external_id doesn't duplicate
