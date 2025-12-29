# Extensibility Implementation Plan

*Based on EXTENSIBILITY_TECHNICAL.md*

---

## Overview

This plan implements the extensibility features in three tiers:

1. **Tier 1: API Foundation** - Core infrastructure that everything else depends on
2. **Tier 2: Developer Tools** - SDKs and improved API ergonomics
3. **Tier 3: Integration Patterns** - Import pipelines and dedicated endpoints

Each feature section covers backend changes, UI requirements, and test requirements.

---

# Tier 1: API Foundation

## 1.1 OpenAPI Specification

**Goal:** Auto-generate an OpenAPI spec from our Rust types so developers can generate their own clients and we can serve interactive API docs.

### Backend

Add the `utoipa` and `utoipa-swagger-ui` crates to Cargo.toml. These crates let us derive OpenAPI schemas from our existing Rust structs and serve Swagger UI.

For each model (Thing, Kind, Reaction, Comment, etc.), add the `ToSchema` derive macro. This automatically generates the JSON schema for that type.

For each API handler, add the `#[utoipa::path(...)]` attribute that documents the endpoint's path, parameters, request body, and response types. This is similar to JSDoc but enforced by the compiler.

Create a new `ApiDoc` struct that aggregates all the paths and schemas into a single OpenAPI document. Serve this at `/api/openapi.json` and mount Swagger UI at `/api/docs`.

**New files:**
- `src/api/openapi.rs` - The ApiDoc struct and configuration

**Modified files:**
- `Cargo.toml` - Add utoipa dependencies
- `src/models/mod.rs` - Add ToSchema derives to all types
- `src/api/mod.rs` - Add path annotations to all handlers, serve Swagger UI

### UI

Add a link to `/api/docs` in the settings or help section. Swagger UI provides its own interface, so no custom UI is needed.

### Tests

Write a test that generates the OpenAPI spec and verifies it's valid JSON containing expected paths like `/api/things` and `/api/kinds`. Write an integration test that hits `/api/openapi.json` and verifies it returns a 200 with valid OpenAPI 3.0 content.

---

## 1.2 Webhook Subscriptions

**Goal:** Let users subscribe to system events and receive POST requests to external URLs when those events occur.

### Backend

**Database schema:** Create a `webhook_subscriptions` table with columns for: id, user_id, name (optional), event_type (e.g., "thing.created"), URL to POST to, HTTP method, custom headers (stored as JSON), whether retry is enabled, max retry count, optional HMAC signing secret, enabled flag, and timestamps.

**Models:** Create a `WebhookSubscription` struct matching the schema, and a `WebhookPayload` struct that represents what gets sent to the external URL (event_type, timestamp, resource_type, resource_id, and the actual data).

**Dispatcher:** Create a `WebhookDispatcher` that takes a subscription and payload, builds an HTTP request with the configured method and headers, optionally signs the body with HMAC-SHA256 (putting the signature in `X-Tenant-Signature` header), and sends the request.

**Event integration:** Modify the existing event system. When an event fires, query for all enabled subscriptions matching that event type. For each subscription, build the payload and either dispatch immediately (fire-and-forget) or queue for retry (if retry is enabled on that subscription).

**API endpoints:** Add CRUD endpoints for webhook subscriptions:
- `POST /api/webhooks` - Create subscription
- `GET /api/webhooks` - List user's subscriptions
- `GET /api/webhooks/{id}` - Get single subscription
- `PATCH /api/webhooks/{id}` - Update subscription
- `DELETE /api/webhooks/{id}` - Delete subscription
- `POST /api/webhooks/{id}/test` - Send a test payload

**New files:**
- `src/models/webhook.rs` - WebhookSubscription, WebhookPayload structs
- `src/store/webhooks.rs` - Database operations for subscriptions
- `src/webhooks/mod.rs` - Module definition
- `src/webhooks/dispatcher.rs` - HTTP dispatch logic with HMAC signing
- `src/api/webhooks.rs` - API endpoint handlers

**Modified files:**
- `src/events/mod.rs` - Call dispatcher when events fire
- `src/api/mod.rs` - Register new routes

### UI

Add a "Webhooks" tab to the Settings page. This tab shows a list of the user's webhook subscriptions with columns for name, event type, URL, and enabled status. Each row has Edit, Delete, and Test buttons.

The Create/Edit modal has fields for: optional name, event type dropdown (thing.created, thing.updated, thing.deleted, reaction.added, comment.created, etc.), target URL, a checkbox to enable retry, and an "Advanced" section with fields for signing secret and custom headers.

The Test button sends a sample payload to the URL and shows the response status (success or failure with error message).

### Tests

Test subscription CRUD operations in the store. Test that the dispatcher correctly builds HTTP requests and includes HMAC signatures when a secret is configured. Test that creating a Thing actually triggers the webhook by using a mock HTTP server. Test the API endpoints return correct status codes and response formats.

---

## 1.3 Webhook Delivery Queue

**Goal:** For webhooks with retry enabled, track delivery attempts and retry failed deliveries with exponential backoff.

### Backend

**Database schema:** Create a `webhook_deliveries` table with columns for: id, subscription_id (foreign key), payload (JSON string), status (pending/success/failed/exhausted), attempt count, last attempt timestamp, next attempt timestamp, last error message, response status code, response body snippet, and created_at.

**Models:** Create a `WebhookDelivery` struct and a `DeliveryStatus` enum.

**Processor:** Create a `WebhookProcessor` that runs as a background task. Every few seconds, it queries for pending deliveries where `next_attempt_at` is in the past. For each delivery, it fetches the subscription, dispatches the webhook, and updates the delivery record. On success, mark as Success. On failure, increment attempts and either schedule the next retry (with exponential backoff: 30s, 2min, 8min, 32min) or mark as Exhausted if max retries reached.

**Queue integration:** When the event system needs to dispatch a webhook with retry enabled, instead of calling the dispatcher directly, create a delivery record with status Pending. The processor picks it up.

**API endpoints:**
- `GET /api/webhooks/{id}/deliveries` - List recent deliveries for a subscription
- `POST /api/webhooks/{id}/deliveries/{delivery_id}/retry` - Manually retry a failed delivery

**New files:**
- `src/webhooks/processor.rs` - Background worker that processes the queue

**Modified files:**
- `src/models/webhook.rs` - Add WebhookDelivery struct
- `src/store/webhooks.rs` - Add delivery table operations
- `src/main.rs` - Spawn the processor as a background task
- `src/api/webhooks.rs` - Add delivery endpoints

### UI

When viewing a webhook's details, show a "Recent Deliveries" section. Each row shows: timestamp, status icon (checkmark for success, X for failed), response status code, and for failed deliveries a Retry button.

Failed deliveries show the attempt count (e.g., "2/3 retries") and the error message on hover or expansion.

### Tests

Test that queueing a delivery creates a record with Pending status. Test that the processor picks up pending deliveries and updates their status. Test exponential backoff timing calculations. Test that deliveries are marked Exhausted after max retries. Test the API endpoints for listing and retrying deliveries.

---

## 1.4 Source Attribution

**Goal:** When Things are imported from external systems, track where they came from for querying, deduplication, and provenance.

### Backend

**Database schema:** Add four nullable columns to the `things` table: `source_system` (e.g., "pocket", "github", "twitter"), `source_external_id` (the ID in the source system), `source_url` (link to the original), and `source_imported_at` (when we imported it). Add a unique index on (user_id, source_system, source_external_id) to prevent duplicate imports.

**Models:** Add a `Source` struct with fields for system, external_id, url, and imported_at. Add an optional `source` field to the `Thing` struct.

**API updates:** Accept an optional `source` object when creating Things via the API. Add a `source_system` query parameter to the list Things endpoint for filtering. Add a store method `get_thing_by_source(user_id, system, external_id)` for deduplication checks.

**Modified files:**
- `src/models/mod.rs` - Add Source struct, add source field to Thing
- `src/store/mod.rs` - Update Thing queries to handle source, add dedup query
- `src/api/mod.rs` - Accept source in create, add source_system filter to list

### UI

On Thing cards, if a source is present, show a small badge indicating the source (e.g., a Pocket icon, GitHub icon, or just text like "[from Pocket]"). If source_url is present, make it clickable to view the original.

In the Thing list, add a "Source" dropdown to the filter bar with options: All Sources, Pocket, GitHub, Twitter, Readwise, Manual. Selecting a source filters the list.

### Tests

Test creating a Thing with source data and retrieving it. Test the deduplication query returns existing Things. Test that importing the same external_id twice doesn't create duplicates. Test filtering by source_system returns correct results.

---

# Tier 2: Developer Tools

## 2.1 TypeScript SDK

**Goal:** Provide a typed TypeScript client that developers can use to interact with the API.

### Implementation

Create a new `sdks/typescript/` directory with a standard npm package structure. The SDK should be published to npm as `@tenant/sdk` (or similar).

**Type generation:** Use `openapi-typescript` to generate TypeScript interfaces from our OpenAPI spec. Run this as a build step to keep types in sync.

**Client class:** Create a `TenantClient` class that wraps fetch with authentication and error handling. It takes a `baseUrl` and `apiKey` in its constructor. Expose resource namespaces like `client.things`, `client.kinds`, `client.webhooks` with methods like `list()`, `get(id)`, `create(data)`, `update(id, data)`, `delete(id)`.

**Error handling:** Create a `TenantError` class that wraps API error responses and provides typed access to error code, message, and field.

**Package structure:**
- `package.json` - Package metadata, dependencies (none for runtime, just dev deps)
- `tsconfig.json` - TypeScript config
- `src/index.ts` - Main export
- `src/client.ts` - TenantClient class
- `src/types.ts` - Generated types from OpenAPI
- `src/resources/things.ts` - Things methods
- `src/resources/kinds.ts` - Kinds methods
- `src/resources/webhooks.ts` - Webhooks methods
- `README.md` - Usage documentation

### Tests

Write tests using Vitest that cover: listing things, creating a thing, updating a thing, deleting a thing, handling 404 errors, handling validation errors. Tests can use a mock server or run against a test instance.

---

## 2.2 Python SDK

**Goal:** Provide a Python client for developers who prefer Python for automation and data work.

### Implementation

Create a new `sdks/python/` directory with a standard Python package structure using pyproject.toml.

**Dependencies:** Use `httpx` for HTTP requests (modern, async-capable alternative to requests).

**Client class:** Create a `TenantClient` class similar to the TypeScript version. Use Python dataclasses or Pydantic models for type hints. Expose the same resource namespaces: `client.things.list()`, `client.things.create(...)`, etc.

**Package structure:**
- `pyproject.toml` - Package metadata and dependencies
- `tenant/__init__.py` - Package init
- `tenant/client.py` - TenantClient class
- `tenant/models.py` - Dataclasses for Thing, Kind, etc.
- `tenant/exceptions.py` - TenantError exception
- `tests/` - pytest tests
- `README.md` - Usage documentation

### Tests

Write pytest tests covering the same scenarios as TypeScript: CRUD operations, error handling, authentication.

---

## 2.3 Better Error Responses

**Goal:** Standardize error responses across all API endpoints with consistent structure and helpful messages.

### Backend

**Error structure:** All error responses should return JSON in this format:
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

The `code` field is machine-readable (validation_error, not_found, unauthorized, forbidden, rate_limited, internal_error). The `message` is human-readable. The `field` is optional, present for validation errors. The `details` is optional, for additional context.

**Implementation:** Create an `ApiError` struct that implements Actix's `ResponseError` trait. Provide factory methods like `ApiError::validation(field, message)`, `ApiError::not_found(resource)`, `ApiError::unauthorized()`, `ApiError::forbidden()`, `ApiError::rate_limited(retry_after)`, `ApiError::internal(message)`.

Update all handlers to return `Result<HttpResponse, ApiError>` and use these factory methods instead of ad-hoc error responses.

**New files:**
- `src/errors/mod.rs` - ApiError struct and implementations

**Modified files:**
- All API handlers to use the new error type

### Tests

Test that each error type returns the correct HTTP status code (400 for validation, 404 for not found, 401 for unauthorized, 403 for forbidden, 429 for rate limited, 500 for internal). Test that the JSON structure matches the expected format.

---

## 2.4 Rate Limit Headers

**Goal:** Include rate limit information in all API responses so clients know their current limits.

### Backend

**Rate limiter:** Create a `RateLimiter` struct that tracks request counts per key (user ID or IP) within a sliding window. The check method returns a result with: limit (max requests), remaining (requests left), reset (seconds until window resets), and whether the request is allowed.

**Headers:** Add these headers to all API responses:
- `X-RateLimit-Limit` - Maximum requests per window
- `X-RateLimit-Remaining` - Requests remaining in current window
- `X-RateLimit-Reset` - Seconds until the window resets

**Middleware:** Create middleware that checks the rate limiter before each request. If the limit is exceeded, return a 429 response with the rate_limited error. Otherwise, add the headers to the response.

**Configuration:** Default to 100 requests per minute for authenticated users, 20 per minute for unauthenticated. API keys might have different limits based on tier.

**New files:**
- `src/middleware/rate_limit.rs` - RateLimiter struct and middleware

**Modified files:**
- `src/main.rs` - Apply rate limit middleware to API routes

### Tests

Test that the rate limiter correctly counts requests and blocks after the limit. Test that headers are present on all responses. Test that blocked requests return 429 with proper error format.

---

# Tier 3: Integration Patterns

## 3.1 Inbound Webhook Endpoints

**Goal:** Let users create dedicated URLs that external systems can POST to, with automatic transformation into Things.

### Backend

**Database schema:** Create an `inbound_webhooks` table with: id, user_id, name, secret_token (for URL authentication), thing_type (what Kind to create), transform_rules (JSON), enabled, created_at.

**Transform rules:** The transform_rules JSON specifies how to map the incoming payload to a Thing:
- `content_field` - JSONPath to the field that becomes Thing content
- `metadata_mappings` - Map of metadata field names to JSONPaths
- `source_system` - What to put in source.system
- `external_id_field` - JSONPath to the field used for deduplication

**Endpoint:** Create `POST /api/webhooks/inbound/{id}` that:
1. Looks up the inbound webhook by ID
2. Verifies the token query parameter matches the secret_token
3. Parses the incoming JSON body
4. Applies transform rules to extract content and metadata
5. Checks for duplicates using source attribution
6. Creates the Thing (or returns "already imported" if duplicate)

**API endpoints:**
- `POST /api/inbound-webhooks` - Create an inbound webhook
- `GET /api/inbound-webhooks` - List user's inbound webhooks
- `GET /api/inbound-webhooks/{id}` - Get single (includes the full URL to give to external systems)
- `PATCH /api/inbound-webhooks/{id}` - Update
- `DELETE /api/inbound-webhooks/{id}` - Delete

**New files:**
- `src/models/inbound_webhook.rs` - InboundWebhook, TransformRules structs
- `src/store/inbound_webhooks.rs` - Database operations
- `src/api/inbound_webhooks.rs` - API handlers

### UI

Add an "Integrations" tab to Settings. Show a list of inbound webhooks with name, URL (with copy button), Thing type, and enabled status.

The Create/Edit modal has fields for:
- Name (e.g., "GitHub Issues")
- Thing type dropdown
- Transform rules section with:
  - "Content from" field (JSONPath like `/issue/body`)
  - Metadata mappings (key-value pairs with JSONPath values, add/remove buttons)
  - Source system name
  - External ID field (for deduplication)

Show the full webhook URL prominently so users can copy it to configure in external systems.

### Tests

Test that POSTing valid JSON to an inbound webhook creates a Thing. Test that transform rules correctly extract content and metadata. Test that deduplication works (same external_id returns "already imported"). Test that invalid tokens are rejected with 401.

---

## 3.2 Twitter Archive Import

**Goal:** Let users upload their Twitter data export ZIP file and import their tweets as Things.

### Backend

**Endpoint:** Create `POST /api/import/twitter` that accepts a multipart file upload.

**Parser:** The Twitter archive ZIP contains `data/tweets.js` which starts with `window.YTD.tweets.part0 = ` followed by a JSON array. Parse this to extract tweets.

**Import logic:**
1. Read the ZIP file
2. Find and parse `data/tweets.js`
3. For each tweet:
   - Skip retweets (content starts with "RT @")
   - Skip if already imported (check source.external_id)
   - Create a Thing with type "tweet", content as the tweet text, metadata including twitter_id, created_at, favorite_count, retweet_count
   - Set source.system = "twitter", source.external_id = tweet ID, source.url = twitter.com link
4. Return stats: imported count, skipped count, error count

**New files:**
- `src/api/import.rs` - Import endpoint handlers
- `src/import/mod.rs` - Import module
- `src/import/twitter.rs` - Twitter-specific parsing logic

### UI

Add an "Import" tab to Settings. Show an "Import from Twitter" section with:
- Brief instructions (go to twitter.com/settings/download_your_data, request archive, upload here)
- File picker for ZIP file
- Import button

During import, show a progress indicator (if we can stream progress) or a spinner.

After import, show results: how many imported, how many skipped (duplicates + retweets), any errors.

Add a "View imported tweets" link that navigates to the Things list filtered by source_system=twitter.

### Tests

Create a test ZIP file with sample tweet data. Test that import parses correctly and creates Things. Test that retweets are skipped. Test that running import twice doesn't create duplicates. Test error handling for invalid ZIP files.

---

## 3.3 Notion Export Import

**Goal:** Let users upload their Notion export ZIP and import pages as Things.

### Backend

**Endpoint:** Create `POST /api/import/notion` that accepts a multipart file upload.

**Parser:** Notion exports can be HTML or Markdown format. The ZIP contains files organized by database/page hierarchy.

**Import logic:**
1. Read the ZIP file
2. Find all .html and .md files
3. For each file:
   - Extract title from filename
   - Convert HTML to Markdown if needed (use a simple html-to-markdown converter)
   - Infer Thing type from folder structure or default to "note"
   - Create Thing with content as the Markdown, metadata including title and original path
   - Set source.system = "notion", source.external_id = file path
4. Return stats

**New files:**
- `src/import/notion.rs` - Notion-specific parsing logic

### UI

Similar to Twitter import: file picker, import button, progress indicator, results display.

### Tests

Create test ZIP with sample Notion export structure. Test HTML and Markdown files are both handled. Test that folder structure is preserved in metadata. Test deduplication.

---

# Implementation Order

## Phase 1: API Foundation (Weeks 1-3)

Focus on the core infrastructure that other features depend on.

1. **Better error responses** - Clean up error handling first since we'll be adding many new endpoints
2. **Source attribution** - Simple schema change that's needed for imports
3. **Rate limit headers** - Quick middleware addition
4. **OpenAPI spec** - Foundation for SDK generation

## Phase 2: Webhooks (Weeks 4-6)

Build the complete webhook system.

1. **Webhook subscriptions** - Core subscription management and fire-and-forget dispatch
2. **Webhook delivery queue** - Add retry logic and delivery tracking

## Phase 3: Developer Tools (Weeks 7-9)

Make the API easy to use programmatically.

1. **TypeScript SDK** - Primary audience, can start using immediately
2. **Python SDK** - Secondary audience, similar structure

## Phase 4: Integrations (Weeks 10-12)

Enable data import and external system connections.

1. **Inbound webhook endpoints** - Enable Zapier/n8n/custom integrations
2. **Twitter archive import** - Popular request, good test of import pipeline
3. **Notion export import** - Second import source

---

# Files Summary

## New Backend Files

| File | Purpose |
|------|---------|
| `src/api/openapi.rs` | OpenAPI document generation |
| `src/errors/mod.rs` | Standardized API errors |
| `src/middleware/rate_limit.rs` | Rate limiting |
| `src/models/webhook.rs` | Webhook subscription and delivery models |
| `src/models/inbound_webhook.rs` | Inbound webhook models |
| `src/store/webhooks.rs` | Webhook database operations |
| `src/store/inbound_webhooks.rs` | Inbound webhook database operations |
| `src/webhooks/mod.rs` | Webhook module |
| `src/webhooks/dispatcher.rs` | HTTP dispatch with HMAC signing |
| `src/webhooks/processor.rs` | Background delivery queue processor |
| `src/api/webhooks.rs` | Webhook API endpoints |
| `src/api/inbound_webhooks.rs` | Inbound webhook API endpoints |
| `src/api/import.rs` | Import API endpoints |
| `src/import/mod.rs` | Import module |
| `src/import/twitter.rs` | Twitter archive parser |
| `src/import/notion.rs` | Notion export parser |

## New SDK Files

| Directory | Purpose |
|-----------|---------|
| `sdks/typescript/` | TypeScript SDK npm package |
| `sdks/python/` | Python SDK pip package |

## Database Migrations

| Migration | Purpose |
|-----------|---------|
| `add_source_to_things` | Add source_* columns to things table |
| `add_webhook_subscriptions` | Create webhook_subscriptions table |
| `add_webhook_deliveries` | Create webhook_deliveries table |
| `add_inbound_webhooks` | Create inbound_webhooks table |

## Frontend Changes

All UI changes are in `web/src/App.tsx`:

- Add "Webhooks" tab to Settings with subscription list and create/edit modal
- Add webhook detail view with delivery history
- Add "Integrations" tab with inbound webhook management
- Add "Import" tab with Twitter and Notion importers
- Add source badge to Thing cards
- Add source filter to Thing list
