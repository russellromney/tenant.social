# Integrations UI Implementation Plan

## Overview

Add an Integrations page to Settings that provides a dashboard view of outbound webhooks (event subscriptions) and inbound webhooks (data importers). The UI is primarily for viewing/managing integrations created via API, with secondary support for manual creation.

---

## Backend APIs (Already Implemented)

### Outbound Webhooks (Subscriptions)
- `GET /api/webhooks` - List all subscriptions
- `POST /api/webhooks` - Create subscription
- `GET /api/webhooks/{id}` - Get subscription details
- `PUT /api/webhooks/{id}` - Update subscription
- `DELETE /api/webhooks/{id}` - Delete subscription
- `POST /api/webhooks/{id}/test` - Send test event
- `GET /api/webhooks/{id}/deliveries` - List recent deliveries

### Inbound Webhooks
- `GET /api/webhooks/inbound` - List all inbound webhooks
- `POST /api/webhooks/inbound` - Create inbound webhook
- `GET /api/webhooks/inbound/{id}` - Get inbound webhook
- `PUT /api/webhooks/inbound/{id}` - Update inbound webhook
- `DELETE /api/webhooks/inbound/{id}` - Delete inbound webhook
- `POST /api/webhooks/receive/{id}?token={secret}` - Receive data (external)

---

## UI Components

### 1. IntegrationsPage

Main page component accessible from Settings navigation.

```
/settings/integrations
```

**Layout:**
- Header: "Integrations"
- Two sections with headers: "Outbound Webhooks" and "Inbound Webhooks"
- Empty states for each section
- "Add" buttons (secondary, for power users)

### 2. OutboundWebhookCard

Displays a single outbound webhook subscription.

**Fields shown:**
- Name (or URL if no name)
- URL (truncated with tooltip)
- Event types as pills/badges
- Enabled/disabled toggle
- Health indicator (green/yellow/red dot)
- Stats: "47 sent, 2 failed (24h)"
- Last triggered: "2m ago"

**Actions:**
- Toggle enabled/disabled
- "Test" button (inline result)
- "Delete" button (with confirmation)
- Expand to show details

**Expanded view:**
- Full URL
- Signing secret (masked, copy button)
- Event type filter config
- Recent deliveries (last 5)

### 3. InboundWebhookCard

Displays a single inbound webhook.

**Fields shown:**
- Name
- Source system badge
- Endpoint URL (copy button)
- Token: `****...abc` (reveal button, copy button)
- Default thing type
- Stats: "12 items imported"

**Actions:**
- Enable/disable toggle
- "Delete" button (with confirmation)
- Expand to show details

**Expanded view:**
- Full endpoint URL with token
- Default visibility setting
- Recent imports (last 5 things created)

### 4. WebhookTestResult

Ephemeral inline component showing test results.

**States:**
- Loading: spinner
- Success: green checkmark, status code, response time
- Failed: red X, error message

**Behavior:**
- Appears below webhook card after test
- Auto-dismisses after 10 seconds
- Can be manually dismissed

### 5. CreateOutboundWebhookModal

Form for manually creating outbound webhooks.

**Fields:**
- Name (optional)
- URL (required)
- Event types (checkboxes): thing.created, thing.updated, thing.deleted, comment.created
- Thing type filter (optional, dropdown of user's Kinds)
- Signing secret (auto-generated, with regenerate button)

### 6. CreateInboundWebhookModal

Form for manually creating inbound webhooks.

**Fields:**
- Name (required)
- Source system identifier (text input, e.g., "github", "notion")
- Default thing type (dropdown of user's Kinds)
- Default visibility (dropdown: public, private, unlisted)

**On create:**
- Show the generated endpoint URL and token
- Prompt to copy before closing

---

## TypeScript Interfaces

```typescript
interface OutboundWebhook {
  id: string
  name: string
  url: string
  event_types: string[]  // ["thing.created", "comment.created"]
  filter_thing_type?: string
  signing_secret: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface WebhookDelivery {
  id: string
  subscription_id: string
  status: 'pending' | 'delivered' | 'failed' | 'exhausted'
  attempts: number
  last_attempt_at: string
  response_code?: number
  error?: string
}

interface InboundWebhook {
  id: string
  name: string
  source_system: string
  default_thing_type: string
  default_visibility: string
  token_prefix: string  // First 8 chars for display
  secret_token?: string  // Only on creation
  enabled: boolean
  created_at: string
  updated_at: string
}

interface WebhookTestResult {
  success: boolean
  status_code?: number
  response_time_ms?: number
  error?: string
}
```

---

## Implementation Steps

### Phase 1: Basic List Views
1. Add `/settings/integrations` route
2. Add "Integrations" link to Settings navigation
3. Create IntegrationsPage component with two sections
4. Fetch and display outbound webhooks list
5. Fetch and display inbound webhooks list
6. Add empty states

### Phase 2: Outbound Webhook Features
1. OutboundWebhookCard component
2. Enable/disable toggle (PUT request)
3. Delete with confirmation
4. Expand/collapse for details
5. Test webhook button with inline result
6. CreateOutboundWebhookModal

### Phase 3: Inbound Webhook Features
1. InboundWebhookCard component
2. Copy endpoint URL button
3. Reveal/copy token button
4. Enable/disable toggle
5. Delete with confirmation
6. CreateInboundWebhookModal with token display

### Phase 4: Polish
1. Health indicators based on recent delivery status
2. Aggregate stats (success/fail counts)
3. Recent deliveries list in expanded view
4. Loading states
5. Error handling

---

## File Changes

| File | Changes |
|------|---------|
| `web/src/App.tsx` | Add IntegrationsPage, route, Settings nav link |
| (same file) | OutboundWebhookCard component |
| (same file) | InboundWebhookCard component |
| (same file) | CreateOutboundWebhookModal |
| (same file) | CreateInboundWebhookModal |
| (same file) | WebhookTestResult component |

---

## UI Patterns

### Consistent with existing app:
- Use `theme` object for colors
- Modal pattern from KindEditModal
- Card style from ThingCard
- Toggle switches (checkbox styled)
- Inline actions on hover (desktop) or always visible (mobile)
- Toast-style notifications for actions

### New patterns:
- Expandable cards (click to expand details)
- Copy-to-clipboard buttons
- Masked secrets with reveal
- Health indicator dots
- Ephemeral test results

---

## API Response Handling

The backend returns arrays directly (not wrapped in objects):
- `GET /api/webhooks` returns `[{...}, {...}]`
- `GET /api/webhooks/inbound` returns `[{...}, {...}]`

Test endpoint returns:
- `POST /api/webhooks/{id}/test` returns `{ success: bool, ... }`

---

## Security Considerations

1. Signing secrets are only shown once (on create) or masked
2. Inbound tokens shown masked with reveal option
3. Delete requires confirmation
4. All endpoints require authentication
