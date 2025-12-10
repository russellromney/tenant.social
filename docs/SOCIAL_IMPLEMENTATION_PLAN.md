# Social Features Implementation Plan

## Overview

tenant.social is a **personal event-driven data platform**. Events are ephemeral triggers that flow through the system, get processed, cause effects, and are discarded. The social features (notifications, reactions, comments, mentions) are built on this event-driven foundation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         EVENT SOURCES                           │
├─────────────┬─────────────┬─────────────┬─────────────┬────────┤
│ First-party │   Friends   │  Webhooks   │    APIs     │  Cron  │
│  (UI/App)   │ (Federation)│  (Inbound)  │ (External)  │ (Time) │
└──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┴───┬────┘
       │             │             │             │          │
       └─────────────┴─────────────┴─────────────┴──────────┘
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │     EVENT (ephemeral)    │
                    │  { type, source, actor,  │
                    │    payload, timestamp }  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │   SUBSCRIPTION MATCHER   │
                    │  "who cares about this?" │
                    └────────────┬─────────────┘
                                 │
       ┌─────────────┬───────────┴───────────┬─────────────┐
       ▼             ▼                       ▼             ▼
┌────────────┐ ┌──────────┐           ┌─────────┐ ┌───────────┐
│   Send     │ │ Deliver  │           │ Create/ │ │   Run     │
│Notification│ │ Webhook  │           │ Update  │ │  Action   │
│ (outbound) │ │  (POST)  │           │  Thing  │ │  (code)   │
└─────┬──────┘ └────┬─────┘           └────┬────┘ └─────┬─────┘
      │             │                      │            │
      ▼             ▼                      ▼            ▼
  [try send]   [fire&forget]          [persisted]  [side-effect]
      │
      ▼
┌─────────────────────────────────┐
│  Remote node responds:          │
│  - "accepted" → done            │
│  - "rejected" → discard         │
│  - timeout    → queue retry     │
└─────────────────────────────────┘
```

## Key Principles

1. **Events are ephemeral** - processed and discarded, not stored
2. **Recipient decides** - notification settings live on the receiver's node
3. **Try then respect** - send notification, get yes/no response, respect it
4. **Subscriptions drive actions** - rules match events to effects

## Current State (Already Built)

- Follows system (follow/unfollow, followers list, following list, mutuals)
- Friend feed (Things from followed users with `friends`/`public` visibility)
- Federation endpoint (`/api/fed/things/{user_id}`)
- Visibility levels (`private`, `friends`, `public`)

---

## Phase 1: Event & Notification System

### Database Schema

```sql
-- ============================================================
-- SENDER SIDE: Subscriptions and outbound delivery
-- ============================================================

-- Subscriptions: what happens when events occur
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT,                       -- Human readable name

    -- Event matching
    event_type TEXT NOT NULL,        -- 'follow.created', 'reaction.added', '*'
    source_type TEXT,                -- 'first_party', 'friend', 'webhook', NULL = any
    source_id TEXT,                  -- Specific source ID, NULL = any

    -- Action to take
    action_type TEXT NOT NULL,       -- 'notification', 'webhook', 'create_thing'
    action_config TEXT NOT NULL,     -- JSON: action-specific configuration

    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_event_type ON subscriptions(event_type);

-- Delivery queue: pending/retry outbound deliveries
CREATE TABLE IF NOT EXISTS delivery_queue (
    id TEXT PRIMARY KEY,

    -- What to deliver
    delivery_type TEXT NOT NULL,     -- 'notification', 'webhook'
    destination TEXT NOT NULL,       -- URL endpoint
    payload TEXT NOT NULL,           -- JSON payload

    -- State
    status TEXT DEFAULT 'pending',   -- 'pending', 'delivered', 'rejected', 'failed'
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    next_attempt_at TEXT,
    last_error TEXT,

    created_at TEXT NOT NULL,
    delivered_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_delivery_queue_status ON delivery_queue(status);
CREATE INDEX IF NOT EXISTS idx_delivery_queue_next_attempt ON delivery_queue(next_attempt_at)
    WHERE status = 'pending';

-- ============================================================
-- RECEIVER SIDE: Settings and stored notifications
-- ============================================================

-- Notification settings: what types you accept/reject
CREATE TABLE IF NOT EXISTS notification_settings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    notification_type TEXT NOT NULL, -- 'follow', 'reaction', 'comment', 'mention', '*'
    enabled INTEGER DEFAULT 1,       -- 1 = accept, 0 = reject
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, notification_type)
);

CREATE INDEX IF NOT EXISTS idx_notification_settings_user ON notification_settings(user_id);

-- Notifications: accepted notifications
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,           -- Recipient

    -- Type and source
    notification_type TEXT NOT NULL, -- 'follow', 'reaction', 'comment', 'mention'
    actor_id TEXT,                   -- Who triggered it
    actor_type TEXT,                 -- 'user', 'webhook', 'system'

    -- Related resource
    resource_type TEXT,              -- 'thing', 'follow', 'comment'
    resource_id TEXT,

    -- Display content
    title TEXT,
    body TEXT,
    url TEXT,
    metadata TEXT,                   -- JSON: extra rendering data

    -- State
    read INTEGER DEFAULT 0,

    created_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications(user_id, read);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);
```

### Rust Models

```rust
// ============================================================
// Event (ephemeral - not stored)
// ============================================================

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,          // 'follow.created', 'reaction.added', etc.
    pub source_type: String,         // 'first_party', 'friend', 'webhook'
    pub source_id: Option<String>,   // Specific source ID
    pub actor_id: String,            // Who triggered it
    pub actor_type: String,          // 'user', 'system'
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub payload: Option<HashMap<String, serde_json::Value>>,
    pub timestamp: DateTime<Utc>,
}

// ============================================================
// Subscription (stored)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub event_type: String,
    pub source_type: Option<String>,
    pub source_id: Option<String>,
    pub action_type: String,
    pub action_config: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================
// Delivery Queue (stored)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryQueueItem {
    pub id: String,
    pub delivery_type: String,       // 'notification', 'webhook'
    pub destination: String,         // URL
    pub payload: String,             // JSON string
    pub status: String,              // 'pending', 'delivered', 'rejected', 'failed'
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Rejected,
    Failed,
}

// ============================================================
// Notification Settings (stored - receiver side)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub id: String,
    pub user_id: String,
    pub notification_type: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================================
// Notification (stored - receiver side)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub notification_type: String,
    pub actor_id: Option<String>,
    pub actor_type: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

// ============================================================
// Inbound notification request/response
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundNotificationRequest {
    pub notification_type: String,
    pub actor_id: Option<String>,
    pub actor_type: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundNotificationResponse {
    pub status: String,  // "accepted" or "rejected"
}
```

### Event Processing Logic

```rust
/// Process an ephemeral event
pub fn process_event(store: &Store, event: Event) -> Vec<ActionResult> {
    // 1. Find matching subscriptions
    let subscriptions = store.find_matching_subscriptions(
        &event.event_type,
        event.source_type.as_deref(),
        event.source_id.as_deref(),
    );

    // 2. Execute each subscription's action
    subscriptions
        .iter()
        .filter(|s| s.enabled)
        .map(|sub| execute_action(store, &event, sub))
        .collect()
}

/// Execute a subscription action
fn execute_action(store: &Store, event: &Event, sub: &Subscription) -> ActionResult {
    match sub.action_type.as_str() {
        "notification" => send_notification(store, event, &sub.action_config),
        "webhook" => send_webhook(store, event, &sub.action_config),
        "create_thing" => create_thing_from_event(store, event, &sub.action_config),
        _ => ActionResult::Error(format!("Unknown action type: {}", sub.action_type)),
    }
}

/// Send notification to recipient
fn send_notification(
    store: &Store,
    event: &Event,
    config: &HashMap<String, serde_json::Value>,
) -> ActionResult {
    // Resolve recipient from config or event
    let recipient_endpoint = resolve_recipient_endpoint(config, event);

    // Build notification payload
    let payload = InboundNotificationRequest {
        notification_type: config.get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        actor_id: Some(event.actor_id.clone()),
        actor_type: Some(event.actor_type.clone()),
        resource_type: event.resource_type.clone(),
        resource_id: event.resource_id.clone(),
        title: config.get("title").and_then(|v| v.as_str()).map(String::from),
        body: config.get("body").and_then(|v| v.as_str()).map(String::from),
        url: config.get("url").and_then(|v| v.as_str()).map(String::from),
        metadata: event.payload.clone(),
    };

    // Try to deliver
    match try_deliver_notification(&recipient_endpoint, &payload) {
        DeliveryResult::Accepted => ActionResult::Success,
        DeliveryResult::Rejected => ActionResult::Rejected,
        DeliveryResult::Failed(err) => {
            // Queue for retry
            store.queue_delivery(
                "notification",
                &recipient_endpoint,
                &serde_json::to_string(&payload).unwrap(),
            );
            ActionResult::Queued
        }
    }
}

/// Try to deliver notification to remote endpoint
fn try_deliver_notification(endpoint: &str, payload: &InboundNotificationRequest) -> DeliveryResult {
    // POST to {endpoint}/api/notifications/inbound
    // Parse response: { "status": "accepted" } or { "status": "rejected" }
    // Return appropriate DeliveryResult
}

#[derive(Debug)]
pub enum ActionResult {
    Success,
    Rejected,
    Queued,
    Error(String),
}

#[derive(Debug)]
pub enum DeliveryResult {
    Accepted,
    Rejected,
    Failed(String),
}
```

### API Endpoints

**Sender side (outbound):**
```
GET  /api/subscriptions              - List your subscriptions
POST /api/subscriptions              - Create subscription
PUT  /api/subscriptions/{id}         - Update subscription
DELETE /api/subscriptions/{id}       - Delete subscription

GET  /api/delivery-queue             - View pending deliveries (debug)
POST /api/delivery-queue/{id}/retry  - Manually retry a delivery
```

**Receiver side (inbound):**
```
POST /api/notifications/inbound      - Receive notification (returns accepted/rejected)

GET  /api/notifications              - List your notifications
GET  /api/notifications/unread-count - Get unread count
PUT  /api/notifications/{id}/read    - Mark as read
PUT  /api/notifications/read-all     - Mark all as read
DELETE /api/notifications/{id}       - Delete notification

GET  /api/notifications/settings     - Get your notification settings
PUT  /api/notifications/settings/{type} - Update setting for a type
```

### Inbound Notification Endpoint

```rust
/// POST /api/notifications/inbound
/// Receives notification from remote node, returns accepted/rejected
pub async fn receive_notification(
    state: web::Data<AppState>,
    req: web::Json<InboundNotificationRequest>,
) -> impl Responder {
    // Get the recipient user (owner of this node)
    let user = match state.store.get_owner() {
        Ok(u) => u,
        Err(_) => return HttpResponse::InternalServerError()
            .json(InboundNotificationResponse { status: "error".to_string() }),
    };

    // Check if user has this notification type blocked
    let settings = state.store
        .get_notification_settings(&user.id, &req.notification_type)
        .ok();

    if let Some(s) = settings {
        if !s.enabled {
            return HttpResponse::Ok()
                .json(InboundNotificationResponse { status: "rejected".to_string() });
        }
    }
    // No settings = default enabled

    // Create the notification
    let notification = Notification {
        id: Uuid::new_v4().to_string(),
        user_id: user.id,
        notification_type: req.notification_type.clone(),
        actor_id: req.actor_id.clone(),
        actor_type: req.actor_type.clone(),
        resource_type: req.resource_type.clone(),
        resource_id: req.resource_id.clone(),
        title: req.title.clone(),
        body: req.body.clone(),
        url: req.url.clone(),
        metadata: req.metadata.clone(),
        read: false,
        created_at: Utc::now(),
    };

    if let Err(e) = state.store.create_notification(&notification) {
        return HttpResponse::InternalServerError()
            .json(InboundNotificationResponse { status: "error".to_string() });
    }

    HttpResponse::Ok()
        .json(InboundNotificationResponse { status: "accepted".to_string() })
}
```

### Default Subscriptions

When a user is created, set up default subscriptions for social events:

```rust
fn create_default_subscriptions(store: &Store, user_id: &str) {
    let defaults = vec![
        ("follow.created", "notification", json!({
            "type": "follow",
            "title_template": "{{actor_name}} followed you"
        })),
        ("reaction.added", "notification", json!({
            "type": "reaction",
            "title_template": "{{actor_name}} reacted to your post"
        })),
        ("comment.created", "notification", json!({
            "type": "comment",
            "title_template": "{{actor_name}} commented on your post"
        })),
        ("mention.created", "notification", json!({
            "type": "mention",
            "title_template": "{{actor_name}} mentioned you"
        })),
    ];

    for (event_type, action_type, config) in defaults {
        store.create_subscription(&Subscription {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            name: Some(format!("Default: {}", event_type)),
            event_type: event_type.to_string(),
            source_type: None,
            source_id: None,
            action_type: action_type.to_string(),
            action_config: serde_json::from_value(config).unwrap(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    }
}
```

### Implementation Tasks

1. Add tables to schema in `store/mod.rs`
2. Add models to `models/mod.rs`
3. Add store methods:
   - Subscriptions: `create_subscription`, `list_subscriptions`, `update_subscription`, `delete_subscription`, `find_matching_subscriptions`
   - Delivery queue: `queue_delivery`, `get_pending_deliveries`, `update_delivery_status`
   - Notification settings: `get_notification_settings`, `update_notification_settings`
   - Notifications: `create_notification`, `list_notifications`, `get_unread_count`, `mark_read`, `mark_all_read`, `delete_notification`
4. Add event processing module
5. Add API endpoints
6. Update `add_friend` to emit `follow.created` event
7. Add default subscriptions on user creation

---

## Phase 2: Reactions

### Constraints
- One `like` per user per Thing
- One emoji reaction per user per Thing
- Max 2 reactions per user per Thing (1 like + 1 emoji)

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS reactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    thing_id TEXT NOT NULL,
    reaction_type TEXT NOT NULL,     -- 'like', 'heart', 'fire', 'laugh', 'sad', 'celebrate'
    created_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE,
    UNIQUE(user_id, thing_id, reaction_type)
);

CREATE INDEX IF NOT EXISTS idx_reactions_thing ON reactions(thing_id);
CREATE INDEX IF NOT EXISTS idx_reactions_user_thing ON reactions(user_id, thing_id);
```

### Event Integration

When reaction is added, emit event:
```rust
process_event(store, Event {
    event_type: "reaction.added".to_string(),
    source_type: "first_party".to_string(),
    source_id: None,
    actor_id: user_id.to_string(),
    actor_type: "user".to_string(),
    resource_type: Some("thing".to_string()),
    resource_id: Some(thing_id.to_string()),
    payload: Some(hashmap!{ "reaction_type" => reaction_type }),
    timestamp: Utc::now(),
});
```

---

## Phase 3: Comments

### Design
- Comments are Things with `type="comment"`
- Max thread depth of 3
- One top-level comment per user per Thing

### Metadata Structure

```json
{
  "parent_id": "thing_or_comment_id",
  "root_id": "original_thing_id",
  "depth": 0
}
```

### Event Integration

```rust
// Top-level comment
process_event(store, Event {
    event_type: "comment.created".to_string(),
    resource_type: Some("thing".to_string()),
    resource_id: Some(thing_id.to_string()),
    ...
});

// Reply to comment
process_event(store, Event {
    event_type: "reply.created".to_string(),
    resource_type: Some("comment".to_string()),
    resource_id: Some(parent_comment_id.to_string()),
    ...
});
```

---

## Phase 4: Mentions

### Design
- Parse `@username` in content
- Emit `mention.created` event for each valid mentioned user

### Event Integration

```rust
for username in extract_mentions(&content) {
    if let Ok(user) = store.get_user_by_username(&username) {
        process_event(store, Event {
            event_type: "mention.created".to_string(),
            resource_type: Some("thing".to_string()),
            resource_id: Some(thing_id.to_string()),
            payload: Some(hashmap!{
                "mentioned_user_id" => user.id,
                "mentioned_username" => username,
            }),
            ...
        });
    }
}
```

---

## Testing Checklist

### Phase 1: Event & Notification System
- [ ] Subscription CRUD works
- [ ] Event matching finds correct subscriptions
- [ ] Inbound notification accepted when enabled
- [ ] Inbound notification rejected when blocked
- [ ] Failed delivery queued for retry
- [ ] Notification list returns user's notifications
- [ ] Unread count accurate
- [ ] Mark read works
- [ ] Settings can be updated
- [ ] Default subscriptions created for new users

### Phase 2: Reactions
- [ ] Add reaction works
- [ ] Duplicate reaction blocked
- [ ] Remove reaction works
- [ ] Event emitted on add
- [ ] Notification sent to Thing owner

### Phase 3: Comments
- [ ] Create comment works
- [ ] Depth limit enforced
- [ ] One top-level per user enforced
- [ ] Event emitted (comment vs reply)

### Phase 4: Mentions
- [ ] @username parsed correctly
- [ ] Event emitted for valid mention
- [ ] Invalid username ignored
- [ ] Self-mention doesn't trigger event
