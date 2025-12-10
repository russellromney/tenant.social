//! Event Processing Module
//!
//! Events are ephemeral triggers that flow through the system.
//! They are NOT stored - processed and discarded.
//!
//! Flow: Event -> Find matching Subscriptions -> Execute Actions
//!
//! Actions can be:
//! - `notification`: Create a local notification (instant) or try to deliver to remote node
//! - `webhook`: POST to external URL
//! - `create_thing`: Create a Thing from the event data

use chrono::Utc;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::models::*;
use crate::store::Store;

/// Result type for event processing
pub type EventResult<T> = Result<T, EventError>;

#[derive(Debug)]
pub enum EventError {
    Store(String),
    Delivery(String),
    Config(String),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::Store(msg) => write!(f, "Store error: {}", msg),
            EventError::Delivery(msg) => write!(f, "Delivery error: {}", msg),
            EventError::Config(msg) => write!(f, "Config error: {}", msg),
        }
    }
}

/// Event processor handles event routing and action execution
pub struct EventProcessor {
    store: Arc<Store>,
    http_client: Client,
}

impl EventProcessor {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    /// Process an event: find matching subscriptions and execute actions
    pub async fn process(&self, event: &Event) -> EventResult<ProcessResult> {
        let mut result = ProcessResult::default();

        // Find all subscriptions that match this event
        let subscriptions = self.store.find_matching_subscriptions(
            &event.event_type,
            Some(&event.source_type),
            event.source_id.as_deref(),
        ).map_err(|e| EventError::Store(e.to_string()))?;

        result.subscriptions_matched = subscriptions.len();

        // Execute each subscription's action
        for sub in subscriptions {
            match self.execute_action(&sub, event).await {
                Ok(action_result) => {
                    result.actions_executed += 1;
                    if action_result.success {
                        result.actions_succeeded += 1;
                    }
                    result.action_results.push(action_result);
                }
                Err(e) => {
                    result.action_results.push(ActionResult {
                        subscription_id: sub.id.clone(),
                        action_type: sub.action_type.clone(),
                        success: false,
                        error: Some(e.to_string()),
                        queued: false,
                    });
                }
            }
        }

        Ok(result)
    }

    /// Execute a single subscription action
    async fn execute_action(&self, sub: &Subscription, event: &Event) -> EventResult<ActionResult> {
        match sub.action_type.as_str() {
            "notification" => self.execute_notification_action(sub, event).await,
            "webhook" => self.execute_webhook_action(sub, event).await,
            "create_thing" => self.execute_create_thing_action(sub, event).await,
            _ => Err(EventError::Config(format!("Unknown action type: {}", sub.action_type))),
        }
    }

    /// Execute a notification action
    /// If destination is local (same user_id as subscription owner), create notification directly.
    /// If destination is remote, try to deliver and queue on failure.
    async fn execute_notification_action(&self, sub: &Subscription, event: &Event) -> EventResult<ActionResult> {
        let config = &sub.action_config;

        // Get destination - defaults to local (subscription owner)
        let destination = config.get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("local");

        if destination == "local" {
            // Create local notification directly
            self.create_local_notification(sub, event)?;
            return Ok(ActionResult {
                subscription_id: sub.id.clone(),
                action_type: "notification".to_string(),
                success: true,
                error: None,
                queued: false,
            });
        }

        // Remote notification - try to deliver
        let notification_type = config.get("notification_type")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.event_type);

        let request = InboundNotificationRequest {
            notification_type: notification_type.to_string(),
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
        match self.deliver_notification(destination, &request).await {
            Ok(response) => {
                if response.status == "accepted" {
                    Ok(ActionResult {
                        subscription_id: sub.id.clone(),
                        action_type: "notification".to_string(),
                        success: true,
                        error: None,
                        queued: false,
                    })
                } else {
                    // Rejected - don't queue, just mark as rejected
                    Ok(ActionResult {
                        subscription_id: sub.id.clone(),
                        action_type: "notification".to_string(),
                        success: false,
                        error: Some("Notification rejected by recipient".to_string()),
                        queued: false,
                    })
                }
            }
            Err(e) => {
                // Delivery failed - queue for retry
                let payload = serde_json::to_string(&request)
                    .map_err(|e| EventError::Delivery(e.to_string()))?;

                self.store.queue_delivery("notification", destination, &payload)
                    .map_err(|e| EventError::Store(e.to_string()))?;

                Ok(ActionResult {
                    subscription_id: sub.id.clone(),
                    action_type: "notification".to_string(),
                    success: false,
                    error: Some(e.to_string()),
                    queued: true,
                })
            }
        }
    }

    /// Create a local notification for the subscription owner
    fn create_local_notification(&self, sub: &Subscription, event: &Event) -> EventResult<()> {
        let config = &sub.action_config;

        // Check if user accepts this notification type
        let notification_type = config.get("notification_type")
            .and_then(|v| v.as_str())
            .unwrap_or(&event.event_type);

        // Check user's notification settings
        if let Ok(settings) = self.store.get_notification_settings(&sub.user_id, notification_type) {
            if !settings.enabled {
                // User has disabled this notification type - skip silently
                return Ok(());
            }
        }
        // If no settings exist, default to accepting

        let notification = Notification {
            id: Uuid::new_v4().to_string(),
            user_id: sub.user_id.clone(),
            notification_type: notification_type.to_string(),
            actor_id: Some(event.actor_id.clone()),
            actor_type: Some(event.actor_type.clone()),
            resource_type: event.resource_type.clone(),
            resource_id: event.resource_id.clone(),
            title: config.get("title").and_then(|v| v.as_str()).map(String::from),
            body: config.get("body").and_then(|v| v.as_str()).map(String::from),
            url: config.get("url").and_then(|v| v.as_str()).map(String::from),
            metadata: event.payload.clone(),
            read: false,
            created_at: Utc::now(),
        };

        self.store.create_notification(&notification)
            .map_err(|e| EventError::Store(e.to_string()))
    }

    /// Deliver a notification to a remote endpoint
    async fn deliver_notification(
        &self,
        destination: &str,
        request: &InboundNotificationRequest,
    ) -> EventResult<InboundNotificationResponse> {
        let url = format!("{}/api/notifications/inbound", destination.trim_end_matches('/'));

        let response = self.http_client
            .post(&url)
            .json(request)
            .send()
            .await
            .map_err(|e| EventError::Delivery(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            return Err(EventError::Delivery(format!(
                "HTTP {} from {}",
                response.status(),
                destination
            )));
        }

        response.json::<InboundNotificationResponse>()
            .await
            .map_err(|e| EventError::Delivery(format!("JSON parse error: {}", e)))
    }

    /// Execute a webhook action - POST event data to external URL
    async fn execute_webhook_action(&self, sub: &Subscription, event: &Event) -> EventResult<ActionResult> {
        let config = &sub.action_config;

        let url = config.get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| EventError::Config("Webhook URL not configured".to_string()))?;

        // Build webhook payload
        let payload = serde_json::json!({
            "event_type": event.event_type,
            "source_type": event.source_type,
            "source_id": event.source_id,
            "actor_id": event.actor_id,
            "actor_type": event.actor_type,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "payload": event.payload,
            "timestamp": event.timestamp.to_rfc3339(),
        });

        // Try to deliver
        let result = self.http_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Tenant-Event", &event.event_type)
            .json(&payload)
            .send()
            .await;

        match result {
            Ok(response) if response.status().is_success() => {
                Ok(ActionResult {
                    subscription_id: sub.id.clone(),
                    action_type: "webhook".to_string(),
                    success: true,
                    error: None,
                    queued: false,
                })
            }
            Ok(response) => {
                // Non-success status - queue for retry
                let payload_str = serde_json::to_string(&payload)
                    .map_err(|e| EventError::Delivery(e.to_string()))?;

                self.store.queue_delivery("webhook", url, &payload_str)
                    .map_err(|e| EventError::Store(e.to_string()))?;

                Ok(ActionResult {
                    subscription_id: sub.id.clone(),
                    action_type: "webhook".to_string(),
                    success: false,
                    error: Some(format!("HTTP {}", response.status())),
                    queued: true,
                })
            }
            Err(e) => {
                // Network error - queue for retry
                let payload_str = serde_json::to_string(&payload)
                    .map_err(|e| EventError::Delivery(e.to_string()))?;

                self.store.queue_delivery("webhook", url, &payload_str)
                    .map_err(|e| EventError::Store(e.to_string()))?;

                Ok(ActionResult {
                    subscription_id: sub.id.clone(),
                    action_type: "webhook".to_string(),
                    success: false,
                    error: Some(e.to_string()),
                    queued: true,
                })
            }
        }
    }

    /// Execute a create_thing action - create a Thing from event data
    async fn execute_create_thing_action(&self, sub: &Subscription, event: &Event) -> EventResult<ActionResult> {
        let config = &sub.action_config;

        let thing_type = config.get("thing_type")
            .and_then(|v| v.as_str())
            .unwrap_or("event");

        let content = config.get("content_template")
            .and_then(|v| v.as_str())
            .map(|template| self.render_template(template, event))
            .unwrap_or_else(|| format!("{}: {}", event.event_type, event.actor_id));

        let visibility = config.get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("private");

        // Build metadata from event
        let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
        metadata.insert("event_type".to_string(), serde_json::json!(event.event_type));
        metadata.insert("source_type".to_string(), serde_json::json!(event.source_type));
        if let Some(ref source_id) = event.source_id {
            metadata.insert("source_id".to_string(), serde_json::json!(source_id));
        }
        if let Some(ref resource_type) = event.resource_type {
            metadata.insert("resource_type".to_string(), serde_json::json!(resource_type));
        }
        if let Some(ref resource_id) = event.resource_id {
            metadata.insert("resource_id".to_string(), serde_json::json!(resource_id));
        }
        if let Some(ref payload) = event.payload {
            metadata.insert("event_payload".to_string(), serde_json::json!(payload));
        }

        let mut thing = Thing {
            id: String::new(),
            user_id: sub.user_id.clone(),
            thing_type: thing_type.to_string(),
            content,
            metadata,
            visibility: visibility.to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };

        self.store.create_thing(&mut thing)
            .map_err(|e| EventError::Store(e.to_string()))?;

        Ok(ActionResult {
            subscription_id: sub.id.clone(),
            action_type: "create_thing".to_string(),
            success: true,
            error: None,
            queued: false,
        })
    }

    /// Simple template rendering - replaces {{field}} with event values
    fn render_template(&self, template: &str, event: &Event) -> String {
        template
            .replace("{{event_type}}", &event.event_type)
            .replace("{{actor_id}}", &event.actor_id)
            .replace("{{actor_type}}", &event.actor_type)
            .replace("{{source_type}}", &event.source_type)
            .replace("{{source_id}}", event.source_id.as_deref().unwrap_or(""))
            .replace("{{resource_type}}", event.resource_type.as_deref().unwrap_or(""))
            .replace("{{resource_id}}", event.resource_id.as_deref().unwrap_or(""))
            .replace("{{timestamp}}", &event.timestamp.to_rfc3339())
    }

    /// Process pending deliveries from the queue (called periodically)
    pub async fn process_delivery_queue(&self, limit: i64) -> EventResult<QueueProcessResult> {
        let mut result = QueueProcessResult::default();

        let pending = self.store.get_pending_deliveries(limit)
            .map_err(|e| EventError::Store(e.to_string()))?;

        result.items_found = pending.len();

        for item in pending {
            match item.delivery_type.as_str() {
                "notification" => {
                    let request: InboundNotificationRequest = serde_json::from_str(&item.payload)
                        .map_err(|e| EventError::Config(format!("Invalid payload: {}", e)))?;

                    match self.deliver_notification(&item.destination, &request).await {
                        Ok(response) => {
                            if response.status == "accepted" {
                                self.store.update_delivery_status(&item.id, &DeliveryStatus::Delivered, None)
                                    .map_err(|e| EventError::Store(e.to_string()))?;
                                result.items_delivered += 1;
                            } else {
                                self.store.update_delivery_status(&item.id, &DeliveryStatus::Rejected, None)
                                    .map_err(|e| EventError::Store(e.to_string()))?;
                                result.items_rejected += 1;
                            }
                        }
                        Err(e) => {
                            self.store.update_delivery_status(&item.id, &DeliveryStatus::Failed, Some(&e.to_string()))
                                .map_err(|e| EventError::Store(e.to_string()))?;
                            result.items_failed += 1;
                        }
                    }
                }
                "webhook" => {
                    let response = self.http_client
                        .post(&item.destination)
                        .header("Content-Type", "application/json")
                        .body(item.payload.clone())
                        .send()
                        .await;

                    match response {
                        Ok(r) if r.status().is_success() => {
                            self.store.update_delivery_status(&item.id, &DeliveryStatus::Delivered, None)
                                .map_err(|e| EventError::Store(e.to_string()))?;
                            result.items_delivered += 1;
                        }
                        Ok(r) => {
                            let error = format!("HTTP {}", r.status());
                            self.store.update_delivery_status(&item.id, &DeliveryStatus::Failed, Some(&error))
                                .map_err(|e| EventError::Store(e.to_string()))?;
                            result.items_failed += 1;
                        }
                        Err(e) => {
                            self.store.update_delivery_status(&item.id, &DeliveryStatus::Failed, Some(&e.to_string()))
                                .map_err(|e| EventError::Store(e.to_string()))?;
                            result.items_failed += 1;
                        }
                    }
                }
                _ => {
                    // Unknown delivery type - mark as failed
                    self.store.update_delivery_status(
                        &item.id,
                        &DeliveryStatus::Failed,
                        Some(&format!("Unknown delivery type: {}", item.delivery_type)),
                    ).map_err(|e| EventError::Store(e.to_string()))?;
                    result.items_failed += 1;
                }
            }
        }

        Ok(result)
    }
}

/// Result of processing an event
#[derive(Debug, Default)]
pub struct ProcessResult {
    pub subscriptions_matched: usize,
    pub actions_executed: usize,
    pub actions_succeeded: usize,
    pub action_results: Vec<ActionResult>,
}

/// Result of a single action execution
#[derive(Debug)]
pub struct ActionResult {
    pub subscription_id: String,
    pub action_type: String,
    pub success: bool,
    pub error: Option<String>,
    pub queued: bool,
}

/// Result of processing the delivery queue
#[derive(Debug, Default)]
pub struct QueueProcessResult {
    pub items_found: usize,
    pub items_delivered: usize,
    pub items_rejected: usize,
    pub items_failed: usize,
}

// ============================================================
// Helper functions for emitting events
// ============================================================

/// Emit a follow.created event
pub fn follow_created_event(follower_id: &str, following_id: &str, follow_id: &str) -> Event {
    let mut payload = HashMap::new();
    payload.insert("follow_id".to_string(), serde_json::json!(follow_id));
    payload.insert("following_id".to_string(), serde_json::json!(following_id));

    Event::new("follow.created", follower_id)
        .with_resource("follow", follow_id)
        .with_payload(payload)
}

/// Emit a reaction.added event
pub fn reaction_added_event(
    user_id: &str,
    thing_id: &str,
    reaction_type: &str,
    thing_owner_id: &str,
) -> Event {
    let mut payload = HashMap::new();
    payload.insert("reaction_type".to_string(), serde_json::json!(reaction_type));
    payload.insert("thing_owner_id".to_string(), serde_json::json!(thing_owner_id));

    Event::new("reaction.added", user_id)
        .with_resource("thing", thing_id)
        .with_payload(payload)
}

/// Emit a comment.created event
pub fn comment_created_event(
    user_id: &str,
    comment_id: &str,
    parent_thing_id: &str,
    thing_owner_id: &str,
) -> Event {
    let mut payload = HashMap::new();
    payload.insert("parent_thing_id".to_string(), serde_json::json!(parent_thing_id));
    payload.insert("thing_owner_id".to_string(), serde_json::json!(thing_owner_id));

    Event::new("comment.created", user_id)
        .with_resource("thing", comment_id)
        .with_payload(payload)
}

/// Emit a mention event
pub fn mention_event(
    actor_id: &str,
    mentioned_user_id: &str,
    thing_id: &str,
) -> Event {
    let mut payload = HashMap::new();
    payload.insert("mentioned_user_id".to_string(), serde_json::json!(mentioned_user_id));

    Event::new("mention.created", actor_id)
        .with_resource("thing", thing_id)
        .with_payload(payload)
}

/// Emit a thing.created event
pub fn thing_created_event(user_id: &str, thing_id: &str, thing_type: &str) -> Event {
    let mut payload = HashMap::new();
    payload.insert("thing_type".to_string(), serde_json::json!(thing_type));

    Event::new("thing.created", user_id)
        .with_resource("thing", thing_id)
        .with_payload(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_follow_created_event() {
        let event = follow_created_event("user1", "user2", "follow123");
        assert_eq!(event.event_type, "follow.created");
        assert_eq!(event.actor_id, "user1");
        assert_eq!(event.resource_type, Some("follow".to_string()));
        assert_eq!(event.resource_id, Some("follow123".to_string()));
    }

    #[test]
    fn test_reaction_added_event() {
        let event = reaction_added_event("user1", "thing123", "like", "owner1");
        assert_eq!(event.event_type, "reaction.added");
        assert_eq!(event.actor_id, "user1");
        assert_eq!(event.resource_type, Some("thing".to_string()));
    }

    #[test]
    fn test_comment_created_event() {
        let event = comment_created_event("user1", "comment123", "thing456", "owner1");
        assert_eq!(event.event_type, "comment.created");
        assert_eq!(event.resource_id, Some("comment123".to_string()));
    }

    #[test]
    fn test_mention_event() {
        let event = mention_event("user1", "user2", "thing123");
        assert_eq!(event.event_type, "mention.created");
        assert!(event.payload.is_some());
    }

    #[tokio::test]
    async fn test_event_processor_no_subscriptions() {
        let store = Arc::new(Store::in_memory().unwrap());
        let processor = EventProcessor::new(store);

        let event = Event::new("test.event", "user1");
        let result = processor.process(&event).await.unwrap();

        assert_eq!(result.subscriptions_matched, 0);
        assert_eq!(result.actions_executed, 0);
    }

    #[tokio::test]
    async fn test_event_processor_with_local_notification() {
        let store = Arc::new(Store::in_memory().unwrap());

        // Create a test user
        let mut user = User {
            id: String::new(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: "Test User".to_string(),
            bio: String::new(),
            avatar_url: String::new(),
            is_admin: false,
            is_locked: false,
            recovery_hash: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_user(&mut user).unwrap();

        // Create a subscription for follow.created events
        let mut config = HashMap::new();
        config.insert("destination".to_string(), serde_json::json!("local"));
        config.insert("notification_type".to_string(), serde_json::json!("follow"));

        let sub = Subscription {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: Some("Follow notifications".to_string()),
            event_type: "follow.created".to_string(),
            source_type: None,
            source_id: None,
            action_type: "notification".to_string(),
            action_config: config,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_subscription(&sub).unwrap();

        // Process a follow event
        let processor = EventProcessor::new(store.clone());
        let event = follow_created_event(&user.id, "user2", "follow123");
        let result = processor.process(&event).await.unwrap();

        assert_eq!(result.subscriptions_matched, 1);
        assert_eq!(result.actions_executed, 1);
        assert_eq!(result.actions_succeeded, 1);

        // Check notification was created
        let notifications = store.list_notifications(&user.id, 10, 0).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].notification_type, "follow");
    }
}
