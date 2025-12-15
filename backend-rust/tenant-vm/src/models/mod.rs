use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User represents a tenant - each user owns their own data space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub display_name: String,
    pub bio: String,
    pub avatar_url: String,
    pub is_admin: bool,
    pub is_locked: bool,
    #[serde(skip_serializing)]
    pub recovery_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Session represents an active user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    #[serde(skip_serializing)]
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Thing is the universal unit in Tenant.
/// Everything is a Thing: notes, links, tasks, images, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thing {
    pub id: String,
    pub user_id: String,
    #[serde(rename = "type")]
    pub thing_type: String,
    pub content: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub visibility: String,
    pub version: i32,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub photos: Vec<Photo>,
}

/// ThingVersion stores historical versions of a Thing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThingVersion {
    pub id: String,
    pub thing_id: String,
    pub version: i32,
    #[serde(rename = "type")]
    pub thing_type: String,
    pub content: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// APIKey allows programmatic access to the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub user_id: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Available API key scopes
pub const API_KEY_SCOPES: &[&str] = &[
    "things:read",
    "things:write",
    "things:delete",
    "kinds:read",
    "kinds:write",
    "kinds:delete",
    "keys:manage",
    "notifications:read",
    "notifications:write",
    "reactions:read",
    "reactions:write",
];

/// Kind is a category of Thing (note, link, task, article, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kind {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub icon: String,
    pub template: String,
    pub attributes: Vec<Attribute>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Attribute defines a field that Things of a Kind can have
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    #[serde(rename = "type")]
    pub attr_type: String,
    pub required: bool,
    pub options: String,
}

/// Tag is a lightweight label for Things
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub user_id: String,
    pub name: String,
}

/// Relationship connects two Things
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    #[serde(rename = "type")]
    pub rel_type: String,
    pub created_at: DateTime<Utc>,
}

/// ThingKind links Things to Kinds (a Thing has one Kind)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThingKind {
    pub thing_id: String,
    pub kind_id: String,
}

/// ThingTag links Things to Tags (many-to-many)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThingTag {
    pub thing_id: String,
    pub tag_id: String,
}

/// Photo stores image/video binary data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Photo {
    pub id: String,
    pub thing_id: String,
    pub caption: String,
    pub order_index: i32,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
    pub content_type: String,
    pub filename: String,
    pub size: i64,
    pub created_at: DateTime<Utc>,
}

/// View is a way to display Things (Notion-inspired)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct View {
    pub id: String,
    pub user_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub view_type: String,
    pub kind_id: Option<String>,
    pub config: ViewConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ViewConfig holds view-specific settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ViewConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<SortConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub filters: Vec<FilterRule>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub board_columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_view: Option<String>,
}

/// SortConfig defines sorting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortConfig {
    pub field: String,
    pub order: String,
}

/// FilterRule defines a single filter condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub field: String,
    pub op: String,
    pub value: String,
}

/// Follow represents a friend connection to another node
/// Per whitepaper: "sharing your API endpoint with someone and adding theirs to your config"
/// Friendship is bidirectional - both nodes must follow each other
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Follow {
    pub id: String,
    pub follower_id: String,        // Local user who added this friend
    pub following_id: String,        // Remote user identifier (username@domain)
    pub remote_endpoint: String,     // Friend's API endpoint (e.g., "https://friend.tenant.social")
    #[serde(skip_serializing)]
    pub access_token: Option<String>, // Optional token for calling friend's API
    pub created_at: DateTime<Utc>,
    pub last_confirmed_at: Option<DateTime<Utc>>, // Last time follower confirmed they still follow
}

/// Channel for group communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub owner_id: String,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// ChannelMember links users to channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    pub channel_id: String,
    pub user_id: String,
    pub role: ChannelRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRole {
    Owner,
    Admin,
    Member,
}

// ============================================================
// EVENT SYSTEM
// ============================================================

/// Event is an ephemeral trigger - processed and discarded, not stored.
/// Events flow through the system, match subscriptions, and cause effects.
#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,              // 'follow.created', 'reaction.added', etc.
    pub source_type: String,             // 'first_party', 'friend', 'webhook'
    pub source_id: Option<String>,       // Specific source ID
    pub actor_id: String,                // Who triggered it
    pub actor_type: String,              // 'user', 'system'
    pub resource_type: Option<String>,   // 'thing', 'follow', 'comment'
    pub resource_id: Option<String>,     // ID of the resource
    pub payload: Option<HashMap<String, serde_json::Value>>,
    pub timestamp: DateTime<Utc>,
}

impl Event {
    pub fn new(
        event_type: impl Into<String>,
        actor_id: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            source_type: "first_party".to_string(),
            source_id: None,
            actor_id: actor_id.into(),
            actor_type: "user".to_string(),
            resource_type: None,
            resource_id: None,
            payload: None,
            timestamp: Utc::now(),
        }
    }

    pub fn with_source(mut self, source_type: impl Into<String>, source_id: Option<String>) -> Self {
        self.source_type = source_type.into();
        self.source_id = source_id;
        self
    }

    pub fn with_resource(mut self, resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    pub fn with_payload(mut self, payload: HashMap<String, serde_json::Value>) -> Self {
        self.payload = Some(payload);
        self
    }
}

/// Subscription defines what happens when events occur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub name: Option<String>,
    pub event_type: String,              // Event type to match, or '*' for all
    pub source_type: Option<String>,     // Filter by source type
    pub source_id: Option<String>,       // Filter by specific source
    pub action_type: String,             // 'notification', 'webhook', 'create_thing'
    pub action_config: HashMap<String, serde_json::Value>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// DeliveryQueueItem for retrying failed outbound deliveries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryQueueItem {
    pub id: String,
    pub delivery_type: String,           // 'notification', 'webhook'
    pub destination: String,             // URL endpoint
    pub payload: String,                 // JSON payload
    pub status: DeliveryStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Rejected,
    Failed,
}

impl DeliveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::Rejected => "rejected",
            DeliveryStatus::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "delivered" => DeliveryStatus::Delivered,
            "rejected" => DeliveryStatus::Rejected,
            "failed" => DeliveryStatus::Failed,
            _ => DeliveryStatus::Pending,
        }
    }
}

// ============================================================
// NOTIFICATIONS
// ============================================================

/// NotificationSettings controls what notification types a user accepts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub id: String,
    pub user_id: String,
    pub notification_type: String,       // 'follow', 'reaction', 'comment', 'mention', '*'
    pub enabled: bool,                   // true = accept, false = reject
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Notification is a stored, accepted notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub user_id: String,                 // Recipient
    pub notification_type: String,       // 'follow', 'reaction', 'comment', 'mention'
    pub actor_id: Option<String>,        // Who triggered it
    pub actor_type: Option<String>,      // 'user', 'webhook', 'system'
    pub resource_type: Option<String>,   // 'thing', 'follow', 'comment'
    pub resource_id: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

/// Inbound notification request from remote node
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

/// Response to inbound notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundNotificationResponse {
    pub status: String,  // "accepted" or "rejected"
}

// ============================================================
// REACTIONS
// ============================================================

/// Reaction on a Thing (like, heart, fire, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub id: String,
    pub user_id: String,
    pub thing_id: String,
    pub reaction_type: String,           // 'like', 'heart', 'fire', 'laugh', 'sad', 'celebrate'
    pub created_at: DateTime<Utc>,
}

/// Allowed reaction types - text-based names and popular emojis
pub const ALLOWED_REACTIONS: &[&str] = &[
    // Text-based reaction names
    "like",      // thumbs up
    "heart",     // love
    "fire",      // hot/good
    "laugh",     // funny
    "sad",       // sad
    "celebrate", // party/congrats
    // Popular emojis (50 most commonly used)
    "👍", "👎", "❤️", "🔥", "😂",
    "😍", "😢", "😮", "😡", "🎉",
    "👏", "🙏", "💯", "✨", "🎊",
    "💪", "🤔", "😊", "😎", "🥳",
    "😭", "🤣", "💕", "✅", "❌",
    "🚀", "💡", "⭐", "🌟", "💫",
    "🙌", "🤝", "👋", "💖", "💗",
    "💓", "💘", "💝", "🥰", "😇",
    "🤩", "😻", "💙", "💚", "💛",
    "💜", "🖤", "🤍", "🧡", "💔",
];

/// Reaction counts and user's reactions for a Thing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionSummary {
    pub counts: HashMap<String, i64>,
    pub user_reactions: Vec<String>,
}

// Request/Response types for API
#[derive(Debug, Deserialize)]
pub struct CreateThingRequest {
    #[serde(rename = "type")]
    pub thing_type: String,
    pub content: String,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(default = "default_visibility")]
    pub visibility: String,
}

fn default_visibility() -> String {
    "private".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateThingRequest {
    #[serde(rename = "type")]
    pub thing_type: Option<String>,
    pub content: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub visibility: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKindRequest {
    pub name: String,
    pub icon: String,
    pub template: String,
    #[serde(default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateKindRequest {
    pub name: Option<String>,
    pub icon: Option<String>,
    pub template: Option<String>,
    pub attributes: Option<Vec<Attribute>>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to add a remote friend node
#[derive(Debug, Deserialize)]
pub struct AddFriendRequest {
    pub remote_user_id: String,      // username@domain format
    pub remote_endpoint: String,      // e.g., "https://friend.tenant.social"
    pub access_token: Option<String>, // Optional bearer token for their API
}

/// Follow token for secure federated follows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowToken {
    pub token: String,
    pub user_id: String,
    pub endpoint: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Request to verify a follow token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowVerifyRequest {
    pub follow_token: String,
}

/// Response to token verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowVerifyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

/// Response for creating a follow token
#[derive(Debug, Clone, Serialize)]
pub struct CreateFollowTokenResponse {
    pub follow_token: String,
    pub expires_in: u64,  // Seconds (300 = 5 minutes)
}

/// Request to notify a remote server that someone is following their user
#[derive(Debug, Clone, Deserialize)]
pub struct NotifyFollowRequest {
    pub follower_user_id: String,    // Who is following (the sender's user ID)
    pub follower_endpoint: String,   // Where the follower lives (e.g., "https://russ.tenant.social")
    pub follow_token: String,        // Token to verify authenticity
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ============================================================
// Request types for subscriptions, notifications, reactions
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub name: Option<String>,
    pub event_type: String,
    pub source_type: Option<String>,
    pub source_id: Option<String>,
    pub action_type: String,
    pub action_config: HashMap<String, serde_json::Value>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub name: Option<String>,
    pub event_type: Option<String>,
    pub source_type: Option<Option<String>>,
    pub source_id: Option<Option<String>>,
    pub action_type: Option<String>,
    pub action_config: Option<HashMap<String, serde_json::Value>>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotificationSettingsRequest {
    pub notification_type: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddReactionRequest {
    #[serde(rename = "type")]
    pub reaction_type: String,
}

/// Response for listing notifications
#[derive(Debug, Serialize)]
pub struct NotificationsListResponse {
    pub notifications: Vec<NotificationWithActor>,
    pub total: i64,
    pub unread_count: i64,
}

/// Notification with actor info joined
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationWithActor {
    pub id: String,
    pub notification_type: String,
    pub actor: Option<ActorInfo>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    pub read: bool,
    pub created_at: DateTime<Utc>,
}

/// Basic actor info for notification display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorInfo {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub avatar_url: String,
}
