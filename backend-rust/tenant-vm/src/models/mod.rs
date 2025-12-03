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

/// Friendship represents a connection between users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Friendship {
    pub id: String,
    pub user_id: String,
    pub friend_id: String,
    pub status: FriendshipStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FriendshipStatus {
    Pending,
    Accepted,
    Blocked,
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

#[derive(Debug, Serialize)]
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
