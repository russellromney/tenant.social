package models

import "time"

// User represents a tenant - each user owns their own data space
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`     // Unique username (used for login and URL)
	Email        string    `json:"email"`        // Email address
	PasswordHash string    `json:"-"`            // Hashed password (never sent to client)
	DisplayName  string    `json:"displayName"`  // Display name
	Bio          string    `json:"bio"`          // Short bio
	AvatarURL    string    `json:"avatarUrl"`    // Profile picture URL
	IsAdmin      bool      `json:"isAdmin"`      // Server admin (can manage users, but not see their data)
	IsLocked     bool      `json:"isLocked"`     // If true, user cannot login (admin locked them out)
	RecoveryHash string    `json:"-"`            // Hash of recovery phrase (for data recovery)
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	Token     string    `json:"-"`      // Session token (not sent in JSON)
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// Thing is the universal unit in Tenant.
// Everything is a Thing: notes, links, tasks, images, etc.
type Thing struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"userId"`    // Owner of this Thing
	Type      string                 `json:"type"`      // "note", "link", "task", "image", etc.
	Content   string                 `json:"content"`   // Main content (text, URL, etc.)
	Metadata  map[string]interface{} `json:"metadata"`  // Type-specific data as JSON
	Version   int                    `json:"version"`   // Current version number
	DeletedAt *time.Time             `json:"deletedAt"` // Soft delete timestamp (nil = not deleted)
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

// ThingVersion stores historical versions of a Thing.
// Every update creates a new version - you never lose data.
type ThingVersion struct {
	ID        string                 `json:"id"`
	ThingID   string                 `json:"thingId"`   // Parent Thing ID
	Version   int                    `json:"version"`   // Version number (1, 2, 3, ...)
	Type      string                 `json:"type"`      // Type at this version
	Content   string                 `json:"content"`   // Content at this version
	Metadata  map[string]interface{} `json:"metadata"`  // Metadata at this version
	CreatedAt time.Time              `json:"createdAt"` // When this version was created
	CreatedBy string                 `json:"createdBy"` // User ID or API Key ID that made this change
}

// APIKey allows programmatic access to the API.
// Keys are shown once at creation, then stored as bcrypt hash.
type APIKey struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"userId"`              // Owner of this key
	Name       string                 `json:"name"`                // Human-readable name (e.g., "Personal Website")
	KeyHash    string                 `json:"-"`                   // bcrypt hash of the key (never exposed)
	KeyPrefix  string                 `json:"keyPrefix"`           // First 8 chars for identification (e.g., "ts_abc12")
	Scopes     []string               `json:"scopes"`              // Permissions: things:read, things:write, etc.
	Metadata   map[string]interface{} `json:"metadata,omitempty"`  // User-defined metadata
	LastUsedAt *time.Time             `json:"lastUsedAt"`          // Last time this key was used
	ExpiresAt  *time.Time             `json:"expiresAt,omitempty"` // Optional expiration (nil = never)
	CreatedAt  time.Time              `json:"createdAt"`
}

// APIKeyScopes defines available permission scopes
var APIKeyScopes = []string{
	"things:read",   // List and get things
	"things:write",  // Create and update things
	"things:delete", // Delete things
	"kinds:read",    // List and get kinds
	"kinds:write",   // Create and update kinds
	"kinds:delete",  // Delete kinds
	"keys:manage",   // Create, update, delete API keys
}

// Kind is a category of Thing (note, link, task, article, etc.).
// Things have exactly one Kind.
type Kind struct {
	ID         string      `json:"id"`
	UserID     string      `json:"userId"`     // Owner of this Kind
	Name       string      `json:"name"`
	Icon       string      `json:"icon"`       // Emoji
	Template   string      `json:"template"`   // Display template: default, compact, card, checklist, link
	Attributes []Attribute `json:"attributes"` // Schema for this Kind
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
}

// Attribute defines a field that Things of a Kind can have
type Attribute struct {
	Name     string `json:"name"`     // Field name
	Type     string `json:"type"`     // text, number, date, url, checkbox, select
	Required bool   `json:"required"` // Is this field required?
	Options  string `json:"options"`  // For select type: comma-separated options
}

// Tag is a lightweight label for Things.
type Tag struct {
	ID     string `json:"id"`
	UserID string `json:"userId"` // Owner of this Tag
	Name   string `json:"name"`
}

// Relationship connects two Things.
// Examples: "references", "blocks", "reply-to", "child-of"
type Relationship struct {
	ID        string    `json:"id"`
	FromID    string    `json:"fromId"`    // Source Thing ID
	ToID      string    `json:"toId"`      // Target Thing ID
	Type      string    `json:"type"`      // Relationship type
	CreatedAt time.Time `json:"createdAt"`
}

// ThingKind links Things to Kinds (a Thing has one Kind)
type ThingKind struct {
	ThingID string `json:"thingId"`
	KindID  string `json:"kindId"`
}

// ThingTag links Things to Tags (many-to-many)
type ThingTag struct {
	ThingID string `json:"thingId"`
	TagID   string `json:"tagId"`
}

// Photo stores image/video binary data as a blob
type Photo struct {
	ID          string    `json:"id"`
	ThingID     string    `json:"thingId"`     // Associated Thing
	Data        []byte    `json:"-"`           // Binary data (not serialized to JSON)
	ContentType string    `json:"contentType"` // MIME type (image/jpeg, video/mp4, etc.)
	Filename    string    `json:"filename"`    // Original filename
	Size        int64     `json:"size"`        // File size in bytes
	CreatedAt   time.Time `json:"createdAt"`
}

// View is a way to display Things (Notion-inspired).
// Same data, different representations: feed, table, board, calendar.
type View struct {
	ID        string     `json:"id"`
	UserID    string     `json:"userId"`    // Owner of this View
	Name      string     `json:"name"`      // User-defined name
	Type      string     `json:"type"`      // "feed", "table", "board", "calendar"
	KindID    *string    `json:"kindId"`    // Optional: filter to specific Kind (nil = all)
	Config    ViewConfig `json:"config"`    // View-specific settings
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
}

// ViewConfig holds view-specific settings
type ViewConfig struct {
	// Common
	Sort    *SortConfig   `json:"sort,omitempty"`    // Sort order
	Filters []FilterRule  `json:"filters,omitempty"` // Filter rules

	// Table view
	Columns []string `json:"columns,omitempty"` // Column names to display

	// Board view
	GroupBy       string   `json:"groupBy,omitempty"`       // Attribute to group by
	BoardColumns  []string `json:"boardColumns,omitempty"`  // Column values (e.g., ["todo", "in-progress", "done"])

	// Calendar view
	DateField   string `json:"dateField,omitempty"`   // Attribute containing date
	DefaultView string `json:"defaultView,omitempty"` // "day", "week", "month"
}

// SortConfig defines sorting
type SortConfig struct {
	Field string `json:"field"` // Field to sort by
	Order string `json:"order"` // "asc" or "desc"
}

// FilterRule defines a single filter condition
type FilterRule struct {
	Field string `json:"field"` // Field to filter on
	Op    string `json:"op"`    // Operator: "eq", "ne", "contains", "gt", "lt"
	Value string `json:"value"` // Value to compare
}
