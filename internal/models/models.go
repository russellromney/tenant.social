package models

import "time"

// Thing is the universal unit in Stuffbox.
// Everything is a Thing: notes, links, tasks, images, etc.
type Thing struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`      // "note", "link", "task", "image", etc.
	Content   string                 `json:"content"`   // Main content (text, URL, etc.)
	Metadata  map[string]interface{} `json:"metadata"`  // Type-specific data as JSON
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

// Kind is a category of Thing (note, link, task, article, etc.).
// Things have exactly one Kind.
type Kind struct {
	ID         string      `json:"id"`
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
	ID   string `json:"id"`
	Name string `json:"name"`
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
