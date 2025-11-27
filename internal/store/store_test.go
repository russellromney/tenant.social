package store

import (
	"os"
	"testing"

	"tenant/internal/models"
)

// setupTestStore creates a test store using Turso dev database.
// Use this for integration tests that need to test against the actual Turso backend.
func setupTestStore(t *testing.T) (*Store, func()) {
	t.Helper()

	// Use Turso dev database for tests
	dbURL := os.Getenv("TURSO_DATABASE_URL")
	authToken := os.Getenv("TURSO_AUTH_TOKEN")
	if dbURL == "" || authToken == "" {
		t.Skip("TURSO_DATABASE_URL and TURSO_AUTH_TOKEN not set, skipping test")
	}

	cfg := Config{
		Backend:    BackendTurso,
		TursoURL:   dbURL,
		TursoToken: authToken,
	}

	store, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	cleanup := func() {
		// Clean up test data
		store.db.Exec("DELETE FROM views")
		store.db.Exec("DELETE FROM photos")
		store.db.Exec("DELETE FROM thing_tags")
		store.db.Exec("DELETE FROM thing_kinds")
		store.db.Exec("DELETE FROM things")
		store.db.Exec("DELETE FROM kinds")
		store.db.Exec("DELETE FROM tags")
		store.Close()
	}

	return store, cleanup
}

// setupLocalTestStore creates a test store using local in-memory SQLite.
// Use this for fast unit tests that don't need network access.
func setupLocalTestStore(t *testing.T) (*Store, func()) {
	t.Helper()

	cfg := Config{
		Backend:    BackendSQLite,
		SQLitePath: ":memory:",
	}

	store, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create local store: %v", err)
	}

	cleanup := func() {
		store.Close()
	}

	return store, cleanup
}

// TestLocalSQLite verifies that the local SQLite backend works
func TestLocalSQLite(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create a thing
	thing := &models.Thing{
		Type:     "note",
		Content:  "Local SQLite test",
		Metadata: map[string]interface{}{"local": true},
	}

	err := store.CreateThing(thing)
	if err != nil {
		t.Fatalf("Failed to create thing in local SQLite: %v", err)
	}

	if thing.ID == "" {
		t.Error("Expected ID to be set")
	}

	// Retrieve it
	retrieved, err := store.GetThing(thing.ID)
	if err != nil {
		t.Fatalf("Failed to get thing from local SQLite: %v", err)
	}

	if retrieved.Content != thing.Content {
		t.Errorf("Expected content %s, got %s", thing.Content, retrieved.Content)
	}

	// Create a kind
	kind := &models.Kind{
		Name: "test-kind",
		Icon: "🧪",
	}
	err = store.CreateKind(kind)
	if err != nil {
		t.Fatalf("Failed to create kind in local SQLite: %v", err)
	}

	// List things
	things, err := store.ListThings("", 10, 0)
	if err != nil {
		t.Fatalf("Failed to list things: %v", err)
	}
	if len(things) != 1 {
		t.Errorf("Expected 1 thing, got %d", len(things))
	}
}

func TestNew(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	if store == nil {
		t.Fatal("Expected store to be non-nil")
	}
}

func TestNewInvalidTurso(t *testing.T) {
	// Try to create a store with an invalid Turso URL
	cfg := Config{
		Backend:    BackendTurso,
		TursoURL:   "libsql://invalid-db.turso.io",
		TursoToken: "badtoken",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("Expected error for invalid Turso URL")
	}
}

func TestNewInvalidBackend(t *testing.T) {
	cfg := Config{
		Backend: "invalid",
	}
	_, err := New(cfg)
	if err == nil {
		t.Error("Expected error for invalid backend")
	}
}

func TestClose(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	err := store.Close()
	if err != nil {
		t.Errorf("Failed to close store: %v", err)
	}
}

// Thing tests

func TestCreateThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		Type:     "note",
		Content:  "Test content",
		Metadata: map[string]interface{}{"key": "value"},
	}

	err := store.CreateThing(thing)
	if err != nil {
		t.Fatalf("Failed to create thing: %v", err)
	}

	if thing.ID == "" {
		t.Error("Expected ID to be set")
	}
	if thing.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if thing.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
}

func TestGetThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create a thing first
	thing := &models.Thing{
		Type:     "note",
		Content:  "Test content",
		Metadata: map[string]interface{}{"key": "value"},
	}
	store.CreateThing(thing)

	// Get the thing
	retrieved, err := store.GetThing(thing.ID)
	if err != nil {
		t.Fatalf("Failed to get thing: %v", err)
	}

	if retrieved.ID != thing.ID {
		t.Errorf("Expected ID %s, got %s", thing.ID, retrieved.ID)
	}
	if retrieved.Content != thing.Content {
		t.Errorf("Expected content %s, got %s", thing.Content, retrieved.Content)
	}
}

func TestGetThingNotFound(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	_, err := store.GetThing("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent thing")
	}
}

func TestListThings(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create multiple things
	for i := 0; i < 5; i++ {
		store.CreateThing(&models.Thing{
			Type:    "note",
			Content: "Test content",
		})
	}
	for i := 0; i < 3; i++ {
		store.CreateThing(&models.Thing{
			Type:    "task",
			Content: "Task content",
		})
	}

	t.Run("list all", func(t *testing.T) {
		things, err := store.ListThings("", 50, 0)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 8 {
			t.Errorf("Expected 8 things, got %d", len(things))
		}
	})

	t.Run("filter by type", func(t *testing.T) {
		things, err := store.ListThings("note", 50, 0)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 5 {
			t.Errorf("Expected 5 notes, got %d", len(things))
		}
	})

	t.Run("with limit", func(t *testing.T) {
		things, err := store.ListThings("", 3, 0)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 3 {
			t.Errorf("Expected 3 things, got %d", len(things))
		}
	})

	t.Run("with offset", func(t *testing.T) {
		things, err := store.ListThings("", 50, 5)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 3 {
			t.Errorf("Expected 3 things, got %d", len(things))
		}
	})
}

func TestUpdateThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create a thing
	thing := &models.Thing{
		Type:     "note",
		Content:  "Original content",
		Metadata: map[string]interface{}{},
	}
	store.CreateThing(thing)

	// Update it
	thing.Content = "Updated content"
	thing.Metadata["updated"] = true
	err := store.UpdateThing(thing)
	if err != nil {
		t.Fatalf("Failed to update thing: %v", err)
	}

	// Retrieve and verify
	retrieved, _ := store.GetThing(thing.ID)
	if retrieved.Content != "Updated content" {
		t.Errorf("Expected updated content, got %s", retrieved.Content)
	}
}

func TestDeleteThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create a thing
	thing := &models.Thing{
		Type:    "note",
		Content: "To be deleted",
	}
	store.CreateThing(thing)

	// Delete it
	err := store.DeleteThing(thing.ID)
	if err != nil {
		t.Fatalf("Failed to delete thing: %v", err)
	}

	// Verify it's gone
	_, err = store.GetThing(thing.ID)
	if err == nil {
		t.Error("Expected error for deleted thing")
	}
}

func TestSearchThings(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create things with different content
	store.CreateThing(&models.Thing{Type: "note", Content: "Hello world"})
	store.CreateThing(&models.Thing{Type: "note", Content: "Goodbye world"})
	store.CreateThing(&models.Thing{Type: "task", Content: "Hello task"})
	store.CreateThing(&models.Thing{Type: "link", Content: "Random content"})

	t.Run("search by content", func(t *testing.T) {
		things, err := store.SearchThings("Hello", 50)
		if err != nil {
			t.Fatalf("Failed to search: %v", err)
		}
		if len(things) != 2 {
			t.Errorf("Expected 2 results, got %d", len(things))
		}
	})

	t.Run("search by type", func(t *testing.T) {
		things, err := store.SearchThings("task", 50)
		if err != nil {
			t.Fatalf("Failed to search: %v", err)
		}
		if len(things) != 1 {
			t.Errorf("Expected 1 result, got %d", len(things))
		}
	})

	t.Run("search with default limit", func(t *testing.T) {
		things, err := store.SearchThings("world", 0)
		if err != nil {
			t.Fatalf("Failed to search: %v", err)
		}
		if len(things) != 2 {
			t.Errorf("Expected 2 results, got %d", len(things))
		}
	})

	t.Run("no results", func(t *testing.T) {
		things, err := store.SearchThings("nonexistent", 50)
		if err != nil {
			t.Fatalf("Failed to search: %v", err)
		}
		if len(things) != 0 {
			t.Errorf("Expected 0 results, got %d", len(things))
		}
	})
}

// Kind tests

func TestCreateKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		Name:     "article",
		Icon:     "📰",
		Template: "card",
		Attributes: []models.Attribute{
			{Name: "url", Type: "url", Required: true},
		},
	}

	err := store.CreateKind(kind)
	if err != nil {
		t.Fatalf("Failed to create kind: %v", err)
	}

	if kind.ID == "" {
		t.Error("Expected ID to be set")
	}
}

func TestCreateKindDefaults(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		Name: "minimal",
	}

	err := store.CreateKind(kind)
	if err != nil {
		t.Fatalf("Failed to create kind: %v", err)
	}

	if kind.Template != "default" {
		t.Errorf("Expected default template, got %s", kind.Template)
	}
	if kind.Attributes == nil {
		t.Error("Expected attributes to be initialized")
	}
}

func TestGetKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		Name:     "test-kind",
		Icon:     "🧪",
		Template: "compact",
	}
	store.CreateKind(kind)

	retrieved, err := store.GetKind(kind.ID)
	if err != nil {
		t.Fatalf("Failed to get kind: %v", err)
	}

	if retrieved.Name != kind.Name {
		t.Errorf("Expected name %s, got %s", kind.Name, retrieved.Name)
	}
}

func TestGetKindNotFound(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	_, err := store.GetKind("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent kind")
	}
}

func TestGetOrCreateKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	t.Run("create new kind", func(t *testing.T) {
		kind, err := store.GetOrCreateKind("new-kind")
		if err != nil {
			t.Fatalf("Failed to get or create kind: %v", err)
		}
		if kind.Name != "new-kind" {
			t.Errorf("Expected name new-kind, got %s", kind.Name)
		}
	})

	t.Run("get existing kind", func(t *testing.T) {
		kind, err := store.GetOrCreateKind("new-kind")
		if err != nil {
			t.Fatalf("Failed to get existing kind: %v", err)
		}
		if kind.Name != "new-kind" {
			t.Errorf("Expected name new-kind, got %s", kind.Name)
		}
	})
}

func TestUpdateKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		Name:     "original",
		Icon:     "🔵",
		Template: "default",
	}
	store.CreateKind(kind)

	// Update
	kind.Name = "updated"
	kind.Icon = "🔴"
	kind.Template = "card"
	kind.Attributes = []models.Attribute{
		{Name: "field", Type: "text"},
	}
	err := store.UpdateKind(kind)
	if err != nil {
		t.Fatalf("Failed to update kind: %v", err)
	}

	// Verify
	retrieved, _ := store.GetKind(kind.ID)
	if retrieved.Name != "updated" {
		t.Errorf("Expected updated name, got %s", retrieved.Name)
	}
	if retrieved.Icon != "🔴" {
		t.Errorf("Expected updated icon, got %s", retrieved.Icon)
	}
}

func TestUpdateKindDefaults(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{Name: "test"}
	store.CreateKind(kind)

	// Update with nil values
	kind.Attributes = nil
	kind.Template = ""
	err := store.UpdateKind(kind)
	if err != nil {
		t.Fatalf("Failed to update kind: %v", err)
	}

	retrieved, _ := store.GetKind(kind.ID)
	if retrieved.Template != "default" {
		t.Errorf("Expected default template, got %s", retrieved.Template)
	}
}

func TestDeleteKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{Name: "to-delete"}
	store.CreateKind(kind)

	err := store.DeleteKind(kind.ID)
	if err != nil {
		t.Fatalf("Failed to delete kind: %v", err)
	}

	_, err = store.GetKind(kind.ID)
	if err == nil {
		t.Error("Expected error for deleted kind")
	}
}

func TestListKinds(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create kinds
	store.CreateKind(&models.Kind{Name: "alpha"})
	store.CreateKind(&models.Kind{Name: "beta"})
	store.CreateKind(&models.Kind{Name: "gamma"})

	kinds, err := store.ListKinds()
	if err != nil {
		t.Fatalf("Failed to list kinds: %v", err)
	}

	if len(kinds) != 3 {
		t.Errorf("Expected 3 kinds, got %d", len(kinds))
	}

	// Should be sorted by name
	if kinds[0].Name != "alpha" {
		t.Errorf("Expected first kind to be alpha, got %s", kinds[0].Name)
	}
}

// Tag tests

func TestCreateTag(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	tag := &models.Tag{Name: "important"}
	err := store.CreateTag(tag)
	if err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	if tag.ID == "" {
		t.Error("Expected ID to be set")
	}
}

func TestGetOrCreateTag(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	t.Run("create new tag", func(t *testing.T) {
		tag, err := store.GetOrCreateTag("new-tag")
		if err != nil {
			t.Fatalf("Failed to get or create tag: %v", err)
		}
		if tag.Name != "new-tag" {
			t.Errorf("Expected name new-tag, got %s", tag.Name)
		}
	})

	t.Run("get existing tag", func(t *testing.T) {
		tag, err := store.GetOrCreateTag("new-tag")
		if err != nil {
			t.Fatalf("Failed to get existing tag: %v", err)
		}
		if tag.Name != "new-tag" {
			t.Errorf("Expected name new-tag, got %s", tag.Name)
		}
	})
}

func TestListTags(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	store.CreateTag(&models.Tag{Name: "alpha"})
	store.CreateTag(&models.Tag{Name: "beta"})
	store.CreateTag(&models.Tag{Name: "gamma"})

	tags, err := store.ListTags()
	if err != nil {
		t.Fatalf("Failed to list tags: %v", err)
	}

	if len(tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(tags))
	}
}

func TestTagThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "note", Content: "Test"}
	store.CreateThing(thing)

	tag := &models.Tag{Name: "important"}
	store.CreateTag(tag)

	err := store.TagThing(thing.ID, tag.ID)
	if err != nil {
		t.Fatalf("Failed to tag thing: %v", err)
	}

	// Tagging again should not error (INSERT OR IGNORE)
	err = store.TagThing(thing.ID, tag.ID)
	if err != nil {
		t.Fatalf("Failed to tag thing again: %v", err)
	}
}

func TestSetThingKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "note", Content: "Test"}
	store.CreateThing(thing)

	kind := &models.Kind{Name: "article"}
	store.CreateKind(kind)

	err := store.SetThingKind(thing.ID, kind.ID)
	if err != nil {
		t.Fatalf("Failed to set thing kind: %v", err)
	}

	// Setting again should replace (INSERT OR REPLACE)
	err = store.SetThingKind(thing.ID, kind.ID)
	if err != nil {
		t.Fatalf("Failed to set thing kind again: %v", err)
	}
}

// Photo tests

func TestCreatePhoto(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "photo", Content: "Caption"}
	store.CreateThing(thing)

	photo := &models.Photo{
		ThingID:     thing.ID,
		Data:        []byte("fake image data"),
		ContentType: "image/png",
		Filename:    "test.png",
		Size:        15,
	}

	err := store.CreatePhoto(photo)
	if err != nil {
		t.Fatalf("Failed to create photo: %v", err)
	}

	if photo.ID == "" {
		t.Error("Expected ID to be set")
	}
}

func TestGetPhoto(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "photo", Content: "Caption"}
	store.CreateThing(thing)

	photo := &models.Photo{
		ThingID:     thing.ID,
		Data:        []byte("fake image data"),
		ContentType: "image/png",
		Filename:    "test.png",
		Size:        15,
	}
	store.CreatePhoto(photo)

	retrieved, err := store.GetPhoto(photo.ID)
	if err != nil {
		t.Fatalf("Failed to get photo: %v", err)
	}

	if string(retrieved.Data) != "fake image data" {
		t.Error("Photo data mismatch")
	}
	if retrieved.ContentType != "image/png" {
		t.Errorf("Expected content type image/png, got %s", retrieved.ContentType)
	}
}

func TestGetPhotoNotFound(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	_, err := store.GetPhoto("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent photo")
	}
}

func TestGetPhotoByThingID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "photo", Content: "Caption"}
	store.CreateThing(thing)

	photo := &models.Photo{
		ThingID:     thing.ID,
		Data:        []byte("image data"),
		ContentType: "image/jpeg",
		Filename:    "photo.jpg",
		Size:        10,
	}
	store.CreatePhoto(photo)

	retrieved, err := store.GetPhotoByThingID(thing.ID)
	if err != nil {
		t.Fatalf("Failed to get photo by thing ID: %v", err)
	}

	if retrieved.ID != photo.ID {
		t.Errorf("Expected photo ID %s, got %s", photo.ID, retrieved.ID)
	}
}

func TestGetPhotoByThingIDNotFound(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	_, err := store.GetPhotoByThingID("nonexistent-thing-id")
	if err == nil {
		t.Error("Expected error for nonexistent thing ID")
	}
}

func TestDeletePhoto(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{Type: "photo", Content: "Caption"}
	store.CreateThing(thing)

	photo := &models.Photo{
		ThingID:     thing.ID,
		Data:        []byte("data"),
		ContentType: "image/png",
		Filename:    "test.png",
		Size:        4,
	}
	store.CreatePhoto(photo)

	err := store.DeletePhoto(photo.ID)
	if err != nil {
		t.Fatalf("Failed to delete photo: %v", err)
	}

	_, err = store.GetPhoto(photo.ID)
	if err == nil {
		t.Error("Expected error for deleted photo")
	}
}

// Test metadata JSON handling

func TestThingMetadataJSON(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		Type:    "note",
		Content: "Test",
		Metadata: map[string]interface{}{
			"string":  "value",
			"number":  42.0,
			"boolean": true,
			"nested": map[string]interface{}{
				"key": "nested value",
			},
		},
	}
	store.CreateThing(thing)

	retrieved, _ := store.GetThing(thing.ID)

	if retrieved.Metadata["string"] != "value" {
		t.Error("String metadata mismatch")
	}
	if retrieved.Metadata["number"] != 42.0 {
		t.Error("Number metadata mismatch")
	}
	if retrieved.Metadata["boolean"] != true {
		t.Error("Boolean metadata mismatch")
	}
}

func TestKindAttributesJSON(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		Name: "test",
		Attributes: []models.Attribute{
			{Name: "field1", Type: "text", Required: true, Options: ""},
			{Name: "field2", Type: "select", Required: false, Options: "a,b,c"},
		},
	}
	store.CreateKind(kind)

	retrieved, _ := store.GetKind(kind.ID)

	if len(retrieved.Attributes) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(retrieved.Attributes))
	}
	if retrieved.Attributes[0].Name != "field1" {
		t.Error("First attribute name mismatch")
	}
	if retrieved.Attributes[1].Options != "a,b,c" {
		t.Error("Second attribute options mismatch")
	}
}

// View tests

func TestCreateView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{
		Name: "My Feed",
		Type: "feed",
		Config: models.ViewConfig{
			Sort: &models.SortConfig{Field: "created_at", Order: "desc"},
		},
	}

	err := store.CreateView(view)
	if err != nil {
		t.Fatalf("Failed to create view: %v", err)
	}

	if view.ID == "" {
		t.Error("Expected ID to be set")
	}
	if view.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
}

func TestGetView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{
		Name: "Tasks Board",
		Type: "board",
		Config: models.ViewConfig{
			GroupBy:      "status",
			BoardColumns: []string{"todo", "in-progress", "done"},
		},
	}
	store.CreateView(view)

	retrieved, err := store.GetView(view.ID)
	if err != nil {
		t.Fatalf("Failed to get view: %v", err)
	}

	if retrieved.Name != view.Name {
		t.Errorf("Expected name %s, got %s", view.Name, retrieved.Name)
	}
	if retrieved.Type != "board" {
		t.Errorf("Expected type board, got %s", retrieved.Type)
	}
	if retrieved.Config.GroupBy != "status" {
		t.Errorf("Expected groupBy status, got %s", retrieved.Config.GroupBy)
	}
}

func TestGetViewNotFound(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	_, err := store.GetView("nonexistent-id")
	if err == nil {
		t.Error("Expected error for nonexistent view")
	}
}

func TestUpdateView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{
		Name: "Original",
		Type: "feed",
	}
	store.CreateView(view)

	view.Name = "Updated"
	view.Type = "table"
	view.Config = models.ViewConfig{
		Columns: []string{"content", "type", "created_at"},
	}
	err := store.UpdateView(view)
	if err != nil {
		t.Fatalf("Failed to update view: %v", err)
	}

	retrieved, _ := store.GetView(view.ID)
	if retrieved.Name != "Updated" {
		t.Errorf("Expected name Updated, got %s", retrieved.Name)
	}
	if retrieved.Type != "table" {
		t.Errorf("Expected type table, got %s", retrieved.Type)
	}
	if len(retrieved.Config.Columns) != 3 {
		t.Errorf("Expected 3 columns, got %d", len(retrieved.Config.Columns))
	}
}

func TestDeleteView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{Name: "To Delete", Type: "feed"}
	store.CreateView(view)

	err := store.DeleteView(view.ID)
	if err != nil {
		t.Fatalf("Failed to delete view: %v", err)
	}

	_, err = store.GetView(view.ID)
	if err == nil {
		t.Error("Expected error for deleted view")
	}
}

func TestListViews(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	store.CreateView(&models.View{Name: "Alpha", Type: "feed"})
	store.CreateView(&models.View{Name: "Beta", Type: "table"})
	store.CreateView(&models.View{Name: "Gamma", Type: "board"})

	views, err := store.ListViews()
	if err != nil {
		t.Fatalf("Failed to list views: %v", err)
	}

	if len(views) != 3 {
		t.Errorf("Expected 3 views, got %d", len(views))
	}

	// Should be sorted by name
	if views[0].Name != "Alpha" {
		t.Errorf("Expected first view to be Alpha, got %s", views[0].Name)
	}
}

func TestViewWithKind(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create a kind
	kind := &models.Kind{Name: "article"}
	store.CreateKind(kind)

	// Create a view filtered to that kind
	view := &models.View{
		Name:   "Articles Only",
		Type:   "table",
		KindID: &kind.ID,
	}
	store.CreateView(view)

	retrieved, err := store.GetView(view.ID)
	if err != nil {
		t.Fatalf("Failed to get view: %v", err)
	}

	if retrieved.KindID == nil {
		t.Fatal("Expected KindID to be set")
	}
	if *retrieved.KindID != kind.ID {
		t.Errorf("Expected KindID %s, got %s", kind.ID, *retrieved.KindID)
	}
}
