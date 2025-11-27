package store

import (
	"os"
	"testing"

	"tenant/internal/models"
)

// Test user for all tests
var testUserID = "test-user-id"

// setupTestStore creates a test store using Turso dev database.
func setupTestStore(t *testing.T) (*Store, func()) {
	t.Helper()

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

	// Create test user
	testUser := &models.User{
		ID:           testUserID,
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	store.db.Exec("DELETE FROM users WHERE id = ?", testUserID)
	store.db.Exec(`INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)`,
		testUser.ID, testUser.Username, testUser.Email, testUser.PasswordHash)

	cleanup := func() {
		store.db.Exec("DELETE FROM views WHERE user_id = ?", testUserID)
		store.db.Exec("DELETE FROM photos")
		store.db.Exec("DELETE FROM thing_tags")
		store.db.Exec("DELETE FROM thing_kinds")
		store.db.Exec("DELETE FROM things WHERE user_id = ?", testUserID)
		store.db.Exec("DELETE FROM kinds WHERE user_id = ?", testUserID)
		store.db.Exec("DELETE FROM tags WHERE user_id = ?", testUserID)
		store.db.Exec("DELETE FROM users WHERE id = ?", testUserID)
		store.Close()
	}

	return store, cleanup
}

// setupLocalTestStore creates a test store using local in-memory SQLite.
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

	// Create test user
	testUser := &models.User{
		ID:           testUserID,
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	store.db.Exec(`INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)`,
		testUser.ID, testUser.Username, testUser.Email, testUser.PasswordHash)

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
		UserID:   testUserID,
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
		UserID: testUserID,
		Name:   "test-kind",
		Icon:   "🧪",
	}
	err = store.CreateKind(kind)
	if err != nil {
		t.Fatalf("Failed to create kind in local SQLite: %v", err)
	}

	// List things
	things, err := store.ListThings(testUserID, "", 10, 0)
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
		UserID:   testUserID,
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
}

func TestGetThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		UserID:   testUserID,
		Type:     "note",
		Content:  "Test content",
		Metadata: map[string]interface{}{"key": "value"},
	}
	store.CreateThing(thing)

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

func TestListThings(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	// Create multiple things
	for i := 0; i < 5; i++ {
		store.CreateThing(&models.Thing{
			UserID:  testUserID,
			Type:    "note",
			Content: "Test content",
		})
	}
	for i := 0; i < 3; i++ {
		store.CreateThing(&models.Thing{
			UserID:  testUserID,
			Type:    "task",
			Content: "Task content",
		})
	}

	t.Run("list all", func(t *testing.T) {
		things, err := store.ListThings(testUserID, "", 50, 0)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 8 {
			t.Errorf("Expected 8 things, got %d", len(things))
		}
	})

	t.Run("filter by type", func(t *testing.T) {
		things, err := store.ListThings(testUserID, "note", 50, 0)
		if err != nil {
			t.Fatalf("Failed to list things: %v", err)
		}
		if len(things) != 5 {
			t.Errorf("Expected 5 notes, got %d", len(things))
		}
	})

	t.Run("with limit", func(t *testing.T) {
		things, err := store.ListThings(testUserID, "", 3, 0)
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

	thing := &models.Thing{
		UserID:   testUserID,
		Type:     "note",
		Content:  "Original content",
		Metadata: map[string]interface{}{},
	}
	store.CreateThing(thing)

	thing.Content = "Updated content"
	thing.Metadata["updated"] = true
	err := store.UpdateThing(thing)
	if err != nil {
		t.Fatalf("Failed to update thing: %v", err)
	}

	retrieved, _ := store.GetThing(thing.ID)
	if retrieved.Content != "Updated content" {
		t.Errorf("Expected updated content, got %s", retrieved.Content)
	}
}

func TestDeleteThing(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		UserID:  testUserID,
		Type:    "note",
		Content: "To be deleted",
	}
	store.CreateThing(thing)

	err := store.DeleteThing(thing.ID, testUserID)
	if err != nil {
		t.Fatalf("Failed to delete thing: %v", err)
	}

	_, err = store.GetThing(thing.ID)
	if err == nil {
		t.Error("Expected error for deleted thing")
	}
}

func TestSearchThings(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	store.CreateThing(&models.Thing{UserID: testUserID, Type: "note", Content: "Hello world"})
	store.CreateThing(&models.Thing{UserID: testUserID, Type: "note", Content: "Goodbye world"})
	store.CreateThing(&models.Thing{UserID: testUserID, Type: "task", Content: "Hello task"})
	store.CreateThing(&models.Thing{UserID: testUserID, Type: "link", Content: "Random content"})

	t.Run("search by content", func(t *testing.T) {
		things, err := store.SearchThings(testUserID, "Hello", 50)
		if err != nil {
			t.Fatalf("Failed to search: %v", err)
		}
		if len(things) != 2 {
			t.Errorf("Expected 2 results, got %d", len(things))
		}
	})

	t.Run("no results", func(t *testing.T) {
		things, err := store.SearchThings(testUserID, "nonexistent", 50)
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
		UserID:   testUserID,
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

func TestGetKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{
		UserID:   testUserID,
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

func TestGetOrCreateKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	t.Run("create new kind", func(t *testing.T) {
		kind, err := store.GetOrCreateKind(testUserID, "new-kind")
		if err != nil {
			t.Fatalf("Failed to get or create kind: %v", err)
		}
		if kind.Name != "new-kind" {
			t.Errorf("Expected name new-kind, got %s", kind.Name)
		}
	})

	t.Run("get existing kind", func(t *testing.T) {
		kind, err := store.GetOrCreateKind(testUserID, "new-kind")
		if err != nil {
			t.Fatalf("Failed to get existing kind: %v", err)
		}
		if kind.Name != "new-kind" {
			t.Errorf("Expected name new-kind, got %s", kind.Name)
		}
	})
}

func TestDeleteKind(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	kind := &models.Kind{UserID: testUserID, Name: "to-delete"}
	store.CreateKind(kind)

	err := store.DeleteKind(kind.ID, testUserID)
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

	store.CreateKind(&models.Kind{UserID: testUserID, Name: "alpha"})
	store.CreateKind(&models.Kind{UserID: testUserID, Name: "beta"})
	store.CreateKind(&models.Kind{UserID: testUserID, Name: "gamma"})

	kinds, err := store.ListKinds(testUserID)
	if err != nil {
		t.Fatalf("Failed to list kinds: %v", err)
	}

	if len(kinds) != 3 {
		t.Errorf("Expected 3 kinds, got %d", len(kinds))
	}
}

// Tag tests

func TestCreateTag(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	tag := &models.Tag{UserID: testUserID, Name: "important"}
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
		tag, err := store.GetOrCreateTag(testUserID, "new-tag")
		if err != nil {
			t.Fatalf("Failed to get or create tag: %v", err)
		}
		if tag.Name != "new-tag" {
			t.Errorf("Expected name new-tag, got %s", tag.Name)
		}
	})

	t.Run("get existing tag", func(t *testing.T) {
		tag, err := store.GetOrCreateTag(testUserID, "new-tag")
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

	store.CreateTag(&models.Tag{UserID: testUserID, Name: "alpha"})
	store.CreateTag(&models.Tag{UserID: testUserID, Name: "beta"})
	store.CreateTag(&models.Tag{UserID: testUserID, Name: "gamma"})

	tags, err := store.ListTags(testUserID)
	if err != nil {
		t.Fatalf("Failed to list tags: %v", err)
	}

	if len(tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(tags))
	}
}

// Photo tests

func TestCreatePhoto(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	thing := &models.Thing{UserID: testUserID, Type: "photo", Content: "Caption"}
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

	thing := &models.Thing{UserID: testUserID, Type: "photo", Content: "Caption"}
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
}

// View tests

func TestCreateView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{
		UserID: testUserID,
		Name:   "My Feed",
		Type:   "feed",
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
}

func TestGetView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{
		UserID: testUserID,
		Name:   "Tasks Board",
		Type:   "board",
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
}

func TestDeleteView(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	view := &models.View{UserID: testUserID, Name: "To Delete", Type: "feed"}
	store.CreateView(view)

	err := store.DeleteView(view.ID, testUserID)
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

	store.CreateView(&models.View{UserID: testUserID, Name: "Alpha", Type: "feed"})
	store.CreateView(&models.View{UserID: testUserID, Name: "Beta", Type: "table"})
	store.CreateView(&models.View{UserID: testUserID, Name: "Gamma", Type: "board"})

	views, err := store.ListViews(testUserID)
	if err != nil {
		t.Fatalf("Failed to list views: %v", err)
	}

	if len(views) != 3 {
		t.Errorf("Expected 3 views, got %d", len(views))
	}
}

// User tests

func TestCreateUser(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	user := &models.User{
		Username:     "newuser",
		Email:        "new@example.com",
		PasswordHash: "hash123",
		DisplayName:  "New User",
	}

	err := store.CreateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.ID == "" {
		t.Error("Expected ID to be set")
	}
}

func TestGetUserByUsername(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	retrieved, err := store.GetUserByUsername("testuser")
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if retrieved.Username != "testuser" {
		t.Errorf("Expected username testuser, got %s", retrieved.Username)
	}
}

func TestGetUserByEmail(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	retrieved, err := store.GetUserByEmail("test@example.com")
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if retrieved.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", retrieved.Email)
	}
}

// Session tests

func TestCreateSession(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	session := &models.Session{
		UserID: testUserID,
	}

	err := store.CreateSession(session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.ID == "" {
		t.Error("Expected ID to be set")
	}
	if session.Token == "" {
		t.Error("Expected Token to be set")
	}
}

func TestGetSessionByToken(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	session := &models.Session{
		UserID: testUserID,
	}
	store.CreateSession(session)

	retrieved, err := store.GetSessionByToken(session.Token)
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if retrieved.UserID != testUserID {
		t.Errorf("Expected userID %s, got %s", testUserID, retrieved.UserID)
	}
}

func TestDeleteSession(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	session := &models.Session{
		UserID: testUserID,
	}
	store.CreateSession(session)

	err := store.DeleteSession(session.Token)
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	_, err = store.GetSessionByToken(session.Token)
	if err == nil {
		t.Error("Expected error for deleted session")
	}
}

// API Key tests

func TestCreateAPIKey(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	key := &models.APIKey{
		UserID: testUserID,
		Name:   "Test Key",
		Scopes: []string{"things:read", "kinds:read"},
	}
	rawKey := "ts_test123456789"
	keyHash := "hashed_key_value"

	err := store.CreateAPIKey(key, rawKey, keyHash)
	if err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	if key.ID == "" {
		t.Error("Expected ID to be set")
	}
	if key.KeyPrefix == "" {
		t.Error("Expected KeyPrefix to be set")
	}
}

func TestGetAPIKey(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	key := &models.APIKey{
		UserID: testUserID,
		Name:   "Test Key",
		Scopes: []string{"things:read"},
	}
	store.CreateAPIKey(key, "ts_test123456789", "hashed_key")

	retrieved, err := store.GetAPIKey(key.ID)
	if err != nil {
		t.Fatalf("Failed to get API key: %v", err)
	}

	if retrieved.Name != key.Name {
		t.Errorf("Expected name %s, got %s", key.Name, retrieved.Name)
	}
}

func TestGetAPIKeyByPrefix(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	key := &models.APIKey{
		UserID: testUserID,
		Name:   "Prefix Test Key",
		Scopes: []string{"things:read", "things:write"},
	}
	store.CreateAPIKey(key, "ts_prefixtest123", "hashed_key")

	retrieved, err := store.GetAPIKeyByPrefix(key.KeyPrefix)
	if err != nil {
		t.Fatalf("Failed to get API key by prefix: %v", err)
	}

	if retrieved.Name != key.Name {
		t.Errorf("Expected name %s, got %s", key.Name, retrieved.Name)
	}
}

func TestListAPIKeys(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Keys need at least 8 chars after prefix for the prefix extraction
	store.CreateAPIKey(&models.APIKey{UserID: testUserID, Name: "Key 1", Scopes: []string{"things:read"}}, "ts_key1abcdef123", "hash1")
	store.CreateAPIKey(&models.APIKey{UserID: testUserID, Name: "Key 2", Scopes: []string{"kinds:read"}}, "ts_key2abcdef456", "hash2")
	store.CreateAPIKey(&models.APIKey{UserID: testUserID, Name: "Key 3", Scopes: []string{}}, "ts_key3abcdef789", "hash3")

	keys, err := store.ListAPIKeys(testUserID)
	if err != nil {
		t.Fatalf("Failed to list API keys: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 API keys, got %d", len(keys))
	}
}

func TestDeleteAPIKey(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	key := &models.APIKey{
		UserID: testUserID,
		Name:   "To Delete",
		Scopes: []string{"things:read"},
	}
	store.CreateAPIKey(key, "ts_todelete123", "hashed_key")

	err := store.DeleteAPIKey(key.ID, testUserID)
	if err != nil {
		t.Fatalf("Failed to delete API key: %v", err)
	}

	_, err = store.GetAPIKey(key.ID)
	if err == nil {
		t.Error("Expected error for deleted API key")
	}
}

func TestAPIKeyScopes(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	t.Run("admin key has no scopes", func(t *testing.T) {
		key := &models.APIKey{
			UserID: testUserID,
			Name:   "Admin Key",
			Scopes: []string{}, // Empty = admin with all permissions
		}
		store.CreateAPIKey(key, "ts_admin123", "hash")

		retrieved, _ := store.GetAPIKey(key.ID)
		if len(retrieved.Scopes) != 0 {
			t.Error("Admin key should have empty scopes")
		}
	})

	t.Run("scoped key has specific scopes", func(t *testing.T) {
		key := &models.APIKey{
			UserID: testUserID,
			Name:   "Scoped Key",
			Scopes: []string{"things:read", "kinds:read"},
		}
		store.CreateAPIKey(key, "ts_scoped123", "hash")

		retrieved, _ := store.GetAPIKey(key.ID)
		if len(retrieved.Scopes) != 2 {
			t.Errorf("Expected 2 scopes, got %d", len(retrieved.Scopes))
		}
	})
}
