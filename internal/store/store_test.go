package store

import (
	"testing"
	"tenant/internal/models"
)

var testUserID string

func setupTestDB(t *testing.T) *Store {
	cfg := Config{
		Backend:    BackendSQLite,
		SQLitePath: ":memory:",
	}

	store, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}

	return store
}

func setupLocalTestStore(t *testing.T) (*Store, func()) {
	store := setupTestDB(t)

	// Create a test user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	testUserID = user.ID

	cleanup := func() {
		store.Close()
	}

	return store, cleanup
}

func TestGetBacklinks_Basic(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create three things: A, B, C
	thingA := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	thingB := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing B",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingB); err != nil {
		t.Fatalf("failed to create thing B: %v", err)
	}

	thingC := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing C",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingC); err != nil {
		t.Fatalf("failed to create thing C: %v", err)
	}

	// Create Thing D with a link attribute pointing to A
	thingD := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing D",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": thingA.ID,
				},
			},
		},
	}
	if err := store.CreateThing(thingD); err != nil {
		t.Fatalf("failed to create thing D: %v", err)
	}

	// Test GetBacklinks for A - should return [D]
	backlinks, err := store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}

	if len(backlinks) != 1 {
		t.Errorf("expected 1 backlink, got %d", len(backlinks))
	}
	if len(backlinks) > 0 && backlinks[0].ID != thingD.ID {
		t.Errorf("expected backlink from D, got from %s", backlinks[0].ID)
	}

	// Test GetBacklinks for B - should return empty
	backlinks, err = store.GetBacklinks(user.ID, thingB.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 0 {
		t.Errorf("expected 0 backlinks for B, got %d", len(backlinks))
	}
}

func TestGetBacklinks_MultipleLinks(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create things A, B
	thingA := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	thingB := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing B",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingB); err != nil {
		t.Fatalf("failed to create thing B: %v", err)
	}

	// Create Thing E with link to both A and B (array of IDs)
	thingE := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing E",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": []interface{}{thingA.ID, thingB.ID},
				},
			},
		},
	}
	if err := store.CreateThing(thingE); err != nil {
		t.Fatalf("failed to create thing E: %v", err)
	}

	// Test GetBacklinks for A - should return [E]
	backlinks, err := store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 1 {
		t.Errorf("expected 1 backlink for A, got %d", len(backlinks))
	}

	// Test GetBacklinks for B - should return [E]
	backlinks, err = store.GetBacklinks(user.ID, thingB.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 1 {
		t.Errorf("expected 1 backlink for B, got %d", len(backlinks))
	}
}

func TestGetBacklinks_MultipleThingsLinking(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create thing A
	thingA := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	// Create Thing D linking to A
	thingD := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing D",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": thingA.ID,
				},
			},
		},
	}
	if err := store.CreateThing(thingD); err != nil {
		t.Fatalf("failed to create thing D: %v", err)
	}

	// Create Thing E linking to A
	thingE := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing E",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": thingA.ID,
				},
			},
		},
	}
	if err := store.CreateThing(thingE); err != nil {
		t.Fatalf("failed to create thing E: %v", err)
	}

	// Test GetBacklinks for A - should return [D, E]
	backlinks, err := store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 2 {
		t.Errorf("expected 2 backlinks, got %d", len(backlinks))
	}

	// Verify both D and E are in backlinks
	backlinkIDs := make(map[string]bool)
	for _, bl := range backlinks {
		backlinkIDs[bl.ID] = true
	}
	if !backlinkIDs[thingD.ID] {
		t.Errorf("expected D in backlinks")
	}
	if !backlinkIDs[thingE.ID] {
		t.Errorf("expected E in backlinks")
	}
}

func TestGetBacklinks_ExcludesDeleted(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create thing A
	thingA := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	// Create Thing D linking to A
	thingD := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing D",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": thingA.ID,
				},
			},
		},
	}
	if err := store.CreateThing(thingD); err != nil {
		t.Fatalf("failed to create thing D: %v", err)
	}

	// Verify D is a backlink
	backlinks, err := store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 1 {
		t.Errorf("expected 1 backlink before delete, got %d", len(backlinks))
	}

	// Soft-delete D
	if err := store.SoftDeleteThing(thingD.ID, user.ID); err != nil {
		t.Fatalf("failed to delete thing D: %v", err)
	}

	// GetBacklinks should now return empty (D is deleted)
	backlinks, err = store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 0 {
		t.Errorf("expected 0 backlinks after delete, got %d", len(backlinks))
	}
}

func TestGetBacklinks_UserIsolation(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create two users
	user1 := &models.User{
		Username:     "user1",
		Email:        "user1@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user1); err != nil {
		t.Fatalf("failed to create user1: %v", err)
	}

	user2 := &models.User{
		Username:     "user2",
		Email:        "user2@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user2); err != nil {
		t.Fatalf("failed to create user2: %v", err)
	}

	// Create thing A for user1
	thingA := &models.Thing{
		UserID:   user1.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	// Create thing B for user2
	thingB := &models.Thing{
		UserID:   user2.ID,
		Type:     "note",
		Content:  "Thing B",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingB); err != nil {
		t.Fatalf("failed to create thing B: %v", err)
	}

	// Create thing C for user2 linking to thingB
	thingC := &models.Thing{
		UserID:  user2.ID,
		Type:    "note",
		Content: "Thing C",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "link",
					"name":  "related",
					"value": thingB.ID,
				},
			},
		},
	}
	if err := store.CreateThing(thingC); err != nil {
		t.Fatalf("failed to create thing C: %v", err)
	}

	// User1's GetBacklinks for thingA should return empty
	backlinks, err := store.GetBacklinks(user1.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 0 {
		t.Errorf("expected 0 backlinks for user1, got %d", len(backlinks))
	}

	// User2's GetBacklinks for thingB should return [C]
	backlinks, err = store.GetBacklinks(user2.ID, thingB.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 1 {
		t.Errorf("expected 1 backlink for user2, got %d", len(backlinks))
	}
}

func TestGetBacklinks_NonexistentTarget(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Query backlinks for a thing that doesn't exist
	backlinks, err := store.GetBacklinks(user.ID, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}

	// Should return empty (no error, just no results)
	if len(backlinks) != 0 {
		t.Errorf("expected 0 backlinks for nonexistent target, got %d", len(backlinks))
	}
}

func TestGetBacklinks_NoLinkAttributes(t *testing.T) {
	store := setupTestDB(t)
	defer store.Close()

	// Create a user
	user := &models.User{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	if err := store.CreateUser(user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Create thing A
	thingA := &models.Thing{
		UserID:   user.ID,
		Type:     "note",
		Content:  "Thing A",
		Metadata: map[string]interface{}{},
	}
	if err := store.CreateThing(thingA); err != nil {
		t.Fatalf("failed to create thing A: %v", err)
	}

	// Create thing D with non-link attributes
	thingD := &models.Thing{
		UserID:  user.ID,
		Type:    "note",
		Content: "Thing D",
		Metadata: map[string]interface{}{
			"attributes": []interface{}{
				map[string]interface{}{
					"type":  "text",
					"name":  "description",
					"value": "some text",
				},
			},
		},
	}
	if err := store.CreateThing(thingD); err != nil {
		t.Fatalf("failed to create thing D: %v", err)
	}

	// GetBacklinks for A should return empty (D has no link attributes)
	backlinks, err := store.GetBacklinks(user.ID, thingA.ID)
	if err != nil {
		t.Fatalf("GetBacklinks failed: %v", err)
	}
	if len(backlinks) != 0 {
		t.Errorf("expected 0 backlinks, got %d", len(backlinks))
	}
}
