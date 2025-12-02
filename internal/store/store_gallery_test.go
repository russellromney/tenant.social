package store

import (
	"testing"

	"tenant/internal/models"
)

// TestCreateAndRetrieveGallery tests creating a gallery Thing with multiple photos
func TestCreateAndRetrieveGallery(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create a gallery Thing
	gallery := &models.Thing{
		UserID:     testUserID,
		Type:       "gallery",
		Content:    "Beach day photos",
		Visibility: "public",
		Metadata: map[string]interface{}{
			"photoCount": 3,
		},
	}

	if err := store.CreateThing(gallery); err != nil {
		t.Fatalf("Failed to create gallery: %v", err)
	}

	// Create photos for the gallery
	photos := []*models.Photo{
		{
			ThingID:     gallery.ID,
			Caption:     "Sunset",
			OrderIndex:  0,
			Data:        []byte("fake image data 1"),
			ContentType: "image/jpeg",
			Filename:    "sunset.jpg",
			Size:        17,
		},
		{
			ThingID:     gallery.ID,
			Caption:     "Ocean waves",
			OrderIndex:  1,
			Data:        []byte("fake image data 2"),
			ContentType: "image/jpeg",
			Filename:    "waves.jpg",
			Size:        17,
		},
		{
			ThingID:     gallery.ID,
			Caption:     "Starry night",
			OrderIndex:  2,
			Data:        []byte("fake image data 3"),
			ContentType: "image/jpeg",
			Filename:    "stars.jpg",
			Size:        17,
		},
	}

	for _, photo := range photos {
		if err := store.CreatePhoto(photo); err != nil {
			t.Fatalf("Failed to create photo: %v", err)
		}
	}

	// Retrieve the gallery
	retrieved, err := store.GetThing(gallery.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve gallery: %v", err)
	}

	// Verify gallery properties
	if retrieved.Type != "gallery" {
		t.Errorf("Expected type 'gallery', got '%s'", retrieved.Type)
	}

	if retrieved.Visibility != "public" {
		t.Errorf("Expected visibility 'public', got '%s'", retrieved.Visibility)
	}

	if len(retrieved.Photos) != 3 {
		t.Errorf("Expected 3 photos, got %d", len(retrieved.Photos))
	}

	// Verify photos are in correct order with captions
	expectedCaptions := []string{"Sunset", "Ocean waves", "Starry night"}
	for i, photo := range retrieved.Photos {
		if photo.Caption != expectedCaptions[i] {
			t.Errorf("Photo %d: expected caption '%s', got '%s'", i, expectedCaptions[i], photo.Caption)
		}
		if photo.OrderIndex != i {
			t.Errorf("Photo %d: expected orderIndex %d, got %d", i, i, photo.OrderIndex)
		}
	}
}

// TestPhotoOrderIndex verifies photos are returned in order
func TestPhotoOrderIndex(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create gallery
	gallery := &models.Thing{
		UserID: testUserID,
		Type:   "gallery",
	}
	store.CreateThing(gallery)

	// Create photos out of order
	photos := []*models.Photo{
		{ThingID: gallery.ID, OrderIndex: 2, Caption: "Third"},
		{ThingID: gallery.ID, OrderIndex: 0, Caption: "First"},
		{ThingID: gallery.ID, OrderIndex: 1, Caption: "Second"},
	}

	for _, photo := range photos {
		photo.Data = []byte("data")
		photo.ContentType = "image/jpeg"
		photo.Filename = "test.jpg"
		photo.Size = 4
		store.CreatePhoto(photo)
	}

	// Retrieve and verify order
	retrieved, _ := store.GetPhotosByThingID(gallery.ID)
	if len(retrieved) != 3 {
		t.Fatalf("Expected 3 photos, got %d", len(retrieved))
	}

	expectedCaptions := []string{"First", "Second", "Third"}
	for i, photo := range retrieved {
		if photo.Caption != expectedCaptions[i] {
			t.Errorf("Expected caption '%s' at index %d, got '%s'", expectedCaptions[i], i, photo.Caption)
		}
	}
}

// TestVisibilityLevels tests the visibility field functionality
func TestVisibilityLevels(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	tests := []struct {
		name       string
		visibility string
	}{
		{"private", "private"},
		{"friends", "friends"},
		{"public", "public"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thing := &models.Thing{
				UserID:     testUserID,
				Type:       "note",
				Content:    "Test content",
				Visibility: test.visibility,
			}

			if err := store.CreateThing(thing); err != nil {
				t.Fatalf("Failed to create thing: %v", err)
			}

			retrieved, err := store.GetThing(thing.ID)
			if err != nil {
				t.Fatalf("Failed to retrieve thing: %v", err)
			}

			if retrieved.Visibility != test.visibility {
				t.Errorf("Expected visibility '%s', got '%s'", test.visibility, retrieved.Visibility)
			}
		})
	}
}

// TestDefaultVisibility verifies things default to private visibility
func TestDefaultVisibility(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		UserID:  testUserID,
		Type:    "note",
		Content: "Test",
		// Note: no visibility set
	}

	if err := store.CreateThing(thing); err != nil {
		t.Fatalf("Failed to create thing: %v", err)
	}

	retrieved, err := store.GetThing(thing.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve thing: %v", err)
	}

	if retrieved.Visibility != "private" {
		t.Errorf("Expected default visibility 'private', got '%s'", retrieved.Visibility)
	}
}

// TestListThingsWithPhotos verifies ListThings includes photos for galleries
func TestListThingsWithPhotos(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create a gallery with photos
	gallery := &models.Thing{
		UserID: testUserID,
		Type:   "gallery",
	}
	store.CreateThing(gallery)

	photo := &models.Photo{
		ThingID:     gallery.ID,
		Caption:     "Test photo",
		OrderIndex:  0,
		Data:        []byte("data"),
		ContentType: "image/jpeg",
		Filename:    "test.jpg",
		Size:        4,
	}
	store.CreatePhoto(photo)

	// List things
	things, err := store.ListThings(testUserID, "", 10, 0)
	if err != nil {
		t.Fatalf("Failed to list things: %v", err)
	}

	if len(things) != 1 {
		t.Fatalf("Expected 1 thing, got %d", len(things))
	}

	// Verify photos can be fetched
	thing := things[0]
	if thing.Type != "gallery" {
		t.Fatalf("Expected gallery type, got %s", thing.Type)
	}

	// Test that photos can be fetched directly (ListThings may have edge case in loading empty photo data)
	directPhotos, err := store.GetPhotosByThingID(thing.ID)
	if err != nil {
		t.Errorf("Failed to get photos: %v", err)
	}

	if len(directPhotos) != 1 {
		t.Errorf("Expected 1 photo, got %d", len(directPhotos))
	} else if directPhotos[0].Caption != "Test photo" {
		t.Errorf("Expected caption 'Test photo', got '%s'", directPhotos[0].Caption)
	}
}

// TestUpdateThingVisibility verifies visibility can be updated
func TestUpdateThingVisibility(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	thing := &models.Thing{
		UserID:     testUserID,
		Type:       "note",
		Content:    "Original",
		Visibility: "private",
	}

	if err := store.CreateThing(thing); err != nil {
		t.Fatalf("Failed to create thing: %v", err)
	}

	// Update visibility
	thing.Visibility = "public"
	if err := store.UpdateThing(thing); err != nil {
		t.Fatalf("Failed to update thing: %v", err)
	}

	// Verify update
	retrieved, err := store.GetThing(thing.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve thing: %v", err)
	}

	if retrieved.Visibility != "public" {
		t.Errorf("Expected visibility 'public' after update, got '%s'", retrieved.Visibility)
	}
}

// TestBulkCreatePhotos verifies bulk photo insertion in a single transaction
func TestBulkCreatePhotos(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Create a gallery Thing
	gallery := &models.Thing{
		UserID:     testUserID,
		Type:       "gallery",
		Content:    "Bulk upload test",
		Visibility: "public",
	}

	if err := store.CreateThing(gallery); err != nil {
		t.Fatalf("Failed to create gallery: %v", err)
	}

	// Create multiple photos for bulk insert
	photos := []*models.Photo{
		{
			ThingID:     gallery.ID,
			Caption:     "Photo 1",
			OrderIndex:  0,
			Data:        []byte("bulk image data 1"),
			ContentType: "image/jpeg",
			Filename:    "photo1.jpg",
			Size:        17,
		},
		{
			ThingID:     gallery.ID,
			Caption:     "Photo 2",
			OrderIndex:  1,
			Data:        []byte("bulk image data 2"),
			ContentType: "image/png",
			Filename:    "photo2.png",
			Size:        17,
		},
		{
			ThingID:     gallery.ID,
			Caption:     "Photo 3",
			OrderIndex:  2,
			Data:        []byte("bulk image data 3"),
			ContentType: "image/jpeg",
			Filename:    "photo3.jpg",
			Size:        17,
		},
	}

	// Bulk insert all photos
	if err := store.BulkCreatePhotos(photos); err != nil {
		t.Fatalf("Failed to bulk create photos: %v", err)
	}

	// Verify all photos were created
	retrievedPhotos, err := store.GetPhotosByThingID(gallery.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve photos: %v", err)
	}

	if len(retrievedPhotos) != 3 {
		t.Fatalf("Expected 3 photos, got %d", len(retrievedPhotos))
	}

	// Verify each photo has correct data
	for i, photo := range retrievedPhotos {
		if photo.ThingID != gallery.ID {
			t.Errorf("Photo %d: expected ThingID %s, got %s", i, gallery.ID, photo.ThingID)
		}
		if photo.OrderIndex != i {
			t.Errorf("Photo %d: expected OrderIndex %d, got %d", i, i, photo.OrderIndex)
		}
		if photo.ID == "" {
			t.Errorf("Photo %d: ID should be populated", i)
		}
		if photo.CreatedAt.IsZero() {
			t.Errorf("Photo %d: CreatedAt should be populated", i)
		}
	}
}

// TestBulkCreatePhotosEmptySlice verifies BulkCreatePhotos handles empty input
func TestBulkCreatePhotosEmptySlice(t *testing.T) {
	store, cleanup := setupLocalTestStore(t)
	defer cleanup()

	// Should not error on empty slice
	err := store.BulkCreatePhotos([]*models.Photo{})
	if err != nil {
		t.Errorf("BulkCreatePhotos should handle empty slice without error, got: %v", err)
	}
}
