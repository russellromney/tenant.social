package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"

	"tenant/internal/auth"
	"tenant/internal/store"
)

const testPassword = "testpassword123"

// testAPI creates a test API instance with Turso dev database
func testAPI(t *testing.T) (*API, func()) {
	t.Helper()

	dbURL := os.Getenv("TURSO_DATABASE_URL")
	authToken := os.Getenv("TURSO_AUTH_TOKEN")
	if dbURL == "" || authToken == "" {
		t.Skip("TURSO_DATABASE_URL and TURSO_AUTH_TOKEN not set, skipping test")
	}

	cfg := store.Config{
		Backend:    store.BackendTurso,
		TursoURL:   dbURL,
		TursoToken: authToken,
	}

	s, err := store.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	tmpDir := t.TempDir()

	// Set env for API creation
	os.Setenv("TENANT_PASSWORD", testPassword)
	os.Setenv("TENANT_DATA_DIR", tmpDir)

	api := New(s)

	cleanup := func() {
		// Clean up test data
		s.Close()
		os.Unsetenv("TENANT_PASSWORD")
		os.Unsetenv("TENANT_DATA_DIR")
	}

	return api, cleanup
}

// getValidToken authenticates and returns a valid token
func getValidToken(t *testing.T, api *API) string {
	t.Helper()

	passwordHash := auth.HashPassword(testPassword)

	body, _ := json.Marshal(map[string]string{"passwordHash": passwordHash})
	req := httptest.NewRequest("POST", "/auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	api.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to authenticate: %d - %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	token, ok := resp["token"].(string)
	if !ok {
		t.Fatal("No token in response")
	}

	return token
}

// TestAuthenticate tests the authentication endpoint
func TestAuthenticate(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	t.Run("valid password hash", func(t *testing.T) {
		passwordHash := auth.HashPassword(testPassword)
		body, _ := json.Marshal(map[string]string{"passwordHash": passwordHash})

		req := httptest.NewRequest("POST", "/auth", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["status"] != "ok" {
			t.Error("Expected status ok")
		}
		if resp["token"] == nil {
			t.Error("Expected token in response")
		}
		if resp["expiresAt"] == nil {
			t.Error("Expected expiresAt in response")
		}

		// Check cookie was set
		cookies := w.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == "tenant_auth" {
				found = true
				if c.HttpOnly != true {
					t.Error("Cookie should be HttpOnly")
				}
				break
			}
		}
		if !found {
			t.Error("Expected tenant_auth cookie to be set")
		}
	})

	t.Run("invalid password hash", func(t *testing.T) {
		passwordHash := auth.HashPassword("wrongpassword")
		body, _ := json.Marshal(map[string]string{"passwordHash": passwordHash})

		req := httptest.NewRequest("POST", "/auth", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/auth", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", w.Code)
		}
	})
}

// TestCheckAuth tests the auth check endpoint
func TestCheckAuth(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	t.Run("no auth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/check", nil)

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		var resp map[string]bool
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["authenticated"] != false {
			t.Error("Expected authenticated to be false")
		}
	})

	t.Run("with valid token cookie", func(t *testing.T) {
		token := getValidToken(t, api)

		req := httptest.NewRequest("GET", "/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		var resp map[string]bool
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["authenticated"] != true {
			t.Error("Expected authenticated to be true")
		}
	})

	t.Run("with valid bearer token", func(t *testing.T) {
		token := getValidToken(t, api)

		req := httptest.NewRequest("GET", "/auth/check", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		var resp map[string]bool
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["authenticated"] != true {
			t.Error("Expected authenticated to be true")
		}
	})

	t.Run("with invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: "invalidtoken"})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		var resp map[string]bool
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["authenticated"] != false {
			t.Error("Expected authenticated to be false")
		}
	})
}

// TestLogout tests the logout endpoint
func TestLogout(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	// Logout
	req := httptest.NewRequest("POST", "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

	w := httptest.NewRecorder()
	api.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Check cookie was cleared
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "tenant_auth" {
			if c.MaxAge != -1 {
				t.Error("Cookie MaxAge should be -1 to clear it")
			}
			break
		}
	}

	// Token should no longer be valid
	req = httptest.NewRequest("GET", "/auth/check", nil)
	req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

	w = httptest.NewRecorder()
	api.Routes().ServeHTTP(w, req)

	var resp map[string]bool
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["authenticated"] != false {
		t.Error("Token should be invalid after logout")
	}
}

// TestAuthMiddleware tests that protected routes require authentication
func TestAuthMiddleware(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	protectedRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/things"},
		{"POST", "/things"},
		{"GET", "/things/123"},
		{"PUT", "/things/123"},
		{"DELETE", "/things/123"},
		{"GET", "/kinds"},
		{"POST", "/kinds"},
		{"GET", "/tags"},
	}

	t.Run("without auth", func(t *testing.T) {
		for _, route := range protectedRoutes {
			req := httptest.NewRequest(route.method, route.path, nil)
			w := httptest.NewRecorder()
			api.Routes().ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: expected 401, got %d", route.method, route.path, w.Code)
			}
		}
	})

	t.Run("with valid auth", func(t *testing.T) {
		token := getValidToken(t, api)

		// Test GET /things with auth
		req := httptest.NewRequest("GET", "/things", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code == http.StatusUnauthorized {
			t.Error("Should allow access with valid token")
		}
	})
}

// TestThingsCRUD tests CRUD operations on things
func TestThingsCRUD(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	var thingID string

	t.Run("create thing", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"type":    "note",
			"content": "Test note content",
			"metadata": map[string]interface{}{
				"priority": "high",
			},
		})

		req := httptest.NewRequest("POST", "/things", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		thingID = resp["id"].(string)
		if thingID == "" {
			t.Error("Expected ID in response")
		}
		if resp["type"] != "note" {
			t.Error("Expected type to be note")
		}
		if resp["content"] != "Test note content" {
			t.Error("Expected content to match")
		}
	})

	t.Run("list things", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/things", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if len(resp) != 1 {
			t.Errorf("Expected 1 thing, got %d", len(resp))
		}
	})

	t.Run("get thing", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/things/"+thingID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["id"] != thingID {
			t.Error("Expected ID to match")
		}
	})

	t.Run("update thing", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"type":    "note",
			"content": "Updated content",
		})

		req := httptest.NewRequest("PUT", "/things/"+thingID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["content"] != "Updated content" {
			t.Error("Expected content to be updated")
		}
	})

	t.Run("search things", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/things/search?q=Updated", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if len(resp) != 1 {
			t.Errorf("Expected 1 search result, got %d", len(resp))
		}
	})

	t.Run("delete thing", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/things/"+thingID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("Expected 204, got %d", w.Code)
		}

		// Verify deleted
		req = httptest.NewRequest("GET", "/things/"+thingID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w = httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected 404 after delete, got %d", w.Code)
		}
	})
}

// TestKindsCRUD tests CRUD operations on kinds
func TestKindsCRUD(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	var kindID string

	t.Run("create kind", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name":     "bookmark",
			"icon":     "🔖",
			"template": "link",
			"attributes": []map[string]interface{}{
				{"name": "url", "type": "url", "required": true},
			},
		})

		req := httptest.NewRequest("POST", "/kinds", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		kindID = resp["id"].(string)
		if kindID == "" {
			t.Error("Expected ID in response")
		}
	})

	t.Run("list kinds", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kinds", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if len(resp) < 1 {
			t.Error("Expected at least 1 kind")
		}
	})

	t.Run("get kind", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kinds/"+kindID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}
	})

	t.Run("update kind", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name": "bookmark",
			"icon": "📚",
		})

		req := httptest.NewRequest("PUT", "/kinds/"+kindID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["icon"] != "📚" {
			t.Error("Expected icon to be updated")
		}
	})

	t.Run("delete kind", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/kinds/"+kindID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("Expected 204, got %d", w.Code)
		}
	})
}

// TestTagsCRUD tests operations on tags
func TestTagsCRUD(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	t.Run("create tag", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "important"})

		req := httptest.NewRequest("POST", "/tags", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("list tags", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/tags", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if len(resp) < 1 {
			t.Error("Expected at least 1 tag")
		}
	})
}

// TestThingsValidation tests input validation for things
func TestThingsValidation(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	t.Run("create thing without type", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"content": "Test content",
		})

		req := httptest.NewRequest("POST", "/things", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", w.Code)
		}
	})
}

// TestBearerTokenAuth tests authentication via Bearer token header
func TestBearerTokenAuth(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	t.Run("access protected route with Bearer token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/things", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code == http.StatusUnauthorized {
			t.Error("Should allow access with Bearer token")
		}
	})

	t.Run("invalid Bearer token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/things", nil)
		req.Header.Set("Authorization", "Bearer invalidtoken")

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", w.Code)
		}
	})
}

// TestPhotoUpload tests photo upload and retrieval
func TestPhotoUpload(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	var photoURL string

	t.Run("upload photo", func(t *testing.T) {
		// Create a simple test image (1x1 PNG)
		pngData := []byte{
			0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
			0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
			0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
			0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F,
			0x00, 0x05, 0xFE, 0x02, 0xFE, 0xDC, 0xCC, 0x59,
			0xE7, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
			0x44, 0xAE, 0x42, 0x60, 0x82, // IEND chunk
		}

		// Create multipart form with proper content-type header
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// Create form file with explicit content-type
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="file"; filename="test.png"`)
		h.Set("Content-Type", "image/png")
		part, err := writer.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		part.Write(pngData)
		writer.WriteField("caption", "Test photo caption")
		writer.Close()

		req := httptest.NewRequest("POST", "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["type"] != "photo" {
			t.Error("Expected type to be photo")
		}
		if resp["content"] != "Test photo caption" {
			t.Error("Expected caption to match")
		}

		metadata := resp["metadata"].(map[string]interface{})
		photoURL = metadata["url"].(string)
		if photoURL == "" {
			t.Error("Expected photo URL in metadata")
		}
	})

	t.Run("retrieve photo", func(t *testing.T) {
		if photoURL == "" {
			t.Skip("No photo URL from upload test")
		}

		// photoURL is "/api/photos/{id}" but our routes don't have /api prefix
		// Extract just the /photos/{id} part
		photoPath := strings.TrimPrefix(photoURL, "/api")
		req := httptest.NewRequest("GET", photoPath, nil)

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "image/png" {
			t.Errorf("Expected Content-Type image/png, got %s", contentType)
		}

		if w.Body.Len() == 0 {
			t.Error("Expected non-empty response body")
		}
	})

	t.Run("photo not found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/photos/nonexistent", nil)

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected 404, got %d", w.Code)
		}
	})
}

// TestViewsCRUD tests CRUD operations on views
func TestViewsCRUD(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	var viewID string

	t.Run("create view", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name": "My Feed",
			"type": "feed",
			"config": map[string]interface{}{
				"sort": map[string]string{
					"field": "created_at",
					"order": "desc",
				},
			},
		})

		req := httptest.NewRequest("POST", "/views", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		viewID = resp["id"].(string)
		if viewID == "" {
			t.Error("Expected ID in response")
		}
		if resp["type"] != "feed" {
			t.Error("Expected type to be feed")
		}
	})

	t.Run("list views", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/views", nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if len(resp) < 1 {
			t.Error("Expected at least 1 view")
		}
	})

	t.Run("get view", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/views/"+viewID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d", w.Code)
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["id"] != viewID {
			t.Error("Expected ID to match")
		}
	})

	t.Run("update view", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name": "Updated Feed",
			"type": "table",
			"config": map[string]interface{}{
				"columns": []string{"content", "type", "created_at"},
			},
		})

		req := httptest.NewRequest("PUT", "/views/"+viewID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["name"] != "Updated Feed" {
			t.Error("Expected name to be updated")
		}
		if resp["type"] != "table" {
			t.Error("Expected type to be table")
		}
	})

	t.Run("delete view", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/views/"+viewID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Fatalf("Expected 204, got %d", w.Code)
		}

		// Verify deleted
		req = httptest.NewRequest("GET", "/views/"+viewID, nil)
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w = httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected 404 after delete, got %d", w.Code)
		}
	})
}

// TestViewsValidation tests input validation for views
func TestViewsValidation(t *testing.T) {
	api, cleanup := testAPI(t)
	defer cleanup()

	token := getValidToken(t, api)

	t.Run("create view without name", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"type": "feed",
		})

		req := httptest.NewRequest("POST", "/views", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", w.Code)
		}
	})

	t.Run("create view with invalid type", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name": "Test View",
			"type": "invalid",
		})

		req := httptest.NewRequest("POST", "/views", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected 400, got %d", w.Code)
		}
	})

	t.Run("create view with default type", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"name": "Default Type View",
		})

		req := httptest.NewRequest("POST", "/views", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "tenant_auth", Value: token})

		w := httptest.NewRecorder()
		api.Routes().ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Expected 201, got %d: %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		if resp["type"] != "feed" {
			t.Errorf("Expected default type 'feed', got %s", resp["type"])
		}
	})
}
