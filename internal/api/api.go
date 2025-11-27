package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"tenant/internal/auth"
	"tenant/internal/models"
	"tenant/internal/store"

	"github.com/go-chi/chi/v5"
)

const (
	CookieMaxAge = 6 * 30 * 24 * 60 * 60 // 6 months in seconds
)

type API struct {
	store *store.Store
	auth  *auth.AuthManager
}

func New(s *store.Store) *API {
	password := os.Getenv("TENANT_PASSWORD")
	if password == "" {
		password = "dev" // Default for local development
	}

	// Data directory for token storage
	dataDir := os.Getenv("TENANT_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	// Initialize auth manager
	authMgr, err := auth.New(password, dataDir)
	if err != nil {
		panic("failed to initialize auth: " + err.Error())
	}

	return &API{store: s, auth: authMgr}
}

// AuthMiddleware checks for valid token in Authorization header or cookie
func (a *API) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header first (Bearer token)
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if a.auth.ValidateToken(token) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check cookie
		cookie, err := r.Cookie("tenant_auth")
		if err == nil && a.auth.ValidateToken(cookie.Value) {
			next.ServeHTTP(w, r)
			return
		}

		respondError(w, http.StatusUnauthorized, "Unauthorized")
	})
}

func (a *API) Routes() chi.Router {
	r := chi.NewRouter()

	// Auth endpoint (no auth required)
	r.Post("/auth", a.authenticate)
	r.Post("/auth/logout", a.logout)
	r.Get("/auth/check", a.checkAuth)

	// Photos endpoint - public for serving images (auth via cookie for upload)
	r.Get("/photos/{id}", a.servePhoto)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(a.AuthMiddleware)

		// Things
		r.Route("/things", func(r chi.Router) {
			r.Get("/", a.listThings)
			r.Post("/", a.createThing)
			r.Get("/search", a.searchThings)
			r.Get("/{id}", a.getThing)
			r.Put("/{id}", a.updateThing)
			r.Delete("/{id}", a.deleteThing)
		})

		// Kinds
		r.Route("/kinds", func(r chi.Router) {
			r.Get("/", a.listKinds)
			r.Post("/", a.createKind)
			r.Get("/{id}", a.getKind)
			r.Put("/{id}", a.updateKind)
			r.Delete("/{id}", a.deleteKind)
		})

		// Tags
		r.Route("/tags", func(r chi.Router) {
			r.Get("/", a.listTags)
			r.Post("/", a.createTag)
		})

		// Views
		r.Route("/views", func(r chi.Router) {
			r.Get("/", a.listViews)
			r.Post("/", a.createView)
			r.Get("/{id}", a.getView)
			r.Put("/{id}", a.updateView)
			r.Delete("/{id}", a.deleteView)
		})

		// Photos
		r.Post("/upload", a.uploadPhoto)
	})

	return r
}

// Auth handlers

func (a *API) authenticate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PasswordHash string `json:"passwordHash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Verify the password hash
	if !a.auth.VerifyPasswordHash(req.PasswordHash) {
		respondError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	// Generate a new session token
	token, err := a.auth.GenerateToken()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie for browser persistence (6 months)
	http.SetCookie(w, &http.Cookie{
		Name:     "tenant_auth",
		Value:    token,
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	// Return token and expiry for client
	expiry := a.auth.GetTokenExpiry()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"token":     token,
		"expiresAt": expiry.Format(time.RFC3339),
	})
}

func (a *API) checkAuth(w http.ResponseWriter, r *http.Request) {
	// Check Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if a.auth.ValidateToken(token) {
			respondJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
			return
		}
	}

	// Check cookie
	cookie, err := r.Cookie("tenant_auth")
	if err == nil && a.auth.ValidateToken(cookie.Value) {
		respondJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
		return
	}

	respondJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	// Revoke the token from disk
	a.auth.RevokeToken()

	// Clear the auth cookie by setting it to expire in the past
	http.SetCookie(w, &http.Cookie{
		Name:     "tenant_auth",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// JSON helpers

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// Thing handlers

func (a *API) listThings(w http.ResponseWriter, r *http.Request) {
	thingType := r.URL.Query().Get("type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit == 0 {
		limit = 50
	}

	things, err := a.store.ListThings(thingType, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if things == nil {
		things = []models.Thing{}
	}

	respondJSON(w, http.StatusOK, things)
}

func (a *API) createThing(w http.ResponseWriter, r *http.Request) {
	var t models.Thing
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if t.Type == "" {
		respondError(w, http.StatusBadRequest, "Type is required")
		return
	}

	if err := a.store.CreateThing(&t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, t)
}

func (a *API) getThing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	t, err := a.store.GetThing(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Thing not found")
		return
	}

	respondJSON(w, http.StatusOK, t)
}

func (a *API) updateThing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var t models.Thing
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	t.ID = id
	if err := a.store.UpdateThing(&t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, t)
}

func (a *API) deleteThing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteThing(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) searchThings(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	if limit == 0 {
		limit = 50
	}

	things, err := a.store.SearchThings(query, limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if things == nil {
		things = []models.Thing{}
	}

	respondJSON(w, http.StatusOK, things)
}

// Kind handlers

func (a *API) listKinds(w http.ResponseWriter, r *http.Request) {
	kinds, err := a.store.ListKinds()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if kinds == nil {
		kinds = []models.Kind{}
	}

	respondJSON(w, http.StatusOK, kinds)
}

func (a *API) createKind(w http.ResponseWriter, r *http.Request) {
	var k models.Kind
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if k.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if err := a.store.CreateKind(&k); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, k)
}

func (a *API) getKind(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	k, err := a.store.GetKind(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Kind not found")
		return
	}

	respondJSON(w, http.StatusOK, k)
}

func (a *API) updateKind(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var k models.Kind
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	k.ID = id
	if err := a.store.UpdateKind(&k); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, k)
}

func (a *API) deleteKind(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteKind(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Tag handlers

func (a *API) listTags(w http.ResponseWriter, r *http.Request) {
	tags, err := a.store.ListTags()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if tags == nil {
		tags = []models.Tag{}
	}

	respondJSON(w, http.StatusOK, tags)
}

func (a *API) createTag(w http.ResponseWriter, r *http.Request) {
	var t models.Tag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if t.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	tag, err := a.store.GetOrCreateTag(t.Name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, tag)
}

// Photo upload handler - stores photo as blob in SQLite

func (a *API) uploadPhoto(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (32MB max)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondError(w, http.StatusBadRequest, "Failed to parse form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		respondError(w, http.StatusBadRequest, "No file provided")
		return
	}
	defer file.Close()

	// Validate file type
	contentType := header.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") && !strings.HasPrefix(contentType, "video/") {
		respondError(w, http.StatusBadRequest, "Only images and videos are allowed")
		return
	}

	// Read file data into memory
	data, err := io.ReadAll(file)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to read file")
		return
	}

	// Get optional caption
	caption := r.FormValue("caption")

	// Create a Thing with type "photo"
	t := &models.Thing{
		Type:    "photo",
		Content: caption,
		Metadata: map[string]interface{}{
			"filename":    header.Filename,
			"contentType": contentType,
			"size":        len(data),
		},
	}

	if err := a.store.CreateThing(t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Create Photo blob linked to the Thing
	photo := &models.Photo{
		ThingID:     t.ID,
		Data:        data,
		ContentType: contentType,
		Filename:    header.Filename,
		Size:        int64(len(data)),
	}

	if err := a.store.CreatePhoto(photo); err != nil {
		// Clean up the Thing if photo creation fails
		a.store.DeleteThing(t.ID)
		respondError(w, http.StatusInternalServerError, "Failed to save photo: "+err.Error())
		return
	}

	// Add photo ID to metadata so frontend knows how to fetch it
	t.Metadata["photoId"] = photo.ID
	t.Metadata["url"] = "/api/photos/" + photo.ID
	a.store.UpdateThing(t)

	respondJSON(w, http.StatusCreated, t)
}

// Photo serve handler - serves photo blob from SQLite

func (a *API) servePhoto(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	photo, err := a.store.GetPhoto(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Photo not found")
		return
	}

	w.Header().Set("Content-Type", photo.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(photo.Size, 10))
	w.Header().Set("Cache-Control", "public, max-age=31536000") // Cache for 1 year
	w.Write(photo.Data)
}

// View handlers

func (a *API) listViews(w http.ResponseWriter, r *http.Request) {
	views, err := a.store.ListViews()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if views == nil {
		views = []models.View{}
	}

	respondJSON(w, http.StatusOK, views)
}

func (a *API) createView(w http.ResponseWriter, r *http.Request) {
	var v models.View
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if v.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	if v.Type == "" {
		v.Type = "feed" // Default view type
	}

	// Validate view type
	validTypes := map[string]bool{"feed": true, "table": true, "board": true, "calendar": true}
	if !validTypes[v.Type] {
		respondError(w, http.StatusBadRequest, "Invalid view type. Must be: feed, table, board, or calendar")
		return
	}

	if err := a.store.CreateView(&v); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, v)
}

func (a *API) getView(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	v, err := a.store.GetView(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "View not found")
		return
	}

	respondJSON(w, http.StatusOK, v)
}

func (a *API) updateView(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var v models.View
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	v.ID = id

	// Validate view type if provided
	if v.Type != "" {
		validTypes := map[string]bool{"feed": true, "table": true, "board": true, "calendar": true}
		if !validTypes[v.Type] {
			respondError(w, http.StatusBadRequest, "Invalid view type. Must be: feed, table, board, or calendar")
			return
		}
	}

	if err := a.store.UpdateView(&v); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, v)
}

func (a *API) deleteView(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteView(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
