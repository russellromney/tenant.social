package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tenant/internal/models"
	"tenant/internal/store"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	CookieMaxAge    = 6 * 30 * 24 * 60 * 60 // 6 months in seconds
	SessionDuration = 6 * 30 * 24 * time.Hour
)

type contextKey string

const userContextKey contextKey = "user"

type API struct {
	store *store.Store
}

func New(s *store.Store) *API {
	return &API{store: s}
}

// getUserFromContext extracts the authenticated user from the request context
func getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value(userContextKey).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// AuthMiddleware checks for valid session token in Authorization header or cookie
func (a *API) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string

		// Check Authorization header first (Bearer token)
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Check cookie
			cookie, err := r.Cookie("tenant_auth")
			if err == nil {
				token = cookie.Value
			}
		}

		if token == "" {
			respondError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}

		// Validate session
		session, err := a.store.GetSessionByToken(token)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "Invalid session")
			return
		}

		// Check if session is expired
		if session.ExpiresAt.Before(time.Now()) {
			a.store.DeleteSession(token)
			respondError(w, http.StatusUnauthorized, "Session expired")
			return
		}

		// Get user
		user, err := a.store.GetUser(session.UserID)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "User not found")
			return
		}

		// Check if user is locked
		if user.IsLocked {
			respondError(w, http.StatusForbidden, "Account is locked")
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware requires the user to be an admin
func (a *API) AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromContext(r)
		if user == nil || !user.IsAdmin {
			respondError(w, http.StatusForbidden, "Admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) Routes() chi.Router {
	r := chi.NewRouter()

	// Public auth endpoints
	r.Post("/auth/register", a.register)
	r.Post("/auth/login", a.login)
	r.Post("/auth/logout", a.logout)
	r.Get("/auth/check", a.checkAuth)

	// Photos endpoint - public for serving images
	r.Get("/photos/{id}", a.servePhoto)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(a.AuthMiddleware)

		// User profile
		r.Get("/auth/me", a.getMe)
		r.Put("/auth/me", a.updateMe)

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

		// Admin routes
		r.Group(func(r chi.Router) {
			r.Use(a.AdminMiddleware)
			r.Get("/admin/users", a.listUsers)
			r.Put("/admin/users/{id}/lock", a.lockUser)
			r.Put("/admin/users/{id}/unlock", a.unlockUser)
			r.Delete("/admin/users/{id}", a.deleteUser)
		})
	})

	return r
}

// Auth handlers

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Validate required fields
	if req.Username == "" || req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Username, email, and password are required")
		return
	}

	// Validate username format (alphanumeric, underscore, hyphen, 3-30 chars)
	if len(req.Username) < 3 || len(req.Username) > 30 {
		respondError(w, http.StatusBadRequest, "Username must be 3-30 characters")
		return
	}

	// Check if username exists
	if _, err := a.store.GetUserByUsername(req.Username); err == nil {
		respondError(w, http.StatusConflict, "Username already taken")
		return
	}

	// Check if email exists
	if _, err := a.store.GetUserByEmail(req.Email); err == nil {
		respondError(w, http.StatusConflict, "Email already registered")
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Check if this is the first user (make them admin)
	userCount, err := a.store.CountUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		DisplayName:  req.Username,
		IsAdmin:      userCount == 0, // First user is admin
	}

	if err := a.store.CreateUser(user); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Create session
	session := &models.Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	if err := a.store.CreateSession(session); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "tenant_auth",
		Value:    session.Token,
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"user":      user,
		"token":     session.Token,
		"expiresAt": session.ExpiresAt.Format(time.RFC3339),
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"` // Can be username or email
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Find user by username or email
	var user *models.User
	var err error

	if strings.Contains(req.Username, "@") {
		user, err = a.store.GetUserByEmail(req.Username)
	} else {
		user, err = a.store.GetUserByUsername(req.Username)
	}

	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check if user is locked
	if user.IsLocked {
		respondError(w, http.StatusForbidden, "Account is locked")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Create session
	session := &models.Session{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	if err := a.store.CreateSession(session); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create session")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "tenant_auth",
		Value:    session.Token,
		Path:     "/",
		MaxAge:   CookieMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"user":      user,
		"token":     session.Token,
		"expiresAt": session.ExpiresAt.Format(time.RFC3339),
	})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	// Get token from cookie or header
	var token string
	if cookie, err := r.Cookie("tenant_auth"); err == nil {
		token = cookie.Value
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Delete session if token exists
	if token != "" {
		a.store.DeleteSession(token)
	}

	// Clear cookie
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

func (a *API) checkAuth(w http.ResponseWriter, r *http.Request) {
	var token string

	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		// Check cookie
		if cookie, err := r.Cookie("tenant_auth"); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		respondJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
		return
	}

	session, err := a.store.GetSessionByToken(token)
	if err != nil || session.ExpiresAt.Before(time.Now()) {
		respondJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
		return
	}

	user, err := a.store.GetUser(session.UserID)
	if err != nil || user.IsLocked {
		respondJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"authenticated": true,
		"user":          user,
	})
}

func (a *API) getMe(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	respondJSON(w, http.StatusOK, user)
}

func (a *API) updateMe(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	var req struct {
		DisplayName string `json:"displayName"`
		Bio         string `json:"bio"`
		AvatarURL   string `json:"avatarUrl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	user.DisplayName = req.DisplayName
	user.Bio = req.Bio
	user.AvatarURL = req.AvatarURL

	if err := a.store.UpdateUser(user); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	respondJSON(w, http.StatusOK, user)
}

// Admin handlers

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.ListUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Don't send password hashes
	for i := range users {
		users[i].PasswordHash = ""
		users[i].RecoveryHash = ""
	}

	respondJSON(w, http.StatusOK, users)
}

func (a *API) lockUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	currentUser := getUserFromContext(r)

	// Can't lock yourself
	if id == currentUser.ID {
		respondError(w, http.StatusBadRequest, "Cannot lock yourself")
		return
	}

	user, err := a.store.GetUser(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}

	user.IsLocked = true
	if err := a.store.UpdateUser(user); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to lock user")
		return
	}

	// Delete all user sessions
	a.store.DeleteUserSessions(id)

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) unlockUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	user, err := a.store.GetUser(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found")
		return
	}

	user.IsLocked = false
	if err := a.store.UpdateUser(user); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to unlock user")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	currentUser := getUserFromContext(r)

	// Can't delete yourself
	if id == currentUser.ID {
		respondError(w, http.StatusBadRequest, "Cannot delete yourself")
		return
	}

	if err := a.store.DeleteUser(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

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
	user := getUserFromContext(r)
	thingType := r.URL.Query().Get("type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	if limit == 0 {
		limit = 50
	}

	things, err := a.store.ListThings(user.ID, thingType, limit, offset)
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
	user := getUserFromContext(r)

	var t models.Thing
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if t.Type == "" {
		respondError(w, http.StatusBadRequest, "Type is required")
		return
	}

	t.UserID = user.ID

	if err := a.store.CreateThing(&t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, t)
}

func (a *API) getThing(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	t, err := a.store.GetThingForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Thing not found")
		return
	}

	respondJSON(w, http.StatusOK, t)
}

func (a *API) updateThing(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	var t models.Thing
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	t.ID = id
	t.UserID = user.ID
	if err := a.store.UpdateThing(&t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, t)
}

func (a *API) deleteThing(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteThing(id, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) searchThings(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	query := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	if limit == 0 {
		limit = 50
	}

	things, err := a.store.SearchThings(user.ID, query, limit)
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
	user := getUserFromContext(r)

	kinds, err := a.store.ListKinds(user.ID)
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
	user := getUserFromContext(r)

	var k models.Kind
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if k.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	k.UserID = user.ID

	if err := a.store.CreateKind(&k); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, k)
}

func (a *API) getKind(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	k, err := a.store.GetKindForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Kind not found")
		return
	}

	respondJSON(w, http.StatusOK, k)
}

func (a *API) updateKind(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	var k models.Kind
	if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	k.ID = id
	k.UserID = user.ID
	if err := a.store.UpdateKind(&k); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, k)
}

func (a *API) deleteKind(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteKind(id, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Tag handlers

func (a *API) listTags(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	tags, err := a.store.ListTags(user.ID)
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
	user := getUserFromContext(r)

	var t models.Tag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if t.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	tag, err := a.store.GetOrCreateTag(user.ID, t.Name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, tag)
}

// Photo upload handler

func (a *API) uploadPhoto(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

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
		UserID:  user.ID,
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
		a.store.DeleteThing(t.ID, user.ID)
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
	user := getUserFromContext(r)

	views, err := a.store.ListViews(user.ID)
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
	user := getUserFromContext(r)

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

	v.UserID = user.ID

	if err := a.store.CreateView(&v); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, v)
}

func (a *API) getView(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	v, err := a.store.GetViewForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "View not found")
		return
	}

	respondJSON(w, http.StatusOK, v)
}

func (a *API) updateView(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	var v models.View
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	v.ID = id
	v.UserID = user.ID

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
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteView(id, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
