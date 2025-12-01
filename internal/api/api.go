package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	_ "image/gif"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tenant/internal/models"
	"tenant/internal/store"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	CookieMaxAge    = 6 * 30 * 24 * 60 * 60 // 6 months in seconds
	SessionDuration = 6 * 30 * 24 * time.Hour
	APIKeyPrefix    = "ts_" // tenant-social API key prefix

	// Image cache configuration
	PhotoCacheDir             = "/tmp/tenant-photo-cache"
	PhotoCacheTTL             = 30 * 24 * time.Hour // 30 days
	PhotoCacheCleanupInterval = 6 * time.Hour       // Cleanup every 6 hours

	// Full size image settings (for modal viewer)
	PhotoQuality  = 80  // JPEG quality (0-100)
	PhotoMaxWidth = 1600 // Max width in pixels

	// Thumbnail settings (for feed/gallery display)
	PhotoThumbQuality  = 65  // Lower quality for thumbnails
	PhotoThumbMaxWidth = 400 // Smaller size for gallery thumbnails
)

type contextKey string

const userContextKey contextKey = "user"
const apiKeyContextKey contextKey = "apiKey"
const creatorIDContextKey contextKey = "creatorID" // user ID or API key ID

type API struct {
	store       *store.Store
	sandboxMode bool
}

func New(s *store.Store) *API {
	return NewWithSandbox(s, false)
}

func NewWithSandbox(s *store.Store, sandboxMode bool) *API {
	api := &API{store: s, sandboxMode: sandboxMode}

	// Start background cache cleanup routine
	go api.cleanupPhotoCache()

	return api
}

// getUserFromContext extracts the authenticated user from the request context
func getUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value(userContextKey).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// getAPIKeyFromContext extracts the API key from the request context (if auth was via API key)
func getAPIKeyFromContext(r *http.Request) *models.APIKey {
	apiKey, ok := r.Context().Value(apiKeyContextKey).(*models.APIKey)
	if !ok {
		return nil
	}
	return apiKey
}

// getCreatorIDFromContext returns the ID of who's making the request (user ID or API key ID)
func getCreatorIDFromContext(r *http.Request) string {
	creatorID, ok := r.Context().Value(creatorIDContextKey).(string)
	if !ok {
		user := getUserFromContext(r)
		if user != nil {
			return user.ID
		}
		return ""
	}
	return creatorID
}

// generateAPIKey generates a new random API key
func generateAPIKey() (string, error) {
	bytes := make([]byte, 24) // 48 hex chars
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return APIKeyPrefix + hex.EncodeToString(bytes), nil
}

// hasScope checks if an API key has a specific scope
// Empty scopes means admin/all permissions (full access)
func hasScope(apiKey *models.APIKey, scope string) bool {
	// Empty scopes = admin key with all permissions
	if len(apiKey.Scopes) == 0 {
		return true
	}
	for _, s := range apiKey.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// AuthMiddleware checks for valid session token or API key in Authorization header or cookie
func (a *API) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sandbox mode: bypass auth and use sandbox user
		if a.sandboxMode {
			a.authenticateAsSandboxUser(w, r, next)
			return
		}

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

		// Check if it's an API key (starts with ts_)
		if strings.HasPrefix(token, APIKeyPrefix) {
			a.authenticateWithAPIKey(w, r, next, token)
			return
		}

		// Otherwise, treat as session token
		a.authenticateWithSession(w, r, next, token)
	})
}

// authenticateAsSandboxUser bypasses auth and uses the sandbox user for all requests
func (a *API) authenticateAsSandboxUser(w http.ResponseWriter, r *http.Request, next http.Handler) {
	user, err := a.store.GetUserByUsername("sandbox")
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Sandbox user not found")
		return
	}

	ctx := context.WithValue(r.Context(), userContextKey, user)
	ctx = context.WithValue(ctx, creatorIDContextKey, user.ID)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// authenticateWithAPIKey validates an API key and sets up the context
func (a *API) authenticateWithAPIKey(w http.ResponseWriter, r *http.Request, next http.Handler, rawKey string) {
	// Get the key prefix (first 8 chars including ts_)
	if len(rawKey) < 8 {
		respondError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}
	prefix := rawKey[:8]

	// Find API key by prefix
	apiKey, err := a.store.GetAPIKeyByPrefix(prefix)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	// Verify the full key against stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(apiKey.KeyHash), []byte(rawKey)); err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid API key")
		return
	}

	// Check if key is expired
	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		respondError(w, http.StatusUnauthorized, "API key expired")
		return
	}

	// Get the user who owns this API key
	user, err := a.store.GetUser(apiKey.UserID)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "User not found")
		return
	}

	// Check if user is locked
	if user.IsLocked {
		respondError(w, http.StatusForbidden, "Account is locked")
		return
	}

	// Update last used timestamp (async, don't block request)
	go a.store.UpdateAPIKeyLastUsed(apiKey.ID)

	// Add user, API key, and creator ID to context
	ctx := context.WithValue(r.Context(), userContextKey, user)
	ctx = context.WithValue(ctx, apiKeyContextKey, apiKey)
	ctx = context.WithValue(ctx, creatorIDContextKey, apiKey.ID)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// authenticateWithSession validates a session token and sets up the context
func (a *API) authenticateWithSession(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
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

	// Add user and creator ID to context
	ctx := context.WithValue(r.Context(), userContextKey, user)
	ctx = context.WithValue(ctx, creatorIDContextKey, user.ID)
	next.ServeHTTP(w, r.WithContext(ctx))
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

// RequireScope creates middleware that checks for a specific API key scope
// If authenticated via session (not API key), it always passes
func (a *API) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := getAPIKeyFromContext(r)
			// If no API key, user is authenticated via session - allow all
			if apiKey == nil {
				next.ServeHTTP(w, r)
				return
			}
			// Check if API key has required scope
			if !hasScope(apiKey, scope) {
				respondError(w, http.StatusForbidden, "Missing required scope: "+scope)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter provides IP-based rate limiting
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int           // max requests
	window   time.Duration // time window
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Get existing requests for this IP
	reqs := rl.requests[ip]

	// Filter to only requests within window
	var validReqs []time.Time
	for _, t := range reqs {
		if t.After(windowStart) {
			validReqs = append(validReqs, t)
		}
	}

	// Check if under limit
	if len(validReqs) >= rl.limit {
		rl.requests[ip] = validReqs
		return false
	}

	// Add this request
	validReqs = append(validReqs, now)
	rl.requests[ip] = validReqs
	return true
}

// RateLimitMiddleware limits requests per IP
func (a *API) RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get IP from X-Forwarded-For or RemoteAddr
			ip := r.Header.Get("X-Forwarded-For")
			if ip == "" {
				ip = r.Header.Get("X-Real-IP")
			}
			if ip == "" {
				ip = r.RemoteAddr
			}
			// Take first IP if multiple
			if idx := strings.Index(ip, ","); idx != -1 {
				ip = strings.TrimSpace(ip[:idx])
			}

			if !limiter.Allow(ip) {
				w.Header().Set("Retry-After", "1")
				respondError(w, http.StatusTooManyRequests, "Rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *API) Routes() chi.Router {
	r := chi.NewRouter()

	// Rate limiter: 10 requests per second per IP
	rateLimiter := NewRateLimiter(10, time.Second)
	r.Use(a.RateLimitMiddleware(rateLimiter))

	// Public auth endpoints
	r.Post("/auth/register", a.register)
	r.Post("/auth/login", a.login)
	r.Post("/auth/logout", a.logout)
	r.Get("/auth/check", a.checkAuth)
	r.Get("/auth/status", a.authStatus) // Check if instance has owner

	// Photos endpoint - public for serving images
	r.Get("/photos/{id}", a.servePhoto)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(a.AuthMiddleware)

		// User profile
		r.Get("/auth/me", a.getMe)
		r.Put("/auth/me", a.updateMe)

		// API Keys management
		r.Route("/keys", func(r chi.Router) {
			r.With(a.RequireScope("keys:manage")).Get("/", a.listAPIKeys)
			r.With(a.RequireScope("keys:manage")).Post("/", a.createAPIKey)
			r.With(a.RequireScope("keys:manage")).Get("/{id}", a.getAPIKey)
			r.With(a.RequireScope("keys:manage")).Put("/{id}", a.updateAPIKey)
			r.With(a.RequireScope("keys:manage")).Delete("/{id}", a.deleteAPIKey)
		})

		// Things
		r.Route("/things", func(r chi.Router) {
			// Read operations
			r.With(a.RequireScope("things:read")).Get("/", a.listThings)
			r.With(a.RequireScope("things:read")).Get("/query", a.queryThings) // Advanced query
			r.With(a.RequireScope("things:read")).Get("/search", a.searchThings)
			r.With(a.RequireScope("things:read")).Get("/{id}", a.getThing)
			r.With(a.RequireScope("things:read")).Get("/{id}/versions", a.listThingVersions)
			r.With(a.RequireScope("things:read")).Get("/{id}/versions/{version}", a.getThingVersion)
		r.With(a.RequireScope("things:read")).Get("/{id}/backlinks", a.getThingBacklinks)
		r.With(a.RequireScope("things:write")).Post("/{id}/versions/{version}/revert", a.revertToVersion)

			// Write operations
			r.With(a.RequireScope("things:write")).Post("/", a.createThing)
			r.With(a.RequireScope("things:write")).Put("/{id}", a.updateThing)
			r.With(a.RequireScope("things:write")).Put("/upsert", a.upsertThing)
			r.With(a.RequireScope("things:write")).Post("/bulk", a.bulkCreateThings)
			r.With(a.RequireScope("things:write")).Put("/bulk", a.bulkUpdateThings)

			// Delete operations
			r.With(a.RequireScope("things:delete")).Delete("/{id}", a.deleteThing)
			r.With(a.RequireScope("things:delete")).Delete("/bulk", a.bulkDeleteThings)
			r.With(a.RequireScope("things:write")).Post("/{id}/restore", a.restoreThing)
		})

		// Kinds
		r.Route("/kinds", func(r chi.Router) {
			r.With(a.RequireScope("kinds:read")).Get("/", a.listKinds)
			r.With(a.RequireScope("kinds:read")).Get("/{id}", a.getKind)
			r.With(a.RequireScope("kinds:write")).Post("/", a.createKind)
			r.With(a.RequireScope("kinds:write")).Put("/{id}", a.updateKind)
			r.With(a.RequireScope("kinds:delete")).Delete("/{id}", a.deleteKind)
		})

		// Tags
		r.Route("/tags", func(r chi.Router) {
			r.With(a.RequireScope("tags:read")).Get("/", a.listTags)
			r.With(a.RequireScope("tags:write")).Post("/", a.createTag)
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
		r.Get("/photos/{id}", a.servePhoto)
		r.Put("/photos/{id}", a.updatePhoto)
		r.Delete("/photos/{id}", a.deletePhoto)

		// Export/Import - user data portability
		r.Get("/export", a.exportData)
		r.Post("/import", a.importData)

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
	// Single-tenant: only allow one user (the owner)
	userCount, err := a.store.CountUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}
	if userCount > 0 {
		respondError(w, http.StatusForbidden, "Registration disabled - this is a single-tenant instance")
		return
	}

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

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(passwordHash),
		DisplayName:  req.Username,
		IsAdmin:      true, // Single user is always admin
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
	// Sandbox mode: always authenticated as sandbox user
	if a.sandboxMode {
		user, err := a.store.GetUserByUsername("sandbox")
		if err != nil {
			respondJSON(w, http.StatusOK, map[string]interface{}{"authenticated": false})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"authenticated": true,
			"user":          user,
			"sandboxMode":   true,
		})
		return
	}

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

// authStatus returns the instance status - whether it has an owner (single-tenant)
func (a *API) authStatus(w http.ResponseWriter, r *http.Request) {
	userCount, err := a.store.CountUsers()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Database error")
		return
	}

	response := map[string]interface{}{
		"hasOwner":            userCount > 0,
		"registrationEnabled": userCount == 0 && !a.sandboxMode,
		"sandboxMode":         a.sandboxMode,
		"authDisabled":        a.sandboxMode, // No login required in sandbox
	}

	respondJSON(w, http.StatusOK, response)
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
	if user == nil {
		respondError(w, http.StatusUnauthorized, "User not found in context")
		return
	}

	// Parse multipart form (32MB max)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondError(w, http.StatusBadRequest, "Failed to parse form: "+err.Error())
		return
	}

	// Get files from "files" field (multipart form)
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		respondError(w, http.StatusBadRequest, "No files provided")
		return
	}

	// Get captions array from form
	captions := r.Form["captions"]

	// Get post content
	content := r.FormValue("content")

	// Create a Thing with type "gallery"
	t := &models.Thing{
		UserID:     user.ID,
		Type:       "gallery",
		Content:    content,
		Visibility: r.FormValue("visibility"),
		Metadata: map[string]interface{}{
			"photoCount": len(files),
		},
	}

	// Default visibility to private
	if t.Visibility == "" {
		t.Visibility = "private"
	}

	if err := a.store.CreateThing(t); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Process each file
	var photos []models.Photo
	for i, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to open file: "+err.Error())
			return
		}
		defer file.Close()

		// Validate file type
		contentType := fileHeader.Header.Get("Content-Type")
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

		// Get caption for this photo (if provided)
		caption := ""
		if i < len(captions) {
			caption = captions[i]
		}

		// Create Photo blob linked to the gallery Thing
		photo := &models.Photo{
			ThingID:     t.ID,
			Caption:     caption,
			OrderIndex:  i,
			Data:        data,
			ContentType: contentType,
			Filename:    fileHeader.Filename,
			Size:        int64(len(data)),
		}

		if err := a.store.CreatePhoto(photo); err != nil {
			// Clean up the Thing if any photo creation fails
			a.store.DeleteThing(t.ID, user.ID)
			respondError(w, http.StatusInternalServerError, "Failed to save photo: "+err.Error())
			return
		}

		photos = append(photos, *photo)
	}

	// Reload the Thing with photos included
	t.Photos = photos

	respondJSON(w, http.StatusCreated, t)
}

// Photo serve handler - serves photo blob from SQLite
// Supports ?size=thumb for thumbnail or ?size=full (default) for full size

func (a *API) servePhoto(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	size := r.URL.Query().Get("size") // "thumb" or "full" (default)
	isThumb := size == "thumb"

	photo, err := a.store.GetPhoto(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Photo not found: "+id)
		return
	}

	// Try to serve from cache first (separate cache for thumb vs full)
	cacheKey := id
	if isThumb {
		cacheKey = id + "_thumb"
	}
	cachedData, contentType, cacheHit := a.getPhotoFromCache(cacheKey, photo.ContentType)

	if !cacheHit {
		// Compress/transform image if needed and save to cache
		var transformedData []byte

		if strings.HasPrefix(photo.ContentType, "image/") {
			if isThumb {
				transformedData, err = a.compressImageWithSettings(photo.Data, photo.ContentType, PhotoThumbMaxWidth, PhotoThumbQuality)
			} else {
				transformedData, err = a.compressImageWithSettings(photo.Data, photo.ContentType, PhotoMaxWidth, PhotoQuality)
			}
			if err != nil {
				// Fall back to original if compression fails
				transformedData = photo.Data
			} else {
				// Cache the compressed image (best effort, don't fail if cache write fails)
				_ = a.cachePhoto(cacheKey, transformedData, photo.ContentType)
			}
		} else {
			// Videos: serve original (no compression)
			transformedData = photo.Data
		}

		cachedData = transformedData
		contentType = photo.ContentType
	}

	// For cached images, serve as JPEG
	if cacheHit {
		contentType = "image/jpeg"
	}

	// Generate ETag based on photo ID and size (content-addressable)
	etag := fmt.Sprintf(`"%s"`, cacheKey)

	// Check if client has cached version
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(cachedData)))
	w.Header().Set("Cache-Control", "public, max-age=604800") // Cache for 1 week
	w.Header().Set("ETag", etag)
	w.Write(cachedData)
}

// updatePhoto updates photo metadata (caption)
func (a *API) updatePhoto(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	// Get the photo to verify ownership
	photo, err := a.store.GetPhoto(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Photo not found")
		return
	}

	// Get the parent thing to verify user owns it
	thing, err := a.store.GetThingForUser(photo.ThingID, user.ID)
	if err != nil || thing == nil {
		respondError(w, http.StatusForbidden, "Not authorized to edit this photo")
		return
	}

	// Parse the update request
	var update struct {
		Caption string `json:"caption"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	// Update the photo caption
	if err := a.store.UpdatePhotoCaption(id, update.Caption); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update photo")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// deletePhoto deletes a photo from a gallery
func (a *API) deletePhoto(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	// Get the photo to verify ownership
	photo, err := a.store.GetPhoto(id)
	if err != nil {
		respondError(w, http.StatusNotFound, "Photo not found")
		return
	}

	// Get the parent thing to verify user owns it
	thing, err := a.store.GetThingForUser(photo.ThingID, user.ID)
	if err != nil || thing == nil {
		respondError(w, http.StatusForbidden, "Not authorized to delete this photo")
		return
	}

	// Delete the photo
	if err := a.store.DeletePhoto(id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete photo")
		return
	}

	// Clean up cached files
	cachePath := filepath.Join(PhotoCacheDir, id+".jpg")
	_ = os.Remove(cachePath)
	thumbCachePath := filepath.Join(PhotoCacheDir, id+"_thumb.jpg")
	_ = os.Remove(thumbCachePath)

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// getPhotoFromCache retrieves a cached photo if it exists and is fresh
func (a *API) getPhotoFromCache(photoID, contentType string) ([]byte, string, bool) {
	cachePath := filepath.Join(PhotoCacheDir, photoID+".jpg")

	// Check if cached file exists
	info, err := os.Stat(cachePath)
	if err != nil {
		return nil, "", false
	}

	// Check if cache is still fresh (less than 30 days old)
	if time.Since(info.ModTime()) > PhotoCacheTTL {
		_ = os.Remove(cachePath) // Delete stale cache
		return nil, "", false
	}

	// Read cached data
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, "", false
	}

	// Cached images are always JPEG
	return data, "image/jpeg", true
}

// cachePhoto saves a compressed photo to the cache directory
func (a *API) cachePhoto(photoID string, data []byte, contentType string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(PhotoCacheDir, 0755); err != nil {
		return err
	}

	cachePath := filepath.Join(PhotoCacheDir, photoID+".jpg")
	return os.WriteFile(cachePath, data, 0644)
}

// compressImage reduces image quality and resizes to max width (uses default settings)
func (a *API) compressImage(data []byte, contentType string) ([]byte, error) {
	return a.compressImageWithSettings(data, contentType, PhotoMaxWidth, PhotoQuality)
}

// compressImageWithSettings reduces image quality and resizes with custom settings
func (a *API) compressImageWithSettings(data []byte, contentType string, maxWidth, quality int) ([]byte, error) {
	// Decode image
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Resize if larger than max width
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X

	if width > maxWidth {
		height := bounds.Max.Y - bounds.Min.Y
		newHeight := (height * maxWidth) / width
		img = resizeImage(img, maxWidth, newHeight)
	}

	// Encode as JPEG with specified quality
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
	if err != nil {
		return nil, fmt.Errorf("failed to encode image: %w", err)
	}

	return buf.Bytes(), nil
}

// resizeImage performs simple nearest-neighbor resizing
func resizeImage(src image.Image, newWidth, newHeight int) image.Image {
	srcBounds := src.Bounds()
	srcWidth := srcBounds.Max.X - srcBounds.Min.X
	srcHeight := srcBounds.Max.Y - srcBounds.Min.Y

	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	for y := 0; y < newHeight; y++ {
		for x := 0; x < newWidth; x++ {
			srcX := (x * srcWidth) / newWidth
			srcY := (y * srcHeight) / newHeight
			dst.Set(x, y, src.At(srcBounds.Min.X+srcX, srcBounds.Min.Y+srcY))
		}
	}

	return dst
}

// cleanupPhotoCache periodically removes expired cached images
func (a *API) cleanupPhotoCache() {
	ticker := time.NewTicker(PhotoCacheCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		_ = a.cleanupExpiredPhotos()
	}
}

// cleanupExpiredPhotos removes photo cache files older than the TTL
func (a *API) cleanupExpiredPhotos() error {
	entries, err := os.ReadDir(PhotoCacheDir)
	if err != nil {
		// Directory might not exist yet, that's fine
		return nil
	}

	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Delete if older than TTL
		if now.Sub(info.ModTime()) > PhotoCacheTTL {
			filePath := filepath.Join(PhotoCacheDir, entry.Name())
			_ = os.Remove(filePath)
		}
	}

	return nil
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

// ============================================================================
// API Key handlers
// ============================================================================

func (a *API) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	keys, err := a.store.ListAPIKeys(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if keys == nil {
		keys = []models.APIKey{}
	}

	// Clear the hash from response
	for i := range keys {
		keys[i].KeyHash = ""
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"keys":            keys,
		"availableScopes": models.APIKeyScopes,
	})
}

func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	var req struct {
		Name      string                 `json:"name"`
		Scopes    []string               `json:"scopes"`
		Metadata  map[string]interface{} `json:"metadata"`
		ExpiresAt *time.Time             `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "Name is required")
		return
	}

	// Validate scopes
	validScopes := make(map[string]bool)
	for _, s := range models.APIKeyScopes {
		validScopes[s] = true
	}
	for _, s := range req.Scopes {
		if !validScopes[s] {
			respondError(w, http.StatusBadRequest, "Invalid scope: "+s)
			return
		}
	}

	// Generate raw key
	rawKey, err := generateAPIKey()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	// Hash the key
	keyHash, err := bcrypt.GenerateFromPassword([]byte(rawKey), bcrypt.DefaultCost)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash API key")
		return
	}

	key := &models.APIKey{
		UserID:    user.ID,
		Name:      req.Name,
		Scopes:    req.Scopes,
		Metadata:  req.Metadata,
		ExpiresAt: req.ExpiresAt,
	}

	if err := a.store.CreateAPIKey(key, rawKey, string(keyHash)); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return key with the raw key (only time it's visible!)
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":        key.ID,
		"name":      key.Name,
		"keyPrefix": key.KeyPrefix,
		"key":       rawKey, // Only returned once!
		"scopes":    key.Scopes,
		"metadata":  key.Metadata,
		"expiresAt": key.ExpiresAt,
		"createdAt": key.CreatedAt,
		"warning":   "This is the only time the full API key will be shown. Store it securely!",
	})
}

func (a *API) getAPIKey(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	key, err := a.store.GetAPIKeyForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "API key not found")
		return
	}

	key.KeyHash = "" // Never expose hash
	respondJSON(w, http.StatusOK, key)
}

func (a *API) updateAPIKey(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	var req struct {
		Name      string                 `json:"name"`
		Scopes    []string               `json:"scopes"`
		Metadata  map[string]interface{} `json:"metadata"`
		ExpiresAt *time.Time             `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	key, err := a.store.GetAPIKeyForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "API key not found")
		return
	}

	// Validate scopes
	validScopes := make(map[string]bool)
	for _, s := range models.APIKeyScopes {
		validScopes[s] = true
	}
	for _, s := range req.Scopes {
		if !validScopes[s] {
			respondError(w, http.StatusBadRequest, "Invalid scope: "+s)
			return
		}
	}

	key.Name = req.Name
	key.Scopes = req.Scopes
	key.Metadata = req.Metadata
	key.ExpiresAt = req.ExpiresAt

	if err := a.store.UpdateAPIKey(key); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	key.KeyHash = "" // Never expose hash
	respondJSON(w, http.StatusOK, key)
}

func (a *API) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	if err := a.store.DeleteAPIKey(id, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Thing Version handlers
// ============================================================================

func (a *API) listThingVersions(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	thingID := chi.URLParam(r, "id")

	versions, err := a.store.ListThingVersions(thingID, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Thing not found")
		return
	}

	if versions == nil {
		versions = []models.ThingVersion{}
	}

	respondJSON(w, http.StatusOK, versions)
}

func (a *API) getThingVersion(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	thingID := chi.URLParam(r, "id")
	versionStr := chi.URLParam(r, "version")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid version number")
		return
	}

	v, err := a.store.GetThingVersion(thingID, user.ID, version)
	if err != nil {
		respondError(w, http.StatusNotFound, "Version not found")
		return
	}

	respondJSON(w, http.StatusOK, v)
}


func (a *API) getThingBacklinks(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	backlinks, err := a.store.GetBacklinks(user.ID, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if backlinks == nil {
		backlinks = []models.Thing{} // Return empty array instead of null
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"backlinks": backlinks,
	})
}

func (a *API) restoreThing(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")

	if err := a.store.RestoreThing(id, user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Get the restored thing
	t, err := a.store.GetThingForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Thing not found")
		return
	}

	respondJSON(w, http.StatusOK, t)
}

func (a *API) revertToVersion(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	id := chi.URLParam(r, "id")
	versionStr := chi.URLParam(r, "version")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid version number")
		return
	}

	// Get the specified version
	v, err := a.store.GetThingVersion(id, user.ID, version)
	if err != nil {
		respondError(w, http.StatusNotFound, "Version not found")
		return
	}

	// Get the current thing to check ownership
	current, err := a.store.GetThingForUser(id, user.ID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Thing not found")
		return
	}

	// Update the thing with the version's content (this creates a new version)
	current.Content = v.Content
	current.Type = v.Type
	current.Metadata = v.Metadata

	// Get creator ID (user or API key)
	creatorID := getCreatorIDFromContext(r)

	if err := a.store.UpdateThingWithCreator(current, creatorID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return the updated thing
	updated, _ := a.store.GetThingForUser(id, user.ID)
	respondJSON(w, http.StatusOK, updated)
}

// ============================================================================
// Advanced Query handlers
// ============================================================================

func (a *API) queryThings(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	query := r.URL.Query()

	// Build query params
	q := store.ThingQuery{
		UserID:         user.ID,
		Type:           query.Get("type"),
		Sort:           query.Get("sort"),
		MetadataFilter: make(map[string]string),
		IncludeDeleted: query.Get("includeDeleted") == "true",
	}

	// Parse pagination
	if page, err := strconv.Atoi(query.Get("page")); err == nil {
		q.Page = page
	} else {
		q.Page = 1
	}

	if count := query.Get("count"); count == "all" {
		q.Count = -1
	} else if c, err := strconv.Atoi(count); err == nil {
		q.Count = c
	} else {
		q.Count = 50 // default
	}

	// Parse metadata filters (meta.field=value)
	for key, values := range query {
		if strings.HasPrefix(key, "meta.") && len(values) > 0 {
			field := strings.TrimPrefix(key, "meta.")
			q.MetadataFilter[field] = values[0]
		}
	}

	result, err := a.store.QueryThings(q)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// ============================================================================
// Upsert handler
// ============================================================================

func (a *API) upsertThing(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	creatorID := getCreatorIDFromContext(r)
	query := r.URL.Query()

	thingType := query.Get("type")
	matchField := query.Get("matchField")
	matchValue := query.Get("matchValue")

	if thingType == "" {
		respondError(w, http.StatusBadRequest, "type query param is required")
		return
	}
	if matchField == "" {
		respondError(w, http.StatusBadRequest, "matchField query param is required")
		return
	}
	if matchValue == "" {
		respondError(w, http.StatusBadRequest, "matchValue query param is required")
		return
	}

	var t models.Thing
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	result, created, err := a.store.UpsertThing(user.ID, thingType, matchField, matchValue, &t, creatorID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}

	respondJSON(w, status, map[string]interface{}{
		"thing":   result,
		"created": created,
	})
}

// ============================================================================
// Bulk operation handlers
// ============================================================================

func (a *API) bulkCreateThings(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	creatorID := getCreatorIDFromContext(r)

	var req struct {
		Things []models.Thing `json:"things"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.Things) == 0 {
		respondError(w, http.StatusBadRequest, "No things provided")
		return
	}

	if len(req.Things) > 100 {
		respondError(w, http.StatusBadRequest, "Maximum 100 things per request")
		return
	}

	// Set user ID on all things
	things := make([]*models.Thing, len(req.Things))
	for i := range req.Things {
		req.Things[i].UserID = user.ID
		things[i] = &req.Things[i]
	}

	if err := a.store.BulkCreateThings(things, creatorID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"created": len(things),
		"things":  things,
	})
}

func (a *API) bulkUpdateThings(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	creatorID := getCreatorIDFromContext(r)

	var req struct {
		Things []models.Thing `json:"things"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.Things) == 0 {
		respondError(w, http.StatusBadRequest, "No things provided")
		return
	}

	if len(req.Things) > 100 {
		respondError(w, http.StatusBadRequest, "Maximum 100 things per request")
		return
	}

	// Verify all things belong to user and set user ID
	things := make([]*models.Thing, len(req.Things))
	for i := range req.Things {
		if req.Things[i].ID == "" {
			respondError(w, http.StatusBadRequest, "All things must have an ID")
			return
		}
		req.Things[i].UserID = user.ID
		things[i] = &req.Things[i]
	}

	if err := a.store.BulkUpdateThings(things, creatorID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"updated": len(things),
		"things":  things,
	})
}

func (a *API) bulkDeleteThings(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if len(req.IDs) == 0 {
		respondError(w, http.StatusBadRequest, "No IDs provided")
		return
	}

	if len(req.IDs) > 100 {
		respondError(w, http.StatusBadRequest, "Maximum 100 IDs per request")
		return
	}

	if err := a.store.BulkDeleteThings(user.ID, req.IDs); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": len(req.IDs),
	})
}

// Export/Import handlers for data portability

// ExportData represents the full export format
type ExportData struct {
	Version   string          `json:"version"`
	ExportedAt string         `json:"exportedAt"`
	Things    []models.Thing  `json:"things"`
	Kinds     []models.Kind   `json:"kinds"`
}

func (a *API) exportData(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Get all things for this user using QueryThings with Count: -1 (all items)
	result, err := a.store.QueryThings(store.ThingQuery{
		UserID:         user.ID,
		Count:          -1, // Return all items
		IncludeDeleted: false,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to export things: "+err.Error())
		return
	}

	// Get all kinds for this user
	kinds, err := a.store.ListKinds(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to export kinds: "+err.Error())
		return
	}

	export := ExportData{
		Version:    "1.0",
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		Things:     result.Things,
		Kinds:      kinds,
	}

	// Set headers for file download
	filename := "tenant-export-" + time.Now().Format("2006-01-02") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	respondJSON(w, http.StatusOK, export)
}

func (a *API) importData(w http.ResponseWriter, r *http.Request) {
	user := getUserFromContext(r)
	if user == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Read body (limit to 100MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 100*1024*1024))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var data ExportData
	if err := json.Unmarshal(body, &data); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON format: "+err.Error())
		return
	}

	// Validate version
	if data.Version == "" {
		respondError(w, http.StatusBadRequest, "Missing version field in import data")
		return
	}

	// Get existing kinds to check for duplicates
	existingKinds, err := a.store.ListKinds(user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list existing kinds: "+err.Error())
		return
	}
	existingKindNames := make(map[string]bool)
	for _, k := range existingKinds {
		existingKindNames[k.Name] = true
	}

	// Import kinds first (things depend on kinds)
	kindsCreated := 0
	kindsSkipped := 0
	for _, kind := range data.Kinds {
		// Check if kind already exists by name
		if existingKindNames[kind.Name] {
			kindsSkipped++
			continue
		}

		// Create new kind with new ID
		newKind := &models.Kind{
			UserID:     user.ID,
			Name:       kind.Name,
			Icon:       kind.Icon,
			Template:   kind.Template,
			Attributes: kind.Attributes,
		}
		if err := a.store.CreateKind(newKind); err != nil {
			// Skip on error, continue with others
			kindsSkipped++
			continue
		}
		kindsCreated++
		existingKindNames[kind.Name] = true // Track newly created
	}

	// Import things
	thingsCreated := 0
	thingsSkipped := 0
	for _, thing := range data.Things {
		// Create new thing with new ID
		newThing := &models.Thing{
			UserID:   user.ID,
			Type:     thing.Type,
			Content:  thing.Content,
			Metadata: thing.Metadata,
		}
		if err := a.store.CreateThing(newThing); err != nil {
			thingsSkipped++
			continue
		}
		thingsCreated++
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Import completed",
		"kindsCreated":  kindsCreated,
		"kindsSkipped":  kindsSkipped,
		"thingsCreated": thingsCreated,
		"thingsSkipped": thingsSkipped,
	})
}
