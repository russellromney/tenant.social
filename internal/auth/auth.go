package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	TokenValidityDuration = 6 * 30 * 24 * time.Hour // 6 months
)

// TokenData stores the token and its metadata
type TokenData struct {
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthManager handles password verification and token management
type AuthManager struct {
	passwordHash string
	tokenPath    string
	token        *TokenData
	mu           sync.RWMutex
}

// New creates a new AuthManager
func New(password string, dataDir string) (*AuthManager, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	// Hash the password for storage/comparison
	hash := hashPassword(password)

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}

	tokenPath := filepath.Join(dataDir, "auth_token.json")

	am := &AuthManager{
		passwordHash: hash,
		tokenPath:    tokenPath,
	}

	// Load existing token if present
	am.loadToken()

	return am, nil
}

// hashPassword creates a SHA-256 hash of the password
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// HashPassword is exported for client-side hashing verification
func HashPassword(password string) string {
	return hashPassword(password)
}

// VerifyPasswordHash checks if a provided hash matches the stored password hash
func (am *AuthManager) VerifyPasswordHash(providedHash string) bool {
	return providedHash == am.passwordHash
}

// GenerateToken creates a new session token and stores it on disk
func (am *AuthManager) GenerateToken() (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Generate random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)

	now := time.Now()
	am.token = &TokenData{
		Token:     token,
		CreatedAt: now,
		ExpiresAt: now.Add(TokenValidityDuration),
	}

	// Save to disk
	if err := am.saveToken(); err != nil {
		return "", err
	}

	return token, nil
}

// ValidateToken checks if a token is valid and not expired
func (am *AuthManager) ValidateToken(token string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.token == nil {
		return false
	}

	if am.token.Token != token {
		return false
	}

	if time.Now().After(am.token.ExpiresAt) {
		return false
	}

	return true
}

// RevokeToken deletes the current token
func (am *AuthManager) RevokeToken() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.token = nil

	// Remove from disk
	if err := os.Remove(am.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// GetTokenExpiry returns the expiry time of the current token
func (am *AuthManager) GetTokenExpiry() *time.Time {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.token == nil {
		return nil
	}

	return &am.token.ExpiresAt
}

// loadToken reads token from disk
func (am *AuthManager) loadToken() {
	data, err := os.ReadFile(am.tokenPath)
	if err != nil {
		return
	}

	var token TokenData
	if err := json.Unmarshal(data, &token); err != nil {
		return
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		os.Remove(am.tokenPath)
		return
	}

	am.token = &token
}

// saveToken writes token to disk
func (am *AuthManager) saveToken() error {
	data, err := json.MarshalIndent(am.token, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(am.tokenPath, data, 0600)
}
