package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHashPassword(t *testing.T) {
	// Test that hashing is deterministic
	hash1 := HashPassword("testpassword")
	hash2 := HashPassword("testpassword")

	if hash1 != hash2 {
		t.Error("Same password should produce same hash")
	}

	// Test that different passwords produce different hashes
	hash3 := HashPassword("differentpassword")
	if hash1 == hash3 {
		t.Error("Different passwords should produce different hashes")
	}

	// Test hash length (SHA-256 produces 64 hex characters)
	if len(hash1) != 64 {
		t.Errorf("Hash should be 64 characters, got %d", len(hash1))
	}
}

func TestNewAuthManager(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with empty password
	_, err := New("", tmpDir)
	if err == nil {
		t.Error("Should error with empty password")
	}

	// Test with valid password
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	if am == nil {
		t.Error("Auth manager should not be nil")
	}
}

func TestVerifyPasswordHash(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Correct password hash
	correctHash := HashPassword("testpassword")
	if !am.VerifyPasswordHash(correctHash) {
		t.Error("Should verify correct password hash")
	}

	// Incorrect password hash
	incorrectHash := HashPassword("wrongpassword")
	if am.VerifyPasswordHash(incorrectHash) {
		t.Error("Should not verify incorrect password hash")
	}
}

func TestGenerateToken(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	token, err := am.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Token should be 64 hex characters (32 bytes)
	if len(token) != 64 {
		t.Errorf("Token should be 64 characters, got %d", len(token))
	}

	// Token should be saved to disk
	tokenPath := filepath.Join(tmpDir, "auth_token.json")
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		t.Error("Token file should be created on disk")
	}

	// Generate another token - should be different
	token2, err := am.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	if token == token2 {
		t.Error("Each generated token should be unique")
	}
}

func TestValidateToken(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// No token yet - should not validate
	if am.ValidateToken("anytoken") {
		t.Error("Should not validate when no token exists")
	}

	// Generate token
	token, err := am.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Valid token should validate
	if !am.ValidateToken(token) {
		t.Error("Should validate correct token")
	}

	// Invalid token should not validate
	if am.ValidateToken("invalidtoken") {
		t.Error("Should not validate incorrect token")
	}

	// Empty token should not validate
	if am.ValidateToken("") {
		t.Error("Should not validate empty token")
	}
}

func TestRevokeToken(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Generate and then revoke token
	token, err := am.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	err = am.RevokeToken()
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}

	// Token should no longer validate
	if am.ValidateToken(token) {
		t.Error("Revoked token should not validate")
	}

	// Token file should be deleted
	tokenPath := filepath.Join(tmpDir, "auth_token.json")
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Error("Token file should be deleted after revocation")
	}
}

func TestGetTokenExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// No token - should return nil
	if am.GetTokenExpiry() != nil {
		t.Error("Should return nil when no token exists")
	}

	// Generate token
	_, err = am.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	expiry := am.GetTokenExpiry()
	if expiry == nil {
		t.Fatal("Should return expiry time after token generation")
	}

	// Expiry should be approximately 6 months from now
	expectedExpiry := time.Now().Add(TokenValidityDuration)
	diff := expiry.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("Expiry should be ~6 months from now, got diff of %v", diff)
	}
}

func TestTokenPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create auth manager and generate token
	am1, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	token, err := am1.GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Create new auth manager with same data dir - should load token
	am2, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create second auth manager: %v", err)
	}

	// Token should still be valid
	if !am2.ValidateToken(token) {
		t.Error("Token should persist across auth manager instances")
	}
}

func TestRevokeNonexistentToken(t *testing.T) {
	tmpDir := t.TempDir()
	am, err := New("testpassword", tmpDir)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Revoking when no token exists should not error
	err = am.RevokeToken()
	if err != nil {
		t.Errorf("Revoking nonexistent token should not error: %v", err)
	}
}
