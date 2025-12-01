package store

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
	_ "modernc.org/sqlite"
)

// DataBackendType identifies the database backend
type DataBackendType string

const (
	BackendSQLite DataBackendType = "sqlite"
	BackendTurso  DataBackendType = "turso"
)

// DataBackend defines the interface for database backends
type DataBackend interface {
	// Type returns the backend type
	Type() DataBackendType

	// Connect establishes a database connection
	Connect() (*sql.DB, error)

	// Description returns a human-readable description
	Description() string
}

// Config holds the database configuration
type Config struct {
	Backend DataBackendType `json:"backend"`

	// SQLite-specific
	SQLitePath string `json:"sqlitePath,omitempty"` // e.g., "./tenant.db" or ":memory:"

	// Turso-specific
	TursoURL   string `json:"tursoUrl,omitempty"`   // e.g., "libsql://mydb.turso.io"
	TursoToken string `json:"tursoToken,omitempty"` // Auth token
}

// ConfigFromEnv creates a Config from environment variables
// DB_BACKEND: "sqlite" or "turso" (defaults to "sqlite")
// For SQLite: SQLITE_PATH (defaults to "tenant.db")
// For Turso: TURSO_DATABASE_URL, TURSO_AUTH_TOKEN
func ConfigFromEnv() Config {
	backend := DataBackendType(os.Getenv("DB_BACKEND"))
	if backend == "" {
		// Auto-detect from legacy env vars
		if os.Getenv("TURSO_DATABASE_URL") != "" {
			backend = BackendTurso
		} else {
			backend = BackendSQLite
		}
	}

	cfg := Config{Backend: backend}

	switch backend {
	case BackendTurso:
		cfg.TursoURL = os.Getenv("TURSO_DATABASE_URL")
		cfg.TursoToken = os.Getenv("TURSO_AUTH_TOKEN")
	case BackendSQLite:
		cfg.SQLitePath = os.Getenv("SQLITE_PATH")
		if cfg.SQLitePath == "" {
			cfg.SQLitePath = "tenant.db"
		}
	}

	return cfg
}

// NewDataBackend creates a DataBackend from Config
func NewDataBackend(cfg Config) (DataBackend, error) {
	switch cfg.Backend {
	case BackendSQLite:
		return &SQLiteBackend{Path: cfg.SQLitePath}, nil
	case BackendTurso:
		return &TursoBackend{URL: cfg.TursoURL, Token: cfg.TursoToken}, nil
	default:
		return nil, fmt.Errorf("unsupported backend: %s", cfg.Backend)
	}
}

// SQLiteBackend implements DataBackend for local SQLite
type SQLiteBackend struct {
	Path string // File path or ":memory:" for in-memory
}

func (b *SQLiteBackend) Type() DataBackendType {
	return BackendSQLite
}

func (b *SQLiteBackend) Connect() (*sql.DB, error) {
	path := b.Path
	if path == "" {
		path = "tenantsocial.db"
	}
	return sql.Open("sqlite", path)
}

func (b *SQLiteBackend) Description() string {
	if b.Path == ":memory:" || b.Path == "file::memory:" {
		return "SQLite (in-memory)"
	}
	return fmt.Sprintf("SQLite (%s)", b.Path)
}

// TursoBackend implements DataBackend for Turso cloud database
type TursoBackend struct {
	URL   string // libsql://mydb.turso.io
	Token string // Auth token
}

func (b *TursoBackend) Type() DataBackendType {
	return BackendTurso
}

func (b *TursoBackend) Connect() (*sql.DB, error) {
	if b.URL == "" {
		return nil, fmt.Errorf("turso URL is required")
	}

	connStr := b.URL
	if b.Token != "" {
		connStr = b.URL + "?authToken=" + b.Token
	}

	return sql.Open("libsql", connStr)
}

func (b *TursoBackend) Description() string {
	return fmt.Sprintf("Turso (%s)", b.URL)
}

// SupportedBackends returns a list of all supported backend types
func SupportedBackends() []DataBackendType {
	return []DataBackendType{
		BackendSQLite,
		BackendTurso,
	}
}
